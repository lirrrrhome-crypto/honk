//! Long-running soak test for TCP proxy chains: connection success rate,
//! dial / first-byte latency percentiles, error breakdown by hop, and leak
//! indicators (live loopback bridges, open file descriptors) over time.
//!
//! Real nodes (hops in traffic order; the exit is last):
//!
//!   cargo run --release -p honk-outbound --features rprx --example chain_soak -- \
//!     hop='socks5://127.0.0.1:1080#front' exit='trojan://pw@exit.example:443#exit' \
//!     url=http://www.gstatic.com/generate_204 concurrency=8 duration=3600
//!
//! Self test (local SOCKS5 hops + echo target, optional fault injection):
//!
//!   cargo run --release -p honk-outbound --example chain_soak -- \
//!     selftest hops=3 concurrency=32 duration=60 fail=0.02 jitter=20
//!
//! Options (key=value):
//!   hop=LINK        a hop share link; repeat for each hop, first hop first
//!   exit=LINK       the exit share link (required unless `selftest`)
//!   url=http://H/P  probe with a plain HTTP GET (2xx/3xx counts as success)
//!   echo=HOST:PORT  probe an echo server: send `payload` bytes, verify reply
//!   udp=HOST:PORT   UDP: open a chained UDP transport per probe, send
//!                   `packets` datagrams of `payload` bytes to a UDP echo
//!                   server and verify every reply
//!   dns=HOST:PORT   UDP: one A query for `name` (default example.com) per
//!                   probe; success is a matching response
//!   packets=N       datagrams per UDP probe (default 1)
//!   concurrency=N   parallel probe workers (default 4)
//!   duration=SECS   total run time; 0 runs until Ctrl-C (default 60)
//!   interval=SECS   report window (default 10)
//!   gap=MS          pause per worker between probes (default 200)
//!   timeout=SECS    per-dial connect timeout, as honk's `connect_timeout`
//!                   (the whole chain gets 3x, like the core) (default 5)
//!   io_timeout=SECS deadline for the request/reply exchange (default 10)
//!   payload=BYTES   echo payload size (default 1024)
//!   hold=MS         keep each connection open this long after the reply,
//!                   to soak long-lived flows (default 0)
//!   csv=PATH        append one row per report window
//!   selftest        run local hops; with hops=N, fail=P (probability a hop
//!                   drops a connection), jitter=MS (random delay per hop).
//!                   With `udp` (no value needed), the exit is a local
//!                   Trojan server and the target a local UDP echo.

use std::collections::{BTreeMap, HashMap};
use std::io::Write as _;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use honk_config::node::{ChainConfig, ChainExit, Node, OutboundConfig};
use honk_outbound::proxy::ProxyRegistry;
use honk_outbound::proxy::chain::{self, ChainResolver};
use parking_lot::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

// ---------------------------------------------------------------- options

struct Options {
    hops: Vec<String>,
    exit: Option<String>,
    url: Option<String>,
    echo: Option<String>,
    udp: Option<String>,
    dns: Option<String>,
    name: String,
    packets: usize,
    concurrency: usize,
    duration: Duration,
    interval: Duration,
    gap: Duration,
    timeout: Duration,
    io_timeout: Duration,
    payload: usize,
    hold: Duration,
    csv: Option<String>,
    selftest: bool,
    selftest_hops: usize,
    fail: f64,
    jitter: u64,
}

fn parse_options() -> Options {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let get = |key: &str| {
        args.iter()
            .rev()
            .find_map(|arg| arg.strip_prefix(&format!("{key}=")).map(str::to_owned))
    };
    let num = |key: &str, default: f64| -> f64 {
        get(key)
            .map(|value| {
                value
                    .parse()
                    .unwrap_or_else(|_| panic!("{key}= expects a number, got {value}"))
            })
            .unwrap_or(default)
    };
    Options {
        hops: args
            .iter()
            .filter_map(|arg| arg.strip_prefix("hop=").map(str::to_owned))
            .collect(),
        exit: get("exit"),
        url: get("url"),
        echo: get("echo"),
        udp: get("udp").or_else(|| args.iter().any(|arg| arg == "udp").then(String::new)),
        dns: get("dns"),
        name: get("name").unwrap_or_else(|| "example.com".to_owned()),
        packets: num("packets", 1.0).max(1.0) as usize,
        concurrency: num("concurrency", 4.0).max(1.0) as usize,
        duration: Duration::from_secs_f64(num("duration", 60.0)),
        interval: Duration::from_secs_f64(num("interval", 10.0).max(1.0)),
        gap: Duration::from_millis(num("gap", 200.0) as u64),
        timeout: Duration::from_secs_f64(num("timeout", 5.0)),
        io_timeout: Duration::from_secs_f64(num("io_timeout", 10.0)),
        payload: num("payload", 1024.0).max(1.0) as usize,
        hold: Duration::from_millis(num("hold", 0.0) as u64),
        csv: get("csv"),
        selftest: args.iter().any(|arg| arg == "selftest"),
        selftest_hops: num("hops", 3.0).max(1.0) as usize,
        fail: num("fail", 0.0).clamp(0.0, 1.0),
        jitter: num("jitter", 0.0) as u64,
    }
}

// ---------------------------------------------------------------- resolver

struct MapResolver(HashMap<String, Node>);

impl ChainResolver for MapResolver {
    fn resolve(&self, tag: &str) -> Option<Node> {
        self.0.get(tag).cloned()
    }
}

fn parse_node(link: &str, fallback: &str) -> anyhow::Result<Node> {
    let mut node = Node::from_share_link(link)
        .map_err(|error| anyhow::anyhow!("cannot parse share link for {fallback}: {error}"))?;
    if node.name.is_empty() {
        node.name = fallback.to_owned();
    }
    node.id = node.derive_id();
    Ok(node)
}

// ---------------------------------------------------------------- probes

#[derive(Clone)]
enum Probe {
    Http {
        target: SocketAddr,
        domain: Option<String>,
        request: Vec<u8>,
    },
    Echo {
        target: SocketAddr,
        domain: Option<String>,
    },
    UdpEcho {
        target: SocketAddr,
        domain: Option<String>,
    },
    Dns {
        target: SocketAddr,
        domain: Option<String>,
        query: Vec<u8>,
    },
}

fn dns_query(name: &str) -> Vec<u8> {
    // id, RD flag, one question; the id is rewritten per probe.
    let mut query = vec![0, 0, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.trim_end_matches('.').split('.') {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.extend_from_slice(&[0, 0, 1, 0, 1]);
    query
}

fn split_host_port(authority: &str, default_port: u16) -> (String, u16) {
    if let Some(rest) = authority.strip_prefix('[')
        && let Some((host, tail)) = rest.split_once(']')
    {
        let port = tail.strip_prefix(':').and_then(|p| p.parse().ok());
        return (host.to_owned(), port.unwrap_or(default_port));
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => {
            (host.to_owned(), port.parse().unwrap_or(default_port))
        }
        _ => (authority.to_owned(), default_port),
    }
}

/// A target travels to the exit as an IP literal or as a domain the exit
/// resolves, like honk's own domain dialing.
fn proxy_target(host: &str, port: u16) -> (SocketAddr, Option<String>) {
    match host.parse::<std::net::IpAddr>() {
        Ok(ip) => (SocketAddr::new(ip, port), None),
        Err(_) => (
            SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED), port),
            Some(host.to_owned()),
        ),
    }
}

fn http_probe(url: &str) -> anyhow::Result<Probe> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| anyhow::anyhow!("url= must be plain http:// (TLS would hide chain errors)"))?;
    let (authority, path) = match rest.find('/') {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, "/"),
    };
    let (host, port) = split_host_port(authority, 80);
    let (target, domain) = proxy_target(&host, port);
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: honk-chain-soak\r\nConnection: close\r\n\r\n"
    )
    .into_bytes();
    Ok(Probe::Http {
        target,
        domain,
        request,
    })
}

#[derive(Debug)]
enum Outcome {
    Ok {
        dial: Duration,
        first_byte: Duration,
    },
    Fail(String),
}

/// Classify an error into a stable bucket: which hop failed and how.
fn classify(error: &anyhow::Error) -> String {
    let text = format!("{error:#}");
    let hop = text
        .find("proxy chain hop `")
        .and_then(|start| {
            let tail = &text[start..];
            let open = tail.find('(')?;
            let close = tail.find(')')?;
            Some(format!("hop {}", &tail[open + 1..close]))
        })
        .unwrap_or_else(|| "chain".to_owned());
    let lower = text.to_ascii_lowercase();
    let kind = if lower.contains("timed out") || lower.contains("timeout") {
        "timeout"
    } else if lower.contains("refused") && lower.contains("connection") {
        "refused"
    } else if lower.contains("reset") {
        "reset"
    } else if lower.contains("eof") {
        "eof"
    } else if lower.contains("resolves to no node") || lower.contains("refused:") {
        "config"
    } else {
        "other"
    };
    format!("{hop} {kind}")
}

async fn run_probe(
    registry: &ProxyRegistry,
    chain_node: &Node,
    probe: &Probe,
    options: &Options,
    payload: &[u8],
) -> Outcome {
    if matches!(probe, Probe::UdpEcho { .. } | Probe::Dns { .. }) {
        return run_udp_probe(registry, chain_node, probe, options, payload).await;
    }
    let (target, domain) = match probe {
        Probe::Http { target, domain, .. } | Probe::Echo { target, domain } => (*target, domain),
        Probe::UdpEcho { .. } | Probe::Dns { .. } => unreachable!(),
    };
    let start = Instant::now();
    // Like the core: each hop gets `connect_timeout`, the dial as a whole 3x.
    let dial = tokio::time::timeout(
        options.timeout * 3,
        registry.dial(chain_node, target, domain.as_deref(), options.timeout),
    )
    .await;
    let mut stream = match dial {
        Err(_) => return Outcome::Fail("chain timeout (whole-dial deadline)".to_owned()),
        Ok(Err(error)) => return Outcome::Fail(classify(&error)),
        Ok(Ok(stream)) => stream.stream,
    };
    let dial_time = start.elapsed();

    let exchange = async {
        match probe {
            Probe::Http { request, .. } => {
                stream.write_all(request).await?;
                let mut head = [0u8; 12];
                let mut read = 0;
                while read < head.len() {
                    let n = stream.read(&mut head[read..]).await?;
                    if n == 0 {
                        anyhow::bail!("eof before HTTP status line");
                    }
                    read += n;
                }
                let first_byte = start.elapsed();
                let status = std::str::from_utf8(&head[9..12])
                    .ok()
                    .and_then(|code| code.parse::<u16>().ok())
                    .ok_or_else(|| anyhow::anyhow!("not an HTTP response"))?;
                anyhow::ensure!((200..400).contains(&status), "http status {status}");
                // Drain so the exit sees an orderly close.
                let mut sink = vec![0u8; 16 * 1024];
                while stream.read(&mut sink).await? != 0 {}
                Ok(first_byte)
            }
            Probe::UdpEcho { .. } | Probe::Dns { .. } => unreachable!(),
            Probe::Echo { .. } => {
                stream.write_all(payload).await?;
                let mut reply = vec![0u8; payload.len()];
                stream.read_exact(&mut reply[..1]).await?;
                let first_byte = start.elapsed();
                stream.read_exact(&mut reply[1..]).await?;
                anyhow::ensure!(reply == payload, "echo payload mismatch (data corruption)");
                Ok(first_byte)
            }
        }
    };
    let result = tokio::time::timeout(options.io_timeout, exchange).await;
    let outcome = match result {
        Err(_) => Outcome::Fail("io timeout".to_owned()),
        Ok(Err(error)) => {
            let text = format!("{error:#}");
            Outcome::Fail(if text.contains("mismatch") {
                "io corruption".to_owned()
            } else if text.contains("http status") {
                format!("io {text}")
            } else {
                format!("io {}", classify(&error).trim_start_matches("chain "))
            })
        }
        Ok(Ok(first_byte)) => Outcome::Ok {
            dial: dial_time,
            first_byte,
        },
    };
    if matches!(outcome, Outcome::Ok { .. }) && !options.hold.is_zero() {
        tokio::time::sleep(options.hold).await;
    }
    let _ = stream.shutdown().await;
    outcome
}

async fn run_udp_probe(
    registry: &ProxyRegistry,
    chain_node: &Node,
    probe: &Probe,
    options: &Options,
    payload: &[u8],
) -> Outcome {
    let (target, domain) = match probe {
        Probe::UdpEcho { target, domain } | Probe::Dns { target, domain, .. } => (*target, domain),
        _ => unreachable!(),
    };
    let Some(packet) = registry
        .find(honk_config::types::NodeProtocol::Chain)
        .and_then(|entry| entry.packet.clone())
    else {
        return Outcome::Fail("chain has no UDP handler".to_owned());
    };
    let start = Instant::now();
    let dial = tokio::time::timeout(
        options.timeout * 3,
        packet.dial_udp_transport(chain_node, target, domain.as_deref(), options.timeout),
    )
    .await;
    let transport = match dial {
        Err(_) => return Outcome::Fail("udp chain timeout (whole-dial deadline)".to_owned()),
        Ok(Err(error)) => return Outcome::Fail(format!("udp {}", classify(&error))),
        Ok(Ok(transport)) => transport,
    };
    let dial_time = start.elapsed();
    let exchange = async {
        let mut first_byte = None;
        let mut reply = vec![0u8; 65535];
        for index in 0..options.packets {
            let datagram: Vec<u8> = match probe {
                Probe::Dns { query, .. } => {
                    let mut query = query.clone();
                    let id = (start.elapsed().as_nanos() as u16) ^ index as u16;
                    query[..2].copy_from_slice(&id.to_be_bytes());
                    query
                }
                _ => {
                    let mut datagram = payload.to_vec();
                    datagram[0] = index as u8;
                    datagram
                }
            };
            transport.send_packet(&datagram).await?;
            let (n, _) = transport.recv_packet(&mut reply).await?;
            first_byte.get_or_insert_with(|| start.elapsed());
            match probe {
                Probe::Dns { .. } => anyhow::ensure!(
                    n >= 12 && reply[..2] == datagram[..2] && reply[2] & 0x80 != 0,
                    "dns reply does not answer the query"
                ),
                _ => anyhow::ensure!(reply[..n] == datagram[..], "udp payload mismatch (data corruption)"),
            }
        }
        Ok::<_, anyhow::Error>(first_byte.expect("at least one packet"))
    };
    match tokio::time::timeout(options.io_timeout, exchange).await {
        Err(_) => Outcome::Fail("udp io timeout (datagram lost)".to_owned()),
        Ok(Err(error)) => {
            let text = format!("{error:#}");
            Outcome::Fail(if text.contains("mismatch") {
                "udp io corruption".to_owned()
            } else if text.contains("dns reply") {
                "udp io bad dns reply".to_owned()
            } else {
                format!("udp io {}", classify(&error).trim_start_matches("chain "))
            })
        }
        Ok(Ok(first_byte)) => Outcome::Ok {
            dial: dial_time,
            first_byte,
        },
    }
}

// ---------------------------------------------------------------- stats

#[derive(Default)]
struct Window {
    ok: u64,
    fail: u64,
    dial_us: Vec<u32>,
    first_byte_us: Vec<u32>,
    errors: BTreeMap<String, u64>,
}

impl Window {
    fn record(&mut self, outcome: Outcome) {
        match outcome {
            Outcome::Ok { dial, first_byte } => {
                self.ok += 1;
                self.dial_us.push(dial.as_micros().min(u32::MAX as u128) as u32);
                self.first_byte_us
                    .push(first_byte.as_micros().min(u32::MAX as u128) as u32);
            }
            Outcome::Fail(kind) => {
                self.fail += 1;
                *self.errors.entry(kind).or_default() += 1;
            }
        }
    }

    fn merge(&mut self, other: &Window) {
        self.ok += other.ok;
        self.fail += other.fail;
        self.dial_us.extend_from_slice(&other.dial_us);
        self.first_byte_us.extend_from_slice(&other.first_byte_us);
        for (kind, count) in &other.errors {
            *self.errors.entry(kind.clone()).or_default() += count;
        }
    }
}

struct Percentiles {
    p50: f64,
    p90: f64,
    p99: f64,
    max: f64,
}

fn percentiles(samples: &mut [u32]) -> Option<Percentiles> {
    if samples.is_empty() {
        return None;
    }
    samples.sort_unstable();
    let at = |p: f64| {
        let index = ((samples.len() as f64 - 1.0) * p).round() as usize;
        samples[index] as f64 / 1000.0
    };
    Some(Percentiles {
        p50: at(0.50),
        p90: at(0.90),
        p99: at(0.99),
        max: *samples.last().unwrap() as f64 / 1000.0,
    })
}

fn open_fds() -> usize {
    std::fs::read_dir("/proc/self/fd").map_or(0, |dir| dir.count())
}

fn fmt_pct(p: &Option<Percentiles>) -> String {
    match p {
        Some(p) => format!(
            "p50 {:7.1} p90 {:7.1} p99 {:7.1} max {:7.1} ms",
            p.p50, p.p90, p.p99, p.max
        ),
        None => "-".to_owned(),
    }
}

fn success_rate(window: &Window) -> f64 {
    let total = window.ok + window.fail;
    if total == 0 {
        0.0
    } else {
        window.ok as f64 * 100.0 / total as f64
    }
}

// ---------------------------------------------------------------- self test

/// A small deterministic PRNG so the self test needs no extra dependency.
fn next_random(state: &mut u64) -> f64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    (*state >> 11) as f64 / (1u64 << 53) as f64
}

/// No-auth SOCKS5 CONNECT server with optional fault injection.
async fn local_socks(fail: f64, jitter: u64, seed: u64) -> anyhow::Result<u16> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let port = listener.local_addr()?.port();
    let rng = Arc::new(Mutex::new(seed | 1));
    tokio::spawn(async move {
        loop {
            let Ok((mut client, _)) = listener.accept().await else {
                continue;
            };
            let (drop_it, delay) = {
                let mut state = rng.lock();
                (
                    next_random(&mut state) < fail,
                    (next_random(&mut state) * jitter as f64) as u64,
                )
            };
            tokio::spawn(async move {
                if delay > 0 {
                    tokio::time::sleep(Duration::from_millis(delay)).await;
                }
                if drop_it {
                    return Ok::<_, std::io::Error>(());
                }
                let mut head = [0u8; 2];
                client.read_exact(&mut head).await?;
                let mut methods = vec![0u8; head[1] as usize];
                client.read_exact(&mut methods).await?;
                client.write_all(&[5, 0]).await?;
                let mut request = [0u8; 4];
                client.read_exact(&mut request).await?;
                let target = match request[3] {
                    1 => {
                        let mut raw = [0u8; 6];
                        client.read_exact(&mut raw).await?;
                        format!(
                            "{}:{}",
                            Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3]),
                            u16::from_be_bytes([raw[4], raw[5]])
                        )
                    }
                    3 => {
                        let mut len = [0u8; 1];
                        client.read_exact(&mut len).await?;
                        let mut raw = vec![0u8; len[0] as usize + 2];
                        client.read_exact(&mut raw).await?;
                        let (name, port) = raw.split_at(len[0] as usize);
                        format!(
                            "{}:{}",
                            String::from_utf8_lossy(name),
                            u16::from_be_bytes([port[0], port[1]])
                        )
                    }
                    _ => return Ok(()),
                };
                let Ok(mut upstream) = TcpStream::connect(target).await else {
                    client.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
                    return Ok(());
                };
                client.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
                let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
                Ok(())
            });
        }
    });
    Ok(port)
}

async fn read_socks_addr(stream: &mut (impl AsyncReadExt + Unpin)) -> std::io::Result<SocketAddr> {
    let mut atyp = [0u8; 1];
    stream.read_exact(&mut atyp).await?;
    match atyp[0] {
        1 => {
            let mut raw = [0u8; 6];
            stream.read_exact(&mut raw).await?;
            Ok(SocketAddr::from((
                Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3]),
                u16::from_be_bytes([raw[4], raw[5]]),
            )))
        }
        _ => Err(std::io::Error::other("selftest Trojan supports IPv4 targets")),
    }
}

/// Plaintext Trojan server (CONNECT and UDP) used as the selftest UDP exit.
async fn local_trojan() -> anyhow::Result<u16> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let port = listener.local_addr()?.port();
    tokio::spawn(async move {
        loop {
            let Ok((mut client, _)) = listener.accept().await else {
                continue;
            };
            tokio::spawn(async move {
                let mut auth = [0u8; 59];
                client.read_exact(&mut auth).await?;
                let command = auth[58];
                let target = read_socks_addr(&mut client).await?;
                let mut crlf = [0u8; 2];
                client.read_exact(&mut crlf).await?;
                if command == 1 {
                    let mut upstream = TcpStream::connect(target).await?;
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
                    return Ok::<_, std::io::Error>(());
                }
                let socket = Arc::new(tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?);
                let (mut read, mut write) = client.into_split();
                let replies = Arc::clone(&socket);
                let back = tokio::spawn(async move {
                    let mut buffer = vec![0u8; 65535];
                    while let Ok((n, from)) = replies.recv_from(&mut buffer).await {
                        let SocketAddr::V4(from) = from else { continue };
                        let mut frame = vec![1];
                        frame.extend_from_slice(&from.ip().octets());
                        frame.extend_from_slice(&from.port().to_be_bytes());
                        frame.extend_from_slice(&(n as u16).to_be_bytes());
                        frame.extend_from_slice(b"\r\n");
                        frame.extend_from_slice(&buffer[..n]);
                        if write.write_all(&frame).await.is_err() {
                            break;
                        }
                    }
                });
                while let Ok(destination) = read_socks_addr(&mut read).await {
                    let mut head = [0u8; 4];
                    if read.read_exact(&mut head).await.is_err() {
                        break;
                    }
                    let mut payload = vec![0u8; u16::from_be_bytes([head[0], head[1]]) as usize];
                    read.read_exact(&mut payload).await?;
                    socket.send_to(&payload, destination).await?;
                }
                back.abort();
                Ok(())
            });
        }
    });
    Ok(port)
}

async fn local_udp_echo() -> anyhow::Result<u16> {
    let socket = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let port = socket.local_addr()?.port();
    tokio::spawn(async move {
        let mut buffer = vec![0u8; 65535];
        while let Ok((n, from)) = socket.recv_from(&mut buffer).await {
            let _ = socket.send_to(&buffer[..n], from).await;
        }
    });
    Ok(port)
}

async fn local_echo() -> anyhow::Result<u16> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let port = listener.local_addr()?.port();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                continue;
            };
            tokio::spawn(async move {
                let (mut read, mut write) = stream.split();
                let _ = tokio::io::copy(&mut read, &mut write).await;
            });
        }
    });
    Ok(port)
}

// ---------------------------------------------------------------- main

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut options = parse_options();

    let mut hop_links = options.hops.clone();
    let mut exit_link = options.exit.clone();
    // Share links refuse plaintext Trojan, so the selftest builds it directly.
    let mut selftest_trojan: Option<u16> = None;
    if options.selftest {
        let mut links = Vec::new();
        for index in 0..=options.selftest_hops {
            let port = local_socks(options.fail, options.jitter, 0x9e37_79b9 + index as u64).await?;
            links.push(format!("socks5://127.0.0.1:{port}#selftest-{index}"));
        }
        exit_link = links.pop();
        hop_links = links;
        if options.udp.is_some() {
            // UDP needs an exit that frames it on the chain's stream.
            selftest_trojan = Some(local_trojan().await?);
            if options.udp.as_deref().is_none_or(str::is_empty) {
                options.udp = Some(format!("127.0.0.1:{}", local_udp_echo().await?));
            }
        } else if options.url.is_none() && options.echo.is_none() {
            options.echo = Some(format!("127.0.0.1:{}", local_echo().await?));
        }
    }
    anyhow::ensure!(!hop_links.is_empty(), "give at least one hop=LINK");

    let mut nodes = Vec::new();
    for (index, link) in hop_links.iter().enumerate() {
        nodes.push(parse_node(link, &format!("hop{index}"))?);
    }
    let exit = match selftest_trojan {
        Some(port) => {
            let mut node = Node {
                name: "selftest-trojan".to_owned(),
                address: format!("127.0.0.1:{port}"),
                host: "127.0.0.1".to_owned(),
                port,
                outbound: OutboundConfig::Trojan(honk_config::node::TrojanConfig {
                    password: Some("pw".to_owned()),
                    ..Default::default()
                }),
                ..Node::default()
            };
            node.id = node.derive_id();
            node
        }
        None => parse_node(
            exit_link
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("exit=LINK is required"))?,
            "exit",
        )?,
    };
    honk_config::chain::check_exit_protocol(&exit)
        .map_err(|reason| anyhow::anyhow!("exit cannot be chained: {reason}"))?;
    for hop in &nodes[1..] {
        honk_config::chain::check_exit_protocol(hop)
            .map_err(|reason| anyhow::anyhow!("hop {} cannot be chained: {reason}", hop.name))?;
    }

    // Hop tags must be unique for the resolver.
    let mut tags = Vec::new();
    let mut resolver = HashMap::new();
    for (index, node) in nodes.iter().enumerate() {
        let tag = format!("{}#{index}", node.name);
        resolver.insert(tag.clone(), node.clone());
        tags.push(tag);
    }
    chain::install_resolver(Arc::new(MapResolver(resolver)));
    let mut runtime_nodes = nodes.clone();
    runtime_nodes.push(exit.clone());
    runtime_nodes.dedup_by_key(|node| node.id);
    if let Ok(generation) = honk_outbound::runtime::OutboundRuntimeRegistry::build(&runtime_nodes) {
        chain::install_runtime_registry(generation.into_shared());
    }

    let chain_node = Node {
        name: "soak".to_owned(),
        outbound: OutboundConfig::Chain(ChainConfig {
            hops: tags,
            exit: ChainExit::Node(Box::new(exit.clone())),
        }),
        ..Node::default()
    };
    let registry = Arc::new(ProxyRegistry::default_resolver()?);

    let udp_target = |value: &str, default_port: u16| {
        let (host, port) = split_host_port(value, default_port);
        proxy_target(&host, port)
    };
    let probe = match (&options.url, &options.echo) {
        _ if options.dns.is_some() => {
            let (target, domain) = udp_target(options.dns.as_deref().unwrap(), 53);
            Probe::Dns {
                target,
                domain,
                query: dns_query(&options.name),
            }
        }
        _ if options.udp.as_deref().is_some_and(|value| !value.is_empty()) => {
            let (target, domain) = udp_target(options.udp.as_deref().unwrap(), 7);
            Probe::UdpEcho { target, domain }
        }
        (Some(url), _) => http_probe(url)?,
        (None, Some(echo)) => {
            let (host, port) = split_host_port(echo, 7);
            let (target, domain) = proxy_target(&host, port);
            Probe::Echo { target, domain }
        }
        (None, None) => http_probe("http://www.gstatic.com/generate_204")?,
    };
    let payload: Vec<u8> = (0..options.payload).map(|i| (i * 31 + 7) as u8).collect();

    let path = nodes
        .iter()
        .map(|node| format!("{}[{}]", node.name, node.protocol().as_str()))
        .chain(std::iter::once(format!(
            "{}[{}]",
            exit.name,
            exit.protocol().as_str()
        )))
        .collect::<Vec<_>>()
        .join(" -> ");
    println!("chain     {path}");
    println!(
        "probe     {}",
        match &probe {
            Probe::Http { domain, target, .. } =>
                format!("HTTP GET {}", domain.clone().unwrap_or_else(|| target.to_string())),
            Probe::Echo { domain, target } => format!(
                "echo {} ({} bytes)",
                domain.clone().unwrap_or_else(|| target.to_string()),
                options.payload
            ),
            Probe::UdpEcho { domain, target } => format!(
                "UDP echo {} ({} x {} bytes per probe)",
                domain.clone().unwrap_or_else(|| target.to_string()),
                options.packets,
                options.payload
            ),
            Probe::Dns { domain, target, .. } => format!(
                "UDP DNS {} A {} ({} queries per probe)",
                domain.clone().unwrap_or_else(|| target.to_string()),
                options.name,
                options.packets
            ),
        }
    );
    println!(
        "load      {} workers, gap {} ms, hold {} ms, connect timeout {:?} (chain {:?})",
        options.concurrency,
        options.gap.as_millis(),
        options.hold.as_millis(),
        options.timeout,
        options.timeout * 3
    );
    if options.selftest {
        println!(
            "selftest  {} hops, fail {:.1}% per hop, jitter {} ms",
            options.selftest_hops,
            options.fail * 100.0,
            options.jitter
        );
    }
    println!();

    let mut csv = match &options.csv {
        Some(path) => {
            let fresh = !std::path::Path::new(path).exists();
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)?;
            if fresh {
                writeln!(
                    file,
                    "elapsed_s,ok,fail,success_pct,dial_p50_ms,dial_p90_ms,dial_p99_ms,dial_max_ms,fb_p50_ms,fb_p90_ms,fb_p99_ms,fb_max_ms,live_bridges,open_fds,errors"
                )?;
            }
            Some(file)
        }
        None => None,
    };

    let window = Arc::new(Mutex::new(Window::default()));
    let stop = Arc::new(AtomicBool::new(false));
    let options = Arc::new(options);
    let chain_node = Arc::new(chain_node);
    let payload = Arc::new(payload);

    let mut workers = Vec::new();
    for _ in 0..options.concurrency {
        let (registry, chain_node, probe, options, payload, window, stop) = (
            Arc::clone(&registry),
            Arc::clone(&chain_node),
            probe.clone(),
            Arc::clone(&options),
            Arc::clone(&payload),
            Arc::clone(&window),
            Arc::clone(&stop),
        );
        workers.push(tokio::spawn(async move {
            while !stop.load(Ordering::Relaxed) {
                let outcome = run_probe(&registry, &chain_node, &probe, &options, &payload).await;
                window.lock().record(outcome);
                if !options.gap.is_zero() {
                    tokio::time::sleep(options.gap).await;
                }
            }
        }));
    }

    let started = Instant::now();
    let baseline_fds = open_fds();
    let mut total = Window::default();
    let mut ticker = tokio::time::interval(options.interval);
    ticker.tick().await;
    println!(
        "{:>7}  {:>6} {:>5} {:>7}  {:<52}  {:<52}  {:>7} {:>5}",
        "time", "ok", "fail", "succ%", "dial latency", "first byte", "bridges", "fds"
    );
    loop {
        // The last window may be shorter so the run ends on time.
        let remaining = (!options.duration.is_zero())
            .then(|| options.duration.saturating_sub(started.elapsed()));
        let interrupted = tokio::select! {
            _ = ticker.tick() => false,
            _ = tokio::time::sleep(remaining.unwrap_or(Duration::MAX / 4)), if remaining.is_some() => false,
            _ = tokio::signal::ctrl_c() => true,
        };
        let finished = !options.duration.is_zero() && started.elapsed() >= options.duration;
        let mut current = std::mem::take(&mut *window.lock());
        total.merge(&current);
        let dial = percentiles(&mut current.dial_us);
        let first_byte = percentiles(&mut current.first_byte_us);
        let elapsed = started.elapsed().as_secs();
        println!(
            "{:>6}s  {:>6} {:>5} {:>6.2}%  {:<52}  {:<52}  {:>7} {:>5}",
            elapsed,
            current.ok,
            current.fail,
            success_rate(&current),
            fmt_pct(&dial),
            fmt_pct(&first_byte),
            chain::live_bridges(),
            open_fds()
        );
        if !current.errors.is_empty() {
            let errors: Vec<String> = current
                .errors
                .iter()
                .map(|(kind, count)| format!("{kind}: {count}"))
                .collect();
            println!("         errors  {}", errors.join(", "));
        }
        if let Some(file) = csv.as_mut() {
            let cell = |p: &Option<Percentiles>, f: fn(&Percentiles) -> f64| {
                p.as_ref().map_or_else(String::new, |p| format!("{:.2}", f(p)))
            };
            let errors: Vec<String> = current
                .errors
                .iter()
                .map(|(kind, count)| format!("{kind}={count}"))
                .collect();
            writeln!(
                file,
                "{elapsed},{},{},{:.3},{},{},{},{},{},{},{},{},{},{},\"{}\"",
                current.ok,
                current.fail,
                success_rate(&current),
                cell(&dial, |p| p.p50),
                cell(&dial, |p| p.p90),
                cell(&dial, |p| p.p99),
                cell(&dial, |p| p.max),
                cell(&first_byte, |p| p.p50),
                cell(&first_byte, |p| p.p90),
                cell(&first_byte, |p| p.p99),
                cell(&first_byte, |p| p.max),
                chain::live_bridges(),
                open_fds(),
                errors.join(";")
            )?;
            file.flush()?;
        }
        if finished || interrupted {
            break;
        }
    }

    stop.store(true, Ordering::Relaxed);
    let drain = async {
        for worker in workers {
            let _ = worker.await;
        }
    };
    let _ = tokio::time::timeout(options.io_timeout + options.timeout * 3 + options.hold, drain).await;
    // Let bridges see their EOFs before the leak check.
    let settle = Instant::now();
    while chain::live_bridges() > 0 && settle.elapsed() < Duration::from_secs(35) {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let dial = percentiles(&mut total.dial_us);
    let first_byte = percentiles(&mut total.first_byte_us);
    let attempts = total.ok + total.fail;
    println!();
    println!("summary   {:.0}s, {attempts} attempts", started.elapsed().as_secs_f64());
    println!(
        "success   {} ok / {} failed = {:.3}%",
        total.ok,
        total.fail,
        success_rate(&total)
    );
    println!("dial      {}", fmt_pct(&dial));
    println!("1st byte  {}", fmt_pct(&first_byte));
    if !total.errors.is_empty() {
        println!("errors");
        let mut errors: Vec<_> = total.errors.iter().collect();
        errors.sort_by(|a, b| b.1.cmp(a.1));
        for (kind, count) in errors {
            println!(
                "          {count:>8}  {:>6.2}%  {kind}",
                *count as f64 * 100.0 / attempts.max(1) as f64
            );
        }
    }
    let leaked = chain::live_bridges();
    let fds = open_fds();
    println!(
        "leaks     live bridges after drain: {leaked}; open fds: {fds} (at start {baseline_fds})"
    );
    if leaked > 0 {
        println!("WARNING   bridge tasks outlived their flows");
        std::process::exit(2);
    }
    Ok(())
}
