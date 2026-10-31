//! Handler-level dials (health probes, delay tests, downloads) of a chained
//! node must go through its front, never straight to the landing server.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use parking_lot::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

use crate::alive::{
    AliveDialerSet, HttpProbeOutcome, HttpProbeResult, HttpProber, IpVersion, ProbeCancellation,
    ProbeDomain,
};
use crate::proxy::ProxyRegistry;
use crate::runtime::OutboundRuntimeRegistry;

/// Read one SOCKS5 CONNECT request (IPv4, or a domain holding an IPv4
/// literal) and return its target.
async fn socks_handshake(client: &mut tokio::net::TcpStream) -> Option<SocketAddr> {
    let mut head = [0u8; 2];
    client.read_exact(&mut head).await.ok()?;
    let mut methods = vec![0u8; head[1] as usize];
    client.read_exact(&mut methods).await.ok()?;
    client.write_all(&[5, 0]).await.ok()?;
    let mut req = [0u8; 4];
    client.read_exact(&mut req).await.ok()?;
    match req[3] {
        1 => {
            let mut raw = [0u8; 6];
            client.read_exact(&mut raw).await.ok()?;
            Some(SocketAddr::from((
                [raw[0], raw[1], raw[2], raw[3]],
                u16::from_be_bytes([raw[4], raw[5]]),
            )))
        }
        3 => {
            let mut len = [0u8; 1];
            client.read_exact(&mut len).await.ok()?;
            let mut raw = vec![0u8; len[0] as usize + 2];
            client.read_exact(&mut raw).await.ok()?;
            let (host, port) = raw.split_at(len[0] as usize);
            let ip: std::net::IpAddr = std::str::from_utf8(host).ok()?.parse().ok()?;
            Some(SocketAddr::new(ip, u16::from_be_bytes([port[0], port[1]])))
        }
        _ => None,
    }
}

#[derive(Default)]
struct Log {
    /// Targets requested from this server.
    targets: Mutex<Vec<SocketAddr>>,
    /// Peer address of every accepted connection.
    peers: Mutex<Vec<SocketAddr>>,
    /// Local address of every upstream connection this server opened.
    upstream_locals: Mutex<Vec<SocketAddr>>,
}

/// SOCKS5 server. When `up` is false it drops connections at once (a dead
/// front). Targets equal to `alias` are redirected to `real`, so a server
/// published under an unroutable alias is reachable only through here.
async fn socks_server(
    up: Arc<AtomicBool>,
    alias: Option<(SocketAddr, SocketAddr)>,
    log: Arc<Log>,
) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut client, peer)) = listener.accept().await else {
                return;
            };
            log.peers.lock().push(peer);
            if !up.load(Ordering::SeqCst) {
                drop(client);
                continue;
            }
            let log = Arc::clone(&log);
            tokio::spawn(async move {
                let Some(target) = socks_handshake(&mut client).await else {
                    return;
                };
                log.targets.lock().push(target);
                let real = match alias {
                    Some((from, to)) if from == target => to,
                    _ => target,
                };
                let Ok(mut upstream) = tokio::net::TcpStream::connect(real).await else {
                    return;
                };
                if let Ok(local) = upstream.local_addr() {
                    log.upstream_locals.lock().push(local);
                }
                if client
                    .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                    .await
                    .is_err()
                {
                    return;
                }
                let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
            });
        }
    });
    addr
}

/// HTTP server answering every request with 204.
async fn http_server() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut byte = [0u8; 1];
                loop {
                    if stream.read_exact(&mut byte).await.is_err() {
                        return;
                    }
                    buf.push(byte[0]);
                    if buf.ends_with(b"\r\n\r\n") {
                        buf.clear();
                        if stream
                            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                }
            });
        }
    });
    addr
}

/// The core HTTP prober's dial path in miniature: the registry's public TCP
/// handler, the node's generation runtime, `measure_http_probe`.
struct RegistryProber {
    registry: Arc<ProxyRegistry>,
    generation: Arc<OutboundRuntimeRegistry>,
}

impl HttpProber for RegistryProber {
    fn probe_http(
        &self,
        node_id: Uuid,
        addr: SocketAddr,
        url: &str,
        timeout: Duration,
        _cancel: ProbeCancellation,
    ) -> Pin<Box<dyn Future<Output = HttpProbeOutcome> + Send + 'static>> {
        let registry = Arc::clone(&self.registry);
        let runtime = self.generation.get(&node_id);
        let request = crate::urltest::health_http_probe_request(url, "GET");
        Box::pin(async move {
            let (Some(runtime), Ok(request)) = (runtime, request) else {
                return HttpProbeResult::SetupFailure("setup".into()).into();
            };
            let entry = registry.find(runtime.node.protocol()).unwrap();
            match crate::urltest::measure_http_probe(
                &runtime,
                entry.tcp.as_ref(),
                &request,
                addr,
                None,
                timeout,
                timeout,
                None,
            )
            .await
            {
                Ok(sample) => HttpProbeResult::WarmSuccess(sample.latency).into(),
                Err(error) => HttpProbeResult::ExchangeFailure(format!("{error:#}")).into(),
            }
        })
    }
}

/// Tests install a process-wide runtime cell; run them one at a time.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct Fixture {
    front_up: Arc<AtomicBool>,
    front: Arc<Log>,
    land: Arc<Log>,
    land_id: Uuid,
    http: SocketAddr,
    registry: Arc<ProxyRegistry>,
    generation: Arc<OutboundRuntimeRegistry>,
    _cell: crate::runtime::SharedRuntimeRegistry,
}

/// Front `hc_a` (SOCKS5) and landing `hc_b` (SOCKS5, `dialer-proxy=hc_a`).
/// `hc_b` is published under TEST-NET-1 (192.0.2.1), unroutable from this
/// host; only `hc_a` maps that address to the real listener.
async fn fixture() -> Fixture {
    let front_up = Arc::new(AtomicBool::new(true));
    let front = Arc::new(Log::default());
    let land = Arc::new(Log::default());
    let land_real = socks_server(Arc::new(AtomicBool::new(true)), None, Arc::clone(&land)).await;
    let land_alias = SocketAddr::from(([192, 0, 2, 1], land_real.port()));
    let front_addr = socks_server(
        Arc::clone(&front_up),
        Some((land_alias, land_real)),
        Arc::clone(&front),
    )
    .await;
    let http = http_server().await;
    let config = honk_config::parser::parse_dae_config_with_detailed_diagnostics(
        &format!(
            "node {{\n hc_a: 'socks5://{front_addr}'\n hc_b: 'socks5://{land_alias}?dialer-proxy=hc_a'\n}}\n"
        ),
        &mut Vec::new(),
    )
    .unwrap();
    config.validate_detailed().unwrap();
    let land_id = config.nodes.iter().find(|n| n.name == "hc_b").unwrap().id;
    let generation = Arc::new(OutboundRuntimeRegistry::build(&config.nodes).unwrap());
    let cell = Arc::new(parking_lot::RwLock::new(Arc::clone(&generation)));
    super::install_runtime_registry(&cell);
    Fixture {
        front_up,
        front,
        land,
        land_id,
        http,
        registry: Arc::new(ProxyRegistry::default_resolver().unwrap()),
        generation,
        _cell: cell,
    }
}

impl Fixture {
    /// Every connection the landing server accepted came from the front's
    /// upstream socket: nothing on this host dialed it directly.
    fn assert_land_only_via_front(&self) {
        let upstream = self.front.upstream_locals.lock().clone();
        let peers = self.land.peers.lock().clone();
        for peer in &peers {
            assert!(
                upstream.contains(peer),
                "landing server saw a direct connection from {peer}; front upstreams {upstream:?}"
            );
        }
    }
}

#[tokio::test]
async fn chained_node_health_follows_its_front() {
    let _serial = SERIAL.lock().await;
    let f = fixture().await;
    let set = AliveDialerSet::new();
    set.set_http_probe(
        Arc::new(RegistryProber {
            registry: Arc::clone(&f.registry),
            generation: Arc::clone(&f.generation),
        }),
        format!("http://{}/", f.http),
        "GET".into(),
    )
    .await;
    set.register_node(f.land_id, "hc_b".into(), "192.0.2.1:1".into());
    set.expire_grace_for_test(f.land_id);
    let timeout = Duration::from_secs(2);
    let alive = || set.is_alive_for(f.land_id, ProbeDomain::Tcp, IpVersion::V4);

    // B is reachable only through A: probes succeed via the chain.
    assert!(set.probe_node(f.land_id, timeout).await, "probe via front");
    assert!(alive());
    assert!(!f.front.targets.lock().is_empty(), "front carried the hop");
    assert!(!f.land.peers.lock().is_empty(), "landing node was used");
    f.assert_land_only_via_front();

    // A down: B must go unavailable, never reached directly.
    f.front_up.store(false, Ordering::SeqCst);
    let land_before = f.land.peers.lock().len();
    for _ in 0..6 {
        set.probe_node(f.land_id, timeout).await;
        if !alive() {
            break;
        }
    }
    assert!(
        !alive(),
        "chained node must be unavailable while its front is down"
    );
    assert_eq!(
        f.land.peers.lock().len(),
        land_before,
        "no connection reached the landing node while the front was down"
    );

    // A back: B recovers.
    f.front_up.store(true, Ordering::SeqCst);
    for _ in 0..6 {
        set.probe_node(f.land_id, timeout).await;
        if alive() {
            break;
        }
    }
    assert!(alive(), "chained node recovers once its front is back");
    f.assert_land_only_via_front();
}

/// Every handler-level entry point used by delay tests, native probes and
/// download tunnels dials through the front.
#[tokio::test]
async fn handler_level_dials_of_a_chained_node_use_the_front() {
    let _serial = SERIAL.lock().await;
    let f = fixture().await;
    let runtime = f.generation.get(&f.land_id).unwrap();
    let node = runtime.node.as_ref().clone();
    let entry = f.registry.find(node.protocol()).unwrap();
    let timeout = Duration::from_secs(2);

    let mut stream = entry
        .tcp
        .dial_runtime(Arc::clone(&runtime), f.http, None, timeout)
        .await
        .expect("dial_runtime through front");
    stream
        .stream
        .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap();
    let mut head = [0u8; 12];
    stream.stream.read_exact(&mut head).await.unwrap();
    assert_eq!(&head, b"HTTP/1.1 204");
    drop(stream);

    entry
        .tcp
        .dial(&node, f.http, None, timeout)
        .await
        .expect("node dial through front");

    let latency = crate::urltest::urltest_node_in_generation_with_feedback(
        &f.generation,
        &node,
        entry.tcp.as_ref(),
        entry.warmable.as_deref(),
        &format!("http://{}/", f.http),
        timeout,
        &crate::group::GroupManager::new(&[], std::slice::from_ref(&node)),
        ProbeCancellation::default(),
    )
    .await;
    assert!(latency.is_ok(), "delay test via front: {latency:?}");

    let udp = entry
        .packet
        .as_ref()
        .unwrap()
        .dial_udp_transport_runtime(Arc::clone(&runtime), f.http, None, timeout)
        .await
        .map(|_| ())
        .expect_err("UDP must not leave directly (front has no UDP relay)");
    assert!(udp.to_string().contains("detour"), "{udp}");
    assert!(
        !entry
            .probeable
            .as_ref()
            .unwrap()
            .test_connectivity(&node)
            .await,
        "raw reachability must not connect to a chained server"
    );

    assert!(f.front.targets.lock().len() >= 3);
    f.assert_land_only_via_front();

    // Front down: every path fails closed.
    f.front_up.store(false, Ordering::SeqCst);
    let land_before = f.land.peers.lock().len();
    assert!(
        entry
            .tcp
            .dial_runtime(Arc::clone(&runtime), f.http, None, timeout)
            .await
            .is_err()
    );
    assert!(entry.tcp.dial(&node, f.http, None, timeout).await.is_err());
    assert_eq!(f.land.peers.lock().len(), land_before);
}

async fn http_204(stream: &mut crate::proxy::ProxyStream) {
    stream
        .stream
        .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap();
    let mut head = [0u8; 12];
    stream.stream.read_exact(&mut head).await.unwrap();
    assert_eq!(&head, b"HTTP/1.1 204");
    let mut rest = [0u8; 2];
    // Drain the remaining header bytes so the next request starts clean.
    let mut tail = Vec::new();
    while !tail.ends_with(b"\r\n\r\n") {
        stream.stream.read_exact(&mut rest[..1]).await.unwrap();
        tail.push(rest[0]);
    }
}

/// A front that is a selector group: each new connection uses the group's
/// selection at connect time; a switch leaves open connections alone.
#[tokio::test]
async fn group_front_follows_the_current_selection() {
    let _serial = SERIAL.lock().await;
    let land = Arc::new(Log::default());
    let land_real = socks_server(Arc::new(AtomicBool::new(true)), None, Arc::clone(&land)).await;
    let land_alias = SocketAddr::from(([192, 0, 2, 1], land_real.port()));
    let (a1, a2) = (Arc::new(Log::default()), Arc::new(Log::default()));
    let a1_addr = socks_server(
        Arc::new(AtomicBool::new(true)),
        Some((land_alias, land_real)),
        Arc::clone(&a1),
    )
    .await;
    let a2_addr = socks_server(
        Arc::new(AtomicBool::new(true)),
        Some((land_alias, land_real)),
        Arc::clone(&a2),
    )
    .await;
    let http = http_server().await;
    let config = honk_config::parser::parse_dae_config_with_detailed_diagnostics(
        &format!(
            "node {{\n ga1: 'socks5://{a1_addr}'\n ga2: 'socks5://{a2_addr}'\n gb: 'socks5://{land_alias}?detour=gfronts'\n}}\n\
             group {{\n gfronts {{\n filter: name(ga1, ga2)\n policy: selector\n }}\n}}\n"
        ),
        &mut Vec::new(),
    )
    .unwrap();
    config.validate_detailed().unwrap();
    let land_id = config.nodes.iter().find(|n| n.name == "gb").unwrap().id;
    let generation = Arc::new(OutboundRuntimeRegistry::build(&config.nodes).unwrap());
    let cell = Arc::new(parking_lot::RwLock::new(Arc::clone(&generation)));
    super::install_runtime_registry(&cell);
    let manager = Arc::new(crate::group::GroupManager::new(
        &config.groups,
        &config.nodes,
    ));
    super::install_group_manager(Arc::new(parking_lot::RwLock::new(Arc::clone(&manager))));
    let registry = ProxyRegistry::default_resolver().unwrap();
    let runtime = generation.get(&land_id).unwrap();
    let entry = registry.find(runtime.node.protocol()).unwrap();
    let timeout = Duration::from_secs(2);
    let select = |member: &str| {
        manager
            .set_selector_choice("gfronts", member, crate::group::SelectorNetworks::Both)
            .unwrap();
    };

    select("ga1");
    // Connection path (registry hook, pinned generation) and handler path.
    let mut held = registry
        .dial_runtime(Arc::clone(&generation), land_id, http, None, timeout)
        .await
        .expect("registry dial via ga1");
    http_204(&mut held).await;
    let mut probe = entry
        .tcp
        .dial_runtime(Arc::clone(&runtime), http, None, timeout)
        .await
        .expect("handler dial via ga1");
    http_204(&mut probe).await;
    drop(probe);
    assert_eq!(a1.targets.lock().len(), 2);
    assert!(a2.targets.lock().is_empty());

    select("ga2");
    let mut fresh = registry
        .dial_runtime(Arc::clone(&generation), land_id, http, None, timeout)
        .await
        .expect("registry dial via ga2");
    http_204(&mut fresh).await;
    let latency = crate::urltest::urltest_node_in_generation_with_feedback(
        &generation,
        &runtime.node,
        entry.tcp.as_ref(),
        entry.warmable.as_deref(),
        &format!("http://{http}/"),
        timeout,
        &manager,
        ProbeCancellation::default(),
    )
    .await;
    assert!(latency.is_ok(), "delay test via ga2: {latency:?}");
    assert_eq!(a1.targets.lock().len(), 2, "no new hop through ga1");
    assert_eq!(a2.targets.lock().len(), 2);
    // The connection opened before the switch still works through ga1.
    http_204(&mut held).await;

    let upstream: Vec<_> = a1
        .upstream_locals
        .lock()
        .iter()
        .chain(a2.upstream_locals.lock().iter())
        .copied()
        .collect();
    for peer in land.peers.lock().iter() {
        assert!(upstream.contains(peer), "direct connection from {peer}");
    }
}

/// Handler-level dials resolve node-named fronts in the caller's pinned
/// generation, not whatever generation is live.
#[tokio::test]
async fn pinned_generation_decides_the_front() {
    let _serial = SERIAL.lock().await;
    let land = Arc::new(Log::default());
    let land_real = socks_server(Arc::new(AtomicBool::new(true)), None, Arc::clone(&land)).await;
    let land_alias = SocketAddr::from(([192, 0, 2, 1], land_real.port()));
    let (old, new) = (Arc::new(Log::default()), Arc::new(Log::default()));
    let mut addrs = Vec::new();
    for log in [&old, &new] {
        addrs.push(
            socks_server(
                Arc::new(AtomicBool::new(true)),
                Some((land_alias, land_real)),
                Arc::clone(log),
            )
            .await,
        );
    }
    let http = http_server().await;
    let build = |front: SocketAddr| {
        let config = honk_config::parser::parse_dae_config_with_detailed_diagnostics(
            &format!(
                "node {{\n pa: 'socks5://{front}'\n pb: 'socks5://{land_alias}?detour=pa'\n}}\n"
            ),
            &mut Vec::new(),
        )
        .unwrap();
        Arc::new(OutboundRuntimeRegistry::build(&config.nodes).unwrap())
    };
    let (gen_old, gen_new) = (build(addrs[0]), build(addrs[1]));
    let cell = Arc::new(parking_lot::RwLock::new(Arc::clone(&gen_new)));
    super::install_runtime_registry(&cell);
    let registry = ProxyRegistry::default_resolver().unwrap();
    let runtime = gen_old
        .values()
        .find(|runtime| runtime.node.name == "pb")
        .unwrap();
    let entry = registry.find(runtime.node.protocol()).unwrap();
    let timeout = Duration::from_secs(2);

    super::pin_generation(
        Arc::clone(&gen_old),
        entry
            .tcp
            .dial_runtime(Arc::clone(runtime), http, None, timeout),
    )
    .await
    .expect("pinned dial");
    assert_eq!(old.targets.lock().len(), 1);
    assert!(new.targets.lock().is_empty());

    entry
        .tcp
        .dial_runtime(Arc::clone(runtime), http, None, timeout)
        .await
        .expect("unpinned dial");
    assert_eq!(new.targets.lock().len(), 1, "unpinned uses the live one");
}

/// Plain (TLS-off) Trojan server that echoes UDP frames for IPv4 targets.
/// Records the peer of every accepted connection.
async fn trojan_udp_echo(password: &'static str, log: Arc<Log>) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut tcp, peer)) = listener.accept().await else {
                return;
            };
            log.peers.lock().push(peer);
            tokio::spawn(async move {
                // sha224 hex + CRLF + CMD_UDP + IPv4 addr + CRLF
                let mut request = vec![0u8; 56 + 2 + 1 + 7 + 2];
                if tcp.read_exact(&mut request).await.is_err() {
                    return;
                }
                assert_eq!(
                    &request[..56],
                    super::super::trojan::hex_sha224(password).as_bytes()
                );
                assert_eq!(request[58], 3, "UDP command");
                loop {
                    // ATYP(1) + IPv4(4) + port(2) + len(2) + CRLF(2)
                    let mut head = [0u8; 11];
                    if tcp.read_exact(&mut head).await.is_err() {
                        return;
                    }
                    let len = u16::from_be_bytes([head[7], head[8]]) as usize;
                    let mut payload = vec![0u8; len];
                    tcp.read_exact(&mut payload).await.unwrap();
                    let mut reply = head.to_vec();
                    reply.extend_from_slice(&payload);
                    if tcp.write_all(&reply).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    addr
}

struct UdpFixture {
    front_up: Arc<AtomicBool>,
    front: Arc<Log>,
    land: Arc<Log>,
    registry: Arc<ProxyRegistry>,
    generation: Arc<OutboundRuntimeRegistry>,
    land_id: Uuid,
    ss_id: Uuid,
    _cell: crate::runtime::SharedRuntimeRegistry,
}

/// Front `ut_a` (SOCKS5, TCP only), landing `ut_b` (Trojan, TLS off,
/// `detour=ut_a`) published under an unroutable alias, and a Shadowsocks
/// landing `ut_ss` behind the same front (native UDP: must be refused).
async fn udp_fixture() -> UdpFixture {
    let front_up = Arc::new(AtomicBool::new(true));
    let front = Arc::new(Log::default());
    let land = Arc::new(Log::default());
    let land_real = trojan_udp_echo("udp-chain", Arc::clone(&land)).await;
    let land_alias = SocketAddr::from(([192, 0, 2, 1], land_real.port()));
    let front_addr = socks_server(
        Arc::clone(&front_up),
        Some((land_alias, land_real)),
        Arc::clone(&front),
    )
    .await;
    let mut config = honk_config::parser::parse_dae_config_with_detailed_diagnostics(
        &format!(
            "node {{\n ut_a: 'socks5://{front_addr}'\n ut_ss: 'ss://YWVzLTEyOC1nY206cHc=@192.0.2.1:8388?dialer-proxy=ut_a'\n}}\n"
        ),
        &mut Vec::new(),
    )
    .unwrap();
    let mut land_node = honk_config::node::Node {
        name: "ut_b".into(),
        address: land_alias.ip().to_string(),
        host: land_alias.ip().to_string(),
        port: land_alias.port(),
        detour: Some("ut_a".into()),
        outbound: honk_config::node::OutboundConfig::Trojan(honk_config::node::TrojanConfig {
            password: Some("udp-chain".into()),
            ..Default::default()
        }),
        ..Default::default()
    };
    land_node.tls_mut().unwrap().enabled = false;
    land_node.id = land_node.derive_id();
    let land_id = land_node.id;
    config.nodes.push(land_node);
    config.validate_detailed().unwrap();
    let ss_id = config.nodes.iter().find(|n| n.name == "ut_ss").unwrap().id;
    let generation = Arc::new(OutboundRuntimeRegistry::build(&config.nodes).unwrap());
    let cell = Arc::new(parking_lot::RwLock::new(Arc::clone(&generation)));
    super::install_runtime_registry(&cell);
    UdpFixture {
        front_up,
        front,
        land,
        registry: Arc::new(ProxyRegistry::default_resolver().unwrap()),
        generation,
        land_id,
        ss_id,
        _cell: cell,
    }
}

async fn udp_echo_once(transport: &dyn crate::proxy::PacketTransport, target: SocketAddr) {
    transport.send_packet(b"ping").await.unwrap();
    let mut buf = [0u8; 64];
    let (n, peer) = tokio::time::timeout(Duration::from_secs(3), transport.recv_packet(&mut buf))
        .await
        .expect("echo reply")
        .unwrap();
    assert_eq!((peer, &buf[..n]), (target, &b"ping"[..]));
}

/// A UDP-over-TCP landing carries UDP through its front's TCP chain, for
/// both per-flow and shared-source transports, and fails closed (never
/// direct) when the front is down. A native-UDP landing is refused.
#[tokio::test]
async fn udp_over_tcp_landing_rides_the_front_chain() {
    let _serial = SERIAL.lock().await;
    let f = udp_fixture().await;
    let runtime = f.generation.get(&f.land_id).unwrap();
    assert!(runtime.udp_capable, "chained trojan is UDP-capable");
    let entry = f.registry.find(runtime.node.protocol()).unwrap();
    let target: SocketAddr = "198.51.100.7:53".parse().unwrap();
    let timeout = Duration::from_secs(2);

    let flow = f
        .registry
        .dial_udp_transport_runtime(Arc::clone(&f.generation), f.land_id, target, None, timeout)
        .await
        .expect("per-flow UDP through front");
    udp_echo_once(flow.as_ref(), target).await;

    let shared = entry
        .shared
        .as_ref()
        .unwrap()
        .prepare_shared_source(Arc::clone(&runtime), target, None, timeout, false)
        .await
        .expect("shared-source UDP through front")
        .commit()
        .await
        .unwrap();
    udp_echo_once(shared.as_ref(), target).await;

    let speculative = entry
        .packet
        .as_ref()
        .unwrap()
        .dial_udp_transport_speculative_runtime(Arc::clone(&runtime), target, None, timeout)
        .await
        .unwrap()
        .commit()
        .await
        .unwrap();
    udp_echo_once(speculative.as_ref(), target).await;

    assert!(f.front.targets.lock().len() >= 3, "front carried every hop");
    let upstream = f.front.upstream_locals.lock().clone();
    for peer in f.land.peers.lock().iter() {
        assert!(upstream.contains(peer), "direct connection from {peer}");
    }

    // Native-UDP landing behind a front with no UDP relay: fails closed.
    let ss = f.generation.get(&f.ss_id).unwrap();
    let err = f
        .registry
        .dial_udp_transport_runtime(Arc::clone(&f.generation), f.ss_id, target, None, timeout)
        .await
        .map(|_| ())
        .expect_err("ss UDP needs a front UDP relay");
    assert!(err.to_string().contains("detour"), "{err}");
    let err = f
        .registry
        .find(ss.node.protocol())
        .unwrap()
        .packet
        .as_ref()
        .unwrap()
        .dial_udp_transport(&ss.node, target, None, timeout)
        .await
        .map(|_| ())
        .expect_err("ss UDP needs a front UDP relay");
    assert!(err.to_string().contains("detour"), "{err}");

    // Front down: UDP fails, nothing reaches the landing server.
    f.front_up.store(false, Ordering::SeqCst);
    let before = f.land.peers.lock().len();
    assert!(
        f.registry
            .dial_udp_transport_runtime(Arc::clone(&f.generation), f.land_id, target, None, timeout)
            .await
            .is_err()
    );
    assert!(
        entry
            .shared
            .as_ref()
            .unwrap()
            .prepare_shared_source(Arc::clone(&runtime), target, None, timeout, false)
            .await
            .is_err()
    );
    assert_eq!(f.land.peers.lock().len(), before);
}

// ---------------------------------------------------------------------------
// Native UDP landings (Shadowsocks, SOCKS5) over a front's UDP relay.
// ---------------------------------------------------------------------------

#[derive(Default)]
struct UdpLog {
    /// UDP targets this relay forwarded to (as named by the client).
    udp_targets: Mutex<Vec<SocketAddr>>,
    /// Local addresses of this relay's upstream UDP sockets.
    udp_locals: Mutex<Vec<SocketAddr>>,
    /// Every client address a datagram arrived from.
    udp_peers: Mutex<Vec<SocketAddr>>,
    /// TCP CONNECT targets.
    tcp_targets: Mutex<Vec<SocketAddr>>,
}

/// Maps a published alias onto the real loopback address. An alias with
/// port 0 is a wildcard for its IP and keeps the port (relay ports are only
/// known per association). Exact entries win over wildcards.
fn alias_of(aliases: &[(SocketAddr, SocketAddr)], addr: SocketAddr) -> SocketAddr {
    if let Some((_, to)) = aliases.iter().find(|(from, _)| *from == addr) {
        return *to;
    }
    aliases
        .iter()
        .find(|(from, _)| from.port() == 0 && from.ip() == addr.ip())
        .map_or(addr, |(_, to)| SocketAddr::new(to.ip(), addr.port()))
}
fn unalias(aliases: &[(SocketAddr, SocketAddr)], addr: SocketAddr) -> SocketAddr {
    if let Some((from, _)) = aliases.iter().find(|(_, to)| *to == addr) {
        return *from;
    }
    aliases
        .iter()
        .find(|(_, to)| to.port() == 0 && to.ip() == addr.ip())
        .map_or(addr, |(from, _)| SocketAddr::new(from.ip(), addr.port()))
}
/// SOCKS5 UDP request/reply header + payload (RFC 1928 section 7).
fn socks_udp_frame(addr: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![0, 0, 0];
    match addr {
        SocketAddr::V4(v4) => {
            frame.push(1);
            frame.extend_from_slice(&v4.ip().octets());
        }
        SocketAddr::V6(v6) => {
            frame.push(4);
            frame.extend_from_slice(&v6.ip().octets());
        }
    }
    frame.extend_from_slice(&addr.port().to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}
fn parse_socks_udp_frame(frame: &[u8]) -> Option<(SocketAddr, &[u8])> {
    if frame.len() < 4 || frame[2] != 0 {
        return None;
    }
    let (ip, rest): (std::net::IpAddr, &[u8]) = match frame[3] {
        1 if frame.len() >= 10 => {
            let raw: [u8; 4] = frame[4..8].try_into().ok()?;
            (raw.into(), &frame[8..])
        }
        4 if frame.len() >= 22 => {
            let raw: [u8; 16] = frame[4..20].try_into().ok()?;
            (raw.into(), &frame[20..])
        }
        3 => {
            let len = *frame.get(4)? as usize;
            let host = std::str::from_utf8(frame.get(5..5 + len)?).ok()?;
            (host.parse().ok()?, frame.get(5 + len..)?)
        }
        _ => return None,
    };
    let port = u16::from_be_bytes([*rest.first()?, *rest.get(1)?]);
    Some((SocketAddr::new(ip, port), &rest[2..]))
}
async fn socks_udp_server(
    up: Arc<AtomicBool>,
    aliases: Vec<(SocketAddr, SocketAddr)>,
    log: Arc<UdpLog>,
) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let aliases = Arc::new(aliases);
    tokio::spawn(async move {
        loop {
            let Ok((mut client, _)) = listener.accept().await else {
                return;
            };
            if !up.load(Ordering::SeqCst) {
                drop(client);
                continue;
            }
            let (log, aliases) = (Arc::clone(&log), Arc::clone(&aliases));
            tokio::spawn(async move {
                let mut head = [0u8; 2];
                client.read_exact(&mut head).await.ok()?;
                let mut methods = vec![0u8; head[1] as usize];
                client.read_exact(&mut methods).await.ok()?;
                client.write_all(&[5, 0]).await.ok()?;
                let mut req = [0u8; 4];
                client.read_exact(&mut req).await.ok()?;
                let target = match req[3] {
                    1 => {
                        let mut raw = [0u8; 6];
                        client.read_exact(&mut raw).await.ok()?;
                        SocketAddr::from((
                            [raw[0], raw[1], raw[2], raw[3]],
                            u16::from_be_bytes([raw[4], raw[5]]),
                        ))
                    }
                    3 => {
                        let mut len = [0u8; 1];
                        client.read_exact(&mut len).await.ok()?;
                        let mut raw = vec![0u8; len[0] as usize + 2];
                        client.read_exact(&mut raw).await.ok()?;
                        let (host, port) = raw.split_at(len[0] as usize);
                        let ip: std::net::IpAddr = std::str::from_utf8(host).ok()?.parse().ok()?;
                        SocketAddr::new(ip, u16::from_be_bytes([port[0], port[1]]))
                    }
                    _ => return None,
                };
                if req[1] == 1 {
                    log.tcp_targets.lock().push(target);
                    let mut upstream = tokio::net::TcpStream::connect(alias_of(&aliases, target))
                        .await
                        .ok()?;
                    client
                        .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                        .await
                        .ok()?;
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
                    return Some(());
                }
                // UDP ASSOCIATE.
                let relay = tokio::net::UdpSocket::bind("127.0.0.1:0").await.ok()?;
                let upstream = tokio::net::UdpSocket::bind("127.0.0.1:0").await.ok()?;
                log.udp_locals.lock().push(upstream.local_addr().ok()?);
                let port = relay.local_addr().ok()?.port().to_be_bytes();
                client
                    .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, port[0], port[1]])
                    .await
                    .ok()?;
                let mut client_peer = None;
                let (mut a, mut b) = ([0u8; 2048], [0u8; 2048]);
                let mut probe = [0u8; 1];
                loop {
                    tokio::select! {
                        got = relay.recv_from(&mut a) => {
                            let (n, peer) = got.ok()?;
                            log.udp_peers.lock().push(peer);
                            client_peer = Some(peer);
                            let Some((target, payload)) = parse_socks_udp_frame(&a[..n]) else {
                                continue;
                            };
                            log.udp_targets.lock().push(target);
                            let _ = upstream.send_to(payload, alias_of(&aliases, target)).await;
                        }
                        got = upstream.recv_from(&mut b) => {
                            let (n, source) = got.ok()?;
                            if let Some(peer) = client_peer {
                                let frame = socks_udp_frame(unalias(&aliases, source), &b[..n]);
                                let _ = relay.send_to(&frame, peer).await;
                            }
                        }
                        read = client.read(&mut probe) => {
                            if matches!(read, Ok(0) | Err(_)) {
                                return Some(());
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

/// Shadowsocks (aes-128-gcm, password `pw`) UDP server that echoes every
/// payload back from its requested target; logs client addresses.
async fn ss_udp_echo(log: Arc<UdpLog>) -> SocketAddr {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let crypto = crate::proxy::shadowsocks::LegacyUdpCrypto::new("aes-128-gcm", "pw").unwrap();
        let mut buf = [0u8; 4096];
        loop {
            let Ok((n, peer)) = socket.recv_from(&mut buf).await else {
                return;
            };
            log.udp_peers.lock().push(peer);
            let Ok(datagram) = crypto.open(&buf[..n]) else {
                continue;
            };
            let crate::proxy::addr::SocksAddr::V4(target) = datagram.peer else {
                continue;
            };
            log.udp_targets.lock().push(SocketAddr::V4(target));
            let socks = crate::proxy::addr::encode_address(SocketAddr::V4(target), None).unwrap();
            let reply = crypto.seal(&socks, datagram.payload()).unwrap();
            let _ = socket.send_to(&reply, peer).await;
        }
    });
    addr
}

/// Plain UDP echo server.
async fn udp_echo() -> SocketAddr {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        while let Ok((n, peer)) = socket.recv_from(&mut buf).await {
            let _ = socket.send_to(&buf[..n], peer).await;
        }
    });
    addr
}

fn install_generation(config: &honk_config::config::Config) -> Arc<OutboundRuntimeRegistry> {
    let generation = Arc::new(OutboundRuntimeRegistry::build(&config.nodes).unwrap());
    let cell = Arc::new(parking_lot::RwLock::new(Arc::clone(&generation)));
    super::install_runtime_registry(&cell);
    std::mem::forget(cell);
    generation
}

fn node_id(config: &honk_config::config::Config, name: &str) -> Uuid {
    config.nodes.iter().find(|n| n.name == name).unwrap().id
}

/// Shadowsocks and SOCKS5 landings send their native datagrams through the
/// front's UDP relay (per-flow and shared-source), a landing that is itself
/// chained can serve as a UDP front (nested), and the landing servers only
/// ever see the fronts' relay sockets.
#[tokio::test]
async fn native_udp_landings_ride_the_front_udp_relay() {
    let _serial = SERIAL.lock().await;
    let ss_log = Arc::new(UdpLog::default());
    let ss_real = ss_udp_echo(Arc::clone(&ss_log)).await;
    let ss_alias = SocketAddr::from(([192, 0, 2, 1], ss_real.port()));
    let echo = udp_echo().await;
    // The nested landing uses a second alias of the same server so the two
    // ss nodes keep distinct ids.
    let ss_alias2 = SocketAddr::from(([192, 0, 2, 3], ss_real.port()));

    // B: SOCKS5 landing (published under an alias, reachable via A only)
    // that also relays to the ss landing for the nested chain.
    let b_log = Arc::new(UdpLog::default());
    let b_real = socks_udp_server(
        Arc::new(AtomicBool::new(true)),
        vec![(ss_alias2, ss_real)],
        Arc::clone(&b_log),
    )
    .await;
    let b_alias = SocketAddr::from(([192, 0, 2, 2], b_real.port()));
    let a_log = Arc::new(UdpLog::default());
    let a_addr = socks_udp_server(
        Arc::new(AtomicBool::new(true)),
        vec![
            (ss_alias, ss_real),
            (b_alias, b_real),
            (
                SocketAddr::new(b_alias.ip(), 0),
                SocketAddr::from(([127, 0, 0, 1], 0)),
            ),
        ],
        Arc::clone(&a_log),
    )
    .await;
    // B's UDP relay port is only known per association: A maps any port on
    // B's alias IP to loopback.
    let config = honk_config::parser::parse_dae_config_with_detailed_diagnostics(
        &format!(
            "node {{\n na: 'socks5://{a_addr}'\n nss: 'ss://YWVzLTEyOC1nY206cHc=@{ss_alias}?detour=na'\n\
             nsk: 'socks5://{b_alias}?detour=na'\n nnest: 'ss://YWVzLTEyOC1nY206cHc=@{ss_alias2}?detour=nsk'\n}}\n"
        ),
        &mut Vec::new(),
    )
    .unwrap();
    config.validate_detailed().unwrap();
    let generation = install_generation(&config);
    let registry = ProxyRegistry::default_resolver().unwrap();
    let timeout = Duration::from_secs(3);
    let target: SocketAddr = "198.51.100.7:53".parse().unwrap();

    // ss landing via a SOCKS5 front: per-flow and shared-source.
    let nss = generation.get(&node_id(&config, "nss")).unwrap();
    assert!(nss.udp_capable, "chained ss is UDP-capable");
    let flow = registry
        .dial_udp_transport_runtime(Arc::clone(&generation), nss.node.id, target, None, timeout)
        .await
        .expect("ss UDP via socks5 front");
    udp_echo_once(flow.as_ref(), target).await;
    let shared = registry
        .find(nss.node.protocol())
        .unwrap()
        .shared
        .as_ref()
        .unwrap()
        .prepare_shared_source(Arc::clone(&nss), target, None, timeout, false)
        .await
        .expect("ss shared-source UDP via front")
        .commit()
        .await
        .unwrap();
    udp_echo_once(shared.as_ref(), target).await;
    assert!(a_log.udp_targets.lock().contains(&ss_alias));
    assert!(ss_log.udp_targets.lock().contains(&target));

    // SOCKS5 landing via a SOCKS5 front: control over A's TCP, datagrams over
    // A's UDP to B's relay (unspecified BND mapped onto B's alias).
    let nsk = generation.get(&node_id(&config, "nsk")).unwrap();
    let flow = registry
        .dial_udp_transport_runtime(Arc::clone(&generation), nsk.node.id, echo, None, timeout)
        .await
        .expect("socks5 UDP via socks5 front");
    udp_echo_once(flow.as_ref(), echo).await;
    assert!(a_log.tcp_targets.lock().contains(&b_alias));
    assert!(b_log.udp_targets.lock().contains(&echo));

    // Nested: ss over (socks5 landing over socks5 front).
    let before = b_log.udp_targets.lock().len();
    let nnest = generation.get(&node_id(&config, "nnest")).unwrap();
    let flow = registry
        .dial_udp_transport_runtime(
            Arc::clone(&generation),
            nnest.node.id,
            target,
            None,
            timeout,
        )
        .await
        .expect("ss UDP via nested chain");
    udp_echo_once(flow.as_ref(), target).await;
    assert!(b_log.udp_targets.lock()[before..].contains(&ss_alias2));

    // Landing servers only saw their fronts' relay sockets.
    let a_locals = a_log.udp_locals.lock().clone();
    let b_locals = b_log.udp_locals.lock().clone();
    for peer in ss_log.udp_peers.lock().iter() {
        assert!(
            a_locals.contains(peer) || b_locals.contains(peer),
            "direct ss datagram from {peer}"
        );
    }
    for peer in b_log.udp_peers.lock().iter() {
        assert!(a_locals.contains(peer), "direct socks datagram from {peer}");
    }
}

/// Front down, a front without a UDP relay, or an HTTP front: a clear error,
/// and nothing reaches the landing server directly.
#[tokio::test]
async fn native_udp_landing_fails_closed() {
    let _serial = SERIAL.lock().await;
    let ss_log = Arc::new(UdpLog::default());
    let ss_real = ss_udp_echo(Arc::clone(&ss_log)).await;
    let up = Arc::new(AtomicBool::new(false));
    let a_addr = socks_udp_server(Arc::clone(&up), vec![], Arc::new(UdpLog::default())).await;
    let tcp_only = socks_server(
        Arc::new(AtomicBool::new(true)),
        None,
        Arc::new(Log::default()),
    )
    .await;
    let config = honk_config::parser::parse_dae_config_with_detailed_diagnostics(
        &format!(
            "node {{\n fa: 'socks5://{a_addr}'\n ft: 'socks5://{tcp_only}'\n\
             fv: 'http://127.0.0.1:9'\n\
             ldown: 'ss://YWVzLTEyOC1nY206cHc=@{ss_real}?detour=fa'\n\
             ltcp: 'ss://YWVzLTEyOC1nY206cHcy@{ss_real}?detour=ft'\n\
             lv: 'ss://YWVzLTEyOC1nY206cHcz@{ss_real}?detour=fv'\n}}\n"
        ),
        &mut Vec::new(),
    )
    .unwrap();
    config.validate_detailed().unwrap();
    let generation = install_generation(&config);
    let registry = ProxyRegistry::default_resolver().unwrap();
    let timeout = Duration::from_millis(800);
    let target: SocketAddr = "198.51.100.7:53".parse().unwrap();
    for (name, expect) in [
        ("ldown", "detour"),
        ("ltcp", "detour"),
        ("lv", "cannot relay UDP"),
    ] {
        let err = registry
            .dial_udp_transport_runtime(
                Arc::clone(&generation),
                node_id(&config, name),
                target,
                None,
                timeout,
            )
            .await
            .map(|_| ())
            .expect_err("chained UDP must fail closed");
        assert!(format!("{err:#}").contains(expect), "{name}: {err:#}");
    }
    assert!(
        ss_log.udp_peers.lock().is_empty(),
        "nothing reached ss directly"
    );
}

/// A group front: each new UDP session uses the group's selection at dial
/// time; an open session keeps its relay.
#[tokio::test]
async fn native_udp_group_front_follows_the_selection() {
    let _serial = SERIAL.lock().await;
    let ss_log = Arc::new(UdpLog::default());
    let ss_real = ss_udp_echo(Arc::clone(&ss_log)).await;
    let ss_alias = SocketAddr::from(([192, 0, 2, 1], ss_real.port()));
    let (l1, l2) = (Arc::new(UdpLog::default()), Arc::new(UdpLog::default()));
    let up = || Arc::new(AtomicBool::new(true));
    let g1 = socks_udp_server(up(), vec![(ss_alias, ss_real)], Arc::clone(&l1)).await;
    let g2 = socks_udp_server(up(), vec![(ss_alias, ss_real)], Arc::clone(&l2)).await;
    let config = honk_config::parser::parse_dae_config_with_detailed_diagnostics(
        &format!(
            "node {{\n ug1: 'socks5://{g1}'\n ug2: 'socks5://{g2}'\n\
             ugl: 'ss://YWVzLTEyOC1nY206cHc=@{ss_alias}?detour=ugroup'\n}}\n\
             group {{\n ugroup {{\n filter: name(ug1, ug2)\n policy: selector\n }}\n}}\n"
        ),
        &mut Vec::new(),
    )
    .unwrap();
    config.validate_detailed().unwrap();
    let generation = install_generation(&config);
    let manager = Arc::new(crate::group::GroupManager::new(
        &config.groups,
        &config.nodes,
    ));
    super::install_group_manager(Arc::new(parking_lot::RwLock::new(Arc::clone(&manager))));
    let select = |member: &str| {
        manager
            .set_selector_choice("ugroup", member, crate::group::SelectorNetworks::Both)
            .unwrap();
    };
    let registry = ProxyRegistry::default_resolver().unwrap();
    let land = node_id(&config, "ugl");
    let timeout = Duration::from_secs(3);
    let target: SocketAddr = "198.51.100.7:53".parse().unwrap();

    select("ug1");
    let held = registry
        .dial_udp_transport_runtime(Arc::clone(&generation), land, target, None, timeout)
        .await
        .expect("UDP via ug1");
    udp_echo_once(held.as_ref(), target).await;
    assert_eq!(l1.udp_targets.lock().len(), 1);
    assert!(l2.udp_targets.lock().is_empty());

    select("ug2");
    let fresh = registry
        .dial_udp_transport_runtime(Arc::clone(&generation), land, target, None, timeout)
        .await
        .expect("UDP via ug2");
    udp_echo_once(fresh.as_ref(), target).await;
    assert_eq!(l2.udp_targets.lock().len(), 1);
    // The session opened before the switch keeps using ug1.
    udp_echo_once(held.as_ref(), target).await;
    assert_eq!(l1.udp_targets.lock().len(), 2);
    assert_eq!(l2.udp_targets.lock().len(), 1);

    let relays: Vec<_> = l1
        .udp_locals
        .lock()
        .iter()
        .chain(l2.udp_locals.lock().iter())
        .copied()
        .collect();
    for peer in ss_log.udp_peers.lock().iter() {
        assert!(relays.contains(peer), "direct datagram from {peer}");
    }
}

/// The QUIC loopback bridge forwards the owning peer's datagrams to the
/// front pipe and the replies back, and drops datagrams from any other
/// local source.
#[tokio::test]
async fn quic_udp_bridge_relays_owner_and_drops_foreign_peers() {
    let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server.local_addr().unwrap();
    let pipe_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    pipe_socket.connect(server_addr).await.unwrap();
    let (bridge, _guard) = super::udp_bridge(crate::proxy::datagram_pipe::DatagramPipe::Socket(
        pipe_socket,
    ))
    .await
    .unwrap();
    assert!(bridge.ip().is_loopback());

    let owner = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    owner.send_to(b"hello", bridge).await.unwrap();
    let mut buf = [0u8; 64];
    let (n, from) = server.recv_from(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"hello");
    server.send_to(b"world", from).await.unwrap();
    let (n, reply_from) = tokio::time::timeout(Duration::from_secs(2), owner.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!((&buf[..n], reply_from), (&b"world"[..], bridge));

    let foreign = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    foreign.send_to(b"intruder", bridge).await.unwrap();
    owner.send_to(b"again", bridge).await.unwrap();
    let (n, _) = server.recv_from(&mut buf).await.unwrap();
    assert_eq!(
        &buf[..n],
        b"again",
        "foreign datagram must not reach the front"
    );
}

/// Dropping the dialed stream/transport's guard stops the bridge at once
/// (releasing the front relay) rather than after `QUIC_BRIDGE_IDLE`.
#[tokio::test]
async fn quic_udp_bridge_stops_when_guard_drops() {
    let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let pipe_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    pipe_socket
        .connect(server.local_addr().unwrap())
        .await
        .unwrap();
    let (bridge, guard) = super::udp_bridge(crate::proxy::datagram_pipe::DatagramPipe::Socket(
        pipe_socket,
    ))
    .await
    .unwrap();
    let owner = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    owner.send_to(b"one", bridge).await.unwrap();
    let mut buf = [0u8; 64];
    let (n, _) = server.recv_from(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"one");
    drop(guard);
    // Within the close grace the client's CONNECTION_CLOSE still gets out.
    owner.send_to(b"close", bridge).await.unwrap();
    let (n, _) = tokio::time::timeout(Duration::from_secs(1), server.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf[..n], b"close");
    tokio::time::sleep(super::QUIC_BRIDGE_CLOSE_GRACE + Duration::from_millis(200)).await;
    // The bridge socket is closed: further datagrams go nowhere.
    let _ = owner.send_to(b"two", bridge).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(300), server.recv_from(&mut buf))
            .await
            .is_err(),
        "bridge kept relaying after its guard dropped"
    );
}

#[test]
fn quic_landings_ride_fronts_except_port_hopping_hysteria2() {
    use honk_config::node::Node;
    for (link, chained) in [
        ("hysteria2://pw@1.2.3.4:443?sni=a.example", true),
        ("hysteria2://pw@1.2.3.4:443?mport=443-450", false),
        (
            "tuic://00000000-0000-0000-0000-000000000001:p@1.2.3.4:443",
            true,
        ),
    ] {
        let mut node = Node::from_share_link(link).unwrap();
        node.detour = Some("front".into());
        assert_eq!(node.supports_detour(), chained, "{link}");
        assert_eq!(
            crate::descriptor::chained_udp_supported(&node),
            chained,
            "{link}"
        );
    }
}

#[test]
fn vless_udp_rides_fronts_and_vless_fronts_relay_udp() {
    use honk_config::node::Node;
    let id = "00000000-0000-0000-0000-000000000001";
    let mut landing =
        Node::from_share_link(&format!("vless://{id}@1.2.3.4:443?encryption=none")).unwrap();
    assert!(
        super::front_relays_udp(&landing),
        "unchained vless front relays UDP"
    );
    landing.detour = Some("front".into());
    assert!(crate::descriptor::chained_udp_supported(&landing));
    assert!((crate::descriptor::descriptor(landing.protocol()).supports_udp)(&landing));
}

#[test]
fn group_front_candidates_put_selection_first_and_skip_landing() {
    let config = honk_config::parser::parse_dae_config_with_detailed_diagnostics(
        "node {\n c1: 'socks5://127.0.0.1:1'\n c2: 'socks5://127.0.0.1:2'\n c3: 'socks5://127.0.0.1:3'\n c4: 'socks5://127.0.0.1:4'\n c5: 'socks5://127.0.0.1:5'\n c6: 'socks5://127.0.0.1:6'\n}\n",
        &mut Vec::new(),
    )
    .unwrap();
    let by = |n: &str| config.nodes.iter().find(|x| x.name == n).unwrap().clone();
    let members: Vec<_> = ["c1", "c2", "c3", "c4", "c5", "c6"].map(by).into();
    let names = |v: Vec<honk_config::node::Node>| v.into_iter().map(|n| n.name).collect::<Vec<_>>();
    // Selection first, no duplicate, landing excluded, capped.
    assert_eq!(
        names(super::front_candidate_order(
            Some(by("c3")),
            members.clone(),
            by("c2").id
        )),
        ["c3", "c1", "c4", "c5"]
    );
    assert_eq!(super::MAX_FRONT_CANDIDATES, 4);
    // No live selection: members are still tried in order.
    assert_eq!(
        names(super::front_candidate_order(
            None,
            members[..2].to_vec(),
            Uuid::nil()
        )),
        ["c1", "c2"]
    );
    // A selection equal to the landing is dropped, never dialed.
    assert!(super::front_candidate_order(Some(by("c1")), vec![by("c1")], by("c1").id).is_empty());
}

/// Every path that dials a node's server from this host outside the chained
/// dialers (bare-TCP pool, ready-stream pool, warm) must stay closed for a
/// node with a detour, for every protocol.
#[test]
fn chained_nodes_of_every_protocol_never_pool_or_warm_direct() {
    use crate::proxy::WarmRequirement;
    use base64::Engine;
    use honk_config::node::Node;
    let id = "00000000-0000-0000-0000-000000000001";
    let vmess = base64::engine::general_purpose::STANDARD.encode(format!(
        r#"{{"v":"2","ps":"v","add":"1.2.3.4","port":"443","id":"{id}","aid":"0","net":"tcp","type":"none","tls":""}}"#
    ));
    let links = [
        "ss://YWVzLTI1Ni1nY206cHc@1.2.3.4:443".to_string(),
        "socks5://1.2.3.4:1080".to_string(),
        "http://1.2.3.4:8080".to_string(),
        "trojan://pw@1.2.3.4:443?sni=a.example".to_string(),
        format!("vmess://{vmess}"),
        format!("vless://{id}@1.2.3.4:443?encryption=none"),
        format!("vless://{id}@1.2.3.4:443?encryption=none&type=ws&path=/w"),
        "trojan://pw@1.2.3.4:443?type=grpc&serviceName=g".to_string(),
        "anytls://pw@1.2.3.4:443?sni=a.example".to_string(),
        "hysteria2://pw@1.2.3.4:443?sni=a.example".to_string(),
        format!("tuic://{id}:p@1.2.3.4:443"),
        format!("juicity://{id}:p@1.2.3.4:443"),
    ];
    for link in links {
        let mut node = Node::from_share_link(&link).unwrap_or_else(|e| panic!("{link}: {e:?}"));
        node.detour = Some("front".into());
        node.id = node.derive_id();
        let d = crate::descriptor::descriptor(node.protocol());
        assert!(
            !(d.pool_bare_tcp)(&node),
            "{link}: bare TCP pooled for chained node"
        );
        assert!(
            !(d.pool_ready_streams)(&node),
            "{link}: ready stream pooled for chained node"
        );
        for req in [WarmRequirement::Session, WarmRequirement::Udp] {
            assert!(
                !d.supports_warm(&node, req),
                "{link}: chained node warmed ({req:?})"
            );
        }
        if (d.supports_udp)(&node) {
            assert!(
                crate::descriptor::chained_udp_supported(&node),
                "{link}: claims UDP while chained without a chained UDP path"
            );
        }
    }
}

/// Accepts TCP and never answers, so every handshake through it hangs.
async fn silent_server() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream);
        }
    });
    addr
}

/// Nested front groups whose members all hang share one total deadline:
/// failover still walks members in order, but a dead path fails within
/// `CHAIN_BUDGET_FACTOR × connect_timeout` instead of multiplying per hop.
#[tokio::test]
async fn nested_group_front_failover_shares_one_deadline() {
    let _serial = SERIAL.lock().await;
    let mut nodes = String::new();
    for i in 0..4 {
        nodes += &format!(" si{i}: 'socks5://{}'\n", silent_server().await);
    }
    for i in 0..4 {
        nodes += &format!(" sm{i}: 'socks5://{}?detour=gi'\n", silent_server().await);
    }
    nodes += " sl: 'socks5://192.0.2.9:1080?detour=gm'\n";
    let config = honk_config::parser::parse_dae_config_with_detailed_diagnostics(
        &format!(
            "node {{\n{nodes}}}\ngroup {{\n gi {{\n filter: name(si0, si1, si2, si3)\n policy: selector\n }}\n\
             gm {{\n filter: name(sm0, sm1, sm2, sm3)\n policy: selector\n }}\n}}\n"
        ),
        &mut Vec::new(),
    )
    .unwrap();
    config.validate_detailed().unwrap();
    let generation = install_generation(&config);
    let manager = Arc::new(crate::group::GroupManager::new(
        &config.groups,
        &config.nodes,
    ));
    super::install_group_manager(Arc::new(parking_lot::RwLock::new(Arc::clone(&manager))));
    let registry = ProxyRegistry::default_resolver().unwrap();
    let land = node_id(&config, "sl");
    let timeout = Duration::from_millis(300);
    let started = tokio::time::Instant::now();
    let result = tokio::time::timeout(
        Duration::from_secs(30),
        registry.dial_runtime(
            Arc::clone(&generation),
            land,
            "198.51.100.7:80".parse().unwrap(),
            None,
            timeout,
        ),
    )
    .await
    .expect("dial must end by itself");
    let elapsed = started.elapsed();
    eprintln!("NESTED elapsed={elapsed:?} ok={}", result.is_ok());
    assert!(result.is_err());
    let budget = timeout * super::CHAIN_BUDGET_FACTOR;
    assert!(
        elapsed < budget + Duration::from_millis(500),
        "dead nested fronts took {elapsed:?}, budget {budget:?}"
    );
}

/// Under the shared deadline, a hanging selected front still fails over to
/// the next member inside the same dial.
#[tokio::test]
async fn hanging_group_front_still_fails_over_in_order() {
    let _serial = SERIAL.lock().await;
    let land = Arc::new(Log::default());
    let land_real = socks_server(Arc::new(AtomicBool::new(true)), None, Arc::clone(&land)).await;
    let land_alias = SocketAddr::from(([192, 0, 2, 1], land_real.port()));
    let good_log = Arc::new(Log::default());
    let good = socks_server(
        Arc::new(AtomicBool::new(true)),
        Some((land_alias, land_real)),
        Arc::clone(&good_log),
    )
    .await;
    let dead = silent_server().await;
    let http = http_server().await;
    let config = honk_config::parser::parse_dae_config_with_detailed_diagnostics(
        &format!(
            "node {{\n hd: 'socks5://{dead}'\n hg: 'socks5://{good}'\n hl: 'socks5://{land_alias}?detour=hgroup'\n}}\n\
             group {{\n hgroup {{\n filter: name(hd, hg)\n policy: selector\n }}\n}}\n"
        ),
        &mut Vec::new(),
    )
    .unwrap();
    config.validate_detailed().unwrap();
    let generation = install_generation(&config);
    let manager = Arc::new(crate::group::GroupManager::new(
        &config.groups,
        &config.nodes,
    ));
    super::install_group_manager(Arc::new(parking_lot::RwLock::new(Arc::clone(&manager))));
    manager
        .set_selector_choice("hgroup", "hd", crate::group::SelectorNetworks::Both)
        .unwrap();
    let registry = ProxyRegistry::default_resolver().unwrap();
    let timeout = Duration::from_millis(400);
    let started = tokio::time::Instant::now();
    let mut stream = registry
        .dial_runtime(
            Arc::clone(&generation),
            node_id(&config, "hl"),
            http,
            None,
            timeout,
        )
        .await
        .expect("fails over from the hanging member to hg");
    http_204(&mut stream).await;
    assert_eq!(good_log.targets.lock().len(), 1);
    assert!(started.elapsed() < timeout * super::CHAIN_BUDGET_FACTOR + Duration::from_millis(300));
}

fn open_fds() -> usize {
    std::fs::read_dir("/proc/self/fd")
        .map(|dir| dir.count())
        .unwrap_or(0)
}

/// Churning QUIC bridges at a high rate: each dropped bridge lingers only
/// for the close grace, so live sockets stay bounded by rate × grace and
/// all of them are released shortly after the churn stops.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quic_bridge_churn_releases_sockets_after_the_grace() {
    let _serial = SERIAL.lock().await;
    let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target = server.local_addr().unwrap();
    let baseline = open_fds();
    let started = tokio::time::Instant::now();
    let mut peak = 0;
    for _ in 0..1000 {
        let pipe = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        pipe.connect(target).await.unwrap();
        let (_addr, guard) =
            super::udp_bridge(crate::proxy::datagram_pipe::DatagramPipe::Socket(pipe))
                .await
                .unwrap();
        drop(guard);
        peak = peak.max(open_fds());
    }
    let churn = started.elapsed();
    tokio::time::sleep(super::QUIC_BRIDGE_CLOSE_GRACE + Duration::from_millis(700)).await;
    let after = open_fds();
    eprintln!("CHURN churn={churn:?} baseline={baseline} peak={peak} after={after}");
    assert!(
        after <= baseline + 40,
        "bridges leaked: {baseline} -> {after}"
    );
}

#[tokio::test]
async fn chain_deadline_saturates_on_absurd_connect_timeouts() {
    for timeout in [
        Duration::ZERO,
        Duration::MAX,
        Duration::from_secs(u64::MAX / 2),
    ] {
        let deadline = super::chain_deadline(timeout);
        assert!(deadline >= tokio::time::Instant::now() - Duration::from_secs(1));
    }
}

/// UDP through a group front whose selected member hangs still fails over
/// to the next member within the shared chain deadline.
#[tokio::test]
async fn hanging_udp_group_front_still_fails_over() {
    let _serial = SERIAL.lock().await;
    let ss_log = Arc::new(UdpLog::default());
    let ss_real = ss_udp_echo(Arc::clone(&ss_log)).await;
    let ss_alias = SocketAddr::from(([192, 0, 2, 1], ss_real.port()));
    let good_log = Arc::new(UdpLog::default());
    let good = socks_udp_server(
        Arc::new(AtomicBool::new(true)),
        vec![(ss_alias, ss_real)],
        Arc::clone(&good_log),
    )
    .await;
    let dead = silent_server().await;
    let config = honk_config::parser::parse_dae_config_with_detailed_diagnostics(
        &format!(
            "node {{\n ud: 'socks5://{dead}'\n ugood: 'socks5://{good}'\n\
             ul: 'ss://YWVzLTEyOC1nY206cHc=@{ss_alias}?detour=uhg'\n}}\n\
             group {{\n uhg {{\n filter: name(ud, ugood)\n policy: selector\n }}\n}}\n"
        ),
        &mut Vec::new(),
    )
    .unwrap();
    config.validate_detailed().unwrap();
    let generation = install_generation(&config);
    let manager = Arc::new(crate::group::GroupManager::new(
        &config.groups,
        &config.nodes,
    ));
    super::install_group_manager(Arc::new(parking_lot::RwLock::new(Arc::clone(&manager))));
    manager
        .set_selector_choice("uhg", "ud", crate::group::SelectorNetworks::Both)
        .unwrap();
    let registry = ProxyRegistry::default_resolver().unwrap();
    let timeout = Duration::from_millis(400);
    let target: SocketAddr = "198.51.100.7:53".parse().unwrap();
    let started = tokio::time::Instant::now();
    let transport = tokio::time::timeout(
        Duration::from_secs(20),
        registry.dial_udp_transport_runtime(
            Arc::clone(&generation),
            node_id(&config, "ul"),
            target,
            None,
            timeout,
        ),
    )
    .await
    .expect("UDP dial must end by itself")
    .expect("fails over from the hanging member to ugood");
    assert!(started.elapsed() < timeout * super::CHAIN_BUDGET_FACTOR + Duration::from_millis(300));
    udp_echo_once(transport.as_ref(), target).await;
    assert_eq!(good_log.udp_targets.lock().len(), 1);
}

/// A caller that cuts the dial at `connect_timeout` (as DNS does) still
/// reaches the last, working member behind three hanging ones; and a
/// caller deadline given via `with_chain_deadline` sets the budget.
#[tokio::test]
async fn last_front_candidate_is_not_starved_by_the_caller_bound() {
    let _serial = SERIAL.lock().await;
    let land = Arc::new(Log::default());
    let land_real = socks_server(Arc::new(AtomicBool::new(true)), None, Arc::clone(&land)).await;
    let land_alias = SocketAddr::from(([192, 0, 2, 1], land_real.port()));
    let good_log = Arc::new(Log::default());
    let good = socks_server(
        Arc::new(AtomicBool::new(true)),
        Some((land_alias, land_real)),
        Arc::clone(&good_log),
    )
    .await;
    let mut nodes = String::new();
    for i in 0..3 {
        nodes += &format!(" sd{i}: 'socks5://{}'\n", silent_server().await);
    }
    let http = http_server().await;
    let config = honk_config::parser::parse_dae_config_with_detailed_diagnostics(
        &format!(
            "node {{\n{nodes} sg: 'socks5://{good}'\n sland: 'socks5://{land_alias}?detour=sgrp'\n}}\n\
             group {{\n sgrp {{\n filter: name(sd0, sd1, sd2, sg)\n policy: selector\n }}\n}}\n"
        ),
        &mut Vec::new(),
    )
    .unwrap();
    config.validate_detailed().unwrap();
    let generation = install_generation(&config);
    let manager = Arc::new(crate::group::GroupManager::new(
        &config.groups,
        &config.nodes,
    ));
    super::install_group_manager(Arc::new(parking_lot::RwLock::new(Arc::clone(&manager))));
    manager
        .set_selector_choice("sgrp", "sd0", crate::group::SelectorNetworks::Both)
        .unwrap();
    let registry = ProxyRegistry::default_resolver().unwrap();
    let land_id = node_id(&config, "sland");
    let timeout = Duration::from_millis(800);
    let mut stream = tokio::time::timeout(
        timeout,
        registry.dial_runtime(Arc::clone(&generation), land_id, http, None, timeout),
    )
    .await
    .expect("the chain fits inside the caller's connect_timeout bound")
    .expect("reaches the last member sg");
    http_204(&mut stream).await;
    assert_eq!(good_log.targets.lock().len(), 1);

    // A caller deadline shorter than connect_timeout is honoured.
    let started = tokio::time::Instant::now();
    let short = started + Duration::from_millis(200);
    let result = super::with_chain_deadline(
        short,
        registry.dial_runtime(
            Arc::clone(&generation),
            land_id,
            http,
            None,
            Duration::from_secs(5),
        ),
    )
    .await;
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_millis(600),
        "ignored the caller deadline: {elapsed:?}"
    );
    drop(result);
}
