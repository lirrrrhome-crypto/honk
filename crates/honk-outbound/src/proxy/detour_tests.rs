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
        .expect_err("UDP must not leave directly");
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

    // Native-UDP landing behind a TCP-only chain: clear refusal.
    let ss = f.generation.get(&f.ss_id).unwrap();
    let err = f
        .registry
        .dial_udp_transport_runtime(Arc::clone(&f.generation), f.ss_id, target, None, timeout)
        .await
        .map(|_| ())
        .expect_err("ss UDP cannot be chained");
    assert!(err.to_string().contains("native UDP"), "{err}");
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
        .expect_err("ss UDP cannot be chained");
    assert!(err.to_string().contains("native UDP"), "{err}");

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
