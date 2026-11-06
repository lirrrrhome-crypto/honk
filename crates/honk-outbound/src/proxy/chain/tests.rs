use super::*;
use std::collections::HashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

struct MapResolver(HashMap<String, Node>);

impl ChainResolver for MapResolver {
    fn resolve(&self, tag: &str) -> Option<Node> {
        self.0.get(tag).cloned()
    }
}

/// A handler whose members resolve among `nodes`.
fn handler(nodes: &[&Node]) -> ChainHandler {
    let handler = ChainHandler::new(ProxyRegistry::default_resolver().unwrap());
    handler.install_resolver(Arc::new(MapResolver(
        nodes
            .iter()
            .map(|node| (node.name.clone(), (*node).clone()))
            .collect(),
    )));
    handler
}

fn node(name: &str, port: u16, outbound: OutboundConfig) -> Node {
    let mut node = Node {
        name: name.to_owned(),
        address: format!("127.0.0.1:{port}"),
        host: "127.0.0.1".to_owned(),
        port,
        outbound,
        ..Node::default()
    };
    node.id = node.derive_id();
    node
}

fn socks(name: &str, port: u16) -> Node {
    node(name, port, OutboundConfig::Socks5(Default::default()))
}

fn trojan(name: &str, port: u16) -> Node {
    node(
        name,
        port,
        OutboundConfig::Trojan(honk_config::node::TrojanConfig {
            password: Some("pw".to_owned()),
            ..Default::default()
        }),
    )
}

fn chain_node(hops: &[&str], out: &str) -> Node {
    Node {
        name: "chain".to_owned(),
        outbound: OutboundConfig::Chain(ChainConfig {
            hops: hops.iter().map(|hop| (*hop).to_owned()).collect(),
            out: ChainOut::Tag(out.to_owned()),
            group_exit: None,
        }),
        ..Node::default()
    }
}

fn local(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
}

type Log = Arc<parking_lot::Mutex<Vec<String>>>;

async fn read_target(stream: &mut TcpStream, atyp: u8) -> std::io::Result<String> {
    Ok(match atyp {
        1 => {
            let mut raw = [0u8; 6];
            stream.read_exact(&mut raw).await?;
            format!(
                "{}:{}",
                Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3]),
                u16::from_be_bytes([raw[4], raw[5]])
            )
        }
        3 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut raw = vec![0u8; len[0] as usize + 2];
            stream.read_exact(&mut raw).await?;
            let (name, port) = raw.split_at(len[0] as usize);
            format!(
                "{}:{}",
                String::from_utf8_lossy(name),
                u16::from_be_bytes([port[0], port[1]])
            )
        }
        _ => return Err(std::io::Error::other("unsupported atyp")),
    })
}

async fn splice_to(mut client: TcpStream, target: &str) -> std::io::Result<()> {
    let mut upstream = TcpStream::connect(target.replace("localhost", "127.0.0.1")).await?;
    tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
    Ok(())
}

/// No-auth SOCKS5 CONNECT server recording each requested target.
async fn socks_server(log: Log) -> u16 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut client, _) = listener.accept().await.unwrap();
            let log = Arc::clone(&log);
            tokio::spawn(async move {
                let mut head = [0u8; 2];
                client.read_exact(&mut head).await?;
                let mut methods = vec![0u8; head[1] as usize];
                client.read_exact(&mut methods).await?;
                client.write_all(&[5, 0]).await?;
                let mut request = [0u8; 4];
                client.read_exact(&mut request).await?;
                let target = read_target(&mut client, request[3]).await?;
                log.lock().push(target.clone());
                client.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
                splice_to(client, &target).await
            });
        }
    });
    port
}

/// Plaintext Trojan CONNECT server recording each requested target.
async fn trojan_server(log: Log) -> u16 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut client, _) = listener.accept().await.unwrap();
            let log = Arc::clone(&log);
            tokio::spawn(async move {
                let mut auth = [0u8; 58];
                client.read_exact(&mut auth).await?;
                let mut command = [0u8; 2];
                client.read_exact(&mut command).await?;
                assert_eq!(command[0], 1, "CONNECT");
                let target = read_target(&mut client, command[1]).await?;
                let mut crlf = [0u8; 2];
                client.read_exact(&mut crlf).await?;
                log.lock().push(target.clone());
                splice_to(client, &target).await
            });
        }
    });
    port
}

async fn echo_server() -> u16 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let (mut read, mut write) = stream.split();
                let _ = tokio::io::copy(&mut read, &mut write).await;
            });
        }
    });
    port
}

async fn round_trip(stream: &mut ProxyStream, payload: &[u8]) {
    stream.stream.write_all(payload).await.unwrap();
    let mut reply = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(5), stream.stream.read_exact(&mut reply))
        .await
        .expect("echo within 5s")
        .unwrap();
    assert_eq!(reply, payload);
}

#[tokio::test]
async fn members_dial_in_order_each_over_the_previous_stream() {
    let logs: [Log; 3] = Default::default();
    let a = socks("a", socks_server(Arc::clone(&logs[0])).await);
    let mut b = trojan("b", trojan_server(Arc::clone(&logs[1])).await);
    b.host = "localhost".to_owned();
    let c = socks("c", socks_server(Arc::clone(&logs[2])).await);
    let handler = handler(&[&a, &b, &c]);
    let echo = echo_server().await;

    let mut stream = handler
        .dial(
            &chain_node(&["a", "b"], "c"),
            local(echo),
            None,
            Duration::from_secs(3),
        )
        .await
        .unwrap();
    round_trip(&mut stream, b"through a, b and c").await;

    // a reached b's server by name (no local DNS for later members), b
    // reached c's server, c the destination; each exactly once.
    assert_eq!(*logs[0].lock(), [format!("localhost:{}", b.port)]);
    assert_eq!(*logs[1].lock(), [format!("127.0.0.1:{}", c.port)]);
    assert_eq!(*logs[2].lock(), [format!("127.0.0.1:{echo}")]);
}

#[tokio::test]
async fn concurrent_bulk_flows_stay_intact() {
    let a = socks("a", socks_server(Log::default()).await);
    let b = trojan("b", trojan_server(Log::default()).await);
    let handler = handler(&[&a, &b]);
    let echo = echo_server().await;
    let handler = Arc::new(handler);
    let mut flows = Vec::new();
    for flow in 0..32u32 {
        let handler = Arc::clone(&handler);
        flows.push(tokio::spawn(async move {
            let stream = handler
                .dial(
                    &chain_node(&["a"], "b"),
                    local(echo),
                    None,
                    Duration::from_secs(5),
                )
                .await
                .unwrap();
            let payload: Vec<u8> = (0..256 * 1024u32)
                .map(|i| (i.wrapping_mul(31) ^ flow) as u8)
                .collect();
            let (mut read, mut write) = tokio::io::split(stream.stream);
            let sent = payload.clone();
            let writer = tokio::spawn(async move {
                write.write_all(&sent).await.unwrap();
                write
            });
            let mut reply = vec![0u8; payload.len()];
            read.read_exact(&mut reply).await.unwrap();
            let _write = writer.await.unwrap();
            assert_eq!(reply, payload, "flow {flow}");
        }));
    }
    for flow in flows {
        tokio::time::timeout(Duration::from_secs(20), flow)
            .await
            .expect("flow finished")
            .unwrap();
    }
}

#[tokio::test]
async fn a_member_that_cannot_ride_a_stream_is_refused_before_dialing() {
    let log = Log::default();
    let a = socks("a", socks_server(Arc::clone(&log)).await);
    let quic = node("quic", 1, OutboundConfig::Hysteria2(Default::default()));
    let handler = handler(&[&a, &quic]);
    let error = handler
        .dial(
            &chain_node(&["a"], "quic"),
            local(9),
            None,
            Duration::from_secs(3),
        )
        .await
        .unwrap_err();
    assert!(format!("{error:#}").contains("refused"), "{error:#}");
    assert!(
        log.lock().is_empty(),
        "nothing may be dialed for a refused chain"
    );
}

async fn dead_port() -> u16 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            drop(stream);
        }
    });
    port
}

#[tokio::test]
async fn a_dead_confirming_member_is_named_with_what_it_was_reaching() {
    let a = socks("a", socks_server(Log::default()).await);
    let b = socks("b", dead_port().await);
    let c = socks("c", 1);
    let handler = handler(&[&a, &b, &c]);
    let error = handler
        .dial(
            &chain_node(&["a", "b"], "c"),
            local(9),
            None,
            Duration::from_secs(3),
        )
        .await
        .unwrap_err();
    let error = format!("{error:#}");
    assert!(
        error.contains("chain member `b` (2/3) reaching `c`"),
        "{error}"
    );
    assert!(!error.contains("may have failed instead"), "{error}");
}

/// Trojan sends its request without an answer, so its death surfaces at
/// the next member's read; the error must point back at it.
#[tokio::test]
async fn an_unconfirming_member_in_front_is_named_as_a_possible_cause() {
    let a = socks("a", socks_server(Log::default()).await);
    let b = trojan("b", dead_port().await);
    let c = socks("c", 1);
    let handler = handler(&[&a, &b, &c]);
    let error = handler
        .dial(
            &chain_node(&["a", "b"], "c"),
            local(9),
            None,
            Duration::from_secs(3),
        )
        .await
        .unwrap_err();
    let error = format!("{error:#}");
    assert!(error.contains("chain member `c` (3/3)"), "{error}");
    assert!(error.contains("may have failed instead: `b`"), "{error}");
}

#[tokio::test]
async fn unresolved_direct_and_self_reaching_members_fail_closed() {
    let a = socks("a", 1);
    let looping = chain_node(&["looping"], "a");
    let mut named_loop = looping.clone();
    named_loop.name = "looping".to_owned();
    let direct = Node {
        name: "direct".to_owned(),
        outbound: OutboundConfig::Direct,
        ..Node::default()
    };
    let handler = handler(&[&a, &named_loop, &direct]);
    for (chain, expected) in [
        (chain_node(&["missing"], "a"), "resolves to no node"),
        (chain_node(&["direct"], "a"), "resolves to direct"),
        (looping, "nests too deeply"),
    ] {
        let error = handler
            .dial(&chain, local(9), None, Duration::from_secs(1))
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains(expected), "{error:#}");
    }
}

#[tokio::test]
async fn arrow_sugar_dials_its_inline_out_node() {
    let log = Log::default();
    let front = socks("front", socks_server(Arc::clone(&log)).await);
    let land = trojan("land", trojan_server(Log::default()).await);
    let handler = handler(&[&front]);
    let echo = echo_server().await;
    let sugar = Node {
        name: "land".to_owned(),
        outbound: OutboundConfig::Chain(ChainConfig {
            hops: vec!["front".to_owned()],
            out: ChainOut::Node(Box::new(land.clone())),
            group_exit: None,
        }),
        ..Node::default()
    };
    let mut stream = handler
        .dial(&sugar, local(echo), None, Duration::from_secs(3))
        .await
        .unwrap();
    round_trip(&mut stream, b"sugar").await;
    assert_eq!(*log.lock(), [format!("127.0.0.1:{}", land.port)]);
}

/// Capability checks run inside selection; they must leave a round-robin
/// member group's cursor where real dials put it.
#[test]
fn peeks_do_not_advance_a_member_group() {
    let a = socks("a", 1);
    let b = socks("b", 2);
    let group = honk_config::group::Group {
        name: "lb".to_owned(),
        policy: honk_config::group::GroupPolicy::LoadBalance,
        nodes: vec![a.id, b.id],
        ..Default::default()
    };
    let shared =
        crate::group::GroupManager::new(std::slice::from_ref(&group), &[a, b]).into_shared();
    let resolver = GroupManagerResolver::new(shared);
    let first = resolver.resolve("lb").unwrap().name;
    for _ in 0..5 {
        resolver.peek("lb").unwrap();
    }
    let second = resolver.resolve("lb").unwrap().name;
    assert_ne!(first, second, "peeks must not consume round-robin turns");
}

/// Selection may hold the manager's read guard while a reload writer
/// queues; resolving must not park behind that writer.
#[test]
fn resolver_never_waits_on_the_manager_cell() {
    let a = socks("a", 1);
    let shared = crate::group::GroupManager::new(&[], std::slice::from_ref(&a)).into_shared();
    let resolver = Arc::new(GroupManagerResolver::new(Arc::clone(&shared)));
    let guard = shared.read();
    let writer = {
        let shared = Arc::clone(&shared);
        std::thread::spawn(move || {
            let _write = shared.write();
        })
    };
    std::thread::sleep(Duration::from_millis(100));
    let (done, wait) = std::sync::mpsc::channel();
    std::thread::spawn({
        let resolver = Arc::clone(&resolver);
        move || {
            let _ = done.send(resolver.resolve("a").map(|node| node.name));
        }
    });
    let resolved = wait.recv_timeout(Duration::from_secs(2));
    drop(guard);
    assert_eq!(
        resolved
            .expect("resolver waited behind a queued writer")
            .as_deref(),
        Some("a")
    );
    writer.join().unwrap();
}
