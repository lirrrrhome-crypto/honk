//! TCP proxy chains (mihomo `dialer-proxy` / `relay`).
//!
//! A chain node names its hops by tag. At dial time each tag resolves to a
//! concrete leaf through the installed [`ChainResolver`] (a group follows its
//! own policy), nested chains are flattened, and the leaves are dialed in
//! order: the first leaf reaches the second leaf's server, each later leaf
//! performs its handshake over the previous leaf's stream, and the last leaf
//! reaches the destination.
//!
//! Later leaves accept only a `TcpStream` carrier (`dial_with_tcp`), so the
//! previous leaf's stream is bridged through a private loopback connection.
//! A leaf that would open a connection of its own is refused, never dialed
//! around the chain: see [`honk_config::chain::check_exit_protocol`].

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use honk_config::node::{ChainConfig, ChainExit, Node, OutboundConfig};
use honk_config::types::NodeProtocol;
use parking_lot::RwLock;
use tokio::net::{TcpListener, TcpStream};

use super::{ProbeableOutbound, ProxyRegistry, ProxyStream, TcpOutbound};

/// Upper bound on flattened leaves, nested chains included.
pub const MAX_CHAIN_LEAVES: usize = 16;

/// Resolves a hop tag to the leaf it currently stands for.
pub trait ChainResolver: Send + Sync {
    /// A node by name, or a group's current TCP selection.
    fn resolve(&self, tag: &str) -> Option<Node>;
}

static RESOLVER: RwLock<Option<Arc<dyn ChainResolver>>> = RwLock::new(None);
static RUNTIMES: RwLock<Option<crate::runtime::SharedRuntimeRegistry>> = RwLock::new(None);

/// Install the live runtime registry so a session protocol (Hysteria2,
/// TUIC, AnyTLS, multiplexed VLESS) as first hop reuses its warmed session
/// instead of handshaking a fresh one for every chained flow.
pub fn install_runtime_registry(registry: crate::runtime::SharedRuntimeRegistry) {
    *RUNTIMES.write() = Some(registry);
}

/// Install the process-wide hop resolver (honk-core does this once, over its
/// shared group manager, so reloads are followed automatically).
pub fn install_resolver(resolver: Arc<dyn ChainResolver>) {
    *RESOLVER.write() = Some(resolver);
}

/// [`ChainResolver`] over the live group manager.
pub struct GroupManagerResolver(pub crate::group::SharedGroupManager);

impl ChainResolver for GroupManagerResolver {
    fn resolve(&self, tag: &str) -> Option<Node> {
        let manager = Arc::clone(&self.0.read());
        manager
            .node_by_name(tag)
            .or_else(|| manager.select_node(tag))
            .cloned()
    }
}

fn resolve(tag: &str) -> anyhow::Result<Node> {
    let resolver = RESOLVER
        .read()
        .clone()
        .ok_or_else(|| anyhow::anyhow!("proxy chain resolver is not installed"))?;
    resolver
        .resolve(tag)
        .ok_or_else(|| anyhow::anyhow!("proxy chain hop `{tag}` resolves to no node"))
}

/// Flatten `node` into concrete leaves, appending them to `out`.
fn flatten(node: Node, out: &mut Vec<Node>, depth: usize) -> anyhow::Result<()> {
    anyhow::ensure!(
        depth <= MAX_CHAIN_LEAVES,
        "proxy chain nests too deeply (a hop probably reaches itself)"
    );
    let OutboundConfig::Chain(config) = node.outbound else {
        if node.protocol() != NodeProtocol::Direct {
            out.push(node);
        }
        return Ok(());
    };
    flatten_config(config, out, depth)
}

fn flatten_config(config: ChainConfig, out: &mut Vec<Node>, depth: usize) -> anyhow::Result<()> {
    for hop in &config.hops {
        flatten(resolve(hop)?, out, depth + 1)?;
        anyhow::ensure!(
            out.len() <= MAX_CHAIN_LEAVES,
            "proxy chain exceeds {MAX_CHAIN_LEAVES} hops"
        );
    }
    let exit = match config.exit {
        ChainExit::Node(node) => *node,
        ChainExit::Tag(tag) => resolve(&tag)?,
    };
    flatten(exit, out, depth + 1)?;
    anyhow::ensure!(
        out.len() <= MAX_CHAIN_LEAVES,
        "proxy chain exceeds {MAX_CHAIN_LEAVES} hops"
    );
    Ok(())
}

/// The leaves `node` dials through, first hop first, exit last.
pub fn leaves(node: &Node) -> anyhow::Result<Vec<Node>> {
    let mut out = Vec::new();
    flatten(node.clone(), &mut out, 0)?;
    anyhow::ensure!(!out.is_empty(), "proxy chain has no proxy hop");
    for leaf in &out[1..] {
        honk_config::chain::check_exit_protocol(leaf).map_err(|reason| {
            anyhow::anyhow!("proxy chain hop `{}` refused: {reason}", leaf.name)
        })?;
    }
    for leaf in &out {
        anyhow::ensure!(
            leaf.protocol() != NodeProtocol::Block,
            "proxy chain hop `{}` is block",
            leaf.name
        );
    }
    Ok(out)
}

/// The address a leaf's server is reached at, as a proxy target: an IP
/// literal travels numerically, a name travels as the domain.
fn server_target(node: &Node) -> (SocketAddr, Option<String>) {
    let host = node.host();
    let host = host.trim_start_matches('[').trim_end_matches(']');
    match host.parse::<IpAddr>() {
        Ok(ip) => (SocketAddr::new(ip, node.port), None),
        Err(_) => (
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), node.port),
            Some(host.to_owned()),
        ),
    }
}

/// After one direction of a bridge ends, the other may idle this long
/// before the bridge closes (matches the relay's `DRAIN_DEADLINE`), so a
/// peer that never closes cannot pin the task and both sockets.
#[cfg(not(test))]
const DRAIN_DEADLINE: Duration = Duration::from_secs(30);
#[cfg(test)]
const DRAIN_DEADLINE: Duration = Duration::from_millis(300);

/// Bridges currently alive (observability and leak tests).
static LIVE_BRIDGES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Number of loopback bridges whose copy task is still running.
pub fn live_bridges() -> usize {
    LIVE_BRIDGES.load(std::sync::atomic::Ordering::Relaxed)
}

struct LiveBridge;

impl LiveBridge {
    fn new() -> Self {
        LIVE_BRIDGES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Self
    }
}

impl Drop for LiveBridge {
    fn drop(&mut self) {
        LIVE_BRIDGES.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Copy `reader` to `writer` until EOF, then half-close `writer`. Once
/// `drained` is set (the opposite direction ended), each read may wait at
/// most [`DRAIN_DEADLINE`].
async fn pump<R, W>(
    mut reader: R,
    mut writer: W,
    drained: &tokio::sync::watch::Receiver<bool>,
) -> std::io::Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buffer = vec![0u8; 16 * 1024];
    let mut drained = drained.clone();
    loop {
        let read = async {
            if *drained.borrow() {
                return tokio::time::timeout(DRAIN_DEADLINE, reader.read(&mut buffer))
                    .await
                    .unwrap_or_else(|_| {
                        Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "proxy chain bridge drain deadline",
                        ))
                    });
            }
            tokio::select! {
                read = reader.read(&mut buffer) => read,
                _ = drained.changed() => Err(std::io::Error::from(std::io::ErrorKind::Interrupted)),
            }
        };
        let read = match read.await {
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            other => other?,
        };
        if read == 0 {
            writer.shutdown().await?;
            return Ok(());
        }
        writer.write_all(&buffer[..read]).await?;
        writer.flush().await?;
    }
}

/// Carry `upstream` on a fresh loopback `TcpStream`: returns our end, and a
/// task copies between the other end and `upstream`. EOF in one direction
/// half-closes the other side and starts the drain deadline; an error in
/// either direction closes both at once. The connection is marked so a
/// datapath hooked on `lo` leaves it alone, and only our own connect is
/// accepted.
async fn bridge(upstream: ProxyStream, timeout: Duration) -> anyhow::Result<TcpStream> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let connect =
        crate::util::connect_marked_addr(address, Some(crate::util::bypass_mark()), timeout);
    let accept = listener.accept();
    let (ours, (theirs, peer)) =
        tokio::time::timeout(timeout, async { tokio::try_join!(connect, accept) })
            .await
            .map_err(|_| anyhow::anyhow!("proxy chain bridge setup timed out"))??;
    drop(listener);
    anyhow::ensure!(
        ours.local_addr()? == peer,
        "proxy chain bridge accepted a foreign connection"
    );
    let _ = theirs.set_nodelay(true);
    let _ = ours.set_nodelay(true);
    let live = LiveBridge::new();
    tokio::spawn(async move {
        let _live = live;
        let (local_read, local_write) = theirs.into_split();
        let (remote_read, remote_write) = tokio::io::split(upstream.stream);
        let (drained_tx, drained_rx) = tokio::sync::watch::channel(false);
        let outbound = pump(local_read, remote_write, &drained_rx);
        let inbound = pump(remote_read, local_write, &drained_rx);
        tokio::pin!(outbound, inbound);
        // The first direction to finish starts the drain of the other; an
        // error ends both (dropping the halves closes the sockets).
        let first = tokio::select! {
            result = &mut outbound => (result, true),
            result = &mut inbound => (result, false),
        };
        let result = match first {
            (Err(error), _) => Err(error),
            (Ok(()), outbound_done) => {
                let _ = drained_tx.send(true);
                if outbound_done { inbound.await } else { outbound.await }
            }
        };
        if let Err(error) = result {
            tracing::debug!("proxy chain bridge closed: {error}");
        }
    });
    Ok(ours)
}

/// "hop `a` (1/3) reaching `b`": which leaf failed and what it was reaching,
/// so a dead later hop is not blamed on the hop in front of it.
fn hop_context(leaves: &[Node], index: usize) -> String {
    let toward = leaves
        .get(index + 1)
        .map_or_else(|| "the destination".to_owned(), |next| format!("`{}`", next.name));
    format!(
        "proxy chain hop `{}` ({}/{}) reaching {toward}",
        leaves[index].name,
        index + 1,
        leaves.len()
    )
}

/// Dials chain nodes over a registry of the ordinary protocols.
pub struct ChainHandler {
    base: ProxyRegistry,
}

impl ChainHandler {
    pub fn new(base: ProxyRegistry) -> Self {
        Self { base }
    }

    async fn dial_leaves(
        &self,
        leaves: &[Node],
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        let next = |index: usize| -> (SocketAddr, Option<String>) {
            match leaves.get(index + 1) {
                Some(leaf) => server_target(leaf),
                None => (target, target_domain.map(str::to_owned)),
            }
        };
        let (hop_target, hop_domain) = next(0);
        tracing::debug!(
            "proxy chain: {} -> {}",
            leaves
                .iter()
                .map(|leaf| leaf.name.as_str())
                .collect::<Vec<_>>()
                .join(" -> "),
            target_domain.map_or_else(|| target.to_string(), str::to_owned)
        );
        let generation = RUNTIMES
            .read()
            .as_ref()
            .map(|shared| Arc::clone(&shared.read()))
            .filter(|generation| generation.get(&leaves[0].id).is_some());
        let first = match generation {
            Some(generation) => {
                self.base
                    .dial_runtime(
                        generation,
                        leaves[0].id,
                        hop_target,
                        hop_domain.as_deref(),
                        connect_timeout,
                    )
                    .await
            }
            None => {
                self.base
                    .dial(&leaves[0], hop_target, hop_domain.as_deref(), connect_timeout)
                    .await
            }
        };
        let mut stream = first.map_err(|error| error.context(hop_context(leaves, 0)))?;
        for (index, leaf) in leaves.iter().enumerate().skip(1) {
            let entry = self
                .base
                .find(leaf.protocol())
                .ok_or_else(|| anyhow::anyhow!("no handler for {}", leaf.protocol().as_str()))?;
            let carrier = bridge(stream, connect_timeout).await?;
            let (hop_target, hop_domain) = next(index);
            stream = entry
                .tcp
                .dial_with_tcp(
                    leaf,
                    hop_target,
                    hop_domain.as_deref(),
                    carrier,
                    connect_timeout,
                )
                .await
                .map_err(|error| error.context(hop_context(leaves, index)))?;
        }
        stream.target_addr = target;
        stream.target_domain = target_domain.map(str::to_owned);
        Ok(stream)
    }
}

#[async_trait]
impl TcpOutbound for ChainHandler {
    async fn dial(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        let leaves = leaves(node)?;
        self.dial_leaves(&leaves, target, target_domain, connect_timeout)
            .await
    }

    /// A chain owns its first connection; a supplied socket is never used.
    async fn dial_with_tcp(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        tcp: TcpStream,
        connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        drop(tcp);
        self.dial(node, target, target_domain, connect_timeout)
            .await
    }
}

#[async_trait]
impl ProbeableOutbound for ChainHandler {
    /// Reachability of the first hop; the full path is covered by URL tests.
    async fn test_connectivity(&self, node: &Node) -> bool {
        let Ok(leaves) = leaves(node) else {
            return false;
        };
        match self.base.find(leaves[0].protocol()) {
            Some(entry) => match &entry.probeable {
                Some(probe) => probe.test_connectivity(&leaves[0]).await,
                None => false,
            },
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct MapResolver(HashMap<String, Node>);

    impl ChainResolver for MapResolver {
        fn resolve(&self, tag: &str) -> Option<Node> {
            self.0.get(tag).cloned()
        }
    }

    fn socks(name: &str, port: u16) -> Node {
        let mut node = Node {
            name: name.to_owned(),
            address: format!("127.0.0.1:{port}"),
            host: "127.0.0.1".to_owned(),
            port,
            outbound: OutboundConfig::Socks5(Default::default()),
            ..Node::default()
        };
        node.id = node.derive_id();
        node
    }

    /// Minimal no-auth SOCKS5 CONNECT server that records each target.
    async fn socks_server(log: Arc<parking_lot::Mutex<Vec<String>>>) -> u16 {
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
                            let port = u16::from_be_bytes([port[0], port[1]]);
                            format!("{}:{port}", String::from_utf8_lossy(name))
                        }
                        _ => return Ok::<_, std::io::Error>(()),
                    };
                    log.lock().push(target.clone());
                    let connect = target.replace("localhost", "127.0.0.1");
                    let mut upstream = TcpStream::connect(connect).await?;
                    client.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
                    tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
                    Ok(())
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

    /// Chain tests share the process-wide resolver and bridge counter.
    static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    struct Setup {
        logs: [Arc<parking_lot::Mutex<Vec<String>>>; 3],
        hops: [Node; 3],
        relay: Node,
        handler: ChainHandler,
    }

    async fn setup() -> Setup {
        let logs: [Arc<parking_lot::Mutex<Vec<String>>>; 3] = Default::default();
        let a = socks("a", socks_server(Arc::clone(&logs[0])).await);
        let mut b = socks("b", socks_server(Arc::clone(&logs[1])).await);
        b.host = "localhost".to_owned();
        let c = socks("c", socks_server(Arc::clone(&logs[2])).await);
        install_resolver(Arc::new(MapResolver(HashMap::from([
            ("a".to_owned(), a.clone()),
            ("b".to_owned(), b.clone()),
            ("c".to_owned(), c.clone()),
        ]))));
        // relay: a -> b -> c
        let relay = Node {
            name: "r/relay".to_owned(),
            outbound: OutboundConfig::Chain(ChainConfig {
                hops: vec!["a".to_owned(), "b".to_owned()],
                exit: ChainExit::Tag("c".to_owned()),
            }),
            ..Node::default()
        };
        Setup {
            logs,
            hops: [a, b, c],
            relay,
            handler: ChainHandler::new(ProxyRegistry::default_resolver().unwrap()),
        }
    }

    async fn bridges_settle(baseline: usize) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while live_bridges() > baseline {
            assert!(
                tokio::time::Instant::now() < deadline,
                "{} bridge task(s) leaked",
                live_bridges() - baseline
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    fn local(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    #[tokio::test]
    async fn three_hop_chain_visits_every_hop_in_order() {
        let _serial = SERIAL.lock().await;
        let baseline = live_bridges();
        let Setup {
            logs,
            hops: [_, b, c],
            relay,
            handler,
        } = setup().await;
        let echo = echo_server().await;
        let target = local(echo);
        let mut stream = handler
            .dial(&relay, target, None, Duration::from_secs(3))
            .await
            .unwrap();
        stream.stream.write_all(b"ping through three hops").await.unwrap();
        let mut reply = [0u8; 23];
        stream.stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"ping through three hops");

        // a reached b's server by name, b reached c's server, c the target.
        assert_eq!(*logs[0].lock(), [format!("localhost:{}", b.port)]);
        assert_eq!(*logs[1].lock(), [format!("127.0.0.1:{}", c.port)]);
        assert_eq!(*logs[2].lock(), [format!("127.0.0.1:{echo}")]);
        drop(stream);
        bridges_settle(baseline).await;

        // A refused later hop fails closed before any connection.
        let mut quic = socks("q", 1);
        quic.outbound = OutboundConfig::Hysteria2(Default::default());
        let refused = Node {
            outbound: OutboundConfig::Chain(ChainConfig {
                hops: vec!["a".to_owned()],
                exit: ChainExit::Node(Box::new(quic)),
            }),
            ..Node::default()
        };
        let error = handler
            .dial(&refused, target, None, Duration::from_secs(3))
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("refused"), "{error:#}");
        assert_eq!(logs[0].lock().len(), 1);
    }

    /// Many concurrent flows with bulk data stay byte-exact and leave no
    /// bridge behind.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_bulk_flows_stay_intact() {
        let _serial = SERIAL.lock().await;
        let baseline = live_bridges();
        let setup = Arc::new(setup().await);
        let target = local(echo_server().await);
        let mut flows = tokio::task::JoinSet::new();
        for flow in 0..64u32 {
            let setup = Arc::clone(&setup);
            flows.spawn(async move {
                let stream = setup
                    .handler
                    .dial(&setup.relay, target, None, Duration::from_secs(5))
                    .await
                    .unwrap();
                let (mut read, mut write) = tokio::io::split(stream.stream);
                let payload: Vec<u8> = (0..256 * 1024u32)
                    .map(|i| (i.wrapping_mul(31).wrapping_add(flow) % 251) as u8)
                    .collect();
                let expected = payload.clone();
                let writer = tokio::spawn(async move {
                    write.write_all(&payload).await.unwrap();
                    write.shutdown().await.unwrap();
                });
                let mut echoed = Vec::new();
                read.read_to_end(&mut echoed).await.unwrap();
                writer.await.unwrap();
                assert_eq!(echoed.len(), expected.len(), "flow {flow} length");
                assert!(echoed == expected, "flow {flow} corrupted");
            });
        }
        let started = std::time::Instant::now();
        while let Some(result) = flows.join_next().await {
            result.unwrap();
        }
        tracing::info!("64 x 256 KiB through 3 hops in {:?}", started.elapsed());
        assert_eq!(setup.logs[2].lock().len(), 64);
        bridges_settle(baseline).await;
    }

    /// The client half-closes, the server answers after EOF and closes.
    #[tokio::test]
    async fn half_close_round_trip() {
        let _serial = SERIAL.lock().await;
        let baseline = live_bridges();
        let setup = setup().await;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let target = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            stream.read_to_end(&mut request).await.unwrap();
            stream
                .write_all(format!("got {} bytes", request.len()).as_bytes())
                .await
                .unwrap();
        });
        let stream = setup
            .handler
            .dial(&setup.relay, target, None, Duration::from_secs(3))
            .await
            .unwrap();
        let (mut read, mut write) = tokio::io::split(stream.stream);
        write.write_all(&[7u8; 1000]).await.unwrap();
        write.shutdown().await.unwrap();
        let mut reply = String::new();
        tokio::time::timeout(Duration::from_secs(3), read.read_to_string(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reply, "got 1000 bytes");
        drop((read, write));
        bridges_settle(baseline).await;
    }

    /// A destination that never answers or closes after the client's
    /// half-close cannot pin the bridges: they drain out on the deadline.
    #[tokio::test]
    async fn silent_peer_after_half_close_is_reaped() {
        let _serial = SERIAL.lock().await;
        let baseline = live_bridges();
        let setup = setup().await;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let target = listener.local_addr().unwrap();
        let held = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let keep = Arc::clone(&held);
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut sink = Vec::new();
            stream.read_to_end(&mut sink).await.unwrap();
            keep.lock().push(stream); // never writes, never closes
        });
        let stream = setup
            .handler
            .dial(&setup.relay, target, None, Duration::from_secs(3))
            .await
            .unwrap();
        let (mut read, mut write) = tokio::io::split(stream.stream);
        write.shutdown().await.unwrap();
        assert!(live_bridges() > baseline);
        // The client side stays open; only the bridges' deadline ends it.
        let mut rest = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(5), read.read_to_end(&mut rest)).await;
        bridges_settle(baseline).await;
        drop((read, write, held));
    }

    /// A dead middle hop fails the dial promptly and cleans up.
    #[tokio::test]
    async fn dead_middle_hop_fails_fast() {
        let _serial = SERIAL.lock().await;
        let baseline = live_bridges();
        let Setup {
            hops: [a, _, c],
            relay,
            handler,
            ..
        } = setup().await;
        let closed = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let dead = socks("b", closed.local_addr().unwrap().port());
        drop(closed);
        install_resolver(Arc::new(MapResolver(HashMap::from([
            ("a".to_owned(), a),
            ("b".to_owned(), dead),
            ("c".to_owned(), c),
        ]))));
        let started = std::time::Instant::now();
        let error = handler
            .dial(&relay, local(9), None, Duration::from_secs(3))
            .await
            .unwrap_err();
        assert!(started.elapsed() < Duration::from_secs(2), "{:?}", started.elapsed());
        assert!(format!("{error:#}").contains("reaching `b`"), "{error:#}");
        bridges_settle(baseline).await;
    }

    /// Dropping a flow mid-transfer releases every hop.
    #[tokio::test]
    async fn aborted_flow_releases_bridges() {
        let _serial = SERIAL.lock().await;
        let baseline = live_bridges();
        let setup = setup().await;
        let target = local(echo_server().await);
        for _ in 0..16 {
            let mut stream = setup
                .handler
                .dial(&setup.relay, target, None, Duration::from_secs(3))
                .await
                .unwrap();
            stream.stream.write_all(&[1u8; 64 * 1024]).await.unwrap();
            drop(stream);
        }
        bridges_settle(baseline).await;
    }

    /// An unresolvable hop and a self-referencing chain are refused.
    #[tokio::test]
    async fn unresolved_and_cyclic_hops_are_errors() {
        let _serial = SERIAL.lock().await;
        let setup = setup().await;
        let missing = Node {
            outbound: OutboundConfig::Chain(ChainConfig {
                hops: vec!["nope".to_owned()],
                exit: ChainExit::Tag("c".to_owned()),
            }),
            ..Node::default()
        };
        let error = setup
            .handler
            .dial(&missing, local(9), None, Duration::from_secs(1))
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("resolves to no node"), "{error:#}");

        let looped = Node {
            name: "loop".to_owned(),
            outbound: OutboundConfig::Chain(ChainConfig {
                hops: vec!["loop".to_owned()],
                exit: ChainExit::Tag("c".to_owned()),
            }),
            ..Node::default()
        };
        install_resolver(Arc::new(MapResolver(HashMap::from([
            ("loop".to_owned(), looped.clone()),
            ("c".to_owned(), setup.hops[2].clone()),
        ]))));
        let error = setup
            .handler
            .dial(&looped, local(9), None, Duration::from_secs(1))
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("nests too deeply"), "{error:#}");
    }
}
