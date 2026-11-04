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

/// Carry `upstream` on a fresh loopback `TcpStream`: returns our end, and a
/// task copies between the other end and `upstream` until either closes.
/// The connection is marked so a datapath hooked on `lo` leaves it alone,
/// and only our own connect is accepted.
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
    let mut upstream = upstream.stream;
    tokio::spawn(async move {
        let mut theirs = theirs;
        if let Err(error) = tokio::io::copy_bidirectional(&mut theirs, &mut upstream).await {
            tracing::debug!("proxy chain bridge closed: {error}");
        }
    });
    Ok(ours)
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
        let mut stream = self
            .base
            .dial(&leaves[0], hop_target, hop_domain.as_deref(), connect_timeout)
            .await
            .map_err(|error| error.context(format!("proxy chain hop `{}`", leaves[0].name)))?;
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
                .map_err(|error| error.context(format!("proxy chain hop `{}`", leaf.name)))?;
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

    #[tokio::test]
    async fn three_hop_chain_visits_every_hop_in_order() {
        let log_a = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let log_b = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let log_c = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let a = socks("a", socks_server(Arc::clone(&log_a)).await);
        let mut b = socks("b", socks_server(Arc::clone(&log_b)).await);
        b.host = "localhost".to_owned();
        let c = socks("c", socks_server(Arc::clone(&log_c)).await);
        let echo = echo_server().await;
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
        let handler = ChainHandler::new(ProxyRegistry::default_resolver().unwrap());
        let target: SocketAddr = format!("127.0.0.1:{echo}").parse().unwrap();
        let mut stream = handler
            .dial(&relay, target, None, Duration::from_secs(3))
            .await
            .unwrap();
        stream.stream.write_all(b"ping through three hops").await.unwrap();
        let mut reply = [0u8; 23];
        stream.stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"ping through three hops");

        // a reached b's server by name, b reached c's server, c the target.
        assert_eq!(*log_a.lock(), [format!("localhost:{}", b.port)]);
        assert_eq!(*log_b.lock(), [format!("127.0.0.1:{}", c.port)]);
        assert_eq!(*log_c.lock(), [format!("127.0.0.1:{echo}")]);

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
        assert_eq!(log_a.lock().len(), 1);
    }
}
