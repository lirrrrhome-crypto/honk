//! TCP and UDP proxy chains (mihomo `dialer-proxy` / `relay`).
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
//!
//! UDP takes one of two shapes per exit:
//! - stream-framed exits (Trojan UDP, VLESS native / XUDP / UoT v2) frame UDP
//!   on the chain's TCP stream to their server;
//! - a SOCKS5 exit negotiates UDP ASSOCIATE on the chain's TCP stream and
//!   sends its RFC 1928 datagrams to the relay through the hops in front,
//!   which must themselves carry UDP (recursively).
//!
//! Exits that need their own datagram socket to their server (Shadowsocks,
//! QUIC protocols) refuse UDP in a later position instead of sending it
//! around the chain; see [`udp_path_supported`].

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use honk_config::node::{ChainConfig, ChainExit, Node, OutboundConfig};
use honk_config::types::NodeProtocol;
use parking_lot::RwLock;
use tokio::net::{TcpListener, TcpStream};

use super::{
    PacketOutbound, PacketTransport, ProbeableOutbound, ProxyRegistry, ProxyStream, TcpOutbound,
};

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
pub struct GroupManagerResolver {
    shared: crate::group::SharedGroupManager,
    /// Last manager seen, used when the cell cannot be read without waiting.
    last: parking_lot::Mutex<Arc<crate::group::GroupManager>>,
}

impl GroupManagerResolver {
    pub fn new(shared: crate::group::SharedGroupManager) -> Self {
        let last = parking_lot::Mutex::new(Arc::clone(&shared.read()));
        Self { shared, last }
    }

    /// Never blocks on the manager cell. UDP eligibility asks a chain from
    /// inside group selection, possibly under this cell's read guard, and
    /// parking_lot's task-fair lock would park a second read behind a
    /// queued reload writer forever. While a writer holds or awaits the
    /// cell, the previous manager answers.
    fn manager(&self) -> Arc<crate::group::GroupManager> {
        match self.shared.try_read() {
            Some(guard) => {
                let manager = Arc::clone(&guard);
                drop(guard);
                *self.last.lock() = Arc::clone(&manager);
                manager
            }
            None => Arc::clone(&self.last.lock()),
        }
    }
}

impl ChainResolver for GroupManagerResolver {
    fn resolve(&self, tag: &str) -> Option<Node> {
        let manager = self.manager();
        manager
            .node_by_name(tag)
            .or_else(|| manager.select_node(tag))
            .cloned()
    }
}

fn resolve(tag: &str) -> anyhow::Result<Node> {
    // Written once at startup; the guard never outlives this statement.
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

/// Whether `exit` can carry UDP to `port` over a stream the chain supplies.
pub fn udp_exit_supported(exit: &Node, port: u16) -> Result<(), String> {
    match &exit.outbound {
        OutboundConfig::Trojan(_) => {
            if crate::descriptor::network_allows_udp(exit) {
                Ok(())
            } else {
                Err("Trojan node network excludes udp".to_owned())
            }
        }
        OutboundConfig::Vless(vless) => {
            use honk_config::node::VlessUdpPath;
            match vless.udp_path(port) {
                _ if exit.is_xhttp() => Err("VLESS XHTTP UDP cannot be chained".to_owned()),
                Some(VlessUdpPath::Native | VlessUdpPath::Xudp | VlessUdpPath::UotV2) => Ok(()),
                Some(other) => Err(format!("VLESS {other:?} UDP cannot be chained")),
                None => Err(format!("VLESS UDP to port {port} is disabled")),
            }
        }
        other => Err(format!(
            "{} UDP needs its own datagram socket to its server; later hops chain UDP \
             only as Trojan, VLESS or SOCKS5",
            other.protocol().as_str()
        )),
    }
}

/// Whether UDP to `port` can traverse `leaves` (first hop first, exit last).
/// A lone leaf uses its own UDP; a stream-framed exit needs only TCP from the
/// hops in front; a SOCKS5 exit needs the hops in front to carry UDP to its
/// relay, checked recursively.
pub fn udp_path_supported(leaves: &[Node], port: u16) -> Result<(), String> {
    let Some((exit, hops)) = leaves.split_last() else {
        return Err("empty chain".to_owned());
    };
    if hops.is_empty() {
        return if (crate::descriptor::descriptor(exit.protocol()).supports_udp)(exit) {
            Ok(())
        } else {
            Err(format!("`{}` ({}) carries no UDP", exit.name, exit.protocol().as_str()))
        };
    }
    match &exit.outbound {
        // The relay port is only known after UDP ASSOCIATE; 0 skips port policy.
        OutboundConfig::Socks5(_) => udp_path_supported(hops, 0).map_err(|reason| {
            format!(
                "SOCKS5 exit `{}` needs UDP from the hops in front: {reason}",
                exit.name
            )
        }),
        _ => udp_exit_supported(exit, port),
    }
}

/// Descriptor predicate: whether UDP can traverse the chain's current leaves.
/// Resolved live, so a relay whose exit is a group follows that group's pick.
pub fn chain_supports_udp(node: &Node) -> bool {
    leaves(node).is_ok_and(|leaves| udp_path_supported(&leaves, 0).is_ok())
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

    /// Dial through `leaves` to `target`. `chain` is the whole chain the
    /// leaves start, so errors name hops by their place in it (a UDP dial
    /// stops one leaf short, at the exit's server).
    async fn dial_leaves(
        &self,
        leaves: &[Node],
        chain: &[Node],
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
        let mut stream = first.map_err(|error| error.context(hop_context(chain, 0)))?;
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
                .map_err(|error| error.context(hop_context(chain, index)))?;
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
        self.dial_leaves(&leaves, &leaves, target, target_domain, connect_timeout)
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

impl ChainHandler {
    /// A UDP transport to `target` through `leaves`; `chain` names hops in
    /// errors. Recursive for SOCKS5 exits, whose datagrams take the leaves in
    /// front of them.
    fn udp_through<'a>(
        &'a self,
        leaves: &'a [Node],
        chain: &'a [Node],
        target: SocketAddr,
        target_domain: Option<&'a str>,
        connect_timeout: Duration,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<Arc<dyn PacketTransport>>> + Send + 'a>,
    > {
        Box::pin(async move {
            let (exit, hops) = leaves.split_last().expect("leaves are nonempty");
            let index = leaves.len() - 1;
            if hops.is_empty() {
                // The first hop sends real datagrams; reuse its live session.
                let generation = RUNTIMES
                    .read()
                    .as_ref()
                    .map(|shared| Arc::clone(&shared.read()))
                    .filter(|generation| generation.get(&exit.id).is_some());
                let transport = match generation {
                    Some(generation) => {
                        self.base
                            .dial_udp_transport_runtime(
                                generation,
                                exit.id,
                                target,
                                target_domain,
                                connect_timeout,
                            )
                            .await
                    }
                    None => {
                        self.base
                            .dial_udp_transport(exit, target, target_domain, connect_timeout)
                            .await
                    }
                };
                return transport.map_err(|error| error.context(hop_context(chain, index)));
            }
            let refuse = |reason: String| {
                anyhow::Error::from(super::PacketRejection::Policy).context(format!(
                    "proxy chain hop `{}` refused UDP: {reason}",
                    exit.name
                ))
            };
            let (server, server_domain) = server_target(exit);
            if let OutboundConfig::Socks5(_) = &exit.outbound {
                udp_path_supported(hops, 0).map_err(refuse)?;
                let stream = self
                    .dial_leaves(hops, chain, server, server_domain.as_deref(), connect_timeout)
                    .await?;
                let mut control = bridge(stream, connect_timeout).await?;
                let relay = super::socks5::Socks5Handler::associate_over_chain(exit, &mut control)
                    .await
                    .map_err(|error| error.context(hop_context(chain, index)))?;
                let (relay_target, relay_domain) = match relay {
                    super::socks5::RelayAddr::Ip(addr) => (addr, None),
                    super::socks5::RelayAddr::Domain(domain, port) => (
                        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port),
                        Some(domain),
                    ),
                };
                tracing::debug!(
                    "proxy chain: SOCKS5 `{}` relay {} via the hops in front",
                    exit.name,
                    relay_domain
                        .as_deref()
                        .map_or_else(|| relay_target.to_string(), |d| format!("{d}:{}", relay_target.port()))
                );
                let datagrams = self
                    .udp_through(hops, chain, relay_target, relay_domain.as_deref(), connect_timeout)
                    .await?;
                let transport =
                    super::socks5::Socks5RelayedUdp::new(datagrams, control, target, target_domain)?;
                return Ok(Arc::new(transport));
            }
            udp_exit_supported(exit, target.port()).map_err(refuse)?;
            let packet = self
                .base
                .find(exit.protocol())
                .and_then(|entry| entry.packet.clone())
                .ok_or_else(|| refuse("no UDP handler".to_owned()))?;
            let stream = self
                .dial_leaves(hops, chain, server, server_domain.as_deref(), connect_timeout)
                .await?;
            let carrier = bridge(stream, connect_timeout).await?;
            packet
                .dial_udp_transport_with_tcp(exit, target, target_domain, carrier, connect_timeout)
                .await
                .map_err(|error| error.context(hop_context(chain, index)))
        })
    }
}

#[async_trait]
impl PacketOutbound for ChainHandler {
    async fn dial_udp_transport(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        let leaves = leaves(node)?;
        // Refuse before dialing anything when no hop arrangement can carry it.
        udp_path_supported(&leaves, target.port()).map_err(|reason| {
            anyhow::Error::from(super::PacketRejection::Policy)
                .context(format!("proxy chain refused UDP: {reason}"))
        })?;
        self.udp_through(&leaves, &leaves, target, target_domain, connect_timeout)
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

    // ------------------------------------------------------------ UDP

    async fn read_socks_addr(
        stream: &mut (impl tokio::io::AsyncRead + Unpin),
    ) -> std::io::Result<SocketAddr> {
        let mut atyp = [0u8; 1];
        stream.read_exact(&mut atyp).await?;
        match atyp[0] {
            1 => {
                let mut raw = [0u8; 6];
                stream.read_exact(&mut raw).await?;
                Ok(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3])),
                    u16::from_be_bytes([raw[4], raw[5]]),
                ))
            }
            3 => {
                let mut len = [0u8; 1];
                stream.read_exact(&mut len).await?;
                let mut raw = vec![0u8; len[0] as usize + 2];
                stream.read_exact(&mut raw).await?;
                let port = u16::from_be_bytes([raw[len[0] as usize], raw[len[0] as usize + 1]]);
                // Test names all mean loopback.
                Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port))
            }
            _ => Err(std::io::Error::other("unsupported atyp")),
        }
    }

    fn socks_addr(addr: SocketAddr) -> Vec<u8> {
        let SocketAddr::V4(v4) = addr else {
            panic!("tests use IPv4")
        };
        let mut out = vec![1];
        out.extend_from_slice(&v4.ip().octets());
        out.extend_from_slice(&v4.port().to_be_bytes());
        out
    }

    /// Plaintext Trojan server: CONNECT and UDP ASSOCIATE, recording the
    /// command of every accepted request.
    async fn trojan_server(commands: Arc<parking_lot::Mutex<Vec<u8>>>) -> u16 {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let (mut client, _) = listener.accept().await.unwrap();
                let commands = Arc::clone(&commands);
                tokio::spawn(async move {
                    let mut auth = [0u8; 58];
                    client.read_exact(&mut auth).await?;
                    let mut command = [0u8; 1];
                    client.read_exact(&mut command).await?;
                    let target = read_socks_addr(&mut client).await?;
                    let mut crlf = [0u8; 2];
                    client.read_exact(&mut crlf).await?;
                    commands.lock().push(command[0]);
                    if command[0] == 1 {
                        let mut upstream = TcpStream::connect(target).await?;
                        tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
                        return Ok::<_, std::io::Error>(());
                    }
                    let socket = Arc::new(tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?);
                    let (mut read, mut write) = client.into_split();
                    let replies = Arc::clone(&socket);
                    let back = tokio::spawn(async move {
                        let mut buffer = vec![0u8; 65535];
                        loop {
                            let (n, from) = replies.recv_from(&mut buffer).await?;
                            let mut frame = socks_addr(from);
                            frame.extend_from_slice(&(n as u16).to_be_bytes());
                            frame.extend_from_slice(b"\r\n");
                            frame.extend_from_slice(&buffer[..n]);
                            write.write_all(&frame).await?;
                        }
                        #[allow(unreachable_code)]
                        Ok::<_, std::io::Error>(())
                    });
                    loop {
                        let Ok(destination) = read_socks_addr(&mut read).await else {
                            break;
                        };
                        let mut head = [0u8; 4];
                        read.read_exact(&mut head).await?;
                        let len = u16::from_be_bytes([head[0], head[1]]) as usize;
                        let mut payload = vec![0u8; len];
                        read.read_exact(&mut payload).await?;
                        socket.send_to(&payload, destination).await?;
                    }
                    back.abort();
                    Ok(())
                });
            }
        });
        port
    }

    async fn udp_echo() -> SocketAddr {
        let socket = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buffer = vec![0u8; 65535];
            loop {
                let (n, from) = socket.recv_from(&mut buffer).await.unwrap();
                socket.send_to(&buffer[..n], from).await.unwrap();
            }
        });
        address
    }

    fn trojan(name: &str, port: u16) -> Node {
        let mut node = Node {
            name: name.to_owned(),
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

    #[tokio::test]
    async fn udp_rides_the_chain_to_a_trojan_exit() {
        let _serial = SERIAL.lock().await;
        let baseline = live_bridges();
        let logs: [Arc<parking_lot::Mutex<Vec<String>>>; 2] = Default::default();
        let a = socks("a", socks_server(Arc::clone(&logs[0])).await);
        let b = socks("b", socks_server(Arc::clone(&logs[1])).await);
        let commands = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let exit = trojan("exit", trojan_server(Arc::clone(&commands)).await);
        install_resolver(Arc::new(MapResolver(HashMap::from([
            ("a".to_owned(), a.clone()),
            ("b".to_owned(), b.clone()),
            ("exit".to_owned(), exit.clone()),
        ]))));
        let relay = Node {
            name: "r/relay".to_owned(),
            outbound: OutboundConfig::Chain(ChainConfig {
                hops: vec!["a".to_owned(), "b".to_owned()],
                exit: ChainExit::Tag("exit".to_owned()),
            }),
            ..Node::default()
        };
        assert!(chain_supports_udp(&relay));
        let handler = ChainHandler::new(ProxyRegistry::default_resolver().unwrap());
        let echo = udp_echo().await;

        let transport = handler
            .dial_udp_transport(&relay, echo, None, Duration::from_secs(3))
            .await
            .unwrap();
        // Many datagrams, sizes up to near the UDP maximum, in order.
        for size in [1usize, 512, 1400, 8 * 1024, 60 * 1024] {
            let payload: Vec<u8> = (0..size).map(|i| (i * 7 + size) as u8).collect();
            transport.send_packet(&payload).await.unwrap();
            let mut reply = vec![0u8; 65535];
            let (n, from) = tokio::time::timeout(Duration::from_secs(3), transport.recv_packet(&mut reply))
                .await
                .expect("reply within 3s")
                .unwrap();
            assert_eq!(&reply[..n], &payload[..], "datagram of {size} bytes");
            assert_eq!(from, echo);
        }
        // The TCP path went a -> b -> exit; only the exit spoke UDP.
        assert_eq!(*logs[0].lock(), [format!("127.0.0.1:{}", b.port)]);
        assert_eq!(*logs[1].lock(), [format!("127.0.0.1:{}", exit.port)]);
        assert_eq!(*commands.lock(), [3]);

        drop(transport);
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while live_bridges() > baseline && std::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(live_bridges(), baseline, "UDP bridges must close with the transport");
    }

    #[tokio::test]
    async fn udp_to_a_datagram_only_exit_is_refused_before_any_connection() {
        let _serial = SERIAL.lock().await;
        let log = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let a = socks("a", socks_server(Arc::clone(&log)).await);
        let mut ss = socks("ss", 1);
        ss.outbound = OutboundConfig::Shadowsocks(honk_config::node::ShadowsocksConfig {
            password: Some("pw".to_owned()),
            encryption: Some("aes-128-gcm".to_owned()),
            ..Default::default()
        });
        install_resolver(Arc::new(MapResolver(HashMap::from([("a".to_owned(), a)]))));
        let chained = Node {
            outbound: OutboundConfig::Chain(ChainConfig {
                hops: vec!["a".to_owned()],
                exit: ChainExit::Node(Box::new(ss)),
            }),
            ..Node::default()
        };
        assert!(!chain_supports_udp(&chained));
        let handler = ChainHandler::new(ProxyRegistry::default_resolver().unwrap());
        let error = handler
            .dial_udp_transport(&chained, local(53), None, Duration::from_secs(3))
            .await
            .unwrap_err();
        assert!(
            error.chain().any(|cause| cause.downcast_ref::<super::super::PacketRejection>().is_some()),
            "{error:#}"
        );
        assert!(log.lock().is_empty(), "no hop may be dialed for a refused exit");
    }

    /// Plaintext VLESS server for native command-UDP only.
    #[cfg(feature = "rprx")]
    async fn vless_udp_server(uuid: [u8; 16]) -> u16 {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let (mut client, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut head = [0u8; 18];
                    client.read_exact(&mut head).await?;
                    assert_eq!(&head[1..17], &uuid, "VLESS uuid");
                    let mut addons = vec![0u8; head[17] as usize];
                    client.read_exact(&mut addons).await?;
                    let mut command = [0u8; 3];
                    client.read_exact(&mut command).await?;
                    assert_eq!(command[0], 2, "native UDP command");
                    let port = u16::from_be_bytes([command[1], command[2]]);
                    let mut atyp = [0u8; 1];
                    client.read_exact(&mut atyp).await?;
                    let mut ip = [0u8; 4];
                    assert_eq!(atyp[0], 1, "tests use IPv4 targets");
                    client.read_exact(&mut ip).await?;
                    let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port);
                    client.write_all(&[0, 0]).await?;
                    let socket = Arc::new(tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?);
                    socket.connect(target).await?;
                    let (mut read, mut write) = client.into_split();
                    let replies = Arc::clone(&socket);
                    let back = tokio::spawn(async move {
                        let mut buffer = vec![0u8; 65535];
                        loop {
                            let n = replies.recv(&mut buffer).await?;
                            write.write_all(&(n as u16).to_be_bytes()).await?;
                            write.write_all(&buffer[..n]).await?;
                        }
                        #[allow(unreachable_code)]
                        Ok::<_, std::io::Error>(())
                    });
                    loop {
                        let mut len = [0u8; 2];
                        if read.read_exact(&mut len).await.is_err() {
                            break;
                        }
                        let mut payload = vec![0u8; u16::from_be_bytes(len) as usize];
                        read.read_exact(&mut payload).await?;
                        socket.send(&payload).await?;
                    }
                    back.abort();
                    Ok::<_, std::io::Error>(())
                });
            }
        });
        port
    }

    #[cfg(feature = "rprx")]
    #[tokio::test]
    async fn udp_rides_the_chain_to_a_vless_native_exit() {
        let _serial = SERIAL.lock().await;
        let baseline = live_bridges();
        let log = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let a = socks("a", socks_server(Arc::clone(&log)).await);
        let uuid = *uuid::Uuid::parse_str("9d3e3b62-6a0b-4d55-9a3c-1b2f6f1b0c11").unwrap().as_bytes();
        let port = vless_udp_server(uuid).await;
        let mut exit = socks("vless-exit", port);
        exit.outbound = OutboundConfig::Vless(honk_config::node::VlessConfig {
            uuid: Some("9d3e3b62-6a0b-4d55-9a3c-1b2f6f1b0c11".to_owned()),
            encryption: Some("none".to_owned()),
            udp_encoding: honk_config::node::VlessUdpEncoding::Native,
            ..Default::default()
        });
        exit.id = exit.derive_id();
        install_resolver(Arc::new(MapResolver(HashMap::from([("a".to_owned(), a)]))));
        let chained = Node {
            outbound: OutboundConfig::Chain(ChainConfig {
                hops: vec!["a".to_owned()],
                exit: ChainExit::Node(Box::new(exit.clone())),
            }),
            ..Node::default()
        };
        assert!(chain_supports_udp(&chained));
        let handler = ChainHandler::new(ProxyRegistry::default_resolver().unwrap());
        let echo = udp_echo().await;
        let transport = handler
            .dial_udp_transport(&chained, echo, None, Duration::from_secs(3))
            .await
            .unwrap();
        // VLESS native UDP caps a datagram at 8190 bytes.
        for size in [1usize, 1200, 8190] {
            let payload: Vec<u8> = (0..size).map(|i| (i * 13 + 1) as u8).collect();
            transport.send_packet(&payload).await.unwrap();
            let mut reply = vec![0u8; 65535];
            let (n, _) = tokio::time::timeout(Duration::from_secs(3), transport.recv_packet(&mut reply))
                .await
                .expect("reply within 3s")
                .unwrap();
            assert_eq!(&reply[..n], &payload[..]);
        }
        assert_eq!(*log.lock(), [format!("127.0.0.1:{}", exit.port)]);
        drop(transport);
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while live_bridges() > baseline && std::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(live_bridges(), baseline);
    }

    /// UDP eligibility runs inside group selection, which may hold the
    /// manager's read guard; a reload writer queued meanwhile must not
    /// deadlock the chain's resolver.
    #[test]
    fn resolver_reads_under_a_held_guard_with_a_queued_writer() {
        let node = socks("a", 1);
        let shared = crate::group::GroupManager::new(&[], std::slice::from_ref(&node)).into_shared();
        let resolver = GroupManagerResolver::new(Arc::clone(&shared));
        let guard = shared.read();
        let writer = {
            let shared = Arc::clone(&shared);
            std::thread::spawn(move || {
                let _write = shared.write();
            })
        };
        // Give the writer time to queue behind `guard`.
        std::thread::sleep(Duration::from_millis(100));
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let resolver = Arc::new(resolver);
        // Detached: a deadlocked resolver must fail the test, not hang it.
        std::thread::spawn({
            let resolver = Arc::clone(&resolver);
            move || {
                let _ = done_tx.send(resolver.resolve("a").map(|node| node.name));
            }
        });
        let resolved = done_rx.recv_timeout(Duration::from_secs(2));
        drop(guard);
        let resolved = resolved.expect("resolver deadlocked behind a queued writer");
        assert_eq!(resolved.as_deref(), Some("a"));
        writer.join().unwrap();
    }

    // ------------------------------------------------------------ SOCKS5 UDP

    #[derive(Default)]
    struct SocksUdpLog {
        connects: Vec<String>,
        associations: usize,
        datagrams_to: Vec<SocketAddr>,
    }

    /// SOCKS5 server with CONNECT and UDP ASSOCIATE. The associate reply
    /// names `0.0.0.0:<relay port>`, as many servers do, so clients must
    /// substitute the server's address themselves.
    async fn socks_udp_server(log: Arc<parking_lot::Mutex<SocksUdpLog>>) -> u16 {
        socks_udp_server_on(Ipv4Addr::LOCALHOST, log).await
    }

    /// `ip` lets the server live on a loopback address other than the
    /// bridges' 127.0.0.1, so a relay rebuilt from the bridge peer is caught.
    async fn socks_udp_server_on(ip: Ipv4Addr, log: Arc<parking_lot::Mutex<SocksUdpLog>>) -> u16 {
        let listener = TcpListener::bind((ip, 0)).await.unwrap();
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
                    let mut request = [0u8; 3];
                    client.read_exact(&mut request).await?;
                    let target = read_socks_addr(&mut client).await?;
                    if request[1] == 1 {
                        log.lock().connects.push(target.to_string());
                        let mut upstream = TcpStream::connect(target).await?;
                        client.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
                        tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
                        return Ok::<_, std::io::Error>(());
                    }
                    assert_eq!(request[1], 3, "UDP ASSOCIATE");
                    log.lock().associations += 1;
                    let relay = tokio::net::UdpSocket::bind((ip, 0)).await?;
                    let relay_port = relay.local_addr()?.port();
                    let mut reply = vec![5, 0, 0, 1, 0, 0, 0, 0];
                    reply.extend_from_slice(&relay_port.to_be_bytes());
                    client.write_all(&reply).await?;
                    let mut buffer = vec![0u8; 65535];
                    let mut probe = [0u8; 1];
                    let mut peer: Option<SocketAddr> = None;
                    loop {
                        tokio::select! {
                            received = relay.recv_from(&mut buffer) => {
                                let (n, from) = received?;
                                if peer.is_none_or(|peer| peer == from) && n >= 10 && buffer[3] == 1 {
                                    // A client request: strip the header, forward.
                                    peer = Some(from);
                                    let destination = SocketAddr::new(
                                        IpAddr::V4(Ipv4Addr::new(buffer[4], buffer[5], buffer[6], buffer[7])),
                                        u16::from_be_bytes([buffer[8], buffer[9]]),
                                    );
                                    log.lock().datagrams_to.push(destination);
                                    relay.send_to(&buffer[10..n], destination).await?;
                                } else if let Some(peer) = peer {
                                    // A reply: wrap with its source, return to the client.
                                    let mut frame = vec![0, 0, 0];
                                    frame.extend_from_slice(&socks_addr(from));
                                    frame.extend_from_slice(&buffer[..n]);
                                    relay.send_to(&frame, peer).await?;
                                }
                            }
                            closed = client.read(&mut probe) => {
                                if closed.unwrap_or(0) == 0 {
                                    return Ok(());
                                }
                            }
                        }
                    }
                });
            }
        });
        port
    }

    async fn udp_round_trips(transport: &Arc<dyn PacketTransport>, echo: SocketAddr) {
        for size in [1usize, 512, 1400, 8 * 1024] {
            let payload: Vec<u8> = (0..size).map(|i| (i * 11 + size) as u8).collect();
            transport.send_packet(&payload).await.unwrap();
            let mut reply = vec![0u8; 65535];
            let (n, from) = tokio::time::timeout(Duration::from_secs(3), transport.recv_packet(&mut reply))
                .await
                .expect("reply within 3s")
                .unwrap();
            assert_eq!(&reply[..n], &payload[..], "datagram of {size} bytes");
            assert_eq!(from, echo, "reply names the real remote peer");
        }
    }

    async fn wait_for_bridges(baseline: usize) {
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while live_bridges() > baseline && std::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(live_bridges(), baseline, "bridges must close with the transport");
    }

    #[tokio::test]
    async fn udp_reaches_a_socks5_exit_through_a_native_udp_hop() {
        let _serial = SERIAL.lock().await;
        let baseline = live_bridges();
        let front_log = Arc::new(parking_lot::Mutex::new(SocksUdpLog::default()));
        let exit_log = Arc::new(parking_lot::Mutex::new(SocksUdpLog::default()));
        let front = socks("front", socks_udp_server(Arc::clone(&front_log)).await);
        let exit_ip = Ipv4Addr::new(127, 0, 0, 2);
        let mut exit = socks("exit", socks_udp_server_on(exit_ip, Arc::clone(&exit_log)).await);
        exit.host = exit_ip.to_string();
        exit.address = format!("{exit_ip}:{}", exit.port);
        install_resolver(Arc::new(MapResolver(HashMap::from([("front".to_owned(), front)]))));
        let chained = Node {
            outbound: OutboundConfig::Chain(ChainConfig {
                hops: vec!["front".to_owned()],
                exit: ChainExit::Node(Box::new(exit.clone())),
            }),
            ..Node::default()
        };
        assert!(chain_supports_udp(&chained));
        let handler = ChainHandler::new(ProxyRegistry::default_resolver().unwrap());
        let echo = udp_echo().await;
        let transport = handler
            .dial_udp_transport(&chained, echo, None, Duration::from_secs(3))
            .await
            .unwrap();
        udp_round_trips(&transport, echo).await;

        // Control went front -> exit over TCP; the exit's unspecified relay
        // was replaced by its own server host, and front carried the
        // datagrams to it with its own UDP association.
        let front_log = front_log.lock();
        assert_eq!(front_log.connects, [format!("{exit_ip}:{}", exit.port)]);
        assert_eq!(front_log.associations, 1);
        assert_eq!(front_log.datagrams_to.len(), 4);
        assert!(
            front_log.datagrams_to.iter().all(|to| to.ip() == IpAddr::V4(exit_ip) && to.port() != exit.port),
            "datagrams must go to the exit's own relay, not the bridge: {:?}",
            front_log.datagrams_to
        );
        drop(front_log);
        let exit_log = exit_log.lock();
        assert_eq!(exit_log.associations, 1);
        assert!(exit_log.datagrams_to.iter().all(|to| *to == echo));
        assert_eq!(exit_log.datagrams_to.len(), 4);
        drop(exit_log);
        drop(transport);
        wait_for_bridges(baseline).await;
    }

    #[tokio::test]
    async fn udp_reaches_a_socks5_exit_through_a_trojan_hop() {
        let _serial = SERIAL.lock().await;
        let baseline = live_bridges();
        let a = socks("a", socks_server(Arc::new(parking_lot::Mutex::new(Vec::new()))).await);
        let commands = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let middle = trojan("middle", trojan_server(Arc::clone(&commands)).await);
        let exit_log = Arc::new(parking_lot::Mutex::new(SocksUdpLog::default()));
        let exit = socks("exit", socks_udp_server(Arc::clone(&exit_log)).await);
        install_resolver(Arc::new(MapResolver(HashMap::from([
            ("a".to_owned(), a),
            ("middle".to_owned(), middle),
        ]))));
        let chained = Node {
            outbound: OutboundConfig::Chain(ChainConfig {
                hops: vec!["a".to_owned(), "middle".to_owned()],
                exit: ChainExit::Node(Box::new(exit)),
            }),
            ..Node::default()
        };
        assert!(chain_supports_udp(&chained));
        let handler = ChainHandler::new(ProxyRegistry::default_resolver().unwrap());
        let echo = udp_echo().await;
        let transport = handler
            .dial_udp_transport(&chained, echo, None, Duration::from_secs(3))
            .await
            .unwrap();
        udp_round_trips(&transport, echo).await;
        // Trojan carried the control CONNECT and, separately, the datagrams.
        let mut seen = commands.lock().clone();
        seen.sort_unstable();
        assert_eq!(seen, [1, 3]);
        assert_eq!(exit_log.lock().datagrams_to.len(), 4);
        drop(transport);
        wait_for_bridges(baseline).await;
    }

    #[tokio::test]
    async fn socks5_exit_without_udp_in_front_is_refused_before_dialing() {
        let _serial = SERIAL.lock().await;
        let log = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let a = socks("a", socks_server(Arc::clone(&log)).await);
        let mut ss = socks("ss", 1);
        ss.outbound = OutboundConfig::Shadowsocks(honk_config::node::ShadowsocksConfig {
            password: Some("pw".to_owned()),
            encryption: Some("aes-128-gcm".to_owned()),
            ..Default::default()
        });
        install_resolver(Arc::new(MapResolver(HashMap::from([
            ("a".to_owned(), a),
            ("ss".to_owned(), ss),
        ]))));
        let chained = Node {
            outbound: OutboundConfig::Chain(ChainConfig {
                hops: vec!["a".to_owned(), "ss".to_owned()],
                exit: ChainExit::Node(Box::new(socks("exit", 2))),
            }),
            ..Node::default()
        };
        assert!(!chain_supports_udp(&chained));
        let handler = ChainHandler::new(ProxyRegistry::default_resolver().unwrap());
        let error = handler
            .dial_udp_transport(&chained, local(53), None, Duration::from_secs(3))
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("SOCKS5 exit `exit` needs UDP"), "{error:#}");
        assert!(log.lock().is_empty(), "nothing may be dialed for a refused chain");
    }
}
