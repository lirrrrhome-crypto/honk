//! Node-level chained dialing (`detour` / `dialer-proxy`).
//!
//! A node whose [`Node::detour`] names another node or a group opens its
//! server connection *through* that front hop: the front is dialed with the
//! chained node's server as its target, and the resulting stream is handed to
//! the chained node's [`super::TcpOutbound::dial_with_tcp`].
//!
//! Handlers take their pre-connected carrier as a `TcpStream`, so the front
//! stream is bridged through a private loopback socket pair (one accepted
//! connection, verified by peer address, relayed by one task). This keeps
//! every TCP-carried protocol unchanged at the cost of one local copy.
//!
//! UDP: a landing that frames UDP inside its own TCP stream (Trojan, VLESS) carries
//! it over the same front chain, so any TCP-capable front (node or group)
//! works. Native-UDP landings (Shadowsocks, SOCKS5 UDP ASSOCIATE) send their
//! framed datagrams through a [`super::datagram_pipe::DatagramPipe`] that is
//! the front's own UDP relay (SOCKS5 UDP ASSOCIATE, Shadowsocks UDP, Trojan
//! UDP-over-TCP, or a chained front recursively) addressed to the landing's
//! server; a front without a UDP path is refused with a clear error, never
//! bypassed (see [`FrontCarrier`]). Detour nodes never
//! pool or warm (see `descriptor::unchained`); configuration validation rejects UDP/QUIC-native
//! protocols, unknown or ambiguous fronts and cycles, and the dial path
//! re-checks depth as a guard against cycles introduced by dynamic group
//! membership.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use futures_util::future::BoxFuture;
use honk_config::node::Node;
use honk_config::types::NodeProtocol;
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use anyhow::Context as _;
use async_trait::async_trait;

use super::{DirectMark, ProxyStream, TcpOutbound};
use crate::group::SharedGroupManager;
use crate::runtime::OutboundRuntimeRegistry;
use crate::runtime::{NodeRuntime, SharedRuntimeRegistry};

/// Longest accepted front chain; deeper chains are treated as a cycle.
pub const MAX_DETOUR_DEPTH: usize = honk_config::node::MAX_DETOUR_HOPS;

static GROUP_MANAGER: OnceLock<parking_lot::RwLock<Option<SharedGroupManager>>> = OnceLock::new();

/// Install the live group manager so group-named fronts resolve to the
/// group's current TCP selection. Reloads swap the shared cell's contents,
/// so installing once per process is sufficient; reinstalling replaces it.
pub fn install_group_manager(manager: SharedGroupManager) {
    *GROUP_MANAGER
        .get_or_init(|| parking_lot::RwLock::new(None))
        .write() = Some(manager);
}

static RUNTIME_REGISTRY: OnceLock<
    parking_lot::RwLock<std::sync::Weak<parking_lot::RwLock<Arc<OutboundRuntimeRegistry>>>>,
> = OnceLock::new();

/// Install the live runtime-generation cell so handler-level dials (health
/// probes, delay tests, downloads) that hold only a [`NodeRuntime`] resolve
/// node-named fronts against the current generation. Held weakly: the owner
/// of the cell keeps it alive.
pub fn install_runtime_registry(registry: &SharedRuntimeRegistry) {
    *RUNTIME_REGISTRY
        .get_or_init(|| parking_lot::RwLock::new(std::sync::Weak::new()))
        .write() = Arc::downgrade(registry);
}

/// A whole chained dial, however deep, finishes within this many
/// `connect_timeout`s. It matches honk-core's per-dial cap
/// (`connect_timeout * 3`), so the chain's own failover finishes first.
pub(crate) const CHAIN_BUDGET_FACTOR: u32 = 3;

tokio::task_local! {
    static PINNED_GENERATION: Arc<OutboundRuntimeRegistry>;
}

/// Run `future` with `generation` pinned for chained dials made through a
/// bare handler (probes, delay tests, download tunnels): their node-named
/// fronts resolve against this generation instead of the live one, so a
/// probe started before a reload keeps using the fronts it was planned with.
pub async fn pin_generation<F: std::future::Future>(
    generation: Arc<OutboundRuntimeRegistry>,
    future: F,
) -> F::Output {
    PINNED_GENERATION.scope(generation, future).await
}

/// The caller's pinned generation if any, otherwise the live one.
fn caller_generation() -> Option<Arc<OutboundRuntimeRegistry>> {
    PINNED_GENERATION
        .try_with(Arc::clone)
        .ok()
        .or_else(current_generation)
}

fn current_generation() -> Option<Arc<OutboundRuntimeRegistry>> {
    let cell = RUNTIME_REGISTRY.get()?.read().upgrade()?;
    let generation = Arc::clone(&cell.read());
    Some(generation)
}

/// Raw (unwrapped) TCP handlers by protocol, shared between a registry and
/// the [`ChainAware`] wrappers it hands out. It holds only inner handlers, so
/// there is no reference cycle back to the wrappers or the registry.
pub(crate) type TcpTable = Arc<parking_lot::RwLock<Vec<(NodeProtocol, Arc<dyn TcpOutbound>)>>>;

fn inner_handler(table: &TcpTable, protocol: NodeProtocol) -> anyhow::Result<Arc<dyn TcpOutbound>> {
    table
        .read()
        .iter()
        .find(|(candidate, _)| *candidate == protocol)
        .map(|(_, handler)| Arc::clone(handler))
        .ok_or_else(|| anyhow::anyhow!("No handler for protocol {:?}", protocol))
}

/// The registry's public TCP handler: delegates to the protocol handler, but
/// any dial of a node carrying a detour goes through [`dial_chained`]. Every
/// caller that reaches a handler directly (urltest, delay tests, native
/// probes, download tunnels) therefore honours the chain and never connects
/// straight to a chained node's server.
pub(crate) struct ChainAware {
    pub(crate) inner: Arc<dyn TcpOutbound>,
    pub(crate) table: TcpTable,
    pub(crate) packet: PacketTable,
}

#[async_trait]
impl TcpOutbound for ChainAware {
    async fn dial(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        if node.detour.is_some() {
            return dial_chained(
                &self.table,
                &self.packet,
                caller_generation(),
                node.clone(),
                target,
                target_domain.map(str::to_owned),
                connect_timeout,
                0,
            )
            .await;
        }
        self.inner
            .dial(node, target, target_domain, connect_timeout)
            .await
    }

    async fn dial_with_tcp(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        tcp: TcpStream,
        connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        self.inner
            .dial_with_tcp(node, target, target_domain, tcp, connect_timeout)
            .await
    }

    async fn dial_runtime(
        &self,
        runtime: Arc<NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        if runtime.node.detour.is_some() {
            return dial_chained(
                &self.table,
                &self.packet,
                caller_generation(),
                runtime.node.as_ref().clone(),
                target,
                target_domain.map(str::to_owned),
                connect_timeout,
                0,
            )
            .await;
        }
        self.inner
            .dial_runtime(runtime, target, target_domain, connect_timeout)
            .await
    }

    async fn dial_runtime_marked(
        &self,
        runtime: Arc<NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
        mark: DirectMark,
    ) -> anyhow::Result<ProxyStream> {
        if runtime.node.detour.is_some() {
            return self
                .dial_runtime(runtime, target, target_domain, connect_timeout)
                .await;
        }
        self.inner
            .dial_runtime_marked(runtime, target, target_domain, connect_timeout, mark)
            .await
    }
}

/// `Some(selection)` when `name` is a live group (`None` inside when it has
/// no current TCP selection); `None` when it is not a group.
fn group_front(name: &str) -> Option<Option<Node>> {
    let shared = GROUP_MANAGER.get()?.read().clone()?;
    let manager = Arc::clone(&shared.read());
    manager.get_group_policy(name)?;
    Some(manager.select_node(name).cloned())
}

/// Most fronts tried for one dial when the front is a group: its current
/// selection, then other members in declaration order.
pub(crate) const MAX_FRONT_CANDIDATES: usize = 4;

tokio::task_local! {
    /// The instant a chained dial must finish by. The outermost chained dial
    /// sets it; every nested hop and front attempt inherits (a share of) it,
    /// so failover across nested groups cannot multiply `connect_timeout`
    /// per hop.
    static CHAIN_DEADLINE: tokio::time::Instant;
}

/// The deadline in force, or a fresh one for an outermost chained dial.
fn chain_deadline(connect_timeout: Duration) -> tokio::time::Instant {
    CHAIN_DEADLINE
        .try_with(|deadline| *deadline)
        .unwrap_or_else(|_| {
            let now = tokio::time::Instant::now();
            // An absurd configured timeout saturates rather than overflowing.
            let far = Duration::from_secs(u32::MAX.into());
            let budget = connect_timeout
                .checked_mul(CHAIN_BUDGET_FACTOR)
                .unwrap_or(far);
            now.checked_add(budget)
                .or_else(|| now.checked_add(far))
                .unwrap_or(now)
        })
}

/// Run `dial` under the chain deadline (inherited or fresh), failing with a
/// timeout error once it passes.
async fn within_chain_deadline<T>(
    connect_timeout: Duration,
    what: &str,
    dial: impl std::future::Future<Output = anyhow::Result<T>>,
) -> anyhow::Result<T> {
    let deadline = chain_deadline(connect_timeout);
    CHAIN_DEADLINE
        .scope(deadline, tokio::time::timeout_at(deadline, dial))
        .await
        .unwrap_or_else(|_| Err(anyhow::anyhow!("{what} timed out (detour chain deadline)")))
}

/// Front candidates for one dial, in try order. A group yields its current
/// selection first and then its other ordinary member leaves, so a dead
/// selection fails over within the same dial; built-in direct/block members
/// and the landing itself are never added as fallbacks (no bypass). A plain
/// node yields itself.
pub(crate) fn resolve_front_candidates(
    name: &str,
    scope: Option<uuid::Uuid>,
    generation: Option<&OutboundRuntimeRegistry>,
    landing: uuid::Uuid,
) -> anyhow::Result<Vec<Node>> {
    let group = GROUP_MANAGER
        .get()
        .and_then(|cell| cell.read().clone())
        .map(|shared| Arc::clone(&shared.read()))
        .filter(|manager| manager.get_group_policy(name).is_some());
    let Some(manager) = group else {
        let front = resolve_front(name, scope, generation)?;
        anyhow::ensure!(front.id != landing, "node detour resolves to itself");
        return Ok(vec![front]);
    };
    let selected = manager.select_node(name).cloned();
    let members: Vec<Node> = manager
        .leaf_nodes_in_group(name)
        .into_iter()
        .cloned()
        .collect();
    let candidates = front_candidate_order(selected, members, landing);
    anyhow::ensure!(
        !candidates.is_empty(),
        "detour front group {name:?} has no available selection"
    );
    Ok(candidates)
}

/// Selection first, then members; no duplicates, never the landing, and no
/// built-in direct/block member as a fallback.
pub(crate) fn front_candidate_order(
    selected: Option<Node>,
    members: Vec<Node>,
    landing: uuid::Uuid,
) -> Vec<Node> {
    let mut out: Vec<Node> = Vec::new();
    if let Some(selected) = selected.filter(|node| node.id != landing) {
        out.push(selected);
    }
    for member in members {
        if out.len() >= MAX_FRONT_CANDIDATES {
            break;
        }
        if member.id == landing
            || matches!(
                member.protocol(),
                NodeProtocol::Direct | NodeProtocol::Block
            )
            || out.iter().any(|node| node.id == member.id)
        {
            continue;
        }
        out.push(member);
    }
    out
}

/// Resolve a front name at connect time, matching configuration validation:
/// a group name wins and yields the group's *current* TCP selection (select,
/// url-test, fallback, ... — whatever the policy picks right now), so a
/// group switch affects new connections only; otherwise the unique node of
/// that name in the captured generation.
pub(crate) fn resolve_front(
    name: &str,
    scope: Option<uuid::Uuid>,
    generation: Option<&OutboundRuntimeRegistry>,
) -> anyhow::Result<Node> {
    if let Some(selection) = group_front(name) {
        return selection.ok_or_else(|| {
            anyhow::anyhow!("detour front group {name:?} has no available selection")
        });
    }
    if let Some(generation) = generation {
        // Same subscription first, then a globally unique name.
        match honk_config::node::pick_detour_node(
            scope,
            generation
                .values()
                .filter(|runtime| runtime.node.name == name)
                .map(|runtime| (runtime.node.subscription_id, runtime)),
        ) {
            honk_config::node::DetourNodeMatch::Unique(runtime) => {
                return Ok(runtime.node.as_ref().clone());
            }
            honk_config::node::DetourNodeMatch::Ambiguous => {
                anyhow::bail!("detour front {name:?} names several nodes")
            }
            honk_config::node::DetourNodeMatch::None => {}
        }
    }
    Err(anyhow::anyhow!(
        "detour front {name:?} is not a known node or group"
    ))
}

/// The chained node's server as the front hop's target. A domain server is
/// resolved remotely by proxy fronts and through the bootstrap resolver by a
/// direct front.
async fn server_target(node: &Node, front: &Node) -> anyhow::Result<(SocketAddr, Option<String>)> {
    let host = node.host();
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok((SocketAddr::new(ip, node.port), None));
    }
    if front.protocol() == NodeProtocol::Direct {
        let ip = crate::bootstrap::resolve(host)
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("detour server {host:?} resolved to no address"))?;
        return Ok((SocketAddr::new(ip, node.port), None));
    }
    Ok((
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), node.port),
        Some(host.to_string()),
    ))
}

/// Bridge an arbitrary front stream into a connected loopback `TcpStream`.
pub(crate) async fn bridge(
    front: ProxyStream,
    connect_timeout: Duration,
) -> anyhow::Result<TcpStream> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let addr = listener.local_addr()?;
    let (client, accepted) = tokio::time::timeout(connect_timeout, async {
        tokio::join!(TcpStream::connect(addr), listener.accept())
    })
    .await
    .map_err(|_| anyhow::anyhow!("detour loopback bridge timed out"))?;
    let client = client?;
    let (server, peer) = accepted?;
    drop(listener);
    anyhow::ensure!(
        peer == client.local_addr()?,
        "detour loopback bridge accepted an unexpected peer"
    );
    let _ = client.set_nodelay(true);
    let _ = server.set_nodelay(true);
    let mut front = front.stream;
    tokio::spawn(async move {
        let mut server = server;
        let _ = tokio::io::copy_bidirectional(&mut server, &mut front).await;
    });
    Ok(client)
}

/// Dial `node` (which carries a detour) to `target` through its front chain.
#[allow(clippy::too_many_arguments)]
pub(crate) fn dial_chained<'a>(
    table: &'a TcpTable,
    packet: &'a PacketTable,
    generation: Option<Arc<OutboundRuntimeRegistry>>,
    node: Node,
    target: SocketAddr,
    target_domain: Option<String>,
    connect_timeout: Duration,
    depth: usize,
) -> BoxFuture<'a, anyhow::Result<ProxyStream>> {
    Box::pin(async move {
        let what = format!("chained dial of {:?}", node.name);
        within_chain_deadline(connect_timeout, &what, async move {
        tracing::debug!("Dialing {} via chained node {}", target, node.name);
        if is_quic(&node) {
            let carrier = FrontCarrier::new(
                Arc::clone(table),
                Arc::clone(packet),
                generation.or_else(caller_generation),
                node.clone(),
                depth,
            );
            let (bridged, bridge) = quic_bridged_node(&node, &carrier, connect_timeout).await?;
            return inner_handler(table, node.protocol())?
                .dial(&bridged, target, target_domain.as_deref(), connect_timeout)
                .await
                .map(|stream| stream.with_owner(bridge))
                .with_context(|| {
                    format!(
                        "QUIC landing {:?} through detour failed (front path only; nothing sent direct)",
                        node.name
                    )
                });
        }
        let tcp = dial_front_tcp(table, packet, generation, &node, connect_timeout, depth).await?;
        inner_handler(table, node.protocol())?
            .dial_with_tcp(
                &node,
                target,
                target_domain.as_deref(),
                tcp,
                connect_timeout,
            )
            .await
        })
        .await
    })
}

/// Open a connected stream to `node`'s server through its front chain (the
/// carrier handed to the landing protocol, for TCP and UDP-over-TCP alike).
pub(crate) fn dial_front_tcp<'a>(
    table: &'a TcpTable,
    packet: &'a PacketTable,
    generation: Option<Arc<OutboundRuntimeRegistry>>,
    node: &'a Node,
    connect_timeout: Duration,
    depth: usize,
) -> BoxFuture<'a, anyhow::Result<TcpStream>> {
    Box::pin(async move {
        let front_name = node
            .detour
            .clone()
            .ok_or_else(|| anyhow::anyhow!("node {:?} has no detour", node.name))?;
        anyhow::ensure!(
            depth < MAX_DETOUR_DEPTH,
            "detour chain exceeds {MAX_DETOUR_DEPTH} hops (cycle?)"
        );
        anyhow::ensure!(
            node.supports_detour(),
            "protocol {} cannot be chained through a detour",
            node.protocol().as_str()
        );
        let generation = generation.or_else(caller_generation);
        let fronts = resolve_front_candidates(
            &front_name,
            node.subscription_id,
            generation.as_deref(),
            node.id,
        )?;
        let mut last = None;
        let deadline = chain_deadline(connect_timeout);
        let count = fronts.len();
        for (index, front) in fronts.into_iter().enumerate() {
            let name = front.name.clone();
            let now = tokio::time::Instant::now();
            if now >= deadline {
                last = Some(anyhow::anyhow!(
                    "detour chain deadline passed before front {name} of {}",
                    node.name
                ));
                break;
            }
            // Each remaining candidate gets an equal share of what is left,
            // so one hanging member cannot starve the ones after it.
            let share = deadline.saturating_duration_since(now) / (count - index) as u32;
            let attempt_deadline = now + share;
            let attempt = CHAIN_DEADLINE.scope(
                attempt_deadline,
                tokio::time::timeout_at(
                    attempt_deadline,
                    dial_front_once(
                        table,
                        packet,
                        generation.clone(),
                        node,
                        front,
                        connect_timeout,
                        depth,
                    ),
                ),
            );
            match attempt
                .await
                .unwrap_or_else(|_| Err(anyhow::anyhow!("front attempt timed out after {share:?}")))
            {
                Ok(stream) => return Ok(stream),
                Err(error) => {
                    tracing::warn!(
                        "detour front {name} of {} failed: {error:#}; trying next member",
                        node.name
                    );
                    last = Some(error);
                }
            }
        }
        Err(last
            .unwrap_or_else(|| anyhow::anyhow!("detour front {front_name:?} has no candidates")))
    })
}

/// One front attempt of [`dial_front_tcp`].
async fn dial_front_once(
    table: &TcpTable,
    packet: &PacketTable,
    generation: Option<Arc<OutboundRuntimeRegistry>>,
    node: &Node,
    front: Node,
    connect_timeout: Duration,
    depth: usize,
) -> anyhow::Result<TcpStream> {
    let (server, server_domain) = server_target(node, &front).await?;
    tracing::debug!("Dialing {} server through detour {}", node.name, front.name);
    let front_stream = if front.detour.is_some() {
        dial_chained(
            table,
            packet,
            generation.clone(),
            front,
            server,
            server_domain,
            connect_timeout,
            depth + 1,
        )
        .await?
    } else {
        let handler = inner_handler(table, front.protocol())?;
        match generation
            .as_ref()
            .and_then(|generation| Some((generation, generation.get(&front.id)?)))
        {
            Some((generation, runtime)) => {
                anyhow::ensure!(
                    !generation.is_shutdown(),
                    "outbound runtime generation is shut down"
                );
                generation
                    .scope_dials(handler.dial_runtime(
                        runtime,
                        server,
                        server_domain.as_deref(),
                        connect_timeout,
                    ))
                    .await?
            }
            None => {
                handler
                    .dial(&front, server, server_domain.as_deref(), connect_timeout)
                    .await?
            }
        }
    };
    bridge(front_stream, connect_timeout).await
}

/// QUIC landings (hysteria2, tuic, juicity) reach their server through the
/// front's UDP relay: a loopback UDP bridge stands in for the server, so the
/// QUIC stack runs unchanged and never sends a datagram from this host.
pub(crate) fn is_quic(node: &Node) -> bool {
    matches!(
        node.protocol(),
        NodeProtocol::Hysteria2 | NodeProtocol::Tuic | NodeProtocol::Juicity
    )
}

/// How long a QUIC bridge survives without an uplink datagram. Every QUIC
/// landing sends keep-alives far more often, so only a closed connection
/// lets it expire.
const QUIC_BRIDGE_IDLE: Duration = Duration::from_secs(90);

/// A copy of the chained QUIC `node` whose server is a loopback UDP bridge
/// relayed by the front: no detour, the TLS server name pinned to the real
/// server, and no port hopping (refused, a relay has one fixed target).
pub(crate) async fn quic_bridged_node(
    node: &Node,
    carrier: &dyn UdpCarrier,
    connect_timeout: Duration,
) -> anyhow::Result<(Node, BridgeGuard)> {
    anyhow::ensure!(
        node.hysteria2()
            .is_none_or(|config| config.port_hopping.as_deref().is_none_or(str::is_empty)),
        "hysteria2 node {:?}: port hopping cannot run through a detour (the front relays one \
         fixed server port); refusing instead of sending direct",
        node.name
    );
    let (server, server_domain) = carrier.server().await?;
    let pipe = carrier
        .datagrams(server, server_domain.as_deref(), connect_timeout)
        .await?;
    anyhow::ensure!(
        pipe.is_relayed(),
        "QUIC landing {:?}: front did not provide a UDP relay; refusing instead of sending direct",
        node.name
    );
    let (local, guard) = udp_bridge(pipe).await?;
    let mut bridged = node.clone();
    let real_host = node
        .host()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();
    if let Some(tls) = bridged.tls_mut()
        && tls.sni.as_deref().is_none_or(str::is_empty)
    {
        tls.sni = Some(real_host);
    }
    bridged.detour = None;
    bridged.host = local.ip().to_string();
    bridged.address = local.to_string();
    bridged.port = local.port();
    Ok((bridged, guard))
}

/// Stops a loopback QUIC bridge (and releases its front relay) when the
/// stream or transport dialed over it is dropped, instead of after
/// [`QUIC_BRIDGE_IDLE`] of silence.
#[derive(Debug)]
pub(crate) struct BridgeGuard(tokio::task::AbortHandle);

/// Time the bridge keeps relaying after its owner drops, so the dropped QUIC
/// client's CONNECTION_CLOSE still reaches the landing server.
pub(crate) const QUIC_BRIDGE_CLOSE_GRACE: Duration = Duration::from_secs(1);

impl Drop for BridgeGuard {
    fn drop(&mut self) {
        let task = self.0.clone();
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn(async move {
                    tokio::time::sleep(QUIC_BRIDGE_CLOSE_GRACE).await;
                    task.abort();
                });
            }
            Err(_) => task.abort(),
        }
    }
}

/// Serve `pipe` on a fresh loopback UDP socket: the first local peer owns the
/// bridge (datagrams from any other source are dropped), uplink datagrams go
/// to the front relay and relayed replies come back to that peer.
pub(crate) async fn udp_bridge(
    pipe: super::datagram_pipe::DatagramPipe,
) -> anyhow::Result<(SocketAddr, BridgeGuard)> {
    let socket = Arc::new(UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?);
    let local = socket.local_addr()?;
    let pipe = Arc::new(pipe);
    let peer = Arc::new(OnceLock::<SocketAddr>::new());
    let up = {
        let (socket, pipe, peer) = (Arc::clone(&socket), Arc::clone(&pipe), Arc::clone(&peer));
        async move {
            let mut buf = vec![0u8; 65_536];
            loop {
                let (n, from) = match tokio::time::timeout(
                    QUIC_BRIDGE_IDLE,
                    socket.recv_from(&mut buf),
                )
                .await
                {
                    Ok(Ok(received)) => received,
                    _ => return,
                };
                if *peer.get_or_init(|| from) != from {
                    tracing::debug!("QUIC detour bridge: dropping datagram from foreign {from}");
                    continue;
                }
                if pipe.send(&buf[..n]).await.is_err() {
                    return;
                }
            }
        }
    };
    let down = async move {
        let mut buf = vec![0u8; 65_536];
        loop {
            let Ok(n) = pipe.recv(&mut buf).await else {
                return;
            };
            if let Some(peer) = peer.get() {
                let _ = socket.send_to(&buf[..n], peer).await;
            }
        }
    };
    let task = tokio::spawn(async move {
        tokio::select! {
            () = up => {}
            () = down => {}
        }
    });
    Ok((local, BridgeGuard(task.abort_handle())))
}

/// Chained UDP of `node` through `carrier`: QUIC landings over a loopback
/// bridge, every other landing through its own chained implementation.
async fn dial_udp_chained(
    handler: &dyn super::PacketOutbound,
    node: &Node,
    carrier: &dyn UdpCarrier,
    target: SocketAddr,
    target_domain: Option<&str>,
    connect_timeout: Duration,
) -> anyhow::Result<Arc<dyn super::PacketTransport>> {
    let what = format!("chained UDP dial of {:?}", node.name);
    within_chain_deadline(connect_timeout, &what, async {
        if is_quic(node) {
            let (bridged, bridge) = quic_bridged_node(node, carrier, connect_timeout).await?;
            return handler
                .dial_udp_transport(&bridged, target, target_domain, connect_timeout)
                .await
                .map(|transport| super::packet_transport_with_owner(transport, bridge));
        }
        handler
            .dial_udp_transport_chained(node, carrier, target, target_domain, connect_timeout)
            .await
    })
    .await
}

/// Why `node` (which carries a detour) cannot carry UDP through its front.
pub(crate) fn chained_udp_refusal(node: &Node) -> String {
    format!(
        "UDP not supported through detour for node {:?}: protocol {} has no chained \
         UDP path (only trojan, vless, shadowsocks, socks5 and QUIC landings carry \
         UDP through a front); refusing instead of sending direct",
        node.name,
        node.protocol().as_str()
    )
}

/// Context of a failed chained UDP dial: the front path failed and nothing
/// was sent direct.
fn chained_udp_failure(node: &Node) -> String {
    format!(
        "UDP through detour for node {:?} failed (front path only; nothing sent direct)",
        node.name
    )
}

/// Why `front` cannot relay the native UDP of the chained `landing`.
fn front_udp_refusal(front: &Node, landing: &Node) -> String {
    format!(
        "UDP not supported through detour for node {:?}: front {:?} (protocol {}) \
         cannot relay UDP; refusing instead of sending direct",
        landing.name,
        front.name,
        front.protocol().as_str()
    )
}

/// Whether an unchained `front` may relay a landing's datagrams: any front
/// with its own UDP path (VLESS included when its UDP is enabled).
fn front_relays_udp(front: &Node) -> bool {
    (crate::descriptor::descriptor(front.protocol()).supports_udp)(front)
}

/// Raw (unwrapped) packet handlers by protocol, the UDP counterpart of
/// [`TcpTable`].
pub(crate) type PacketTable =
    Arc<parking_lot::RwLock<Vec<(NodeProtocol, Arc<dyn super::PacketOutbound>)>>>;

fn inner_packet(
    table: &PacketTable,
    node: &Node,
) -> anyhow::Result<Arc<dyn super::PacketOutbound>> {
    table
        .read()
        .iter()
        .find(|(candidate, _)| *candidate == node.protocol())
        .map(|(_, handler)| Arc::clone(handler))
        .ok_or_else(|| anyhow::anyhow!("no UDP handler for protocol {}", node.protocol().as_str()))
}

/// Everything a chained landing may use to reach its server: a stream through
/// the front chain (UDP-over-TCP landings, SOCKS5 control channels) and the
/// front's datagram relay (native-UDP landings). Neither ever connects to the
/// server from this host.
#[async_trait]
pub trait UdpCarrier: Send + Sync {
    /// A connected stream to the landing's server through the front chain.
    async fn stream(&self, connect_timeout: Duration) -> anyhow::Result<TcpStream>;
    /// The landing's server as the front's target (domain kept remote unless
    /// the front is direct).
    async fn server(&self) -> anyhow::Result<(SocketAddr, Option<String>)>;
    /// A datagram pipe to `server` relayed by the front's UDP path.
    async fn datagrams(
        &self,
        server: SocketAddr,
        server_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<super::datagram_pipe::DatagramPipe>;
}

/// The [`UdpCarrier`] of one chained node, resolving its front at use time
/// (a group front yields its current selection; nested fronts recurse).
pub(crate) struct FrontCarrier {
    tcp: TcpTable,
    packet: PacketTable,
    generation: Option<Arc<OutboundRuntimeRegistry>>,
    node: Node,
    depth: usize,
}

impl FrontCarrier {
    pub(crate) fn new(
        tcp: TcpTable,
        packet: PacketTable,
        generation: Option<Arc<OutboundRuntimeRegistry>>,
        node: Node,
        depth: usize,
    ) -> Self {
        Self {
            tcp,
            packet,
            generation,
            node,
            depth,
        }
    }

    fn fronts(&self) -> anyhow::Result<Vec<Node>> {
        let name = self
            .node
            .detour
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("node {:?} has no detour", self.node.name))?;
        anyhow::ensure!(
            self.depth < MAX_DETOUR_DEPTH,
            "detour chain exceeds {MAX_DETOUR_DEPTH} hops (cycle?)"
        );
        resolve_front_candidates(
            name,
            self.node.subscription_id,
            self.generation.as_deref(),
            self.node.id,
        )
    }

    async fn front_transport(
        &self,
        front: Node,
        server: SocketAddr,
        server_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<Arc<dyn super::PacketTransport>> {
        if front.detour.is_some() {
            anyhow::ensure!(
                crate::descriptor::chained_udp_supported(&front),
                front_udp_refusal(&front, &self.node)
            );
            let handler = inner_packet(&self.packet, &front)?;
            let carrier = FrontCarrier::new(
                Arc::clone(&self.tcp),
                Arc::clone(&self.packet),
                self.generation.clone(),
                front.clone(),
                self.depth + 1,
            );
            return dial_udp_chained(
                handler.as_ref(),
                &front,
                &carrier,
                server,
                server_domain,
                connect_timeout,
            )
            .await;
        }
        anyhow::ensure!(
            front_relays_udp(&front),
            front_udp_refusal(&front, &self.node)
        );
        let handler = inner_packet(&self.packet, &front)?;
        match self
            .generation
            .as_ref()
            .and_then(|generation| Some((generation, generation.get(&front.id)?)))
        {
            Some((generation, runtime)) => {
                anyhow::ensure!(
                    !generation.is_shutdown(),
                    "outbound runtime generation is shut down"
                );
                generation
                    .scope_dials(handler.dial_udp_transport_runtime(
                        runtime,
                        server,
                        server_domain,
                        connect_timeout,
                    ))
                    .await
            }
            None => {
                handler
                    .dial_udp_transport(&front, server, server_domain, connect_timeout)
                    .await
            }
        }
    }
}

#[async_trait]
impl UdpCarrier for FrontCarrier {
    async fn stream(&self, connect_timeout: Duration) -> anyhow::Result<TcpStream> {
        dial_front_tcp(
            &self.tcp,
            &self.packet,
            self.generation.clone(),
            &self.node,
            connect_timeout,
            self.depth,
        )
        .await
    }

    async fn server(&self) -> anyhow::Result<(SocketAddr, Option<String>)> {
        let front = self.fronts()?.swap_remove(0);
        server_target(&self.node, &front).await
    }

    async fn datagrams(
        &self,
        server: SocketAddr,
        server_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<super::datagram_pipe::DatagramPipe> {
        let mut last = None;
        for front in self.fronts()? {
            let name = front.name.clone();
            tracing::debug!(
                "UDP of chained node {} to {} via front {}",
                self.node.name,
                server_domain.unwrap_or(&server.to_string()),
                name
            );
            match self
                .front_transport(front, server, server_domain, connect_timeout)
                .await
            {
                Ok(transport) => {
                    return Ok(super::datagram_pipe::DatagramPipe::relay(
                        transport,
                        server,
                        server_domain,
                    ));
                }
                Err(error) => {
                    tracing::warn!(
                        "UDP detour front {name} of {} failed: {error:#}; trying next member",
                        self.node.name
                    );
                    last = Some(error);
                }
            }
        }
        Err(last.unwrap_or_else(|| anyhow::anyhow!("detour front has no candidates")))
    }
}

/// Wraps a capability that has no chained implementation (shared sources,
/// warm, raw reachability) or routes it through a [`FrontCarrier`] (UDP), so
/// a node carrying a detour is never contacted directly from this host.
pub(crate) struct DetourGuard<T: ?Sized>(
    pub(crate) Arc<T>,
    pub(crate) TcpTable,
    pub(crate) PacketTable,
);

impl<T: ?Sized> DetourGuard<T> {
    /// The front carrier of a chained UDP landing, or a clear refusal.
    fn chained_udp_carrier(&self, node: &Node) -> anyhow::Result<FrontCarrier> {
        anyhow::ensure!(
            crate::descriptor::chained_udp_supported(node),
            chained_udp_refusal(node)
        );
        tracing::debug!("UDP via chained node {}", node.name);
        Ok(FrontCarrier::new(
            Arc::clone(&self.1),
            Arc::clone(&self.2),
            caller_generation(),
            node.clone(),
            0,
        ))
    }
}

#[async_trait]
impl super::PacketOutbound for DetourGuard<dyn super::PacketOutbound> {
    async fn dial_udp_transport(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<Arc<dyn super::PacketTransport>> {
        if node.detour.is_some() {
            let carrier = self.chained_udp_carrier(node)?;
            return dial_udp_chained(
                self.0.as_ref(),
                node,
                &carrier,
                target,
                target_domain,
                connect_timeout,
            )
            .await
            .with_context(|| chained_udp_failure(node));
        }
        self.0
            .dial_udp_transport(node, target, target_domain, connect_timeout)
            .await
    }

    async fn dial_udp_transport_runtime(
        &self,
        runtime: Arc<NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<Arc<dyn super::PacketTransport>> {
        if runtime.node.detour.is_some() {
            return self
                .dial_udp_transport(&runtime.node, target, target_domain, connect_timeout)
                .await;
        }
        self.0
            .dial_udp_transport_runtime(runtime, target, target_domain, connect_timeout)
            .await
    }

    async fn dial_udp_transport_runtime_marked(
        &self,
        runtime: Arc<NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
        mark: DirectMark,
    ) -> anyhow::Result<Arc<dyn super::PacketTransport>> {
        // A chained node is never a direct route, so it carries no mark.
        if runtime.node.detour.is_some() {
            return self
                .dial_udp_transport(&runtime.node, target, target_domain, connect_timeout)
                .await;
        }
        self.0
            .dial_udp_transport_runtime_marked(
                runtime,
                target,
                target_domain,
                connect_timeout,
                mark,
            )
            .await
    }

    async fn dial_udp_transport_speculative_runtime(
        &self,
        runtime: Arc<NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<super::PreparedUdpTransport> {
        if runtime.node.detour.is_some() {
            // Chained transports publish no reusable state, so the dialed
            // transport is ready as-is.
            return self
                .dial_udp_transport(&runtime.node, target, target_domain, connect_timeout)
                .await
                .map(super::PreparedUdpTransport::ready);
        }
        self.0
            .dial_udp_transport_speculative_runtime(runtime, target, target_domain, connect_timeout)
            .await
    }

    async fn dial_udp_transport_with_tcp(
        &self,
        node: &Node,
        tcp: TcpStream,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<Arc<dyn super::PacketTransport>> {
        self.0
            .dial_udp_transport_with_tcp(node, tcp, target, target_domain, connect_timeout)
            .await
    }

    async fn dial_udp_transport_chained(
        &self,
        node: &Node,
        carrier: &dyn UdpCarrier,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<Arc<dyn super::PacketTransport>> {
        self.0
            .dial_udp_transport_chained(node, carrier, target, target_domain, connect_timeout)
            .await
    }
}

#[async_trait]
impl super::SharedSourceOutbound for DetourGuard<dyn super::SharedSourceOutbound> {
    async fn prepare_shared_source(
        &self,
        runtime: Arc<NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
        speculative: bool,
    ) -> anyhow::Result<super::PreparedUdpTransport<dyn super::MultiTargetTransport>> {
        if runtime.node.detour.is_some() {
            let carrier = self.chained_udp_carrier(&runtime.node)?;
            return self
                .0
                .prepare_shared_source_chained(
                    &runtime.node,
                    &carrier,
                    target,
                    target_domain,
                    connect_timeout,
                )
                .await
                .with_context(|| chained_udp_failure(&runtime.node));
        }
        self.0
            .prepare_shared_source(runtime, target, target_domain, connect_timeout, speculative)
            .await
    }

    async fn prepare_shared_source_with_tcp(
        &self,
        node: &Node,
        tcp: TcpStream,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<super::PreparedUdpTransport<dyn super::MultiTargetTransport>> {
        self.0
            .prepare_shared_source_with_tcp(node, tcp, target, target_domain, connect_timeout)
            .await
    }
    async fn prepare_shared_source_chained(
        &self,
        node: &Node,
        carrier: &dyn UdpCarrier,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<super::PreparedUdpTransport<dyn super::MultiTargetTransport>> {
        self.0
            .prepare_shared_source_chained(node, carrier, target, target_domain, connect_timeout)
            .await
    }
}

#[async_trait]
impl super::WarmableOutbound for DetourGuard<dyn super::WarmableOutbound> {
    async fn warm(
        &self,
        runtime: Arc<NodeRuntime>,
        connect_timeout: Duration,
        requirement: super::WarmRequirement,
    ) -> anyhow::Result<()> {
        // Chained nodes own no warm state: every dial opens a fresh chain.
        if runtime.node.detour.is_some() {
            return Ok(());
        }
        self.0.warm(runtime, connect_timeout, requirement).await
    }
}

#[async_trait]
impl super::ProbeableOutbound for DetourGuard<dyn super::ProbeableOutbound> {
    async fn test_connectivity(&self, node: &Node) -> bool {
        // A raw reachability check would connect straight to the server;
        // chained nodes are only judged by dials through their front.
        if node.detour.is_some() {
            return false;
        }
        self.0.test_connectivity(node).await
    }
}

#[cfg(test)]
#[path = "detour_tests.rs"]
mod tests;
