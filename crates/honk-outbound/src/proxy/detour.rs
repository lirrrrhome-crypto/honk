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
//! Scope (MVP): TCP only. Detour nodes never pool, warm or carry UDP (see
//! `descriptor::unchained`); configuration validation rejects UDP/QUIC-native
//! protocols, unknown or ambiguous fronts and cycles, and the dial path
//! re-checks depth as a guard against cycles introduced by dynamic group
//! membership.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use futures_util::future::BoxFuture;
use honk_config::node::Node;
use honk_config::types::NodeProtocol;
use tokio::net::{TcpListener, TcpStream};

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
                current_generation(),
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
                current_generation(),
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

fn group_front(name: &str) -> Option<Node> {
    let shared = GROUP_MANAGER.get()?.read().clone()?;
    let manager = Arc::clone(&shared.read());
    manager.select_node(name).cloned()
}

/// Resolve a front name: a node in the captured generation first, then a
/// group's current selection.
pub(crate) fn resolve_front(
    name: &str,
    generation: Option<&OutboundRuntimeRegistry>,
) -> anyhow::Result<Node> {
    if let Some(generation) = generation {
        let mut matches = generation
            .values()
            .filter(|runtime| runtime.node.name == name);
        if let Some(runtime) = matches.next() {
            anyhow::ensure!(
                matches.next().is_none(),
                "detour front {name:?} names several nodes"
            );
            return Ok(runtime.node.as_ref().clone());
        }
    }
    group_front(name)
        .ok_or_else(|| anyhow::anyhow!("detour front {name:?} is not a known node or group"))
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
pub(crate) fn dial_chained<'a>(
    table: &'a TcpTable,
    generation: Option<Arc<OutboundRuntimeRegistry>>,
    node: Node,
    target: SocketAddr,
    target_domain: Option<String>,
    connect_timeout: Duration,
    depth: usize,
) -> BoxFuture<'a, anyhow::Result<ProxyStream>> {
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
        let generation = generation.or_else(current_generation);
        let front = resolve_front(&front_name, generation.as_deref())?;
        anyhow::ensure!(front.id != node.id, "node detour resolves to itself");
        let (server, server_domain) = server_target(&node, &front).await?;
        tracing::debug!(
            "Dialing {} via {} through detour {}",
            target,
            node.name,
            front.name
        );
        let front_stream = if front.detour.is_some() {
            dial_chained(
                table,
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
        let tcp = bridge(front_stream, connect_timeout).await?;
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
}

const NO_DETOUR_UDP: &str = "UDP not supported through a detour";

/// Wraps a capability that has no chained implementation (UDP, shared
/// sources, warm, raw reachability) so a node carrying a detour is refused
/// instead of being contacted directly from this host.
pub(crate) struct DetourGuard<T: ?Sized>(pub(crate) Arc<T>);

#[async_trait]
impl super::PacketOutbound for DetourGuard<dyn super::PacketOutbound> {
    async fn dial_udp_transport(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<Arc<dyn super::PacketTransport>> {
        anyhow::ensure!(node.detour.is_none(), NO_DETOUR_UDP);
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
        anyhow::ensure!(runtime.node.detour.is_none(), NO_DETOUR_UDP);
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
        anyhow::ensure!(runtime.node.detour.is_none(), NO_DETOUR_UDP);
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
        anyhow::ensure!(runtime.node.detour.is_none(), NO_DETOUR_UDP);
        self.0
            .dial_udp_transport_speculative_runtime(runtime, target, target_domain, connect_timeout)
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
        anyhow::ensure!(runtime.node.detour.is_none(), NO_DETOUR_UDP);
        self.0
            .prepare_shared_source(runtime, target, target_domain, connect_timeout, speculative)
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
