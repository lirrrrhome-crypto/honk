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

use super::{ProxyRegistry, ProxyStream};
use crate::group::SharedGroupManager;
use crate::runtime::OutboundRuntimeRegistry;

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
    registry: &'a ProxyRegistry,
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
                registry,
                generation.clone(),
                front,
                server,
                server_domain,
                connect_timeout,
                depth + 1,
            )
            .await?
        } else {
            match generation
                .as_ref()
                .filter(|generation| generation.get(&front.id).is_some())
            {
                Some(generation) => {
                    registry
                        .dial_runtime(
                            Arc::clone(generation),
                            front.id,
                            server,
                            server_domain.as_deref(),
                            connect_timeout,
                        )
                        .await?
                }
                None => {
                    registry
                        .dial(&front, server, server_domain.as_deref(), connect_timeout)
                        .await?
                }
            }
        };
        let tcp = bridge(front_stream, connect_timeout).await?;
        let entry = registry
            .find(node.protocol())
            .ok_or_else(|| anyhow::anyhow!("No handler for protocol {:?}", node.protocol()))?;
        entry
            .tcp
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
