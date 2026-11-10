//! Chain dialing: a chain node's members, read left to right, are resolved
//! to concrete nodes at dial time (a group member keeps applying its own
//! policy), nested chains are flattened, and each member after the first
//! performs its handshake directly on the stream the member before it
//! returned. There is no loopback socket and no copy task between members:
//! the stream a flow relays is the protocol stack itself.
//!
//! The first member is dialed like any node (reusing its live session where
//! the protocol has one). Later members must run entirely on that one stream
//! ([`honk_config::chain::check_later_member`]); a member that would open a
//! connection of its own is refused, never dialed around the chain.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use honk_config::node::{ChainConfig, ChainOut, Node, OutboundConfig};
use parking_lot::RwLock;

use super::{ProbeableOutbound, ProxyRegistry, ProxyStream, TcpOutbound};

/// Resolves a chain member tag to the node it currently stands for.
pub trait ChainResolver: Send + Sync {
    /// A node by name, or a group's current TCP selection. This is a dial:
    /// a group may count it as use.
    fn resolve(&self, tag: &str) -> Option<Node>;

    /// Like [`Self::resolve`] for checks that are not traffic: a group must
    /// not count it as use, advance a round-robin cursor or wake a URL test.
    fn peek(&self, tag: &str) -> Option<Node> {
        self.resolve(tag)
    }
}

/// [`ChainResolver`] over the live group manager.
pub struct GroupManagerResolver {
    shared: crate::group::SharedGroupManager,
    /// Last manager seen, answering while the cell cannot be read at once.
    last: parking_lot::Mutex<Arc<crate::group::GroupManager>>,
}

impl GroupManagerResolver {
    pub fn new(shared: crate::group::SharedGroupManager) -> Self {
        let last = parking_lot::Mutex::new(Arc::clone(&shared.read()));
        Self { shared, last }
    }

    /// Never blocks on the manager cell, so resolving adds no lock-order
    /// edge: a caller may already hold the cell's read guard, and
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

/// What a member tag names. An operator's own declarations win over a
/// subscription's display names: a provider must not be able to redirect a
/// chain by naming one of its nodes like the operator's group. A group
/// that currently selects nothing fails the dial; it never falls through
/// to a same-named provider node.
enum Tagged<'a> {
    Node(&'a Node),
    Group,
    Unknown,
}

fn classify<'a>(manager: &'a crate::group::GroupManager, tag: &str) -> Tagged<'a> {
    if let Some(own) = manager
        .nodes_named(tag)
        .find(|node| node.subscription_id.is_none())
    {
        return Tagged::Node(own);
    }
    if manager.get_group_policy(tag).is_some() {
        return Tagged::Group;
    }
    manager
        .node_by_name(tag)
        .map_or(Tagged::Unknown, Tagged::Node)
}

impl ChainResolver for GroupManagerResolver {
    fn resolve(&self, tag: &str) -> Option<Node> {
        let manager = self.manager();
        match classify(&manager, tag) {
            Tagged::Node(node) => Some(node.clone()),
            Tagged::Group => manager.select_node(tag).cloned(),
            Tagged::Unknown => None,
        }
    }

    fn peek(&self, tag: &str) -> Option<Node> {
        let manager = self.manager();
        match classify(&manager, tag) {
            Tagged::Node(node) => Some(node.clone()),
            Tagged::Group => manager
                .peek_selection_plan_for_domain(
                    tag,
                    crate::alive::ProbeDomain::Tcp,
                    crate::alive::IpVersion::V4,
                )
                .nodes
                .first()
                .map(|node| (*node).clone()),
            Tagged::Unknown => None,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Resolution {
    Dial,
    Peek,
}

fn resolve(resolver: &dyn ChainResolver, tag: &str, mode: Resolution) -> anyhow::Result<Node> {
    match mode {
        Resolution::Dial => resolver.resolve(tag),
        Resolution::Peek => resolver.peek(tag),
    }
    .ok_or_else(|| anyhow::anyhow!("chain member `{tag}` resolves to no node"))
}

fn flatten(
    resolver: &dyn ChainResolver,
    node: Node,
    out: &mut Vec<Node>,
    depth: usize,
    mode: Resolution,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        depth <= honk_config::chain::MAX_FLATTENED_LEN,
        "chain nests too deeply (a member probably reaches the chain itself)"
    );
    match node.outbound {
        OutboundConfig::Chain(config) => flatten_config(resolver, config, out, depth, mode),
        OutboundConfig::Direct => anyhow::bail!("chain member `{}` resolves to direct", node.name),
        OutboundConfig::Block => anyhow::bail!("chain member `{}` resolves to block", node.name),
        _ => {
            out.push(node);
            anyhow::ensure!(
                out.len() <= honk_config::chain::MAX_FLATTENED_LEN,
                "chain exceeds {} members after expansion",
                honk_config::chain::MAX_FLATTENED_LEN
            );
            Ok(())
        }
    }
}

fn flatten_config(
    resolver: &dyn ChainResolver,
    config: ChainConfig,
    out: &mut Vec<Node>,
    depth: usize,
    mode: Resolution,
) -> anyhow::Result<()> {
    for hop in &config.hops {
        flatten(
            resolver,
            resolve(resolver, hop, mode)?,
            out,
            depth + 1,
            mode,
        )?;
    }
    let exit = match config.out {
        ChainOut::Node(node) => *node,
        ChainOut::Tag(tag) => resolve(resolver, &tag, mode)?,
    };
    flatten(resolver, exit, out, depth + 1, mode)
}

fn members_with(
    resolver: &dyn ChainResolver,
    node: &Node,
    mode: Resolution,
) -> anyhow::Result<Vec<Node>> {
    let mut out = Vec::new();
    flatten(resolver, node.clone(), &mut out, 0, mode)?;
    anyhow::ensure!(out.len() >= 2, "chain needs at least two concrete members");
    for later in &out[1..] {
        honk_config::chain::check_later_member(later)
            .map_err(|reason| anyhow::anyhow!("chain member `{}` refused: {reason}", later.name))?;
    }
    Ok(out)
}

/// The address a member's server is reached at, as a proxy target: an IP
/// literal travels numerically, a name as the domain the member in front
/// resolves (no local DNS for later members).
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

/// "member `a` (1/3) reaching `b`": which member failed and what it was
/// reaching. Only SOCKS5 answers its request before data flows; the other
/// stream protocols send their request and return, so a member in front
/// that never accepted it surfaces only when a later member reads. Those
/// members are named as possible causes rather than letting the error
/// blame the member that merely noticed.
fn member_context(members: &[Node], index: usize) -> String {
    let toward = members.get(index + 1).map_or_else(
        || "the destination".to_owned(),
        |next| format!("`{}`", next.name),
    );
    let mut context = format!(
        "chain member `{}` ({}/{}) reaching {toward}",
        members[index].name,
        index + 1,
        members.len()
    );
    let unconfirmed: Vec<&str> = members[..index]
        .iter()
        .filter(|member| !matches!(member.outbound, OutboundConfig::Socks5(_)))
        .map(|member| member.name.as_str())
        .collect();
    if !unconfirmed.is_empty() {
        context.push_str(&format!(
            "; members in front that do not confirm their request may have failed instead: `{}`",
            unconfirmed.join("`, `")
        ));
    }
    context
}

/// Dials chain nodes over a registry of the ordinary protocols. Each
/// registry owns its handler, and its owner installs what members resolve
/// against, so control planes in one process never see each other's groups.
pub struct ChainHandler {
    base: ProxyRegistry,
    resolver: RwLock<Option<Arc<dyn ChainResolver>>>,
    runtimes: RwLock<Option<crate::runtime::SharedRuntimeRegistry>>,
}

impl ChainHandler {
    pub fn new(base: ProxyRegistry) -> Self {
        Self {
            base,
            resolver: RwLock::new(None),
            runtimes: RwLock::new(None),
        }
    }

    /// What member tags resolve against. honk-core installs one over its
    /// shared group manager at startup; reloads swap the manager inside it.
    pub fn install_resolver(&self, resolver: Arc<dyn ChainResolver>) {
        *self.resolver.write() = Some(resolver);
    }

    /// The live runtime registry, so a session protocol as first member
    /// (Hysteria2, TUIC, AnyTLS, multiplexed VLESS) reuses its warmed session.
    pub fn install_runtime_registry(&self, registry: crate::runtime::SharedRuntimeRegistry) {
        *self.runtimes.write() = Some(registry);
    }

    fn resolver(&self) -> anyhow::Result<Arc<dyn ChainResolver>> {
        self.resolver
            .read()
            .clone()
            .ok_or_else(|| anyhow::anyhow!("chain resolver is not installed"))
    }

    /// The concrete members `node` dials through, first first, out last.
    /// This is a dial: member groups count it as use.
    pub fn members(&self, node: &Node) -> anyhow::Result<Vec<Node>> {
        members_with(self.resolver()?.as_ref(), node, Resolution::Dial)
    }

    /// [`Self::members`] for inspection only: member groups keep their state.
    pub fn peek_members(&self, node: &Node) -> anyhow::Result<Vec<Node>> {
        members_with(self.resolver()?.as_ref(), node, Resolution::Peek)
    }

    async fn dial_members(
        &self,
        members: &[Node],
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        let next = |index: usize| -> (SocketAddr, Option<String>) {
            match members.get(index + 1) {
                Some(member) => server_target(member),
                None => (target, target_domain.map(str::to_owned)),
            }
        };
        let (first_target, first_domain) = next(0);
        let generation = self
            .runtimes
            .try_read()
            .and_then(|cell| {
                cell.as_ref()
                    .and_then(|shared| shared.try_read().map(|g| Arc::clone(&g)))
            })
            .filter(|generation| generation.get(&members[0].id).is_some());
        let first = match generation {
            Some(generation) => {
                self.base
                    .dial_runtime(
                        generation,
                        members[0].id,
                        first_target,
                        first_domain.as_deref(),
                        connect_timeout,
                    )
                    .await
            }
            None => {
                self.base
                    .dial(
                        &members[0],
                        first_target,
                        first_domain.as_deref(),
                        connect_timeout,
                    )
                    .await
            }
        };
        let mut stream = first.map_err(|error| error.context(member_context(members, 0)))?;
        for (index, member) in members.iter().enumerate().skip(1) {
            let entry = self
                .base
                .find(member.protocol())
                .ok_or_else(|| anyhow::anyhow!("no handler for {}", member.protocol().as_str()))?;
            let (hop_target, hop_domain) = next(index);
            stream = entry
                .tcp
                .dial_over(
                    member,
                    hop_target,
                    hop_domain.as_deref(),
                    stream.stream,
                    connect_timeout,
                )
                .await
                .map_err(|error| error.context(member_context(members, index)))?;
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
        let members = self.members(node)?;
        self.dial_members(&members, target, target_domain, connect_timeout)
            .await
    }

    /// A chain opens its own first connection; a supplied socket is unused.
    async fn dial_with_tcp(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        tcp: tokio::net::TcpStream,
        connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        drop(tcp);
        self.dial(node, target, target_domain, connect_timeout)
            .await
    }
}

#[async_trait]
impl ProbeableOutbound for ChainHandler {
    /// Reachability of the first member; URL tests cover the whole chain.
    async fn test_connectivity(&self, node: &Node) -> bool {
        let Ok(members) = self.peek_members(node) else {
            return false;
        };
        match self
            .base
            .find(members[0].protocol())
            .and_then(|entry| entry.probeable.as_ref())
        {
            Some(probe) => probe.test_connectivity(&members[0]).await,
            None => false,
        }
    }
}

#[cfg(test)]
mod tests;
