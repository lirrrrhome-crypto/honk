//! Chains: virtual nodes read left to right, `in -> … -> out`.
//!
//! A chain node comes from a `name: chain { a -> b -> out }` block, from
//! arrow sugar `name: 'link' -> hop` (the concrete node stays inline as the
//! out), or from a group `exit`: every member `m` of a group with
//! `exit: e` is served as a derived chain `m -> e`. Group exits depend on
//! membership, which subscriptions refresh, so they are derived inside every
//! group-filter resolution ([`crate::parser::resolve_group_filters`]) and
//! never by a separate reload step.

use std::collections::{HashMap, HashSet};

use crate::node::{
    ChainConfig, ChainOut, ExitMember, Group, GroupExitSource, MAX_CHAIN_LEN, Node, OutboundConfig,
};

/// A chain or group-exit problem. Messages are fixed text: configuration
/// values (names may carry credentials-like text) are never echoed into
/// diagnostics, only into the operator's own log through `name`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainIssue {
    pub subject: ChainSubject,
    /// The group or node name, for logs.
    pub name: String,
    pub code: &'static str,
    pub message: &'static str,
}

/// Which configuration item a [`ChainIssue`] belongs to, by position.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainSubject {
    Group(usize),
    Node(usize),
}

/// Name of the chain derived for `member` of a group with exit `exit`.
pub fn group_exit_name(member: &str, exit: &str) -> String {
    format!("{member} -> {exit}")
}

/// Whether `node` was derived from a group `exit`. Like `direct`/`block`,
/// such nodes are never picked by unfiltered groups or filter patterns.
pub fn is_group_exit_node(node: &Node) -> bool {
    matches!(
        &node.outbound,
        OutboundConfig::Chain(ChainConfig {
            group_exit: Some(_),
            ..
        })
    )
}

/// Undo the previous derivation: every group gets its original members back
/// (derived node IDs become the member node IDs, derived subgroup members
/// become `groups` entries again). Runs before filters are resolved, so
/// explicit and filtered membership both start from configured members.
pub(crate) fn restore_group_exit_members(groups: &mut [Group], nodes: &[Node]) {
    let sources: HashMap<uuid::Uuid, &GroupExitSource> = nodes
        .iter()
        .filter_map(|node| match &node.outbound {
            OutboundConfig::Chain(ChainConfig {
                group_exit: Some(source),
                ..
            }) => Some((node.id, source)),
            _ => None,
        })
        .collect();
    for group in groups.iter_mut() {
        let mut restored = Vec::with_capacity(group.nodes.len());
        for id in std::mem::take(&mut group.nodes) {
            match sources.get(&id) {
                // Groups with the same member and exit share one derived
                // chain, so the source's group need not be this one.
                Some(source) => match &source.member {
                    ExitMember::Node(member) => restored.push(*member),
                    ExitMember::Group(member) => {
                        if !group.groups.contains(member) {
                            group.groups.push(member.clone());
                        }
                    }
                },
                None => restored.push(id),
            }
        }
        restored.dedup();
        group.nodes = restored;
        if let Some(default) = &group.default
            && let Some(exit) = &group.exit
            && let Some(member) = default.strip_suffix(&format!(" -> {exit}"))
        {
            group.default = Some(member.to_owned());
        }
    }
}

/// Derive `member -> exit` chains for every group with an `exit` and make
/// them the group's members. Idempotent: unchanged derived nodes are kept as
/// they were. A group whose exit is unusable is emptied, so its traffic
/// follows `final` or fails rather than skipping the exit.
pub(crate) fn derive_group_exits(nodes: &mut Vec<Node>, groups: &mut [Group]) -> Vec<ChainIssue> {
    let mut diagnostics = Vec::new();
    let mut previous: HashMap<uuid::Uuid, Node> = HashMap::new();
    nodes.retain(|node| {
        if is_group_exit_node(node) {
            previous.insert(node.id, node.clone());
            false
        } else {
            true
        }
    });
    let names: HashMap<uuid::Uuid, String> = nodes
        .iter()
        .map(|node| (node.id, node.name.clone()))
        .collect();
    let taken: HashSet<String> = nodes.iter().map(|node| node.name.clone()).collect();
    let group_names: HashSet<String> = groups.iter().map(|group| group.name.clone()).collect();

    let mut derived: Vec<Node> = Vec::new();
    let mut derived_ids: HashSet<uuid::Uuid> = HashSet::new();
    for (index, group) in groups.iter_mut().enumerate() {
        let Some(exit) = group.exit.clone() else {
            continue;
        };
        let exit = exit.trim().to_owned();
        let issue = |code, message| ChainIssue {
            subject: ChainSubject::Group(index),
            name: group.name.clone(),
            code,
            message,
        };
        let unusable = match exit.as_str() {
            "" | "block" | "direct" => true,
            _ => exit == group.name,
        };
        if unusable {
            diagnostics.push(issue(
                "invalid-group-exit",
                "exit must name another proxy node or group; the group serves no members",
            ));
            group.nodes.clear();
            group.groups.clear();
            continue;
        }
        if !taken.contains(&exit) && !group_names.contains(&exit) {
            diagnostics.push(issue(
                "unknown-group-exit",
                "exit names no node or group yet; dials through it fail until one exists",
            ));
        }

        let mut members: Vec<(String, ExitMember)> = Vec::new();
        for id in &group.nodes {
            if let Some(name) = names.get(id) {
                members.push((name.clone(), ExitMember::Node(*id)));
            }
        }
        for subgroup in &group.groups {
            members.push((subgroup.clone(), ExitMember::Group(subgroup.clone())));
        }

        let mut served = Vec::with_capacity(members.len());
        for (member, source) in members {
            if member == exit {
                // The exit itself as a member would chain into itself.
                continue;
            }
            let name = group_exit_name(&member, &exit);
            if taken.contains(&name) {
                diagnostics.push(ChainIssue {
                    subject: ChainSubject::Group(index),
                    name: group.name.clone(),
                    code: "group-exit-name-taken",
                    message: "a node already has a member's derived `member -> exit` name; that member is not served",
                });
                continue;
            }
            let mut node = Node {
                name,
                outbound: OutboundConfig::Chain(ChainConfig {
                    hops: vec![member],
                    out: ChainOut::Tag(exit.clone()),
                    group_exit: Some(GroupExitSource {
                        group: group.name.clone(),
                        member: source,
                    }),
                }),
                ..Node::default()
            };
            node.id = node.derive_id();
            if !served.contains(&node.id) {
                served.push(node.id);
            }
            // The ID covers name, member tag and exit: another group that
            // derived the same chain shares it, or the node set would hold
            // duplicate IDs and be refused.
            if derived_ids.insert(node.id) {
                derived.push(match previous.remove(&node.id) {
                    Some(kept) if same_chain(&kept, &node) => kept,
                    _ => node,
                });
            }
        }
        if let Some(default) = &group.default
            && (taken.contains(default) || group_names.contains(default))
        {
            group.default = Some(group_exit_name(default, &exit));
        }
        group.nodes = served;
        group.groups.clear();
    }
    nodes.extend(derived);
    diagnostics.extend(chain_cycles(nodes, groups));
    diagnostics
}

/// Whether a previously derived node is still the chain derivation would
/// produce; which group first derived it is not part of that.
fn same_chain(kept: &Node, fresh: &Node) -> bool {
    match (&kept.outbound, &fresh.outbound) {
        (OutboundConfig::Chain(kept), OutboundConfig::Chain(fresh)) => {
            kept.hops == fresh.hops
                && kept.out == fresh.out
                && kept.group_exit.as_ref().map(|source| &source.member)
                    == fresh.group_exit.as_ref().map(|source| &source.member)
        }
        _ => false,
    }
}

/// Report chains that can reach themselves: through their own members,
/// nested chains, or a group that (directly or through subgroups) holds the
/// chain. Picking such a member nests the dial until the depth limit fails
/// it, so these are configuration errors worth surfacing before traffic.
pub fn chain_cycles(nodes: &[Node], groups: &[Group]) -> Vec<ChainIssue> {
    let by_name: HashMap<&str, &Node> = nodes
        .iter()
        .map(|node| (node.name.as_str(), node))
        .collect();
    let by_id: HashMap<uuid::Uuid, &Node> = nodes.iter().map(|node| (node.id, node)).collect();
    let group_by_name: HashMap<&str, &Group> = groups
        .iter()
        .map(|group| (group.name.as_str(), group))
        .collect();

    let mut diagnostics = Vec::new();
    for (index, start) in nodes.iter().enumerate() {
        let OutboundConfig::Chain(chain) = &start.outbound else {
            continue;
        };
        let mut seen: HashSet<String> = HashSet::new();
        let mut stack: Vec<String> = chain.tags().map(str::to_owned).collect();
        let mut cyclic = None;
        while let Some(tag) = stack.pop() {
            if tag == start.name {
                cyclic = Some(tag);
                break;
            }
            if !seen.insert(tag.clone()) {
                continue;
            }
            // Same precedence as dialing: the operator's node, then a
            // group, then a provider node.
            let own_node = nodes
                .iter()
                .any(|node| node.name == tag && node.subscription_id.is_none());
            if let Some(group) = group_by_name.get(tag.as_str()).filter(|_| !own_node) {
                for id in &group.nodes {
                    if *id == start.id {
                        cyclic = Some(tag.clone());
                        break;
                    }
                    if let Some(node) = by_id.get(id) {
                        stack.push(node.name.clone());
                    }
                }
                stack.extend(group.groups.iter().cloned());
                if let Some(exit) = &group.exit {
                    stack.push(exit.clone());
                }
            } else if let Some(node) = by_name.get(tag.as_str())
                && let OutboundConfig::Chain(inner) = &node.outbound
            {
                stack.extend(inner.tags().map(str::to_owned));
            }
            if cyclic.is_some() {
                break;
            }
        }
        if cyclic.is_some() {
            diagnostics.push(ChainIssue {
                subject: ChainSubject::Node(index),
                name: start.name.clone(),
                code: "chain-cycle",
                message: "the chain can reach itself through its members; dials that take that path fail",
            });
        }
    }
    diagnostics
}

/// Later chain members (all but the first) are reached over the previous
/// member's stream, so they must open exactly one stream to their server and
/// accept it from the chain. QUIC protocols need datagrams to their server,
/// and session protocols (AnyTLS, multiplexed or XHTTP VLESS) or plugins open
/// connections of their own that would bypass the chain.
pub fn check_later_member(node: &Node) -> Result<(), String> {
    match &node.outbound {
        OutboundConfig::Shadowsocks(config) if config.plugin.is_some() => {
            Err("Shadowsocks plugins cannot be reached through a chain".to_owned())
        }
        OutboundConfig::Shadowsocks(_)
        | OutboundConfig::Trojan(_)
        | OutboundConfig::Vmess(_)
        | OutboundConfig::Socks5(_) => {
            if node.is_xhttp() {
                Err("XHTTP cannot be reached through a chain".to_owned())
            } else {
                Ok(())
            }
        }
        OutboundConfig::Vless(config) => {
            if node.is_xhttp() {
                Err("XHTTP cannot be reached through a chain".to_owned())
            } else if config.tcp_path() != crate::node::VlessTcpPath::Direct {
                Err("multiplexed VLESS cannot be reached through a chain".to_owned())
            } else {
                Ok(())
            }
        }
        other => Err(format!(
            "{} cannot be reached through a chain over TCP",
            other.protocol().as_str()
        )),
    }
}

/// Upper bound on a chain's flattened members, nested chains included.
pub const MAX_FLATTENED_LEN: usize = MAX_CHAIN_LEN;
