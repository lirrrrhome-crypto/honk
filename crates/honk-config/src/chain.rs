//! Proxy chains (mihomo `dialer-proxy` and `type: relay`).
//!
//! Two spellings converge on one derived node protocol,
//! [`OutboundConfig::Chain`]:
//!
//! - `dialer`: `node { exit: 'trojan://…' -> front }` or a subscription
//!   entry's `dialer: front`. The node keeps its name and group membership,
//!   but its own server connection is opened through `front`.
//! - `relay`: `group { r { policy: relay; relay: a -> b -> exit } }`. The
//!   group becomes a one-member selector over a derived node named
//!   `r/relay` that enters `a`, reaches `b`, and leaves through `exit`.
//!
//! Hops are node or group tags resolved at dial time. Expansion is
//! idempotent, so every runtime re-resolution may run it again.

use std::collections::{HashMap, HashSet};

use crate::ConfigDiagnostic;
use crate::node::{ChainConfig, ChainExit, Group, GroupPolicy, Node, OutboundConfig};
use crate::subscription::Subscription;
use crate::types::NodeProtocol;

/// Longest accepted chain, hops plus exit, after nested chains are counted.
pub const MAX_CHAIN_LEN: usize = 8;

/// Suffix of the derived node that carries a relay group's chain.
pub const RELAY_NODE_SUFFIX: &str = "/relay";

/// The derived node name for relay group `group`.
pub fn relay_node_name(group: &str) -> String {
    format!("{group}{RELAY_NODE_SUFFIX}")
}

/// Whether `node` is a relay group's derived node. Like `direct`/`block`,
/// unfiltered groups and patterns skip it; only an exact `name()` admits it.
pub fn is_relay_node(node: &Node) -> bool {
    matches!(
        &node.outbound,
        OutboundConfig::Chain(ChainConfig {
            exit: ChainExit::Tag(_),
            ..
        })
    )
}

/// Expand every pending `dialer` (node or subscription) and relay group into
/// chain nodes. Invalid chains are dropped with a diagnostic rather than
/// dialed without their upstream: a chain never silently becomes direct.
pub fn expand_chains(
    nodes: &mut Vec<Node>,
    groups: &mut [Group],
    subscriptions: &[Subscription],
) -> Vec<ConfigDiagnostic> {
    let mut diagnostics = Vec::new();

    // Subscription-level dialers apply to fresh nodes of that provider.
    let sub_dialers: HashMap<uuid::Uuid, &str> = subscriptions
        .iter()
        .filter(|sub| !sub.dialer.trim().is_empty())
        .map(|sub| (sub.id, sub.dialer.trim()))
        .collect();
    for node in nodes.iter_mut() {
        if node.dialer.is_none()
            && node.protocol() != NodeProtocol::Chain
            && let Some(dialer) = node.subscription_id.and_then(|id| sub_dialers.get(&id))
        {
            node.dialer = Some((*dialer).to_owned());
        }
    }

    // Drop the previous expansion's relay nodes; they are rebuilt below.
    let relay_names: HashSet<String> = groups
        .iter()
        .filter(|group| !group.relay.is_empty())
        .map(|group| relay_node_name(&group.name))
        .collect();
    let mut previous_relays: HashMap<String, Node> = HashMap::new();
    nodes.retain(|node| {
        if is_relay_node(node) && relay_names.contains(&node.name) {
            previous_relays.insert(node.name.clone(), node.clone());
            false
        } else {
            true
        }
    });

    let group_names: HashSet<&str> = groups.iter().map(|group| group.name.as_str()).collect();
    let mut known: HashSet<String> = nodes.iter().map(|node| node.name.clone()).collect();
    known.extend(group_names.iter().map(|name| (*name).to_owned()));
    known.extend(relay_names.iter().cloned());

    let check_tag = |tag: &str, owner: &str| -> Result<(), String> {
        if tag.is_empty() {
            Err("empty hop".to_owned())
        } else if tag == "block" {
            Err("`block` cannot carry a chain".to_owned())
        } else if tag == owner {
            Err(format!("`{tag}` cannot dial through itself"))
        } else {
            Ok(())
        }
    };
    // Subscription nodes arrive after parsing, so an unknown tag is only
    // reported when no provider could supply it later. Either way the chain
    // is kept: its dial fails on the unresolved hop instead of going direct.
    let mut unknown = Vec::new();
    let mut report_unknown = |tag: &str, setting: String| {
        if subscriptions.is_empty() && !known.contains(tag) && tag != "direct" {
            unknown.push(ConfigDiagnostic {
                setting,
                value: tag.to_owned(),
                message: "unknown node or group; dials through this chain will fail".to_owned(),
            });
        }
    };

    // `dialer` nodes.
    let mut kept = Vec::with_capacity(nodes.len());
    for mut node in std::mem::take(nodes) {
        let Some(dialer) = node.dialer.take() else {
            kept.push(node);
            continue;
        };
        let dialer = dialer.trim().to_owned();
        if let Err(reason) = check_tag(&dialer, &node.name) {
            diagnostics.push(ConfigDiagnostic {
                setting: format!("node.{}.dialer", node.name),
                value: dialer,
                message: format!("chain dropped: {reason}"),
            });
            continue;
        }
        if let Err(reason) = check_exit_protocol(&node) {
            diagnostics.push(ConfigDiagnostic {
                setting: format!("node.{}.dialer", node.name),
                value: dialer,
                message: format!("chain dropped: {reason}"),
            });
            continue;
        }
        report_unknown(&dialer, format!("node.{}.dialer", node.name));
        kept.push(chain_node_from_exit(node, vec![dialer]));
    }
    *nodes = kept;

    // Relay groups.
    for group in groups.iter_mut().filter(|group| !group.relay.is_empty()) {
        let members: Vec<String> = group.relay.iter().map(|m| m.trim().to_owned()).collect();
        let derived = relay_node_name(&group.name);
        let invalid = if members.len() < 2 {
            Some("a relay needs at least two members".to_owned())
        } else if members.len() > MAX_CHAIN_LEN {
            Some(format!("a relay has at most {MAX_CHAIN_LEN} members"))
        } else {
            members
                .iter()
                .find_map(|tag| check_tag(tag, &group.name).err())
                .or_else(|| {
                    (members.iter().any(|tag| tag == &derived))
                        .then(|| "a relay cannot contain itself".to_owned())
                })
                .or_else(|| {
                    // `name('<group>/relay')` would also admit that node.
                    nodes
                        .iter()
                        .any(|node| node.name == derived)
                        .then(|| format!("a node is already named `{derived}`"))
                })
        };
        group.policy = GroupPolicy::Selector;
        group.nodes.clear();
        group.groups.clear();
        group.default = None;
        if let Some(reason) = invalid {
            diagnostics.push(ConfigDiagnostic {
                setting: format!("group.{}.relay", group.name),
                value: members.join(" -> "),
                message: format!("relay disabled: {reason}"),
            });
            // A filter that matches nothing: the group stays routable but
            // empty, so its `final` (or a dial error) decides, never direct.
            group.filters = vec![format!("name({})", quote_filter_arg(&derived))];
            continue;
        }
        for tag in &members {
            report_unknown(tag, format!("group.{}.relay", group.name));
        }
        let (exit, hops) = members.split_last().expect("at least two members");
        let mut node = Node {
            name: derived.clone(),
            outbound: OutboundConfig::Chain(ChainConfig {
                hops: hops.to_vec(),
                exit: ChainExit::Tag(exit.clone()),
            }),
            ..Node::default()
        };
        node.id = node.derive_id();
        match previous_relays.remove(&derived) {
            // Unchanged: keep the earlier node, timestamps included.
            Some(previous) if previous.outbound == node.outbound => nodes.push(previous),
            _ => nodes.push(node),
        }
        group.filters = vec![format!("name({})", quote_filter_arg(&derived))];
    }

    diagnostics.extend(unknown);
    diagnostics.extend(static_cycles(nodes, groups));
    diagnostics
}

/// Protocols whose own server connection can ride on another proxy's
/// stream: they open exactly one TCP connection per flow and accept a
/// supplied carrier. QUIC protocols need a UDP carrier and session
/// protocols (AnyTLS, multiplexed or XHTTP VLESS) open connections of their
/// own, so chaining them could leak traffic around the upstream.
pub fn check_exit_protocol(node: &Node) -> Result<(), String> {
    match &node.outbound {
        OutboundConfig::Shadowsocks(config) if config.plugin.is_some() => {
            Err("Shadowsocks plugins cannot be chained".to_owned())
        }
        OutboundConfig::Shadowsocks(_)
        | OutboundConfig::Trojan(_)
        | OutboundConfig::Vmess(_)
        | OutboundConfig::Socks5(_) => {
            if node.is_xhttp() {
                Err("XHTTP transport cannot be chained".to_owned())
            } else {
                Ok(())
            }
        }
        OutboundConfig::Vless(config) => {
            if node.is_xhttp() {
                Err("XHTTP transport cannot be chained".to_owned())
            } else if config.tcp_path() != crate::node::VlessTcpPath::Direct {
                Err("multiplexed VLESS cannot be chained".to_owned())
            } else {
                Ok(())
            }
        }
        other => Err(format!(
            "{} cannot be reached through another proxy over TCP",
            other.protocol().as_str()
        )),
    }
}

/// After group filters are resolved: report chains whose hop group (or a
/// group nested in it) has the chain node itself as a member. When the group
/// picks that member, the dial nests into itself until the depth limit and
/// fails (e.g. a subscription `dialer: proxy` where `proxy` holds every node
/// of that subscription). Groups are re-resolved on every refresh, so this
/// runs after each resolution, not inside [`expand_chains`].
pub fn membership_cycles(nodes: &[Node], groups: &[Group]) -> Vec<ConfigDiagnostic> {
    let by_name: HashMap<&str, &Group> = groups.iter().map(|g| (g.name.as_str(), g)).collect();
    let reaches = |start: &str, target: uuid::Uuid| -> bool {
        let mut stack = vec![start];
        let mut seen = HashSet::new();
        while let Some(name) = stack.pop() {
            if !seen.insert(name) {
                continue;
            }
            let Some(group) = by_name.get(name) else {
                continue;
            };
            if group.nodes.contains(&target) {
                return true;
            }
            stack.extend(group.groups.iter().map(String::as_str));
        }
        false
    };
    let mut diagnostics = Vec::new();
    for node in nodes {
        let OutboundConfig::Chain(config) = &node.outbound else {
            continue;
        };
        if let Some(tag) = config.referenced_tags().find(|tag| reaches(tag, node.id)) {
            diagnostics.push(ConfigDiagnostic {
                setting: format!("node.{}.chain", node.name),
                value: tag.to_owned(),
                message: format!(
                    "hop group `{tag}` contains this node itself; dials that pick it fail"
                ),
            });
        }
    }
    diagnostics
}

fn chain_node_from_exit(exit: Node, hops: Vec<String>) -> Node {
    let mut node = Node {
        id: uuid::Uuid::nil(),
        name: exit.name.clone(),
        address: exit.address.clone(),
        host: exit.host.clone(),
        port: exit.port,
        mark: exit.mark,
        tags: exit.tags.clone(),
        subscription_id: exit.subscription_id,
        group_id: exit.group_id,
        created_at: exit.created_at,
        updated_at: exit.updated_at,
        dialer: None,
        outbound: OutboundConfig::Chain(ChainConfig {
            hops,
            exit: ChainExit::Node(Box::new(exit)),
        }),
    };
    node.id = node.derive_id();
    node
}

fn quote_filter_arg(value: &str) -> String {
    if value.contains('\'') {
        format!("\"{value}\"")
    } else {
        format!("'{value}'")
    }
}

/// Report chains whose hops reach back to themselves through other chain
/// nodes or relay groups' members. Groups with dynamic membership are
/// checked again at dial time by the depth limit.
fn static_cycles(nodes: &[Node], groups: &[Group]) -> Vec<ConfigDiagnostic> {
    let by_name: HashMap<&str, &ChainConfig> = nodes
        .iter()
        .filter_map(|node| match &node.outbound {
            OutboundConfig::Chain(config) => Some((node.name.as_str(), config)),
            _ => None,
        })
        .collect();
    let relay_of: HashMap<String, &str> = groups
        .iter()
        .filter(|group| !group.relay.is_empty())
        .map(|group| (group.name.clone(), group.name.as_str()))
        .collect();
    let mut diagnostics = Vec::new();
    for name in by_name.keys() {
        let mut stack: Vec<String> = vec![(*name).to_owned()];
        let mut seen: HashSet<String> = HashSet::new();
        while let Some(current) = stack.pop() {
            let key = relay_of
                .get(&current)
                .map(|group| relay_node_name(group))
                .unwrap_or(current);
            let Some(config) = by_name.get(key.as_str()) else {
                continue;
            };
            for tag in config.referenced_tags() {
                let target = relay_of
                    .get(tag)
                    .map(|group| relay_node_name(group))
                    .unwrap_or_else(|| tag.to_owned());
                if target == *name {
                    diagnostics.push(ConfigDiagnostic {
                        setting: format!("node.{name}.chain"),
                        value: tag.to_owned(),
                        message: "chain reaches itself; dials through it will fail".to_owned(),
                    });
                    stack.clear();
                    break;
                }
                if seen.insert(target.clone()) {
                    stack.push(target);
                }
            }
        }
    }
    diagnostics
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn chain(node: &Node) -> &ChainConfig {
        match &node.outbound {
            OutboundConfig::Chain(config) => config,
            other => panic!("expected chain, got {other:?}"),
        }
    }

    #[test]
    fn dialer_wraps_exit_and_keeps_name() {
        let mut exit = socks("exit", 2);
        exit.dialer = Some("front".to_owned());
        let mut nodes = vec![socks("front", 1), exit];
        let diagnostics = expand_chains(&mut nodes, &mut [], &[]);
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        let exit = nodes.iter().find(|n| n.name == "exit").unwrap();
        let config = chain(exit);
        assert_eq!(config.hops, ["front"]);
        assert!(matches!(&config.exit, ChainExit::Node(inner) if inner.name == "exit"));
        assert_eq!(exit.port, 2);
        // Idempotent.
        let before = nodes.clone();
        assert!(expand_chains(&mut nodes, &mut [], &[]).is_empty());
        assert_eq!(nodes, before);
    }

    #[test]
    fn unknown_dialer_is_reported_and_still_chained() {
        let mut exit = socks("exit", 2);
        exit.dialer = Some("missing".to_owned());
        let mut nodes = vec![exit];
        let diagnostics = expand_chains(&mut nodes, &mut [], &[]);
        assert_eq!(diagnostics.len(), 1);
        // Still a chain: it fails at dial time rather than going direct.
        assert_eq!(chain(&nodes[0]).hops, ["missing"]);
    }

    #[test]
    fn self_dialer_drops_node() {
        let mut exit = socks("exit", 2);
        exit.dialer = Some("exit".to_owned());
        let mut nodes = vec![exit];
        assert_eq!(expand_chains(&mut nodes, &mut [], &[]).len(), 1);
        assert!(nodes.is_empty());
    }

    #[test]
    fn relay_group_gets_one_derived_member() {
        let mut nodes = vec![socks("a", 1), socks("b", 2)];
        let mut groups = vec![Group {
            name: "r".to_owned(),
            relay: vec!["a".to_owned(), "b".to_owned()],
            policy: GroupPolicy::Fallback,
            ..Group::default()
        }];
        assert!(expand_chains(&mut nodes, &mut groups, &[]).is_empty());
        let derived = nodes.iter().find(|n| n.name == "r/relay").unwrap();
        assert!(is_relay_node(derived));
        assert_eq!(chain(derived).hops, ["a"]);
        assert_eq!(groups[0].policy, GroupPolicy::Selector);
        assert_eq!(groups[0].filters, ["name('r/relay')"]);
        // Re-expansion replaces rather than duplicates.
        assert!(expand_chains(&mut nodes, &mut groups, &[]).is_empty());
        assert_eq!(nodes.iter().filter(|n| n.name == "r/relay").count(), 1);
    }

    #[test]
    fn quic_exit_is_refused() {
        let mut exit = socks("exit", 2);
        exit.outbound = OutboundConfig::Hysteria2(Default::default());
        exit.dialer = Some("front".to_owned());
        let mut nodes = vec![socks("front", 1), exit];
        let diagnostics = expand_chains(&mut nodes, &mut [], &[]);
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(nodes.len(), 1);
    }

    #[test]
    fn cycle_is_reported() {
        let mut a = socks("a", 1);
        a.dialer = Some("b".to_owned());
        let mut b = socks("b", 2);
        b.dialer = Some("a".to_owned());
        let mut nodes = vec![a, b];
        let diagnostics = expand_chains(&mut nodes, &mut [], &[]);
        assert!(
            diagnostics
                .iter()
                .any(|d| d.message.contains("reaches itself")),
            "{diagnostics:?}"
        );
    }

    #[test]
    fn subscription_dialer_applies_to_its_nodes() {
        let sub = Subscription {
            dialer: "front".to_owned(),
            ..Subscription::default()
        };
        let mut exit = socks("exit", 2);
        exit.subscription_id = Some(sub.id);
        let mut nodes = vec![socks("front", 1), exit];
        assert!(expand_chains(&mut nodes, &mut [], std::slice::from_ref(&sub)).is_empty());
        let exit = nodes.iter().find(|n| n.name == "exit").unwrap();
        assert_eq!(chain(exit).hops, ["front"]);
        assert_eq!(exit.subscription_id, Some(sub.id));
    }

    #[test]
    fn relay_name_taken_by_a_node_disables_the_relay() {
        let mut nodes = vec![socks("a", 1), socks("b", 2), socks("r/relay", 3)];
        let mut groups = vec![Group {
            name: "r".to_owned(),
            relay: vec!["a".to_owned(), "b".to_owned()],
            ..Group::default()
        }];
        let diagnostics = expand_chains(&mut nodes, &mut groups, &[]);
        assert!(
            diagnostics
                .iter()
                .any(|d| d.message.contains("already named")),
            "{diagnostics:?}"
        );
        assert!(
            !nodes.iter().any(is_relay_node),
            "no derived node beside the user's"
        );
    }

    #[test]
    fn hop_group_containing_the_chain_itself_is_reported() {
        let sub = Subscription {
            dialer: "proxy".to_owned(),
            ..Subscription::default()
        };
        let mut exit = socks("exit", 2);
        exit.subscription_id = Some(sub.id);
        let mut nodes = vec![socks("front", 1), exit];
        let mut groups = vec![Group {
            name: "proxy".to_owned(),
            ..Group::default()
        }];
        assert!(expand_chains(&mut nodes, &mut groups, std::slice::from_ref(&sub)).is_empty());
        // An unfiltered group takes every node, the chained `exit` included.
        crate::parser::resolve_group_filters(&mut groups, &nodes, std::slice::from_ref(&sub));
        let diagnostics = membership_cycles(&nodes, &groups);
        assert_eq!(diagnostics.len(), 1, "{diagnostics:?}");
        assert_eq!(diagnostics[0].setting, "node.exit.chain");

        // A front group without the chained node is fine.
        groups[0].filters = vec!["name('front')".to_owned()];
        crate::parser::resolve_group_filters(&mut groups, &nodes, std::slice::from_ref(&sub));
        assert!(membership_cycles(&nodes, &groups).is_empty());
    }
}
