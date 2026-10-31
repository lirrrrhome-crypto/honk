//! Per-protocol facts: UDP support, pooling behavior, generation runtime
//! ownership, and share-link schemes.

use honk_config::node::{Node, VlessTcpPath, VlessUdpPath};
use honk_config::types::NodeProtocol;

use crate::proxy::WarmRequirement;
use crate::runtime::GenerationRuntime;

/// Predicate fields cover per-node conditions:
/// VLESS, Trojan, and AnyTLS gate UDP on `node.network`, while Trojan
/// ready-stream pooling additionally depends on its transport.
pub struct ProtocolDescriptor {
    pub protocol: NodeProtocol,
    pub supports_udp: fn(&Node) -> bool,
    pub pool_ready_streams: fn(&Node) -> bool,
    pub pool_bare_tcp: fn(&Node) -> bool,
    supports_warm: fn(&Node, WarmRequirement) -> bool,
    pub generation_runtime: GenerationRuntime,
    pub share_link_schemes: &'static [&'static str],
}

impl ProtocolDescriptor {
    pub fn supports_warm(&self, node: &Node, requirement: WarmRequirement) -> bool {
        (self.supports_warm)(node, requirement)
    }
}

/// The dial-time network gate shared by capability predicates and UDP dial
/// paths: no `network` restriction means UDP is allowed; otherwise the list
/// must contain "udp".
pub(crate) fn network_allows_udp(node: &Node) -> bool {
    unchained(node) && network_lists_udp(node)
}

fn network_lists_udp(node: &Node) -> bool {
    node.network().is_none_or(|network| {
        network
            .split(',')
            .any(|entry| entry.trim().eq_ignore_ascii_case("udp"))
    })
}

/// Whether a node carrying a detour can carry UDP. Trojan frames UDP inside
/// its own stream and rides the front's TCP chain, as does VLESS (native
/// UDP, single XUDP or UoT v2 inside the chained stream); Shadowsocks and SOCKS5
/// send their native datagrams through the front's UDP relay, and QUIC
/// landings (hysteria2 without port hopping, tuic, juicity) run their whole
/// QUIC connection over that relay (refused at dial time when the front has
/// none). Nothing is ever sent directly.
pub fn chained_udp_supported(node: &Node) -> bool {
    node.detour.is_some()
        && node.supports_detour()
        && match node.protocol() {
            NodeProtocol::Trojan => network_lists_udp(node),
            NodeProtocol::SS | NodeProtocol::Socks5 => true,
            NodeProtocol::VLess => node.vless().is_some_and(|vless| vless.udp_enabled()),
            NodeProtocol::Hysteria2 | NodeProtocol::Tuic | NodeProtocol::Juicity => true,
            _ => false,
        }
}

/// Native UDP when unchained, the front's UDP relay when chained.
fn native_or_chained_udp(node: &Node) -> bool {
    unchained(node) || chained_udp_supported(node)
}

fn trojan_supports_udp(node: &Node) -> bool {
    network_allows_udp(node) || chained_udp_supported(node)
}

fn never(_: &Node) -> bool {
    false
}

/// Every capability that would open a server connection outside the
/// per-flow dial (UDP relays, pooled bare TCP or ready streams, warm
/// sessions) bypasses a chained front hop, so a node with a `detour` keeps
/// none of them: it is TCP-only and dialed fresh through its front.
fn unchained(node: &Node) -> bool {
    node.detour.is_none()
}

fn always(node: &Node) -> bool {
    unchained(node)
}

fn stream_pool_bare_tcp(node: &Node) -> bool {
    unchained(node) && !node.is_xhttp()
}

fn stream_supports_warm(node: &Node, requirement: WarmRequirement) -> bool {
    unchained(node)
        && node.is_xhttp()
        && (requirement == WarmRequirement::Session
            || (descriptor(node.protocol()).supports_udp)(node))
}

fn pooled_supports_warm(node: &Node, requirement: WarmRequirement) -> bool {
    unchained(node)
        && (requirement == WarmRequirement::Session
            || (descriptor(node.protocol()).supports_udp)(node))
}

fn no_warm(_: &Node, _: WarmRequirement) -> bool {
    false
}

fn vless_supports_warm(node: &Node, requirement: WarmRequirement) -> bool {
    if !unchained(node) {
        return false;
    }
    let vless = node
        .vless()
        .expect("VLESS descriptor requires VLESS config");
    stream_supports_warm(node, requirement)
        || match requirement {
            WarmRequirement::Session => {
                matches!(vless.tcp_path(), VlessTcpPath::H2 | VlessTcpPath::Cool)
            }
            WarmRequirement::Udp => matches!(
                vless.udp_path(0),
                Some(VlessUdpPath::H2 | VlessUdpPath::CoolShared | VlessUdpPath::CoolSeparate)
            ),
        }
}

fn vless_supports_udp(node: &Node) -> bool {
    (unchained(node) || chained_udp_supported(node)) && node.vless().unwrap().udp_enabled()
}

fn vless_pool_bare_tcp(node: &Node) -> bool {
    stream_pool_bare_tcp(node) && node.vless().unwrap().tcp_path() == VlessTcpPath::Direct
}

/// Poolable only on the plain TCP transport: `dial()` completes the TLS
/// handshake (if enabled) and writes the one-shot request header; Trojan
/// defines no server handshake reply, so the stream is then a target-bound
/// data channel. WebSocket/gRPC transports add a bridge task / HTTP/2
/// framing state whose idle liveness cannot be probed at the fd level, so
/// they stay on bare-TCP pooling. XHTTP instead owns its physical session pool.
fn trojan_pool_ready_streams(node: &Node) -> bool {
    unchained(node) && matches!(node.transport().unwrap().transport.as_str(), "" | "tcp")
}

static DESCRIPTORS: &[ProtocolDescriptor] = &[
    ProtocolDescriptor {
        protocol: NodeProtocol::SS,
        supports_udp: native_or_chained_udp,
        pool_ready_streams: never,
        pool_bare_tcp: always,
        supports_warm: no_warm,
        generation_runtime: GenerationRuntime::None,
        share_link_schemes: &["ss"],
    },
    ProtocolDescriptor {
        protocol: NodeProtocol::Trojan,
        supports_udp: trojan_supports_udp,
        pool_ready_streams: trojan_pool_ready_streams,
        pool_bare_tcp: stream_pool_bare_tcp,
        supports_warm: stream_supports_warm,
        generation_runtime: GenerationRuntime::None,
        share_link_schemes: &["trojan"],
    },
    ProtocolDescriptor {
        protocol: NodeProtocol::VMess,
        supports_udp: never,
        pool_ready_streams: never,
        pool_bare_tcp: stream_pool_bare_tcp,
        supports_warm: stream_supports_warm,
        generation_runtime: GenerationRuntime::None,
        share_link_schemes: &["vmess"],
    },
    ProtocolDescriptor {
        protocol: NodeProtocol::VLess,
        supports_udp: vless_supports_udp,
        pool_ready_streams: never,
        pool_bare_tcp: vless_pool_bare_tcp,
        supports_warm: vless_supports_warm,
        generation_runtime: GenerationRuntime::Vless,
        share_link_schemes: &["vless"],
    },
    // After the greeting (+ optional RFC 1929 auth) and a successful CONNECT
    // reply, the connection is a pure data channel bound to the requested
    // target — the server sends nothing of its own first, so a fully-dialed
    // stream is safe to pool and reuse directly.
    ProtocolDescriptor {
        protocol: NodeProtocol::Socks5,
        supports_udp: native_or_chained_udp,
        pool_ready_streams: always,
        pool_bare_tcp: always,
        supports_warm: no_warm,
        generation_runtime: GenerationRuntime::None,
        share_link_schemes: &["socks5", "socks4", "socks4a"],
    },
    // HTTP CONNECT: TCP only. After a 2xx reply the tunnel is a pure data
    // channel bound to its target, like SOCKS5; a bare TCP still owes the
    // (optional) TLS handshake, which `dial_with_tcp` performs.
    ProtocolDescriptor {
        protocol: NodeProtocol::Http,
        supports_udp: never,
        pool_ready_streams: never,
        pool_bare_tcp: always,
        supports_warm: no_warm,
        generation_runtime: GenerationRuntime::None,
        share_link_schemes: &["http", "https"],
    },
    // QUIC-based (hy2/tuic/juicity): a pooled bare TCP is unusable — their
    // `dial_with_tcp` fails — so preconnect warmup must not deposit one (it
    // would poison the first flow).
    ProtocolDescriptor {
        protocol: NodeProtocol::Hysteria2,
        supports_udp: native_or_chained_udp,
        pool_ready_streams: never,
        pool_bare_tcp: never,
        supports_warm: pooled_supports_warm,
        generation_runtime: GenerationRuntime::Quic,
        share_link_schemes: &["hysteria2", "hysteria", "hy2"],
    },
    ProtocolDescriptor {
        protocol: NodeProtocol::Tuic,
        supports_udp: native_or_chained_udp,
        pool_ready_streams: never,
        pool_bare_tcp: never,
        supports_warm: pooled_supports_warm,
        generation_runtime: GenerationRuntime::Quic,
        share_link_schemes: &["tuic"],
    },
    ProtocolDescriptor {
        protocol: NodeProtocol::Juicity,
        supports_udp: native_or_chained_udp,
        pool_ready_streams: never,
        pool_bare_tcp: never,
        supports_warm: pooled_supports_warm,
        generation_runtime: GenerationRuntime::Quic,
        share_link_schemes: &["juicity"],
    },
    // Multiplexed: the node-owned session pool already keeps reusable
    // connections. Bare-TCP or ready-stream pooling would bypass that owner,
    // creating an untracked TLS/auth session outside its lifecycle.
    ProtocolDescriptor {
        protocol: NodeProtocol::AnyTLS,
        supports_udp: network_allows_udp,
        pool_ready_streams: never,
        pool_bare_tcp: never,
        supports_warm: pooled_supports_warm,
        generation_runtime: GenerationRuntime::AnyTls,
        share_link_schemes: &["anytls"],
    },
    // Each direct flow owns a socket carrying its own rule or global mark; a
    // pooled socket would hand one flow another flow's mark.
    ProtocolDescriptor {
        protocol: NodeProtocol::Direct,
        supports_udp: always,
        pool_ready_streams: never,
        pool_bare_tcp: never,
        supports_warm: no_warm,
        generation_runtime: GenerationRuntime::None,
        share_link_schemes: &[],
    },
    ProtocolDescriptor {
        protocol: NodeProtocol::Block,
        supports_udp: never,
        pool_ready_streams: never,
        pool_bare_tcp: always,
        supports_warm: no_warm,
        generation_runtime: GenerationRuntime::None,
        share_link_schemes: &[],
    },
];

/// Target policy only; absent UDP capability is handled separately by callers.
pub fn udp_target_allowed(node: &Node, port: u16) -> bool {
    node.vless()
        .is_none_or(|vless| !vless.udp_enabled() || vless.udp_path(port).is_some())
}

pub fn descriptor(protocol: NodeProtocol) -> &'static ProtocolDescriptor {
    DESCRIPTORS
        .iter()
        .find(|d| d.protocol == protocol)
        .expect("every NodeProtocol has a descriptor")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_protocol_has_a_descriptor() {
        for protocol in [
            NodeProtocol::SS,
            NodeProtocol::Trojan,
            NodeProtocol::VMess,
            NodeProtocol::VLess,
            NodeProtocol::Socks5,
            NodeProtocol::Http,
            NodeProtocol::Hysteria2,
            NodeProtocol::Tuic,
            NodeProtocol::Juicity,
            NodeProtocol::AnyTLS,
            NodeProtocol::Direct,
            NodeProtocol::Block,
        ] {
            assert_eq!(descriptor(protocol).protocol, protocol);
        }
    }

    #[test]
    fn vless_capabilities_follow_selected_paths() {
        use honk_config::node::{Udp443Policy, VlessMultiplex, VlessUdpMux};
        use std::num::NonZeroU16;

        let descriptor = descriptor(NodeProtocol::VLess);
        let limit = NonZeroU16::new(8).unwrap();
        for (multiplex, bare, warm_tcp, warm_udp) in [
            (VlessMultiplex::Off, true, false, false),
            (VlessMultiplex::H2 { padding: false }, false, true, true),
            (
                VlessMultiplex::Xray {
                    tcp: Some(limit),
                    udp: VlessUdpMux::SharedTcp,
                    udp443: Udp443Policy::Reject,
                },
                false,
                true,
                true,
            ),
            (
                VlessMultiplex::Xray {
                    tcp: None,
                    udp: VlessUdpMux::Separate(limit),
                    udp443: Udp443Policy::Reject,
                },
                true,
                false,
                true,
            ),
        ] {
            let node = Node {
                outbound: honk_config::node::OutboundConfig::Vless(
                    honk_config::node::VlessConfig {
                        multiplex,
                        ..Default::default()
                    },
                ),
                ..Default::default()
            };
            assert!((descriptor.supports_udp)(&node));
            assert_eq!((descriptor.pool_bare_tcp)(&node), bare);
            assert_eq!(
                descriptor.supports_warm(&node, WarmRequirement::Session),
                warm_tcp
            );
            assert_eq!(
                descriptor.supports_warm(&node, WarmRequirement::Udp),
                warm_udp
            );
        }
    }

    #[test]
    fn xhttp_owns_warming_without_bare_or_ready_tcp_competition() {
        for protocol in [
            NodeProtocol::Trojan,
            NodeProtocol::VMess,
            NodeProtocol::VLess,
        ] {
            let mut node = Node {
                outbound: honk_config::node::OutboundConfig::from_protocol(protocol),
                ..Default::default()
            };
            node.transport_mut().unwrap().transport = "xhttp".into();
            let descriptor = descriptor(protocol);
            assert!(!(descriptor.pool_bare_tcp)(&node));
            assert!(!(descriptor.pool_ready_streams)(&node));
            assert!(descriptor.supports_warm(&node, WarmRequirement::Session));
            assert_eq!(
                descriptor.supports_warm(&node, WarmRequirement::Udp),
                (descriptor.supports_udp)(&node),
            );
            match protocol {
                NodeProtocol::Trojan => node.trojan_mut().unwrap().network = Some("tcp".into()),
                NodeProtocol::VLess => node.vless_mut().unwrap().network = Some("tcp".into()),
                _ => {}
            }
            assert!(!descriptor.supports_warm(&node, WarmRequirement::Udp));
        }
    }

    #[test]
    fn udp_capability_follows_the_network_gate() {
        let mut base = Node {
            outbound: honk_config::node::OutboundConfig::Trojan(Default::default()),
            ..Default::default()
        };
        let trojan = descriptor(NodeProtocol::Trojan).supports_udp;
        assert!(trojan(&base), "no network restriction allows UDP");
        base.trojan_mut().unwrap().network = Some("ws".to_string());
        assert!(!trojan(&base));
        base.trojan_mut().unwrap().network = Some("tcp, udp".to_string());
        assert!(trojan(&base));

        let anytls = descriptor(NodeProtocol::AnyTLS).supports_udp;
        let ws_only = Node {
            outbound: honk_config::node::OutboundConfig::AnyTls(honk_config::node::AnyTlsConfig {
                network: Some("ws".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(!anytls(&ws_only));

        let vless = descriptor(NodeProtocol::VLess).supports_udp;
        let tcp_only = Node {
            outbound: honk_config::node::OutboundConfig::Vless(honk_config::node::VlessConfig {
                multiplex: honk_config::node::VlessMultiplex::H2 { padding: false },
                network: Some("tcp".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(!vless(&tcp_only));

        let ss = descriptor(NodeProtocol::SS).supports_udp;
        let node = Node::default();
        assert!(ss(&node), "SS UDP is not network-gated");
    }

    #[test]
    fn vless_udp_443_policy_is_path_scoped() {
        use honk_config::node::{Udp443Policy, VlessMultiplex, VlessUdpMux};
        use std::num::NonZeroU16;

        let mut node = Node {
            outbound: honk_config::node::OutboundConfig::Vless(honk_config::node::VlessConfig {
                multiplex: VlessMultiplex::Xray {
                    tcp: Some(NonZeroU16::new(8).unwrap()),
                    udp: VlessUdpMux::SharedTcp,
                    udp443: Udp443Policy::Reject,
                },
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(udp_target_allowed(&node, 53));
        assert!(!udp_target_allowed(&node, 443));

        let VlessMultiplex::Xray { udp443, .. } = &mut node.vless_mut().unwrap().multiplex else {
            unreachable!()
        };
        *udp443 = Udp443Policy::Allow;
        assert!(udp_target_allowed(&node, 443));
        assert!(udp_target_allowed(&Node::default(), 443));
    }
}
