//! dae-style node chains: `'landing -> relay1 -> relay2'`.
//!
//! Semantics follow dae (`daeuniverse/outbound` `NewNetproxyDialerFromLink`):
//! the leftmost link is the endpoint (landing) node, every link to its right
//! is a relay that carries the link on its left, and the rightmost link is the
//! hop dialed first. A chain therefore maps onto the existing `detour` model:
//! the landing's detour is the first relay, each relay's detour is the next
//! relay, and the last relay keeps its own `dialer-proxy=` (if any).
//!
//! Relays have no user-facing name, so [`ChainNamer`] gives each a generated
//! name that never equals another node's name, or reuses an identical node
//! (same identity and same onward detour) that already exists.

use std::collections::{HashMap, HashSet};

use crate::diagnostic::{SettingPath, SourceRef};
use crate::error::{DetailedConfigError, ErrorCategory};
use crate::node::{MAX_DETOUR_HOPS, Node};

/// Bare transport layers dae accepts as chain hops. honk has no standalone
/// transport outbound, so nesting a proxy inside one (e.g. `socks5 -> wss`)
/// fails with a clear error instead.
const TRANSPORT_ONLY_SCHEMES: [&str; 5] = ["ws", "wss", "tls", "utls", "simpleobfs"];

/// One parsed `->` chain: the landing node and its relays, nearest the
/// landing first. Relay names and all detours but the last relay's are wired
/// by [`ChainNamer::link`].
#[derive(Debug, Clone)]
pub struct ShareLinkChain {
    pub landing: Node,
    pub relays: Vec<Node>,
}

/// Split a share link on dae's `->` hop separator.
pub fn chain_hops(link: &str) -> Vec<&str> {
    link.split("->").map(str::trim).collect()
}

/// Whether `link` is a multi-hop `->` chain.
pub fn is_chain(link: &str) -> bool {
    link.contains("->")
}

/// Whether a `->` hop is a bare node/group name rather than a share link.
/// A hop is a link exactly when it contains `://`; anything else names a
/// node or group declared elsewhere (resolved like `detour`: group first,
/// then a unique node name).
pub fn is_bare_name(hop: &str) -> bool {
    !hop.contains("://")
}

pub(crate) fn chain_error(
    source: &SourceRef,
    code: &'static str,
    message: &'static str,
) -> DetailedConfigError {
    DetailedConfigError::new(
        ErrorCategory::Validation,
        code,
        source.clone(),
        SettingPath::new("nodes").field("chain"),
        message,
    )
}

impl Node {
    /// Parse a share link that may be a dae `->` chain. A single link yields
    /// a chain without relays.
    pub fn from_share_link_chain(link: &str) -> Result<ShareLinkChain, crate::error::ConfigError> {
        let mut diagnostics = Vec::new();
        let source = crate::diagnostic::DiagnosticSources::new(None).root();
        let result = Self::parse_share_link_chain(link, &source, &mut |diagnostic| {
            diagnostics.push(diagnostic);
        });
        crate::diagnostic::report_detailed_diagnostics(&diagnostics);
        result.map_err(DetailedConfigError::into_legacy)
    }

    /// [`Node::from_share_link_chain`] with a caller-owned diagnostic sink.
    pub fn from_share_link_chain_with_detailed_diagnostics_emit(
        link: &str,
        emit: &mut impl FnMut(crate::diagnostic::DetailedDiagnostic),
    ) -> Result<ShareLinkChain, DetailedConfigError> {
        let source = crate::diagnostic::DiagnosticSources::new(None).root();
        Self::parse_share_link_chain(link, &source, emit)
    }

    pub(crate) fn parse_share_link_chain(
        link: &str,
        source: &SourceRef,
        emit: &mut impl FnMut(crate::diagnostic::DetailedDiagnostic),
    ) -> Result<ShareLinkChain, DetailedConfigError> {
        let hops = chain_hops(link);
        if hops.len() == 1 {
            let landing = Self::parse_share_link(link, source, emit)?;
            return Ok(ShareLinkChain {
                landing,
                relays: Vec::new(),
            });
        }
        if hops.len() > MAX_DETOUR_HOPS + 1 {
            return Err(chain_error(
                source,
                "detour-chain-too-deep",
                "node chain (->) is longer than 8 hops",
            ));
        }
        let mut nodes = Vec::with_capacity(hops.len());
        let mut target = None;
        let link_count = hops.len() - usize::from(hops.last().is_some_and(|hop| is_bare_name(hop)));
        for (index, hop) in hops.iter().enumerate() {
            if hop.is_empty() {
                return Err(chain_error(
                    source,
                    "invalid-chain",
                    "node chain (->) has an empty hop",
                ));
            }
            if is_bare_name(hop) {
                if index == 0 {
                    return Err(chain_error(
                        source,
                        "invalid-chain",
                        "node chain (->) landing must be a share link here; a bare-name \
                         landing (`my_node -> relay`) is only allowed as a node section entry",
                    ));
                }
                if index + 1 != hops.len() {
                    return Err(chain_error(
                        source,
                        "invalid-chain",
                        "node chain (->): a bare node/group name hop must be the last \
                         (rightmost) hop",
                    ));
                }
                target = Some((*hop).to_owned());
                break;
            }
            let scheme = hop
                .split_once("://")
                .map(|(scheme, _)| scheme.to_ascii_lowercase());
            if let Some(scheme) = scheme.as_deref()
                && TRANSPORT_ONLY_SCHEMES.contains(&scheme)
            {
                return Err(chain_error(
                    source,
                    "unsupported-chain-transport",
                    "node chain (->) hop is a bare transport (ws/wss/tls/utls/simpleobfs); \
                     nesting a proxy inside a transport (e.g. socks5 over wss) is unsupported, \
                     use a protocol link with its own transport (type=ws, security=tls) instead",
                ));
            }
            let node = Self::parse_share_link(hop, source, emit)?;
            // The rightmost link; a trailing name hop becomes its detour.
            let last = index + 1 == link_count;
            if node.detour.is_some() && !last {
                return Err(chain_error(
                    source,
                    "conflicting-detour",
                    "only the last (rightmost) hop of a node chain (->) may set dialer-proxy/detour",
                ));
            }
            if index + 1 < hops.len() && !node.supports_detour() {
                return Err(chain_error(
                    source,
                    "unsupported-detour-protocol",
                    "node chain (->): this protocol cannot ride a relay (anytls, xhttp, \
                     hysteria2 port hopping); it must be the rightmost hop",
                ));
            }
            nodes.push(node);
        }
        if let Some(target) = target {
            let tail = nodes.last_mut().expect("landing parsed before a name hop");
            if tail.detour.as_ref().is_some_and(|detour| *detour != target) {
                return Err(chain_error(
                    source,
                    "conflicting-detour",
                    "node chain (->): the last link's dialer-proxy/detour differs from the \
                     named hop after it",
                ));
            }
            tail.detour = Some(target);
            tail.id = tail.derive_id();
        }
        let landing = nodes.remove(0);
        Ok(ShareLinkChain {
            landing,
            relays: nodes,
        })
    }
}

/// Assigns relay names that never collide with existing node names, and
/// reuses an existing identical relay (same identity, same onward detour).
#[derive(Debug, Default)]
pub struct ChainNamer {
    names: HashSet<String>,
    by_id: HashMap<uuid::Uuid, (String, Option<String>)>,
}

impl ChainNamer {
    /// Seed with every node already declared (user names are reserved).
    pub fn new<'a>(nodes: impl IntoIterator<Item = &'a Node>) -> Self {
        let mut namer = Self::default();
        for node in nodes {
            namer.reserve(node);
        }
        namer
    }

    /// Reserve a node's name and record it for relay reuse.
    pub fn reserve(&mut self, node: &Node) {
        self.names.insert(node.name.clone());
        self.by_id
            .entry(node.base_id())
            .or_insert_with(|| (node.name.clone(), node.detour.clone()));
    }

    /// Wire `chain` into detour form: returns the landing followed by the
    /// relays that must be added (relays identical to a known node are
    /// reused, not returned). The landing's name must already be final.
    pub fn link(&mut self, chain: ShareLinkChain) -> Result<Vec<Node>, &'static str> {
        let ShareLinkChain {
            mut landing,
            relays,
        } = chain;
        if relays.is_empty() {
            landing.id = landing.derive_id();
            self.reserve(&landing);
            return Ok(vec![landing]);
        }
        if landing.detour.is_some() {
            return Err(
                "a node chain (->) landing cannot also set dialer-proxy/detour; \
                 put it on the last (rightmost) hop",
            );
        }
        self.names.insert(landing.name.clone());
        let count = relays.len();
        let mut added = Vec::new();
        let mut onward: Option<String> = None;
        for (offset, mut relay) in relays.into_iter().rev().enumerate() {
            let position = count - offset;
            if offset > 0 {
                relay.detour = onward.take();
            }
            if let Some((name, detour)) = self.by_id.get(&relay.base_id()) {
                if *detour != relay.detour {
                    return Err("node chain (->) relay duplicates another node's identity \
                         with a different onward chain");
                }
                onward = Some(name.clone());
                continue;
            }
            relay.name = self.unique(&landing.name, position, &relay.base_id());
            relay.id = relay.derive_id();
            onward = Some(relay.name.clone());
            self.reserve(&relay);
            added.push(relay);
        }
        landing.detour = onward;
        landing.id = landing.derive_id();
        self.reserve(&landing);
        added.reverse();
        let mut out = vec![landing];
        out.extend(added);
        Ok(out)
    }

    fn unique(&mut self, landing: &str, position: usize, id: &uuid::Uuid) -> String {
        let short = &id.simple().to_string()[..8];
        let base = format!("{landing}~relay{position}-{short}");
        let mut name = base.clone();
        let mut suffix = 2;
        while self.names.contains(&name) {
            name = format!("{base}~{suffix}");
            suffix += 1;
        }
        name
    }
}
