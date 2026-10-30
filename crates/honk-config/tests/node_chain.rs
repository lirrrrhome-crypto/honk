//! dae `->` node chains: left = landing (endpoint), right = relay dialed first.

use honk_config::node::Node;
use honk_config::share_link::ChainNamer;
use honk_config::{Config, parser::parse_dae_config_with_detailed_diagnostics};

const LAND: &str = "trojan://pw@land.example:443?sni=land.example";
const MID: &str = "ss://YWVzLTEyOC1nY206cHc@10.0.0.2:8388";
const FRONT: &str = "socks5://10.0.0.1:1080";

fn parse_with(
    nodes: &str,
    groups: &str,
) -> (Config, Vec<honk_config::diagnostic::DetailedDiagnostic>) {
    let mut diagnostics = Vec::new();
    let config = parse_dae_config_with_detailed_diagnostics(
        &format!("node {{\n{nodes}\n}}\ngroup {{\n{groups}\n}}\n"),
        &mut diagnostics,
    )
    .unwrap();
    (config, diagnostics)
}

fn parse(nodes: &str) -> Config {
    parse_with(nodes, "").0
}

fn node<'a>(config: &'a Config, name: &str) -> &'a Node {
    config.nodes.iter().find(|n| n.name == name).unwrap()
}

fn code(config: &Config) -> Option<&'static str> {
    let detailed = config.validate_detailed().err().map(|e| e.diagnostic.code);
    let assembled = config.validate_assembled().err().map(|e| e.diagnostic.code);
    assert_eq!(detailed, assembled);
    detailed
}

fn hops(config: &Config, start: &str) -> Vec<String> {
    let mut out = vec![start.to_owned()];
    let mut current = node(config, start);
    while let Some(next) = current.detour.as_deref() {
        out.push(next.to_owned());
        let Some(next) = config.nodes.iter().find(|n| n.name == next) else {
            break;
        };
        current = next;
    }
    out
}

#[test]
fn two_hop_chain_left_is_landing_right_is_relay() {
    let config = parse(&format!("c: '{LAND} -> {FRONT}'"));
    assert_eq!(config.nodes.len(), 2);
    let land = node(&config, "c");
    assert_eq!(land.host, "land.example");
    let relay = node(&config, land.detour.as_deref().unwrap());
    assert_eq!(relay.host, "10.0.0.1");
    assert_eq!(relay.detour, None, "rightmost hop is dialed directly");
    assert_eq!(code(&config), None);
}

#[test]
fn multi_level_chain_wires_every_hop_in_order() {
    let config = parse(&format!("c: '{LAND} -> {MID} -> {FRONT}'"));
    let chain = hops(&config, "c");
    let hosts: Vec<_> = chain
        .iter()
        .map(|n| node(&config, n).host.clone())
        .collect();
    assert_eq!(hosts, ["land.example", "10.0.0.2", "10.0.0.1"]);
    assert_eq!(code(&config), None);
}

#[test]
fn generated_names_never_collide_with_user_names() {
    // Pre-compute what the generated name would be, then declare a user
    // node with exactly that name *after* the chain.
    let probe = parse(&format!("c: '{LAND} -> {FRONT}'"));
    let generated = node(&probe, "c").detour.clone().unwrap();
    let config = parse(&format!(
        "c: '{LAND} -> {FRONT}'\n '{generated}': 'socks5://192.0.2.9:1080'"
    ));
    let mut names: Vec<_> = config.nodes.iter().map(|n| n.name.clone()).collect();
    names.sort();
    names.dedup();
    assert_eq!(names.len(), config.nodes.len(), "{names:?}");
    let relay = node(&config, node(&config, "c").detour.as_deref().unwrap());
    assert_eq!(
        relay.host, "10.0.0.1",
        "landing still rides the chain relay"
    );
    assert_eq!(node(&config, &generated).host, "192.0.2.9");
    assert_eq!(code(&config), None);
}

#[test]
fn identical_relay_is_reused_not_duplicated() {
    let config = parse(&format!(
        "front: '{FRONT}'\n c1: '{LAND} -> {FRONT}'\n c2: 'trojan://pw@land2.example:443?sni=land2.example -> {FRONT}'"
    ));
    assert_eq!(
        config.nodes.len(),
        3,
        "both chains reuse the declared front"
    );
    assert_eq!(node(&config, "c1").detour.as_deref(), Some("front"));
    assert_eq!(node(&config, "c2").detour.as_deref(), Some("front"));
    assert_eq!(code(&config), None);
}

#[test]
fn last_hop_may_continue_to_a_named_front_or_group() {
    let (config, _) = parse_with(
        &format!("a: '{FRONT}'\n c: '{LAND} -> {MID}?dialer-proxy=fronts'"),
        "fronts {\n filter: name(a)\n policy: fixed(0)\n}",
    );
    let chain = hops(&config, "c");
    assert_eq!(chain.last().unwrap(), "fronts");
    assert_eq!(code(&config), None);
}

#[test]
fn chains_reuse_cycle_and_depth_validation() {
    // The last hop points back at the landing: a cycle.
    let config = parse(&format!("c: '{LAND} -> {MID}?dialer-proxy=c'"));
    assert_eq!(code(&config), Some("detour-cycle"));
    // Nine relays plus the landing exceed the hop bound at parse time.
    let long = (0..9)
        .map(|i| format!("socks5://10.0.1.{i}:1080"))
        .collect::<Vec<_>>()
        .join(" -> ");
    let (config, diagnostics) = parse_with(&format!("c: '{LAND} -> {long}'"), "");
    assert!(config.nodes.is_empty());
    assert!(
        diagnostics
            .iter()
            .any(|d| d.code == "detour-chain-too-deep")
    );
    // Eight hops through a declared chain front: validation bounds the total.
    let fronts = (0..8)
        .map(|i| format!("socks5://10.0.2.{i}:1080"))
        .collect::<Vec<_>>()
        .join(" -> ");
    let config = parse(&format!(
        "f: '{FRONT} -> {fronts}'\n c: '{LAND} -> {MID}?dialer-proxy=f'"
    ));
    assert_eq!(code(&config), Some("detour-chain-too-deep"));
}

#[test]
fn rejected_chains_drop_the_entry_with_a_clear_code() {
    for (link, expected) in [
        // socks5 over wss (dae same-port nesting): bare transports unsupported.
        (
            "socks5://h.example:6999 -> wss://h.example:6999/path".to_owned(),
            "unsupported-chain-transport",
        ),
        // QUIC landing over a TCP relay.
        (
            format!("tuic://00000000-0000-0000-0000-000000000001:p@t.example:443 -> {FRONT}"),
            "unsupported-detour-protocol",
        ),
        // Only the rightmost hop may name a further front.
        (
            format!("{LAND}&dialer-proxy=x -> {FRONT}"),
            "conflicting-detour",
        ),
        (format!("{LAND} -> -> {FRONT}"), "invalid-chain"),
    ] {
        let (config, diagnostics) = parse_with(&format!("c: '{link}'"), "");
        assert!(
            config.nodes.is_empty(),
            "{link}: entry must be dropped, never reduced"
        );
        assert!(
            diagnostics.iter().any(|d| d.code == expected),
            "{link}: {:?}",
            diagnostics.iter().map(|d| d.code).collect::<Vec<_>>()
        );
    }
}

#[test]
fn single_link_api_refuses_chains_instead_of_dropping_hops() {
    assert!(Node::from_share_link(&format!("{LAND} -> {FRONT}")).is_err());
    let chain = Node::from_share_link_chain(&format!("{LAND} -> {MID} -> {FRONT}")).unwrap();
    assert_eq!(chain.landing.host, "land.example");
    let relays: Vec<_> = chain.relays.iter().map(|n| n.host.as_str()).collect();
    assert_eq!(relays, ["10.0.0.2", "10.0.0.1"]);
}

#[test]
fn namer_rejects_a_relay_reused_with_another_onward_chain() {
    let mut namer = ChainNamer::default();
    let first = Node::from_share_link_chain(&format!("{LAND}#a -> {MID} -> {FRONT}")).unwrap();
    namer.link(first).unwrap();
    // MID again, but now dialed directly: same identity, different detour.
    let second = Node::from_share_link_chain(&format!("{LAND}#b -> {MID}")).unwrap();
    assert!(namer.link(second).is_err());
}

#[test]
fn bare_name_hop_targets_a_node_or_group() {
    let (config, _) = parse_with(
        &format!(
            "front: '{FRONT}'\nc: '{LAND} -> front'\nd: 'trojan://pw2@land.example:443?sni=land.example -> {MID} -> relays'"
        ),
        "relays {\n filter: name(front)\n policy: fixed(0)\n}",
    );
    assert_eq!(hops(&config, "c"), ["c", "front"]);
    let d = hops(&config, "d");
    assert_eq!(d.len(), 3);
    assert_eq!(d[2], "relays");
    assert_eq!(code(&config), None);
}

#[test]
fn bare_name_landing_declares_an_existing_nodes_detour() {
    let explicit = parse(&format!("land: '{LAND}'\nmid: '{MID}'\nland -> mid"));
    // Unquoted and quoted bare-name declarations, plus an identical repeat.
    let repeated = parse(&format!(
        "land: '{LAND}'\nmid: '{MID}'\n'land -> mid'\nland: 'land -> mid'"
    ));
    let via_param = parse(&format!("land: '{LAND}&dialer-proxy=mid'\nmid: '{MID}'"));
    for config in [&explicit, &repeated, &via_param] {
        assert_eq!(config.nodes.len(), 2);
        assert_eq!(hops(config, "land"), ["land", "mid"]);
        assert_eq!(code(config), None);
    }
    // A named landing with link relays generates relay nodes like a chain.
    let relayed = parse(&format!("land: '{LAND}'\n'land -> {MID} -> {FRONT}'"));
    assert_eq!(hops(&relayed, "land").len(), 3);
}

#[test]
fn conflicting_detour_declarations_are_an_error() {
    let mut diagnostics = Vec::new();
    let error = parse_dae_config_with_detailed_diagnostics(
        &format!("node {{\nland: '{LAND}&dialer-proxy=mid'\nmid: '{MID}'\nfront: '{FRONT}'\n'land -> front'\n}}\n"),
        &mut diagnostics,
    )
    .unwrap_err();
    assert!(
        format!("{error:?}").contains("conflicting-detour"),
        "{error:?}"
    );
}

#[test]
fn bare_name_rules_are_enforced() {
    // A name in the middle, an unknown named landing, and a tag mismatch are
    // warned and dropped; a lone link entry still parses.
    for entry in [
        format!("c: '{LAND} -> front -> {FRONT}'"),
        "'ghost -> front'".to_owned(),
        "x: 'front -> other'".to_owned(),
    ] {
        let (config, diagnostics) = parse_with(&format!("front: '{FRONT}'\n{entry}"), "");
        assert_eq!(config.nodes.len(), 1, "{entry}");
        assert!(node(&config, "front").detour.is_none(), "{entry}");
        assert!(!diagnostics.is_empty(), "{entry}");
    }
}

#[test]
fn detour_names_prefer_the_own_subscription_then_must_be_globally_unique() {
    let mut config = parse(&format!(
        "f: '{FRONT}'\n x: '{MID}?dialer-proxy=f'\n g: '{FRONT}'\n y: '{MID}?dialer-proxy=f'"
    ));
    let (a, b) = (uuid::Uuid::from_u128(1), uuid::Uuid::from_u128(2));
    for n in &mut config.nodes {
        n.subscription_id = Some(if matches!(n.name.as_str(), "f" | "x") {
            a
        } else {
            b
        });
        if n.name == "g" {
            n.name = "f".into();
            n.host = "10.0.0.9".into();
        }
        if n.name == "y" {
            n.host = "10.0.0.8".into();
        }
        n.id = n.derive_id();
    }
    assert_eq!(
        code(&config),
        None,
        "each subscription resolves its own `f`"
    );
    for n in &mut config.nodes {
        if n.name == "y" {
            n.subscription_id = None;
            n.id = n.derive_id();
        }
    }
    assert_eq!(code(&config), Some("ambiguous-detour-target"));
}
