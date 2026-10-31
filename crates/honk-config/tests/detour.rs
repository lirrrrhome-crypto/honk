//! Node-level `detour` / `dialer-proxy` parsing and validation.

use honk_config::{Config, parser::parse_dae_config_with_detailed_diagnostics};

fn parse(nodes: &str, groups: &str) -> Config {
    parse_dae_config_with_detailed_diagnostics(
        &format!("node {{\n{nodes}\n}}\ngroup {{\n{groups}\n}}\n"),
        &mut Vec::new(),
    )
    .unwrap()
}

fn code(config: &Config) -> Option<&'static str> {
    let detailed = config.validate_detailed().err().map(|e| e.diagnostic.code);
    let assembled = config.validate_assembled().err().map(|e| e.diagnostic.code);
    assert_eq!(detailed, assembled);
    detailed
}

#[test]
fn share_link_detour_param_is_stripped_and_kept() {
    let config = parse(
        "front: 'socks5://10.0.0.1:1080'\n land: 'trojan://pw@land.example:443?sni=land.example&dialer-proxy=front#land'",
        "",
    );
    let land = config.nodes.iter().find(|n| n.name == "land").unwrap();
    assert_eq!(land.detour.as_deref(), Some("front"));
    let plain = parse(
        "land: 'trojan://pw@land.example:443?sni=land.example#land'",
        "",
    );
    assert_eq!(
        plain.nodes[0].id, land.id,
        "detour is not part of node identity"
    );
    assert_eq!(code(&config), None);
}

#[test]
fn detour_aliases_and_percent_decoding() {
    for key in ["detour", "dialer_proxy", "DIALER-PROXY"] {
        let config = parse(
            &format!(
                "'my front': 'socks5://10.0.0.1:1080'\n land: 'ss://YWVzLTEyOC1nY206cHc@1.2.3.4:8388?{key}=my%20front'"
            ),
            "",
        );
        let land = config.nodes.iter().find(|n| n.name == "land").unwrap();
        assert_eq!(land.detour.as_deref(), Some("my front"), "{key}");
        assert_eq!(code(&config), None, "{key}");
    }
}

#[test]
fn group_front_is_accepted() {
    let config = parse(
        "a: 'socks5://10.0.0.1:1080'\n land: 'socks5://1.2.3.4:1080?detour=fronts'",
        "fronts {\n filter: name(a)\n policy: fixed(0)\n}",
    );
    assert_eq!(code(&config), None);
}

#[test]
fn invalid_detours_are_rejected() {
    for (nodes, groups, expected) in [
        (
            "land: 'socks5://1.2.3.4:1080?detour=missing'",
            "",
            "unknown-detour-target",
        ),
        (
            "land: 'socks5://1.2.3.4:1080?detour=land'",
            "",
            "detour-cycle",
        ),
        (
            "a: 'socks5://1.1.1.1:1080?detour=b'\n b: 'socks5://2.2.2.2:1080?detour=a'",
            "",
            "detour-cycle",
        ),
        (
            "a: 'socks5://1.1.1.1:1080?detour=g'",
            "g {\n filter: name(a)\n policy: fixed(0)\n}",
            "detour-cycle",
        ),
        (
            "f: 'socks5://1.1.1.1:1080'\n h: 'hysteria2://pw@2.2.2.2:443?mport=443-450&detour=f'",
            "",
            "unsupported-detour-protocol",
        ),
    ] {
        let config = parse(nodes, groups);
        assert_eq!(code(&config), Some(expected), "{nodes}");
    }
}

#[test]
fn structured_node_round_trips_detour_and_accepts_dialer_proxy_alias() {
    let parsed = parse(
        "front: 'socks5://10.0.0.1:1080'\n land: 'socks5://1.2.3.4:1080?detour=front'",
        "",
    );
    let mut value = serde_json::json!({"nodes": parsed.nodes});
    let text = value.to_string();
    assert!(text.contains("\"detour\":\"front\""), "{text}");
    let config: Config = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(config.nodes[1].detour.as_deref(), Some("front"));

    fn rename(value: &mut serde_json::Value) {
        match value {
            serde_json::Value::Object(map) => {
                if let Some(v) = map.remove("detour") {
                    map.insert("dialer-proxy".into(), v);
                }
                map.values_mut().for_each(rename);
            }
            serde_json::Value::Array(items) => items.iter_mut().for_each(rename),
            _ => {}
        }
    }
    rename(&mut value);
    let config: Config = serde_json::from_value(value).unwrap();
    assert_eq!(config.nodes[1].detour.as_deref(), Some("front"));
    assert_eq!(code(&config), None);
}

#[test]
fn documented_example_validates() {
    let config = parse(
        "front: 'socks5://10.0.0.1:1080'\n land: 'trojan://secret@land.example:443?sni=land.example&dialer-proxy=front'\n land2: 'ss://YWVzLTI1Ni1nY206cHc@203.0.113.5:8388?detour=fronts'",
        "fronts { filter: name(front) policy: min_moving_avg }",
    );
    assert_eq!(code(&config), None);
    let land2 = config.nodes.iter().find(|n| n.name == "land2").unwrap();
    assert_eq!(land2.detour.as_deref(), Some("fronts"));
}

#[test]
fn empty_detour_value_means_no_detour() {
    for query in ["dialer-proxy=", "detour=%20", "detour"] {
        let config = parse(&format!("land: 'socks5://1.2.3.4:1080?{query}'"), "");
        assert_eq!(config.nodes[0].detour, None, "{query}");
        assert_eq!(code(&config), None, "{query}");
    }
}

#[test]
fn both_detour_keys_must_agree() {
    let same = parse(
        "a: 'socks5://1.1.1.1:1080'\n land: 'socks5://1.2.3.4:1080?detour=a&dialer-proxy=a'",
        "",
    );
    let land = same.nodes.iter().find(|n| n.name == "land").unwrap();
    assert_eq!(land.detour.as_deref(), Some("a"));
    // A conflicting pair used to silently keep the last value.
    let nodes = "a: 'socks5://1.1.1.1:1080'\n b: 'socks5://2.2.2.2:1080'\n land: 'socks5://1.2.3.4:1080?detour=a&dialer-proxy=b'";
    let error = parse_dae_config_with_detailed_diagnostics(
        &format!("node {{\n{nodes}\n}}\n"),
        &mut Vec::new(),
    );
    match error {
        Err(error) => assert_eq!(error.diagnostic.code, "invalid-detour"),
        Ok(config) => {
            let land = config.nodes.iter().find(|n| n.name == "land");
            assert!(land.is_none(), "conflicting detours must not yield a node");
        }
    }
}

fn chain(len: usize) -> String {
    // n0 is the outermost front; n{i} detours through n{i-1}.
    let mut nodes = String::from("n0: 'socks5://10.0.0.1:1080'\n");
    for i in 1..=len {
        nodes.push_str(&format!(
            "n{i}: 'socks5://10.0.0.{}:1080?detour=n{}'\n",
            i + 1,
            i - 1
        ));
    }
    nodes
}

#[test]
fn chain_depth_is_bounded_at_validation() {
    assert_eq!(code(&parse(&chain(8), "")), None);
    assert_eq!(code(&parse(&chain(9), "")), Some("detour-chain-too-deep"));
    // A group hop costs nothing but its members' chains count.
    let mut nodes = chain(8);
    nodes.push_str("top: 'socks5://9.9.9.9:1080?detour=g'\n");
    assert_eq!(
        code(&parse(
            &nodes,
            "g {\n filter: name(n8)\n policy: fixed(0)\n}"
        )),
        Some("detour-chain-too-deep")
    );
}

#[test]
fn special_characters_in_detour_names() {
    for (name, encoded) in [
        ("a&b", "a%26b"),
        ("a#b", "a%23b"),
        ("a?b=c", "a%3Fb%3Dc"),
        ("前置", "%E5%89%8D%E7%BD%AE"),
    ] {
        let config = parse(
            &format!(
                "'{name}': 'socks5://10.0.0.1:1080'\n land: 'socks5://1.2.3.4:1080?detour={encoded}#land'"
            ),
            "",
        );
        let land = config.nodes.iter().find(|n| n.name == "land").unwrap();
        assert_eq!(land.detour.as_deref(), Some(name));
        assert_eq!(code(&config), None, "{name}");
    }
}

/// Dependency-free fuzz: random share-link-ish strings must never panic the
/// parser or validator, and a parsed node never keeps a detour key upstream.
#[test]
fn fuzz_share_links_do_not_panic() {
    const PIECES: &[&str] = &[
        "socks5://",
        "ss://YWVzLTEyOC1nY206cHc@",
        "trojan://pw@",
        "vless://",
        "1.2.3.4",
        ":1080",
        "?",
        "&",
        "#",
        "=",
        "detour",
        "dialer-proxy",
        "dialer_proxy",
        "%",
        "%2",
        "%ZZ",
        "%E5",
        "->",
        "a",
        "land",
        "前",
        " ",
        "sni=x",
        "type=ws",
        "\\",
        "@",
        "[::1]",
    ];
    let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for _ in 0..20_000 {
        let len = (next() % 12) as usize;
        let link: String = (0..len)
            .map(|_| PIECES[(next() % PIECES.len() as u64) as usize])
            .collect();
        let link = link.replace('\'', "");
        let text = format!("node {{\n a: 'socks5://9.9.9.9:1080'\n land: '{link}'\n}}\n");
        if let Ok(config) = parse_dae_config_with_detailed_diagnostics(&text, &mut Vec::new()) {
            let _ = config.validate_detailed();
        }
    }
}

#[test]
fn group_front_depth_uses_the_deepest_member() {
    // g holds a shallow n0 and the deepest n7; a node fronted by g is one
    // hop deeper than n7 whichever member the policy picks at connect time.
    let mut nodes = chain(7);
    nodes.push_str("top: 'socks5://9.9.9.9:1080?detour=g'\n");
    let shallow_and_deep = "g {\n filter: name(n0, n7)\n policy: selector\n}";
    assert_eq!(code(&parse(&nodes, shallow_and_deep)), None);
    nodes.push_str("top2: 'socks5://9.9.9.8:1080?detour=top'\n");
    assert_eq!(
        code(&parse(&nodes, shallow_and_deep)),
        Some("detour-chain-too-deep")
    );
    // Through a nested group as well: outer → inner → n8.
    let mut nodes = chain(8);
    nodes.push_str("top: 'socks5://9.9.9.9:1080?detour=outer'\n");
    assert_eq!(
        code(&parse(
            &nodes,
            "inner {\n filter: name(n0, n8)\n policy: selector\n}\nouter {\n filter: group(inner)\n policy: selector\n}"
        )),
        Some("detour-chain-too-deep")
    );
}

#[test]
fn cycles_through_nested_groups_and_final_are_rejected() {
    for (nodes, groups) in [
        (
            "a: 'socks5://1.1.1.1:1080?detour=outer'\n b: 'socks5://2.2.2.2:1080'",
            "inner {\n filter: name(a, b)\n policy: selector\n}\nouter {\n filter: group(inner)\n policy: selector\n}",
        ),
        (
            "a: 'socks5://1.1.1.1:1080?detour=g'\n b: 'socks5://2.2.2.2:1080'",
            "g {\n filter: name(b)\n policy: fallback\n final: a\n}",
        ),
        (
            "a: 'socks5://1.1.1.1:1080?detour=g'\n b: 'socks5://2.2.2.2:1080?detour=h'",
            "g {\n filter: name(b)\n policy: selector\n}\nh {\n filter: name(a)\n policy: url_test\n}",
        ),
    ] {
        assert_eq!(
            code(&parse(nodes, groups)),
            Some("detour-cycle"),
            "{groups}"
        );
    }
    // Sibling members of the same group are not a cycle.
    assert_eq!(
        code(&parse(
            "a1: 'socks5://1.1.1.1:1080'\n a2: 'socks5://1.1.1.2:1080'\n b: 'socks5://2.2.2.2:1080?detour=fronts'",
            "fronts {\n filter: name(a1, a2)\n policy: selector\n}"
        )),
        None
    );
}

#[test]
fn group_to_group_chains_validate_and_cycles_through_them_are_rejected() {
    let nodes = "a1: 'socks5://10.0.0.1:1080'\n a2: 'socks5://10.0.0.2:1080'\n b1: 'socks5://10.0.0.3:1080?dialer-proxy=outer'\n b2: 'socks5://10.0.0.4:1080?dialer-proxy=outer'";
    let ok = parse(
        nodes,
        "fronts {\n filter: name(a1, a2)\n policy: selector\n}\nouter {\n filter: group(fronts)\n policy: selector\n}\nlands {\n filter: name(b1, b2)\n policy: selector\n}",
    );
    assert_eq!(code(&ok), None);
    // The front group nests the landing group: b1 -> outer -> lands -> b1.
    let cyclic = parse(
        nodes,
        "lands {\n filter: name(b1, b2)\n policy: selector\n}\nouter {\n filter: group(lands)\n policy: selector\n}",
    );
    assert_eq!(code(&cyclic), Some("detour-cycle"));
}
