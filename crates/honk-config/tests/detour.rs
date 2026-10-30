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
            "f: 'socks5://1.1.1.1:1080'\n h: 'hysteria2://pw@2.2.2.2:443?detour=f'",
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
