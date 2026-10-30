use super::*;
use base64::Engine as _;
use honk_config::types::NodeProtocol;
use sha2::{Digest as _, Sha256};

mod admission;
mod clash;

fn parse_clash_subscription(
    content: &str,
    subscription_id: Option<uuid::Uuid>,
) -> anyhow::Result<Vec<Node>> {
    let yaml = parse_structured_value(content)?;
    let proxies = yaml
        .get("proxies")
        .and_then(serde_yaml::Value::as_sequence)
        .ok_or_else(|| anyhow::anyhow!("no 'proxies' array found in Clash YAML"))?;
    parse_clash_proxies(proxies, subscription_id)
}

#[test]
fn subscription_userinfo_parses_known_unsigned_fields() {
    let cases = [
        ("", [None, None, None, None]),
        (
            "upload=422986054; download=5198408536; total=214748364800; expire=1796712849",
            [
                Some(422986054),
                Some(5198408536),
                Some(214748364800),
                Some(1796712849),
            ],
        ),
        (
            " upload = 0 ; download = 0 ; total = 0 ; expire = 0 ",
            [Some(0), Some(0), None, None],
        ),
        (
            "download=12; ignored=34; upload=7",
            [Some(7), Some(12), None, None],
        ),
        (
            "upload=-1; download=no; total=18446744073709551616; expire=1=2; broken",
            [None, None, None, None],
        ),
        (
            "upload=18446744073709551615; total=1; expire=2",
            [Some(u64::MAX), None, Some(1), Some(2)],
        ),
    ];
    for (header, expected) in cases {
        let parsed = parse_subscription_userinfo(header);
        assert_eq!(
            [parsed.upload, parsed.download, parsed.total, parsed.expire],
            expected,
            "{header}"
        );
    }
}

#[test]
fn private_literal_hosts_are_recognized_by_address_not_name() {
    for url in [
        "http://127.0.0.1/sub",
        "http://10.203.0.1:8080/sub",
        "http://192.168.1.1/sub",
        "http://169.254.1.1/sub",
        "http://[::1]/sub",
        "http://[fd00::1]/sub",
        "http://[fe80::1]/sub",
        "http://[::ffff:127.0.0.1]/sub",
        "http://0.0.0.0/sub",
        "http://[::]/sub",
    ] {
        let url = reqwest::Url::parse(url).unwrap();
        assert!(has_private_literal_host(&url), "{url} should be private");
    }
    for url in [
        "https://example.com/sub",
        "http://93.184.216.34/sub",
        "http://[2001:db8::1]/sub",
        // Resolution is out of scope: only a stated literal is refused.
        "http://internal.example/sub",
    ] {
        let url = reqwest::Url::parse(url).unwrap();
        assert!(
            !has_private_literal_host(&url),
            "{url} should not be private"
        );
    }
}

#[test]
fn test_parse_base64_subscription() {
    let uris = [
        "socks5://192.168.1.1:1080#Node1",
        "socks5://10.0.0.1:2080#Node2",
    ];
    let joined = uris.join("\n");
    let encoded = base64::engine::general_purpose::STANDARD.encode(joined.as_bytes());
    let nodes = parse_subscription_content(
        &Subscription {
            sub_type: SubscriptionType::Simple,
            ..Default::default()
        },
        &encoded,
    )
    .unwrap();
    assert_eq!(nodes.len(), 2);
    assert_eq!(nodes[0].name, "Node1");
    assert_eq!(nodes[1].name, "Node2");
    assert_eq!(nodes[0].protocol(), NodeProtocol::Socks5);
    assert_eq!(nodes[1].protocol(), NodeProtocol::Socks5);
}

#[test]
fn base64_subscription_chains_become_detour_hops() {
    // dae: left = landing, right = relay. The second chain reuses the first
    // relay; the plain node named like a generated relay name keeps its own.
    let lines = [
        "trojan://pw@land.example:443?sni=land.example#Land -> socks5://10.0.0.1:1080",
        "ss://YWVzLTEyOC1nY206cHc@10.0.0.9:8388#Land2 -> ss://YWVzLTEyOC1nY206cHc@10.0.0.2:8388 -> socks5://10.0.0.1:1080",
        "socks5://192.0.2.1:1080#Plain",
        "tuic://00000000-0000-0000-0000-000000000001:p@t.example:443#Bad -> socks5://10.0.0.1:1080",
    ];
    let encoded = base64::engine::general_purpose::STANDARD.encode(lines.join("\n"));
    let nodes = parse_subscription_content(
        &Subscription {
            sub_type: SubscriptionType::Simple,
            ..Default::default()
        },
        &encoded,
    )
    .unwrap();
    let by_name = |name: &str| nodes.iter().find(|n| n.name == name).unwrap();
    let hosts = |start: &str| {
        let mut out = Vec::new();
        let mut current = Some(by_name(start));
        while let Some(node) = current {
            out.push(node.host.clone());
            current = node.detour.as_deref().map(by_name);
        }
        out
    };
    assert_eq!(hosts("Land"), ["land.example", "10.0.0.1"]);
    assert_eq!(hosts("Land2"), ["10.0.0.9", "10.0.0.2", "10.0.0.1"]);
    assert_eq!(
        by_name("Land").detour,
        nodes.iter().find(|n| n.host == "10.0.0.2").unwrap().detour
    );
    assert!(by_name("Plain").detour.is_none());
    assert!(
        nodes
            .iter()
            .all(|n| n.name != "Bad" && n.host != "t.example"),
        "QUIC landing chain dropped"
    );
    let mut names: Vec<_> = nodes.iter().map(|n| &n.name).collect();
    names.sort();
    names.dedup();
    assert_eq!(names.len(), nodes.len());
    assert_eq!(nodes.len(), 5);
}

#[test]
fn uri_subscription_with_empty_vmess_remark_remains_usable() {
    let payload = r#"{"ps":"","add":"vmess.example.com","port":443,"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}"#;
    let uri = format!(
        "vmess://{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload)
    );
    let nodes = parse_subscription_content(
        &Subscription {
            sub_type: SubscriptionType::Simple,
            ..Default::default()
        },
        &uri,
    )
    .unwrap();
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0].protocol(), NodeProtocol::VMess);
    assert_eq!(nodes[0].name, "vmess-vmess.example.com");
}

#[test]
fn test_parse_base64_without_padding() {
    let uris = "socks5://10.0.0.1:1080#NoPad";
    let encoded = base64::engine::general_purpose::STANDARD.encode(uris.as_bytes());
    let no_pad = encoded.trim_end_matches('=');
    let nodes = parse_subscription_content(
        &Subscription {
            sub_type: SubscriptionType::Simple,
            ..Default::default()
        },
        no_pad,
    )
    .unwrap();
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0].name, "NoPad");
}

#[test]
fn test_parse_base64_skips_unsupported() {
    let uris = ["socks5://192.168.1.1:1080#Valid", "unknown://host:1234"];
    let joined = uris.join("\n");
    let encoded = base64::engine::general_purpose::STANDARD.encode(joined.as_bytes());
    let nodes = parse_subscription_content(
        &Subscription {
            sub_type: SubscriptionType::Simple,
            ..Default::default()
        },
        &encoded,
    )
    .unwrap();
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0].name, "Valid");
}

#[test]
fn test_parse_base64_empty_result() {
    let uris = "unknown://host:1234\nanother-unsupported://x:1";
    let encoded = base64::engine::general_purpose::STANDARD.encode(uris.as_bytes());
    let result = parse_subscription_content(
        &Subscription {
            sub_type: SubscriptionType::Simple,
            ..Default::default()
        },
        &encoded,
    );
    assert!(result.is_err());
}

#[test]
fn subscription_normalizes_bom_and_urlsafe_wrapped_base64() {
    let sub = Subscription {
        sub_type: SubscriptionType::Simple,
        ..Default::default()
    };
    let uri = "socks5://127.0.0.1:1080#wrapped";
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(uri);
    let wrapped = encoded
        .as_bytes()
        .chunks(7)
        .map(std::str::from_utf8)
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
        .join(" \n");
    let nodes = parse_subscription_content(&sub, &format!("\u{feff}{wrapped}")).unwrap();
    assert_eq!(nodes[0].name, "wrapped");
}

#[test]
fn simple_and_custom_detect_structured_bodies_without_fallback() {
    let yaml =
        "proxies:\n  - type: socks5\n    server: 127.0.0.1\n    port: 1080\n    name: yaml\n";
    let simple = Subscription {
        sub_type: SubscriptionType::Simple,
        ..Default::default()
    };
    assert_eq!(
        parse_subscription_content(&simple, yaml).unwrap()[0].name,
        "yaml"
    );

    let custom = Subscription {
        sub_type: SubscriptionType::Custom,
        ..Default::default()
    };
    let json =
        r#"{"outbounds":[{"type":"socks","tag":"json","server":"127.0.0.1","server_port":1081}]}"#;
    assert_eq!(
        parse_subscription_content(&custom, json).unwrap()[0].name,
        "json"
    );
    assert!(parse_subscription_content(&simple, r#"{"unknown":"wrapper"}"#).is_err());
    assert!(
        parse_subscription_content(
            &simple,
            "{\"outbounds\":[\ntrojan://secret@example.com:443#not-json",
        )
        .is_err()
    );
}

#[test]
fn explicit_sip008_uses_server_schema_not_uri_parser() {
    let sub = Subscription {
        sub_type: SubscriptionType::Sip008,
        ..Default::default()
    };
    let body = r#"{"servers":[{"server":"ss.example","server_port":8388,"method":"aes-128-gcm","password":"secret","remarks":"sip"}]}"#;
    let nodes = parse_subscription_content(&sub, body).unwrap();
    assert_eq!(nodes[0].name, "sip");
    assert_eq!(nodes[0].protocol(), NodeProtocol::SS);
}

#[test]
fn json_subscription_names_accept_utf16_surrogate_pairs() {
    for (sub_type, body) in [
        (
            SubscriptionType::Simple,
            r#"{"outbounds":[{"type":"socks","tag":"node-\ud83d\ude00","server":"127.0.0.1","server_port":1080}]}"#,
        ),
        (
            SubscriptionType::Clash,
            r#"{"proxies":[{"type":"socks5","name":"node-\ud83d\ude00","server":"127.0.0.1","port":1080}]}"#,
        ),
        (
            SubscriptionType::Sip008,
            r#"{"servers":[{"remarks":"node-\ud83d\ude00","server":"127.0.0.1","server_port":8388,"method":"aes-128-gcm","password":"fixture"}]}"#,
        ),
    ] {
        let sub = Subscription {
            sub_type,
            ..Default::default()
        };
        let nodes = parse_subscription_content(&sub, body).unwrap();
        assert_eq!(nodes[0].name, "node-\u{1f600}");
    }
}

#[test]
fn test_parse_subscription_keeps_unique_nodes_with_duplicates() {
    let sub = Subscription {
        sub_type: SubscriptionType::Simple,
        ..Default::default()
    };
    let content = concat!(
        "socks5://127.0.0.1:1080#same\n",
        "socks5://127.0.0.1:1080#same-again"
    );
    let nodes = parse_subscription_content(&sub, content).unwrap();
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0].name, "same");
}

#[test]
fn test_parse_subscription_keeps_valid_sibling_after_intrinsic_rejection() {
    let invalid = "vless://00000000-0000-4000-8000-000000000001@h:443?encryption=e&type=ws&sni=ws&flow=xudp#a";
    let valid = "vless://00000000-0000-4000-8000-000000000001@h:443?type=ws&sni=u&path=ws&packetEncoding=xudp#b";
    let sub = Subscription {
        sub_type: SubscriptionType::Simple,
        ..Default::default()
    };
    let nodes = parse_subscription_content(&sub, &format!("{invalid}\n{valid}")).unwrap();
    assert_eq!(
        nodes
            .iter()
            .map(|node| node.name.as_str())
            .collect::<Vec<_>>(),
        ["b"]
    );
    let error = Node::from_share_link(invalid).unwrap_err();
    assert!(matches!(error, honk_config::ConfigError::Validation(_)));
}

#[test]
fn test_parse_subscription_skips_proxy_plugins() {
    let clash = Subscription {
        sub_type: SubscriptionType::Clash,
        ..Default::default()
    };
    let clash_nodes = parse_subscription_content(
        &clash,
        r#"proxies:
  - name: obfs
    type: ss
    server: ss.example
    port: 8388
    cipher: aes-128-gcm
    password: secret
    plugin: obfs
    plugin-opts:
      mode: http
      host: mask.example
  - name: plain
    type: socks5
    server: 127.0.0.1
    port: 1080
"#,
    )
    .unwrap();
    assert_eq!(clash_nodes.len(), 1);
    assert_eq!(clash_nodes[0].name, "plain");

    let simple = Subscription {
        sub_type: SubscriptionType::Simple,
        ..Default::default()
    };
    let simple_nodes = parse_subscription_content(
        &simple,
        concat!(
            "ss://YWVzLTI1Ni1nY206cGFzcw@1.2.3.4:8388?plugin=obfs-local%3Bobfs%3Dhttp#obfs\n",
            "socks5://127.0.0.1:1080#plain"
        ),
    )
    .unwrap();
    assert_eq!(simple_nodes.len(), 1);
    assert_eq!(simple_nodes[0].name, "plain");
}

#[tokio::test]
async fn subscription_redirects_retain_same_origin_auth_and_strip_it_permanently() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let origin = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let other = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = origin.local_addr().unwrap();
    let other_address = other.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let hops = [
            (
                &origin,
                "/start",
                Some(format!("http://{address}/same")),
                true,
            ),
            (
                &origin,
                "/same",
                Some(format!("http://{address}/again")),
                true,
            ),
            (
                &origin,
                "/again",
                Some(format!("http://{other_address}/cross")),
                true,
            ),
            (&other, "/cross", Some("/still-cross".into()), false),
            (
                &other,
                "/still-cross",
                Some(format!("http://us%40er:p%3Ass@{address}/back")),
                false,
            ),
            (&origin, "/back", None, false),
        ];
        for (listener, path, location, authenticated) in hops {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut chunk = [0_u8; 256];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let size = stream.read(&mut chunk).await.unwrap();
                assert!(size > 0);
                request.extend_from_slice(&chunk[..size]);
            }
            let request = String::from_utf8(request).unwrap();
            assert!(request.starts_with(&format!("GET {path} HTTP/1.1\r\n")));
            let authorization = request.lines().find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("authorization")
                    .then(|| value.trim())
            });
            let expected = format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode("us@er:p:ss")
            );
            assert_eq!(
                authorization,
                authenticated.then_some(expected.as_str()),
                "{path}"
            );
            assert!(!request.contains("us%40er") && !request.contains("p%3Ass"));
            assert!(!request.contains("us@er") && !request.contains("p:ss"));
            let response = if let Some(location) = location {
                format!(
                    "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
            } else {
                let body = "socks5://127.0.0.1:1080#authenticated";
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
            };
            stream.write_all(response.as_bytes()).await.unwrap();
        }
    });
    let sub = Subscription {
        url: format!("http://us%40er:p%3Ass@{address}/start"),
        download_detour: "direct".into(),
        ..Default::default()
    };
    let nodes = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        SubscriptionManager::new().unwrap().fetch(&sub),
    )
    .await
    .unwrap()
    .unwrap();
    server.await.unwrap();
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0].name, "authenticated");
}

#[tokio::test]
async fn configured_subscription_user_agent_reaches_fetch_request() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut chunk = [0_u8; 256];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let size = stream.read(&mut chunk).await.unwrap();
            assert!(size > 0);
            request.extend_from_slice(&chunk[..size]);
        }
        assert!(String::from_utf8_lossy(&request).lines().any(|line| {
            line.trim_end_matches('\r')
                .eq_ignore_ascii_case("user-agent: provider/2.0")
        }));
        let body = "socks5://127.0.0.1:1080#node";
        stream
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
    });
    let config = honk_config::parser::parse_dae_config(&format!(
            "subscription {{\nprovider: {{\nurl: 'http://{address}/sub'\nua: 'provider/2.0'\ninterval: 0\ndownload_detour: direct\n}}\n}}"
        ))
        .unwrap();

    let nodes = SubscriptionManager::new()
        .unwrap()
        .fetch(&config.subscriptions[0])
        .await
        .unwrap();
    server.await.unwrap();
    assert_eq!(nodes.len(), 1);
}

#[tokio::test]
async fn subscription_store_loads_pre_default_user_agent_key() {
    fn pre_default_filename(sub: &Subscription) -> String {
        fn add_part(hasher: &mut Sha256, value: &[u8]) {
            hasher.update((value.len() as u64).to_be_bytes());
            hasher.update(value);
        }

        let mut hasher = Sha256::new();
        add_part(&mut hasher, sub.url.as_bytes());
        add_part(&mut hasher, b"");
        for header in &sub.headers {
            add_part(&mut hasher, header.key.as_bytes());
            add_part(&mut hasher, header.value.as_bytes());
        }
        use base64::Engine as _;
        format!(
            "{}.sub",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize())
        )
    }

    let temp = tempfile::tempdir().unwrap();
    let store = SubscriptionStore::in_dir(temp.path());
    let sub = Subscription {
        name: "provider".into(),
        url: "https://example.test/subscription".into(),
        ..Subscription::default()
    };
    let content = "socks5://127.0.0.1:1080#stored";
    assert_eq!(SubscriptionStore::key(&sub), pre_default_filename(&sub));
    store.store_content(&sub, content.into()).await.unwrap();

    let restored = store.load_nodes(&sub).await.unwrap().unwrap();
    assert_eq!(restored[0].name, "stored");

    let mut explicit_empty = sub.clone();
    explicit_empty.user_agent = Some(String::new());
    assert!(store.load_nodes(&explicit_empty).await.unwrap().is_some());
}

#[tokio::test]
async fn subscription_cache_identity_isolates_explicit_default_user_agent() {
    let temp = tempfile::tempdir().unwrap();
    let store = SubscriptionStore::in_dir(temp.path());
    let default_sub = Subscription {
        name: "provider".into(),
        url: "https://example.test/subscription".into(),
        ..Subscription::default()
    };
    let mut explicit_default = default_sub.clone();
    explicit_default.user_agent = Some(DEFAULT_SUBSCRIPTION_USER_AGENT.into());

    let mut with_header = default_sub.clone();
    with_header
        .headers
        .push(honk_config::subscription::SubscriptionHeader {
            key: "X-Test".into(),
            value: "1".into(),
        });

    store
        .store_content(&with_header, "socks5://127.0.0.1:1080#header".into())
        .await
        .unwrap();
    assert!(store.load_nodes(&explicit_default).await.unwrap().is_none());
    store
        .store_content(&explicit_default, "socks5://127.0.0.1:1080#explicit".into())
        .await
        .unwrap();
    assert!(store.load_nodes(&default_sub).await.unwrap().is_none());
    assert_eq!(
        store.load_nodes(&with_header).await.unwrap().unwrap()[0].name,
        "header"
    );
    assert_eq!(
        store.load_nodes(&explicit_default).await.unwrap().unwrap()[0].name,
        "explicit"
    );
}

#[tokio::test]
async fn fetch_error_chain_redacts_subscription_url() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    const SENTINEL: &str = "subscription-secret-sentinel";
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::with_capacity(1024);
        let mut chunk = [0_u8; 256];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let size = stream.read(&mut chunk).await.unwrap();
            assert!(size > 0, "HTTP request ended before its headers");
            request.extend_from_slice(&chunk[..size]);
            assert!(request.len() <= 16 * 1024, "HTTP request headers too large");
        }
        let request = String::from_utf8_lossy(&request);
        let expected = format!("user-agent: {DEFAULT_SUBSCRIPTION_USER_AGENT}");
        assert!(
            request
                .lines()
                .any(|line| { line.trim_end_matches('\r').eq_ignore_ascii_case(&expected) })
        );
        stream
            .write_all(
                b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
    });
    let subscription = Subscription {
        name: "provider".into(),
        url: format!("http://{address}/{SENTINEL}?token={SENTINEL}"),
        download_detour: "direct".into(),
        ..Subscription::default()
    };

    let error = SubscriptionManager::new()
        .unwrap()
        .fetch(&subscription)
        .await
        .unwrap_err();
    server.await.unwrap();
    let chain = error
        .chain()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(!chain.contains(SENTINEL));
    assert!(!format!("{error:?}").contains(SENTINEL));
}

#[tokio::test]
async fn subscription_store_recovers_last_valid_fetch() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let temp = tempfile::tempdir().unwrap();
    let store = SubscriptionStore::in_dir(temp.path());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let valid = "socks5://127.0.0.1:1080#stored";
    let server = tokio::spawn(async move {
        for body in [valid, "not a subscription"] {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).await.unwrap();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        }
    });

    let mut sub = Subscription {
        name: "provider".into(),
        url: format!("http://{address}/subscription"),
        download_detour: "direct".into(),
        ..Subscription::default()
    };
    let key = SubscriptionStore::key(&sub);
    let original_id = sub.id;
    let manager = SubscriptionManager::new().unwrap();
    let fetched = manager.fetch_and_store(&sub, Some(&store)).await.unwrap();
    assert_eq!(fetched.len(), 1);
    assert_eq!(fetched[0].subscription_id, Some(original_id));
    assert!(manager.fetch_and_store(&sub, Some(&store)).await.is_err());
    server.await.unwrap();

    sub.id = uuid::Uuid::new_v4();
    sub.name = "renamed-provider".into();
    assert_eq!(SubscriptionStore::key(&sub), key);
    let restored = store.load_nodes(&sub).await.unwrap().unwrap();
    assert_eq!(restored.len(), 1);
    assert_eq!(restored[0].name, "stored");
    assert_eq!(restored[0].subscription_id, Some(sub.id));
}

const C19_PARTIAL: &str = include_str!("../../tests/fixtures/c19-partial-body.txt");
const C19_INVALID: &str = include_str!("../../tests/fixtures/c19-invalid-body.txt");

#[tokio::test]
async fn c19_store_acceptance_is_independent_of_runtime_publication() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let sub = Subscription {
        url: format!("http://{}/sub", listener.local_addr().unwrap()),
        download_detour: "direct".into(),
        ..Subscription::default()
    };
    let server = tokio::spawn(async move {
        for body in [C19_PARTIAL, C19_INVALID, C19_PARTIAL] {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 2048];
            let mut received = 0;
            while !request[..received]
                .windows(4)
                .any(|window| window == b"\r\n\r\n")
            {
                assert!(received < request.len(), "HTTP request headers too large");
                let size = stream.read(&mut request[received..]).await.unwrap();
                assert!(size > 0, "HTTP request ended before its headers");
                received += size;
            }
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
        }
    });
    let temp = tempfile::tempdir().unwrap();
    let store = SubscriptionStore::in_dir(temp.path());
    let manager = SubscriptionManager::new().unwrap();
    let nodes = manager.fetch_and_store(&sub, Some(&store)).await.unwrap();
    assert_eq!(store.body(&sub).as_deref(), Some(C19_PARTIAL));
    assert!(
        honk_outbound::runtime::OutboundRuntimeRegistry::build(&[
            nodes[0].clone(),
            nodes[0].clone()
        ])
        .is_err()
    );
    assert_eq!(
        store.load_nodes(&sub).await.unwrap().unwrap()[0].id,
        nodes[0].id
    );
    assert!(manager.fetch_and_store(&sub, Some(&store)).await.is_err());
    assert_eq!(store.body(&sub).as_deref(), Some(C19_PARTIAL));
    store.store_content(&sub, C19_INVALID.into()).await.unwrap();
    assert!(store.load_nodes(&sub).await.is_err());
    store.refuse_writes();
    let mut diagnostics = Vec::new();
    assert_eq!(
        manager
            .fetch_and_store_with_diagnostics(&sub, Some(&store), &mut diagnostics)
            .await
            .unwrap()[0]
            .id,
        nodes[0].id
    );
    assert!(
        diagnostics
            .iter()
            .any(|d| d.code == "subscription-store-write-failed")
    );
    server.await.unwrap();
}

#[tokio::test]
async fn c19_invalid_http_encoding_preserves_saved_body() {
    use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _};

    let body = include_bytes!("../../tests/fixtures/c19-invalid-utf8-body.txt");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let sub = Subscription {
        url: format!("http://{}/sub", listener.local_addr().unwrap()),
        download_detour: "direct".into(),
        ..Subscription::default()
    };
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = tokio::io::BufReader::new(stream);
        let mut line = String::new();
        while stream.read_line(&mut line).await.unwrap() != 0 {
            if line == "\r\n" {
                break;
            }
            line.clear();
        }
        stream
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        stream.write_all(body).await.unwrap();
    });
    let temp = tempfile::tempdir().unwrap();
    let store = SubscriptionStore::in_dir(temp.path());
    store.store_content(&sub, C19_PARTIAL.into()).await.unwrap();
    let manager = SubscriptionManager::new().unwrap();
    let mut diagnostics = Vec::new();
    let result = manager
        .fetch_and_store_with_diagnostics(&sub, Some(&store), &mut diagnostics)
        .await;
    server.await.unwrap();
    assert!(
        result.is_err(),
        "invalid HTTP encoding must reject the body"
    );
    assert_eq!(store.body(&sub).as_deref(), Some(C19_PARTIAL));
    assert_eq!(diagnostics.len(), 1);
    assert_eq!(diagnostics[0].code, "invalid-subscription-encoding");
    assert!(diagnostics[0].terminal);
    let error = result.unwrap_err();
    let error = error.downcast_ref::<DetailedConfigError>().unwrap();
    assert_eq!(error.diagnostic.as_ref(), &diagnostics[0]);
}

/// Follow a node's detour chain by name, as validation resolves it: node
/// identities in dial-order reverse (landing first), ending with the group
/// name when the chain leaves for a group.
fn resolved_chain(nodes: &[Node], start: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = nodes.iter().find(|node| node.name == start);
    while let Some(node) = current {
        out.push(format!("{}:{}", node.protocol().as_str(), node.id));
        current = match node.detour.as_deref() {
            Some(next) => {
                let found = nodes.iter().find(|node| node.name == next);
                if found.is_none() {
                    out.push(format!("group:{next}"));
                }
                found
            }
            None => None,
        };
    }
    out
}

fn parse_as(sub_type: SubscriptionType, content: &str) -> Vec<Node> {
    parse_subscription_content(
        &Subscription {
            sub_type,
            ..Default::default()
        },
        content,
    )
    .unwrap()
}

#[test]
fn chain_syntaxes_resolve_to_the_same_chain() {
    let land = "trojan://pw@land.example:443?sni=land.example";
    let mid = "ss://YWVzLTEyOC1nY206cHc@10.0.0.2:8388";
    let front = "socks5://10.0.0.1:1080";
    let b64 = |text: String| base64::engine::general_purpose::STANDARD.encode(text);
    let dae = parse_as(
        SubscriptionType::Simple,
        &b64(format!("{land}#Land -> {mid} -> {front}")),
    );
    let links = parse_as(
        SubscriptionType::Simple,
        &b64(format!(
            "{land}&dialer-proxy=Mid#Land\n{mid}?detour=Front#Mid\n{front}#Front"
        )),
    );
    let clash = parse_as(
        SubscriptionType::Clash,
        r#"
proxies:
  - {name: Land, type: trojan, server: land.example, port: 443, password: pw, sni: land.example, dialer-proxy: Mid}
  - {name: Mid, type: ss, server: 10.0.0.2, port: 8388, cipher: aes-128-gcm, password: pw, dialer-proxy: Front}
  - {name: Front, type: socks5, server: 10.0.0.1, port: 1080}
"#,
    );
    let sing_box = parse_as(
        SubscriptionType::Simple,
        r#"{"outbounds":[
  {"type":"trojan","tag":"Land","server":"land.example","server_port":443,"password":"pw","tls":{"enabled":true,"server_name":"land.example"},"detour":"Mid"},
  {"type":"shadowsocks","tag":"Mid","server":"10.0.0.2","server_port":8388,"method":"aes-128-gcm","password":"pw","detour":"Front"},
  {"type":"socks","tag":"Front","server":"10.0.0.1","server_port":1080}
]}"#,
    );
    let expected = resolved_chain(&dae, "Land");
    assert_eq!(expected.len(), 3, "{expected:?}");
    for (label, nodes) in [
        ("links", &links),
        ("clash", &clash),
        ("sing-box", &sing_box),
    ] {
        assert_eq!(resolved_chain(nodes, "Land"), expected, "{label}");
    }
}

#[test]
fn chain_syntaxes_agree_on_a_group_target() {
    let land = "socks5://192.0.2.9:1080";
    let b64 = |text: String| base64::engine::general_purpose::STANDARD.encode(text);
    let dae = parse_as(
        SubscriptionType::Simple,
        &b64(format!("{land}#Land -> relays")),
    );
    let link = parse_as(
        SubscriptionType::Simple,
        &b64(format!("{land}?dialer-proxy=relays#Land")),
    );
    let clash = parse_as(
        SubscriptionType::Clash,
        "proxies:\n  - {name: Land, type: socks5, server: 192.0.2.9, port: 1080, dialer-proxy: relays}\n",
    );
    let sing_box = parse_as(
        SubscriptionType::Simple,
        r#"{"outbounds":[{"type":"socks","tag":"Land","server":"192.0.2.9","server_port":1080,"detour":"relays"},{"type":"selector","tag":"relays","outbounds":["x"]}]}"#,
    );
    let expected = resolved_chain(&dae, "Land");
    assert_eq!(expected.last().map(String::as_str), Some("group:relays"));
    for (label, nodes) in [("link", &link), ("clash", &clash), ("sing-box", &sing_box)] {
        assert_eq!(resolved_chain(nodes, "Land"), expected, "{label}");
    }
}

#[test]
fn imported_conflicting_detours_are_rejected_identical_ones_kept() {
    let clash = |extra: &str| {
        parse_as(
            SubscriptionType::Clash,
            &format!(
                "proxies:\n  - {{name: Land, type: socks5, server: 192.0.2.9, port: 1080, dialer-proxy: a{extra}}}\n  - {{name: Ok, type: socks5, server: 192.0.2.8, port: 1080}}\n"
            ),
        )
    };
    let same = clash(", dialer_proxy: a");
    assert_eq!(
        same.iter()
            .find(|n| n.name == "Land")
            .unwrap()
            .detour
            .as_deref(),
        Some("a")
    );
    let conflict = clash(", dialer_proxy: b");
    assert!(
        conflict.iter().all(|n| n.name != "Land"),
        "conflicting node dropped"
    );
    assert!(conflict.iter().any(|n| n.name == "Ok"));
    let quic = parse_as(
        SubscriptionType::Clash,
        "proxies:\n  - {name: Q, type: hysteria2, server: q.example, port: 443, password: pw, dialer-proxy: a}\n  - {name: Ok, type: socks5, server: 192.0.2.8, port: 1080}\n",
    );
    assert!(quic.iter().all(|n| n.name != "Q"));
}
