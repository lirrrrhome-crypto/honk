//! Chain interop against REAL sing-box inbounds: every member after the first
//! performs its handshake on the stream of the member before it, so each
//! front x landing pair below exercises one protocol's client over another
//! protocol's tunnel. Needs only `sing-box` (`HONK_SING_BOX_BIN` or PATH);
//! every listener and target is loopback.
//!
//! `cargo test -p honk-outbound --features rprx --test chain_interop -- --ignored --nocapture`

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use honk_config::node::{
    ChainConfig, ChainOut, Node, OutboundConfig, ShadowsocksConfig, Socks5Config, TlsOptions,
    TrojanConfig, VmessConfig,
};
use honk_outbound::proxy::ProxyRegistry;
use honk_outbound::proxy::chain::ChainResolver;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const SETUP_TIMEOUT: Duration = Duration::from_secs(5);
const UUID: &str = "b5bc10a6-5c72-4fd0-9f62-15c2b9f8a7d3";

struct Proto {
    name: &'static str,
    inbound: String,
    node: Node,
}

fn free_port() -> u16 {
    std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn tls_options() -> TlsOptions {
    TlsOptions {
        enabled: true,
        sni: Some("localhost".into()),
        skip_cert_verify: true,
        ..Default::default()
    }
}

fn node(name: &str, port: u16, outbound: OutboundConfig) -> Node {
    let mut node = Node {
        name: name.into(),
        address: format!("127.0.0.1:{port}"),
        host: "127.0.0.1".into(),
        port,
        outbound,
        ..Default::default()
    };
    node.id = node.derive_id();
    node
}

fn protos(cert: &str, key: &str) -> Vec<Proto> {
    let tls = format!(
        r#""tls": {{ "enabled": true, "server_name": "localhost", "certificate_path": "{cert}", "key_path": "{key}" }}"#
    );
    let listen = |kind: &str, port: u16, rest: &str| {
        format!(
            r#"{{ "type": "{kind}", "tag": "in-{port}", "listen": "127.0.0.1", "listen_port": {port}, {rest} }}"#
        )
    };
    let mut out = Vec::new();

    let port = free_port();
    out.push(Proto {
        name: "socks5",
        inbound: listen("socks", port, r#""users": []"#),
        node: node(
            "socks5",
            port,
            OutboundConfig::Socks5(Socks5Config::default()),
        ),
    });

    for (name, method, password) in [
        ("ss-aes-128-gcm", "aes-128-gcm", "interop-password"),
        (
            "ss2022-blake3-aes-128-gcm",
            "2022-blake3-aes-128-gcm",
            "AAECAwQFBgcICQoLDA0ODw==",
        ),
    ] {
        let port = free_port();
        out.push(Proto {
            name,
            inbound: listen(
                "shadowsocks",
                port,
                &format!(r#""method": "{method}", "password": "{password}""#),
            ),
            node: node(
                name,
                port,
                OutboundConfig::Shadowsocks(ShadowsocksConfig {
                    password: Some(password.into()),
                    encryption: Some(method.into()),
                    ..Default::default()
                }),
            ),
        });
    }

    let port = free_port();
    out.push(Proto {
        name: "trojan-tls",
        inbound: listen(
            "trojan",
            port,
            &format!(r#""users": [{{ "name": "u", "password": "pw" }}], {tls}"#),
        ),
        node: node(
            "trojan-tls",
            port,
            OutboundConfig::Trojan(TrojanConfig {
                password: Some("pw".into()),
                tls: tls_options(),
                ..Default::default()
            }),
        ),
    });

    let port = free_port();
    out.push(Proto {
        name: "vmess",
        inbound: listen(
            "vmess",
            port,
            &format!(r#""users": [{{ "uuid": "{UUID}", "alterId": 0 }}]"#),
        ),
        node: node(
            "vmess",
            port,
            OutboundConfig::Vmess(VmessConfig {
                uuid: Some(UUID.into()),
                encryption: Some("auto".into()),
                ..Default::default()
            }),
        ),
    });

    let port = free_port();
    let mut vmess_ws = VmessConfig {
        uuid: Some(UUID.into()),
        encryption: Some("auto".into()),
        ..Default::default()
    };
    vmess_ws.transport.transport = "ws".into();
    vmess_ws.transport.ws_path = Some("/chain".into());
    out.push(Proto {
        name: "vmess-ws",
        inbound: listen(
            "vmess",
            port,
            &format!(
                r#""users": [{{ "uuid": "{UUID}", "alterId": 0 }}], "transport": {{ "type": "ws", "path": "/chain" }}"#
            ),
        ),
        node: node("vmess-ws", port, OutboundConfig::Vmess(vmess_ws)),
    });

    #[cfg(feature = "rprx")]
    for (name, flow) in [("vless-tls", ""), ("vless-tls-vision", "xtls-rprx-vision")] {
        let port = free_port();
        let link_flow = if flow.is_empty() {
            String::new()
        } else {
            format!("&flow={flow}")
        };
        let mut vless = Node::from_share_link(&format!(
            "vless://{UUID}@127.0.0.1:{port}?security=tls&sni=localhost{link_flow}#{name}"
        ))
        .unwrap();
        vless.tls_mut().unwrap().skip_cert_verify = true;
        vless.id = vless.derive_id();
        out.push(Proto {
            name,
            inbound: listen(
                "vless",
                port,
                &format!(r#""users": [{{ "uuid": "{UUID}", "flow": "{flow}" }}], {tls}"#),
            ),
            node: vless,
        });
    }
    out
}

struct SingBox {
    child: std::process::Child,
    log: std::path::PathBuf,
}

impl Drop for SingBox {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!(
                "sing-box log:\n{}",
                std::fs::read_to_string(&self.log).unwrap_or_default()
            );
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

async fn start_sing_box(directory: &std::path::Path, protos: &[Proto]) -> SingBox {
    let inbounds: Vec<&str> = protos.iter().map(|proto| proto.inbound.as_str()).collect();
    let config = directory.join("config.json");
    std::fs::write(
        &config,
        format!(
            r#"{{
  "log": {{ "level": "warn" }},
  "inbounds": [{}],
  "outbounds": [{{ "type": "direct", "tag": "direct" }}],
  "route": {{ "final": "direct" }}
}}"#,
            inbounds.join(",\n")
        ),
    )
    .unwrap();
    let log = directory.join("sing-box.log");
    let output = std::fs::File::create(&log).unwrap();
    let bin = std::env::var_os("HONK_SING_BOX_BIN").unwrap_or_else(|| "sing-box".into());
    let mut server = SingBox {
        child: std::process::Command::new(bin)
            .args(["run", "--disable-color", "-c"])
            .arg(&config)
            .stdout(output.try_clone().unwrap())
            .stderr(output)
            .spawn()
            .expect("start sing-box"),
        log,
    };
    for proto in protos {
        let mut ready = false;
        for _ in 0..200 {
            assert!(
                server.child.try_wait().unwrap().is_none(),
                "sing-box exited"
            );
            if tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, proto.node.port))
                .await
                .is_ok()
            {
                ready = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(ready, "sing-box did not bind {}", proto.name);
    }
    server
}

struct MapResolver(HashMap<String, Node>);

impl ChainResolver for MapResolver {
    fn resolve(&self, tag: &str) -> Option<Node> {
        self.0.get(tag).cloned()
    }
}

async fn echo_server() -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let (mut read, mut write) = stream.split();
                let _ = tokio::io::copy(&mut read, &mut write).await;
            });
        }
    });
    addr
}

/// One chain dial and a 64 KiB round trip, or why it failed.
async fn exchange(
    registry: &ProxyRegistry,
    members: &[&str],
    target: SocketAddr,
) -> Result<(), String> {
    let (out, hops) = members.split_last().unwrap();
    let chain = Node {
        name: members.join(" -> "),
        outbound: OutboundConfig::Chain(ChainConfig {
            hops: hops.iter().map(|hop| (*hop).to_owned()).collect(),
            out: ChainOut::Tag((*out).to_owned()),
            group_exit: None,
        }),
        ..Default::default()
    };
    let mut stream = tokio::time::timeout(
        SETUP_TIMEOUT,
        registry.dial(&chain, target, None, SETUP_TIMEOUT),
    )
    .await
    .map_err(|_| "dial timed out".to_owned())?
    .map_err(|error| format!("dial: {error:#}"))?;
    let payload: Vec<u8> = (0..64 * 1024u32).map(|i| (i * 7 + 3) as u8).collect();
    let exchange = async {
        stream.stream.write_all(&payload).await?;
        let mut reply = vec![0u8; payload.len()];
        stream.stream.read_exact(&mut reply).await?;
        Ok::<_, std::io::Error>(reply)
    };
    let reply = tokio::time::timeout(SETUP_TIMEOUT, exchange)
        .await
        .map_err(|_| "echo timed out".to_owned())?
        .map_err(|error| format!("echo: {error}"))?;
    if reply != payload {
        return Err("echo payload differs".to_owned());
    }
    Ok(())
}

#[tokio::test]
#[ignore = "needs sing-box (HONK_SING_BOX_BIN)"]
async fn sing_box_chain_front_by_landing_matrix() {
    let directory = std::env::temp_dir().join(format!(
        "honk-chain-interop-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&directory).unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = cert.self_signed(&key).unwrap();
    let (cert_path, key_path) = (directory.join("cert.pem"), directory.join("key.pem"));
    std::fs::write(&cert_path, cert.pem()).unwrap();
    std::fs::write(&key_path, key.serialize_pem()).unwrap();

    let protos = protos(
        &cert_path.display().to_string(),
        &key_path.display().to_string(),
    );
    let _server = start_sing_box(&directory, &protos).await;
    let registry = ProxyRegistry::default_resolver().unwrap();
    registry
        .chain()
        .unwrap()
        .install_resolver(Arc::new(MapResolver(
            protos
                .iter()
                .map(|proto| (proto.name.to_owned(), proto.node.clone()))
                .collect(),
        )));
    let target = echo_server().await;

    // A fixed front with every landing, every front with a fixed landing,
    // and one three-member chain mixing stream transports.
    let names: Vec<&str> = protos.iter().map(|proto| proto.name).collect();
    let mut cases: Vec<Vec<&str>> = Vec::new();
    for land in &names {
        if *land != "socks5" {
            cases.push(vec!["socks5", land]);
        }
    }
    for front in &names {
        if !["trojan-tls", "socks5"].contains(front) {
            cases.push(vec![front, "trojan-tls"]);
        }
    }
    cases.push(vec!["ss2022-blake3-aes-128-gcm", "vmess-ws", "trojan-tls"]);
    #[cfg(feature = "rprx")]
    cases.push(vec!["ss-aes-128-gcm", "vmess", "vless-tls-vision"]);

    let mut failures = Vec::new();
    for case in &cases {
        let result = exchange(&registry, case, target).await;
        println!(
            "{:<60} {}",
            case.join(" -> "),
            match &result {
                Ok(()) => "ok".to_owned(),
                Err(error) => error.clone(),
            }
        );
        if let Err(error) = result {
            failures.push(format!("{}: {error}", case.join(" -> ")));
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} chains failed:\n{}",
        failures.len(),
        cases.len(),
        failures.join("\n")
    );
}
