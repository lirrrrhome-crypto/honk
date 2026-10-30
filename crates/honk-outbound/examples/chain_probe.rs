//! Dial an HTTP target through a configured node (optionally chained with
//! `dialer-proxy`) using the real outbound registry, and print the response.
//!
//! Usage: chain_probe <nodes.dae> <node-name> <host:port> [path]
//!        chain_probe <nodes.dae> <node-name> <host:port> --listen <ip:port>
//!        (forward every accepted local TCP connection to host:port through the node)
//!        chain_probe <nodes.dae> <node-name> <ip:port> --healthcheck <url>
//!        (run the group health-check HTTP probe path against the node)
//! `nodes.dae` holds a `node { ... }` (and optional `group { ... }`) block.
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use honk_outbound::ProxyRegistry;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();
    let args: Vec<String> = std::env::args().collect();
    anyhow::ensure!(
        args.len() >= 4,
        "usage: chain_probe <nodes.dae> <node> <host:port> [path]"
    );
    let text = std::fs::read_to_string(&args[1])?;
    let config =
        honk_config::parser::parse_dae_config_with_detailed_diagnostics(&text, &mut Vec::new())
            .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    config.validate_detailed().map_err(|e| {
        anyhow::anyhow!("validation: {} {}", e.diagnostic.code, e.diagnostic.setting)
    })?;
    let node = config
        .nodes
        .iter()
        .find(|n| n.name == args[2])
        .ok_or_else(|| anyhow::anyhow!("no node {}", args[2]))?;
    println!(
        "node {} protocol={} detour={:?}",
        node.name,
        node.protocol().as_str(),
        node.detour
    );
    let (host, port) = args[3]
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("host:port"))?;
    let port: u16 = port.parse()?;
    let (target, domain) = match host.parse::<IpAddr>() {
        Ok(ip) => (SocketAddr::new(ip, port), None),
        Err(_) => (
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port),
            Some(host.to_string()),
        ),
    };
    let generation = Arc::new(honk_outbound::runtime::OutboundRuntimeRegistry::build(
        &config.nodes,
    )?);
    // As in honk-core: handler-level dials resolve node-named fronts
    // against the live generation.
    let cell = Arc::new(parking_lot::RwLock::new(Arc::clone(&generation)));
    honk_outbound::proxy::detour::install_runtime_registry(&cell);
    let registry = Arc::new(ProxyRegistry::default_resolver()?);
    if args.get(4).map(String::as_str) == Some("--healthcheck") {
        let url = args
            .get(5)
            .ok_or_else(|| anyhow::anyhow!("--healthcheck <url>"))?;
        let runtime = generation
            .get(&node.id)
            .ok_or_else(|| anyhow::anyhow!("node not in generation"))?;
        let entry = registry
            .find(node.protocol())
            .ok_or_else(|| anyhow::anyhow!("no handler"))?;
        let request = honk_outbound::urltest::health_http_probe_request(url, "GET")?;
        let result = honk_outbound::urltest::measure_http_probe(
            &runtime,
            entry.tcp.as_ref(),
            &request,
            target,
            domain.as_deref(),
            Duration::from_secs(5),
            Duration::from_secs(5),
            None,
        )
        .await;
        println!("healthcheck: {result:?}");
        return Ok(());
    }
    if args.get(4).map(String::as_str) == Some("--listen") {
        let listen = args
            .get(5)
            .ok_or_else(|| anyhow::anyhow!("--listen <ip:port>"))?;
        let listener = tokio::net::TcpListener::bind(listen).await?;
        println!("forwarding {listen} -> {} via {}", args[3], node.name);
        loop {
            let (mut client, peer) = listener.accept().await?;
            let (registry, generation, domain, id) = (
                Arc::clone(&registry),
                Arc::clone(&generation),
                domain.clone(),
                node.id,
            );
            tokio::spawn(async move {
                match registry
                    .dial_runtime(
                        generation,
                        id,
                        target,
                        domain.as_deref(),
                        Duration::from_secs(10),
                    )
                    .await
                {
                    Ok(mut upstream) => {
                        let r =
                            tokio::io::copy_bidirectional(&mut client, &mut upstream.stream).await;
                        println!("{peer}: closed {r:?}");
                    }
                    Err(e) => println!("{peer}: dial failed: {e:#}"),
                }
            });
        }
    }
    let path = args.get(4).map(String::as_str).unwrap_or("/");
    let mut stream = registry
        .dial_runtime(
            generation,
            node.id,
            target,
            domain.as_deref(),
            Duration::from_secs(10),
        )
        .await?;
    stream
        .stream
        .write_all(format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: honk-chain-probe\r\nConnection: close\r\n\r\n").as_bytes())
        .await?;
    let mut body = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(15),
        stream.stream.read_to_end(&mut body),
    )
    .await??;
    let text = String::from_utf8_lossy(&body);
    println!(
        "--- response ({} bytes) ---\n{}",
        body.len(),
        text.chars().take(600).collect::<String>()
    );
    Ok(())
}
