//! Chain dialing cost over loopback: one SOCKS5 node (`direct`), a two-member
//! SOCKS5 chain where the second member handshakes on the first member's
//! stream (`stream`, what honk ships), and the same chain with the second
//! member on a loopback bridge plus a copy task (`loopback`, the rejected
//! design). Fixtures run on their own runtime thread. Each iteration asserts
//! the echoed bytes, so a fast wrong path cannot pass as a result.
//!
//! `cargo bench -p honk-outbound --bench chain`

use std::collections::HashMap;
use std::hint::black_box;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use honk_config::node::{ChainConfig, ChainOut, Node, OutboundConfig, Socks5Config};
use honk_outbound::proxy::chain::ChainResolver;
use honk_outbound::proxy::socks5::Socks5Handler;
use honk_outbound::proxy::{ProxyRegistry, ProxyStream, TcpOutbound};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const BULK_BYTES: usize = 16 * 1024 * 1024;
const CHUNK: usize = 64 * 1024;
const TIMEOUT: Duration = Duration::from_secs(5);

struct Fixtures {
    front: Node,
    land: Node,
    echo: SocketAddr,
}

/// No-auth SOCKS5 CONNECT server (IPv4 targets).
async fn socks_server() -> u16 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut client, _) = listener.accept().await.unwrap();
            let _ = client.set_nodelay(true);
            tokio::spawn(async move {
                let mut head = [0u8; 2];
                client.read_exact(&mut head).await?;
                let mut methods = vec![0u8; head[1] as usize];
                client.read_exact(&mut methods).await?;
                client.write_all(&[5, 0]).await?;
                let mut request = [0u8; 10];
                client.read_exact(&mut request).await?;
                let target = SocketAddr::from((
                    Ipv4Addr::new(request[4], request[5], request[6], request[7]),
                    u16::from_be_bytes([request[8], request[9]]),
                ));
                let mut upstream = TcpStream::connect(target).await?;
                let _ = upstream.set_nodelay(true);
                client.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
                tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
                Ok::<_, std::io::Error>(())
            });
        }
    });
    port
}

async fn echo_server() -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let _ = stream.set_nodelay(true);
            tokio::spawn(async move {
                let (mut read, mut write) = stream.split();
                let _ = tokio::io::copy(&mut read, &mut write).await;
            });
        }
    });
    addr
}

fn socks(name: &str, port: u16) -> Node {
    let mut node = Node {
        name: name.to_owned(),
        address: format!("127.0.0.1:{port}"),
        host: "127.0.0.1".to_owned(),
        port,
        outbound: OutboundConfig::Socks5(Socks5Config::default()),
        ..Node::default()
    };
    node.id = node.derive_id();
    node
}

/// Fixtures on a runtime of their own, so they never share the measured
/// client's scheduler.
fn start_fixtures() -> Fixtures {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let front = socks("front", socks_server().await);
            let land = socks("land", socks_server().await);
            let echo = echo_server().await;
            tx.send(Fixtures { front, land, echo }).unwrap();
            std::future::pending::<()>().await;
        });
    });
    rx.recv().unwrap()
}

struct MapResolver(HashMap<String, Node>);

impl ChainResolver for MapResolver {
    fn resolve(&self, tag: &str) -> Option<Node> {
        self.0.get(tag).cloned()
    }
}

#[derive(Clone, Copy)]
enum Variant {
    Direct,
    Stream,
    Loopback,
}

impl Variant {
    fn name(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Stream => "stream",
            Self::Loopback => "loopback",
        }
    }
}

struct Dialer {
    fixtures: Fixtures,
    registry: ProxyRegistry,
    chain: Node,
}

impl Dialer {
    fn new(fixtures: Fixtures) -> Self {
        let registry = ProxyRegistry::default_resolver().unwrap();
        registry
            .chain()
            .unwrap()
            .install_resolver(Arc::new(MapResolver(HashMap::from([
                ("front".to_owned(), fixtures.front.clone()),
                ("land".to_owned(), fixtures.land.clone()),
            ]))));
        let chain = Node {
            name: "chain".to_owned(),
            outbound: OutboundConfig::Chain(ChainConfig {
                hops: vec!["front".to_owned()],
                out: ChainOut::Tag("land".to_owned()),
                group_exit: None,
            }),
            ..Node::default()
        };
        Self {
            fixtures,
            registry,
            chain,
        }
    }

    async fn dial(&self, variant: Variant) -> ProxyStream {
        let target = self.fixtures.echo;
        match variant {
            Variant::Direct => Socks5Handler::new()
                .dial(&self.fixtures.land, target, None, TIMEOUT)
                .await
                .unwrap(),
            Variant::Stream => self
                .registry
                .dial(&self.chain, target, None, TIMEOUT)
                .await
                .unwrap(),
            Variant::Loopback => {
                let land = SocketAddr::from((Ipv4Addr::LOCALHOST, self.fixtures.land.port));
                let upstream = Socks5Handler::new()
                    .dial(&self.fixtures.front, land, None, TIMEOUT)
                    .await
                    .unwrap();
                let bridge = loopback_bridge(upstream).await;
                Socks5Handler::new()
                    .dial_with_tcp(&self.fixtures.land, target, None, bridge, TIMEOUT)
                    .await
                    .unwrap()
            }
        }
    }
}

/// The rejected design: carry `upstream` on a fresh loopback connection with
/// a copy task in between.
async fn loopback_bridge(upstream: ProxyStream) -> TcpStream {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let (ours, accepted) = tokio::join!(TcpStream::connect(address), listener.accept());
    let ours = ours.unwrap();
    let (mut theirs, _) = accepted.unwrap();
    let _ = ours.set_nodelay(true);
    let _ = theirs.set_nodelay(true);
    let mut upstream = upstream.stream;
    tokio::spawn(async move {
        let _ = tokio::io::copy_bidirectional(&mut theirs, &mut upstream).await;
    });
    ours
}

async fn first_echo(stream: &mut ProxyStream) {
    stream.stream.write_all(b"x").await.unwrap();
    let mut byte = [0u8; 1];
    stream.stream.read_exact(&mut byte).await.unwrap();
    assert_eq!(&byte, b"x", "echo contract");
}

async fn bulk_echo(stream: ProxyStream, payload: Arc<Vec<u8>>) {
    let (mut read, mut write) = tokio::io::split(stream.stream);
    let sent = Arc::clone(&payload);
    let writer = tokio::spawn(async move {
        for chunk in sent.chunks(CHUNK) {
            write.write_all(chunk).await.unwrap();
        }
        write
    });
    let mut received = vec![0u8; payload.len()];
    read.read_exact(&mut received).await.unwrap();
    let _write = writer.await.unwrap();
    assert!(received == *payload, "echo contract");
}

fn bench_chain(c: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let dialer = Arc::new(Dialer::new(start_fixtures()));
    let payload: Arc<Vec<u8>> = Arc::new((0..BULK_BYTES).map(|i| (i % 251) as u8).collect());
    let variants = [Variant::Direct, Variant::Stream, Variant::Loopback];

    let mut setup = c.benchmark_group("chain_setup");
    for variant in variants {
        setup.bench_with_input(
            BenchmarkId::from_parameter(variant.name()),
            &variant,
            |b, &variant| {
                b.to_async(&runtime).iter(|| {
                    let dialer = Arc::clone(&dialer);
                    async move {
                        let mut stream = dialer.dial(variant).await;
                        first_echo(&mut stream).await;
                        black_box(stream);
                    }
                });
            },
        );
    }
    setup.finish();

    let mut bulk = c.benchmark_group("chain_bulk_echo");
    bulk.throughput(Throughput::Bytes(BULK_BYTES as u64));
    bulk.sample_size(20);
    for variant in variants {
        bulk.bench_with_input(
            BenchmarkId::from_parameter(variant.name()),
            &variant,
            |b, &variant| {
                b.to_async(&runtime).iter(|| {
                    let dialer = Arc::clone(&dialer);
                    let payload = Arc::clone(&payload);
                    async move {
                        let stream = dialer.dial(variant).await;
                        bulk_echo(stream, payload).await;
                    }
                });
            },
        );
    }
    bulk.finish();
}

criterion_group!(benches, bench_chain);
criterion_main!(benches);
