use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn target() -> SocketAddr {
    "93.184.216.34:443".parse().unwrap()
}

#[test]
fn request_uses_domain_and_basic_auth() {
    let req = HttpHandler::request(target(), Some("example.com"), Some("u"), Some("p"));
    let req = String::from_utf8(req).unwrap();
    assert!(req.starts_with("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n"));
    assert!(req.contains("Proxy-Authorization: Basic dTpw\r\n"));
    assert!(req.ends_with("\r\n\r\n"));
}

#[test]
fn request_without_auth_brackets_ipv6() {
    let t: SocketAddr = "[2001:db8::1]:80".parse().unwrap();
    let req = String::from_utf8(HttpHandler::request(t, None, None, None)).unwrap();
    assert!(req.starts_with("CONNECT [2001:db8::1]:80 HTTP/1.1\r\n"));
    assert!(!req.contains("Proxy-Authorization"));
}

async fn serve_once(reply: &'static [u8]) -> (SocketAddr, tokio::task::JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut req = Vec::new();
        let mut b = [0u8; 1];
        while !req.ends_with(b"\r\n\r\n") {
            sock.read_exact(&mut b).await.unwrap();
            req.push(b[0]);
        }
        sock.write_all(reply).await.unwrap();
        // Echo one payload chunk to prove the tunnel is intact.
        let mut buf = [0u8; 4];
        if sock.read_exact(&mut buf).await.is_ok() {
            sock.write_all(&buf).await.unwrap();
        }
        req
    });
    (addr, task)
}

#[tokio::test]
async fn handshake_accepts_2xx_and_keeps_trailing_payload() {
    let (addr, task) =
        serve_once(b"HTTP/1.1 200 Connection established\r\nX: y\r\n\r\nEARLY").await;
    let mut s = TcpStream::connect(addr).await.unwrap();
    let req = HttpHandler::request(target(), None, None, None);
    HttpHandler::handshake(&mut s, &req).await.unwrap();
    let mut early = [0u8; 5];
    s.read_exact(&mut early).await.unwrap();
    assert_eq!(&early, b"EARLY");
    s.write_all(b"ping").await.unwrap();
    let mut echo = [0u8; 4];
    s.read_exact(&mut echo).await.unwrap();
    assert_eq!(&echo, b"ping");
    let seen = task.await.unwrap();
    assert!(seen.starts_with(b"CONNECT 93.184.216.34:443 HTTP/1.1\r\n"));
}

#[tokio::test]
async fn handshake_rejects_non_2xx() {
    let (addr, _task) = serve_once(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n").await;
    let mut s = TcpStream::connect(addr).await.unwrap();
    let req = HttpHandler::request(target(), None, None, None);
    let err = HttpHandler::handshake(&mut s, &req).await.unwrap_err();
    assert!(err.to_string().contains("407"), "{err}");
}

#[tokio::test]
async fn handshake_rejects_garbage_and_eof() {
    let (addr, _task) = serve_once(b"SSH-2.0-x\r\n\r\n").await;
    let mut s = TcpStream::connect(addr).await.unwrap();
    let req = HttpHandler::request(target(), None, None, None);
    assert!(HttpHandler::handshake(&mut s, &req).await.is_err());

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (sock, _) = listener.accept().await.unwrap();
        drop(sock);
    });
    let mut s = TcpStream::connect(addr).await.unwrap();
    let err = HttpHandler::handshake(&mut s, &req).await.unwrap_err();
    assert!(
        err.to_string().contains("closed") || err.to_string().contains("reset"),
        "{err}"
    );
}
