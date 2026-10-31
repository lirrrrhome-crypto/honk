//! HTTP/HTTPS proxy outbound: a plain `CONNECT` tunnel (RFC 9110 §9.3.6),
//! optionally over TLS (`https://`) and with Basic proxy authentication.
//! TCP only; it has no UDP path, so chains that need UDP through it are
//! refused by the capability checks rather than sent directly.

use async_trait::async_trait;
use base64::Engine;
use honk_config::node::Node;
use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::debug;

use super::{ProbeableOutbound, ProxyStream, TcpOutbound};

/// Upper bound on the proxy's CONNECT response header block.
const MAX_RESPONSE_HEADER: usize = 16 * 1024;

pub struct HttpHandler;

impl HttpHandler {
    pub fn new() -> Self {
        Self
    }

    /// `host:port` authority for the CONNECT request line; IPv6 bracketed.
    fn authority(target: SocketAddr, target_domain: Option<&str>) -> String {
        match target_domain {
            Some(domain) if !domain.is_empty() => format!("{}:{}", domain, target.port()),
            _ => target.to_string(),
        }
    }

    pub(crate) fn request(
        target: SocketAddr,
        target_domain: Option<&str>,
        username: Option<&str>,
        password: Option<&str>,
    ) -> Vec<u8> {
        let authority = Self::authority(target, target_domain);
        let mut req = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
        if username.is_some() || password.is_some() {
            let creds = format!("{}:{}", username.unwrap_or(""), password.unwrap_or(""));
            let token = base64::engine::general_purpose::STANDARD.encode(creds);
            req.push_str(&format!("Proxy-Authorization: Basic {token}\r\n"));
        }
        req.push_str("\r\n");
        req.into_bytes()
    }

    /// Sends CONNECT and consumes the response header block byte by byte so
    /// no tunnel payload is swallowed. Requires a 2xx status.
    pub(crate) async fn handshake<S: AsyncRead + AsyncWrite + Unpin>(
        stream: &mut S,
        request: &[u8],
    ) -> anyhow::Result<()> {
        stream.write_all(request).await?;
        stream.flush().await?;
        let mut head = Vec::with_capacity(256);
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            if head.len() >= MAX_RESPONSE_HEADER {
                anyhow::bail!("HTTP proxy CONNECT response header too large");
            }
            if stream.read(&mut byte).await? == 0 {
                anyhow::bail!("HTTP proxy closed the connection during CONNECT");
            }
            head.push(byte[0]);
        }
        let status_line = head
            .split(|b| *b == b'\n')
            .next()
            .map(|l| String::from_utf8_lossy(l).trim().to_string())
            .unwrap_or_default();
        let mut parts = status_line.split_whitespace();
        let version = parts.next().unwrap_or("");
        let code: u16 = parts.next().and_then(|c| c.parse().ok()).unwrap_or(0);
        if !version.starts_with("HTTP/1.") {
            anyhow::bail!("HTTP proxy sent an invalid CONNECT response: {status_line:?}");
        }
        if !(200..300).contains(&code) {
            anyhow::bail!("HTTP proxy refused CONNECT: {status_line}");
        }
        Ok(())
    }

    async fn connect_via(
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        tcp: Option<TcpStream>,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<ProxyStream> {
        let config = node
            .http()
            .ok_or_else(|| anyhow::anyhow!("node {} is not an HTTP proxy", node.name))?;
        let mut stream = super::transport::maybe_tls_wrap(node, tcp, connect_timeout).await?;
        crate::runtime::flow_observation::milestone(
            crate::runtime::flow_observation::Milestone::TransportReady,
        );
        let request = Self::request(
            target,
            target_domain,
            config.username.as_deref(),
            config.password.as_deref(),
        );
        tokio::time::timeout(connect_timeout, Self::handshake(&mut stream, &request))
            .await
            .map_err(|_| anyhow::anyhow!("HTTP proxy CONNECT timed out"))??;
        Ok(ProxyStream {
            stream,
            target_addr: target,
            target_domain: target_domain.map(|s| s.to_string()),
        })
    }
}

impl Default for HttpHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl TcpOutbound for HttpHandler {
    async fn dial(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<ProxyStream> {
        debug!("HTTP: {}:{} for target {}", node.host(), node.port, target);
        Self::connect_via(node, target, target_domain, None, connect_timeout).await
    }

    async fn dial_with_tcp(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        stream: TcpStream,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<ProxyStream> {
        Self::connect_via(node, target, target_domain, Some(stream), connect_timeout).await
    }
}

#[async_trait]
impl ProbeableOutbound for HttpHandler {}

#[cfg(test)]
mod tests;
