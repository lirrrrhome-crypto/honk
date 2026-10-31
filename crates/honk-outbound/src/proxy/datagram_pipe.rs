//! A datagram path to one proxy server: either this host's own UDP socket
//! (connected to the server) or a front hop's UDP relay addressed to it.
//!
//! Native-UDP landings (Shadowsocks, SOCKS5 UDP ASSOCIATE) frame their own
//! datagrams and hand them to a [`DatagramPipe`]; for a chained landing the
//! pipe is the front's [`PacketTransport`] dialed with the landing server as
//! its target, so the landing's UDP never leaves this host directly.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::UdpSocket;
use tracing::debug;

use super::PacketTransport;

/// Which reply sources a relayed pipe accepts. A server named by domain is
/// resolved by the front, so only its port is known here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerFilter {
    Exact(SocketAddr),
    Port(u16),
}

impl PeerFilter {
    pub(crate) fn new(server: SocketAddr, domain: Option<&str>) -> Self {
        if domain.is_some() || server.ip().is_unspecified() {
            Self::Port(server.port())
        } else {
            Self::Exact(canonical(server))
        }
    }

    fn admits(self, peer: SocketAddr) -> bool {
        match self {
            Self::Exact(server) => canonical(peer) == server,
            Self::Port(port) => peer.port() == port,
        }
    }
}

fn canonical(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(addr.ip().to_canonical(), addr.port())
}

#[derive(Debug)]
pub enum DatagramPipe {
    /// This host's socket, already connected to the server.
    Socket(UdpSocket),
    /// A front hop's UDP relay whose target is the server.
    Relay {
        transport: Arc<dyn PacketTransport>,
        peer: PeerFilter,
    },
}

impl DatagramPipe {
    pub(crate) fn relay(
        transport: Arc<dyn PacketTransport>,
        server: SocketAddr,
        domain: Option<&str>,
    ) -> Self {
        Self::Relay {
            transport,
            peer: PeerFilter::new(server, domain),
        }
    }

    pub(crate) fn is_relayed(&self) -> bool {
        matches!(self, Self::Relay { .. })
    }

    /// Send one whole datagram; returns its length.
    pub(crate) async fn send(&self, packet: &[u8]) -> io::Result<usize> {
        match self {
            Self::Socket(socket) => socket.send(packet).await,
            Self::Relay { transport, .. } => {
                transport.send_packet(packet).await?;
                Ok(packet.len())
            }
        }
    }

    /// Receive one datagram from the server. A relayed datagram from any
    /// other source is dropped (the relay may be full-cone).
    pub(crate) async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Socket(socket) => socket.recv(buf).await,
            Self::Relay { transport, peer } => loop {
                let (n, from) = transport.recv_packet(buf).await?;
                if peer.admits(from) {
                    return Ok(n);
                }
                debug!("chained UDP: dropping relayed datagram from {from} (expected {peer:?})");
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_filter_pins_literal_servers_and_ports_for_domains() {
        let server: SocketAddr = "10.0.0.2:8388".parse().unwrap();
        let exact = PeerFilter::new(server, None);
        assert!(exact.admits(server));
        assert!(exact.admits("[::ffff:10.0.0.2]:8388".parse().unwrap()));
        assert!(!exact.admits("10.0.0.3:8388".parse().unwrap()));
        assert!(!exact.admits("10.0.0.2:8389".parse().unwrap()));
        let by_name = PeerFilter::new("0.0.0.0:8388".parse().unwrap(), Some("ss.example"));
        assert!(by_name.admits("192.0.2.1:8388".parse().unwrap()));
        assert!(!by_name.admits("192.0.2.1:53".parse().unwrap()));
    }
}
