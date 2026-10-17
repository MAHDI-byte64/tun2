//! The carrier seam of the KCP stack.
//!
//! KCP's reliable ARQ, FEC, packet protection, the datagram path, and the whole
//! handshake/record/mux stack above it do not care what carries the sealed packets. Today
//! that is a UDP socket ([`udp`]); the raw-packet carriers ([`icmp`], [`faketcp`]) ride
//! the same KCP stack over a different datagram carrier.
//!
//! The carrier is selected from `[tunnel] transport` ([`Carrier::from_transport`]) and
//! threaded through [`super::KcpParams`]. For now the socket type is always a
//! [`tokio::net::UdpSocket`]; [`open`] creates it for the UDP carrier and returns
//! [`io::ErrorKind::Unsupported`] for the raw-packet carriers, whose real socket/demux
//! logic the icmp and faketcp units fill in.

use std::io;
use std::net::SocketAddr;

use tokio::net::UdpSocket;

use crate::config::TransportKind;

pub(super) mod faketcp;
pub(super) mod icmp;
pub(super) mod udp;

/// Which datagram carrier the KCP stack rides.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Carrier {
    /// Plain UDP datagrams (`transport = "kcp"` and `transport = "udp"`).
    #[default]
    Udp,
    /// ICMP echo request/reply (`transport = "icmp"`), Linux + root.
    Icmp,
    /// Raw-socket fake TCP (`transport = "faketcp"`), Linux + root.
    Faketcp,
}

impl Carrier {
    /// The carrier a transport uses. Only the KCP-based transports reach here; any other
    /// maps to [`Carrier::Udp`] as a harmless default (it is never used for them).
    pub fn from_transport(kind: TransportKind) -> Self {
        match kind {
            TransportKind::Faketcp => Self::Faketcp,
            TransportKind::Icmp => Self::Icmp,
            // `kcp`, `udp`, and anything non-KCP (never routed through a carrier).
            _ => Self::Udp,
        }
    }
}

/// Opens the carrier's datagram socket.
///
/// `addr` is the bind address: the listen address on the accepting side, or an unspecified
/// local address on the dialing side (the caller then connects it to the peer).
pub(super) fn open(
    carrier: Carrier,
    addr: SocketAddr,
    buffer: usize,
    dscp: Option<u8>,
) -> io::Result<UdpSocket> {
    match carrier {
        Carrier::Udp => udp::open(addr, buffer, dscp),
        Carrier::Icmp => icmp::open(addr, buffer, dscp),
        Carrier::Faketcp => faketcp::open(addr, buffer, dscp),
    }
}

/// What the KCP driver and demultiplexer need from a carrier: send a sealed packet to a
/// peer, and receive `(bytes, peer)`. The UDP carrier is a thin wrapper over
/// [`tokio::net::UdpSocket`]; the icmp and faketcp units implement this for their raw
/// sockets (the dialer's per-connection sender and the listener's shared demultiplexer
/// keyed by `(peer, conv)`) and migrate the driver in [`super`] onto it.
///
/// It is defined now so the seam is named and documented; the current driver still calls
/// [`tokio::net::UdpSocket`] directly through the UDP carrier.
pub trait PacketCarrier: Send + Sync + 'static {
    /// Sends one already-sealed packet to `peer` (or to the connected peer when `peer` is
    /// `None`).
    fn send_to(&self, packet: &[u8], peer: Option<SocketAddr>) -> io::Result<()>;

    /// Receives one packet into `buf`, returning its length and the peer it came from.
    fn recv_from(
        &self,
        buf: &mut [u8],
    ) -> impl std::future::Future<Output = io::Result<(usize, SocketAddr)>> + Send;
}
