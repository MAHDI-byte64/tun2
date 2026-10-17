//! The fake-TCP carrier (`transport = "faketcp"`, BackPack's `pck`): the KCP stack ridden
//! inside crafted TCP segments that bypass the kernel's TCP stack (an `AF_PACKET` receive
//! upstream of conntrack, a raw send to the next hop). Linux + `CAP_NET_RAW`.
//!
//! Scaffold: [`open`] returns [`io::ErrorKind::Unsupported`]. The faketcp unit replaces it
//! with the raw sockets, the token-derived source port, realistic seq/ack/window/flags,
//! next-hop lookup in [`super::super::rawlink`], and the RAII RST-drop / NOTRACK iptables
//! rules. It also migrates the KCP driver onto [`super::PacketCarrier`].

use std::io;
use std::net::SocketAddr;

use tokio::net::UdpSocket;

/// Opens the fake-TCP carrier. Not built yet.
pub(super) fn open(_addr: SocketAddr, _buffer: usize, _dscp: Option<u8>) -> io::Result<UdpSocket> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "transport \"faketcp\" is not built yet (raw fake-TCP carrier)",
    ))
}
