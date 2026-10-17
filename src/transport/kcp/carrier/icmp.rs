//! The ICMP-echo carrier (`transport = "icmp"`, BackPack's `xdi`): the KCP stack ridden
//! inside ICMP echo request/reply packets, for the one network where UDP and TCP are
//! filtered but ICMP is not. Linux + `CAP_NET_RAW`.
//!
//! Scaffold: [`open`] returns [`io::ErrorKind::Unsupported`]. The icmp unit replaces it
//! with a raw ICMP socket, the per-tunnel session tag derived from the token, per-session
//! echo-id demultiplexing, and the RAII firewall rules in [`super::super::rawlink`]. It
//! also migrates the KCP driver onto [`super::PacketCarrier`].

use std::io;
use std::net::SocketAddr;

use tokio::net::UdpSocket;

/// Opens the ICMP carrier. Not built yet.
pub(super) fn open(_addr: SocketAddr, _buffer: usize, _dscp: Option<u8>) -> io::Result<UdpSocket> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "transport \"icmp\" is not built yet (raw ICMP carrier)",
    ))
}
