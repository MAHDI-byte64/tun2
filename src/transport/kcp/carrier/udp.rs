//! The UDP carrier: a plain UDP socket, the carrier `transport = "kcp"` and
//! `transport = "udp"` ride. This is the KCP stack's original datagram carrier, moved
//! behind the [`super::Carrier`] seam unchanged.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::net::UdpSocket;
use tracing::debug;

/// Binds a non-blocking UDP socket with the KCP socket buffers and DSCP mark set.
pub(super) fn open(addr: SocketAddr, buffer: usize, dscp: Option<u8>) -> io::Result<UdpSocket> {
    let socket = std::net::UdpSocket::bind(addr)?;
    tune(&socket, buffer, dscp);
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket)
}

/// Binds an unspecified local address of `peer`'s family and connects it to `peer`: the
/// dialer's per-connection socket. The connect is synchronous (the address is already
/// resolved), so the carrier openers stay non-`async`.
pub(super) fn open_connected(
    peer: SocketAddr,
    buffer: usize,
    dscp: Option<u8>,
) -> io::Result<UdpSocket> {
    let local = match peer {
        SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
        SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
    };
    let socket = std::net::UdpSocket::bind(local)?;
    tune(&socket, buffer, dscp);
    socket.connect(peer)?;
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket)
}

/// Sets the KCP socket buffers and the DSCP mark.
fn tune(socket: &std::net::UdpSocket, buffer: usize, dscp: Option<u8>) {
    let sock = socket2::SockRef::from(socket);
    if let Err(e) = sock
        .set_recv_buffer_size(buffer)
        .and_then(|_| sock.set_send_buffer_size(buffer))
    {
        debug!(error = %e, "could not set KCP socket buffers");
    }
    crate::transport::mark_dscp(&sock, dscp);
}
