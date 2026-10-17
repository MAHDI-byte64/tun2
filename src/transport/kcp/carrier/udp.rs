//! The UDP carrier: a plain UDP socket, the carrier `transport = "kcp"` and
//! `transport = "udp"` ride. This is the KCP stack's original datagram carrier, moved
//! behind the [`super::Carrier`] seam unchanged.

use std::io;
use std::net::SocketAddr;

use tokio::net::UdpSocket;
use tracing::debug;

/// Binds a non-blocking UDP socket with the KCP socket buffers and DSCP mark set.
pub(super) fn open(addr: SocketAddr, buffer: usize, dscp: Option<u8>) -> io::Result<UdpSocket> {
    let socket = std::net::UdpSocket::bind(addr)?;
    let sock = socket2::SockRef::from(&socket);
    if let Err(e) = sock
        .set_recv_buffer_size(buffer)
        .and_then(|_| sock.set_send_buffer_size(buffer))
    {
        debug!(error = %e, "could not set KCP socket buffers");
    }
    crate::transport::mark_dscp(&sock, dscp);
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket)
}
