//! Several datagrams per system call: `sendmmsg` and `recvmmsg` on Linux, one call per
//! packet elsewhere. The UDP forward rules and the KCP carrier go through here, so a busy
//! socket costs one call per batch of packets instead of one per packet.

use std::io;
use std::net::SocketAddr;

use tokio::net::UdpSocket;

/// Datagrams one receive call brings at most.
pub const MAX_RECV: usize = 32;
/// Datagrams one send call takes at most.
pub const MAX_SEND: usize = 64;

/// Datagrams received by one call, each with its sender.
pub struct RecvBatch {
    bufs: Vec<Vec<u8>>,
    /// Per buffer of the last receive: the packet's length and sender, or `None` for one
    /// that was dropped (cut short by the buffer).
    from: Vec<Option<(usize, SocketAddr)>>,
    packet: usize,
    max: usize,
}

impl RecvBatch {
    /// Buffers of `packet` bytes: `initial` of them at first, up to `max` (one more is
    /// added whenever a receive fills every buffer there is, so an idle socket costs
    /// little and a busy one grows into its batch).
    pub fn new(packet: usize, initial: usize, max: usize) -> Self {
        let max = max.clamp(1, MAX_RECV);
        let initial = initial.clamp(1, max);
        Self {
            bufs: (0..initial).map(|_| vec![0u8; packet]).collect(),
            from: Vec::with_capacity(max),
            packet,
            max,
        }
    }

    /// Waits for the socket and receives what it has, up to the batch's size. A
    /// datagram larger than a buffer is dropped.
    pub async fn recv(&mut self, socket: &UdpSocket) -> io::Result<()> {
        self.from.clear();
        #[cfg(target_os = "linux")]
        loop {
            socket.readable().await?;
            match socket.try_io(tokio::io::Interest::READABLE, || self.recv_many(socket)) {
                Ok(()) => break,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e),
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let (n, from) = socket.recv_from(&mut self.bufs[0]).await?;
            self.from.push(Some((n, from)));
        }
        if self.from.len() == self.bufs.len() && self.bufs.len() < self.max {
            self.bufs.push(vec![0u8; self.packet]);
        }
        Ok(())
    }

    /// The first buffer, for a packet received some other way (see [`Self::set_one`]).
    pub fn first_buffer(&mut self) -> &mut [u8] {
        &mut self.bufs[0]
    }

    /// Makes the batch hold one packet of `n` bytes, read into the first buffer.
    pub fn set_one(&mut self, n: usize, from: SocketAddr) {
        self.from.clear();
        self.from.push(Some((n, from)));
    }

    /// The packets of the last receive, in order, each with its sender. Mutable, so the
    /// caller can decrypt in place.
    pub fn packets(&mut self) -> impl Iterator<Item = (&mut [u8], SocketAddr)> {
        self.bufs
            .iter_mut()
            .zip(self.from.iter())
            .filter_map(|(buf, entry)| entry.map(|(n, from)| (&mut buf[..n], from)))
    }

    #[cfg(target_os = "linux")]
    fn recv_many(&mut self, socket: &UdpSocket) -> io::Result<()> {
        use std::os::fd::AsRawFd;
        let count = self.bufs.len();
        let mut names: Vec<socket2::SockAddrStorage> = (0..count)
            .map(|_| socket2::SockAddrStorage::zeroed())
            .collect();
        let mut iovs: Vec<libc::iovec> = self
            .bufs
            .iter_mut()
            .map(|b| libc::iovec {
                iov_base: b.as_mut_ptr().cast(),
                iov_len: b.len(),
            })
            .collect();
        let mut msgs: Vec<libc::mmsghdr> = (0..count)
            .map(|i| {
                // SAFETY: all zeros is a valid (empty) message header.
                let mut m: libc::mmsghdr = unsafe { std::mem::zeroed() };
                m.msg_hdr.msg_name = std::ptr::addr_of_mut!(names[i]).cast();
                m.msg_hdr.msg_namelen = std::mem::size_of::<socket2::SockAddrStorage>() as _;
                m.msg_hdr.msg_iov = std::ptr::addr_of_mut!(iovs[i]);
                m.msg_hdr.msg_iovlen = 1 as _;
                m
            })
            .collect();
        // SAFETY: every pointer in `msgs` points into `names`, `iovs` or `self.bufs`, all
        // of which live past the call; the socket is a UDP socket of this process.
        let n = unsafe {
            libc::recvmmsg(
                socket.as_raw_fd(),
                msgs.as_mut_ptr(),
                count as _,
                libc::MSG_DONTWAIT as _,
                std::ptr::null_mut(),
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        for (i, m) in msgs.iter().take(n as usize).enumerate() {
            let storage = std::mem::replace(&mut names[i], socket2::SockAddrStorage::zeroed());
            // SAFETY: the kernel wrote `msg_namelen` bytes of a socket address into it.
            let addr = unsafe { socket2::SockAddr::new(storage, m.msg_hdr.msg_namelen) };
            // Cut short by the buffer: not a packet of ours. The entry stays, so the
            // packets after it keep their buffers.
            let truncated = m.msg_hdr.msg_flags & libc::MSG_TRUNC != 0;
            self.from.push(match addr.as_socket() {
                Some(from) if !truncated => Some((m.msg_len as usize, from)),
                _ => None,
            });
        }
        Ok(())
    }
}

/// Sends `packets` without waiting, to `peer` or (with `None`) to the connected peer:
/// the ones the socket buffer has no room for are dropped, as a congested link would
/// drop them. Returns how many went out.
pub fn send_now(
    socket: &UdpSocket,
    packets: &[&[u8]],
    peer: Option<SocketAddr>,
) -> io::Result<usize> {
    match packets {
        [] => Ok(0),
        [one] => {
            let r = match peer {
                Some(peer) => socket.try_send_to(one, peer),
                None => socket.try_send(one),
            };
            match r {
                Ok(_) => Ok(1),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(0),
                Err(e) => Err(e),
            }
        }
        #[cfg(target_os = "linux")]
        _ => {
            let mut sent = 0;
            for chunk in packets.chunks(MAX_SEND) {
                let n = match socket.try_io(tokio::io::Interest::WRITABLE, || {
                    send_many(socket, chunk, peer)
                }) {
                    Ok(n) => n,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => 0,
                    Err(e) => return Err(e),
                };
                sent += n;
                if n < chunk.len() {
                    break;
                }
            }
            Ok(sent)
        }
        #[cfg(not(target_os = "linux"))]
        _ => {
            let mut sent = 0;
            for packet in packets {
                let r = match peer {
                    Some(peer) => socket.try_send_to(packet, peer),
                    None => socket.try_send(packet),
                };
                match r {
                    Ok(_) => sent += 1,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => return Err(e),
                }
            }
            Ok(sent)
        }
    }
}

/// Sends every one of `packets`, waiting for room in the socket buffer when it is full
/// (for the sockets towards users and targets, where a wait is better than a drop).
pub async fn send_all(
    socket: &UdpSocket,
    packets: &[&[u8]],
    peer: Option<SocketAddr>,
) -> io::Result<()> {
    let mut done = 0;
    while done < packets.len() {
        let n = send_now(socket, &packets[done..], peer)?;
        done += n;
        if done < packets.len() {
            socket.writable().await?;
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn send_many(socket: &UdpSocket, packets: &[&[u8]], peer: Option<SocketAddr>) -> io::Result<usize> {
    use std::os::fd::AsRawFd;
    let name = peer.map(socket2::SockAddr::from);
    let mut iovs: Vec<libc::iovec> = packets
        .iter()
        .map(|p| libc::iovec {
            iov_base: p.as_ptr().cast_mut().cast(),
            iov_len: p.len(),
        })
        .collect();
    let mut msgs: Vec<libc::mmsghdr> = (0..packets.len())
        .map(|i| {
            // SAFETY: all zeros is a valid (empty) message header.
            let mut m: libc::mmsghdr = unsafe { std::mem::zeroed() };
            if let Some(name) = &name {
                m.msg_hdr.msg_name = name.as_ptr().cast_mut().cast();
                m.msg_hdr.msg_namelen = name.len();
            }
            m.msg_hdr.msg_iov = std::ptr::addr_of_mut!(iovs[i]);
            m.msg_hdr.msg_iovlen = 1 as _;
            m
        })
        .collect();
    // SAFETY: the pointers in `msgs` point into `iovs`, `name` and `packets`, which live
    // past the call; the kernel only reads through them.
    let n = unsafe {
        libc::sendmmsg(
            socket.as_raw_fd(),
            msgs.as_mut_ptr(),
            packets.len() as _,
            libc::MSG_DONTWAIT as _,
        )
    };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(n as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn many_packets_go_out_and_come_in_together() {
        let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let to = b.local_addr().unwrap();
        let packets: Vec<Vec<u8>> = (0..100u8).map(|i| vec![i; 100 + i as usize]).collect();
        let slices: Vec<&[u8]> = packets.iter().map(Vec::as_slice).collect();
        send_all(&a, &slices, Some(to)).await.unwrap();
        let mut batch = RecvBatch::new(2048, 1, MAX_RECV);
        let mut got = Vec::new();
        while got.len() < packets.len() {
            batch.recv(&b).await.unwrap();
            for (data, from) in batch.packets() {
                assert_eq!(from, a.local_addr().unwrap());
                got.push(data.to_vec());
            }
        }
        assert_eq!(got, packets);
        // A connected socket sends without a peer address.
        a.connect(to).await.unwrap();
        assert_eq!(send_now(&a, &slices[..3], None).unwrap(), 3);
        batch.recv(&b).await.unwrap();
        assert!(batch.packets().count() >= 1);
    }

    #[tokio::test]
    async fn a_datagram_larger_than_the_buffer_is_dropped() {
        let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let to = b.local_addr().unwrap();
        a.send_to(&[1u8; 3000], to).await.unwrap();
        a.send_to(&[2u8; 100], to).await.unwrap();
        let mut batch = RecvBatch::new(2048, 4, 4);
        let mut got = Vec::new();
        while got.is_empty() {
            batch.recv(&b).await.unwrap();
            got.extend(batch.packets().map(|(d, _)| d.to_vec()));
        }
        assert_eq!(got, vec![vec![2u8; 100]]);
    }
}
