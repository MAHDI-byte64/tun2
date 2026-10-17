//! The ICMP-echo carrier (`transport = "icmp"`, BackPack's `xdi`): the KCP stack ridden
//! inside ICMP echo request/reply packets, for the one network where UDP and TCP are
//! filtered but ICMP is not. Linux + `CAP_NET_RAW`.
//!
//! Each already-sealed KCP packet rides in the data of an **Echo Request** (dialer →
//! listener) or an **Echo Reply** (listener → dialer). The data is
//! `tag (4) | dir (1) | sealed KCP packet`:
//!
//! * `tag` is this tunnel's 4-byte tag ([`super::IcmpParams::tag`], from the token). An
//!   echo whose first four bytes are not the tag is dropped before the cipher is touched,
//!   so several icmp tunnels share one host and stray pings cost nothing.
//! * `dir` says which way the echo goes. The kernel answers every echo request with an
//!   automatic reply that copies the request's data verbatim — so on the wire it also
//!   carries our tag. `dir` lets the dialer tell that echoed-back copy of its own upload
//!   (`dir = D2L`) from a real reply from the listener (`dir = L2D`) and drop it, which is
//!   what keeps the tunnel correct whether or not the firewall rule below is in place.
//!
//! Each session takes its own 16-bit echo identifier (the dialer picks it; the listener
//! learns it from the requests and answers with it). The listener's demux key is
//! `(peer IP, echo id)`, carried through [`super`] as the `SocketAddr` of the packet (the
//! echo id in the port field), so the existing `(peer, conv)` conversation demux is
//! unchanged.
//!
//! A raw `AF_INET`/`SOCK_RAW`/`IPPROTO_ICMP` socket is used (not `SOCK_DGRAM`: the kernel
//! rewrites the echo id there, which this design controls). When `manage_firewall` is on,
//! the listener installs best-effort iptables rules to suppress the kernel's automatic
//! replies (so the extra upload is saved) and to accept our echoes under a default-DROP
//! policy; they are removed on drop. Without them the tunnel still works (the `dir` byte
//! keeps it correct), it just pays the extra kernel reply.

#[cfg(not(all(feature = "rawlink", target_os = "linux")))]
use std::io;
#[cfg(not(all(feature = "rawlink", target_os = "linux")))]
use std::net::SocketAddr;

#[cfg(not(all(feature = "rawlink", target_os = "linux")))]
use super::CarrierSocket;

/// Lowest 2 bytes of the token subkey pick a source port; shared helper lives here so the
/// non-Linux build still resolves the module path. (Kept minimal; real logic is below.)
#[cfg(not(all(feature = "rawlink", target_os = "linux")))]
pub(super) fn open_dialer(
    _params: &super::IcmpParams,
    _peer: SocketAddr,
    _buffer: usize,
    _dscp: Option<u8>,
) -> io::Result<CarrierSocket> {
    Err(unsupported())
}

#[cfg(not(all(feature = "rawlink", target_os = "linux")))]
pub(super) fn open_listener(
    _params: &super::IcmpParams,
    _local: SocketAddr,
    _buffer: usize,
    _dscp: Option<u8>,
) -> io::Result<CarrierSocket> {
    Err(unsupported())
}

#[cfg(not(all(feature = "rawlink", target_os = "linux")))]
fn unsupported() -> io::Error {
    if cfg!(feature = "rawlink") {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "transport \"icmp\" is Linux-only",
        )
    } else {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "transport \"icmp\" is not built (enable the rawlink feature)",
        )
    }
}

#[cfg(all(feature = "rawlink", target_os = "linux"))]
pub(super) use imp::{open_dialer, open_listener, IcmpSocket};

#[cfg(all(feature = "rawlink", target_os = "linux"))]
mod imp {
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::os::fd::AsRawFd;
    use std::sync::atomic::{AtomicU16, Ordering};

    use etherparse::{IcmpEchoHeader, Icmpv4Header, Icmpv4Slice, Icmpv4Type};
    use socket2::{Domain, Protocol, SockAddr, Socket, Type};
    use tokio::io::unix::AsyncFd;
    use tracing::{debug, warn};

    use super::super::{CarrierSocket, IcmpParams};
    use crate::transport::kcp::rawlink::{unique_suffix, FirewallRules, Rule};

    /// `dir` byte: an Echo Request going dialer → listener.
    const DIR_D2L: u8 = 1;
    /// `dir` byte: an Echo Reply going listener → dialer.
    const DIR_L2D: u8 = 2;
    /// ICMP type numbers.
    const ECHO_REPLY: u8 = 0;
    const ECHO_REQUEST: u8 = 8;
    /// `tag (4) | dir (1)` before the sealed packet.
    const FRAMING: usize = 5;

    /// One raw ICMP socket, as a dialer (sends requests to a fixed peer) or a listener
    /// (answers each peer with a reply).
    pub(in crate::transport::kcp) struct IcmpSocket {
        fd: AsyncFd<Socket>,
        tag: [u8; 4],
        /// Dialer: our session's echo id. Listener: 0 (the id comes from each peer).
        echo_id: u16,
        /// Dialer: the peer to send requests to. Listener: `None`.
        peer: Option<Ipv4Addr>,
        /// The address reported by `local_addr` (listener side).
        local: SocketAddr,
        /// Monotonic echo sequence numbers, for realism.
        seq: AtomicU16,
        /// Kept alive for their RAII effect.
        _firewall: Option<FirewallRules>,
    }

    impl IcmpSocket {
        pub(in super::super) fn local_addr(&self) -> SocketAddr {
            self.local
        }

        /// Builds one echo and sends it to `dest`.
        fn send_echo(
            &self,
            dest: Ipv4Addr,
            id: u16,
            request: bool,
            packet: &[u8],
        ) -> io::Result<usize> {
            let mut data = Vec::with_capacity(FRAMING + packet.len());
            data.extend_from_slice(&self.tag);
            data.push(if request { DIR_D2L } else { DIR_L2D });
            data.extend_from_slice(packet);
            let echo = IcmpEchoHeader {
                id,
                seq: self.seq.fetch_add(1, Ordering::Relaxed),
            };
            let itype = if request {
                Icmpv4Type::EchoRequest(echo)
            } else {
                Icmpv4Type::EchoReply(echo)
            };
            let header = Icmpv4Header::with_checksum(itype, &data);
            let head = header.to_bytes();
            let mut msg = Vec::with_capacity(head.len() + data.len());
            msg.extend_from_slice(&head);
            msg.extend_from_slice(&data);
            let to = SockAddr::from(SocketAddr::V4(SocketAddrV4::new(dest, 0)));
            self.fd.get_ref().send_to(&msg, &to)
        }

        /// Sends a sealed packet to the connected peer (dialer, as an Echo Request).
        pub(in super::super) fn try_send(&self, packet: &[u8]) -> io::Result<usize> {
            let peer = self.peer.ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotConnected, "icmp dialer has no peer")
            })?;
            self.send_echo(peer, self.echo_id, true, packet)
        }

        /// Sends a sealed packet to `peer` (listener, as an Echo Reply with the peer's id).
        pub(in super::super) fn try_send_to(
            &self,
            packet: &[u8],
            peer: SocketAddr,
        ) -> io::Result<usize> {
            let SocketAddr::V4(peer) = peer else {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "icmp is IPv4 only",
                ));
            };
            self.send_echo(*peer.ip(), peer.port(), false, packet)
        }

        /// Receives the next matching echo's sealed packet into `out`, with its peer.
        async fn recv_echo(&self, out: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            // Dialer wants replies from the listener; the listener wants requests.
            let (want_type, want_dir) = if self.peer.is_some() {
                (ECHO_REPLY, DIR_L2D)
            } else {
                (ECHO_REQUEST, DIR_D2L)
            };
            let mut raw = [0u8; 4096];
            loop {
                let n = self.read_packet(&mut raw).await?;
                let pkt = &raw[..n];
                // The raw socket includes the IPv4 header; skip it to reach the ICMP.
                let Some(ihl) = pkt.first().map(|b| (b & 0x0f) as usize * 4) else {
                    continue;
                };
                if pkt.len() < ihl.max(20) {
                    continue;
                }
                let src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
                let Ok(icmp) = Icmpv4Slice::from_slice(&pkt[ihl..]) else {
                    continue;
                };
                if icmp.type_u8() != want_type {
                    continue;
                }
                let data = icmp.payload();
                if data.len() < FRAMING || data[..4] != self.tag || data[4] != want_dir {
                    continue;
                }
                let id = IcmpEchoHeader::from_bytes(icmp.bytes5to8()).id;
                // A dialer only accepts replies carrying its own session id.
                if self.peer.is_some() && id != self.echo_id {
                    continue;
                }
                let sealed = &data[FRAMING..];
                if sealed.len() > out.len() {
                    continue;
                }
                out[..sealed.len()].copy_from_slice(sealed);
                return Ok((sealed.len(), SocketAddr::V4(SocketAddrV4::new(src, id))));
            }
        }

        pub(in super::super) async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
            self.recv_echo(buf).await.map(|(n, _)| n)
        }

        pub(in super::super) async fn recv_from(
            &self,
            buf: &mut [u8],
        ) -> io::Result<(usize, SocketAddr)> {
            self.recv_echo(buf).await
        }

        /// One non-blocking `recv` driven by the reactor.
        async fn read_packet(&self, raw: &mut [u8]) -> io::Result<usize> {
            loop {
                let mut guard = self.fd.readable().await?;
                match guard.try_io(|inner| recv_once(inner.get_ref().as_raw_fd(), raw)) {
                    Ok(result) => return result,
                    Err(_would_block) => continue,
                }
            }
        }
    }

    /// A single non-blocking `recv(2)` on `fd`.
    fn recv_once(fd: std::os::fd::RawFd, buf: &mut [u8]) -> io::Result<usize> {
        // SAFETY: `buf` is a valid writable slice for `buf.len()` bytes.
        let n = unsafe {
            nix::libc::recv(
                fd,
                buf.as_mut_ptr().cast::<nix::libc::c_void>(),
                buf.len(),
                0,
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(n as usize)
    }

    /// Opens the raw ICMP socket shared by both roles.
    fn raw_socket(buffer: usize, dscp: Option<u8>) -> io::Result<Socket> {
        let socket =
            Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)).map_err(map_perm)?;
        socket.set_nonblocking(true)?;
        let _ = socket.set_recv_buffer_size(buffer);
        let _ = socket.set_send_buffer_size(buffer);
        if let Some(dscp) = dscp {
            let _ = socket.set_tos_v4(u32::from(dscp) << 2);
        }
        Ok(socket)
    }

    /// Maps the no-privilege `socket()` failure to a clear message.
    fn map_perm(e: io::Error) -> io::Error {
        if e.kind() == io::ErrorKind::PermissionDenied {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "transport \"icmp\" needs root or CAP_NET_RAW",
            )
        } else {
            e
        }
    }

    /// A non-zero firewall mark from the tunnel's tag, so the listener's own replies are
    /// exempt from the rule that drops the kernel's automatic ones.
    fn mark_of(tag: [u8; 4]) -> u32 {
        let m = u32::from_le_bytes(tag);
        if m == 0 {
            1
        } else {
            m
        }
    }

    pub(in super::super) fn open_dialer(
        params: &IcmpParams,
        peer: SocketAddr,
        buffer: usize,
        dscp: Option<u8>,
    ) -> io::Result<CarrierSocket> {
        let SocketAddr::V4(peer) = peer else {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "transport \"icmp\" is IPv4 only",
            ));
        };
        let socket = raw_socket(buffer, dscp)?;
        let _ = socket.set_mark(mark_of(params.tag));
        let echo_id = random_id()?;
        // Under a default-DROP INPUT policy, accept the replies we expect.
        let firewall = params.manage_firewall.then(|| {
            FirewallRules::install(
                format!("kariz-icmp-dial-{}", unique_suffix()),
                vec![Rule::new(
                    "filter",
                    "INPUT",
                    &["-p", "icmp", "--icmp-type", "echo-reply", "-j", "ACCEPT"],
                )],
            )
        });
        let local = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));
        Ok(CarrierSocket::Icmp(IcmpSocket {
            fd: AsyncFd::new(socket)?,
            tag: params.tag,
            echo_id,
            peer: Some(*peer.ip()),
            local,
            seq: AtomicU16::new(0),
            _firewall: firewall,
        }))
    }

    pub(in super::super) fn open_listener(
        params: &IcmpParams,
        local: SocketAddr,
        buffer: usize,
        dscp: Option<u8>,
    ) -> io::Result<CarrierSocket> {
        if !local.is_ipv4() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "transport \"icmp\" is IPv4 only",
            ));
        }
        let socket = raw_socket(buffer, dscp)?;
        // Bind to the listen address so only echoes to it are received (and so two
        // listeners on one host can coexist by address).
        if let IpAddr::V4(ip) = local.ip() {
            if !ip.is_unspecified() {
                socket.bind(&SockAddr::from(SocketAddr::V4(SocketAddrV4::new(ip, 0))))?;
            }
        }
        let marked = socket.set_mark(mark_of(params.tag)).is_ok();
        let firewall = params.manage_firewall.then(|| {
            let tag = format!("kariz-icmp-{}-{}", local.port(), unique_suffix());
            let mut rules = vec![Rule::new(
                "filter",
                "INPUT",
                &["-p", "icmp", "--icmp-type", "echo-request", "-j", "ACCEPT"],
            )];
            if marked {
                // Drop the kernel's automatic echo replies (mark 0); our own carry the
                // mark and fall through. Without the mark we cannot tell them apart, so we
                // leave the kernel replies alone (the dir byte still keeps us correct).
                let mark = mark_of(params.tag).to_string();
                rules.push(Rule::new(
                    "filter",
                    "OUTPUT",
                    &[
                        "-p", "icmp", "--icmp-type", "echo-reply", "-m", "mark", "!", "--mark",
                        &mark, "-j", "DROP",
                    ],
                ));
            } else {
                warn!("icmp: could not set a firewall mark (needs CAP_NET_ADMIN); the kernel's automatic echo replies are left in place");
            }
            FirewallRules::install(tag, rules)
        });
        if let Some(fw) = &firewall {
            if !fw.is_installed() {
                warn!("icmp: iptables rules not installed; the tunnel still works but pays the kernel's extra echo reply");
            } else {
                debug!(port = local.port(), "icmp: firewall rules installed");
            }
        }
        Ok(CarrierSocket::Icmp(IcmpSocket {
            fd: AsyncFd::new(socket)?,
            tag: params.tag,
            echo_id: 0,
            peer: None,
            local,
            seq: AtomicU16::new(0),
            _firewall: firewall,
        }))
    }

    /// A random, non-zero session echo id.
    fn random_id() -> io::Result<u16> {
        let b = crate::crypto::random_bytes::<2>()?;
        Ok(u16::from_le_bytes(b).max(1))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::crypto::Psk;

        /// Derives the tag the way `Carrier::from_tunnel` does.
        fn tag_of(token: &str) -> [u8; 4] {
            let key = Psk::new(token).subkey(crate::transport::kcp::carrier::ICMP_TAG_CONTEXT);
            [key[0], key[1], key[2], key[3]]
        }

        /// The tag is a stable 4-byte function of the token.
        #[test]
        fn tag_is_stable_four_bytes() {
            assert_eq!(
                tag_of("topsecret"),
                tag_of("topsecret"),
                "same token, same tag"
            );
            assert_ne!(
                tag_of("topsecret"),
                tag_of("another"),
                "different token, different tag"
            );
            assert_eq!(tag_of("topsecret").len(), 4);
        }

        /// The carrier parsed from an icmp tunnel stores exactly that tag.
        #[test]
        fn from_tunnel_stores_the_tag() {
            let carrier = crate::transport::kcp::Carrier::from_tunnel(&tunnel("icmp", "topsecret"));
            match carrier {
                crate::transport::kcp::Carrier::Icmp(p) => assert_eq!(p.tag, tag_of("topsecret")),
                _ => panic!("expected an icmp carrier"),
            }
        }

        /// A wrong-tag echo is dropped by the framing check before the cipher is reached.
        #[test]
        fn wrong_tag_is_rejected_before_cipher() {
            let tag = [1u8, 2, 3, 4];
            let good = {
                let mut d = Vec::new();
                d.extend_from_slice(&tag);
                d.push(DIR_D2L);
                d.extend_from_slice(b"sealed-kcp-bytes");
                d
            };
            // The listener-side acceptance test, mirrored from recv_echo.
            let accepts = |data: &[u8], want_dir: u8| {
                data.len() >= FRAMING && data[..4] == tag && data[4] == want_dir
            };
            assert!(accepts(&good, DIR_D2L));
            // Wrong tag.
            let mut bad = good.clone();
            bad[0] ^= 0xff;
            assert!(!accepts(&bad, DIR_D2L));
            // Wrong direction (the kernel's echoed-back copy of our own request).
            assert!(!accepts(&good, DIR_L2D));
            // Too short to even hold the framing.
            assert!(!accepts(&tag, DIR_D2L));
        }

        /// Build then parse an echo: the framing and sealed bytes round-trip, and the id
        /// that keys the listener's demux survives.
        #[tokio::test]
        async fn echo_build_parse_round_trip() {
            let data = {
                let mut d = Vec::new();
                d.extend_from_slice(&[9, 9, 9, 9]);
                d.push(DIR_L2D);
                d.extend_from_slice(b"a sealed KCP packet");
                d
            };
            let echo = IcmpEchoHeader { id: 0xbeef, seq: 7 };
            let header = Icmpv4Header::with_checksum(Icmpv4Type::EchoReply(echo), &data);
            let mut msg = header.to_bytes().to_vec();
            msg.extend_from_slice(&data);
            // Parse it back as the carrier would (after the IP header is stripped).
            let slice = Icmpv4Slice::from_slice(&msg).unwrap();
            assert_eq!(slice.type_u8(), ECHO_REPLY);
            assert_eq!(IcmpEchoHeader::from_bytes(slice.bytes5to8()).id, 0xbeef);
            assert_eq!(slice.payload(), &data[..]);
            assert_eq!(&slice.payload()[FRAMING..], b"a sealed KCP packet");
        }

        fn tunnel(transport: &str, token: &str) -> crate::config::TunnelConfig {
            toml::from_str(&format!(
                "transport = \"{transport}\"\ntoken = \"{token}\"\n"
            ))
            .expect("minimal tunnel config parses")
        }
    }
}
