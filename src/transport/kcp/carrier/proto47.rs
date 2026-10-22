//! The proto-47 / keyed-GRE carrier (the `[l3]` carrier `proto47`): the KCP stack ridden
//! inside raw IP protocol-47 packets, for the one trusted link where the low overhead or a
//! proto-47-only path matters. Linux + `CAP_NET_RAW`.
//!
//! Each already-sealed KCP packet is the payload of a minimal RFC 2890 **keyed GRE** packet:
//! `flags+version (2) | protocol type (2) | key (4) | sealed KCP packet`. Only the Key bit
//! (`0x2000`) is set, the protocol type is `0x0000` (an opaque Kariz payload, never a real
//! ethertype), and the 4-byte key is this tunnel's tag ([`super::Proto47Params::tag`], from
//! the token). A GRE packet whose key is not the tag — or that is not this exact keyed shape
//! — is dropped before the cipher is touched, so several proto47 tunnels share one host and a
//! foreign protocol-47 packet costs nothing.
//!
//! This is **not** bare cleartext GRE and does **not** interoperate with standard/kernel GRE:
//! the payload is Kariz's encrypted, authenticated framing. It also does not traverse NAT and
//! does not evade DPI — protocol 47 has no port and is identifiable on the wire. That is
//! accepted; the carrier exists for a trusted/uncensored point-to-point link.
//!
//! Unlike the ICMP carrier there is no kernel auto-reply for protocol 47, so there is no `dir`
//! byte: the dialer sends to a fixed peer IP and the listener answers each peer IP it hears
//! from. Protocol 47 has no port, so the `SocketAddr` carried through [`super`] uses port 0 —
//! the KCP conv id demultiplexes the (point-to-point) sessions. IPv4 only.
//!
//! A raw `AF_INET`/`SOCK_RAW`/`IPPROTO_GRE` socket is used. When `manage_firewall` is on, a
//! best-effort `-p gre -j ACCEPT` iptables rule is installed (RAII) so the carrier's packets
//! survive a default-DROP INPUT policy; without it the tunnel still works unless such a policy
//! blocks protocol 47.

#[cfg(not(all(feature = "rawlink", target_os = "linux")))]
use std::io;
#[cfg(not(all(feature = "rawlink", target_os = "linux")))]
use std::net::SocketAddr;

#[cfg(not(all(feature = "rawlink", target_os = "linux")))]
use super::CarrierSocket;

#[cfg(not(all(feature = "rawlink", target_os = "linux")))]
pub(super) fn open_dialer(
    _params: &super::Proto47Params,
    _peer: SocketAddr,
    _buffer: usize,
    _dscp: Option<u8>,
) -> io::Result<CarrierSocket> {
    Err(unsupported())
}

#[cfg(not(all(feature = "rawlink", target_os = "linux")))]
pub(super) fn open_listener(
    _params: &super::Proto47Params,
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
            "transport \"proto47\" is Linux-only",
        )
    } else {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "transport \"proto47\" is not built (enable the rawlink feature)",
        )
    }
}

#[cfg(all(feature = "rawlink", target_os = "linux"))]
pub(super) use imp::{open_dialer, open_listener, Proto47Socket};

#[cfg(all(feature = "rawlink", target_os = "linux"))]
mod imp {
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::os::fd::AsRawFd;

    use socket2::{Domain, Protocol, SockAddr, Socket, Type};
    use tokio::io::unix::AsyncFd;
    use tracing::{debug, warn};

    use super::super::{CarrierSocket, Proto47Params};
    use crate::transport::kcp::rawlink::{unique_suffix, FirewallRules, Rule};

    /// IP protocol number for GRE.
    const IPPROTO_GRE: i32 = 47;
    /// The Key-present bit of the GRE flags/version word (RFC 2890).
    const GRE_FLAG_KEY: u16 = 0x2000;
    /// Checksum and Sequence bits: either would add a word before the key, moving it off the
    /// fixed offset, so our keyed shape must have both clear.
    const GRE_FLAG_CSUM: u16 = 0x8000;
    const GRE_FLAG_SEQ: u16 = 0x1000;
    /// The payload type we put in the GRE header: an opaque Kariz payload, not a real
    /// ethertype (this is never standard GRE).
    const GRE_PROTO: u16 = 0x0000;
    /// `flags+version (2) | protocol (2) | key (4)` — a fixed 8 bytes, since only the Key bit
    /// is ever set.
    const GRE_HEADER_LEN: usize = 8;

    /// Builds the keyed-GRE packet whose payload is `sealed`.
    fn build_gre(tag: [u8; 4], sealed: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(GRE_HEADER_LEN + sealed.len());
        out.extend_from_slice(&GRE_FLAG_KEY.to_be_bytes());
        out.extend_from_slice(&GRE_PROTO.to_be_bytes());
        out.extend_from_slice(&tag);
        out.extend_from_slice(sealed);
        out
    }

    /// Parses a keyed-GRE packet (after the IP header), returning `(key, sealed payload)`, or
    /// `None` when it is not our fixed keyed shape (no Key bit, or a Checksum/Sequence word
    /// that would move the key, or too short).
    fn parse_gre(pkt: &[u8]) -> Option<([u8; 4], &[u8])> {
        if pkt.len() < GRE_HEADER_LEN {
            return None;
        }
        let flags = u16::from_be_bytes([pkt[0], pkt[1]]);
        if flags & GRE_FLAG_KEY == 0 || flags & (GRE_FLAG_CSUM | GRE_FLAG_SEQ) != 0 {
            return None;
        }
        let key = [pkt[4], pkt[5], pkt[6], pkt[7]];
        Some((key, &pkt[GRE_HEADER_LEN..]))
    }

    /// One raw proto-47 socket, as a dialer (sends to a fixed peer) or a listener (answers
    /// each peer it hears from).
    pub(in crate::transport::kcp) struct Proto47Socket {
        fd: AsyncFd<Socket>,
        tag: [u8; 4],
        /// Dialer: the peer to send to. Listener: `None`.
        peer: Option<Ipv4Addr>,
        /// The address reported by `local_addr` (listener side).
        local: SocketAddr,
        /// Kept alive for its RAII effect.
        _firewall: Option<FirewallRules>,
    }

    impl Proto47Socket {
        pub(in super::super) fn local_addr(&self) -> SocketAddr {
            self.local
        }

        /// Wraps `packet` in a keyed-GRE packet and sends it to `dest`.
        fn send_gre(&self, dest: Ipv4Addr, packet: &[u8]) -> io::Result<usize> {
            let msg = build_gre(self.tag, packet);
            let to = SockAddr::from(SocketAddr::V4(SocketAddrV4::new(dest, 0)));
            self.fd.get_ref().send_to(&msg, &to)
        }

        /// Sends a sealed packet to the connected peer (dialer side).
        pub(in super::super) fn try_send(&self, packet: &[u8]) -> io::Result<usize> {
            let peer = self.peer.ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotConnected, "proto47 dialer has no peer")
            })?;
            self.send_gre(peer, packet)
        }

        /// Sends a sealed packet to `peer` (listener side). Protocol 47 has no port, so only
        /// the IP is used.
        pub(in super::super) fn try_send_to(
            &self,
            packet: &[u8],
            peer: SocketAddr,
        ) -> io::Result<usize> {
            let SocketAddr::V4(peer) = peer else {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "proto47 is IPv4 only",
                ));
            };
            self.send_gre(*peer.ip(), packet)
        }

        /// Receives the next matching keyed-GRE packet's sealed payload into `out`, with the
        /// peer it came from (port 0).
        async fn recv_gre(&self, out: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            let mut raw = [0u8; 4096];
            loop {
                let n = self.read_packet(&mut raw).await?;
                let pkt = &raw[..n];
                // The raw socket includes the IPv4 header; skip it to reach the GRE packet.
                let Some(ihl) = pkt.first().map(|b| (b & 0x0f) as usize * 4) else {
                    continue;
                };
                if pkt.len() < ihl.max(20) {
                    continue;
                }
                let src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
                let Some((key, sealed)) = parse_gre(&pkt[ihl..]) else {
                    continue;
                };
                if key != self.tag {
                    continue;
                }
                if sealed.len() > out.len() {
                    continue;
                }
                out[..sealed.len()].copy_from_slice(sealed);
                return Ok((sealed.len(), SocketAddr::V4(SocketAddrV4::new(src, 0))));
            }
        }

        pub(in super::super) async fn recv_from(
            &self,
            buf: &mut [u8],
        ) -> io::Result<(usize, SocketAddr)> {
            self.recv_gre(buf).await
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

    /// Opens the raw proto-47 socket shared by both roles.
    fn raw_socket(buffer: usize, dscp: Option<u8>) -> io::Result<Socket> {
        let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::from(IPPROTO_GRE)))
            .map_err(map_perm)?;
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
                "transport \"proto47\" needs root or CAP_NET_RAW",
            )
        } else {
            e
        }
    }

    /// A non-zero firewall mark from the tunnel's tag, so a mark can distinguish this tunnel's
    /// own packets if a rule ever needs it (best-effort, like icmp).
    fn mark_of(tag: [u8; 4]) -> u32 {
        let m = u32::from_le_bytes(tag);
        if m == 0 {
            1
        } else {
            m
        }
    }

    /// Installs the best-effort `-p gre -j ACCEPT` rule (RAII) so the carrier's packets survive
    /// a default-DROP INPUT policy; it warns, but does not fail, when iptables is unavailable.
    fn install_firewall(port: u16) -> FirewallRules {
        let fw = FirewallRules::install(
            format!("kariz-proto47-{port}-{}", unique_suffix()),
            vec![Rule::new("filter", "INPUT", &["-p", "gre", "-j", "ACCEPT"])],
        );
        if fw.is_installed() {
            debug!(port, "proto47: firewall rule installed");
        } else {
            warn!("proto47: iptables rule not installed; the tunnel still works unless a default-DROP INPUT policy blocks protocol 47");
        }
        fw
    }

    pub(in super::super) fn open_dialer(
        params: &Proto47Params,
        peer: SocketAddr,
        buffer: usize,
        dscp: Option<u8>,
    ) -> io::Result<CarrierSocket> {
        let SocketAddr::V4(peer) = peer else {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "transport \"proto47\" is IPv4 only",
            ));
        };
        let socket = raw_socket(buffer, dscp)?;
        let _ = socket.set_mark(mark_of(params.tag));
        let firewall = params.manage_firewall.then(|| install_firewall(0));
        let local = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));
        Ok(CarrierSocket::Proto47(Proto47Socket {
            fd: AsyncFd::new(socket)?,
            tag: params.tag,
            peer: Some(*peer.ip()),
            local,
            _firewall: firewall,
        }))
    }

    pub(in super::super) fn open_listener(
        params: &Proto47Params,
        local: SocketAddr,
        buffer: usize,
        dscp: Option<u8>,
    ) -> io::Result<CarrierSocket> {
        if !local.is_ipv4() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "transport \"proto47\" is IPv4 only",
            ));
        }
        let socket = raw_socket(buffer, dscp)?;
        // Bind to the listen address so only packets to it are received (and so two listeners
        // on one host can coexist by address).
        if let IpAddr::V4(ip) = local.ip() {
            if !ip.is_unspecified() {
                socket.bind(&SockAddr::from(SocketAddr::V4(SocketAddrV4::new(ip, 0))))?;
            }
        }
        let _ = socket.set_mark(mark_of(params.tag));
        let firewall = params
            .manage_firewall
            .then(|| install_firewall(local.port()));
        Ok(CarrierSocket::Proto47(Proto47Socket {
            fd: AsyncFd::new(socket)?,
            tag: params.tag,
            peer: None,
            local,
            _firewall: firewall,
        }))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::crypto::Psk;

        /// Derives the tag the way `Carrier::from_tunnel` does.
        fn tag_of(token: &str) -> [u8; 4] {
            let key = Psk::new(token).subkey(crate::transport::kcp::carrier::PROTO47_TAG_CONTEXT);
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

        /// The carrier parsed from a proto47 tunnel stores exactly that tag.
        #[test]
        fn from_tunnel_stores_the_tag() {
            let carrier =
                crate::transport::kcp::Carrier::from_tunnel(&tunnel("proto47", "topsecret"));
            match carrier {
                crate::transport::kcp::Carrier::Proto47(p) => {
                    assert_eq!(p.tag, tag_of("topsecret"))
                }
                _ => panic!("expected a proto47 carrier"),
            }
        }

        /// Build then parse a keyed-GRE packet: the header and sealed bytes round-trip.
        #[test]
        fn gre_build_parse_round_trip() {
            let tag = [9u8, 9, 9, 9];
            let sealed = b"a sealed KCP packet";
            let msg = build_gre(tag, sealed);
            assert_eq!(msg.len(), GRE_HEADER_LEN + sealed.len());
            // The flags/version word has only the Key bit set, version 0.
            assert_eq!(u16::from_be_bytes([msg[0], msg[1]]), GRE_FLAG_KEY);
            let (key, payload) = parse_gre(&msg).expect("our own packet parses");
            assert_eq!(key, tag);
            assert_eq!(payload, &sealed[..]);
        }

        /// A wrong-key GRE packet is rejected by the framing check before the cipher, and so
        /// are the non-keyed shapes (no Key bit, or a Checksum/Sequence word present).
        #[test]
        fn wrong_tag_is_rejected_before_cipher() {
            let tag = [1u8, 2, 3, 4];
            let good = build_gre(tag, b"sealed-kcp-bytes");
            let (key, _) = parse_gre(&good).expect("keyed shape parses");
            assert_eq!(key, tag);

            // Wrong key: parses, but the key does not match the tag (dropped by recv_gre).
            let mut wrong = good.clone();
            wrong[4] ^= 0xff;
            assert_eq!(parse_gre(&wrong).map(|(k, _)| k), Some([0xfe, 2, 3, 4]));

            // No Key bit: not our shape at all.
            let mut no_key = good.clone();
            no_key[0] = 0x00;
            no_key[1] = 0x00;
            assert!(parse_gre(&no_key).is_none(), "Key bit required");

            // A Checksum word would move the key off the fixed offset: rejected.
            let mut with_csum = good.clone();
            with_csum[0] |= 0x80; // set the Checksum bit as well
            assert!(parse_gre(&with_csum).is_none(), "checksum shape rejected");

            // Too short to even hold the header.
            assert!(parse_gre(&tag).is_none(), "short packet rejected");
        }

        fn tunnel(transport: &str, token: &str) -> crate::config::TunnelConfig {
            toml::from_str(&format!(
                "transport = \"{transport}\"\ntoken = \"{token}\"\n"
            ))
            .expect("minimal tunnel config parses")
        }
    }
}
