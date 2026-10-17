//! The fake-TCP carrier (`transport = "faketcp"`, BackPack's `pck`): the KCP stack ridden
//! inside crafted TCP segments that bypass the kernel's TCP stack. Linux + `CAP_NET_RAW`.
//!
//! Each already-sealed KCP packet is the payload of a TCP segment. The segments carry the
//! machine's **real** source address and real ports — nothing is forged; what is absent is
//! the kernel's connection state, so neither end runs a TCP state machine. Segments are
//! received through an `AF_PACKET`/`SOCK_DGRAM` socket (upstream of conntrack and
//! netfilter, so they arrive even though no kernel socket owns the port) and sent by
//! building a whole IPv4 + TCP packet and writing it through a raw `IP_HDRINCL` socket.
//!
//! The dialer's source port is derived from the token ([`source_port`]) so it is stable
//! across reconnects, which keeps one firewall rule per tunnel. The listener's demux key
//! is `(peer IP, peer port)`, the same shape as the UDP carrier. The seq/ack/window and a
//! TCP timestamp option are kept realistic; [`FlagPattern`] chooses the flag bits each end
//! sets. When `manage_firewall` is on, each end installs best-effort iptables rules that
//! drop the kernel's RSTs on its port and mark it `NOTRACK`, removed on drop.
//!
//! Loopback caveat: over `lo` the crafted packet is transmitted and immediately received
//! on the same interface, so the e2e tests exercise `AF_PACKET` on `lo` and the RST-drop
//! rule but not a real two-host L2 path; real-NIC validation is left to a soak test.

#[cfg(not(all(feature = "rawlink", target_os = "linux")))]
use std::io;
#[cfg(not(all(feature = "rawlink", target_os = "linux")))]
use std::net::SocketAddr;

use crate::crypto::handshake::Key;

#[cfg(not(all(feature = "rawlink", target_os = "linux")))]
use super::CarrierSocket;

/// The dialer's source port, mapped from the token subkey into the ephemeral range so it
/// is stable across reconnects and collides with no well-known service.
pub(super) fn source_port(key: &Key) -> u16 {
    /// Linux's default ephemeral range (`net.ipv4.ip_local_port_range`).
    const LOW: u16 = 32768;
    const SPAN: u16 = 60999 - LOW + 1;
    LOW + u16::from_le_bytes([key[0], key[1]]) % SPAN
}

/// Which TCP flag bits a segment carries, cycled per segment. Each end sets only its own
/// pattern; the carrier does not inspect the peer's flags.
// The fields and `next` are consumed only by the raw-socket send path; without it (a
// non-Linux or no-rawlink build) the pattern is still parsed and stored but never read.
#[cfg_attr(not(all(feature = "rawlink", target_os = "linux")), allow(dead_code))]
#[derive(Debug, Clone)]
pub struct FlagPattern {
    combos: Vec<FlagCombo>,
    next: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

/// One segment's flag bits.
#[cfg_attr(not(all(feature = "rawlink", target_os = "linux")), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct FlagCombo {
    pub psh: bool,
    pub ack: bool,
    pub urg: bool,
}

#[cfg_attr(not(all(feature = "rawlink", target_os = "linux")), allow(dead_code))]
impl FlagPattern {
    /// Parses a validated flag string (`A`, `PA`, `PA,A`, `PA,A,PA,PAU`) into the sequence
    /// of flag combos it cycles through. A malformed string (validation has rejected those)
    /// falls back to a plain PSH+ACK.
    pub fn parse(s: &str) -> Self {
        let combos: Vec<FlagCombo> = s
            .split(',')
            .map(str::trim)
            .filter(|tok| !tok.is_empty())
            .map(|tok| FlagCombo {
                psh: tok.contains('P'),
                ack: tok.contains('A'),
                urg: tok.contains('U'),
            })
            .collect();
        let combos = if combos.is_empty() {
            vec![FlagCombo {
                psh: true,
                ack: true,
                urg: false,
            }]
        } else {
            combos
        };
        Self {
            combos,
            next: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }

    /// The flag combo for the next segment, advancing the cycle.
    pub(super) fn next(&self) -> FlagCombo {
        let i = self.next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.combos[i % self.combos.len()]
    }
}

#[cfg(not(all(feature = "rawlink", target_os = "linux")))]
pub(super) fn open_dialer(
    _params: &super::FaketcpParams,
    _peer: SocketAddr,
    _buffer: usize,
    _dscp: Option<u8>,
) -> io::Result<CarrierSocket> {
    Err(unsupported())
}

#[cfg(not(all(feature = "rawlink", target_os = "linux")))]
pub(super) fn open_listener(
    _params: &super::FaketcpParams,
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
            "transport \"faketcp\" is Linux-only",
        )
    } else {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "transport \"faketcp\" is not built (enable the rawlink feature)",
        )
    }
}

#[cfg(all(feature = "rawlink", target_os = "linux"))]
pub(super) use imp::{open_dialer, open_listener, FaketcpSocket};

#[cfg(all(feature = "rawlink", target_os = "linux"))]
mod imp {
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Instant;

    use etherparse::{NetSlice, PacketBuilder, SlicedPacket, TcpOptionElement, TransportSlice};
    use socket2::{Domain, Protocol, SockAddr, Socket, Type};
    use tokio::io::unix::AsyncFd;
    use tracing::{debug, warn};

    use super::super::{CarrierSocket, FaketcpParams};
    use super::{FlagCombo, FlagPattern};
    use crate::transport::kcp::rawlink::{netinfo, unique_suffix, FirewallRules, Rule};

    /// A realistic receive window advertised in every segment.
    const WINDOW: u16 = 65535;
    const TTL: u8 = 64;

    /// One fake-TCP endpoint: an `AF_PACKET` receive socket and a raw-IP send socket, plus
    /// the loosely-kept TCP bookkeeping that makes the segments look real.
    pub(in crate::transport::kcp) struct FaketcpSocket {
        recv: AsyncFd<OwnedFd>,
        send: Socket,
        local_ip: Ipv4Addr,
        local_port: u16,
        /// Dialer: the fixed peer. Listener: `None`.
        peer: Option<SocketAddrV4>,
        flags: FlagPattern,
        /// Our next sequence number (a random ISN plus the bytes sent).
        seq: AtomicU32,
        /// The highest peer sequence+length seen, acknowledged back.
        ack: AtomicU32,
        start: Instant,
        local: SocketAddr,
        _firewall: Option<FirewallRules>,
    }

    impl FaketcpSocket {
        pub(in super::super) fn local_addr(&self) -> SocketAddr {
            self.local
        }

        /// Builds and sends one TCP segment carrying `payload` from `local_port` to `dst`.
        fn send_segment(&self, dst: SocketAddrV4, payload: &[u8]) -> io::Result<usize> {
            let seq = self.seq.fetch_add(payload.len() as u32, Ordering::Relaxed);
            let ack = self.ack.load(Ordering::Relaxed);
            let tsval = self.start.elapsed().as_millis() as u32;
            let combo = self.flags.next();
            let packet = build_segment(
                self.local_ip,
                *dst.ip(),
                self.local_port,
                dst.port(),
                seq,
                ack,
                combo,
                tsval,
                payload,
            );
            let to = SockAddr::from(SocketAddr::V4(SocketAddrV4::new(*dst.ip(), 0)));
            self.send.send_to(&packet, &to)
        }

        pub(in super::super) fn try_send(&self, packet: &[u8]) -> io::Result<usize> {
            let peer = self.peer.ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotConnected, "faketcp dialer has no peer")
            })?;
            self.send_segment(peer, packet)
        }

        pub(in super::super) fn try_send_to(
            &self,
            packet: &[u8],
            peer: SocketAddr,
        ) -> io::Result<usize> {
            let SocketAddr::V4(peer) = peer else {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "faketcp is IPv4 only",
                ));
            };
            self.send_segment(peer, packet)
        }

        /// Receives the next segment addressed to our port, returning its payload and the
        /// peer it came from.
        async fn recv_segment(&self, out: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            let mut raw = [0u8; 4096];
            loop {
                let n = self.read_packet(&mut raw).await?;
                let Some((src, sport, dport, seq, payload)) = parse_segment(&raw[..n]) else {
                    continue;
                };
                // Only inbound segments addressed to our port, with a payload to deliver.
                if dport != self.local_port || payload.is_empty() {
                    continue;
                }
                // A dialer only accepts its connected peer.
                if let Some(peer) = self.peer {
                    if src != *peer.ip() || sport != peer.port() {
                        continue;
                    }
                }
                self.ack
                    .fetch_max(seq.wrapping_add(payload.len() as u32), Ordering::Relaxed);
                if payload.len() > out.len() {
                    continue;
                }
                out[..payload.len()].copy_from_slice(payload);
                return Ok((payload.len(), SocketAddr::V4(SocketAddrV4::new(src, sport))));
            }
        }

        pub(in super::super) async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
            self.recv_segment(buf).await.map(|(n, _)| n)
        }

        pub(in super::super) async fn recv_from(
            &self,
            buf: &mut [u8],
        ) -> io::Result<(usize, SocketAddr)> {
            self.recv_segment(buf).await
        }

        async fn read_packet(&self, raw: &mut [u8]) -> io::Result<usize> {
            loop {
                let mut guard = self.recv.readable().await?;
                match guard.try_io(|inner| recv_once(inner.get_ref().as_raw_fd(), raw)) {
                    Ok(result) => return result,
                    Err(_would_block) => continue,
                }
            }
        }
    }

    /// Builds one IPv4 + TCP segment (with checksums and a timestamp option) ready for a
    /// raw `IP_HDRINCL` socket.
    #[allow(clippy::too_many_arguments)]
    fn build_segment(
        src: Ipv4Addr,
        dst: Ipv4Addr,
        sport: u16,
        dport: u16,
        seq: u32,
        ack: u32,
        combo: FlagCombo,
        tsval: u32,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut tcp =
            PacketBuilder::ipv4(src.octets(), dst.octets(), TTL).tcp(sport, dport, seq, WINDOW);
        if combo.ack {
            tcp = tcp.ack(ack);
        }
        if combo.psh {
            tcp = tcp.psh();
        }
        if combo.urg {
            tcp = tcp.urg(0);
        }
        let tcp = tcp
            .options(&[TcpOptionElement::Timestamp(tsval, 0)])
            .expect("a timestamp option is always valid");
        let mut out = Vec::with_capacity(tcp.size(payload.len()));
        tcp.write(&mut out, payload)
            .expect("writing to a Vec cannot fail");
        out
    }

    /// Parses an IPv4 + TCP packet, returning `(src, src port, dst port, seq, payload)`.
    fn parse_segment(packet: &[u8]) -> Option<(Ipv4Addr, u16, u16, u32, &[u8])> {
        let sliced = SlicedPacket::from_ip(packet).ok()?;
        let src = match sliced.net? {
            NetSlice::Ipv4(ip) => ip.header().source_addr(),
            _ => return None,
        };
        match sliced.transport? {
            TransportSlice::Tcp(tcp) => Some((
                src,
                tcp.source_port(),
                tcp.destination_port(),
                tcp.sequence_number(),
                tcp.payload(),
            )),
            _ => None,
        }
    }

    /// A single non-blocking `recv(2)` on `fd`.
    fn recv_once(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
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

    /// Opens an `AF_PACKET`/`SOCK_DGRAM` socket bound to `ifindex`, receiving IPv4 frames.
    fn packet_socket(ifindex: u32, buffer: usize) -> io::Result<OwnedFd> {
        let proto = (nix::libc::ETH_P_IP as u16).to_be();
        // SAFETY: a plain socket(2) call; the fd is adopted by OwnedFd on success.
        let fd = unsafe {
            nix::libc::socket(
                nix::libc::AF_PACKET,
                nix::libc::SOCK_DGRAM,
                i32::from(proto),
            )
        };
        if fd < 0 {
            return Err(map_perm(io::Error::last_os_error()));
        }
        // SAFETY: `fd` is a fresh, owned descriptor.
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        // SAFETY: zeroed sockaddr_ll is a valid (empty) address; fields set below.
        let mut sll: nix::libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        sll.sll_family = nix::libc::AF_PACKET as u16;
        sll.sll_protocol = proto;
        sll.sll_ifindex = ifindex as i32;
        // SAFETY: binding a correctly-sized sockaddr_ll for this packet socket.
        let rc = unsafe {
            nix::libc::bind(
                owned.as_raw_fd(),
                std::ptr::addr_of!(sll).cast::<nix::libc::sockaddr>(),
                std::mem::size_of::<nix::libc::sockaddr_ll>() as nix::libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        set_nonblocking(owned.as_raw_fd())?;
        set_recv_buffer(owned.as_raw_fd(), buffer);
        Ok(owned)
    }

    /// Opens the raw `IP_HDRINCL` TCP send socket.
    fn send_socket(dscp: Option<u8>, mark: u32) -> io::Result<Socket> {
        let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::TCP)).map_err(map_perm)?;
        socket.set_header_included_v4(true)?;
        socket.set_nonblocking(true)?;
        let _ = socket.set_mark(mark);
        if let Some(dscp) = dscp {
            let _ = socket.set_tos_v4(u32::from(dscp) << 2);
        }
        Ok(socket)
    }

    fn set_nonblocking(fd: RawFd) -> io::Result<()> {
        // SAFETY: fcntl on an owned descriptor.
        let flags = unsafe { nix::libc::fcntl(fd, nix::libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: as above.
        let rc = unsafe { nix::libc::fcntl(fd, nix::libc::F_SETFL, flags | nix::libc::O_NONBLOCK) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn set_recv_buffer(fd: RawFd, buffer: usize) {
        let size = buffer as nix::libc::c_int;
        // SAFETY: SO_RCVBUF takes an int; best-effort, errors ignored.
        unsafe {
            nix::libc::setsockopt(
                fd,
                nix::libc::SOL_SOCKET,
                nix::libc::SO_RCVBUF,
                std::ptr::addr_of!(size).cast::<nix::libc::c_void>(),
                std::mem::size_of::<nix::libc::c_int>() as nix::libc::socklen_t,
            );
        }
    }

    fn map_perm(e: io::Error) -> io::Error {
        if e.kind() == io::ErrorKind::PermissionDenied {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "transport \"faketcp\" needs root or CAP_NET_RAW",
            )
        } else {
            e
        }
    }

    /// The iptables rules a fake-TCP endpoint keeps while it runs: drop the kernel's RSTs
    /// on our port (no socket owns it, so the kernel would reset every segment) and mark
    /// the port `NOTRACK` so conntrack does not treat our stateless segments as invalid.
    fn firewall_rules(port: u16) -> FirewallRules {
        let tag = format!("kariz-faketcp-{port}-{}", unique_suffix());
        let port = port.to_string();
        let rules = vec![
            Rule::new(
                "filter",
                "OUTPUT",
                &[
                    "-p",
                    "tcp",
                    "--sport",
                    &port,
                    "--tcp-flags",
                    "RST",
                    "RST",
                    "-j",
                    "DROP",
                ],
            ),
            Rule::new(
                "raw",
                "PREROUTING",
                &["-p", "tcp", "--dport", &port, "-j", "NOTRACK"],
            ),
            Rule::new(
                "raw",
                "OUTPUT",
                &["-p", "tcp", "--sport", &port, "-j", "NOTRACK"],
            ),
        ];
        FirewallRules::install(tag, rules)
    }

    /// A non-zero firewall mark from the source port, so our own segments are identifiable.
    fn mark_of(port: u16) -> u32 {
        0x6b61_0000 | u32::from(port)
    }

    pub(in super::super) fn open_dialer(
        params: &FaketcpParams,
        peer: SocketAddr,
        buffer: usize,
        dscp: Option<u8>,
    ) -> io::Result<CarrierSocket> {
        let SocketAddr::V4(peer) = peer else {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "transport \"faketcp\" is IPv4 only",
            ));
        };
        if let Some(mac) = params.gateway_mac {
            debug!(
                ?mac,
                "faketcp: gateway_mac override is not used by the raw-IP send path"
            );
        }
        let local_ip = netinfo::local_addr_for(*peer.ip())?;
        let (iface, ifindex) = netinfo::egress_interface(local_ip, &params.interface)?;
        debug!(%local_ip, iface, port = params.source_port, "faketcp dialer egress");
        let socket = build(
            params,
            local_ip,
            params.source_port,
            Some(peer),
            ifindex,
            buffer,
            dscp,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
        )?;
        Ok(socket)
    }

    pub(in super::super) fn open_listener(
        params: &FaketcpParams,
        local: SocketAddr,
        buffer: usize,
        dscp: Option<u8>,
    ) -> io::Result<CarrierSocket> {
        let IpAddr::V4(listen_ip) = local.ip() else {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "transport \"faketcp\" is IPv4 only",
            ));
        };
        // A bound IP is the reply source; for an unspecified bind, use the default-route
        // source address so replies carry a routable address.
        let local_ip = if listen_ip.is_unspecified() {
            netinfo::local_addr_for(Ipv4Addr::new(1, 1, 1, 1))?
        } else {
            listen_ip
        };
        let (iface, ifindex) = netinfo::egress_interface(local_ip, &params.interface)?;
        debug!(%local_ip, iface, port = local.port(), "faketcp listener egress");
        build(
            params,
            local_ip,
            local.port(),
            None,
            ifindex,
            buffer,
            dscp,
            local,
        )
    }

    /// Shared endpoint construction for both roles.
    #[allow(clippy::too_many_arguments)]
    fn build(
        params: &FaketcpParams,
        local_ip: Ipv4Addr,
        local_port: u16,
        peer: Option<SocketAddrV4>,
        ifindex: u32,
        buffer: usize,
        dscp: Option<u8>,
        local: SocketAddr,
    ) -> io::Result<CarrierSocket> {
        let recv = packet_socket(ifindex, buffer)?;
        let send = send_socket(dscp, mark_of(local_port))?;
        let firewall = params.manage_firewall.then(|| firewall_rules(local_port));
        if let Some(fw) = &firewall {
            if !fw.is_installed() {
                warn!(port = local_port, "faketcp: iptables rules not installed; the tunnel still runs but is unreliable under load");
            } else {
                debug!(port = local_port, "faketcp: firewall rules installed");
            }
        }
        let isn = u32::from_le_bytes(crate::crypto::random_bytes::<4>()?);
        Ok(CarrierSocket::Faketcp(FaketcpSocket {
            recv: AsyncFd::new(recv)?,
            send,
            local_ip,
            local_port,
            peer,
            flags: params.flags.clone(),
            seq: AtomicU32::new(isn),
            ack: AtomicU32::new(0),
            start: Instant::now(),
            local,
            _firewall: firewall,
        }))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// Build then parse a segment: the five-tuple and payload round-trip.
        #[test]
        fn segment_build_parse_round_trip() {
            let combo = FlagCombo {
                psh: true,
                ack: true,
                urg: false,
            };
            let payload = b"a sealed KCP packet rides here";
            let pkt = build_segment(
                Ipv4Addr::new(10, 0, 0, 1),
                Ipv4Addr::new(10, 0, 0, 2),
                40000,
                4443,
                123456,
                654321,
                combo,
                99,
                payload,
            );
            let (src, sport, dport, seq, got) = parse_segment(&pkt).expect("parses");
            assert_eq!(src, Ipv4Addr::new(10, 0, 0, 1));
            assert_eq!(sport, 40000);
            assert_eq!(dport, 4443);
            assert_eq!(seq, 123456);
            assert_eq!(got, payload);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_port_is_stable_and_in_range() {
        let key = [7u8; 32];
        let a = source_port(&key);
        let b = source_port(&key);
        assert_eq!(a, b, "same key, same port");
        assert!(
            (32768..=60999).contains(&a),
            "port {a} in the ephemeral range"
        );
        // A different key gives a different port (with overwhelming probability).
        let mut key2 = key;
        key2[0] = 8;
        assert_ne!(source_port(&key2), a);
    }

    #[test]
    fn flag_pattern_parses_and_cycles() {
        let p = FlagPattern::parse("PA,A,PA,PAU");
        let seq: Vec<_> = (0..5).map(|_| p.next()).collect();
        assert_eq!(
            seq[0],
            FlagCombo {
                psh: true,
                ack: true,
                urg: false
            }
        );
        assert_eq!(
            seq[1],
            FlagCombo {
                psh: false,
                ack: true,
                urg: false
            }
        );
        assert_eq!(
            seq[2],
            FlagCombo {
                psh: true,
                ack: true,
                urg: false
            }
        );
        assert_eq!(
            seq[3],
            FlagCombo {
                psh: true,
                ack: true,
                urg: true
            }
        );
        // Cycles back to the first combo.
        assert_eq!(seq[4], seq[0]);

        // The single-flag and default patterns.
        assert_eq!(
            FlagPattern::parse("A").next(),
            FlagCombo {
                psh: false,
                ack: true,
                urg: false
            }
        );
        assert_eq!(
            FlagPattern::parse("").next(),
            FlagCombo {
                psh: true,
                ack: true,
                urg: false
            },
            "empty falls back to PSH+ACK"
        );
    }
}
