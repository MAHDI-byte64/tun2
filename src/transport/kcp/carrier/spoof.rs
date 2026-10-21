//! The source-spoofing carrier (`transport = "spoof"`): the KCP stack ridden inside crafted
//! packets whose **source IP is forged** and rotated from a pool, for mutual IP spoofing
//! that blends into ordinary traffic and defeats stateful DPI. Linux + `CAP_NET_RAW`.
//!
//! Each already-sealed KCP packet is wrapped in a packet of the chosen shape
//! ([`crate::config::SpoofShape`]: `udp`, `tcp`, `icmp`, `gre`, `ipip` or `proto58`) whose
//! IPv4 source address is taken from the configured pool, advanced round-robin on every
//! send. The destination is always the peer's *real* address. Both ends forge, so neither
//! can learn the other from the (forged) packets it receives — each is told the peer's real
//! address out of band (the dialer dials it; the acceptor is given it in
//! `[tunnel.spoof] peer`, which the panel fills in). That makes a spoof tunnel strictly
//! point-to-point.
//!
//! Framing inside the shape's payload is `tag (4) | dir (1) | sealed KCP packet`:
//!
//! * `tag` is this tunnel's 4-byte tag (from the token). A packet whose first four payload
//!   bytes are not the tag is dropped before the cipher, so several spoof tunnels share a
//!   host and foreign traffic costs nothing.
//! * `dir` says which way the packet goes (`D2L` dialer→acceptor, `L2D` acceptor→dialer).
//!   Each end accepts only the opposite direction, which drops both our own packets (on a
//!   kernel without `PACKET_IGNORE_OUTGOING`) and the kernel's automatic ICMP echo reply to
//!   a forged request (it copies our data, so it carries our tag).
//!
//! Packets are received through an `AF_PACKET`/`SOCK_DGRAM` socket (upstream of conntrack
//! and netfilter, so they arrive even though the source is forged and no kernel socket owns
//! the port) and sent by building a whole IPv4 packet and writing it through a raw
//! `IP_HDRINCL` socket (the kernel keeps a non-zero source address, which is what lets the
//! forged source go out). `PACKET_IGNORE_OUTGOING` is set best-effort so our own sends are
//! not captured.
//!
//! The port-bearing shapes (`udp`, `tcp`) key their demux on the destination port: the
//! dialer's source port is derived from the token (stable across reconnects), the
//! acceptor's is its listen port, and each side accepts packets addressed to its own port.
//! The portless shapes (`icmp`, `gre`, `ipip`, `proto58`) key on tag + dir alone. Either
//! way the carrier reports a single, stable synthetic peer to [`super`], so the existing
//! `(peer, conv)` conversation demux is unchanged. IPv4 only.
//!
//! This evades DPI by rotating the source and riding an innocuous protocol, but it needs a
//! network that does **not** filter spoofed egress (no BCP38 / uRPF on the path). Where the
//! path drops forged-source packets the tunnel will not establish; the `kariz spooftest`
//! tool finds which source addresses survive.

#[cfg(not(all(feature = "rawlink", target_os = "linux")))]
use std::io;
#[cfg(not(all(feature = "rawlink", target_os = "linux")))]
use std::net::SocketAddr;

#[cfg(not(all(feature = "rawlink", target_os = "linux")))]
use super::CarrierSocket;

#[cfg(not(all(feature = "rawlink", target_os = "linux")))]
pub(super) fn open_dialer(
    _params: &super::SpoofParams,
    _peer: SocketAddr,
    _buffer: usize,
    _dscp: Option<u8>,
) -> io::Result<CarrierSocket> {
    Err(unsupported())
}

#[cfg(not(all(feature = "rawlink", target_os = "linux")))]
pub(super) fn open_listener(
    _params: &super::SpoofParams,
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
            "transport \"spoof\" is Linux-only",
        )
    } else {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "transport \"spoof\" is not built (enable the rawlink feature)",
        )
    }
}

#[cfg(all(feature = "rawlink", target_os = "linux"))]
pub(super) use imp::{open_dialer, open_listener, SpoofSocket};

#[cfg(all(feature = "rawlink", target_os = "linux"))]
mod imp {
    use std::cell::RefCell;
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::sync::atomic::{AtomicU16, AtomicU32, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Instant;

    use etherparse::{IpNumber, Ipv4Header, PacketBuilder, TcpOptionElement};
    use socket2::{Domain, Protocol, SockAddr, Socket, Type};
    use tokio::io::unix::AsyncFd;
    use tracing::{debug, warn};

    use super::super::{CarrierSocket, SpoofParams};
    use crate::config::SpoofShape;
    use crate::transport::kcp::rawlink::{netinfo, unique_suffix, FirewallRules, Rule};

    /// `dir` byte: a packet going dialer → acceptor.
    const DIR_D2L: u8 = 1;
    /// `dir` byte: a packet going acceptor → dialer.
    const DIR_L2D: u8 = 2;
    /// `tag (4) | dir (1)` before the sealed packet.
    const FRAMING: usize = 5;
    /// A realistic receive window advertised in every crafted TCP segment.
    const WINDOW: u16 = 65535;
    const TTL: u8 = 64;

    /// `setsockopt` level/option for `PACKET_IGNORE_OUTGOING` (not always in libc).
    const SOL_PACKET: nix::libc::c_int = 263;
    const PACKET_IGNORE_OUTGOING: nix::libc::c_int = 23;

    thread_local! {
        /// Per-thread scratch for the send hot path: the framed body and the finished
        /// packet, reused across sends so a steady stream allocates nothing. Each thread
        /// gets its own, so `&self` sends from different worker threads stay safe.
        static SCRATCH: RefCell<(Vec<u8>, Vec<u8>)> =
            const { RefCell::new((Vec::new(), Vec::new())) };
    }

    /// One source-spoofing endpoint: an `AF_PACKET` receive socket, a raw-IP send socket, a
    /// forged-source pool with a shared round-robin cursor, and the per-shape bookkeeping
    /// that keeps the crafted packets realistic.
    pub(in crate::transport::kcp) struct SpoofSocket {
        recv: AsyncFd<OwnedFd>,
        send: Socket,
        /// The shape this end forges on its sends.
        shape: SpoofShape,
        /// The shape this end accepts on receive (equal to `shape` unless the tunnel is
        /// asymmetric, where each direction uses a different shape).
        recv_shape: SpoofShape,
        pool: Arc<Vec<Ipv4Addr>>,
        cursor: Arc<AtomicUsize>,
        tag: [u8; 4],
        /// The direction byte this end stamps on its sends.
        dir_send: u8,
        /// The direction byte this end accepts.
        dir_recv: u8,
        /// Our own port (dialer: the token-derived port; acceptor: the listen port). For the
        /// port-bearing shapes an inbound packet must be addressed to it.
        local_port: u16,
        /// Dialer: the peer to send to (its real address, with the listen port). Acceptor:
        /// `None` (it answers the synthetic peer the driver echoes back).
        peer: Option<SocketAddrV4>,
        /// The stable address reported to [`super`] for every received packet, so the
        /// conversation demux sees one peer. Dialer: the real peer. Acceptor:
        /// `(peer real IP, token-derived dialer port)`.
        synthetic: SocketAddrV4,
        /// The address reported by `local_addr` (acceptor side).
        local: SocketAddr,
        /// Our TCP sequence number (random ISN + bytes sent), for the `tcp` shape.
        seq: AtomicU32,
        /// Highest peer TCP sequence+len seen, acknowledged back.
        ack: AtomicU32,
        /// Our ICMP echo identifier, for the `icmp` shape.
        echo_id: u16,
        /// Monotonic ICMP/IP sequence counter, for realism.
        seq16: AtomicU16,
        start: Instant,
        /// Kept alive for its RAII effect.
        _firewall: Option<FirewallRules>,
    }

    impl SpoofSocket {
        pub(in super::super) fn local_addr(&self) -> SocketAddr {
            self.local
        }

        /// The next forged source address, advancing the shared round-robin cursor.
        fn next_source(&self) -> Ipv4Addr {
            let i = self.cursor.fetch_add(1, Ordering::Relaxed);
            // `pool` is never empty (open_* rejects an empty pool).
            self.pool[i % self.pool.len()]
        }

        /// Builds and sends one crafted packet carrying `sealed` to `dst`, reusing per-thread
        /// scratch buffers so a steady stream of packets allocates nothing.
        fn send_to_dst(&self, dst: SocketAddrV4, sealed: &[u8]) -> io::Result<usize> {
            let src = self.next_source();
            let to = SockAddr::from(SocketAddr::V4(SocketAddrV4::new(*dst.ip(), 0)));
            SCRATCH.with(|cell| {
                let (body, packet) = &mut *cell.borrow_mut();
                body.clear();
                body.extend_from_slice(&self.tag);
                body.push(self.dir_send);
                body.extend_from_slice(sealed);
                packet.clear();
                self.build_into(packet, src, *dst.ip(), dst.port(), body);
                self.send.send_to(packet, &to)
            })
        }

        /// Builds the full IPv4 packet for this socket's shape into `out` (already cleared),
        /// from `src` to `dst:dport`, carrying `body` (`tag | dir | sealed`).
        fn build_into(
            &self,
            out: &mut Vec<u8>,
            src: Ipv4Addr,
            dst: Ipv4Addr,
            dport: u16,
            body: &[u8],
        ) {
            match self.shape {
                SpoofShape::Udp => {
                    PacketBuilder::ipv4(src.octets(), dst.octets(), TTL)
                        .udp(self.local_port, dport)
                        .write(out, body)
                        .expect("writing to a Vec cannot fail");
                }
                SpoofShape::Tcp => {
                    let seq = self.seq.fetch_add(body.len() as u32, Ordering::Relaxed);
                    let ack = self.ack.load(Ordering::Relaxed);
                    let tsval = self.start.elapsed().as_millis() as u32;
                    PacketBuilder::ipv4(src.octets(), dst.octets(), TTL)
                        .tcp(self.local_port, dport, seq, WINDOW)
                        .ack(ack)
                        .psh()
                        .options(&[TcpOptionElement::Timestamp(tsval, 0)])
                        .expect("a timestamp option is always valid")
                        .write(out, body)
                        .expect("writing to a Vec cannot fail");
                }
                SpoofShape::Icmp => {
                    let seq = self.seq16.fetch_add(1, Ordering::Relaxed);
                    PacketBuilder::ipv4(src.octets(), dst.octets(), TTL)
                        .icmpv4_echo_request(self.echo_id, seq)
                        .write(out, body)
                        .expect("writing to a Vec cannot fail");
                }
                SpoofShape::Gre | SpoofShape::Ipip | SpoofShape::Proto58 => {
                    build_raw_proto_into(out, self.shape.ip_protocol(), src, dst, body);
                }
            }
        }

        pub(in super::super) fn try_send(&self, packet: &[u8]) -> io::Result<usize> {
            let peer = self.peer.ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotConnected, "spoof dialer has no peer")
            })?;
            self.send_to_dst(peer, packet)
        }

        pub(in super::super) fn try_send_to(
            &self,
            packet: &[u8],
            peer: SocketAddr,
        ) -> io::Result<usize> {
            let SocketAddr::V4(peer) = peer else {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "spoof is IPv4 only",
                ));
            };
            self.send_to_dst(peer, packet)
        }

        /// Receives the next matching packet's sealed payload into `out`, with the stable
        /// synthetic peer.
        async fn recv_packet(&self, out: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            let mut raw = [0u8; 4096];
            loop {
                let n = self.read_packet(&mut raw).await?;
                let Some(body) = self.match_packet(&raw[..n]) else {
                    continue;
                };
                // `body` is `tag | dir | sealed`; the sealed packet follows the framing.
                let sealed = &body[FRAMING..];
                if sealed.len() > out.len() {
                    continue;
                }
                out[..sealed.len()].copy_from_slice(sealed);
                return Ok((sealed.len(), SocketAddr::V4(self.synthetic)));
            }
        }

        /// Returns the framed body (`tag | dir | sealed`) of a captured IPv4 packet when it
        /// is this tunnel's shape, tag and (inbound) direction, else `None`.
        fn match_packet<'a>(&self, pkt: &'a [u8]) -> Option<&'a [u8]> {
            let (ihl, proto) = ip_header(pkt)?;
            if proto != self.recv_shape.ip_protocol() {
                return None;
            }
            let rest = pkt.get(ihl..)?;
            let body = match self.recv_shape {
                SpoofShape::Udp => {
                    // UDP: src port (0..2), dst port (2..4), len (4..6), payload (8..).
                    if rest.len() < 8 {
                        return None;
                    }
                    let dport = u16::from_be_bytes([rest[2], rest[3]]);
                    if dport != self.local_port {
                        return None;
                    }
                    &rest[8..]
                }
                SpoofShape::Tcp => {
                    if rest.len() < 20 {
                        return None;
                    }
                    let dport = u16::from_be_bytes([rest[2], rest[3]]);
                    if dport != self.local_port {
                        return None;
                    }
                    let data_off = (rest[12] >> 4) as usize * 4;
                    if data_off < 20 || rest.len() < data_off {
                        return None;
                    }
                    let seq = u32::from_be_bytes([rest[4], rest[5], rest[6], rest[7]]);
                    let payload = &rest[data_off..];
                    // Acknowledge the highest peer sequence seen, for realism.
                    self.ack
                        .fetch_max(seq.wrapping_add(payload.len() as u32), Ordering::Relaxed);
                    payload
                }
                SpoofShape::Icmp => {
                    // ICMP echo: type (0), code (1), checksum (2..4), id (4..6), seq (6..8),
                    // data (8..). Accept only Echo Request (type 8); the kernel's automatic
                    // Echo Reply to a forged request is type 0 and is ignored here.
                    if rest.len() < 8 || rest[0] != 8 {
                        return None;
                    }
                    &rest[8..]
                }
                SpoofShape::Gre | SpoofShape::Ipip | SpoofShape::Proto58 => rest,
            };
            if body.len() < FRAMING || body[..4] != self.tag || body[4] != self.dir_recv {
                return None;
            }
            Some(body)
        }

        pub(in super::super) async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
            self.recv_packet(buf).await.map(|(n, _)| n)
        }

        pub(in super::super) async fn recv_from(
            &self,
            buf: &mut [u8],
        ) -> io::Result<(usize, SocketAddr)> {
            self.recv_packet(buf).await
        }

        /// One non-blocking `recv` driven by the reactor.
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

    /// Builds an IPv4 packet with the given protocol number carrying `body` into `out`
    /// (the `gre`, `ipip` and `proto58` shapes). The `IP_HDRINCL` socket recomputes the IP
    /// checksum and total length, but a correct header is built anyway.
    fn build_raw_proto_into(
        out: &mut Vec<u8>,
        proto: u8,
        src: Ipv4Addr,
        dst: Ipv4Addr,
        body: &[u8],
    ) {
        let mut header = Ipv4Header::new(
            body.len() as u16,
            TTL,
            IpNumber(proto),
            src.octets(),
            dst.octets(),
        )
        .expect("a sealed KCP packet is far below the IPv4 payload limit");
        header.header_checksum = header.calc_header_checksum();
        header.write(out).expect("writing to a Vec cannot fail");
        out.extend_from_slice(body);
    }

    /// Allocating wrapper for [`build_raw_proto_into`], used by the tests.
    #[cfg(test)]
    fn build_raw_proto(proto: u8, src: Ipv4Addr, dst: Ipv4Addr, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        build_raw_proto_into(&mut out, proto, src, dst, body);
        out
    }

    /// Parses just enough of a captured IPv4 packet to return `(header length, protocol)`.
    fn ip_header(pkt: &[u8]) -> Option<(usize, u8)> {
        let first = *pkt.first()?;
        if first >> 4 != 4 {
            return None; // not IPv4
        }
        let ihl = (first & 0x0f) as usize * 4;
        if ihl < 20 || pkt.len() < ihl {
            return None;
        }
        Some((ihl, pkt[9]))
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

    /// Opens an `AF_PACKET`/`SOCK_DGRAM` socket bound to `ifindex`, receiving IPv4 frames,
    /// with `PACKET_IGNORE_OUTGOING` set best-effort so our own sends are not captured.
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
        ignore_outgoing(owned.as_raw_fd());
        set_nonblocking(owned.as_raw_fd())?;
        set_recv_buffer(owned.as_raw_fd(), buffer);
        Ok(owned)
    }

    /// Best-effort `PACKET_IGNORE_OUTGOING`, so the packet socket does not capture the
    /// packets this same endpoint sends (kernel 4.20+). A failure is harmless: the `dir`
    /// byte already drops our own packets.
    fn ignore_outgoing(fd: RawFd) {
        let on: nix::libc::c_int = 1;
        // SAFETY: setsockopt with an int option value; best-effort, errors ignored.
        unsafe {
            nix::libc::setsockopt(
                fd,
                SOL_PACKET,
                PACKET_IGNORE_OUTGOING,
                std::ptr::addr_of!(on).cast::<nix::libc::c_void>(),
                std::mem::size_of::<nix::libc::c_int>() as nix::libc::socklen_t,
            );
        }
    }

    /// Opens the raw `IP_HDRINCL` send socket (IPPROTO_RAW, so any protocol can be built and
    /// the kernel keeps our forged, non-zero source address). A large send buffer lets the
    /// KCP driver's bursts drain without dropping under load.
    fn send_socket(dscp: Option<u8>, mark: u32, buffer: usize) -> io::Result<Socket> {
        let socket = Socket::new(
            Domain::IPV4,
            Type::RAW,
            Some(Protocol::from(nix::libc::IPPROTO_RAW)),
        )
        .map_err(map_perm)?;
        socket.set_header_included_v4(true)?;
        socket.set_nonblocking(true)?;
        let _ = socket.set_send_buffer_size(buffer);
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
                "transport \"spoof\" needs root or CAP_NET_RAW",
            )
        } else {
            e
        }
    }

    /// A non-zero firewall mark from the tunnel's tag, so a rule can tell this tunnel's own
    /// packets apart if it ever needs to (best-effort, like the other raw carriers).
    fn mark_of(tag: [u8; 4]) -> u32 {
        let m = u32::from_le_bytes(tag);
        if m == 0 {
            1
        } else {
            m
        }
    }

    /// Installs the best-effort iptables rules that keep the carrier's packets flowing under
    /// a default-DROP policy and suppress the kernel's stray replies to our forged packets.
    fn install_firewall(
        send_shape: SpoofShape,
        recv_shape: SpoofShape,
        port: u16,
    ) -> FirewallRules {
        let tag = if send_shape == recv_shape {
            format!(
                "kariz-spoof-{}-{port}-{}",
                send_shape.name(),
                unique_suffix()
            )
        } else {
            format!(
                "kariz-spoof-{}-{}-{port}-{}",
                send_shape.name(),
                recv_shape.name(),
                unique_suffix()
            )
        };
        let port_s = port.to_string();
        let mut rules = Vec::new();
        // Accept inbound packets of each direction's protocol (they are the same for a normal
        // symmetric tunnel).
        let mut protos = vec![send_shape.ip_protocol()];
        if recv_shape.ip_protocol() != send_shape.ip_protocol() {
            protos.push(recv_shape.ip_protocol());
        }
        for proto in protos {
            rules.push(Rule::new(
                "filter",
                "INPUT",
                &["-p", &proto.to_string(), "-j", "ACCEPT"],
            ));
        }
        // Suppress the kernel's stray replies for each shape in use.
        let mut shapes = vec![send_shape];
        if recv_shape != send_shape {
            shapes.push(recv_shape);
        }
        for shape in shapes {
            shape_suppression_rules(&mut rules, shape, &port_s);
        }
        FirewallRules::install(tag, rules)
    }

    /// Adds the per-shape rules that keep a forged `shape` flowing: drop the RST/ICMP the
    /// kernel would send for the unowned port, and keep conntrack off our stateless packets.
    fn shape_suppression_rules(rules: &mut Vec<Rule>, shape: SpoofShape, port_s: &str) {
        match shape {
            SpoofShape::Tcp => {
                // No socket owns the port, so the kernel would RST every inbound segment
                // (to the forged source). Drop those, and keep conntrack off our stateless
                // segments so they are not seen as invalid.
                rules.push(Rule::new(
                    "filter",
                    "OUTPUT",
                    &[
                        "-p",
                        "tcp",
                        "--sport",
                        port_s,
                        "--tcp-flags",
                        "RST",
                        "RST",
                        "-j",
                        "DROP",
                    ],
                ));
                rules.push(Rule::new(
                    "raw",
                    "PREROUTING",
                    &["-p", "tcp", "--dport", port_s, "-j", "NOTRACK"],
                ));
                rules.push(Rule::new(
                    "raw",
                    "OUTPUT",
                    &["-p", "tcp", "--sport", port_s, "-j", "NOTRACK"],
                ));
            }
            SpoofShape::Udp => {
                // Suppress the ICMP port-unreachable the kernel would send (to the forged
                // source) because no socket owns the port, and keep conntrack off.
                rules.push(Rule::new(
                    "filter",
                    "OUTPUT",
                    &[
                        "-p",
                        "icmp",
                        "--icmp-type",
                        "port-unreachable",
                        "-j",
                        "DROP",
                    ],
                ));
                rules.push(Rule::new(
                    "raw",
                    "PREROUTING",
                    &["-p", "udp", "--dport", port_s, "-j", "NOTRACK"],
                ));
            }
            SpoofShape::Icmp => {
                // Drop the kernel's automatic echo reply to inbound forged requests.
                rules.push(Rule::new(
                    "filter",
                    "OUTPUT",
                    &["-p", "icmp", "--icmp-type", "echo-reply", "-j", "DROP"],
                ));
            }
            SpoofShape::Gre | SpoofShape::Ipip | SpoofShape::Proto58 => {}
        }
    }

    /// A random, non-zero 16-bit value (ICMP echo id / ISN helper).
    fn random_u16() -> io::Result<u16> {
        Ok(u16::from_le_bytes(crate::crypto::random_bytes::<2>()?).max(1))
    }

    pub(in super::super) fn open_dialer(
        params: &SpoofParams,
        peer: SocketAddr,
        buffer: usize,
        dscp: Option<u8>,
    ) -> io::Result<CarrierSocket> {
        let SocketAddr::V4(peer) = peer else {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "transport \"spoof\" is IPv4 only",
            ));
        };
        check_pool(params)?;
        // The egress interface toward the peer carries both our sends and the replies.
        let local_ip = netinfo::local_addr_for(*peer.ip())?;
        let (iface, ifindex) = netinfo::egress_interface(local_ip, &params.interface)?;
        debug!(
            %local_ip, iface, shape = params.shape.name(), port = params.dialer_port,
            "spoof dialer egress"
        );
        build(
            params,
            DIR_D2L,
            DIR_L2D,
            params.dialer_port,
            Some(peer),
            peer,
            ifindex,
            buffer,
            dscp,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
        )
    }

    pub(in super::super) fn open_listener(
        params: &SpoofParams,
        local: SocketAddr,
        buffer: usize,
        dscp: Option<u8>,
    ) -> io::Result<CarrierSocket> {
        let IpAddr::V4(listen_ip) = local.ip() else {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "transport \"spoof\" is IPv4 only",
            ));
        };
        check_pool(params)?;
        let peer_ip = params.peer_ip.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "transport \"spoof\" on the accepting side needs the peer's real address \
                 (set tunnel.spoof.peer)",
            )
        })?;
        // The egress interface toward the known peer carries the replies and inbound.
        let probe = if listen_ip.is_unspecified() {
            peer_ip
        } else {
            listen_ip
        };
        let local_ip = netinfo::local_addr_for(probe)?;
        let (iface, ifindex) = netinfo::egress_interface(local_ip, &params.interface)?;
        debug!(
            %local_ip, iface, shape = params.shape.name(), port = local.port(),
            "spoof listener egress"
        );
        // The driver echoes this synthetic peer back to `try_send_to`, so replies go to the
        // peer's real IP and the token-derived dialer port.
        let synthetic = SocketAddrV4::new(peer_ip, params.dialer_port);
        build(
            params,
            DIR_L2D,
            DIR_D2L,
            local.port(),
            None,
            synthetic,
            ifindex,
            buffer,
            dscp,
            local,
        )
    }

    /// Fails early with a clear message when the forged-source pool is empty (validation
    /// already requires a non-empty pool, so this only guards a direct carrier build).
    fn check_pool(params: &SpoofParams) -> io::Result<()> {
        if params.pool.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "transport \"spoof\" needs at least one source address in tunnel.spoof.pool",
            ));
        }
        Ok(())
    }

    /// Shared endpoint construction for both roles.
    #[allow(clippy::too_many_arguments)]
    fn build(
        params: &SpoofParams,
        dir_send: u8,
        dir_recv: u8,
        local_port: u16,
        peer: Option<SocketAddrV4>,
        synthetic: SocketAddrV4,
        ifindex: u32,
        buffer: usize,
        dscp: Option<u8>,
        local: SocketAddr,
    ) -> io::Result<CarrierSocket> {
        let recv = packet_socket(ifindex, buffer)?;
        let send = send_socket(dscp, mark_of(params.tag), buffer)?;
        let firewall = params
            .manage_firewall
            .then(|| install_firewall(params.shape, params.recv_shape, local_port));
        if let Some(fw) = &firewall {
            if fw.is_installed() {
                debug!(
                    port = local_port,
                    shape = params.shape.name(),
                    "spoof: firewall rules installed"
                );
            } else {
                warn!(port = local_port, "spoof: iptables rules not installed; the tunnel still runs unless a default-DROP policy blocks it");
            }
        }
        let isn = u32::from_le_bytes(crate::crypto::random_bytes::<4>()?);
        Ok(CarrierSocket::Spoof(SpoofSocket {
            recv: AsyncFd::new(recv)?,
            send,
            shape: params.shape,
            recv_shape: params.recv_shape,
            pool: params.pool.clone(),
            cursor: params.cursor.clone(),
            tag: params.tag,
            dir_send,
            dir_recv,
            local_port,
            peer,
            synthetic,
            local,
            seq: AtomicU32::new(isn),
            ack: AtomicU32::new(0),
            echo_id: random_u16()?,
            seq16: AtomicU16::new(0),
            start: Instant::now(),
            _firewall: firewall,
        }))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::crypto::Psk;

        fn tag_of(token: &str) -> [u8; 4] {
            let key = Psk::new(token).subkey(crate::transport::kcp::carrier::SPOOF_TAG_CONTEXT);
            [key[0], key[1], key[2], key[3]]
        }

        fn tunnel(extra: &str) -> crate::config::TunnelConfig {
            toml::from_str(&format!(
                "transport = \"spoof\"\ntoken = \"topsecrettopsecret\"\n{extra}"
            ))
            .expect("minimal spoof tunnel config parses")
        }

        /// The carrier parsed from a spoof tunnel stores the tag, shape and expanded pool.
        #[test]
        fn from_tunnel_stores_params() {
            let t = tunnel(
                "[spoof]\nshape = \"icmp\"\npool = [\"203.0.113.5\", \"203.0.113.6\"]\npeer = \"198.51.100.9:4000\"\n",
            );
            match crate::transport::kcp::Carrier::from_tunnel(&t) {
                crate::transport::kcp::Carrier::Spoof(p) => {
                    assert_eq!(p.tag, tag_of("topsecrettopsecret"));
                    assert_eq!(p.shape, SpoofShape::Icmp);
                    assert_eq!(
                        &*p.pool,
                        &[Ipv4Addr::new(203, 0, 113, 5), Ipv4Addr::new(203, 0, 113, 6)]
                    );
                    assert_eq!(p.peer_ip, Some(Ipv4Addr::new(198, 51, 100, 9)));
                }
                _ => panic!("expected a spoof carrier"),
            }
        }

        /// The round-robin cursor walks the pool and wraps.
        #[test]
        fn pool_rotates_round_robin() {
            let pool = Arc::new(vec![
                Ipv4Addr::new(10, 0, 0, 1),
                Ipv4Addr::new(10, 0, 0, 2),
                Ipv4Addr::new(10, 0, 0, 3),
            ]);
            let cursor = Arc::new(AtomicUsize::new(0));
            let pick = |c: &Arc<AtomicUsize>| {
                let i = c.fetch_add(1, Ordering::Relaxed);
                pool[i % pool.len()]
            };
            assert_eq!(pick(&cursor), Ipv4Addr::new(10, 0, 0, 1));
            assert_eq!(pick(&cursor), Ipv4Addr::new(10, 0, 0, 2));
            assert_eq!(pick(&cursor), Ipv4Addr::new(10, 0, 0, 3));
            assert_eq!(pick(&cursor), Ipv4Addr::new(10, 0, 0, 1), "wraps");
        }

        /// A raw-proto packet round-trips: its IP header names the shape's protocol and the
        /// framed body follows.
        #[test]
        fn raw_proto_build_and_header_parse() {
            let body = {
                let mut d = vec![1u8, 2, 3, 4, DIR_D2L];
                d.extend_from_slice(b"a sealed KCP packet");
                d
            };
            for shape in [SpoofShape::Gre, SpoofShape::Ipip, SpoofShape::Proto58] {
                let pkt = build_raw_proto(
                    shape.ip_protocol(),
                    Ipv4Addr::new(203, 0, 113, 1),
                    Ipv4Addr::new(198, 51, 100, 2),
                    &body,
                );
                let (ihl, proto) = ip_header(&pkt).expect("valid IPv4 header");
                assert_eq!(proto, shape.ip_protocol());
                assert_eq!(&pkt[ihl..], &body[..]);
            }
        }

        /// A UDP shape packet parses back to the framed body for the matching dst port.
        #[test]
        fn udp_build_and_parse_round_trip() {
            // Build a UDP packet from src to dst:4000, sport 50000.
            let body = {
                let mut d = vec![9u8, 9, 9, 9, DIR_L2D];
                d.extend_from_slice(b"sealed-bytes-here");
                d
            };
            let builder =
                PacketBuilder::ipv4([203, 0, 113, 1], [198, 51, 100, 2], TTL).udp(50000, 4000);
            let mut pkt = Vec::new();
            builder.write(&mut pkt, &body).unwrap();
            let (ihl, proto) = ip_header(&pkt).expect("valid header");
            assert_eq!(proto, 17);
            let rest = &pkt[ihl..];
            let dport = u16::from_be_bytes([rest[2], rest[3]]);
            assert_eq!(dport, 4000);
            assert_eq!(&rest[8..], &body[..]);
            assert_eq!(&rest[8..12], &[9, 9, 9, 9]);
            assert_eq!(rest[12], DIR_L2D);
        }
    }
}
