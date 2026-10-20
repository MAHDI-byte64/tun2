//! The source-IP spoof tester (`kariz spooftest`): finds which forged source addresses
//! survive the path between two servers, so a `spoof` tunnel's pool can be filled with
//! addresses that actually get through. Linux + `CAP_NET_RAW`.
//!
//! It runs in two roles across the two servers, like the speed test:
//!
//! * The **receiver** runs on the destination server. It captures, through an `AF_PACKET`
//!   socket, every probe of the chosen shape carrying the run's magic and id, and tallies
//!   how many arrived from each forged source address.
//! * The **sender** runs on the source server. For each candidate source address it emits a
//!   burst of probes with that address forged into the IP header, addressed to the
//!   receiver's real address.
//!
//! A source address "passes" when the share of its probes that reached the receiver is at
//! least `1 - loss`. The probe is a tiny packet of the same shape the tunnel will use
//! (`udp`, `tcp`, `icmp`, `gre`, `ipip` or `proto58`), so the test reflects the real path.
//!
//! The payload inside the shape is `magic (4) | run id (4) | seq (2)`; the receiver reads
//! the source address from the IP header. The magic and run id let one receiver ignore
//! stray traffic and distinguish concurrent runs.

use serde::{Deserialize, Serialize};

use crate::config::SpoofShape;

/// The magic every probe payload starts with, so the receiver drops unrelated traffic.
pub const MAGIC: [u8; 4] = *b"KZSP";
/// `magic (4) | run id (4) | seq (2)`.
pub const PROBE_HEADER: usize = 10;
/// The most candidate source addresses a single run will test.
pub const MAX_SOURCES: usize = 1024;

/// How to run the sender side.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SenderOptions {
    /// The receiver's real address (`ip:port`). The port is used by the `udp`/`tcp` shapes.
    pub to: String,
    /// The packet shape to probe with.
    #[serde(default)]
    pub shape: SpoofShape,
    /// Candidate source addresses to forge (single IPs, CIDR blocks or `a-b` ranges).
    #[serde(default)]
    pub sources: Vec<String>,
    /// Probes to send per source address.
    #[serde(default = "default_count")]
    pub count: u16,
    /// Delay between probes, in milliseconds.
    #[serde(default = "default_interval")]
    pub interval_ms: u16,
    /// The run id, matched by the receiver.
    #[serde(default)]
    pub run_id: u32,
    /// Override the auto-detected egress interface (empty: auto).
    #[serde(default)]
    pub interface: String,
}

/// How to run the receiver side.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReceiverOptions {
    /// The address to receive on (`ip:port`); the port is used by the `udp`/`tcp` shapes.
    pub bind: String,
    /// The packet shape to expect.
    #[serde(default)]
    pub shape: SpoofShape,
    /// How long to capture, in seconds.
    #[serde(default = "default_seconds")]
    pub seconds: u16,
    /// The run id to accept.
    #[serde(default)]
    pub run_id: u32,
    /// Probes the sender emits per source (used to score pass/fail).
    #[serde(default = "default_count")]
    pub expect: u16,
    /// Acceptable loss, as a percentage; a source passes when its arrival share is at least
    /// `100 - loss_pct`.
    #[serde(default = "default_loss")]
    pub loss_pct: u8,
    /// Override the auto-detected egress interface (empty: auto).
    #[serde(default)]
    pub interface: String,
}

fn default_count() -> u16 {
    20
}
fn default_interval() -> u16 {
    5
}
fn default_seconds() -> u16 {
    10
}
fn default_loss() -> u8 {
    20
}

/// One candidate source address's result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SourceResult {
    /// The forged source address tested.
    pub ip: String,
    /// How many of its probes the receiver saw.
    pub received: u16,
    /// Whether it met the loss threshold.
    pub ok: bool,
}

/// The receiver's verdict for a run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Report {
    pub run_id: u32,
    pub shape: String,
    /// Probes expected per source.
    pub expect: u16,
    pub loss_pct: u8,
    /// One entry per source the receiver saw at least one probe from, plus any source the
    /// caller listed (filled in by the orchestrator); scored and sorted best-first.
    pub results: Vec<SourceResult>,
    /// Count of sources that passed.
    pub usable: u32,
    /// Count of sources that were seen at all.
    pub seen: u32,
}

/// What the sender emitted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendReport {
    pub run_id: u32,
    pub shape: String,
    /// Distinct source addresses probed.
    pub sources: u32,
    /// Total probes written to the wire.
    pub sent: u64,
}

/// Decides whether a source passes: its arrival share must be at least `100 - loss_pct`.
pub fn passes(received: u16, expect: u16, loss_pct: u8) -> bool {
    if expect == 0 {
        return false;
    }
    let need = (u32::from(expect) * u32::from(100u8.saturating_sub(loss_pct)) + 99) / 100;
    u32::from(received) >= need.max(1)
}

#[cfg(not(target_os = "linux"))]
pub async fn receiver(_opts: ReceiverOptions) -> std::io::Result<Report> {
    Err(unsupported())
}

#[cfg(not(target_os = "linux"))]
pub async fn sender(_opts: SenderOptions) -> std::io::Result<SendReport> {
    Err(unsupported())
}

#[cfg(not(target_os = "linux"))]
fn unsupported() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "`kariz spooftest` needs a Linux server with CAP_NET_RAW",
    )
}

#[cfg(target_os = "linux")]
pub use imp::{receiver, sender};

#[cfg(target_os = "linux")]
mod imp {
    use std::collections::HashMap;
    use std::io;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::time::Duration;

    use etherparse::{IpNumber, Ipv4Header, PacketBuilder};
    use socket2::{Domain, Protocol, SockAddr, Socket, Type};
    use tokio::io::unix::AsyncFd;
    use tokio::time::{sleep, Instant};

    use super::{
        passes, Report, SendReport, SenderOptions, SourceResult, MAGIC, MAX_SOURCES, PROBE_HEADER,
    };
    use crate::config::{expand_ipv4_specs, SpoofShape};
    use crate::transport::kcp::rawlink::netinfo;

    const TTL: u8 = 64;
    const SOL_PACKET: nix::libc::c_int = 263;
    const PACKET_IGNORE_OUTGOING: nix::libc::c_int = 23;

    /// Builds one probe's payload: `magic | run id | seq`.
    fn probe_body(run_id: u32, seq: u16) -> Vec<u8> {
        let mut body = Vec::with_capacity(PROBE_HEADER);
        body.extend_from_slice(&MAGIC);
        body.extend_from_slice(&run_id.to_be_bytes());
        body.extend_from_slice(&seq.to_be_bytes());
        body
    }

    /// Parses a captured probe's run id from a payload, or `None` when it is not a probe.
    fn probe_run_id(body: &[u8]) -> Option<u32> {
        if body.len() < PROBE_HEADER || body[..4] != MAGIC {
            return None;
        }
        Some(u32::from_be_bytes([body[4], body[5], body[6], body[7]]))
    }

    /// Builds a full IPv4 probe packet of `shape`, forging `src`, to `dst:dport`.
    fn build_probe(
        shape: SpoofShape,
        src: Ipv4Addr,
        dst: Ipv4Addr,
        sport: u16,
        dport: u16,
        body: &[u8],
    ) -> Vec<u8> {
        match shape {
            SpoofShape::Udp => {
                let b = PacketBuilder::ipv4(src.octets(), dst.octets(), TTL).udp(sport, dport);
                let mut out = Vec::with_capacity(b.size(body.len()));
                b.write(&mut out, body).expect("vec write cannot fail");
                out
            }
            SpoofShape::Tcp => {
                let b = PacketBuilder::ipv4(src.octets(), dst.octets(), TTL)
                    .tcp(sport, dport, 0, 65535)
                    .syn();
                let mut out = Vec::with_capacity(b.size(body.len()));
                b.write(&mut out, body).expect("vec write cannot fail");
                out
            }
            SpoofShape::Icmp => {
                let b =
                    PacketBuilder::ipv4(src.octets(), dst.octets(), TTL).icmpv4_echo_request(1, 1);
                let mut out = Vec::with_capacity(b.size(body.len()));
                b.write(&mut out, body).expect("vec write cannot fail");
                out
            }
            SpoofShape::Gre | SpoofShape::Ipip | SpoofShape::Proto58 => {
                let mut h = Ipv4Header::new(
                    body.len() as u16,
                    TTL,
                    IpNumber(shape.ip_protocol()),
                    src.octets(),
                    dst.octets(),
                )
                .expect("probe is small");
                h.header_checksum = h.calc_header_checksum();
                let mut out = Vec::with_capacity(h.header_len() + body.len());
                h.write(&mut out).expect("vec write cannot fail");
                out.extend_from_slice(body);
                out
            }
        }
    }

    /// Returns the probe payload region of a captured IPv4 packet for `shape`, or `None`.
    fn probe_payload<'a>(shape: SpoofShape, pkt: &'a [u8]) -> Option<(Ipv4Addr, &'a [u8])> {
        let first = *pkt.first()?;
        if first >> 4 != 4 {
            return None;
        }
        let ihl = (first & 0x0f) as usize * 4;
        if ihl < 20 || pkt.len() < ihl || pkt[9] != shape.ip_protocol() {
            return None;
        }
        let src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
        let rest = pkt.get(ihl..)?;
        let body = match shape {
            SpoofShape::Udp => rest.get(8..)?,
            SpoofShape::Tcp => {
                let off = (rest.get(12).copied()? >> 4) as usize * 4;
                rest.get(off..)?
            }
            SpoofShape::Icmp => {
                if rest.first().copied()? != 8 {
                    return None;
                }
                rest.get(8..)?
            }
            SpoofShape::Gre | SpoofShape::Ipip | SpoofShape::Proto58 => rest,
        };
        Some((src, body))
    }

    /// Opens the raw `IP_HDRINCL` send socket (IPPROTO_RAW: any protocol, forged source).
    fn send_socket() -> io::Result<Socket> {
        let socket = Socket::new(
            Domain::IPV4,
            Type::RAW,
            Some(Protocol::from(nix::libc::IPPROTO_RAW)),
        )
        .map_err(map_perm)?;
        socket.set_header_included_v4(true)?;
        Ok(socket)
    }

    /// Opens an `AF_PACKET`/`SOCK_DGRAM` receive socket bound to `ifindex`.
    fn packet_socket(ifindex: u32) -> io::Result<OwnedFd> {
        let proto = (nix::libc::ETH_P_IP as u16).to_be();
        // SAFETY: a plain socket(2) call; the fd is adopted by OwnedFd on success.
        let fd = unsafe {
            nix::libc::socket(nix::libc::AF_PACKET, nix::libc::SOCK_DGRAM, i32::from(proto))
        };
        if fd < 0 {
            return Err(map_perm(io::Error::last_os_error()));
        }
        // SAFETY: `fd` is a fresh, owned descriptor.
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        // SAFETY: zeroed sockaddr_ll is valid; fields set below.
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
        let on: nix::libc::c_int = 1;
        // SAFETY: best-effort setsockopt with an int value.
        unsafe {
            nix::libc::setsockopt(
                owned.as_raw_fd(),
                SOL_PACKET,
                PACKET_IGNORE_OUTGOING,
                std::ptr::addr_of!(on).cast::<nix::libc::c_void>(),
                std::mem::size_of::<nix::libc::c_int>() as nix::libc::socklen_t,
            );
        }
        set_nonblocking(owned.as_raw_fd())?;
        Ok(owned)
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

    fn map_perm(e: io::Error) -> io::Error {
        if e.kind() == io::ErrorKind::PermissionDenied {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "`kariz spooftest` needs root or CAP_NET_RAW",
            )
        } else {
            e
        }
    }

    fn recv_once(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
        // SAFETY: `buf` is a valid writable slice for `buf.len()` bytes.
        let n = unsafe {
            nix::libc::recv(fd, buf.as_mut_ptr().cast::<nix::libc::c_void>(), buf.len(), 0)
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(n as usize)
    }

    /// The egress interface index toward `peer` (or the default route), overridable.
    fn ifindex_toward(peer: Ipv4Addr, interface: &str) -> io::Result<u32> {
        let local = netinfo::local_addr_for(peer)?;
        let (_name, index) = netinfo::egress_interface(local, interface)?;
        Ok(index)
    }

    /// Parses `ip:port` or a bare IPv4 address, returning the address and the port (0 when
    /// absent).
    fn parse_v4(s: &str) -> io::Result<SocketAddrV4> {
        let s = s.trim();
        if let Ok(a) = s.parse::<SocketAddrV4>() {
            return Ok(a);
        }
        if let Ok(ip) = s.parse::<Ipv4Addr>() {
            return Ok(SocketAddrV4::new(ip, 0));
        }
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{s:?} is not an IPv4 address (optionally with :port)"),
        ))
    }

    pub async fn sender(opts: SenderOptions) -> io::Result<SendReport> {
        let dst = parse_v4(&opts.to)?;
        let sources = expand_ipv4_specs(&opts.sources, MAX_SOURCES)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        if sources.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "no source addresses to test (give an IP, a CIDR block or an a-b range)",
            ));
        }
        // Validate the egress path up front (clear error before the burst).
        let _ = ifindex_toward(*dst.ip(), &opts.interface)?;
        let socket = send_socket()?;
        let dport = if opts.shape.has_ports() {
            if dst.port() == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "the udp and tcp shapes need a destination port (ip:port)",
                ));
            }
            dst.port()
        } else {
            0
        };
        let to = SockAddr::from(SocketAddr::V4(SocketAddrV4::new(*dst.ip(), 0)));
        let interval = Duration::from_millis(u64::from(opts.interval_ms));
        let mut sent: u64 = 0;
        // A fixed, plausible source port for the port-bearing shapes.
        let sport = 44444u16;
        for (i, src) in sources.iter().enumerate() {
            for seq in 0..opts.count {
                let body = probe_body(opts.run_id, seq);
                let pkt = build_probe(opts.shape, *src, *dst.ip(), sport, dport, &body);
                match socket.send_to(&pkt, &to) {
                    Ok(_) => sent += 1,
                    // A single forged source the kernel refuses to route should not abort
                    // the whole run; skip to the next.
                    Err(_) => break,
                }
                if !interval.is_zero() {
                    sleep(interval).await;
                }
            }
            // Yield between sources so a large run stays responsive.
            if i % 16 == 15 {
                tokio::task::yield_now().await;
            }
        }
        Ok(SendReport {
            run_id: opts.run_id,
            shape: opts.shape.name().to_string(),
            sources: sources.len() as u32,
            sent,
        })
    }

    pub async fn receiver(opts: super::ReceiverOptions) -> io::Result<Report> {
        let bind = parse_v4(&opts.bind)?;
        // Find the egress interface: the bound IP's, or the default route's.
        let probe_ip = if bind.ip().is_unspecified() {
            Ipv4Addr::new(1, 1, 1, 1)
        } else {
            *bind.ip()
        };
        let ifindex = ifindex_toward(probe_ip, &opts.interface)?;
        let sock = AsyncFd::new(packet_socket(ifindex)?)?;
        let shape = opts.shape;
        let want_port = bind.port();
        let deadline = Instant::now() + Duration::from_secs(u64::from(opts.seconds.max(1)));
        let mut counts: HashMap<Ipv4Addr, u16> = HashMap::new();
        let mut raw = [0u8; 2048];
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            let readable = tokio::time::timeout(remaining, sock.readable()).await;
            let Ok(guard) = readable else { break };
            let mut guard = guard?;
            let n = match guard.try_io(|inner| recv_once(inner.get_ref().as_raw_fd(), &mut raw)) {
                Ok(Ok(n)) => n,
                Ok(Err(_)) => continue,
                Err(_would_block) => continue,
            };
            let Some((src, body)) = probe_payload(shape, &raw[..n]) else {
                continue;
            };
            // For the port-bearing shapes, only count probes to our port.
            if shape.has_ports() && want_port != 0 {
                let rest = &raw[(raw[0] & 0x0f) as usize * 4..n];
                if rest.len() < 4 {
                    continue;
                }
                let dport = u16::from_be_bytes([rest[2], rest[3]]);
                if dport != want_port {
                    continue;
                }
            }
            if probe_run_id(body) != Some(opts.run_id) {
                continue;
            }
            let c = counts.entry(src).or_insert(0);
            *c = c.saturating_add(1);
        }
        let mut results: Vec<SourceResult> = counts
            .into_iter()
            .map(|(ip, received)| SourceResult {
                ip: ip.to_string(),
                received,
                ok: passes(received, opts.expect, opts.loss_pct),
            })
            .collect();
        // Best first: most received, then address order.
        results.sort_by(|a, b| b.received.cmp(&a.received).then(a.ip.cmp(&b.ip)));
        let usable = results.iter().filter(|r| r.ok).count() as u32;
        let seen = results.len() as u32;
        Ok(Report {
            run_id: opts.run_id,
            shape: shape.name().to_string(),
            expect: opts.expect,
            loss_pct: opts.loss_pct,
            results,
            usable,
            seen,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passes_threshold() {
        // 20 expected, 20% loss → need 16.
        assert!(passes(20, 20, 20));
        assert!(passes(16, 20, 20));
        assert!(!passes(15, 20, 20));
        // 0% loss → need all.
        assert!(passes(20, 20, 0));
        assert!(!passes(19, 20, 0));
        // 100% loss → need at least 1.
        assert!(passes(1, 20, 100));
        assert!(!passes(0, 20, 100));
        // No probes expected never passes.
        assert!(!passes(0, 0, 0));
    }

    #[test]
    fn options_round_trip_json() {
        let opts = SenderOptions {
            to: "198.51.100.7:4000".into(),
            shape: SpoofShape::Icmp,
            sources: vec!["203.0.113.0/24".into()],
            count: 10,
            interval_ms: 3,
            run_id: 42,
            interface: String::new(),
        };
        let json = serde_json::to_string(&opts).unwrap();
        let back: SenderOptions = serde_json::from_str(&json).unwrap();
        assert_eq!(back.run_id, 42);
        assert_eq!(back.shape, SpoofShape::Icmp);
        assert_eq!(back.sources, vec!["203.0.113.0/24".to_string()]);
    }
}
