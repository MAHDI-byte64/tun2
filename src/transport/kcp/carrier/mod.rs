//! The carrier seam of the KCP stack.
//!
//! KCP's reliable ARQ, FEC, packet protection, the datagram path, and the whole
//! handshake/record/mux stack above it do not care what carries the sealed packets. Today
//! that is a UDP socket ([`udp`]); the raw-packet carriers ([`icmp`], [`faketcp`]) ride
//! the same KCP stack over a different datagram carrier.
//!
//! The carrier is selected from `[tunnel] transport` ([`Carrier::from_tunnel`]) and
//! threaded through [`super::KcpParams`]. A [`CarrierSocket`] is what the KCP driver and
//! demultiplexer send through and receive from: it sends one already-sealed packet to a
//! peer and receives `(sealed packet, peer)`, hiding whether the bytes rode a UDP
//! datagram, an ICMP echo or a crafted TCP segment. The raw carriers de-frame down to the
//! sealed packet before returning it, so [`super`]'s protection, conversation demux and
//! FEC logic are identical for every carrier.

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use tokio::net::UdpSocket;

use crate::config::{SpoofShape, TunnelConfig};
use crate::crypto::Psk;

pub(super) mod faketcp;
pub(super) mod icmp;
pub(super) mod proto47;
pub(super) mod spoof;
pub(super) mod udp;

/// Token context for the per-tunnel ICMP tag (first 4 bytes of the subkey).
const ICMP_TAG_CONTEXT: &str = "kariz 2026-10 icmp tag v1";
/// Token context for the fake-TCP dialer source port (stable across reconnects).
const FAKETCP_PORT_CONTEXT: &str = "kariz 2026-10 faketcp port v1";
/// Token context for the per-tunnel proto-47 (GRE) key (first 4 bytes of the subkey).
const PROTO47_TAG_CONTEXT: &str = "kariz 2026-10 proto47 tag v1";
/// Token context for the per-tunnel spoof tag (first 4 bytes of the subkey).
const SPOOF_TAG_CONTEXT: &str = "kariz 2026-10 spoof tag v1";
/// Token context for the spoof dialer port (stable across reconnects, both ends derive it).
const SPOOF_PORT_CONTEXT: &str = "kariz 2026-10 spoof port v1";

/// Which datagram carrier the KCP stack rides, with the per-tunnel parameters it needs.
#[derive(Debug, Clone, Default)]
pub enum Carrier {
    /// Plain UDP datagrams (`transport = "kcp"` and `transport = "udp"`).
    #[default]
    Udp,
    /// ICMP echo request/reply (`transport = "icmp"`), Linux + root.
    Icmp(IcmpParams),
    /// Raw-socket fake TCP (`transport = "faketcp"`), Linux + root.
    Faketcp(FaketcpParams),
    /// Raw IP protocol-47 / keyed GRE (the `[l3]` carrier `proto47`), Linux + root.
    Proto47(Proto47Params),
    /// Source-spoofing carrier (`transport = "spoof"`), Linux + root.
    Spoof(SpoofParams),
}

/// Per-tunnel parameters of the ICMP carrier.
#[derive(Debug, Clone)]
pub struct IcmpParams {
    /// The 4-byte tag every echo of this tunnel carries, so a host can hold several icmp
    /// tunnels and so stray pings are dropped before the cipher.
    pub tag: [u8; 4],
    /// Install/remove the iptables rules (suppress kernel auto-replies, accept our echoes).
    pub manage_firewall: bool,
}

/// Per-tunnel parameters of the fake-TCP carrier.
#[derive(Debug, Clone)]
pub struct FaketcpParams {
    /// The dialer's source port, derived from the token so it is stable across reconnects
    /// (one firewall rule per tunnel). The listener uses its own listen port instead.
    pub source_port: u16,
    /// The TCP flag pattern this end's segments carry.
    pub flags: faketcp::FlagPattern,
    /// Override the auto-detected egress interface (empty: auto).
    pub interface: String,
    /// Override the auto-detected next-hop MAC (only used by an L2 send path).
    pub gateway_mac: Option<[u8; 6]>,
    /// Install/remove the RST-drop and NOTRACK iptables rules.
    pub manage_firewall: bool,
}

/// Per-tunnel parameters of the proto-47 (GRE) carrier.
#[derive(Debug, Clone)]
pub struct Proto47Params {
    /// The 4-byte key every GRE packet of this tunnel carries, so a host can hold several
    /// proto47 tunnels and so a foreign proto-47 packet is dropped before the cipher.
    pub tag: [u8; 4],
    /// Install/remove the best-effort `-p gre -j ACCEPT` iptables rule.
    pub manage_firewall: bool,
}

/// Per-tunnel parameters of the source-spoofing carrier.
#[derive(Debug, Clone)]
pub struct SpoofParams {
    /// The on-wire packet shape (udp, tcp, icmp, gre, ipip or proto58).
    pub shape: SpoofShape,
    /// The forged source addresses, rotated round-robin per packet. Never empty for a real
    /// tunnel (validation requires at least one); an empty pool makes `open_*` fail.
    pub pool: Arc<Vec<Ipv4Addr>>,
    /// Shared round-robin cursor over `pool`, so every send advances it.
    pub cursor: Arc<std::sync::atomic::AtomicUsize>,
    /// The 4-byte tag every packet carries, so a host holds several spoof tunnels and a
    /// foreign packet is dropped before the cipher.
    pub tag: [u8; 4],
    /// The port shared by both ends for the port-bearing shapes (udp, tcp): the dialer's
    /// source and the acceptor's reply destination. Token-derived, stable across reconnects.
    pub dialer_port: u16,
    /// The peer's real address. The acceptor must have it to address replies (the forged
    /// packets never reveal it); the dialer ignores it and uses the address it dials.
    pub peer_ip: Option<Ipv4Addr>,
    /// Override the auto-detected egress interface (empty: auto).
    pub interface: String,
    /// Install/remove the best-effort iptables rules (RAII).
    pub manage_firewall: bool,
}

impl Carrier {
    /// The carrier a tunnel uses, with its token-derived parameters. Only the KCP-based
    /// transports reach a non-UDP carrier; any other maps to [`Carrier::Udp`] (never used
    /// for them).
    pub fn from_tunnel(tunnel: &TunnelConfig) -> Self {
        use crate::config::TransportKind::{Faketcp, Icmp, Proto47, Spoof};
        match tunnel.transport {
            Spoof => {
                let psk = Psk::new(&tunnel.token);
                let tagk = psk.subkey(SPOOF_TAG_CONTEXT);
                let cfg = tunnel.spoof.clone().unwrap_or_default();
                let pool = cfg.expand_pool().unwrap_or_default();
                // The acceptor needs the peer's real address; take it from `spoof.peer`,
                // else from `remote`. The dialer ignores this and uses the address it dials.
                let peer_ip = cfg
                    .peer
                    .as_deref()
                    .or(tunnel.remote.as_deref())
                    .and_then(ipv4_of_addr);
                Self::Spoof(SpoofParams {
                    shape: cfg.shape,
                    pool: Arc::new(pool),
                    cursor: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                    tag: [tagk[0], tagk[1], tagk[2], tagk[3]],
                    dialer_port: faketcp::source_port(&psk.subkey(SPOOF_PORT_CONTEXT)),
                    peer_ip,
                    interface: cfg.interface,
                    manage_firewall: cfg.manage_firewall,
                })
            }
            Icmp => {
                let psk = Psk::new(&tunnel.token);
                let key = psk.subkey(ICMP_TAG_CONTEXT);
                let cfg = tunnel.icmp.clone().unwrap_or_default();
                Self::Icmp(IcmpParams {
                    tag: [key[0], key[1], key[2], key[3]],
                    manage_firewall: cfg.manage_firewall,
                })
            }
            Proto47 => {
                let psk = Psk::new(&tunnel.token);
                let key = psk.subkey(PROTO47_TAG_CONTEXT);
                let cfg = tunnel.proto47.clone().unwrap_or_default();
                Self::Proto47(Proto47Params {
                    tag: [key[0], key[1], key[2], key[3]],
                    manage_firewall: cfg.manage_firewall,
                })
            }
            Faketcp => {
                let psk = Psk::new(&tunnel.token);
                let cfg = tunnel.faketcp.clone().unwrap_or_default();
                Self::Faketcp(FaketcpParams {
                    source_port: faketcp::source_port(&psk.subkey(FAKETCP_PORT_CONTEXT)),
                    flags: faketcp::FlagPattern::parse(&cfg.flags),
                    interface: cfg.interface,
                    gateway_mac: parse_mac(&cfg.gateway_mac),
                    manage_firewall: cfg.manage_firewall,
                })
            }
            // `kcp`, `udp`, and anything non-KCP (never routed through a carrier).
            _ => Self::Udp,
        }
    }
}

/// Extracts an IPv4 address from an address string that may carry a port (`1.2.3.4:5000`,
/// `1.2.3.4` and `host:port` all accepted; a hostname or IPv6 yields `None`, which the
/// carrier turns into a clear open-time error).
fn ipv4_of_addr(s: &str) -> Option<Ipv4Addr> {
    let s = s.trim();
    if let Ok(ip) = s.parse::<Ipv4Addr>() {
        return Some(ip);
    }
    // Strip a `:port` suffix (only for an IPv4 host; bracketed IPv6 is rejected).
    if let Some((host, _port)) = s.rsplit_once(':') {
        if let Ok(ip) = host.trim().parse::<Ipv4Addr>() {
            return Some(ip);
        }
    }
    None
}

/// Parses `aa:bb:cc:dd:ee:ff` into six bytes; `None` for an empty or malformed string
/// (config validation has already rejected a malformed non-empty one).
fn parse_mac(s: &str) -> Option<[u8; 6]> {
    if s.is_empty() {
        return None;
    }
    let mut out = [0u8; 6];
    let mut parts = s.split(':');
    for byte in &mut out {
        *byte = u8::from_str_radix(parts.next()?, 16).ok()?;
    }
    if parts.next().is_some() {
        return None;
    }
    Some(out)
}

/// The socket a KCP dialer or listener sends sealed packets through and receives them
/// from. Each carrier does its own framing: the UDP carrier is a thin wrapper over
/// [`tokio::net::UdpSocket`]; the raw carriers wrap each sealed packet in an ICMP echo or
/// a TCP segment on send, and strip that framing (and drop foreign packets) on receive, so
/// [`super`] always sees a plain sealed packet and a peer.
pub(super) enum CarrierSocket {
    Udp(UdpSocket),
    #[cfg(all(feature = "rawlink", target_os = "linux"))]
    Icmp(icmp::IcmpSocket),
    #[cfg(all(feature = "rawlink", target_os = "linux"))]
    Faketcp(faketcp::FaketcpSocket),
    #[cfg(all(feature = "rawlink", target_os = "linux"))]
    Proto47(proto47::Proto47Socket),
    #[cfg(all(feature = "rawlink", target_os = "linux"))]
    Spoof(spoof::SpoofSocket),
}

impl CarrierSocket {
    /// Sends one sealed packet to the connected peer (dialer side), dropping it on a full
    /// buffer as a congested link would.
    pub(super) fn try_send(&self, packet: &[u8]) -> io::Result<usize> {
        match self {
            Self::Udp(s) => s.try_send(packet),
            #[cfg(all(feature = "rawlink", target_os = "linux"))]
            Self::Icmp(s) => s.try_send(packet),
            #[cfg(all(feature = "rawlink", target_os = "linux"))]
            Self::Faketcp(s) => s.try_send(packet),
            #[cfg(all(feature = "rawlink", target_os = "linux"))]
            Self::Proto47(s) => s.try_send(packet),
            #[cfg(all(feature = "rawlink", target_os = "linux"))]
            Self::Spoof(s) => s.try_send(packet),
        }
    }

    /// Sends one sealed packet to `peer` (listener side, one socket for every peer).
    pub(super) fn try_send_to(&self, packet: &[u8], peer: SocketAddr) -> io::Result<usize> {
        match self {
            Self::Udp(s) => s.try_send_to(packet, peer),
            #[cfg(all(feature = "rawlink", target_os = "linux"))]
            Self::Icmp(s) => s.try_send_to(packet, peer),
            #[cfg(all(feature = "rawlink", target_os = "linux"))]
            Self::Faketcp(s) => s.try_send_to(packet, peer),
            #[cfg(all(feature = "rawlink", target_os = "linux"))]
            Self::Proto47(s) => s.try_send_to(packet, peer),
            #[cfg(all(feature = "rawlink", target_os = "linux"))]
            Self::Spoof(s) => s.try_send_to(packet, peer),
        }
    }

    /// Receives one sealed packet from the connected peer (dialer side).
    pub(super) async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Udp(s) => s.recv(buf).await,
            #[cfg(all(feature = "rawlink", target_os = "linux"))]
            Self::Icmp(s) => s.recv(buf).await,
            #[cfg(all(feature = "rawlink", target_os = "linux"))]
            Self::Faketcp(s) => s.recv(buf).await,
            #[cfg(all(feature = "rawlink", target_os = "linux"))]
            Self::Proto47(s) => s.recv(buf).await,
            #[cfg(all(feature = "rawlink", target_os = "linux"))]
            Self::Spoof(s) => s.recv(buf).await,
        }
    }

    /// Receives one sealed packet and the peer it came from (listener side).
    pub(super) async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        match self {
            Self::Udp(s) => s.recv_from(buf).await,
            #[cfg(all(feature = "rawlink", target_os = "linux"))]
            Self::Icmp(s) => s.recv_from(buf).await,
            #[cfg(all(feature = "rawlink", target_os = "linux"))]
            Self::Faketcp(s) => s.recv_from(buf).await,
            #[cfg(all(feature = "rawlink", target_os = "linux"))]
            Self::Proto47(s) => s.recv_from(buf).await,
            #[cfg(all(feature = "rawlink", target_os = "linux"))]
            Self::Spoof(s) => s.recv_from(buf).await,
        }
    }

    /// The local address a listener bound to.
    pub(super) fn local_addr(&self) -> io::Result<SocketAddr> {
        match self {
            Self::Udp(s) => s.local_addr(),
            #[cfg(all(feature = "rawlink", target_os = "linux"))]
            Self::Icmp(s) => Ok(s.local_addr()),
            #[cfg(all(feature = "rawlink", target_os = "linux"))]
            Self::Faketcp(s) => Ok(s.local_addr()),
            #[cfg(all(feature = "rawlink", target_os = "linux"))]
            Self::Proto47(s) => Ok(s.local_addr()),
            #[cfg(all(feature = "rawlink", target_os = "linux"))]
            Self::Spoof(s) => Ok(s.local_addr()),
        }
    }
}

/// Opens the carrier's socket for a dialer, connected to `peer`.
pub(super) fn open_dialer(
    carrier: &Carrier,
    peer: SocketAddr,
    buffer: usize,
    dscp: Option<u8>,
) -> io::Result<CarrierSocket> {
    match carrier {
        Carrier::Udp => Ok(CarrierSocket::Udp(udp::open_connected(peer, buffer, dscp)?)),
        Carrier::Icmp(params) => icmp::open_dialer(params, peer, buffer, dscp),
        Carrier::Faketcp(params) => faketcp::open_dialer(params, peer, buffer, dscp),
        Carrier::Proto47(params) => proto47::open_dialer(params, peer, buffer, dscp),
        Carrier::Spoof(params) => spoof::open_dialer(params, peer, buffer, dscp),
    }
}

/// Opens the carrier's socket for a listener bound to `local`.
pub(super) fn open_listener(
    carrier: &Carrier,
    local: SocketAddr,
    buffer: usize,
    dscp: Option<u8>,
) -> io::Result<CarrierSocket> {
    match carrier {
        Carrier::Udp => Ok(CarrierSocket::Udp(udp::open(local, buffer, dscp)?)),
        Carrier::Icmp(params) => icmp::open_listener(params, local, buffer, dscp),
        Carrier::Faketcp(params) => faketcp::open_listener(params, local, buffer, dscp),
        Carrier::Proto47(params) => proto47::open_listener(params, local, buffer, dscp),
        Carrier::Spoof(params) => spoof::open_listener(params, local, buffer, dscp),
    }
}

/// A plain UDP socket, for the kcp unit tests that build sockets directly.
#[cfg(test)]
pub(super) fn udp_socket(
    addr: SocketAddr,
    buffer: usize,
    dscp: Option<u8>,
) -> io::Result<UdpSocket> {
    udp::open(addr, buffer, dscp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_parsing_round_trips_and_rejects() {
        assert_eq!(parse_mac(""), None);
        assert_eq!(
            parse_mac("aa:bb:cc:dd:ee:ff"),
            Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        );
        assert_eq!(
            parse_mac("00:11:22:33:44:55"),
            Some([0, 17, 34, 51, 68, 85])
        );
        assert_eq!(parse_mac("aa:bb:cc:dd:ee"), None, "too few octets");
        assert_eq!(parse_mac("aa:bb:cc:dd:ee:ff:00"), None, "too many octets");
        assert_eq!(parse_mac("zz:bb:cc:dd:ee:ff"), None, "not hex");
    }
}
