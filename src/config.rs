//! Configuration file model (TOML) and validation.
//!
//! A tunnel always has two sides:
//!
//! * **entry**: the public-facing server users connect to (usually the Iran server).
//!   It owns the `[[forward]]` rules.
//! * **exit**: the server that reaches the real targets (usually the server abroad).
//!
//! The `mode` decides which side opens the tunnel connections:
//!
//! * `reverse`: exit dials entry (entry listens on `tunnel.listen`).
//! * `direct`: entry dials exit (exit listens on `tunnel.listen`).

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::Deserialize;

use crate::proto::Duplicate;
pub use crate::proxy_header::ProxyVersion;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Entry,
    Exit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Reverse,
    Direct,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Profile {
    #[default]
    Balanced,
    /// The most speed: large buffers and windows, more connections. Also accepted under
    /// its old name, `throughput`.
    #[serde(alias = "throughput")]
    Ultraspeed,
    Gaming,
}

impl Profile {
    pub fn name(self) -> &'static str {
        match self {
            Self::Balanced => "balanced",
            Self::Ultraspeed => "ultraspeed",
            Self::Gaming => "gaming",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransportKind {
    #[default]
    Tcp,
    /// `tcp` with mux always on.
    Tcpmux,
    /// WebSocket over plain TCP (for example behind a CDN that talks HTTP to the origin).
    Ws,
    /// WebSocket over TLS.
    Wss,
    /// QUIC: its own streams, datagrams and TLS 1.3.
    Quic,
    /// KCP over UDP, every packet encrypted with a key from the token.
    Kcp,
    /// All of tcpmux, kcp and ws at once, and the dialing side moves to the one that gets
    /// through when a link stalls (see `auto.rs`). Always multiplexed.
    Auto,
    /// An encrypted TCP stream (like `tcp`) with record-length padding and optional timing
    /// jitter, so record sizes do not leak the traffic shape. Encryption is mandatory.
    Stealth,
    /// `ws` with mux always on (like `tcpmux` vs `tcp`).
    Wsmux,
    /// `wss` with mux always on.
    Wssmux,
    /// The KCP stack over a plain UDP carrier, for forwarding UDP services.
    Udp,
    /// The KCP stack over a raw-socket fake-TCP carrier (Linux, root). BackPack's `pck`.
    #[serde(alias = "pck")]
    Faketcp,
    /// The KCP stack over an ICMP echo carrier (Linux, root). BackPack's `xdi`.
    #[serde(alias = "xdi")]
    Icmp,
    /// The KCP stack over a raw IP protocol-47 (GRE) carrier (Linux, root). Available only
    /// as an `[l3]` carrier, never as a standalone `[tunnel] transport` (validation rejects
    /// that): the sealed KCP packets ride as the payload of a keyed GRE packet.
    Proto47,
    /// The source-spoofing carrier (Linux, root). The KCP stack ridden inside crafted
    /// packets whose source IP is forged and rotated from a pool, for mutual IP spoofing
    /// that blends into real traffic and evades stateful DPI. The on-wire packet shape is
    /// chosen with `[tunnel.spoof] shape` (`udp`, `tcp`, `icmp`, `gre`, `ipip` or
    /// `proto58`). Both ends forge their source; each is told the other's real address.
    /// Encryption is mandatory.
    Spoof,
    /// A managed sing-box naive inbound/outbound carrying the tunnel.
    Naive,
    /// A managed Xray VLESS-over-XHTTP (HTTP/2) tunnel with TLS.
    Xhttp,
    /// A managed Xray VLESS + REALITY + Vision tunnel.
    Reality,
}

impl TransportKind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Tcpmux => "tcpmux",
            Self::Ws => "ws",
            Self::Wss => "wss",
            Self::Quic => "quic",
            Self::Kcp => "kcp",
            Self::Auto => "auto",
            Self::Stealth => "stealth",
            Self::Wsmux => "wsmux",
            Self::Wssmux => "wssmux",
            Self::Udp => "udp",
            Self::Faketcp => "faketcp",
            Self::Icmp => "icmp",
            Self::Proto47 => "proto47",
            Self::Spoof => "spoof",
            Self::Naive => "naive",
            Self::Xhttp => "xhttp",
            Self::Reality => "reality",
        }
    }

    /// Transports that ride the WebSocket code (`ws`, `wss`, and their always-mux twins).
    fn is_websocket(self) -> bool {
        matches!(self, Self::Ws | Self::Wss | Self::Wsmux | Self::Wssmux)
    }

    /// Transports that need a TLS certificate on the listening side.
    fn is_wss(self) -> bool {
        matches!(self, Self::Wss | Self::Wssmux)
    }

    /// Transports with no transport-level crypto of their own, for which the tunnel's own
    /// encryption is mandatory (it is never left to the user). `quic` is not here: it
    /// always encrypts with TLS 1.3 and requires `encryption = "auto"` separately.
    fn forces_encryption(self) -> bool {
        matches!(
            self,
            Self::Stealth
                | Self::Udp
                | Self::Faketcp
                | Self::Icmp
                | Self::Proto47
                | Self::Spoof
                | Self::Naive
                | Self::Xhttp
                | Self::Reality
        )
    }

    /// Transports whose mux cannot be turned off (the always-mux twins, the managed
    /// helpers, which run their own handshake and mux inside the helper stream, and `udp`,
    /// which forwards datagrams on the mux datagram path).
    fn forces_mux(self) -> bool {
        matches!(
            self,
            Self::Tcpmux
                | Self::Auto
                | Self::Wsmux
                | Self::Wssmux
                | Self::Udp
                | Self::Naive
                | Self::Xhttp
                | Self::Reality
        )
    }

    /// The KCP stack over some datagram carrier: `kcp` itself and the raw-packet carriers.
    pub fn is_kcp_based(self) -> bool {
        matches!(
            self,
            Self::Kcp
                | Self::Udp
                | Self::Faketcp
                | Self::Icmp
                | Self::Proto47
                | Self::Spoof
        )
    }

    /// The source-spoofing carrier (`transport = "spoof"`).
    pub fn is_spoof(self) -> bool {
        matches!(self, Self::Spoof)
    }

    /// A managed external-helper transport (`naive`, `xhttp`, `reality`).
    pub fn is_helper(self) -> bool {
        matches!(self, Self::Naive | Self::Xhttp | Self::Reality)
    }

    /// Packets may be lost on the wire (the KCP datagram path, QUIC datagrams), so
    /// `forward.duplicate` can help and probes do not warn.
    fn is_unreliable(self) -> bool {
        self.is_kcp_based() || self == Self::Quic
    }
}

/// Encryption of the tunnel traffic, above the transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
pub enum Encryption {
    /// AES-256-GCM when the CPU has AES instructions, otherwise ChaCha20-Poly1305.
    #[default]
    #[serde(rename = "auto")]
    Auto,
    #[serde(rename = "chacha20-poly1305")]
    Chacha20Poly1305,
    #[serde(rename = "aes-256-gcm")]
    Aes256Gcm,
    #[serde(rename = "none")]
    None,
}

impl Encryption {
    pub fn name(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Chacha20Poly1305 => "chacha20-poly1305",
            Self::Aes256Gcm => "aes-256-gcm",
            Self::None => "none",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
pub enum ForwardProtocol {
    #[default]
    #[serde(rename = "tcp")]
    Tcp,
    #[serde(rename = "udp")]
    Udp,
    /// Both, on the same port.
    #[serde(rename = "tcp+udp")]
    TcpUdp,
}

impl ForwardProtocol {
    pub fn name(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::TcpUdp => "tcp+udp",
        }
    }

    pub fn has_tcp(self) -> bool {
        matches!(self, Self::Tcp | Self::TcpUdp)
    }

    pub fn has_udp(self) -> bool {
        matches!(self, Self::Udp | Self::TcpUdp)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub role: Role,
    pub mode: Mode,
    #[serde(default)]
    pub profile: Profile,
    pub tunnel: TunnelConfig,
    /// The layer-3 / GRE direct-tunnel mode. When present, the tunnel carries whole IP
    /// packets over a TUN interface instead of forwarding ports; see [`L3Config`].
    pub l3: Option<L3Config>,
    #[serde(default)]
    pub forward: Vec<Forward>,
    #[serde(default)]
    pub tuning: TuningOverrides,
    #[serde(default)]
    pub log: LogConfig,
    #[serde(default)]
    pub control: ControlConfig,
    /// The file this was loaded from, if it was (see [`Config::load`]).
    #[serde(skip)]
    pub path: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunnelConfig {
    #[serde(default)]
    pub transport: TransportKind,
    /// Address to listen on for tunnel connections (entry in reverse mode, exit in direct mode).
    pub listen: Option<String>,
    /// Address of the other side (exit in reverse mode, entry in direct mode).
    pub remote: Option<String>,
    /// Shared secret. Both sides must use the same value.
    pub token: String,
    /// Reverse mode only: idle tunnel connections the exit keeps open towards the entry.
    #[serde(default = "default_pool")]
    pub pool: usize,
    #[serde(default)]
    pub encryption: Encryption,
    #[serde(default)]
    pub mux: MuxConfig,
    /// Only for `ws` and `wss`.
    pub ws: Option<WsConfig>,
    /// Only for `wss`.
    pub tls: Option<TlsConfig>,
    /// Only for `quic`.
    pub quic: Option<QuicConfig>,
    /// Only for `kcp`, `udp`, `faketcp` and `icmp` (all KCP carriers).
    pub kcp: Option<KcpConfig>,
    /// Only for `stealth`.
    pub stealth: Option<StealthConfig>,
    /// Only for `faketcp`.
    pub faketcp: Option<FaketcpConfig>,
    /// Only for `icmp`.
    pub icmp: Option<IcmpConfig>,
    /// Only for the `[l3]` carrier `proto47`.
    pub proto47: Option<Proto47Config>,
    /// Only for `spoof`: the on-wire packet shape, the forged source-IP pool and the
    /// peer's real address.
    pub spoof: Option<SpoofConfig>,
    /// Only for the managed helper transports `naive`, `xhttp` and `reality`.
    pub helper: Option<HelperConfig>,
    /// Transports the tunnel falls back to, in order, when the primary one cannot be
    /// established; the primary transport is implicitly tried first. Both sides must use
    /// the same list in the same order. Empty (the default) turns fallback off. Not
    /// allowed with `transport = "auto"`.
    #[serde(default)]
    pub fallback_transports: Vec<TransportKind>,
    /// How long a fallback candidate is held while it tries to connect (seconds). Minimum
    /// 10; default 60.
    #[serde(default = "default_fallback_dwell")]
    pub fallback_dwell_secs: u64,
    /// The exit side answers speed test streams (`kariz speedtest` on the entry side).
    /// They only produce, consume and echo data; they dial nothing.
    #[serde(default = "default_true")]
    pub speedtest: bool,
}

fn default_fallback_dwell() -> u64 {
    60
}

/// `[control]`: the entry side's local control socket, through which `kariz speedtest`
/// uses the running daemon's live sessions (Unix only).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlConfig {
    /// Where the socket goes. Default: the config file's path with `.sock` instead of
    /// `.toml` (`/etc/kariz/main.toml` -> `/etc/kariz/main.sock`). Owner only.
    pub socket: Option<PathBuf>,
}

/// `[tunnel.kcp]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KcpConfig {
    #[serde(default)]
    pub mode: KcpMode,
    /// `mode = "manual"` only; unset ones are taken from `fast2`.
    pub nodelay: Option<bool>,
    pub interval_ms: Option<u32>,
    pub resend: Option<u32>,
    pub no_congestion: Option<bool>,
    /// In packets.
    #[serde(default = "default_kcp_window")]
    pub send_window: u16,
    #[serde(default = "default_kcp_window")]
    pub recv_window: u16,
    /// KCP packet size (its 24-byte header included); the UDP packet adds 29 bytes of
    /// protection, 43 with FEC.
    #[serde(default = "default_kcp_mtu")]
    pub mtu: usize,
    /// Reed-Solomon FEC: parity packets per group of data packets; both 0 = off. Unset:
    /// the profile's default (`Config::kcp`).
    pub fec_data: Option<usize>,
    pub fec_parity: Option<usize>,
    /// UDP flows take the datagram path beside KCP. Off:
    /// they stay in the reliable stream, as in v0.4 (never lost, but a lost segment makes
    /// them wait for its retransmission).
    #[serde(default = "default_true")]
    pub datagrams: bool,
}

fn default_true() -> bool {
    true
}

fn default_kcp_window() -> u16 {
    1024
}

fn default_kcp_mtu() -> usize {
    1350
}

/// Same values as a `[tunnel.kcp]` table with nothing in it.
impl Default for KcpConfig {
    fn default() -> Self {
        Self {
            mode: KcpMode::default(),
            nodelay: None,
            interval_ms: None,
            resend: None,
            no_congestion: None,
            send_window: default_kcp_window(),
            recv_window: default_kcp_window(),
            mtu: default_kcp_mtu(),
            fec_data: None,
            fec_parity: None,
            datagrams: true,
        }
    }
}

/// KCP presets, as in kcp-go / kcptun: from gentle to aggressive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KcpMode {
    Normal,
    Fast,
    #[default]
    Fast2,
    Fast3,
    /// `nodelay`, `interval_ms`, `resend` and `no_congestion` set by hand.
    Manual,
}

impl KcpMode {
    pub fn name(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Fast => "fast",
            Self::Fast2 => "fast2",
            Self::Fast3 => "fast3",
            Self::Manual => "manual",
        }
    }
}

/// The KCP parameters a mode stands for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KcpTiming {
    /// Minimum retransmission timeout 30 ms instead of 100 ms, and gentler backoff.
    pub nodelay: bool,
    /// How often KCP flushes: acks and retransmissions wait up to this long.
    pub interval_ms: u32,
    /// Retransmit after this many acks skip a packet (0: only on timeout).
    pub resend: u32,
    /// Send the whole window regardless of loss.
    pub no_congestion: bool,
}

impl KcpConfig {
    /// `(data, parity)` packets per FEC group, or `None` when FEC is off.
    pub fn fec(&self) -> Option<(usize, usize)> {
        let (data, parity) = (self.fec_data.unwrap_or(0), self.fec_parity.unwrap_or(0));
        (data > 0).then_some((data, parity))
    }

    pub fn timing(&self) -> KcpTiming {
        let preset = |nodelay, interval_ms, resend, no_congestion| KcpTiming {
            nodelay,
            interval_ms,
            resend,
            no_congestion,
        };
        match self.mode {
            KcpMode::Normal => preset(false, 40, 2, true),
            KcpMode::Fast => preset(false, 30, 2, true),
            KcpMode::Fast2 => preset(true, 20, 2, true),
            KcpMode::Fast3 => preset(true, 10, 2, true),
            KcpMode::Manual => {
                let fast2 = KcpConfig::default().timing();
                preset(
                    self.nodelay.unwrap_or(fast2.nodelay),
                    self.interval_ms.unwrap_or(fast2.interval_ms),
                    self.resend.unwrap_or(fast2.resend),
                    self.no_congestion.unwrap_or(fast2.no_congestion),
                )
            }
        }
    }
}

/// `[tunnel.stealth]`: the record-padding and timing-jitter knobs of the `stealth`
/// transport. Padding applies only to stealth links (both ends know the transport), so no
/// other transport's wire is touched.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StealthConfig {
    /// Add random padding inside the AEAD record so record sizes do not leak the traffic
    /// shape.
    #[serde(default = "default_true")]
    pub padding: bool,
    /// Largest padding added to a record, in bytes.
    #[serde(default = "default_stealth_pad_max")]
    pub pad_max: u16,
    /// Random delay added before flushing a record, in milliseconds (0 = none).
    #[serde(default)]
    pub jitter_ms: u16,
}

fn default_stealth_pad_max() -> u16 {
    256
}

impl Default for StealthConfig {
    fn default() -> Self {
        Self {
            padding: true,
            pad_max: default_stealth_pad_max(),
            jitter_ms: 0,
        }
    }
}

/// `[tunnel.faketcp]`: the raw-socket fake-TCP carrier (Linux, root). All keys optional.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FaketcpConfig {
    /// The TCP flag pattern this end's segments carry: one of `A`, `PA`, `PA,A` or
    /// `PA,A,PA,PAU`. Each end sets only its own.
    #[serde(default = "default_faketcp_flags")]
    pub flags: String,
    /// Override the auto-detected egress interface (for virtualised networks).
    #[serde(default)]
    pub interface: String,
    /// Override the auto-detected next-hop MAC address.
    #[serde(default)]
    pub gateway_mac: String,
    /// Install and remove the RST-drop and NOTRACK iptables rules (RAII). Off: the tunnel
    /// still runs but is unreliable under load.
    #[serde(default = "default_true")]
    pub manage_firewall: bool,
}

fn default_faketcp_flags() -> String {
    "PA".into()
}

impl Default for FaketcpConfig {
    fn default() -> Self {
        Self {
            flags: default_faketcp_flags(),
            interface: String::new(),
            gateway_mac: String::new(),
            manage_firewall: true,
        }
    }
}

/// The TCP flag patterns a `faketcp` end may send.
const FAKETCP_FLAGS: &[&str] = &["A", "PA", "PA,A", "PA,A,PA,PAU"];

/// `[tunnel.icmp]`: the raw ICMP-echo carrier (Linux, root). All keys optional.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IcmpConfig {
    /// Install and remove the iptables rules that suppress the kernel's automatic echo
    /// replies and accept our own echoes (RAII). Off: the tunnel still runs but pays the
    /// extra uplink.
    #[serde(default = "default_true")]
    pub manage_firewall: bool,
}

impl Default for IcmpConfig {
    fn default() -> Self {
        Self {
            manage_firewall: true,
        }
    }
}

/// `[tunnel.proto47]`: the raw IP protocol-47 (GRE) carrier (Linux, root). Only meaningful
/// as an `[l3]` carrier. All keys optional.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proto47Config {
    /// Install and remove the best-effort iptables rule that accepts protocol 47 under a
    /// default-DROP INPUT policy (RAII). Off: the tunnel still runs unless such a policy
    /// blocks it.
    #[serde(default = "default_true")]
    pub manage_firewall: bool,
}

impl Default for Proto47Config {
    fn default() -> Self {
        Self {
            manage_firewall: true,
        }
    }
}

/// The on-wire packet shape the `spoof` carrier crafts around each sealed KCP packet. Both
/// ends must choose the same shape. The sealed payload is always Kariz's encrypted,
/// authenticated framing; the shape only decides what the forged packet looks like to the
/// network, so a path can be matched to whatever it lets through.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SpoofShape {
    /// A UDP datagram (realistic source/destination ports). The default.
    #[default]
    Udp,
    /// A crafted TCP segment, like `faketcp` but with a forged source (realistic
    /// seq/ack/window/flags).
    Tcp,
    /// An ICMP echo request carrying the sealed packet in its data.
    Icmp,
    /// A raw IP protocol-47 (GRE-numbered) packet.
    Gre,
    /// A raw IP protocol-4 (IP-in-IP-numbered) packet.
    Ipip,
    /// A raw IP protocol-58 (ICMPv6-numbered) packet, carried over IPv4.
    Proto58,
}

impl SpoofShape {
    pub fn name(self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
            Self::Icmp => "icmp",
            Self::Gre => "gre",
            Self::Ipip => "ipip",
            Self::Proto58 => "proto58",
        }
    }

    /// The IP protocol number this shape puts on the wire.
    pub fn ip_protocol(self) -> u8 {
        match self {
            Self::Udp => 17,
            Self::Tcp => 6,
            Self::Icmp => 1,
            Self::Ipip => 4,
            Self::Gre => 47,
            Self::Proto58 => 58,
        }
    }

    /// Shapes that address a destination port (and so can share a host by port).
    pub fn has_ports(self) -> bool {
        matches!(self, Self::Udp | Self::Tcp)
    }
}

/// `[tunnel.spoof]`: the source-spoofing carrier (Linux, root). Both ends forge their
/// source IP and must be told the other's real address, so neither side learns the peer
/// from the (forged) packets. All keys optional except, in practice, a non-empty `pool`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpoofConfig {
    /// The on-wire packet shape (`udp`, `tcp`, `icmp`, `gre`, `ipip` or `proto58`).
    #[serde(default)]
    pub shape: SpoofShape,
    /// The pool of source addresses to forge, rotated round-robin per packet. Each entry is
    /// a single IPv4 address (`203.0.113.7`), a CIDR block (`203.0.113.0/24`) or an
    /// inclusive range (`203.0.113.1-203.0.113.9`). Expanded and de-duplicated at load,
    /// capped at [`SPOOF_POOL_MAX`] addresses. Both ends keep their own pool.
    #[serde(default)]
    pub pool: Vec<String>,
    /// The peer's real address, which the forged packets never reveal. The dialing side
    /// already has it as `remote`; the accepting side needs it here to address its replies.
    /// `host:port` or a bare host; the port defaults to the tunnel's own.
    #[serde(default)]
    pub peer: Option<String>,
    /// Override the auto-detected egress interface (for virtualised networks), like
    /// `[tunnel.faketcp]`.
    #[serde(default)]
    pub interface: String,
    /// Install and remove the best-effort iptables rules that keep the carrier's packets
    /// flowing under a default-DROP policy and suppress the kernel's stray replies (RAII).
    #[serde(default = "default_true")]
    pub manage_firewall: bool,
}

impl Default for SpoofConfig {
    fn default() -> Self {
        Self {
            shape: SpoofShape::default(),
            pool: Vec::new(),
            peer: None,
            interface: String::new(),
            manage_firewall: true,
        }
    }
}

/// The largest forged-source pool the carrier will expand to; a wide CIDR is capped here.
pub const SPOOF_POOL_MAX: usize = 1024;

impl SpoofConfig {
    /// Expands the `pool` entries (single IPs, CIDR blocks, inclusive ranges) into a
    /// de-duplicated, order-preserving list of IPv4 addresses, capped at
    /// [`SPOOF_POOL_MAX`]. See [`expand_ipv4_specs`].
    pub fn expand_pool(&self) -> Result<Vec<Ipv4Addr>> {
        expand_ipv4_specs(&self.pool, SPOOF_POOL_MAX)
    }
}

/// Expands a list of address specs (single IPs, CIDR blocks, `a.b.c.d-e.f.g.h` ranges) into
/// a de-duplicated, order-preserving list of usable IPv4 addresses, capped at `cap`. Rejects
/// a malformed entry or a multicast/broadcast/unspecified address. Shared by the spoof
/// pool and the `kariz spooftest` source list.
pub fn expand_ipv4_specs(entries: &[String], cap: usize) -> Result<Vec<Ipv4Addr>> {
    let mut out: Vec<Ipv4Addr> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for entry in entries {
        for ip in parse_pool_entry(entry.trim())? {
            if ip.is_unspecified() || ip.is_broadcast() || ip.is_multicast() {
                bail!("{ip} is not a usable source address");
            }
            if seen.insert(ip) {
                out.push(ip);
                if out.len() >= cap {
                    return Ok(out);
                }
            }
        }
    }
    Ok(out)
}

/// Parses one spoof-pool entry into the addresses it names: a single address, a CIDR block
/// (`a.b.c.d/len`, host addresses only) or an inclusive range (`a.b.c.d-e.f.g.h`).
fn parse_pool_entry(entry: &str) -> Result<Vec<Ipv4Addr>> {
    if entry.is_empty() {
        return Ok(Vec::new());
    }
    if let Some((base, len)) = entry.split_once('/') {
        let base: Ipv4Addr = base
            .trim()
            .parse()
            .with_context(|| format!("tunnel.spoof.pool: {entry:?} is not a valid CIDR"))?;
        let len: u32 = len
            .trim()
            .parse()
            .with_context(|| format!("tunnel.spoof.pool: {entry:?} has a bad prefix length"))?;
        if len > 32 {
            bail!("tunnel.spoof.pool: {entry:?} prefix length must be 0-32");
        }
        let base = u32::from(base);
        let (start, count) = if len == 32 {
            (base, 1u64)
        } else {
            let mask = u32::MAX << (32 - len);
            let network = base & mask;
            let size = 1u64 << (32 - len);
            // Skip the network and broadcast addresses for a real subnet.
            if size >= 2 {
                (network + 1, size - 2)
            } else {
                (network, size)
            }
        };
        let count = count.min(SPOOF_POOL_MAX as u64);
        return Ok((0..count)
            .map(|i| Ipv4Addr::from(start.wrapping_add(i as u32)))
            .collect());
    }
    if let Some((lo, hi)) = entry.split_once('-') {
        let lo: Ipv4Addr = lo
            .trim()
            .parse()
            .with_context(|| format!("tunnel.spoof.pool: {entry:?} has a bad range start"))?;
        let hi: Ipv4Addr = hi
            .trim()
            .parse()
            .with_context(|| format!("tunnel.spoof.pool: {entry:?} has a bad range end"))?;
        let (lo, hi) = (u32::from(lo), u32::from(hi));
        if hi < lo {
            bail!("tunnel.spoof.pool: {entry:?} range end is before its start");
        }
        let count = ((hi - lo) as u64 + 1).min(SPOOF_POOL_MAX as u64);
        return Ok((0..count)
            .map(|i| Ipv4Addr::from(lo.wrapping_add(i as u32)))
            .collect());
    }
    let ip: Ipv4Addr = entry
        .parse()
        .with_context(|| format!("tunnel.spoof.pool: {entry:?} is not a valid IPv4 address"))?;
    Ok(vec![ip])
}

/// `[tunnel.helper]`: credentials and paths for a managed helper transport (`naive`,
/// `xhttp`, `reality`). Which keys are required depends on the transport; see
/// [`Config::validate_helper`].
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelperConfig {
    /// Override the helper binary path (default: the installed pinned path).
    pub binary: Option<PathBuf>,
    /// `naive`: username and password of the naive credential.
    pub username: Option<String>,
    pub password: Option<String>,
    /// `xhttp` / `reality`: the VLESS client UUID (canonical form).
    pub uuid: Option<String>,
    /// `xhttp`: the HTTP path.
    pub path: Option<String>,
    /// `xhttp` / `reality`: the TLS server name.
    pub server_name: Option<String>,
    /// `xhttp`: the HTTP `Host` header.
    pub host: Option<String>,
    /// `reality`: the short id, hex, even length, at most 16 characters.
    pub short_id: Option<String>,
    /// `reality` acceptor: the X25519 private key (base64url, 32 bytes).
    pub private_key: Option<String>,
    /// `reality` dialer: the X25519 public key (base64url, 32 bytes).
    pub public_key: Option<String>,
    /// `reality` acceptor: the cover target, `host:port`.
    pub target: Option<String>,
    /// Acceptor TLS (`naive`, `xhttp`): certificate chain (PEM).
    pub certificate: Option<PathBuf>,
    /// Acceptor TLS (`naive`, `xhttp`): private key (PEM).
    pub key: Option<PathBuf>,
    /// Dialer: a CA bundle (PEM) to verify the helper server against.
    pub ca_file: Option<PathBuf>,
}

/// `[l3]`: the layer-3 / GRE direct tunnel. Creates a TUN interface on each host and
/// carries whole IP packets, GRE-encapsulated and sealed inside the tunnel's own session,
/// over an unreliable carrier. Linux only, root.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct L3Config {
    /// `dial` reaches out; `listen` waits for the inbound connection. Either host may
    /// dial, so both direct and reverse are possible.
    pub mode: L3Mode,
    /// `mode = "listen"`: the address to listen on. `mode = "dial"`: the peer's address.
    pub addr: String,
    /// Shared secret. Defaults to `[tunnel].token` when unset.
    pub token: Option<String>,
    /// `3` (default): a TUN device carrying whole IP packets. `2`: a TAP device carrying
    /// Ethernet frames (an encrypted GRETAP), for bridging.
    #[serde(default = "default_l3_layer")]
    pub layer: u8,
    /// This end's address on the tunnel, as a CIDR, e.g. `10.10.0.1/30`. Required for
    /// `layer = 3`; optional for `layer = 2` (an address-less TAP can simply be bridged).
    pub local_ip: Option<String>,
    /// The peer's address on the tunnel, e.g. `10.10.0.2`. Required for `layer = 3`.
    pub peer_ip: Option<String>,
    /// RFC 2890 key, letting several logical tunnels share a carrier. Both ends compare it.
    #[serde(default)]
    pub gre_key: u32,
    /// The interface name to create. Default: the next free `kzN`.
    pub iface: Option<String>,
    /// The carrier the sealed GRE packets ride. Reliable carriers are rejected (two
    /// retransmit timers melt down).
    pub carrier: L3Carrier,
    /// The TUN interface MTU.
    #[serde(default = "default_l3_mtu")]
    pub mtu: u16,
    /// Reed-Solomon FEC over the carrier: both unset = off.
    pub fec_data: Option<usize>,
    pub fec_parity: Option<usize>,
    /// Optional port forwarding over the TUN link (reuses the `[[forward]]` syntax).
    #[serde(default)]
    pub ports: Vec<Forward>,
    /// Accept forwarded UDP over the TUN link.
    #[serde(default)]
    pub accept_udp: bool,
    /// The encapsulation; always `gre` (both ends compare it in the handshake).
    #[serde(default = "default_l3_encap")]
    pub encap: String,
}

fn default_l3_mtu() -> u16 {
    1400
}

fn default_l3_layer() -> u8 {
    3
}

fn default_l3_encap() -> String {
    "gre".into()
}

/// `[l3] mode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum L3Mode {
    Dial,
    Listen,
}

impl L3Mode {
    pub fn name(self) -> &'static str {
        match self {
            Self::Dial => "dial",
            Self::Listen => "listen",
        }
    }
}

/// `[l3] carrier`: only unreliable carriers are allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum L3Carrier {
    Udp,
    Quic,
    Faketcp,
    Icmp,
    Proto47,
}

impl L3Carrier {
    pub fn name(self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::Quic => "quic",
            Self::Faketcp => "faketcp",
            Self::Icmp => "icmp",
            Self::Proto47 => "proto47",
        }
    }
}

/// `[tunnel.quic]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuicConfig {
    #[serde(default)]
    pub congestion: Congestion,
    /// Dialing side: server name in the handshake. Default: the host of `remote` when it
    /// is a name, none when it is an IP address (as browsers do).
    pub sni: Option<String>,
    /// Application protocol announced in the handshake (both sides must agree).
    #[serde(default = "default_alpn")]
    pub alpn: String,
    /// Seal every UDP packet with a key from the token, so the traffic does not look
    /// like QUIC to a middlebox (and the port answers nothing else). Both sides must
    /// agree; costs 28 bytes a packet and some CPU.
    #[serde(default)]
    pub obfs: bool,
}

fn default_alpn() -> String {
    "h3".into()
}

/// Same values as a `[tunnel.quic]` table with nothing in it.
impl Default for QuicConfig {
    fn default() -> Self {
        Self {
            congestion: Congestion::default(),
            sni: None,
            alpn: default_alpn(),
            obfs: false,
        }
    }
}

/// QUIC congestion controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Congestion {
    #[default]
    Cubic,
    /// Copes much better with random loss; experimental in quinn.
    Bbr,
    NewReno,
}

impl Congestion {
    pub fn name(self) -> &'static str {
        match self {
            Self::Cubic => "cubic",
            Self::Bbr => "bbr",
            Self::NewReno => "newreno",
        }
    }
}

/// `[tunnel.mux]`: many user connections over a few long-lived tunnel connections.
/// Unset values come from the profile, see [`MuxSettings`].
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MuxConfig {
    /// Default: on for `tcpmux`, `ws` and `wss`, off for `tcp`.
    pub enabled: Option<bool>,
    /// Long-lived tunnel connections to keep open.
    pub connections: Option<usize>,
    /// Maximum concurrent streams per tunnel connection.
    pub max_streams: Option<usize>,
    /// Per-stream flow-control window in bytes.
    pub stream_window: Option<usize>,
    /// Replace each tunnel connection after this many seconds.
    pub max_lifetime_secs: Option<u64>,
    /// Gather queued frames into larger writes (throughput) or write each at once
    /// (latency). Default: on, off in the gaming profile.
    pub coalesce: Option<bool>,
    /// Seconds between pings; a peer silent for twice as long is dead. Default:
    /// `tuning.keepalive_secs`.
    pub ping_interval_secs: Option<u64>,
    /// Bytes of UDP datagrams a session queues for sending before dropping. Default: the
    /// profile's.
    pub datagram_buffer: Option<usize>,
    /// UDP datagrams each flow queues on the receiving side before dropping the oldest.
    /// Default: the profile's.
    pub datagram_queue: Option<usize>,
    /// `TCP_NOTSENT_LOWAT` in bytes on TCP connections that carry mux; 0 turns it off.
    /// Default: 16384.
    pub notsent_lowat: Option<u32>,
}

/// `[tunnel.ws]`: WebSocket upgrade request.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WsConfig {
    #[serde(default = "default_ws_path")]
    pub path: String,
    /// `Host` header. Dialing side: sent instead of the `remote` host (lets `remote` be a
    /// CDN IP). Listening side: when set, requests for another host are rejected.
    pub host: Option<String>,
    /// Dialing side only.
    pub user_agent: Option<String>,
    /// Dialing side only: extra request headers.
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    /// Dialing side only: send the tunnel hello inside the upgrade request (in
    /// `Sec-WebSocket-Protocol`), saving a round trip. The listening side always
    /// accepts it.
    #[serde(default)]
    pub early_data: bool,
}

fn default_ws_path() -> String {
    "/".into()
}

/// `[tunnel.tls]`: TLS settings for `wss`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    /// Dialing side: server name to present, instead of the `remote` host.
    pub sni: Option<String>,
    /// Dialing side: accept only this certificate (hex SHA-256 of its DER encoding).
    pub pin_sha256: Option<String>,
    /// Dialing side: skip certificate verification. Unsafe; prefer `pin_sha256`.
    #[serde(default)]
    pub insecure: bool,
    /// Listening side: certificate chain (PEM).
    pub cert: Option<PathBuf>,
    /// Listening side: private key (PEM).
    pub key: Option<PathBuf>,
}

fn default_pool() -> usize {
    8
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Forward {
    /// Address users connect to on the entry side, e.g. `0.0.0.0:443`.
    pub listen: String,
    /// Address the exit side connects to, e.g. `127.0.0.1:443`.
    pub target: String,
    #[serde(default)]
    pub protocol: ForwardProtocol,
    /// UDP rules: how many times each packet is sent in all, both ways (1-3; default 1).
    /// Copies go only where packets may be lost (KCP's datagram path, QUIC datagrams).
    pub duplicate: Option<u8>,
    /// Milliseconds between the copies of a packet (0-50; default 5).
    pub duplicate_gap_ms: Option<u8>,
    /// TCP rules: the exit side starts each connection to the target with a PROXY
    /// protocol header (`v1` or `v2`) carrying the user's address, so the target sees who
    /// connected instead of the exit side. The target must expect it (Xray:
    /// `acceptProxyProtocol`), or every connection through this port breaks. Needs an
    /// exit side of 2.5 or newer. UDP flows never get one.
    pub proxy_protocol: Option<ProxyVersion>,
}

impl Forward {
    /// Packet duplication for this rule's UDP flows; `None` with a single copy.
    pub fn duplication(&self) -> Option<Duplicate> {
        let copies = self.duplicate.unwrap_or(1);
        (copies > 1).then(|| Duplicate {
            copies,
            gap_ms: self.duplicate_gap_ms.unwrap_or(DEFAULT_DUPLICATE_GAP_MS),
        })
    }
}

const DEFAULT_DUPLICATE_GAP_MS: u8 = 5;
const DUPLICATE_COPIES: std::ops::RangeInclusive<u8> = 1..=3;
const MAX_DUPLICATE_GAP_MS: u8 = 50;

/// Optional per-field overrides applied on top of the selected profile.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TuningOverrides {
    pub nodelay: Option<bool>,
    pub buffer_size: Option<usize>,
    pub keepalive_secs: Option<u64>,
    pub dial_timeout_secs: Option<u64>,
    pub handshake_timeout_secs: Option<u64>,
    /// Number of worker threads. Defaults to the number of CPU cores.
    pub threads: Option<usize>,
    /// Idle time after which a UDP flow is closed.
    pub udp_timeout_secs: Option<u64>,
    /// Concurrent UDP flows (client addresses) per UDP forward rule.
    pub udp_max_flows: Option<usize>,
    /// Entry side: open user connections and UDP flows one client address may have, over
    /// all forward rules; more are closed at once. Unset or 0: no limit.
    pub max_conns_per_ip: Option<u32>,
    /// DSCP mark for tunnel sockets and the exit's UDP sockets to targets (unset: none).
    pub dscp: Option<Dscp>,
}

/// A DSCP codepoint as written in `[tuning] dscp`: a name (`"ef"`, `"af41"`, `"cs4"`,
/// ...) or a number 0-63.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
pub enum Dscp {
    Name(String),
    Value(u64),
}

impl Dscp {
    /// The 6-bit codepoint; `None` for an unknown name or a number above 63.
    pub fn codepoint(&self) -> Option<u8> {
        match self {
            Self::Value(v) => u8::try_from(*v).ok().filter(|v| *v < 64),
            Self::Name(name) => DSCP_NAMES
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case(name))
                .map(|&(_, v)| v),
        }
    }

    /// The name of `codepoint`, if it has one.
    pub fn name_of(codepoint: u8) -> Option<&'static str> {
        DSCP_NAMES
            .iter()
            .find(|&&(_, v)| v == codepoint)
            .map(|&(n, _)| n)
    }
}

/// Codepoint names of RFC 2474 (class selectors), RFC 2597 (assured forwarding), RFC
/// 3246 (expedited forwarding), RFC 5865 (voice admit) and RFC 8622 (lower effort).
const DSCP_NAMES: [(&str, u8); 24] = [
    ("cs0", 0),
    ("le", 1),
    ("cs1", 8),
    ("af11", 10),
    ("af12", 12),
    ("af13", 14),
    ("cs2", 16),
    ("af21", 18),
    ("af22", 20),
    ("af23", 22),
    ("cs3", 24),
    ("af31", 26),
    ("af32", 28),
    ("af33", 30),
    ("cs4", 32),
    ("af41", 34),
    ("af42", 36),
    ("af43", 38),
    ("cs5", 40),
    ("va", 44),
    ("ef", 46),
    ("cs6", 48),
    ("cs7", 56),
    ("default", 0),
];

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    /// Colours and the startup banner's art: on a terminal (`auto`), always or never.
    #[serde(default)]
    pub color: LogColor,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            color: LogColor::default(),
        }
    }
}

/// `[log] color`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogColor {
    /// Colours on a terminal, unless `NO_COLOR` is set.
    #[default]
    Auto,
    Always,
    Never,
}

fn default_log_level() -> String {
    "info".into()
}

/// Effective tuning values after applying profile defaults and overrides.
#[derive(Debug, Clone)]
pub struct Tuning {
    pub nodelay: bool,
    pub buffer_size: usize,
    pub keepalive: Duration,
    pub dial_timeout: Duration,
    pub handshake_timeout: Duration,
    pub threads: Option<usize>,
    pub udp: UdpTuning,
    /// Open user connections and UDP flows per client address (entry side); `None`: no
    /// limit.
    pub max_conns_per_ip: Option<u32>,
    /// `TCP_NOTSENT_LOWAT` for tunnel connections, set when they carry mux. It keeps the
    /// kernel from queueing much unsent data, so what is sent next is decided by the mux
    /// writer (datagrams first, streams in turn) rather than by the order data entered
    /// the socket. Without it, a UDP packet waits behind everything already queued in the
    /// kernel on a slow link.
    pub notsent_lowat: Option<u32>,
    /// DSCP codepoint for tunnel sockets and the exit's UDP sockets to targets;
    /// `None` leaves the OS default (0).
    pub dscp: Option<u8>,
}

/// UDP forwarding limits and buffers (phase 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpTuning {
    /// A flow with no packet in either direction for this long is closed.
    pub timeout: Duration,
    /// Concurrent flows per UDP forward rule; packets from further clients are dropped.
    pub max_flows: usize,
    /// `SO_RCVBUF` / `SO_SNDBUF` of UDP sockets.
    pub socket_buffer: usize,
    /// Packets queued per flow and direction before dropping.
    pub flow_queue: usize,
    /// Datagram bytes a mux session queues for sending before dropping.
    pub session_buffer: usize,
}

impl UdpTuning {
    fn for_profile(profile: Profile) -> Self {
        let (socket_buffer, flow_queue, session_buffer) = match profile {
            Profile::Balanced => (1 << 20, 128, 256 * 1024),
            Profile::Ultraspeed => (4 << 20, 512, 1 << 20),
            Profile::Gaming => (1 << 20, 64, 128 * 1024),
        };
        Self {
            timeout: Duration::from_secs(60),
            // As many as a connection takes streams (each flow is one); 1024 was from the
            // time a connection took 512.
            max_flows: 4096,
            socket_buffer,
            flow_queue,
            session_buffer,
        }
    }
}

impl Tuning {
    pub fn for_profile(profile: Profile) -> Self {
        let buffer_size = match profile {
            Profile::Balanced => 64 * 1024,
            Profile::Ultraspeed => 256 * 1024,
            Profile::Gaming => 16 * 1024,
        };
        Self {
            nodelay: true,
            buffer_size,
            keepalive: Duration::from_secs(if profile == Profile::Gaming { 10 } else { 30 }),
            dial_timeout: Duration::from_secs(10),
            handshake_timeout: Duration::from_secs(10),
            threads: None,
            udp: UdpTuning::for_profile(profile),
            max_conns_per_ip: None,
            notsent_lowat: None,
            dscp: None,
        }
    }

    fn apply(mut self, o: &TuningOverrides) -> Self {
        if let Some(v) = o.nodelay {
            self.nodelay = v;
        }
        if let Some(v) = o.buffer_size {
            self.buffer_size = v;
        }
        if let Some(v) = o.keepalive_secs {
            self.keepalive = Duration::from_secs(v);
        }
        if let Some(v) = o.dial_timeout_secs {
            self.dial_timeout = Duration::from_secs(v);
        }
        if let Some(v) = o.handshake_timeout_secs {
            self.handshake_timeout = Duration::from_secs(v);
        }
        if o.threads.is_some() {
            self.threads = o.threads;
        }
        if let Some(v) = o.udp_timeout_secs {
            self.udp.timeout = Duration::from_secs(v);
        }
        if let Some(v) = o.udp_max_flows {
            self.udp.max_flows = v;
        }
        if let Some(v) = o.max_conns_per_ip {
            self.max_conns_per_ip = (v > 0).then_some(v);
        }
        // An invalid value is reported by `Config::validate`.
        if let Some(d) = &o.dscp {
            self.dscp = d.codepoint();
        }
        self
    }
}

/// Effective mux values after applying profile defaults and `[tunnel.mux]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MuxSettings {
    pub enabled: bool,
    pub connections: usize,
    pub max_streams: usize,
    pub stream_window: usize,
    pub max_lifetime: Option<Duration>,
    /// Coalesce queued frames into one record before writing; off means flush every frame.
    pub coalesce: bool,
    /// Ping interval (kmux pings, QUIC keep-alives); a peer silent for twice as long is
    /// dead.
    pub ping_interval: Duration,
    /// UDP datagram bytes a session queues for sending.
    pub datagram_buffer: usize,
    /// UDP datagrams each flow queues on the receiving side.
    pub datagram_queue: usize,
    /// `TCP_NOTSENT_LOWAT` for TCP connections carrying mux (see
    /// [`Tuning::notsent_lowat`]); `None`: off.
    pub notsent_lowat: Option<u32>,
}

impl MuxSettings {
    /// `tuning`: the profile's tuning with `[tuning]` applied, for the values mux takes
    /// from it by default.
    fn for_profile(profile: Profile, transport: TransportKind, tuning: &Tuning) -> Self {
        let (stream_window, connections) = match profile {
            Profile::Balanced => (256 * 1024, 4),
            Profile::Ultraspeed => (1024 * 1024, 8),
            Profile::Gaming => (64 * 1024, 2),
        };
        // QUIC streams do not block each other, so more connections only buy more
        // congestion windows; two keep a spare while one reconnects.
        let connections = if transport == TransportKind::Quic {
            2
        } else {
            connections
        };
        // A stalled transport is noticed after twice the ping: auto pings fast, to move on
        // to another one in a few seconds.
        let ping_interval = if transport == TransportKind::Auto {
            Duration::from_secs(crate::auto::PING_SECS)
        } else {
            tuning.keepalive
        };
        Self {
            enabled: transport != TransportKind::Tcp,
            connections,
            max_streams: MUX_DEFAULT_MAX_STREAMS,
            stream_window,
            max_lifetime: None,
            coalesce: profile != Profile::Gaming,
            ping_interval,
            datagram_buffer: tuning.udp.session_buffer,
            datagram_queue: tuning.udp.flow_queue,
            notsent_lowat: Some(NOTSENT_LOWAT),
        }
    }

    fn apply(mut self, o: &MuxConfig) -> Self {
        if let Some(v) = o.enabled {
            self.enabled = v;
        }
        if let Some(v) = o.connections {
            self.connections = v;
        }
        if let Some(v) = o.max_streams {
            self.max_streams = v;
        }
        if let Some(v) = o.stream_window {
            self.stream_window = v;
        }
        if let Some(v) = o.max_lifetime_secs {
            self.max_lifetime = Some(Duration::from_secs(v));
        }
        if let Some(v) = o.coalesce {
            self.coalesce = v;
        }
        if let Some(v) = o.ping_interval_secs {
            self.ping_interval = Duration::from_secs(v);
        }
        if let Some(v) = o.datagram_buffer {
            self.datagram_buffer = v;
        }
        if let Some(v) = o.datagram_queue {
            self.datagram_queue = v;
        }
        if let Some(v) = o.notsent_lowat {
            self.notsent_lowat = (v > 0).then_some(v);
        }
        self
    }
}

const MUX_CONNECTIONS: std::ops::RangeInclusive<usize> = 1..=64;
const MUX_MAX_STREAMS: std::ops::RangeInclusive<usize> = 1..=16384;
/// Streams per tunnel connection by default. A stream is one user connection or UDP flow
/// and costs nothing until it is used; at the limit new connections wait and then fail,
/// so it is set far above what a busy server carries (four connections: 16384 streams).
const MUX_DEFAULT_MAX_STREAMS: usize = 4096;
const MUX_STREAM_WINDOW: std::ops::RangeInclusive<usize> = 16 * 1024..=16 * 1024 * 1024;
const KCP_INTERVAL_MS: std::ops::RangeInclusive<u32> = 10..=1000;
const KCP_MAX_RESEND: u32 = 10;
const KCP_SEND_WINDOW: std::ops::RangeInclusive<u16> = 16..=32768;
/// KCP needs 128 to receive its largest messages.
const KCP_RECV_WINDOW: std::ops::RangeInclusive<u16> = 128..=32768;
/// The upper bound keeps the UDP packet (29 bytes of protection added) within 1472 bytes,
/// the most a 1500-byte path carries unfragmented.
const KCP_MTU: std::ops::RangeInclusive<usize> = 576..=1443;
/// With FEC the largest packet is a parity shard: 43 bytes added.
const KCP_MTU_FEC: usize = 1429;
const KCP_FEC_DATA: std::ops::RangeInclusive<usize> = 1..=64;
const KCP_FEC_PARITY: std::ops::RangeInclusive<usize> = 1..=32;
const MUX_MIN_LIFETIME_SECS: u64 = 60;
const MUX_PING_INTERVAL_SECS: std::ops::RangeInclusive<u64> = 1..=600;
const MUX_DATAGRAM_BUFFER: std::ops::RangeInclusive<usize> = 16 * 1024..=64 * 1024 * 1024;
const MUX_DATAGRAM_QUEUE: std::ops::RangeInclusive<usize> = 8..=65536;
const MUX_NOTSENT_LOWAT: std::ops::RangeInclusive<u32> = 4 * 1024..=16 * 1024 * 1024;
/// See [`Tuning::notsent_lowat`]. Over a throttled 20 Mbit/s link with four bulk
/// transfers next to UDP pings (`udp_latency_under_load`), it cut the UDP round trip
/// from about 340 ms to about 60 ms (the rest is the link's own buffer), with no
/// throughput cost on localhost. 16 KiB is also what large HTTP/2 deployments use.
const NOTSENT_LOWAT: u32 = 16 * 1024;
const UDP_TIMEOUT_SECS: std::ops::RangeInclusive<u64> = 5..=3600;
const UDP_MAX_FLOWS: std::ops::RangeInclusive<usize> = 1..=65536;
/// Keepalives (mux pings) at most this far apart keep a WebSocket through a CDN.
const CDN_IDLE_SAFE: Duration = Duration::from_secs(90);
/// `stealth` record padding bounds: enough to hide short records without wasting much.
const STEALTH_PAD_MAX: std::ops::RangeInclusive<u16> = 1..=4096;
const STEALTH_MAX_JITTER_MS: u16 = 1000;
/// A fallback candidate is held at least this long while it tries to connect.
const FALLBACK_MIN_DWELL_SECS: u64 = 10;
/// The l3 TUN interface MTU bounds.
const L3_MTU: std::ops::RangeInclusive<u16> = 576..=1500;

/// Request headers the WebSocket dialer sets itself.
const RESERVED_WS_HEADERS: &[&str] = &[
    "host",
    "upgrade",
    "connection",
    "content-length",
    "transfer-encoding",
    "sec-websocket-key",
    "sec-websocket-version",
    "sec-websocket-accept",
    "sec-websocket-protocol",
    "sec-websocket-extensions",
];

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read config file {}", path.display()))?;
        let mut config = Self::parse(&text)
            .with_context(|| format!("invalid config file {}", path.display()))?;
        config.path = Some(path.to_path_buf());
        Ok(config)
    }

    /// Where the control socket is: `[control] socket`, else next to the config file it
    /// was loaded from; `None` for a config that came from elsewhere.
    pub fn control_socket(&self) -> Option<PathBuf> {
        self.control
            .socket
            .clone()
            .or_else(|| self.path.as_ref().map(|p| p.with_extension("sock")))
    }

    pub fn parse(text: &str) -> Result<Self> {
        let config: Config = toml::from_str(text)?;
        config.validate()?;
        Ok(config)
    }

    /// Whether this side accepts tunnel connections (as opposed to dialing them).
    pub fn is_acceptor(&self) -> bool {
        matches!(
            (self.role, self.mode),
            (Role::Entry, Mode::Reverse) | (Role::Exit, Mode::Direct)
        )
    }

    pub fn tuning(&self) -> Tuning {
        let mut tuning = Tuning::for_profile(self.profile).apply(&self.tuning);
        let mux = self.mux();
        if mux.enabled {
            tuning.notsent_lowat = mux.notsent_lowat;
        }
        tuning
    }

    pub fn mux(&self) -> MuxSettings {
        let tuning = Tuning::for_profile(self.profile).apply(&self.tuning);
        MuxSettings::for_profile(self.profile, self.tunnel.transport, &tuning)
            .apply(&self.tunnel.mux)
    }

    /// Settings that are valid but weaken the tunnel; shown by `kariz check` and at startup.
    pub fn warnings(&self) -> Vec<&'static str> {
        let mut warnings = Vec::new();
        if self.tunnel.encryption == Encryption::None {
            warnings
                .push("tunnel.encryption = \"none\": traffic between the servers is not encrypted");
        }
        let mux = self.mux();
        let ping = if mux.enabled {
            mux.ping_interval
        } else {
            self.tuning().keepalive
        };
        if self.tunnel.transport.is_websocket() && ping > CDN_IDLE_SAFE {
            warnings.push(
                "the ping interval (tunnel.mux.ping_interval_secs, or tuning.keepalive_secs) \
                 is above 90 s: CDNs close WebSocket connections that are idle for about \
                 100 s (Cloudflare)",
            );
        }
        if self.forward.iter().any(|f| f.protocol.has_udp()) && !self.mux().enabled {
            warnings.push(
                "UDP is forwarded without mux: every UDP flow uses its own tunnel connection; \
                 enable tunnel.mux (or use tcpmux, ws, wss) for UDP",
            );
        }
        let unreliable = self.tunnel.transport.is_unreliable() && self.mux().enabled;
        if self.forward.iter().any(|f| f.duplication().is_some()) && !unreliable {
            warnings.push(
                "forward.duplicate has no effect here: copies are only sent over kcp (with mux) \
                 or quic, where packets may be lost; other transports deliver every packet",
            );
        }
        if self
            .tunnel
            .quic
            .as_ref()
            .is_some_and(|q| q.congestion == Congestion::Bbr)
        {
            warnings.push("tunnel.quic.congestion = \"bbr\": quinn marks its BBR as experimental");
        }
        if self.tunnel.tls.as_ref().is_some_and(|t| t.insecure) {
            warnings.push(
                "tunnel.tls.insecure = true: the server certificate is not verified; \
                 prefer tls.pin_sha256",
            );
        }
        if self.tuning().dscp.is_some() {
            if self.tunnel.transport == TransportKind::Quic {
                warnings.push(
                    "tuning.dscp does not mark QUIC tunnel packets: quinn sets the TOS byte of \
                     every packet itself (for ECN); the exit's UDP sockets to targets are \
                     still marked",
                );
            }
            if cfg!(windows) {
                warnings.push("tuning.dscp has no effect on Windows unless a QoS policy allows it");
            }
        }
        warnings
    }

    pub fn validate(&self) -> Result<()> {
        let built_without = match self.tunnel.transport {
            TransportKind::Quic if !cfg!(feature = "quic") => Some("quic"),
            TransportKind::Kcp if !cfg!(feature = "kcp") => Some("kcp"),
            TransportKind::Udp if !cfg!(feature = "kcp") => Some("udp"),
            TransportKind::Faketcp if !cfg!(feature = "rawlink") => Some("faketcp"),
            TransportKind::Icmp if !cfg!(feature = "rawlink") => Some("icmp"),
            TransportKind::Proto47 if !cfg!(feature = "rawlink") => Some("proto47"),
            TransportKind::Spoof if !cfg!(feature = "rawlink") => Some("spoof"),
            TransportKind::Naive if !cfg!(feature = "helpers") => Some("naive"),
            TransportKind::Xhttp if !cfg!(feature = "helpers") => Some("xhttp"),
            TransportKind::Reality if !cfg!(feature = "helpers") => Some("reality"),
            _ => None,
        };
        if let Some(feature) = built_without {
            bail!(
                "transport = \"{feature}\" is not in this build (built without the needed \
                 cargo feature)"
            );
        }
        if self.l3.is_some() && !cfg!(feature = "l3") {
            bail!("the [l3] mode is not in this build (built without the `l3` cargo feature)");
        }
        if self.tunnel.token.trim().len() < 16 {
            bail!("tunnel.token must be at least 16 characters (generate one with `kariz token`)");
        }
        if self.tunnel.token.contains("CHANGE-ME") {
            bail!("tunnel.token still has the sample value; generate one with `kariz token`");
        }
        // proto47 is a raw proto-47 (GRE) KCP carrier for the point-to-point `[l3]` link only:
        // it has no port, does not cross NAT and is identifiable on the wire, so it is not
        // offered as a standalone tunnel transport. (The `[l3]` path builds its own synthetic
        // carrier config, which is not validated through here.)
        if self.tunnel.transport == TransportKind::Proto47 {
            bail!("transport \"proto47\" is only available as an [l3] carrier");
        }

        // The l3 mode is self-contained: it has its own address, mode and (optional) token
        // in `[l3]`, and carries whole IP packets instead of the port-forwarding tables, so
        // the entry/exit forward checks below do not apply.
        if let Some(l3) = &self.l3 {
            return self.validate_l3(l3);
        }

        if self.is_acceptor() {
            if self.tunnel.listen.is_none() {
                bail!(
                    "tunnel.listen is required for role = \"{}\" in mode = \"{}\"",
                    role_name(self.role),
                    mode_name(self.mode)
                );
            }
        } else if self.tunnel.remote.is_none() {
            bail!(
                "tunnel.remote is required for role = \"{}\" in mode = \"{}\"",
                role_name(self.role),
                mode_name(self.mode)
            );
        }

        match self.role {
            Role::Entry => {
                if self.forward.is_empty() {
                    bail!("the entry side needs at least one [[forward]] rule");
                }
            }
            Role::Exit => {
                if !self.forward.is_empty() {
                    bail!("[[forward]] rules belong on the entry side, not on the exit side");
                }
            }
        }

        if self.mode == Mode::Reverse && self.role == Role::Exit && self.tunnel.pool == 0 {
            bail!("tunnel.pool must be at least 1");
        }

        for f in &self.forward {
            if f.target.len() > u16::MAX as usize {
                bail!("forward target is too long: {}", f.target);
            }
            if (f.duplicate.is_some() || f.duplicate_gap_ms.is_some()) && !f.protocol.has_udp() {
                bail!(
                    "forward {}: duplicate and duplicate_gap_ms are for UDP rules",
                    f.listen
                );
            }
            // Xray takes no PROXY header on UDP, and a UDP flow has no connection to
            // start with one.
            if f.proxy_protocol.is_some() && !f.protocol.has_tcp() {
                bail!(
                    "forward {}: proxy_protocol is for TCP rules (tcp or tcp+udp)",
                    f.listen
                );
            }
            if !DUPLICATE_COPIES.contains(&f.duplicate.unwrap_or(1)) {
                bail!("forward.duplicate must be between 1 and 3");
            }
            if f.duplicate_gap_ms.unwrap_or(0) > MAX_DUPLICATE_GAP_MS {
                bail!("forward.duplicate_gap_ms must be at most {MAX_DUPLICATE_GAP_MS}");
            }
        }

        let tuning = self.tuning();
        if tuning.buffer_size < 1024 {
            bail!("tuning.buffer_size must be at least 1024 bytes");
        }
        if tuning.threads == Some(0) {
            bail!("tuning.threads must be at least 1");
        }
        let udp_timeout = tuning.udp.timeout.as_secs();
        if !UDP_TIMEOUT_SECS.contains(&udp_timeout) {
            bail!(
                "tuning.udp_timeout_secs must be between {} and {}",
                UDP_TIMEOUT_SECS.start(),
                UDP_TIMEOUT_SECS.end()
            );
        }
        if !UDP_MAX_FLOWS.contains(&tuning.udp.max_flows) {
            bail!(
                "tuning.udp_max_flows must be between {} and {}",
                UDP_MAX_FLOWS.start(),
                UDP_MAX_FLOWS.end()
            );
        }
        if let Some(d) = self
            .tuning
            .dscp
            .as_ref()
            .filter(|d| d.codepoint().is_none())
        {
            bail!(
                "tuning.dscp must be a codepoint name (ef, af41, cs4, ...) or a number from \
                 0 to 63, not {d:?}"
            );
        }

        self.validate_mux()?;
        self.validate_ws()?;
        self.validate_tls()?;
        self.validate_quic()?;
        self.validate_kcp()?;
        self.validate_stealth()?;
        self.validate_faketcp()?;
        self.validate_icmp()?;
        self.validate_proto47()?;
        self.validate_spoof()?;
        self.validate_helper()?;
        self.validate_udp()?;
        self.validate_fallback()
    }

    fn validate_kcp(&self) -> Result<()> {
        let Some(k) = &self.tunnel.kcp else {
            return Ok(());
        };
        if !matches!(self.tunnel.transport, TransportKind::Auto)
            && !self.tunnel.transport.is_kcp_based()
        {
            bail!(
                "[tunnel.kcp] is only used with transport = \"kcp\", \"auto\", \"udp\", \
                 \"faketcp\" or \"icmp\""
            );
        }
        let manual = [
            k.nodelay.is_some(),
            k.interval_ms.is_some(),
            k.resend.is_some(),
            k.no_congestion.is_some(),
        ];
        if k.mode != KcpMode::Manual && manual.contains(&true) {
            bail!(
                "tunnel.kcp.nodelay, interval_ms, resend and no_congestion need \
                 mode = \"manual\" (mode = \"{}\" sets them)",
                k.mode.name()
            );
        }
        let timing = k.timing();
        if !KCP_INTERVAL_MS.contains(&timing.interval_ms) {
            bail!(
                "tunnel.kcp.interval_ms must be between {} and {}",
                KCP_INTERVAL_MS.start(),
                KCP_INTERVAL_MS.end()
            );
        }
        if timing.resend > KCP_MAX_RESEND {
            bail!("tunnel.kcp.resend must be at most {KCP_MAX_RESEND}");
        }
        for (name, window, range) in [
            ("send_window", k.send_window, KCP_SEND_WINDOW),
            ("recv_window", k.recv_window, KCP_RECV_WINDOW),
        ] {
            if !range.contains(&window) {
                bail!(
                    "tunnel.kcp.{name} must be between {} and {} packets",
                    range.start(),
                    range.end()
                );
            }
        }
        if !KCP_MTU.contains(&k.mtu) {
            bail!(
                "tunnel.kcp.mtu must be between {} and {} bytes",
                KCP_MTU.start(),
                KCP_MTU.end()
            );
        }
        match (k.fec_data.unwrap_or(0), k.fec_parity.unwrap_or(0)) {
            (0, 0) => {}
            (data, parity) if KCP_FEC_DATA.contains(&data) && KCP_FEC_PARITY.contains(&parity) => {
                if k.mtu > KCP_MTU_FEC {
                    bail!("tunnel.kcp.mtu must be at most {KCP_MTU_FEC} bytes with FEC");
                }
            }
            _ => bail!(
                "tunnel.kcp.fec_data must be between {} and {} and fec_parity between {} and \
                 {}, or both 0 (FEC off)",
                KCP_FEC_DATA.start(),
                KCP_FEC_DATA.end(),
                KCP_FEC_PARITY.start(),
                KCP_FEC_PARITY.end()
            ),
        }
        Ok(())
    }

    /// `[tunnel.kcp]` with the profile's defaults filled in: the gaming profile turns FEC
    /// on (10 data + 3 parity packets per group) unless the table sets `fec_data` or
    /// `fec_parity`, or an MTU too large for FEC. The `udp` transport keeps FEC off by
    /// default whatever the profile (its forwarded datagrams ride the bare unreliable
    /// path); a user who wants it can still set `[tunnel.kcp] fec_data`/`fec_parity`.
    pub fn kcp(&self) -> KcpConfig {
        let mut k = self.tunnel.kcp.clone().unwrap_or_default();
        let unset = k.fec_data.is_none() && k.fec_parity.is_none();
        if self.profile == Profile::Gaming
            && self.tunnel.transport != TransportKind::Udp
            && unset
            && k.mtu <= KCP_MTU_FEC
        {
            (k.fec_data, k.fec_parity) = (Some(10), Some(3));
        }
        k
    }

    fn validate_quic(&self) -> Result<()> {
        let quic = self.tunnel.transport == TransportKind::Quic;
        if self.tunnel.quic.is_some() && !quic {
            bail!("[tunnel.quic] is only used with transport = \"quic\"");
        }
        if !quic {
            return Ok(());
        }
        if self.tunnel.encryption != Encryption::Auto {
            bail!(
                "transport = \"quic\" always encrypts with TLS 1.3; leave tunnel.encryption \
                 at \"auto\""
            );
        }
        if !self.mux().enabled {
            bail!("transport = \"quic\" always multiplexes; tunnel.mux cannot be disabled");
        }
        let Some(q) = &self.tunnel.quic else {
            return Ok(());
        };
        if q.alpn.is_empty() || q.alpn.len() > 255 || !is_visible_ascii(&q.alpn) {
            bail!("tunnel.quic.alpn must be 1 to 255 visible ASCII characters");
        }
        if self.is_acceptor() && q.sni.is_some() {
            bail!("tunnel.quic.sni is only used by the dialing side");
        }
        if q.sni
            .as_deref()
            .is_some_and(|s| s.is_empty() || !is_visible_ascii(s) || s.contains('/'))
        {
            bail!("tunnel.quic.sni must be a host name");
        }
        Ok(())
    }

    fn validate_mux(&self) -> Result<()> {
        if self.tunnel.transport == TransportKind::Auto && self.tunnel.mux.enabled == Some(false) {
            bail!("transport = \"auto\" always uses mux; tunnel.mux cannot be disabled");
        }
        if self.tunnel.transport == TransportKind::Tcpmux && self.tunnel.mux.enabled == Some(false)
        {
            bail!("transport = \"tcpmux\" always uses mux; use transport = \"tcp\" to disable it");
        }
        if self.tunnel.transport.forces_mux()
            && !matches!(
                self.tunnel.transport,
                TransportKind::Auto | TransportKind::Tcpmux
            )
            && self.tunnel.mux.enabled == Some(false)
        {
            bail!(
                "transport = \"{}\" always uses mux; tunnel.mux cannot be disabled",
                self.tunnel.transport.name()
            );
        }
        let mux = self.mux();
        if !MUX_CONNECTIONS.contains(&mux.connections) {
            bail!(
                "tunnel.mux.connections must be between {} and {}",
                MUX_CONNECTIONS.start(),
                MUX_CONNECTIONS.end()
            );
        }
        if !MUX_MAX_STREAMS.contains(&mux.max_streams) {
            bail!(
                "tunnel.mux.max_streams must be between {} and {}",
                MUX_MAX_STREAMS.start(),
                MUX_MAX_STREAMS.end()
            );
        }
        if !MUX_STREAM_WINDOW.contains(&mux.stream_window) {
            bail!(
                "tunnel.mux.stream_window must be between {} and {} bytes",
                MUX_STREAM_WINDOW.start(),
                MUX_STREAM_WINDOW.end()
            );
        }
        if mux
            .max_lifetime
            .is_some_and(|d| d.as_secs() < MUX_MIN_LIFETIME_SECS)
        {
            bail!("tunnel.mux.max_lifetime_secs must be at least {MUX_MIN_LIFETIME_SECS}");
        }
        if !MUX_PING_INTERVAL_SECS.contains(&mux.ping_interval.as_secs()) {
            bail!(
                "tunnel.mux.ping_interval_secs must be between {} and {}",
                MUX_PING_INTERVAL_SECS.start(),
                MUX_PING_INTERVAL_SECS.end()
            );
        }
        if !MUX_DATAGRAM_BUFFER.contains(&mux.datagram_buffer) {
            bail!(
                "tunnel.mux.datagram_buffer must be between {} and {} bytes",
                MUX_DATAGRAM_BUFFER.start(),
                MUX_DATAGRAM_BUFFER.end()
            );
        }
        if !MUX_DATAGRAM_QUEUE.contains(&mux.datagram_queue) {
            bail!(
                "tunnel.mux.datagram_queue must be between {} and {} packets",
                MUX_DATAGRAM_QUEUE.start(),
                MUX_DATAGRAM_QUEUE.end()
            );
        }
        if mux
            .notsent_lowat
            .is_some_and(|v| !MUX_NOTSENT_LOWAT.contains(&v))
        {
            bail!(
                "tunnel.mux.notsent_lowat must be 0 (off) or between {} and {} bytes",
                MUX_NOTSENT_LOWAT.start(),
                MUX_NOTSENT_LOWAT.end()
            );
        }
        Ok(())
    }

    fn validate_ws(&self) -> Result<()> {
        let Some(ws) = &self.tunnel.ws else {
            return Ok(());
        };
        if !self.tunnel.transport.is_websocket() {
            bail!("[tunnel.ws] is only used with transport = \"ws\" or \"wss\"");
        }
        if !ws.path.starts_with('/') || !is_visible_ascii(&ws.path) {
            bail!("tunnel.ws.path must start with '/' and contain no spaces or control characters");
        }
        if ws
            .host
            .as_deref()
            .is_some_and(|h| h.is_empty() || !is_visible_ascii(h) || h.contains('/'))
        {
            bail!("tunnel.ws.host must be a host name, optionally with a port");
        }
        if self.is_acceptor() {
            if ws.user_agent.is_some() || !ws.headers.is_empty() || ws.early_data {
                bail!(
                    "tunnel.ws.user_agent, headers and early_data are only used by the \
                     dialing side"
                );
            }
            return Ok(());
        }
        if ws
            .user_agent
            .as_deref()
            .is_some_and(|ua| !is_header_value(ua))
        {
            bail!("tunnel.ws.user_agent contains invalid characters");
        }
        for (name, value) in &ws.headers {
            if !is_header_name(name) {
                bail!("tunnel.ws.headers: invalid header name {name:?}");
            }
            if RESERVED_WS_HEADERS.contains(&name.to_ascii_lowercase().as_str()) {
                bail!("tunnel.ws.headers: {name} is set by kariz itself");
            }
            if !is_header_value(value) {
                bail!("tunnel.ws.headers: invalid value for {name}");
            }
        }
        Ok(())
    }

    fn validate_tls(&self) -> Result<()> {
        // `wss`/`wssmux` as the primary or as a fallback candidate uses the table.
        let wss = self.tunnel.transport.is_wss()
            || self.tunnel.fallback_transports.iter().any(|k| k.is_wss());
        let tls = match (&self.tunnel.tls, wss) {
            (Some(_), false) => {
                bail!("[tunnel.tls] is only used with transport = \"wss\" or \"wssmux\"")
            }
            (None, false) => return Ok(()),
            (tls, true) => tls.clone().unwrap_or_default(),
        };
        if self.is_acceptor() {
            if tls.cert.is_none() || tls.key.is_none() {
                bail!(
                    "tunnel.tls.cert and tunnel.tls.key are required on the listening side of wss"
                );
            }
            if tls.sni.is_some() || tls.pin_sha256.is_some() || tls.insecure {
                bail!("tunnel.tls.sni, pin_sha256 and insecure are only used by the dialing side");
            }
            return Ok(());
        }
        if tls.cert.is_some() || tls.key.is_some() {
            bail!("tunnel.tls.cert and tunnel.tls.key are only used by the listening side");
        }
        if tls
            .sni
            .as_deref()
            .is_some_and(|s| s.is_empty() || !is_visible_ascii(s) || s.contains('/'))
        {
            bail!("tunnel.tls.sni must be a host name");
        }
        if let Some(pin) = &tls.pin_sha256 {
            if tls.insecure {
                bail!("tunnel.tls.pin_sha256 and tunnel.tls.insecure cannot be used together");
            }
            if pin.len() != 64 || !pin.bytes().all(|b| b.is_ascii_hexdigit()) {
                bail!(
                    "tunnel.tls.pin_sha256 must be 64 hex characters (SHA-256 of the certificate)"
                );
            }
        }
        Ok(())
    }

    fn validate_stealth(&self) -> Result<()> {
        let stealth = self.tunnel.transport == TransportKind::Stealth;
        if self.tunnel.stealth.is_some() && !stealth {
            bail!("[tunnel.stealth] is only used with transport = \"stealth\"");
        }
        if !stealth {
            return Ok(());
        }
        // Padding hides nothing without encryption, and the silent-on-bad-auth behaviour
        // is the whole point.
        if self.tunnel.encryption == Encryption::None {
            bail!("transport = \"stealth\" requires encryption; set tunnel.encryption");
        }
        if let Some(s) = &self.tunnel.stealth {
            if !STEALTH_PAD_MAX.contains(&s.pad_max) {
                bail!(
                    "tunnel.stealth.pad_max must be between {} and {} bytes",
                    STEALTH_PAD_MAX.start(),
                    STEALTH_PAD_MAX.end()
                );
            }
            if s.jitter_ms > STEALTH_MAX_JITTER_MS {
                bail!("tunnel.stealth.jitter_ms must be at most {STEALTH_MAX_JITTER_MS}");
            }
        }
        Ok(())
    }

    fn validate_faketcp(&self) -> Result<()> {
        let is_faketcp = self.tunnel.transport == TransportKind::Faketcp;
        if self.tunnel.faketcp.is_some() && !is_faketcp {
            bail!("[tunnel.faketcp] is only used with transport = \"faketcp\"");
        }
        if !is_faketcp {
            return Ok(());
        }
        // faketcp carries the KCP stack over raw TCP segments with no transport crypto of
        // its own, so the tunnel's own encryption is mandatory.
        if self.tunnel.encryption == Encryption::None {
            bail!("transport = \"faketcp\" requires encryption; set tunnel.encryption");
        }
        if let Some(f) = &self.tunnel.faketcp {
            if !FAKETCP_FLAGS.contains(&f.flags.as_str()) {
                bail!(
                    "tunnel.faketcp.flags must be one of {}",
                    FAKETCP_FLAGS.join(", ")
                );
            }
            if !f.interface.is_empty()
                && (f.interface.len() > 15 || !f.interface.bytes().all(|b| b.is_ascii_graphic()))
            {
                bail!("tunnel.faketcp.interface must be a short interface name");
            }
            if !f.gateway_mac.is_empty() && !is_mac(&f.gateway_mac) {
                bail!("tunnel.faketcp.gateway_mac must be a MAC address (aa:bb:cc:dd:ee:ff)");
            }
        }
        Ok(())
    }

    fn validate_icmp(&self) -> Result<()> {
        let is_icmp = self.tunnel.transport == TransportKind::Icmp;
        if self.tunnel.icmp.is_some() && !is_icmp {
            bail!("[tunnel.icmp] is only used with transport = \"icmp\"");
        }
        // icmp carries the KCP stack inside ICMP echoes with no transport crypto of its
        // own, so the tunnel's own encryption is mandatory.
        if is_icmp && self.tunnel.encryption == Encryption::None {
            bail!("transport = \"icmp\" requires encryption; set tunnel.encryption");
        }
        Ok(())
    }

    fn validate_proto47(&self) -> Result<()> {
        // proto47 is only ever an `[l3]` carrier (a standalone `transport = "proto47"` is
        // rejected above, and the `[l3]` path validates through `validate_l3`), so its table
        // has no place on a normal tunnel.
        if self.tunnel.proto47.is_some() {
            bail!("[tunnel.proto47] is only used with the [l3] carrier \"proto47\"");
        }
        Ok(())
    }

    fn validate_spoof(&self) -> Result<()> {
        let is_spoof = self.tunnel.transport == TransportKind::Spoof;
        if self.tunnel.spoof.is_some() && !is_spoof {
            bail!("[tunnel.spoof] is only used with transport = \"spoof\"");
        }
        if !is_spoof {
            return Ok(());
        }
        // spoof carries the KCP stack inside crafted packets with no transport crypto of
        // its own, so the tunnel's own encryption is mandatory.
        if self.tunnel.encryption == Encryption::None {
            bail!("transport = \"spoof\" requires encryption; set tunnel.encryption");
        }
        let spoof = self.tunnel.spoof.as_ref().ok_or_else(|| {
            anyhow::anyhow!(
                "transport = \"spoof\" needs a [tunnel.spoof] table (at least shape and pool)"
            )
        })?;
        // The forged-source pool must name at least one usable address, or there is nothing
        // to spoof. Expansion also rejects malformed or unusable entries.
        let pool = spoof.expand_pool()?;
        if pool.is_empty() {
            bail!(
                "tunnel.spoof.pool must list at least one source address to forge \
                 (an IP, a CIDR block or an a.b.c.d-e.f.g.h range)"
            );
        }
        if !spoof.interface.is_empty()
            && (spoof.interface.len() > 15
                || !spoof.interface.bytes().all(|b| b.is_ascii_graphic()))
        {
            bail!("tunnel.spoof.interface must be a short interface name");
        }
        // The accepting side cannot learn the dialer's real address from the (forged)
        // packets, so it must be told it; the dialing side already has it as `remote`.
        if self.is_acceptor() && spoof.peer.is_none() && self.tunnel.remote.is_none() {
            bail!(
                "transport = \"spoof\" on the accepting side needs the peer's real address: \
                 set tunnel.spoof.peer (the panel fills this in automatically)"
            );
        }
        Ok(())
    }

    fn validate_udp(&self) -> Result<()> {
        if self.tunnel.transport != TransportKind::Udp {
            return Ok(());
        }
        // The udp transport rides plain UDP datagrams with no transport crypto of its own,
        // so the tunnel's own encryption is mandatory.
        if self.tunnel.encryption == Encryption::None {
            bail!("transport = \"udp\" requires encryption; set tunnel.encryption");
        }
        // Forwarded datagrams ride the unreliable mux datagram path, which needs the KCP
        // datagram side; it is on by default and the udp transport cannot turn it off.
        if self.tunnel.kcp.as_ref().is_some_and(|k| !k.datagrams) {
            bail!(
                "transport = \"udp\" forwards on the datagram path; [tunnel.kcp] datagrams \
                 cannot be false"
            );
        }
        // The udp transport carries forwarded datagrams on the unreliable path; there is no
        // stream to run a TCP forward or a PROXY header over.
        for f in &self.forward {
            if f.protocol.has_tcp() {
                bail!(
                    "forward {}: transport = \"udp\" forwards UDP only; use protocol = \"udp\"",
                    f.listen
                );
            }
            if f.proxy_protocol.is_some() {
                bail!(
                    "forward {}: transport = \"udp\" has no stream for a PROXY header",
                    f.listen
                );
            }
        }
        Ok(())
    }

    fn validate_helper(&self) -> Result<()> {
        let helper = self.tunnel.transport.is_helper();
        if self.tunnel.helper.is_some() && !helper {
            bail!(
                "[tunnel.helper] is only used with transport = \"naive\", \"xhttp\" or \"reality\""
            );
        }
        if !helper {
            return Ok(());
        }
        // The helper proxies have surprising half-close semantics, so the tunnel always
        // runs its own handshake, record encryption and mux inside the helper stream.
        if self.tunnel.encryption == Encryption::None {
            bail!(
                "transport = \"{}\" requires encryption; set tunnel.encryption",
                self.tunnel.transport.name()
            );
        }
        // The managed helpers carry one TCP stream each; they cannot forward UDP.
        if self.forward.iter().any(|f| f.protocol.has_udp()) {
            bail!(
                "transport = \"{}\" cannot forward UDP; use tcp forward rules only",
                self.tunnel.transport.name()
            );
        }
        let h = self.tunnel.helper.clone().unwrap_or_default();
        let acceptor = self.is_acceptor();
        for (path, what) in [
            (&h.binary, "binary"),
            (&h.certificate, "certificate"),
            (&h.key, "key"),
            (&h.ca_file, "ca_file"),
        ] {
            if let Some(p) = path {
                if !p.is_absolute() {
                    bail!("tunnel.helper.{what} must be an absolute path");
                }
            }
        }
        match self.tunnel.transport {
            TransportKind::Naive => {
                if h.username.as_deref().unwrap_or_default().is_empty()
                    || h.password.as_deref().unwrap_or_default().is_empty()
                {
                    bail!("transport = \"naive\" needs tunnel.helper.username and password");
                }
                if acceptor && (h.certificate.is_none() || h.key.is_none()) {
                    bail!("the listening side of naive needs tunnel.helper.certificate and key");
                }
            }
            TransportKind::Xhttp => {
                let uuid = h.uuid.as_deref().unwrap_or_default();
                if !is_uuid(uuid) {
                    bail!("transport = \"xhttp\" needs a canonical tunnel.helper.uuid");
                }
                if h.path.as_deref().unwrap_or_default().is_empty() {
                    bail!("transport = \"xhttp\" needs tunnel.helper.path");
                }
                if h.server_name.as_deref().unwrap_or_default().is_empty() {
                    bail!("transport = \"xhttp\" needs tunnel.helper.server_name");
                }
                if acceptor && (h.certificate.is_none() || h.key.is_none()) {
                    bail!("the listening side of xhttp needs tunnel.helper.certificate and key");
                }
            }
            TransportKind::Reality => {
                let uuid = h.uuid.as_deref().unwrap_or_default();
                if !is_uuid(uuid) {
                    bail!("transport = \"reality\" needs a canonical tunnel.helper.uuid");
                }
                let short_id = h.short_id.as_deref().unwrap_or_default();
                if short_id.len() > 16
                    || short_id.len() % 2 != 0
                    || !short_id.bytes().all(|b| b.is_ascii_hexdigit())
                {
                    bail!(
                        "tunnel.helper.short_id must be hex, an even length, and at most 16 \
                         characters"
                    );
                }
                if h.server_name.as_deref().unwrap_or_default().is_empty() {
                    bail!("transport = \"reality\" needs tunnel.helper.server_name");
                }
                if acceptor {
                    if !is_base64url_32(h.private_key.as_deref().unwrap_or_default()) {
                        bail!(
                            "the listening side of reality needs tunnel.helper.private_key \
                             (base64url, 32 bytes)"
                        );
                    }
                    if h.target.as_deref().unwrap_or_default().is_empty() {
                        bail!("the listening side of reality needs tunnel.helper.target");
                    }
                } else if !is_base64url_32(h.public_key.as_deref().unwrap_or_default()) {
                    bail!(
                        "the dialing side of reality needs tunnel.helper.public_key \
                         (base64url, 32 bytes)"
                    );
                }
            }
            _ => unreachable!("helper is only naive, xhttp or reality"),
        }
        Ok(())
    }

    fn validate_fallback(&self) -> Result<()> {
        let list = &self.tunnel.fallback_transports;
        if list.is_empty() {
            return Ok(());
        }
        if self.tunnel.transport == TransportKind::Auto {
            bail!("tunnel.fallback_transports is not allowed with transport = \"auto\"");
        }
        // The udp transport forwards UDP only, on the unreliable path, so it cannot share a
        // fallback chain with transports that carry TCP or forward reliably.
        if self.tunnel.transport == TransportKind::Udp {
            bail!("tunnel.fallback_transports is not allowed with transport = \"udp\"");
        }
        if self.tunnel.fallback_dwell_secs < FALLBACK_MIN_DWELL_SECS {
            bail!("tunnel.fallback_dwell_secs must be at least {FALLBACK_MIN_DWELL_SECS}");
        }
        for (i, kind) in list.iter().enumerate() {
            if *kind == TransportKind::Auto {
                bail!("tunnel.fallback_transports cannot contain \"auto\"");
            }
            if *kind == TransportKind::Udp {
                bail!("tunnel.fallback_transports cannot contain \"udp\"");
            }
            if *kind == TransportKind::Proto47 {
                bail!("tunnel.fallback_transports cannot contain \"proto47\" (it is only an [l3] carrier)");
            }
            if *kind == self.tunnel.transport {
                bail!(
                    "tunnel.fallback_transports lists the primary transport \"{}\"; it is \
                     tried first implicitly",
                    kind.name()
                );
            }
            if list[..i].contains(kind) {
                bail!(
                    "tunnel.fallback_transports has a duplicate: \"{}\"",
                    kind.name()
                );
            }
            // Every candidate is held to the same rules as a primary. The per-transport
            // validators only check the configured transport, so a candidate's mandatory
            // encryption and TLS table are enforced here.
            if kind.forces_encryption() && self.tunnel.encryption == Encryption::None {
                bail!(
                    "tunnel.fallback_transports has \"{}\", which requires encryption; set \
                     tunnel.encryption",
                    kind.name()
                );
            }
            if kind.is_helper() {
                bail!(
                    "tunnel.fallback_transports cannot contain the managed helper transport \
                     \"{}\"",
                    kind.name()
                );
            }
            if kind.is_wss() && self.is_acceptor() {
                let tls = self.tunnel.tls.as_ref();
                if tls.and_then(|t| t.cert.as_deref()).is_none()
                    || tls.and_then(|t| t.key.as_deref()).is_none()
                {
                    bail!(
                        "tunnel.fallback_transports has \"{}\", which needs [tunnel.tls] cert \
                         and key on the listening side",
                        kind.name()
                    );
                }
            }
        }
        Ok(())
    }

    fn validate_l3(&self, l3: &L3Config) -> Result<()> {
        if l3.encap != "gre" {
            bail!("l3.encap must be \"gre\"");
        }
        // The GRE header and the inner IP packets are sealed inside the tunnel's own
        // handshake + record session (never bare IP proto 47 on the wire), so the tunnel's
        // encryption is mandatory for the l3 mode.
        if self.tunnel.encryption == Encryption::None {
            bail!("the [l3] / GRE tunnel requires encryption; set tunnel.encryption");
        }
        // Reliable carriers (tcp/tcpmux/ws/wss and reliable KCP) would stack two retransmit
        // timers (TCP-over-TCP meltdown); the `L3Carrier` enum only parses the unreliable
        // carriers udp/quic/faketcp/icmp, so a reliable one is rejected at deserialize time.
        let token = l3.token.as_deref().unwrap_or(&self.tunnel.token);
        if token.trim().len() < 16 {
            bail!("l3.token must be at least 16 characters");
        }
        if token.contains("CHANGE-ME") {
            bail!("l3.token still has the sample value; generate one with `kariz token`");
        }
        // `layer = 3` is a TUN (IP packets); `layer = 2` is a TAP (Ethernet frames / an
        // encrypted GRETAP). Nothing else exists.
        if l3.layer != 2 && l3.layer != 3 {
            bail!("l3.layer must be 3 (TUN, IP packets) or 2 (TAP, Ethernet frames)");
        }
        // Layer 3 carries IP, so each end needs its tunnel address. Layer 2 carries whole
        // Ethernet frames and may come up address-less to be put in a bridge, so the
        // addresses are optional there; whatever is given is still checked.
        if l3.layer == 3 && l3.local_ip.is_none() {
            bail!("l3.local_ip is required for layer = 3 (e.g. \"10.10.0.1/30\")");
        }
        if l3.layer == 3 && l3.peer_ip.is_none() {
            bail!("l3.peer_ip is required for layer = 3 (e.g. \"10.10.0.2\")");
        }
        if let Some(local_ip) = &l3.local_ip {
            parse_cidr(local_ip)
                .with_context(|| format!("l3.local_ip is not a valid CIDR: {local_ip}"))?;
        }
        if let Some(peer_ip) = &l3.peer_ip {
            peer_ip
                .parse::<std::net::IpAddr>()
                .with_context(|| format!("l3.peer_ip is not a valid IP address: {peer_ip}"))?;
        }
        if let Some(iface) = &l3.iface {
            // Interface names are bounded (IFNAMSIZ is 16, including the NUL).
            if iface.is_empty() || iface.len() > 15 || iface.contains(['/', ' ']) {
                bail!("l3.iface must be a valid interface name (1-15 chars, no '/' or space)");
            }
        }
        if !L3_MTU.contains(&l3.mtu) {
            bail!(
                "l3.mtu must be between {} and {}",
                L3_MTU.start(),
                L3_MTU.end()
            );
        }
        match (l3.fec_data.unwrap_or(0), l3.fec_parity.unwrap_or(0)) {
            (0, 0) => {}
            (data, parity) if KCP_FEC_DATA.contains(&data) && KCP_FEC_PARITY.contains(&parity) => {}
            _ => bail!(
                "l3.fec_data must be between {} and {} and fec_parity between {} and {}, or \
                 both 0 (FEC off)",
                KCP_FEC_DATA.start(),
                KCP_FEC_DATA.end(),
                KCP_FEC_PARITY.start(),
                KCP_FEC_PARITY.end()
            ),
        }
        for f in &l3.ports {
            if f.proxy_protocol.is_some() && !f.protocol.has_tcp() {
                bail!("l3 forward {}: proxy_protocol is for TCP rules", f.listen);
            }
        }
        Ok(())
    }
}

/// Parses an `addr/prefix` CIDR, returning the address and prefix length.
fn parse_cidr(s: &str) -> Result<(std::net::IpAddr, u8)> {
    let (addr, prefix) = s
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("missing /prefix"))?;
    let addr: std::net::IpAddr = addr.parse()?;
    let prefix: u8 = prefix.parse()?;
    let max = if addr.is_ipv4() { 32 } else { 128 };
    if prefix > max {
        bail!("prefix length {prefix} is too large");
    }
    Ok((addr, prefix))
}

/// A canonical lowercase UUID: `8-4-4-4-12` hex digits.
fn is_uuid(s: &str) -> bool {
    let groups = [8, 4, 4, 4, 12];
    let parts: Vec<&str> = s.split('-').collect();
    parts.len() == groups.len()
        && parts
            .iter()
            .zip(groups)
            .all(|(p, n)| p.len() == n && p.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// True when `s` is base64url (no padding) of exactly 32 bytes.
fn is_base64url_32(s: &str) -> bool {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .is_ok_and(|b| b.len() == 32)
}

/// A MAC address `aa:bb:cc:dd:ee:ff`.
fn is_mac(s: &str) -> bool {
    let parts: Vec<&str> = s.split(':').collect();
    parts.len() == 6
        && parts
            .iter()
            .all(|p| p.len() == 2 && p.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn is_visible_ascii(s: &str) -> bool {
    s.bytes().all(|b| b.is_ascii_graphic())
}

/// RFC 9110 token.
fn is_header_name(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

fn is_header_value(s: &str) -> bool {
    s.bytes().all(|b| b == b'\t' || (b' '..=b'~').contains(&b))
}

pub fn role_name(role: Role) -> &'static str {
    match role {
        Role::Entry => "entry",
        Role::Exit => "exit",
    }
}

pub fn mode_name(mode: Mode) -> &'static str {
    match mode {
        Mode::Reverse => "reverse",
        Mode::Direct => "direct",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "0123456789abcdef0123";

    fn entry_reverse() -> String {
        format!(
            r#"
            role = "entry"
            mode = "reverse"
            [tunnel]
            listen = "0.0.0.0:3080"
            token = "{TOKEN}"
            [[forward]]
            listen = "0.0.0.0:443"
            target = "127.0.0.1:443"
            "#
        )
    }

    #[test]
    fn parses_entry_reverse() {
        let c = Config::parse(&entry_reverse()).unwrap();
        assert!(c.is_acceptor());
        assert_eq!(c.profile, Profile::Balanced);
        assert_eq!(c.forward.len(), 1);
    }

    #[test]
    fn exit_reverse_requires_remote() {
        let text = format!(
            r#"
            role = "exit"
            mode = "reverse"
            [tunnel]
            token = "{TOKEN}"
            "#
        );
        let err = Config::parse(&text).unwrap_err().to_string();
        assert!(err.contains("tunnel.remote"), "{err}");
    }

    #[test]
    fn rejects_short_token() {
        let text = entry_reverse().replace(TOKEN, "short");
        assert!(Config::parse(&text).is_err());
    }

    #[test]
    fn rejects_forward_on_exit() {
        let text = format!(
            r#"
            role = "exit"
            mode = "direct"
            [tunnel]
            listen = "0.0.0.0:3080"
            token = "{TOKEN}"
            [[forward]]
            listen = "0.0.0.0:443"
            target = "127.0.0.1:443"
            "#
        );
        assert!(Config::parse(&text).is_err());
    }

    #[test]
    fn rejects_unknown_fields() {
        let text = entry_reverse().replace("mode = \"reverse\"", "mode = \"reverse\"\ntypo = 1");
        assert!(Config::parse(&text).is_err());
    }

    #[test]
    fn parses_spoof_entry_reverse() {
        let text = format!(
            r#"
            role = "entry"
            mode = "reverse"
            [tunnel]
            transport = "spoof"
            listen = "0.0.0.0:3080"
            token = "{TOKEN}"
            [tunnel.spoof]
            shape = "udp"
            pool = ["203.0.113.10", "203.0.113.11", "203.0.113.0/30"]
            peer = "198.51.100.7:3080"
            [[forward]]
            listen = "0.0.0.0:443"
            target = "127.0.0.1:443"
            "#
        );
        let c = Config::parse(&text).unwrap();
        assert_eq!(c.tunnel.transport, TransportKind::Spoof);
        let spoof = c.tunnel.spoof.as_ref().unwrap();
        assert_eq!(spoof.shape, SpoofShape::Udp);
        // Two singles plus the two host addresses of 203.0.113.0/30 (.1 and .2).
        let pool = spoof.expand_pool().unwrap();
        assert_eq!(
            pool,
            vec![
                Ipv4Addr::new(203, 0, 113, 10),
                Ipv4Addr::new(203, 0, 113, 11),
                Ipv4Addr::new(203, 0, 113, 1),
                Ipv4Addr::new(203, 0, 113, 2),
            ]
        );
    }

    #[test]
    fn spoof_requires_non_empty_pool() {
        let text = format!(
            r#"
            role = "entry"
            mode = "reverse"
            [tunnel]
            transport = "spoof"
            listen = "0.0.0.0:3080"
            token = "{TOKEN}"
            [tunnel.spoof]
            shape = "tcp"
            peer = "198.51.100.7:3080"
            [[forward]]
            listen = "0.0.0.0:443"
            target = "127.0.0.1:443"
            "#
        );
        let err = Config::parse(&text).unwrap_err().to_string();
        assert!(err.contains("pool"), "{err}");
    }

    #[test]
    fn spoof_rejects_encryption_none() {
        let text = format!(
            r#"
            role = "entry"
            mode = "reverse"
            [tunnel]
            transport = "spoof"
            listen = "0.0.0.0:3080"
            token = "{TOKEN}"
            encryption = "none"
            [tunnel.spoof]
            pool = ["203.0.113.10"]
            peer = "198.51.100.7:3080"
            [[forward]]
            listen = "0.0.0.0:443"
            target = "127.0.0.1:443"
            "#
        );
        let err = Config::parse(&text).unwrap_err().to_string();
        assert!(err.contains("requires encryption"), "{err}");
    }

    #[test]
    fn spoof_table_without_transport_is_rejected() {
        let text = format!(
            r#"
            role = "entry"
            mode = "reverse"
            [tunnel]
            transport = "tcp"
            listen = "0.0.0.0:3080"
            token = "{TOKEN}"
            [tunnel.spoof]
            pool = ["203.0.113.10"]
            [[forward]]
            listen = "0.0.0.0:443"
            target = "127.0.0.1:443"
            "#
        );
        let err = Config::parse(&text).unwrap_err().to_string();
        assert!(err.contains("[tunnel.spoof]"), "{err}");
    }

    #[test]
    fn spoof_pool_rejects_bad_entries() {
        let cfg = SpoofConfig {
            pool: vec!["not-an-ip".into()],
            ..SpoofConfig::default()
        };
        assert!(cfg.expand_pool().is_err());
        let cfg = SpoofConfig {
            pool: vec!["203.0.113.0/40".into()],
            ..SpoofConfig::default()
        };
        assert!(cfg.expand_pool().is_err());
        // A range expands inclusively.
        let cfg = SpoofConfig {
            pool: vec!["10.0.0.1-10.0.0.3".into()],
            ..SpoofConfig::default()
        };
        assert_eq!(cfg.expand_pool().unwrap().len(), 3);
    }

    #[test]
    fn spoof_shape_names_round_trip() {
        for (name, shape) in [
            ("udp", SpoofShape::Udp),
            ("tcp", SpoofShape::Tcp),
            ("icmp", SpoofShape::Icmp),
            ("gre", SpoofShape::Gre),
            ("ipip", SpoofShape::Ipip),
            ("proto58", SpoofShape::Proto58),
        ] {
            assert_eq!(shape.name(), name);
            let parsed: SpoofShape =
                toml::from_str(&format!("shape = \"{name}\"\n")).map(|c: SpoofConfig| c.shape).unwrap();
            assert_eq!(parsed, shape);
        }
    }

    #[test]
    fn overrides_apply_on_top_of_profile() {
        let text = format!(
            "profile = \"gaming\"\n{}\n[tuning]\nbuffer_size = 4096\n",
            entry_reverse()
        );
        let c = Config::parse(&text).unwrap();
        let t = c.tuning();
        assert_eq!(t.buffer_size, 4096);
        assert_eq!(t.keepalive, Duration::from_secs(10));
    }

    /// A config for `transport`, with extra `[tunnel]` lines and sub-tables appended.
    fn with_transport(role: &str, transport: &str, extra: &str) -> String {
        let (tunnel, forward) = if role == "entry" {
            (
                "remote = \"203.0.113.1:443\"",
                "[[forward]]\nlisten = \"0.0.0.0:443\"\ntarget = \"127.0.0.1:443\"",
            )
        } else {
            ("listen = \"0.0.0.0:443\"", "")
        };
        format!(
            "role = \"{role}\"\nmode = \"direct\"\n{forward}\n\
             [tunnel]\ntransport = \"{transport}\"\n{tunnel}\ntoken = \"{TOKEN}\"\n{extra}\n"
        )
    }

    fn parse_err(text: &str) -> String {
        format!("{:#}", Config::parse(text).unwrap_err())
    }

    #[test]
    fn ultraspeed_profile_also_under_its_old_name() {
        for name in ["ultraspeed", "throughput"] {
            let text = format!("profile = \"{name}\"\n{}", entry_reverse());
            let c = Config::parse(&text).unwrap();
            assert_eq!(c.profile, Profile::Ultraspeed, "{name}");
            assert_eq!(c.profile.name(), "ultraspeed");
            assert_eq!(c.mux().stream_window, 1024 * 1024);
            assert_eq!(c.tuning().buffer_size, 256 * 1024);
        }
    }

    #[test]
    fn gaming_profile_turns_kcp_fec_on_unless_set() {
        let kcp = |profile: &str, table: &str| {
            let text = format!(
                "profile = \"{profile}\"\n{}",
                with_transport("entry", "kcp", &format!("[tunnel.kcp]\n{table}"))
            );
            Config::parse(&text).unwrap().kcp().fec()
        };
        assert_eq!(kcp("gaming", ""), Some((10, 3)));
        assert_eq!(kcp("balanced", ""), None);
        assert_eq!(kcp("ultraspeed", ""), None);
        assert_eq!(kcp("throughput", ""), None);
        // Set in the table: the table wins, off included.
        assert_eq!(kcp("gaming", "fec_data = 0\nfec_parity = 0"), None);
        assert_eq!(kcp("gaming", "fec_data = 4\nfec_parity = 2"), Some((4, 2)));
        // An MTU too large for FEC keeps it off rather than making the config invalid.
        assert_eq!(kcp("gaming", "mtu = 1440"), None);
        assert_eq!(kcp("gaming", "mtu = 1429"), Some((10, 3)));
    }

    /// Parses without validation, for checking effective values on their own.
    fn parse_unchecked(text: &str) -> Config {
        toml::from_str(text).unwrap()
    }

    #[test]
    fn v01_config_gets_defaults() {
        let c = Config::parse(&entry_reverse()).unwrap();
        assert_eq!(c.tunnel.transport, TransportKind::Tcp);
        assert_eq!(c.tunnel.encryption, Encryption::Auto);
        assert!(!c.mux().enabled);
        assert!(c.warnings().is_empty());
    }

    #[test]
    fn mux_defaults_follow_transport_and_profile() {
        let tcpmux = parse_unchecked(&with_transport("entry", "tcpmux", ""));
        assert!(tcpmux.mux().enabled);
        assert_eq!(tcpmux.mux().stream_window, 256 * 1024);
        assert_eq!(tcpmux.mux().connections, 4);

        let ws = parse_unchecked(&format!(
            "profile = \"gaming\"\n{}",
            with_transport("entry", "ws", "")
        ));
        let mux = ws.mux();
        assert!(mux.enabled);
        assert_eq!(mux.stream_window, 64 * 1024);
        assert!(!mux.coalesce);

        let off = parse_unchecked(&with_transport(
            "entry",
            "ws",
            "[tunnel.mux]\nenabled = false\nconnections = 3",
        ));
        assert!(!off.mux().enabled);
        assert_eq!(off.mux().connections, 3);
    }

    #[test]
    fn auto_always_multiplexes_and_pings_fast() {
        let c = Config::parse(&with_transport("entry", "auto", "")).unwrap();
        let mux = c.mux();
        assert!(mux.enabled);
        assert_eq!(
            mux.ping_interval,
            Duration::from_secs(crate::auto::PING_SECS)
        );
        // An explicit ping still wins.
        let slow = with_transport(
            "entry",
            "auto",
            "[tunnel.mux]
ping_interval_secs = 10",
        );
        assert_eq!(
            Config::parse(&slow).unwrap().mux().ping_interval,
            Duration::from_secs(10)
        );
        let err = parse_err(&with_transport(
            "entry",
            "auto",
            "[tunnel.mux]
enabled = false",
        ));
        assert!(err.contains("auto"), "{err}");
        // Its own tables are only the KCP one.
        assert!(Config::parse(&with_transport(
            "entry",
            "auto",
            "[tunnel.kcp]
mtu = 1200"
        ))
        .is_ok());
        assert!(Config::parse(&with_transport(
            "entry",
            "auto",
            "[tunnel.ws]
path = \"/x\""
        ))
        .is_err());
    }

    #[test]
    fn long_keepalive_over_websocket_is_warned() {
        let slow = "[tuning]\nkeepalive_secs = 120";
        let c = Config::parse(&format!("{}{slow}", with_transport("entry", "ws", ""))).unwrap();
        assert_eq!(c.warnings().len(), 1);
        let c = Config::parse(&format!("{}{slow}", with_transport("entry", "tcp", ""))).unwrap();
        assert!(c.warnings().is_empty());
    }

    /// An entry config with one forward rule using `protocol` and extra top-level lines.
    fn with_forward(protocol: &str, transport: &str, extra: &str) -> String {
        with_transport("entry", transport, extra).replace(
            "target = \"127.0.0.1:443\"",
            &format!("target = \"127.0.0.1:443\"\nprotocol = \"{protocol}\""),
        )
    }

    #[test]
    fn forward_protocols() {
        for (name, tcp, udp) in [
            ("tcp", true, false),
            ("udp", false, true),
            ("tcp+udp", true, true),
        ] {
            let c = parse_unchecked(&with_forward(name, "tcpmux", ""));
            let p = c.forward[0].protocol;
            assert_eq!((p.name(), p.has_tcp(), p.has_udp()), (name, tcp, udp));
        }
        assert_eq!(
            Config::parse(&entry_reverse()).unwrap().forward[0].protocol,
            ForwardProtocol::Tcp
        );
        assert!(toml::from_str::<Config>(&with_forward("sctp", "tcp", "")).is_err());
    }

    #[test]
    fn udp_tuning_defaults_and_overrides() {
        let t = Tuning::for_profile(Profile::Balanced);
        assert_eq!(t.udp.timeout, Duration::from_secs(60));
        assert_eq!(t.udp.max_flows, 4096);
        assert!(Tuning::for_profile(Profile::Gaming).udp.flow_queue < t.udp.flow_queue);
        let c = parse_unchecked(&format!(
            "{}[tuning]\nudp_timeout_secs = 30\nudp_max_flows = 10\n",
            with_forward("udp", "tcpmux", "")
        ));
        assert_eq!(c.tuning().udp.timeout, Duration::from_secs(30));
        assert_eq!(c.tuning().udp.max_flows, 10);
        for bad in [
            "udp_timeout_secs = 1",
            "udp_timeout_secs = 4000",
            "udp_max_flows = 0",
        ] {
            let err = parse_err(&format!("{}[tuning]\n{bad}\n", entry_reverse()));
            assert!(err.contains("tuning.udp_"), "{bad}: {err}");
        }
    }

    #[test]
    fn the_per_address_limit_is_off_unless_set() {
        assert_eq!(
            Tuning::for_profile(Profile::Balanced).max_conns_per_ip,
            None
        );
        let with = |line: &str| {
            parse_unchecked(&format!("{}[tuning]\n{line}\n", entry_reverse()))
                .tuning()
                .max_conns_per_ip
        };
        assert_eq!(with("max_conns_per_ip = 300"), Some(300));
        assert_eq!(with("max_conns_per_ip = 0"), None);
    }

    #[test]
    fn mux_carries_thousands_of_streams_by_default() {
        for profile in ["balanced", "ultraspeed", "gaming"] {
            let c = parse_unchecked(&format!("profile = \"{profile}\"\n{}", entry_reverse()));
            assert_eq!(c.mux().max_streams, 4096, "{profile}");
        }
        let c = parse_unchecked(&format!(
            "{}[tunnel.mux]\nmax_streams = 16384\n",
            entry_reverse()
        ));
        assert!(c.validate_mux().is_ok());
        let c = parse_unchecked(&format!(
            "{}[tunnel.mux]\nmax_streams = 16385\n",
            entry_reverse()
        ));
        assert!(c.validate_mux().is_err());
    }

    #[test]
    fn udp_forward_rules_are_valid() {
        for protocol in ["udp", "tcp+udp"] {
            let c = Config::parse(&with_forward(protocol, "tcpmux", "")).unwrap();
            assert!(c.forward[0].protocol.has_udp());
        }
        // UDP rules belong to the entry side like TCP ones.
        let exit = with_transport("exit", "tcpmux", "");
        assert!(Config::parse(&exit).is_ok());
    }

    #[test]
    fn udp_without_mux_is_warned() {
        let c = parse_unchecked(&with_forward("udp", "tcp", ""));
        assert_eq!(c.warnings().len(), 1);
        assert!(c.warnings()[0].contains("mux"));
        assert!(parse_unchecked(&with_forward("udp", "tcpmux", ""))
            .warnings()
            .is_empty());
        assert!(parse_unchecked(&with_forward("tcp", "tcp", ""))
            .warnings()
            .is_empty());
    }

    #[test]
    fn dscp_names_and_numbers() {
        let with = |value: &str| format!("{}[tuning]\ndscp = {value}\n", entry_reverse());
        for (value, codepoint) in [
            ("\"ef\"", 46),
            ("\"EF\"", 46),
            ("\"af41\"", 34),
            ("\"cs4\"", 32),
            ("\"le\"", 1),
            ("\"default\"", 0),
            ("0", 0),
            ("63", 63),
        ] {
            let c = Config::parse(&with(value)).unwrap();
            assert_eq!(c.tuning().dscp, Some(codepoint), "{value}");
        }
        assert_eq!(Config::parse(&entry_reverse()).unwrap().tuning().dscp, None);
        for bad in ["\"fast\"", "64", "-1", "\"\""] {
            let err = parse_err(&with(bad));
            assert!(err.contains("dscp"), "{bad}: {err}");
        }
        assert_eq!(Dscp::name_of(46), Some("ef"));
        assert_eq!(Dscp::name_of(0), Some("cs0"));
        assert_eq!(Dscp::name_of(7), None);
        // Over QUIC the tunnel's own packets cannot be marked: said, not hidden.
        let quic = Config::parse(&format!(
            "{}[tuning]\ndscp = \"ef\"\n",
            with_transport("entry", "quic", "")
        ))
        .unwrap();
        assert!(quic.warnings().iter().any(|w| w.contains("QUIC")));
    }

    #[test]
    fn duplication_on_udp_rules() {
        let dup = |protocol: &str, transport: &str, lines: &str| {
            with_forward(protocol, transport, "").replace(
                &format!("protocol = \"{protocol}\""),
                &format!("protocol = \"{protocol}\"\n{lines}"),
            )
        };
        let c = Config::parse(&dup("udp", "kcp", "duplicate = 2")).unwrap();
        assert_eq!(
            c.forward[0].duplication(),
            Some(Duplicate {
                copies: 2,
                gap_ms: 5
            })
        );
        assert!(c.warnings().is_empty(), "{:?}", c.warnings());
        let c = Config::parse(&dup(
            "tcp+udp",
            "quic",
            "duplicate = 3\nduplicate_gap_ms = 0",
        ))
        .unwrap();
        assert_eq!(
            c.forward[0].duplication(),
            Some(Duplicate {
                copies: 3,
                gap_ms: 0
            })
        );
        let one = Config::parse(&dup("udp", "kcp", "duplicate = 1")).unwrap();
        assert_eq!(one.forward[0].duplication(), None);
        // Accepted, but pointless over transports that lose nothing.
        let c = Config::parse(&dup("udp", "tcpmux", "duplicate = 2")).unwrap();
        assert!(c.warnings().iter().any(|w| w.contains("duplicate")));
        for (protocol, lines, needle) in [
            ("tcp", "duplicate = 2", "for UDP rules"),
            ("udp", "duplicate = 0", "between 1 and 3"),
            ("udp", "duplicate = 4", "between 1 and 3"),
            ("udp", "duplicate = 2\nduplicate_gap_ms = 51", "at most 50"),
        ] {
            let err = parse_err(&dup(protocol, "kcp", lines));
            assert!(err.contains(needle), "{lines}: {err}");
        }
    }

    #[test]
    fn proxy_protocol_on_tcp_rules() {
        let rule = |protocol: &str, line: &str| {
            with_forward(protocol, "tcpmux", "").replace(
                &format!("protocol = \"{protocol}\""),
                &format!("protocol = \"{protocol}\"\n{line}"),
            )
        };
        let off = Config::parse(&with_forward("tcp", "tcpmux", "")).unwrap();
        assert_eq!(off.forward[0].proxy_protocol, None);
        for (protocol, line, want) in [
            ("tcp", "proxy_protocol = \"v1\"", ProxyVersion::V1),
            ("tcp", "proxy_protocol = \"v2\"", ProxyVersion::V2),
            ("tcp+udp", "proxy_protocol = \"v2\"", ProxyVersion::V2),
        ] {
            let c = Config::parse(&rule(protocol, line)).unwrap();
            assert_eq!(c.forward[0].proxy_protocol, Some(want), "{protocol} {line}");
        }
        let err = parse_err(&rule("udp", "proxy_protocol = \"v2\""));
        assert!(err.contains("proxy_protocol is for TCP rules"), "{err}");
        let err = parse_err(&rule("tcp", "proxy_protocol = \"v3\""));
        assert!(err.contains("v3"), "{err}");
    }

    #[test]
    fn notsent_lowat_only_with_mux() {
        let tcp = Config::parse(&with_transport("entry", "tcp", "")).unwrap();
        assert_eq!(tcp.tuning().notsent_lowat, None);
        for transport in ["tcpmux", "ws", "wss"] {
            let c = parse_unchecked(&with_transport("entry", transport, ""));
            assert_eq!(c.tuning().notsent_lowat, Some(NOTSENT_LOWAT), "{transport}");
        }
    }

    #[test]
    fn mux_settings_default_to_the_profile_and_can_be_set() {
        let mux_of = |top: &str, table: &str| {
            let text = format!(
                "{top}\n{}",
                with_transport("entry", "tcpmux", &format!("[tunnel.mux]\n{table}"))
            );
            let c = Config::parse(&text).unwrap();
            (c.mux(), c.tuning())
        };
        // Defaults: the profile's values, and the keepalive for pings.
        let (mux, tuning) = mux_of("", "");
        assert!(mux.coalesce);
        assert_eq!(mux.ping_interval, tuning.keepalive);
        assert_eq!(mux.datagram_buffer, tuning.udp.session_buffer);
        assert_eq!(mux.datagram_queue, tuning.udp.flow_queue);
        assert_eq!(tuning.notsent_lowat, Some(NOTSENT_LOWAT));
        let (gaming, _) = mux_of("profile = \"gaming\"", "");
        assert!(!gaming.coalesce);
        assert_eq!(gaming.ping_interval, Duration::from_secs(10));
        // [tuning] keepalive_secs still sets the ping when the mux table does not.
        let text = format!(
            "{}[tuning]\nkeepalive_secs = 20\n",
            with_transport("entry", "tcpmux", "")
        );
        let c = Config::parse(&text).unwrap();
        assert_eq!(c.mux().ping_interval, Duration::from_secs(20));
        // A 1 s keepalive, valid before the mux setting existed, stays valid.
        let text = format!(
            "{}[tuning]
keepalive_secs = 1
",
            with_transport("entry", "ws", "")
        );
        assert!(Config::parse(&text).is_ok());

        // Set by hand.
        let (mux, tuning) = mux_of(
            "",
            "coalesce = false\nping_interval_secs = 15\ndatagram_buffer = 65536\n\
             datagram_queue = 32\nnotsent_lowat = 65536",
        );
        assert!(!mux.coalesce);
        assert_eq!(mux.ping_interval, Duration::from_secs(15));
        assert_eq!((mux.datagram_buffer, mux.datagram_queue), (65536, 32));
        assert_eq!(tuning.notsent_lowat, Some(65536));
        let (mux, tuning) = mux_of("", "notsent_lowat = 0");
        assert_eq!((mux.notsent_lowat, tuning.notsent_lowat), (None, None));

        for (table, needle) in [
            ("ping_interval_secs = 0", "ping_interval_secs"),
            ("ping_interval_secs = 601", "ping_interval_secs"),
            ("datagram_buffer = 1024", "datagram_buffer"),
            ("datagram_queue = 4", "datagram_queue"),
            ("notsent_lowat = 100", "notsent_lowat"),
        ] {
            let text = with_transport("entry", "tcpmux", &format!("[tunnel.mux]\n{table}"));
            let err = parse_err(&text);
            assert!(err.contains(needle), "{table}: {err}");
        }
        // A CDN cuts idle WebSockets after about 100 s: warned for the mux ping too.
        let ws = with_transport("entry", "ws", "[tunnel.mux]\nping_interval_secs = 120");
        assert!(Config::parse(&ws).unwrap().warnings()[0].contains("90"));
    }

    #[test]
    fn encryption_none_is_allowed_with_a_warning() {
        let c = Config::parse(&with_transport("entry", "tcp", "encryption = \"none\"")).unwrap();
        assert_eq!(c.tunnel.encryption, Encryption::None);
        assert_eq!(c.warnings().len(), 1);
        assert!(Config::parse(&with_transport("entry", "tcp", "encryption = \"rot13\"")).is_err());
        for cipher in ["chacha20-poly1305", "aes-256-gcm", "auto"] {
            let text = with_transport("entry", "tcp", &format!("encryption = \"{cipher}\""));
            let c = Config::parse(&text).unwrap();
            assert_eq!(c.tunnel.encryption.name(), cipher);
            assert!(c.warnings().is_empty());
        }
    }

    #[test]
    fn mux_configs_parse() {
        let c = Config::parse(&with_transport("entry", "tcpmux", "")).unwrap();
        assert!(c.mux().enabled);
        let text = with_transport(
            "exit",
            "tcp",
            "[tunnel.mux]\nenabled = true\nmax_lifetime_secs = 600",
        );
        let c = Config::parse(&text).unwrap();
        assert_eq!(c.mux().max_lifetime, Some(Duration::from_secs(600)));
    }

    #[test]
    fn tcpmux_cannot_disable_mux() {
        let err = parse_err(&with_transport(
            "entry",
            "tcpmux",
            "[tunnel.mux]\nenabled = false",
        ));
        assert!(err.contains("tcpmux"), "{err}");
    }

    #[test]
    fn mux_bounds() {
        for extra in [
            "connections = 0",
            "connections = 65",
            "max_streams = 0",
            "stream_window = 1024",
            "stream_window = 1073741824",
            "max_lifetime_secs = 5",
        ] {
            let err = parse_err(&with_transport(
                "entry",
                "tcpmux",
                &format!("[tunnel.mux]\n{extra}"),
            ));
            assert!(err.contains("tunnel.mux."), "{extra}: {err}");
        }
    }

    #[test]
    fn ws_and_tls_sections_need_a_matching_transport() {
        let err = parse_err(&with_transport(
            "entry",
            "tcp",
            "[tunnel.ws]\npath = \"/x\"",
        ));
        assert!(err.contains("[tunnel.ws]"), "{err}");
        let err = parse_err(&with_transport(
            "entry",
            "ws",
            "[tunnel.tls]\nsni = \"a.example\"",
        ));
        assert!(err.contains("[tunnel.tls]"), "{err}");
    }

    #[test]
    fn ws_validation() {
        for (extra, expect) in [
            ("path = \"no-slash\"", "tunnel.ws.path"),
            ("path = \"/a b\"", "tunnel.ws.path"),
            ("host = \"\"", "tunnel.ws.host"),
            ("user_agent = \"a\\r\\nX: y\"", "user_agent"),
            ("headers = { \"Bad Name\" = \"v\" }", "invalid header name"),
            (
                "headers = { \"Sec-WebSocket-Key\" = \"v\" }",
                "set by kariz",
            ),
            ("headers = { \"X-A\" = \"a\\nb\" }", "invalid value"),
        ] {
            let err = parse_err(&with_transport(
                "entry",
                "ws",
                &format!("[tunnel.ws]\n{extra}"),
            ));
            assert!(err.contains(expect), "{extra}: {err}");
        }

        let ok = "[tunnel.ws]\npath = \"/api/v1\"\nhost = \"a.example\"\n\
                  headers = { \"Accept-Language\" = \"en-US\" }";
        let c = Config::parse(&with_transport("entry", "ws", ok)).unwrap();
        assert_eq!(c.tunnel.ws.unwrap().path, "/api/v1");
        // `[tunnel.ws]` is optional: path "/", any host.
        let c = Config::parse(&with_transport("exit", "ws", "")).unwrap();
        assert!(c.mux().enabled);

        for extra in ["user_agent = \"x\"", "early_data = true"] {
            let err = parse_err(&with_transport(
                "exit",
                "ws",
                &format!("[tunnel.ws]\n{extra}"),
            ));
            assert!(err.contains("dialing side"), "{extra}: {err}");
        }
        let c = Config::parse(&with_transport(
            "entry",
            "ws",
            "[tunnel.ws]\nearly_data = true",
        ))
        .unwrap();
        assert!(c.tunnel.ws.unwrap().early_data);
    }

    #[test]
    fn tls_validation() {
        // Listening side of wss.
        let err = parse_err(&with_transport("exit", "wss", ""));
        assert!(err.contains("tunnel.tls.cert"), "{err}");
        let err = parse_err(&with_transport(
            "exit",
            "wss",
            "[tunnel.tls]\ncert = \"c.pem\"\nkey = \"k.pem\"\nsni = \"a.example\"",
        ));
        assert!(err.contains("dialing side"), "{err}");
        let ok = "[tunnel.tls]\ncert = \"c.pem\"\nkey = \"k.pem\"";
        assert!(Config::parse(&with_transport("exit", "wss", ok)).is_ok());

        // Dialing side of wss.
        let pin = "ab".repeat(32);
        for (extra, expect) in [
            ("cert = \"c.pem\"".to_string(), "listening side"),
            ("pin_sha256 = \"abc\"".to_string(), "64 hex"),
            (
                format!("pin_sha256 = \"{pin}\"\ninsecure = true"),
                "together",
            ),
            ("sni = \"\"".to_string(), "tunnel.tls.sni"),
        ] {
            let err = parse_err(&with_transport(
                "entry",
                "wss",
                &format!("[tunnel.tls]\n{extra}"),
            ));
            assert!(err.contains(expect), "{extra}: {err}");
        }
        let ok = format!("[tunnel.tls]\nsni = \"a.example\"\npin_sha256 = \"{pin}\"");
        assert!(Config::parse(&with_transport("entry", "wss", &ok)).is_ok());
        // Without [tunnel.tls] the dialer verifies against the bundled Mozilla roots.
        assert!(Config::parse(&with_transport("entry", "wss", "")).is_ok());

        let insecure = parse_unchecked(&with_transport(
            "entry",
            "wss",
            "[tunnel.tls]\ninsecure = true",
        ));
        assert!(insecure.validate_tls().is_ok());
        assert_eq!(insecure.warnings().len(), 1);
    }

    #[cfg(feature = "quic")]
    #[test]
    fn quic_configs_parse() {
        let c = Config::parse(&with_transport("entry", "quic", "")).unwrap();
        assert!(c.mux().enabled);
        assert_eq!(c.mux().connections, 2);
        assert!(c.tunnel.quic.is_none());
        assert!(c.warnings().is_empty());
        let q = QuicConfig::default();
        assert_eq!(
            (q.alpn.as_str(), q.congestion, q.sni),
            ("h3", Congestion::Cubic, None)
        );

        let text = with_transport(
            "entry",
            "quic",
            "[tunnel.quic]\ncongestion = \"bbr\"\nsni = \"a.example\"\nalpn = \"hq-29\"",
        );
        let q = Config::parse(&text).unwrap().tunnel.quic.unwrap();
        assert_eq!(q.congestion, Congestion::Bbr);
        assert_eq!(q.sni.as_deref(), Some("a.example"));
        assert_eq!(q.alpn, "hq-29");
        let text = with_transport("entry", "quic", "[tunnel.quic]\ncongestion = \"bbr\"");
        assert_eq!(Config::parse(&text).unwrap().warnings().len(), 1);
        // `obfs` is off unless asked for, and asking for it is no warning.
        assert!(!QuicConfig::default().obfs);
        let text = with_transport("entry", "quic", "[tunnel.quic]\nobfs = true");
        let c = Config::parse(&text).unwrap();
        assert!(c.tunnel.quic.as_ref().unwrap().obfs);
        assert!(c.warnings().is_empty());
        // An empty table means the defaults, as no table does.
        let text = with_transport("exit", "quic", "[tunnel.quic]");
        assert_eq!(
            Config::parse(&text).unwrap().tunnel.quic.unwrap().alpn,
            "h3"
        );
    }

    #[cfg(feature = "quic")]
    #[test]
    fn quic_validation() {
        let err = parse_err(&with_transport("entry", "tcp", "[tunnel.quic]"));
        assert!(err.contains("[tunnel.quic]"), "{err}");
        let err = parse_err(&with_transport("entry", "quic", "encryption = \"none\""));
        assert!(err.contains("TLS 1.3"), "{err}");
        let err = parse_err(&with_transport(
            "entry",
            "quic",
            "[tunnel.mux]\nenabled = false",
        ));
        assert!(err.contains("multiplexes"), "{err}");
        for (role, extra, expect) in [
            ("entry", "alpn = \"\"", "tunnel.quic.alpn"),
            ("entry", "alpn = \"a b\"", "tunnel.quic.alpn"),
            ("entry", "sni = \"\"", "tunnel.quic.sni"),
            ("entry", "sni = \"a.example/x\"", "tunnel.quic.sni"),
            ("exit", "sni = \"a.example\"", "dialing side"),
            ("entry", "congestion = \"vegas\"", "congestion"),
        ] {
            let err = parse_err(&with_transport(
                role,
                "quic",
                &format!("[tunnel.quic]\n{extra}"),
            ));
            assert!(err.contains(expect), "{extra}: {err}");
        }
    }

    #[cfg(feature = "kcp")]
    #[test]
    fn kcp_configs_parse() {
        let c = Config::parse(&with_transport("entry", "kcp", "")).unwrap();
        assert!(c.mux().enabled, "mux on by default, as for ws");
        assert!(c.warnings().is_empty());
        let k = KcpConfig::default();
        assert_eq!(k.mode, KcpMode::Fast2);
        assert_eq!((k.send_window, k.recv_window, k.mtu), (1024, 1024, 1350));
        assert_eq!(
            k.timing(),
            KcpTiming {
                nodelay: true,
                interval_ms: 20,
                resend: 2,
                no_congestion: true
            }
        );

        // Without mux, and with an explicit cipher: KCP is a stream like tcp.
        let text = with_transport(
            "exit",
            "kcp",
            "encryption = \"chacha20-poly1305\"\n[tunnel.mux]\nenabled = false",
        );
        assert!(!Config::parse(&text).unwrap().mux().enabled);

        let text = with_transport(
            "entry",
            "kcp",
            "[tunnel.kcp]\nmode = \"normal\"\nsend_window = 256\nrecv_window = 512\nmtu = 1200",
        );
        let k = Config::parse(&text).unwrap().tunnel.kcp.unwrap();
        assert_eq!((k.send_window, k.recv_window, k.mtu), (256, 512, 1200));
        assert_eq!(k.fec(), None);
        assert_eq!(k.timing().interval_ms, 40);
        assert!(!k.timing().nodelay);

        let text = with_transport(
            "entry",
            "kcp",
            "[tunnel.kcp]\nfec_data = 10\nfec_parity = 3\nmtu = 1429",
        );
        let k = Config::parse(&text).unwrap().tunnel.kcp.unwrap();
        assert_eq!(k.fec(), Some((10, 3)));

        // Manual: what is set, and fast2 for the rest.
        let text = with_transport(
            "entry",
            "kcp",
            "[tunnel.kcp]\nmode = \"manual\"\ninterval_ms = 15\nno_congestion = false",
        );
        let t = Config::parse(&text).unwrap().tunnel.kcp.unwrap().timing();
        assert_eq!(
            t,
            KcpTiming {
                nodelay: true,
                interval_ms: 15,
                resend: 2,
                no_congestion: false
            }
        );
    }

    /// Only in builds without the transports: their configs are rejected up front.
    #[cfg(not(all(feature = "quic", feature = "kcp")))]
    #[test]
    fn transports_not_built_in_are_rejected() {
        for (transport, built) in [
            ("quic", cfg!(feature = "quic")),
            ("kcp", cfg!(feature = "kcp")),
            ("udp", cfg!(feature = "kcp")),
            ("faketcp", cfg!(feature = "rawlink")),
            ("icmp", cfg!(feature = "rawlink")),
            ("naive", cfg!(feature = "helpers")),
            ("xhttp", cfg!(feature = "helpers")),
            ("reality", cfg!(feature = "helpers")),
        ] {
            if !built {
                let err = parse_err(&with_transport("entry", transport, ""));
                assert!(err.contains("not in this build"), "{transport}: {err}");
            }
        }
    }

    #[cfg(feature = "kcp")]
    #[test]
    fn kcp_validation() {
        let err = parse_err(&with_transport("entry", "quic", "[tunnel.kcp]"));
        assert!(err.contains("[tunnel.kcp]"), "{err}");
        for (extra, expect) in [
            ("nodelay = false", "mode = \"manual\""),
            ("mode = \"fast3\"\nresend = 0", "mode = \"manual\""),
            ("mode = \"turbo\"", "mode"),
            (
                "mode = \"manual\"\ninterval_ms = 5",
                "tunnel.kcp.interval_ms",
            ),
            (
                "mode = \"manual\"\ninterval_ms = 2000",
                "tunnel.kcp.interval_ms",
            ),
            ("mode = \"manual\"\nresend = 11", "tunnel.kcp.resend"),
            ("send_window = 8", "tunnel.kcp.send_window"),
            ("recv_window = 64", "tunnel.kcp.recv_window"),
            ("recv_window = 40000", "tunnel.kcp.recv_window"),
            ("mtu = 500", "tunnel.kcp.mtu"),
            ("mtu = 1444", "tunnel.kcp.mtu"),
            ("fec = 1", "unknown field"),
            ("fec_data = 10", "fec_parity between"),
            ("fec_parity = 3", "fec_parity between"),
            ("fec_data = 65\nfec_parity = 3", "fec_parity between"),
            ("fec_data = 10\nfec_parity = 33", "fec_parity between"),
            ("fec_data = 10\nfec_parity = 3\nmtu = 1430", "with FEC"),
        ] {
            let err = parse_err(&with_transport(
                "entry",
                "kcp",
                &format!("[tunnel.kcp]\n{extra}"),
            ));
            assert!(err.contains(expect), "{extra}: {err}");
        }
    }

    #[test]
    fn stealth_parses_and_defaults_to_mux_on() {
        let c = Config::parse(&with_transport("entry", "stealth", "")).unwrap();
        assert_eq!(c.tunnel.transport, TransportKind::Stealth);
        assert!(c.mux().enabled, "stealth defaults to mux on");
        assert!(c.warnings().is_empty());
        // Mux can be turned off, like tcp/ws.
        let off = Config::parse(&with_transport(
            "entry",
            "stealth",
            "[tunnel.mux]\nenabled = false",
        ));
        assert!(off.is_ok(), "stealth mux is optional: {off:?}");
    }

    #[test]
    fn stealth_validation() {
        for (extra, expect) in [
            ("encryption = \"none\"", "requires encryption"),
            ("[tunnel.stealth]\npad_max = 0", "tunnel.stealth.pad_max"),
            ("[tunnel.stealth]\npad_max = 9000", "tunnel.stealth.pad_max"),
            (
                "[tunnel.stealth]\njitter_ms = 5000",
                "tunnel.stealth.jitter_ms",
            ),
        ] {
            let err = parse_err(&with_transport("entry", "stealth", extra));
            assert!(err.contains(expect), "{extra}: {err}");
        }
        // The stealth table on another transport is refused.
        let err = parse_err(&with_transport("entry", "tcp", "[tunnel.stealth]"));
        assert!(err.contains("[tunnel.stealth]"), "{err}");
    }

    #[test]
    fn wsmux_and_wssmux_force_mux_and_take_their_tables() {
        // wsmux is ws with mux forced on.
        let c = Config::parse(&with_transport(
            "entry",
            "wsmux",
            "[tunnel.ws]\npath = \"/x\"",
        ))
        .unwrap();
        assert!(c.mux().enabled);
        let err = parse_err(&with_transport(
            "entry",
            "wsmux",
            "[tunnel.mux]\nenabled = false",
        ));
        assert!(err.contains("always uses mux"), "{err}");
        // wssmux needs a certificate on the listening side, like wss.
        let err = parse_err(&with_transport("exit", "wssmux", ""));
        assert!(err.contains("cert") && err.contains("key"), "{err}");
        let ok = Config::parse(&with_transport(
            "exit",
            "wssmux",
            "[tunnel.tls]\ncert = \"/tmp/c.pem\"\nkey = \"/tmp/k.pem\"",
        ));
        assert!(ok.is_ok(), "wssmux with a cert should parse: {ok:?}");
    }

    #[cfg(feature = "kcp")]
    #[test]
    fn udp_transport_allows_only_udp_rules() {
        // A TCP forward is refused.
        let err = parse_err(&with_transport("entry", "udp", ""));
        assert!(err.contains("forwards UDP only"), "{err}");
        // A UDP forward with a PROXY header is refused (there is no stream for one).
        let text = "role = \"entry\"\nmode = \"direct\"\n\
             [[forward]]\nlisten = \"0.0.0.0:443\"\ntarget = \"127.0.0.1:443\"\n\
             protocol = \"udp\"\nproxy_protocol = \"v2\"\n\
             [tunnel]\ntransport = \"udp\"\nremote = \"203.0.113.1:443\"\n\
             token = \"0123456789abcdef0123\"\n";
        assert!(parse_err(text).contains("proxy_protocol"), "{text}");
        // udp has no transport crypto of its own, so encryption = "none" is refused.
        let text = "role = \"entry\"\nmode = \"direct\"\n\
             [[forward]]\nlisten = \"0.0.0.0:443\"\ntarget = \"127.0.0.1:443\"\n\
             protocol = \"udp\"\n\
             [tunnel]\ntransport = \"udp\"\nremote = \"203.0.113.1:443\"\n\
             token = \"0123456789abcdef0123\"\nencryption = \"none\"\n";
        assert!(parse_err(text).contains("requires encryption"), "{text}");
        // A plain UDP forward is fine, and [tunnel.kcp] is allowed.
        let ok = "role = \"entry\"\nmode = \"direct\"\n\
             [[forward]]\nlisten = \"0.0.0.0:443\"\ntarget = \"127.0.0.1:443\"\n\
             protocol = \"udp\"\n\
             [tunnel]\ntransport = \"udp\"\nremote = \"203.0.113.1:443\"\n\
             token = \"0123456789abcdef0123\"\n[tunnel.kcp]\nmode = \"fast2\"\n";
        assert!(Config::parse(ok).is_ok(), "{ok}");
    }

    #[cfg(feature = "rawlink")]
    #[test]
    fn faketcp_and_icmp_validation() {
        // The faketcp table only with faketcp; flags and MAC are checked.
        let err = parse_err(&with_transport("entry", "icmp", "[tunnel.faketcp]"));
        assert!(err.contains("[tunnel.faketcp]"), "{err}");
        for (extra, expect) in [
            ("[tunnel.faketcp]\nflags = \"X\"", "tunnel.faketcp.flags"),
            (
                "[tunnel.faketcp]\ngateway_mac = \"zz:zz\"",
                "tunnel.faketcp.gateway_mac",
            ),
        ] {
            let err = parse_err(&with_transport("entry", "faketcp", extra));
            assert!(err.contains(expect), "{extra}: {err}");
        }
        // Both carriers accept [tunnel.kcp], and a good faketcp parses.
        assert!(Config::parse(&with_transport(
            "entry",
            "faketcp",
            "[tunnel.faketcp]\nflags = \"PA,A\"\n[tunnel.kcp]\nmode = \"fast3\"",
        ))
        .is_ok());
        assert!(Config::parse(&with_transport("entry", "icmp", "[tunnel.icmp]")).is_ok());
        // The icmp table only with icmp.
        let err = parse_err(&with_transport("entry", "faketcp", "[tunnel.icmp]"));
        assert!(err.contains("[tunnel.icmp]"), "{err}");
        // Both carriers have no transport crypto of their own, so encryption = "none" is
        // refused (even with no [tunnel.faketcp] / [tunnel.icmp] table present).
        for transport in ["faketcp", "icmp"] {
            let err = parse_err(&with_transport("entry", transport, "encryption = \"none\""));
            assert!(err.contains("requires encryption"), "{transport}: {err}");
        }
    }

    #[cfg(feature = "helpers")]
    #[test]
    fn helper_validation() {
        let uuid = "123e4567-e89b-12d3-a456-426614174000";
        let key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; // 32 bytes base64url-ish
                                                                 // The helper table only with a helper transport.
        let err = parse_err(&with_transport("entry", "tcp", "[tunnel.helper]"));
        assert!(err.contains("[tunnel.helper]"), "{err}");
        // naive dialer needs username and password; encryption is mandatory.
        let err = parse_err(&with_transport("entry", "naive", ""));
        assert!(err.contains("username"), "{err}");
        let err = parse_err(&with_transport(
            "entry",
            "naive",
            "encryption = \"none\"\n[tunnel.helper]\nusername = \"u\"\npassword = \"p\"",
        ));
        assert!(err.contains("requires encryption"), "{err}");
        assert!(Config::parse(&with_transport(
            "entry",
            "naive",
            "[tunnel.helper]\nusername = \"u\"\npassword = \"p\"",
        ))
        .is_ok());
        // A relative binary path is refused.
        let err = parse_err(&with_transport(
            "entry",
            "naive",
            "[tunnel.helper]\nusername = \"u\"\npassword = \"p\"\nbinary = \"sing-box\"",
        ));
        assert!(err.contains("absolute path"), "{err}");
        // xhttp needs a canonical uuid, a path and a server name.
        let err = parse_err(&with_transport(
            "entry",
            "xhttp",
            "[tunnel.helper]\nuuid = \"nope\"",
        ));
        assert!(err.contains("uuid"), "{err}");
        assert!(Config::parse(&with_transport(
            "entry",
            "xhttp",
            &format!(
                "[tunnel.helper]\nuuid = \"{uuid}\"\npath = \"/x\"\nserver_name = \"a.example\""
            ),
        ))
        .is_ok());
        // reality: short_id hex even length, public_key (dialer) base64url 32 bytes.
        let err = parse_err(&with_transport(
            "entry",
            "reality",
            &format!(
                "[tunnel.helper]\nuuid = \"{uuid}\"\nserver_name = \"a.example\"\n\
                 short_id = \"abc\"\npublic_key = \"{key}\""
            ),
        ));
        assert!(err.contains("short_id"), "{err}");
        let err = parse_err(&with_transport(
            "entry",
            "reality",
            &format!(
                "[tunnel.helper]\nuuid = \"{uuid}\"\nserver_name = \"a.example\"\n\
                 short_id = \"abcd\"\npublic_key = \"not-base64!\""
            ),
        ));
        assert!(err.contains("public_key"), "{err}");
    }

    #[cfg(feature = "helpers")]
    #[test]
    fn helper_rejects_udp_forwarding() {
        let text = format!(
            "role = \"entry\"\nmode = \"direct\"\n\
             [[forward]]\nlisten = \"0.0.0.0:443\"\ntarget = \"127.0.0.1:443\"\nprotocol = \"udp\"\n\
             [tunnel]\ntransport = \"naive\"\nremote = \"203.0.113.1:443\"\ntoken = \"{TOKEN}\"\n\
             [tunnel.helper]\nusername = \"u\"\npassword = \"p\"\n"
        );
        let err = parse_err(&text);
        assert!(err.contains("cannot forward UDP"), "{err}");
    }

    #[test]
    fn fallback_validation() {
        // Not allowed with auto.
        let err = parse_err(&with_transport(
            "entry",
            "auto",
            "fallback_transports = [\"kcp\"]",
        ));
        assert!(err.contains("auto"), "{err}");
        // Dwell has a minimum.
        let err = parse_err(&with_transport(
            "entry",
            "tcpmux",
            "fallback_transports = [\"ws\"]\nfallback_dwell_secs = 5",
        ));
        assert!(err.contains("fallback_dwell_secs"), "{err}");
        // No "auto" in the list, no duplicates, no primary.
        let err = parse_err(&with_transport(
            "entry",
            "tcpmux",
            "fallback_transports = [\"auto\"]",
        ));
        assert!(err.contains("auto"), "{err}");
        let err = parse_err(&with_transport(
            "entry",
            "tcpmux",
            "fallback_transports = [\"ws\", \"ws\"]",
        ));
        assert!(err.contains("duplicate"), "{err}");
        let err = parse_err(&with_transport(
            "entry",
            "tcpmux",
            "fallback_transports = [\"tcpmux\"]",
        ));
        assert!(err.contains("primary"), "{err}");
        // A good list parses.
        assert!(Config::parse(&with_transport(
            "entry",
            "tcpmux",
            "fallback_transports = [\"ws\", \"wss\"]\n\
             [tunnel.tls]\ncert = \"/tmp/c.pem\"\nkey = \"/tmp/k.pem\"",
        ))
        .is_err()); // tls belongs on wss, not tcpmux: the table is refused.
        assert!(Config::parse(&with_transport(
            "entry",
            "tcpmux",
            "fallback_transports = [\"ws\", \"tcp\"]",
        ))
        .is_ok());
        // The udp transport cannot be in a chain, as primary or candidate.
        let err = parse_err(&with_transport(
            "entry",
            "tcpmux",
            "fallback_transports = [\"udp\"]",
        ));
        assert!(err.contains("udp"), "{err}");
        // A candidate that mandates encryption is held to it, not just the primary.
        let err = parse_err(&with_transport(
            "entry",
            "tcpmux",
            "encryption = \"none\"\nfallback_transports = [\"stealth\"]",
        ));
        assert!(err.contains("encryption"), "{err}");
        // Managed helpers cannot be chain candidates.
        let err = parse_err(&with_transport(
            "entry",
            "tcpmux",
            "fallback_transports = [\"naive\"]",
        ));
        assert!(err.contains("naive"), "{err}");
        // A wss candidate needs the TLS table on the listening side (a direct exit listens).
        let acceptor = format!(
            "role = \"exit\"\nmode = \"direct\"\n\
             [tunnel]\ntransport = \"tcpmux\"\nlisten = \"0.0.0.0:443\"\ntoken = \"{TOKEN}\"\n\
             fallback_transports = [\"wss\"]\n"
        );
        let err = parse_err(&acceptor);
        assert!(err.contains("tls") || err.contains("wss"), "{err}");
        // With the certificate present it parses, and the table is accepted for the
        // candidate although the primary is not wss.
        let ok = format!(
            "role = \"entry\"\nmode = \"reverse\"\n\
             [[forward]]\nlisten = \"0.0.0.0:443\"\ntarget = \"127.0.0.1:443\"\n\
             [tunnel]\ntransport = \"tcpmux\"\nlisten = \"0.0.0.0:443\"\ntoken = \"{TOKEN}\"\n\
             fallback_transports = [\"wss\"]\n\
             [tunnel.tls]\ncert = \"/tmp/c.pem\"\nkey = \"/tmp/k.pem\"\n"
        );
        assert!(Config::parse(&ok).is_ok(), "{:?}", Config::parse(&ok).err());
    }

    /// A udp-transport entry with a udp-only forward and the given extra `[tunnel]` lines.
    #[cfg(feature = "kcp")]
    fn udp_entry(extra: &str) -> String {
        format!(
            "role = \"entry\"\nmode = \"direct\"\n\
             [[forward]]\nlisten = \"0.0.0.0:443\"\ntarget = \"127.0.0.1:443\"\nprotocol = \"udp\"\n\
             [tunnel]\ntransport = \"udp\"\nremote = \"203.0.113.1:443\"\ntoken = \"{TOKEN}\"\n{extra}\n"
        )
    }

    #[cfg(feature = "kcp")]
    #[test]
    fn udp_transport_constraints() {
        // A plain udp tunnel is valid.
        assert!(Config::parse(&udp_entry("")).is_ok());
        // Mux cannot be turned off (the datagram path needs it).
        let err = parse_err(&udp_entry("[tunnel.mux]\nenabled = false"));
        assert!(err.contains("mux"), "{err}");
        // The datagram side cannot be turned off.
        let err = parse_err(&udp_entry("[tunnel.kcp]\ndatagrams = false"));
        assert!(err.contains("datagram"), "{err}");
        // A fallback chain is not allowed with udp.
        let err = parse_err(&udp_entry("fallback_transports = [\"kcp\"]"));
        assert!(err.contains("udp"), "{err}");
        // FEC stays off by default even in the gaming profile.
        let config = Config::parse(&format!("profile = \"gaming\"\n{}", udp_entry(""))).unwrap();
        assert_eq!(config.kcp().fec(), None);
    }

    #[cfg(feature = "l3")]
    fn l3_cfg(body: &str) -> String {
        format!(
            "role = \"entry\"\nmode = \"direct\"\n\
             [tunnel]\ntoken = \"{TOKEN}\"\n[l3]\n{body}\n"
        )
    }

    #[cfg(feature = "l3")]
    const L3_OK: &str = "mode = \"listen\"\naddr = \"0.0.0.0:51820\"\n\
         local_ip = \"10.10.0.1/30\"\npeer_ip = \"10.10.0.2\"\ncarrier = \"udp\"\n";

    #[cfg(feature = "l3")]
    #[test]
    fn l3_parses_in_both_directions() {
        for mode in ["dial", "listen"] {
            let body = L3_OK.replacen("listen", mode, 1);
            let c = Config::parse(&l3_cfg(&body)).unwrap();
            assert!(c.l3.is_some(), "{mode}");
            assert_eq!(c.l3.unwrap().mode.name(), mode);
        }
        // The token is inherited from [tunnel] when [l3] does not set it.
        let c = Config::parse(&l3_cfg(L3_OK)).unwrap();
        assert_eq!(l3_effective_token(&c), TOKEN);
    }

    #[cfg(feature = "l3")]
    fn l3_effective_token(c: &Config) -> String {
        c.l3.as_ref()
            .unwrap()
            .token
            .clone()
            .unwrap_or_else(|| c.tunnel.token.clone())
    }

    #[cfg(feature = "l3")]
    #[test]
    fn l3_validation() {
        // A reliable carrier does not even deserialize (the enum excludes it).
        let err = parse_err(&l3_cfg(&L3_OK.replace("\"udp\"", "\"tcp\"")));
        assert!(
            err.contains("unknown variant") || err.contains("carrier"),
            "{err}"
        );
        for (field, bad, expect) in [
            (
                "local_ip = \"10.10.0.1/30\"",
                "local_ip = \"nope\"",
                "local_ip",
            ),
            ("peer_ip = \"10.10.0.2\"", "peer_ip = \"nope\"", "peer_ip"),
        ] {
            let err = parse_err(&l3_cfg(&L3_OK.replace(field, bad)));
            assert!(err.contains(expect), "{bad}: {err}");
        }
        // MTU bounds and encap.
        let err = parse_err(&l3_cfg(&format!("{L3_OK}mtu = 100\n")));
        assert!(err.contains("l3.mtu"), "{err}");
        let err = parse_err(&l3_cfg(&format!("{L3_OK}encap = \"ipip\"\n")));
        assert!(err.contains("l3.encap"), "{err}");
        // The GRE tunnel is sealed inside the Kariz session, so encryption = "none" is refused.
        let text = format!(
            "role = \"entry\"\nmode = \"direct\"\n\
             [tunnel]\ntoken = \"{TOKEN}\"\nencryption = \"none\"\n[l3]\n{L3_OK}\n"
        );
        assert!(parse_err(&text).contains("requires encryption"), "{text}");
        // FEC range.
        let err = parse_err(&l3_cfg(&format!("{L3_OK}fec_data = 100\nfec_parity = 3\n")));
        assert!(err.contains("fec_parity between"), "{err}");
        // layer must be 2 or 3.
        let err = parse_err(&l3_cfg(&format!("{L3_OK}layer = 4\n")));
        assert!(err.contains("l3.layer"), "{err}");
    }

    #[cfg(feature = "l3")]
    #[test]
    fn l3_layer2_may_omit_addresses() {
        // A layer-2 (GRETAP) tunnel can come up address-less to be bridged.
        let body = "mode = \"listen\"\naddr = \"0.0.0.0:51820\"\nlayer = 2\ncarrier = \"udp\"\n";
        let c = Config::parse(&l3_cfg(body)).unwrap();
        let l3 = c.l3.unwrap();
        assert_eq!(l3.layer, 2);
        assert!(l3.local_ip.is_none() && l3.peer_ip.is_none());
        // Layer 3 still requires them.
        let body3 = "mode = \"listen\"\naddr = \"0.0.0.0:51820\"\ncarrier = \"udp\"\n";
        assert!(parse_err(&l3_cfg(body3)).contains("l3.local_ip is required"));
    }

    #[cfg(feature = "l3")]
    #[test]
    fn proto47_is_l3_only() {
        // proto47 is a valid [l3] carrier (the keyed-GRE raw carrier).
        let body = L3_OK.replace("\"udp\"", "\"proto47\"");
        let c = Config::parse(&l3_cfg(&body)).unwrap();
        assert_eq!(c.l3.unwrap().carrier, L3Carrier::Proto47);
        // ...but it is rejected as a standalone [tunnel] transport (rawlink implied by l3).
        let err = parse_err(&with_transport("entry", "proto47", ""));
        assert!(err.contains("only available as an [l3] carrier"), "{err}");
        // Its table has no place on a normal tunnel.
        let err = parse_err(&with_transport("entry", "tcp", "[tunnel.proto47]"));
        assert!(err.contains("[tunnel.proto47]"), "{err}");
        // Nor may it appear in a fallback chain.
        let err = parse_err(&with_transport(
            "entry",
            "kcp",
            "fallback_transports = [\"proto47\"]",
        ));
        assert!(err.contains("proto47"), "{err}");
    }
}
