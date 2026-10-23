//! What the panel and its agents say to each other.
//!
//! A request is one mux stream: the panel opens it with the request as JSON in the open
//! bytes, the agent answers with one JSON document and finishes the stream. The panel is
//! always the one that asks; the requests are a fixed list, and none of them runs a
//! command the panel names: there is no remote shell.

use serde::{Deserialize, Serialize};

/// Largest request the panel sends (the open bytes of a stream hold 64 KiB). A tunnel with
/// the most ports the wizard allows (200 forwards) is 15 KB with IPv4 addresses and more
/// than 20 KB with IPv6 ones.
pub const MAX_REQUEST: usize = 60 * 1024;
/// Largest answer the panel reads.
pub const MAX_REPLY: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    /// Who are you? `challenge` is random; a registered agent proves its key over it.
    Hello { challenge: String },
    /// A new agent's identity: keep it and use it from now on.
    Enroll { id: String, key: String },
    /// CPU, memory, network, uptime, load.
    Health,
    /// The tunnels on this server (the `/etc/kariz/*.toml` files) and their state.
    Tunnels,
    /// Is this tunnel spec valid here, and are its ports free?
    TunnelCheck { spec: Spec },
    /// Write the tunnel's config from a spec (the agent renders the file).
    TunnelPut { spec: Spec },
    /// One tunnel's spec, without its token.
    TunnelGet { name: String },
    /// Whether this side would change with `spec`: the file the agent would write is
    /// compared with the one it has. Only an agent of 2.10 or newer knows it; an older
    /// one answers `unknown request`, which reads as "write it and restart".
    TunnelDiff { spec: Spec },
    /// Tell a running entry to read its (just written) config again and apply its forward
    /// rules without a restart (what `kariz reload` does). Only an agent of 2.10 or newer
    /// knows it.
    TunnelReload { name: String },
    /// Stop it, remove its config.
    TunnelDelete { name: String },
    /// `start`, `stop`, `restart`, `enable` or `disable` the tunnel's service.
    TunnelCtl { name: String, action: String },
    /// The listening ports of this server and who owns them.
    Ports,
    /// The last lines of a tunnel's log.
    Logs { name: String, lines: u32 },
    /// Run the entry side's speed test.
    Speedtest {
        name: String,
        seconds: u32,
        streams: u32,
        udp: bool,
    },
    /// Get a Let's Encrypt certificate for a domain (or a public IPv4 address) on this
    /// server, for a wss tunnel that listens here. Runs `kariz-manager tunnel-cert`.
    TunnelCert {
        domain: String,
        #[serde(default)]
        email: Option<String>,
    },
    /// Start the entry side's speed test in the background; its progress is read with
    /// [`Request::SpeedtestPoll`] while it runs.
    SpeedtestStart {
        name: String,
        seconds: u32,
        streams: u32,
        udp: bool,
    },
    /// Stop a started speed test now (its test streams end within half a second).
    SpeedtestStop { id: String },
    /// The progress lines of a started speed test after the first `after`, and the report
    /// once it is done.
    SpeedtestPoll { id: String, after: u32 },
    /// Make (or make again) the GRE interface of a private network link.
    NetUp { net: NetSpec },
    /// Remove a link's interface.
    NetDown { name: String },
    /// The panel's whole list of this server's links: make the ones that are missing or
    /// changed, remove the ones that are not in it (sent when an agent connects).
    NetSync { links: Vec<NetSpec> },
    /// Ping the far end of a link across it.
    NetPing { name: String },
    /// Whether GRE can be made here, and the state of this server's links.
    NetStatus,
    /// Listen for one benchmark test session ([`kariz::bench`]) over `transport` with the
    /// tunnel `profile`, on `port` of every IPv4 address, or of the address `bind` (this
    /// server's IPv6 address: a listener of its own beside the IPv4 one on the same port)
    /// (another free port when that one is taken; 0: any). The answer says the port. The
    /// listener goes away when its session ends, or after `wait_ms` if nobody comes.
    BenchListen {
        token: String,
        transport: String,
        profile: String,
        port: u16,
        wait_ms: u32,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        bind: Option<String>,
    },
    /// Dial a benchmark listener at `addr` and measure the link: its handshake, round trips
    /// for `ping_ms`, and with `seconds` above 0 the rate each way for that long. `sni`: the
    /// server name a `wss` link sends.
    BenchDial {
        addr: String,
        token: String,
        transport: String,
        profile: String,
        ping_ms: u32,
        seconds: u32,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sni: Option<String>,
    },
    /// Receive and tally spoof-test probes of `shape` on this server for `seconds`, scoring
    /// each forged source by arrival. The answer is the report. Run it just before the
    /// sender on the other server. Only an agent of 2.9 or newer knows it.
    IpTestReceiver {
        shape: String,
        bind: String,
        seconds: u16,
        run_id: u32,
        expect: u16,
        loss: u8,
    },
    /// Send spoof-test probes of `shape` from each forged source in `sources` to `to`
    /// (the receiver's real address). Only an agent of 2.9 or newer knows it.
    IpTestSender {
        to: String,
        shape: String,
        sources: Vec<String>,
        count: u16,
        interval_ms: u16,
        run_id: u32,
    },
    /// A release is about to be sent (its three files and their sizes).
    UpdateBegin {
        version: String,
        files: Vec<UpdateFile>,
    },
    /// One piece of one of the files: a base64 chunk at an offset.
    UpdateChunk {
        version: String,
        name: String,
        offset: u64,
        data: String,
    },
    /// Everything has been sent: check it, unpack it and swap the programs.
    UpdateApply { version: String },
    /// A terminal: the stream stays open and carries the shell's bytes both ways (see
    /// [`crate::terminal`]). Refused with `terminal_off` unless the agent's settings allow
    /// it. Only an agent of 2.10 or newer knows it.
    Shell { cols: u16, rows: u16 },
}

/// A file of a release that is being sent to an agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateFile {
    pub name: String,
    pub size: u64,
}

/// One private network link on this server, as data. The
/// agent checks every field before it runs anything.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetSpec {
    /// `kz-` and up to eight small letters or digits.
    pub name: String,
    /// This server's public address, and the other server's.
    pub local: String,
    pub remote: String,
    /// Tells two GRE tunnels between the same two addresses apart; for VXLAN it is the VNI,
    /// which no two VXLAN links of one server share.
    pub key: u32,
    /// This end's private address, the other end's, and the prefix length (30 or 31).
    pub address: String,
    pub peer: String,
    pub prefix: u8,
    pub mtu: u32,
    /// GRE, or VXLAN over UDP `port`. Both are left out for GRE: an agent older than VXLAN
    /// refuses fields it does not know, so it still takes a GRE link and refuses a VXLAN
    /// one (instead of making GRE of it).
    #[serde(default, skip_serializing_if = "LinkKind::is_gre")]
    pub kind: LinkKind,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub port: u16,
}

fn is_zero(port: &u16) -> bool {
    *port == 0
}

/// How the links of a private network are made.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LinkKind {
    /// IP protocol 47.
    #[default]
    Gre,
    /// Ethernet frames in UDP datagrams.
    Vxlan,
}

impl LinkKind {
    pub fn is_gre(&self) -> bool {
        *self == Self::Gre
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Gre => "gre",
            Self::Vxlan => "vxlan",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "gre" => Some(Self::Gre),
            "vxlan" => Some(Self::Vxlan),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetIface {
    pub name: String,
    pub address: String,
    pub exists: bool,
    pub up: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetStatus {
    /// This server can make GRE interfaces (root, the `ip_gre` module, no container limit).
    pub gre: bool,
    /// Why not, when it cannot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// This server can make VXLAN interfaces (the `vxlan` module). An agent older than
    /// VXLAN does not say, which reads as no.
    #[serde(default)]
    pub vxlan: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vxlan_reason: Option<String>,
    #[serde(default)]
    pub links: Vec<NetIface>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PingReply {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// A tunnel's mux settings (`[tunnel.mux]`): every one is optional, and what is left out
/// keeps the profile's value.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MuxSpec {
    /// Off for `ws`, `wss`, `kcp` and `stealth` when a tunnel should not multiplex (`tcp`
    /// is the transport that is off by itself; `tcpmux`, `wsmux`, `wssmux` and `auto`
    /// cannot be turned off).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connections: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_streams: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_window: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_lifetime_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ping_interval_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coalesce: Option<bool>,
}

impl MuxSpec {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// What a tunnel is, as data: everything the manager's `add` takes, without free text
/// going into the file. The agent turns it into the config.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Spec {
    pub name: String,
    pub role: String,
    pub mode: String,
    pub transport: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote: Option<String>,
    /// Sent when a tunnel is made or its token changes; `None` keeps the one in the file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pool: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ws_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ws_host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_sni: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_pin: Option<String>,
    /// A listening wss side: the certificate and key files of a real certificate (made by
    /// [`Request::TunnelCert`], under `/etc/letsencrypt/live/`) instead of a self-signed one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_cert: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_key: Option<String>,
    /// Mux settings; left out, the profile's apply.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mux: Option<MuxSpec>,
    /// The cipher of the tunnel: `aes-256-gcm`, `chacha20-poly1305` or `none` (traffic in the
    /// clear, authenticated only). Left out: `auto` (AES where the CPU has it, else ChaCha).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption: Option<String>,
    /// A `quic` tunnel's `[tunnel.quic] obfs`: every UDP packet sealed with a key from the token,
    /// so the traffic does not look like QUIC. Left out: off. Only an agent of 1.7 or newer
    /// reads it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub quic_obfs: bool,
    /// A `quic` tunnel's fixed send rate in Mbit/s (`[tunnel.quic] congestion = "fixed"` with
    /// `bandwidth_mbps`): the sender holds this rate and treats loss as noise. Left out: the
    /// default congestion control. Only an agent of 2.11 or newer reads it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quic_bandwidth: Option<u32>,
    /// Entry side: `[tuning] max_conns_per_ip`. Left out: no limit. Only an agent of 2.4
    /// or newer reads it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_conns_per_ip: Option<u32>,
    /// Entry side: `[tuning] udp_max_flows`, UDP flows per rule. Left out: the default
    /// (4096 from 2.6.0-beta.4). Only an agent of 2.6.0-beta.4 or newer reads it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub udp_max_flows: Option<u32>,
    /// Entry side: the `proxy_protocol` (`v1` or `v2`) of every TCP forward rule, so the
    /// target sees each user's address. Left out: off. Only an agent of 2.5 or newer reads
    /// it; it is here and not on [`ForwardInfo`] because an older agent would drop an
    /// unknown field there without a word.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_protocol: Option<String>,
    /// `stealth`: the record-padding and timing-jitter knobs (`[tunnel.stealth]`). Only an
    /// agent of 2.7 or newer reads it (the `stealth` transport is 2.7's).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stealth: Option<StealthSpec>,
    /// `faketcp`: the fake-TCP carrier knobs (`[tunnel.faketcp]`). 2.7 or newer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub faketcp: Option<FaketcpSpec>,
    /// `icmp`: the ICMP carrier knobs (`[tunnel.icmp]`). 2.7 or newer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icmp: Option<IcmpSpec>,
    /// `spoof`: the source-spoofing carrier knobs (`[tunnel.spoof]`), already resolved for
    /// this side (the pool, the shape, and the peer's real address on the accepting side).
    /// 2.9 or newer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spoof: Option<SpoofSpec>,
    /// `naive` / `xhttp` / `reality`: the managed-helper credentials (`[tunnel.helper]`),
    /// already split for this side (the acceptor keeps the server secrets, the dialer the
    /// client ones). 2.7 or newer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub helper: Option<HelperSpec>,
    /// The `l3` / GRE direct-tunnel settings (`[l3]`), already resolved for this side.
    /// Present only when `transport == "l3"`. 2.7 or newer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub l3: Option<L3Spec>,
    #[serde(default)]
    pub forwards: Vec<ForwardInfo>,
}

/// `[tunnel.stealth]`: record-length padding and timing jitter of the `stealth` transport.
/// Every field is optional; what is left out keeps the core's default.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StealthSpec {
    /// Random padding inside the AEAD record. Left out: on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub padding: Option<bool>,
    /// Largest padding a record carries, in bytes. Left out: the core's default (256).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pad_max: Option<u16>,
    /// Random delay before a record is flushed, in milliseconds. Left out: none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jitter_ms: Option<u16>,
}

impl StealthSpec {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// `[tunnel.faketcp]`: the raw-socket fake-TCP carrier knobs (Linux, root).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FaketcpSpec {
    /// The TCP flag pattern this side's segments carry (`A`, `PA`, `PA,A`, `PA,A,PA,PAU`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flags: Option<String>,
    /// Install and remove the RST-drop / NOTRACK iptables rules (RAII). Left out: on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manage_firewall: Option<bool>,
}

impl FaketcpSpec {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// `[tunnel.icmp]`: the raw ICMP-echo carrier knobs (Linux, root).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IcmpSpec {
    /// Install and remove the kernel-echo-reply suppression rules (RAII). Left out: on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manage_firewall: Option<bool>,
}

impl IcmpSpec {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// `[tunnel.spoof]`: the source-spoofing carrier knobs (Linux, root). Each end forges its
/// source from *its own* pool, so the two servers keep separate lists: the pair layer
/// resolves `pool` (this side's list) and `peer` per side from the wizard's `entry_pool` /
/// `exit_pool` before this crosses the wire.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpoofSpec {
    /// The on-wire packet shape: `udp`, `tcp`, `icmp`, `gre`, `ipip` or `proto58`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shape: Option<String>,
    /// The forged source addresses *this side* rotates through (IPs, CIDR blocks or ranges),
    /// resolved per side by the pair layer. On a wizard request it is unused — the two
    /// servers' lists travel in `entry_pool` / `exit_pool`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pool: Vec<String>,
    /// Wizard-only: the entry server's forged-source list. The pair layer moves it into the
    /// entry side's `pool` and drops it from the resolved per-side spec.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entry_pool: Vec<String>,
    /// Wizard-only: the exit server's forged-source list (see `entry_pool`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exit_pool: Vec<String>,
    /// The peer's real address, needed by the accepting side to address its replies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer: Option<String>,
    /// Install and remove the best-effort iptables rules (RAII). Left out: on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manage_firewall: Option<bool>,
}

impl SpoofSpec {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// `[tunnel.helper]`: credentials and paths for a managed helper transport (`naive`,
/// `xhttp`, `reality`), already filtered for one side. A certificate or key path must be
/// one the manager made (see [`crate::manage::valid_cert_path`]); the agent reads no other.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelperSpec {
    /// Override the helper binary path. Left out: the installed pinned one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binary: Option<String>,
    /// `naive`: the credential.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    /// `xhttp` / `reality`: the VLESS client UUID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    /// `xhttp`: the HTTP path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// `xhttp` / `reality`: the TLS server name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_name: Option<String>,
    /// `xhttp`: the HTTP `Host` header.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// `reality`: the short id (hex, even length, at most 16).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub short_id: Option<String>,
    /// `reality` acceptor: the X25519 private key (base64url).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>,
    /// `reality` dialer: the X25519 public key (base64url).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    /// `reality` acceptor: the cover target, `host:port`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// `naive` / `xhttp` acceptor TLS: the certificate chain (PEM), under `/etc/letsencrypt`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate: Option<String>,
    /// `naive` / `xhttp` acceptor TLS: the private key (PEM), under `/etc/letsencrypt`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// Dialer: a CA bundle (PEM) to verify the helper server against.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_file: Option<String>,
}

impl HelperSpec {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// `[l3]`: the layer-3 / GRE direct-tunnel settings for one side. The tunnel's address is
/// carried in the ordinary [`Spec::listen`] (acceptor) or [`Spec::remote`] (dialer) field,
/// and the token in [`Spec::token`]; `local_ip` / `peer_ip` are already this side's.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct L3Spec {
    /// `udp`, `quic`, `faketcp`, `icmp` or `proto47`: the unreliable carrier the sealed GRE
    /// rides.
    pub carrier: String,
    /// `3` (TUN, IP packets, the default) or `2` (TAP, Ethernet frames). Left out: 3.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub layer: Option<u8>,
    /// This side's address on the tunnel, as a CIDR (`10.10.0.1/30`). Required for layer 3.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_ip: Option<String>,
    /// The peer's address on the tunnel (`10.10.0.2`). Required for layer 3.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_ip: Option<String>,
    /// RFC 2890 key, the same on both sides. Left out: 0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gre_key: Option<u32>,
    /// The TUN/TAP MTU. Left out: the core's default (1400).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u16>,
    /// Accept forwarded UDP over the TUN link.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub accept_udp: bool,
}

impl L3Spec {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// Something that listens on a port of this server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortOwner {
    /// `tcp` or `udp`.
    pub proto: String,
    pub addr: String,
    pub port: u16,
    /// The process name (`sshd`, `kariz`), when it could be found.
    pub process: Option<String>,
    pub pid: Option<u32>,
}

/// The answer to `tunnel_put`: the certificate pin of a listening wss side, for the
/// dialing side's config.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PutReply {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pin: Option<String>,
}

/// The answer to `tunnel_diff`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffReply {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// The file would come out the same (by value): nothing to write.
    #[serde(default)]
    pub same: bool,
    /// What differs is only what a running entry applies on a reload (the forward rules,
    /// `max_conns_per_ip`, `udp_max_flows`). Also set when `same`.
    #[serde(default)]
    pub reloadable: bool,
}

/// The answer to `tunnel_reload`: the daemon's report, or why it was not done. A refusal
/// (`restart needed: …`, `not an entry`, `not running: …`, or an older agent's `unknown
/// request`) means a restart does it instead.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReloadReply {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report: Option<kariz::control::ReloadReport>,
}

/// The answer to `tunnel_check`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CheckReply {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default)]
    pub warnings: Vec<String>,
    /// Ports the spec wants that something else already listens on.
    #[serde(default)]
    pub conflicts: Vec<PortOwner>,
}

/// The answer to `logs` and `speedtest`: text, or why there is none.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TextReply {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default)]
    pub text: String,
}

/// The answer to [`Request::Speedtest`]: what was measured. An agent older than 1.2
/// answers with `text` (the printed report) and no `report`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SpeedReply {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default)]
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report: Option<kariz::speedtest::Report>,
}

/// The answer to [`Request::IpTestReceiver`]: the scored report, or why it could not run.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct IpTestReceiverReply {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report: Option<kariz::spooftest::Report>,
}

/// The answer to [`Request::IpTestSender`]: what was emitted, or why it could not run.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct IpTestSenderReply {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default)]
    pub sent: u64,
    #[serde(default)]
    pub sources: u32,
}

/// The answer to [`Request::TunnelCert`]: the files of the certificate, or why there are none.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CertReply {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
}

/// The answer to [`Request::BenchListen`].
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct BenchListening {
    pub ok: bool,
    pub error: Option<String>,
    pub port: u16,
    /// The address it listens on, for a `bind` (an agent older than `bind` leaves it out: it
    /// listened on IPv4 only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bound: Option<String>,
}

/// The answer to [`Request::BenchDial`]: what one test link measured.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct BenchMeasured {
    pub ok: bool,
    pub error: Option<String>,
    /// The connection and its handshake, in milliseconds.
    pub connect_ms: f64,
    /// Round trips on an idle link.
    pub latency: Option<kariz::speedtest::Latency>,
    /// With `seconds`: the rate each way, and round trips while data moves.
    pub download_mbps: Option<f64>,
    pub upload_mbps: Option<f64>,
    pub loaded: Option<kariz::speedtest::Latency>,
    /// The server name it sent (an agent older than `sni` leaves it out: it sent none).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
}

/// The answer to [`Request::SpeedtestStart`].
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SpeedStarted {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default)]
    pub id: String,
}

/// The answer to [`Request::SpeedtestPoll`]: what a running speed test has said since the
/// last poll (the lines are `kariz::speedtest::run`'s progress lines), and, once `done`, the
/// report or why there is none.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SpeedPoll {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default)]
    pub lines: Vec<String>,
    /// What to pass as `after` next time.
    #[serde(default)]
    pub next: u32,
    #[serde(default)]
    pub done: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report: Option<kariz::speedtest::Report>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HelloReply {
    /// Set once the agent is registered.
    pub id: Option<String>,
    /// `blake3::keyed_hash(key, challenge)` in hex, with the agent's key.
    pub proof: Option<String>,
    /// The join secret from the join code, until the agent is registered.
    pub join: Option<String>,
    pub hostname: String,
    pub version: String,
    pub arch: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Ack {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Health {
    /// Busy share of all CPUs since the previous sample, 0-100.
    pub cpu_pct: Option<f64>,
    pub mem_total: Option<u64>,
    pub mem_used: Option<u64>,
    /// Bytes per second over the network interfaces (not the loopback), since the
    /// previous sample.
    pub rx_bps: Option<f64>,
    pub tx_bps: Option<f64>,
    pub uptime_secs: Option<u64>,
    pub load1: Option<f64>,
    /// The IPv4 networks this server already has routes for (`172.17.0.0/16`, a cloud's
    /// private network...), without the default route and Kariz's own `kz-` links. Private
    /// networks are never given a range that overlaps one.
    #[serde(default)]
    pub routes: Vec<String>,
    /// This server's own IPv4 and IPv6 addresses: the ones its routes to the internet
    /// leave from (a private one behind NAT; the panel shows the public one it sees).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip4: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip6: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForwardInfo {
    pub listen: String,
    pub target: String,
    pub protocol: String,
}

/// One tunnel config on a server. Never carries the token.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TunnelInfo {
    /// The file name without `.toml`, which is also the service (`kariz@NAME`).
    pub name: String,
    pub role: String,
    pub mode: String,
    pub transport: String,
    pub profile: String,
    /// The tunnel's `encryption` setting (`auto`, `aes-256-gcm`, `chacha20-poly1305`, `none`);
    /// empty from an agent that does not say.
    #[serde(default)]
    pub encryption: String,
    pub listen: Option<String>,
    pub remote: Option<String>,
    pub forwards: Vec<ForwardInfo>,
    /// systemd says the service runs. `None` where systemd is not there to ask.
    pub active: Option<bool>,
    /// From the running daemon's control socket (`kariz status`).
    pub status: Option<kariz::stats::Status>,
    /// Why the file could not be read, if it could not.
    pub error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tunnel_with_the_most_ports_the_wizard_allows_fits_one_request() {
        let spec = Spec {
            name: "big".into(),
            role: "entry".into(),
            mode: "reverse".into(),
            transport: "tcpmux".into(),
            listen: Some("0.0.0.0:3080".into()),
            token: Some("t".repeat(48)),
            forwards: (0..200)
                .map(|i| ForwardInfo {
                    listen: format!("[::]:{}", 10000 + i),
                    target: format!("[2001:db8:85a3::8a2e:370:7334]:{}", 10000 + i),
                    protocol: "tcp+udp".into(),
                })
                .collect(),
            ..Default::default()
        };
        let size = serde_json::to_vec(&Request::TunnelPut { spec })
            .unwrap()
            .len();
        assert!(size < MAX_REQUEST, "{size} bytes");
        assert!(
            size > 16 * 1024,
            "the old limit would have refused it: {size} bytes"
        );
    }

    #[test]
    fn requests_are_tagged_json() {
        let json = serde_json::to_string(&Request::Hello {
            challenge: "ab".into(),
        })
        .unwrap();
        assert_eq!(json, r#"{"op":"hello","challenge":"ab"}"#);
        assert_eq!(
            serde_json::to_string(&Request::Health).unwrap(),
            r#"{"op":"health"}"#
        );
        for text in [
            r#"{"op":"health"}"#,
            r#"{"op":"tunnels"}"#,
            r#"{"op":"enroll","id":"a","key":"b"}"#,
        ] {
            serde_json::from_str::<Request>(text).unwrap();
        }
        // Only these operations exist: there is no way to name a command. (A request
        // with extra fields is read as its operation and the extras are ignored; no
        // operation takes a command, a path or a name.)
        for text in [
            r#"{"op":"exec","cmd":"ls"}"#,
            r#"{"op":"shell"}"#,
            r#"{"op":"enroll"}"#,
            "{}",
            "[]",
        ] {
            assert!(serde_json::from_str::<Request>(text).is_err(), "{text}");
        }
    }
}
