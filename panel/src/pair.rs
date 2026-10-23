//! A tunnel is a pair: the entry on one server and the exit on another. This makes, edits,
//! controls and deletes both sides as one operation. Each
//! operation runs in the background as a list of steps that the browser follows, and a
//! step that fails undoes what the earlier ones did.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

use crate::config::random_hex;
use crate::hub::Hub;
use crate::manage::valid_name;
use crate::wire::{
    Ack, CheckReply, DiffReply, ForwardInfo, PutReply, ReloadReply, Request, Spec, SpeedReply,
    TextReply, TunnelInfo,
};

/// How long a new tunnel has to connect before it counts as failed.
pub const CONNECT_WAIT: Duration = Duration::from_secs(30);

/// What the wizard sends: one tunnel, both sides. Serialized, it is the copy the panel
/// keeps of the tunnel ([`crate::specs`]).
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct PairRequest {
    pub name: String,
    /// Server ids (`local` for the panel's own).
    pub entry: String,
    pub exit: String,
    pub mode: String,
    pub transport: String,
    pub profile: Option<String>,
    /// The address the accepting side listens on, e.g. `0.0.0.0:3080`.
    pub listen: String,
    /// The address the dialing side connects to: the accepting server's, as the other sees it.
    pub dial: String,
    pub pool: Option<u32>,
    pub ws_path: Option<String>,
    pub ws_host: Option<String>,
    pub tls_sni: Option<String>,
    /// Mux settings, the same on both sides; left out, the profile's apply.
    #[serde(default)]
    pub mux: Option<crate::wire::MuxSpec>,
    /// `auto` (or left out), `aes-256-gcm`, `chacha20-poly1305` or `none`: the same on both
    /// sides (a side that is not `auto` refuses a peer that uses another cipher).
    #[serde(default)]
    pub encryption: Option<String>,
    /// quic: seal every UDP packet with a key from the token (`[tunnel.quic] obfs`), the same
    /// on both sides. Ignored for other transports.
    #[serde(default)]
    pub quic_obfs: bool,
    /// quic: a fixed send rate in Mbit/s (`[tunnel.quic] congestion = "fixed"`), applied to
    /// both sides so each caps its own sending direction. Left out: default congestion control.
    #[serde(default)]
    pub quic_bandwidth: Option<u32>,
    /// The entry side's `tuning.max_conns_per_ip`; left out or 0: no limit.
    #[serde(default)]
    pub max_conns_per_ip: Option<u32>,
    /// The entry side's `tuning.udp_max_flows` (UDP flows per rule); left out or 0: the
    /// default of the entry side's version.
    #[serde(default)]
    pub udp_max_flows: Option<u32>,
    /// `v1` or `v2`: every TCP port of the tunnel starts its connections to the target with
    /// a PROXY header naming the user. Left out or `off`: none.
    #[serde(default)]
    pub proxy_protocol: Option<String>,
    /// wss: the files of a real certificate on the listening side (from [`certificate`]),
    /// instead of a self-signed one the dialing side pins.
    #[serde(default)]
    pub tls_cert: Option<String>,
    #[serde(default)]
    pub tls_key: Option<String>,
    /// wss with a real certificate: the domain or address it was issued for. The dialing
    /// side checks the certificate against this name (and sends it as SNI), whatever address
    /// it dials and whatever WebSocket Host it sends.
    #[serde(default)]
    pub tls_host: Option<String>,
    #[serde(default)]
    pub forwards: Vec<ForwardInfo>,
    /// Edit only: make a new token for both sides.
    #[serde(default)]
    pub rotate: bool,
    /// Direct mode only: run the tunnel over a private GRE network (its id). The panel
    /// finds or makes the link between the two servers and the tunnel listens on and
    /// dials the private address.
    #[serde(default)]
    pub network: Option<String>,
    /// `stealth`: the record-padding and timing-jitter knobs, the same on both sides.
    #[serde(default)]
    pub stealth: Option<crate::wire::StealthSpec>,
    /// `faketcp`: the fake-TCP carrier knobs, applied to both sides.
    #[serde(default)]
    pub faketcp: Option<crate::wire::FaketcpSpec>,
    /// `icmp`: the ICMP carrier knobs, applied to both sides.
    #[serde(default)]
    pub icmp: Option<crate::wire::IcmpSpec>,
    /// `spoof`: the source-spoofing carrier knobs. The shape is shared; the two servers'
    /// forged-source lists travel as `entry_pool` / `exit_pool` and the pair layer gives each
    /// side its own. The accepting side's `peer` is filled in from the dialing server's
    /// address by the pair layer when the wizard leaves it empty.
    #[serde(default)]
    pub spoof: Option<crate::wire::SpoofSpec>,
    /// `naive` / `xhttp` / `reality`: every managed-helper credential the wizard collected.
    /// The panel splits it per side: the acceptor keeps the server secrets, the dialer the
    /// client ones.
    #[serde(default)]
    pub helper: Option<crate::wire::HelperSpec>,
    /// `l3`: the carrier the sealed GRE rides (`udp`, `quic`, `faketcp`, `icmp` or `proto47`).
    #[serde(default)]
    pub l3_carrier: Option<String>,
    /// `l3`: `3` (TUN, IP packets, default) or `2` (TAP, Ethernet frames).
    #[serde(default)]
    pub l3_layer: Option<u8>,
    /// `l3` layer 3: the `N` of the auto-picked `10.10.N.0/30` address block. Left out: the
    /// panel picks one from the tunnel's name.
    #[serde(default)]
    pub l3_net: Option<u8>,
    /// `l3`: the RFC 2890 GRE key, the same on both sides.
    #[serde(default)]
    pub l3_gre_key: Option<u32>,
    /// `l3`: the TUN/TAP MTU.
    #[serde(default)]
    pub l3_mtu: Option<u16>,
    /// A traffic limit for the new tunnel (the wizard), written once it is up. Not used by
    /// an edit: the limit lives on the tunnel's page.
    #[serde(default)]
    pub quota: Option<crate::quota::QuotaSpec>,
    /// A server (the `entry` or the `exit`) the panel cannot reach: the panel writes the other
    /// side and hands the operator this side's config to apply by hand. Left out: both sides
    /// online, as usual. Not kept in the tunnel's copy.
    #[serde(default, skip_serializing)]
    pub manual: Option<String>,
}

impl PairRequest {
    /// The two specs. `token` is `None` on an edit that keeps the token; `pin` is the
    /// listening wss side's certificate pin, for the dialing side.
    pub fn specs(&self, token: Option<&str>, pin: Option<&str>) -> (Spec, Spec) {
        let reverse = self.mode == "reverse";
        let side = |role: &str, accepts: bool| Spec {
            name: self.name.clone(),
            role: role.to_owned(),
            mode: self.mode.clone(),
            transport: self.transport.clone(),
            profile: self.profile.clone(),
            listen: accepts.then(|| self.listen.clone()),
            remote: (!accepts).then(|| self.dial.clone()),
            token: token.map(str::to_owned),
            pool: self.pool,
            ws_path: self.ws_path.clone(),
            ws_host: self.ws_host.clone(),
            mux: self.mux.clone().filter(|m| !m.is_empty()),
            encryption: self.chosen_encryption().map(str::to_owned),
            quic_obfs: self.sealed(),
            quic_bandwidth: (self.transport == "quic")
                .then_some(self.quic_bandwidth)
                .flatten(),
            max_conns_per_ip: (role == "entry").then(|| self.per_ip_limit()).flatten(),
            udp_max_flows: (role == "entry").then(|| self.udp_flows()).flatten(),
            // Only the entry side has forward rules; the exit side needs nothing written.
            proxy_protocol: (role == "entry")
                .then(|| self.proxy_version().map(str::to_owned))
                .flatten(),
            tls_sni: (!accepts).then(|| self.dial_sni()).flatten(),
            tls_pin: (!accepts && self.transport == "wss" && self.tls_cert.is_none())
                .then(|| pin.map(str::to_owned))
                .flatten(),
            tls_cert: (accepts && self.transport == "wss")
                .then(|| self.tls_cert.clone())
                .flatten(),
            tls_key: (accepts && self.transport == "wss")
                .then(|| self.tls_key.clone())
                .flatten(),
            stealth: (self.transport == "stealth")
                .then(|| self.stealth.clone())
                .flatten()
                .filter(|s| !s.is_empty()),
            faketcp: (self.transport == "faketcp")
                .then(|| self.faketcp.clone())
                .flatten()
                .filter(|f| !f.is_empty()),
            icmp: (self.transport == "icmp")
                .then(|| self.icmp.clone())
                .flatten()
                .filter(|i| !i.is_empty()),
            spoof: self.spoof_for(accepts, role == "entry"),
            helper: self.helper_for(accepts),
            l3: self.l3_for(accepts),
            forwards: if role == "entry" {
                self.forwards.clone()
            } else {
                Vec::new()
            },
        };
        (side("entry", reverse), side("exit", !reverse))
    }

    /// The TLS server name the dialing side uses. With a real certificate it is the name the
    /// certificate was issued for: any other (a server name typed for a self-signed one, a
    /// WebSocket Host, an address that is not the certificate's) makes the dialing side
    /// refuse the certificate (`BadCertificate`).
    fn dial_sni(&self) -> Option<String> {
        if self.transport == "wss" && self.tls_cert.is_some() {
            if let Some(host) = self
                .tls_host
                .as_deref()
                .map(str::trim)
                .filter(|h| !h.is_empty())
            {
                return Some(host.to_ascii_lowercase());
            }
        }
        self.tls_sni.clone()
    }

    /// The request that makes a tunnel again from the two specs its servers hold: the
    /// reverse of [`Self::specs`], for a tunnel made before the panel kept copies. `None`
    /// when the specs are not a pair (different names, modes or transports) or lack what a
    /// request needs. A tunnel over a private network keeps its addresses, not the
    /// network, and a spoof tunnel's accepting side gets its peer from the dialing server
    /// again at each create.
    pub fn from_specs(
        name: &str,
        entry_id: &str,
        exit_id: &str,
        entry: &Spec,
        exit: &Spec,
    ) -> Option<Self> {
        if entry.name != name
            || exit.name != name
            || entry.mode != exit.mode
            || entry.transport != exit.transport
        {
            return None;
        }
        let reverse = entry.mode == "reverse";
        let (acc, dia) = if reverse {
            (entry, exit)
        } else {
            (exit, entry)
        };
        let listen = acc.listen.clone()?;
        let dial = dia.remote.clone()?;
        let real_cert = acc.tls_cert.is_some() && acc.tls_key.is_some();
        let either = |a: &Option<String>, b: &Option<String>| a.clone().or_else(|| b.clone());
        let spoof = (entry.transport == "spoof").then(|| {
            let (e, x) = (
                entry.spoof.clone().unwrap_or_default(),
                exit.spoof.clone().unwrap_or_default(),
            );
            crate::wire::SpoofSpec {
                shape: e.shape.or(x.shape),
                pool: Vec::new(),
                entry_pool: e.pool,
                exit_pool: x.pool,
                peer: None,
                manage_firewall: e.manage_firewall.or(x.manage_firewall),
            }
        });
        let helper = matches!(entry.transport.as_str(), "naive" | "xhttp" | "reality").then(|| {
            let (a, d) = (
                acc.helper.clone().unwrap_or_default(),
                dia.helper.clone().unwrap_or_default(),
            );
            crate::wire::HelperSpec {
                binary: a.binary.or(d.binary),
                username: a.username.or(d.username),
                password: a.password.or(d.password),
                uuid: a.uuid.or(d.uuid),
                path: a.path.or(d.path),
                server_name: a.server_name.or(d.server_name),
                host: a.host.or(d.host),
                short_id: a.short_id.or(d.short_id),
                private_key: a.private_key,
                target: a.target,
                certificate: a.certificate,
                key: a.key,
                public_key: d.public_key,
                ca_file: d.ca_file,
            }
        });
        let l3 = entry.l3.as_ref().or(exit.l3.as_ref());
        // The auto-picked `10.10.N.0/30` block: its N, when the address is one of those.
        let l3_net = l3
            .and_then(|l| l.local_ip.as_deref())
            .and_then(|ip| ip.strip_prefix("10.10.")?.split('.').next()?.parse().ok());
        Some(Self {
            name: name.to_owned(),
            entry: entry_id.to_owned(),
            exit: exit_id.to_owned(),
            mode: entry.mode.clone(),
            transport: entry.transport.clone(),
            profile: either(&entry.profile, &exit.profile),
            listen,
            dial,
            pool: entry.pool.or(exit.pool),
            ws_path: either(&entry.ws_path, &exit.ws_path),
            ws_host: either(&entry.ws_host, &exit.ws_host),
            tls_sni: if real_cert { None } else { dia.tls_sni.clone() },
            mux: entry.mux.clone().or_else(|| exit.mux.clone()),
            encryption: entry.encryption.clone(),
            quic_obfs: entry.quic_obfs || exit.quic_obfs,
            quic_bandwidth: entry.quic_bandwidth.or(exit.quic_bandwidth),
            max_conns_per_ip: entry.max_conns_per_ip,
            udp_max_flows: entry.udp_max_flows,
            proxy_protocol: entry.proxy_protocol.clone(),
            tls_cert: real_cert.then(|| acc.tls_cert.clone()).flatten(),
            tls_key: real_cert.then(|| acc.tls_key.clone()).flatten(),
            tls_host: real_cert.then(|| dia.tls_sni.clone()).flatten(),
            forwards: entry.forwards.clone(),
            rotate: false,
            network: None,
            stealth: entry.stealth.clone().or_else(|| exit.stealth.clone()),
            faketcp: entry.faketcp.clone().or_else(|| exit.faketcp.clone()),
            icmp: entry.icmp.clone().or_else(|| exit.icmp.clone()),
            spoof,
            helper,
            l3_carrier: l3.map(|l| l.carrier.clone()),
            l3_layer: l3.and_then(|l| l.layer),
            l3_net,
            l3_gre_key: l3.and_then(|l| l.gre_key),
            l3_mtu: l3.and_then(|l| l.mtu),
            quota: None,
            manual: None,
        })
    }

    /// The server that accepts the tunnel's connections, and the one that dials.
    pub fn acceptor_first(&self) -> [&str; 2] {
        if self.mode == "reverse" {
            [&self.entry, &self.exit]
        } else {
            [&self.exit, &self.entry]
        }
    }

    /// The role that accepts the tunnel's connections: the entry in reverse mode, the exit in
    /// direct mode.
    fn acceptor_role(&self) -> &'static str {
        if self.mode == "reverse" {
            "entry"
        } else {
            "exit"
        }
    }

    /// When a side is set up by hand (`manual` names one of the two servers): the manual
    /// server and its role, and the reachable server and its role.
    fn manual_side(&self) -> Option<(&str, &'static str, &str, &'static str)> {
        let m = self.manual.as_deref()?;
        if m == self.entry {
            Some((&self.entry, "entry", &self.exit, "exit"))
        } else if m == self.exit {
            Some((&self.exit, "exit", &self.entry, "entry"))
        } else {
            None
        }
    }

    /// Whether this tunnel uses something older servers do not know (`auto`, mux settings):
    /// both of its servers must run 1.5 or newer, or they would refuse the config.
    fn needs_new_servers(&self) -> bool {
        self.transport == "auto" || self.mux.as_ref().is_some_and(|m| !m.is_empty())
    }

    /// Whether the tunnel's QUIC packets are sealed.
    fn sealed(&self) -> bool {
        self.quic_obfs && self.transport == "quic"
    }

    /// The per-address limit to write on the entry side, if there is one.
    fn per_ip_limit(&self) -> Option<u32> {
        self.max_conns_per_ip.filter(|v| *v > 0)
    }

    /// The UDP flow limit to write on the entry side, if one was chosen.
    fn udp_flows(&self) -> Option<u32> {
        self.udp_max_flows.filter(|v| *v > 0)
    }

    /// Whether this tunnel uses what came with 2.4: a per-address limit (entry side), or
    /// more than 4096 streams per connection (both sides refused that before).
    fn needs_2_4(&self) -> (bool, bool) {
        let streams = self
            .mux
            .as_ref()
            .and_then(|m| m.max_streams)
            .is_some_and(|v| v > 4096);
        (self.per_ip_limit().is_some() || streams, streams)
    }

    /// The PROXY header to write on the entry side's TCP rules, if there is one.
    fn proxy_version(&self) -> Option<&str> {
        self.proxy_protocol.as_deref().filter(|v| *v != "off")
    }

    /// The cipher to write: `None` for `auto`.
    fn chosen_encryption(&self) -> Option<&str> {
        self.encryption.as_deref().filter(|e| *e != "auto")
    }

    /// This side's slice of the managed-helper credentials: the acceptor runs the helper
    /// server (its private key, cover target and TLS certificate), the dialer the helper
    /// client (the public key and the CA to trust). The shared identity (credential, UUID,
    /// path, names, short id) goes to both.
    fn helper_for(&self, acceptor: bool) -> Option<crate::wire::HelperSpec> {
        if !matches!(self.transport.as_str(), "naive" | "xhttp" | "reality") {
            return None;
        }
        let h = self.helper.as_ref()?;
        let mut side = crate::wire::HelperSpec {
            binary: h.binary.clone(),
            username: h.username.clone(),
            password: h.password.clone(),
            uuid: h.uuid.clone(),
            path: h.path.clone(),
            server_name: h.server_name.clone(),
            host: h.host.clone(),
            short_id: h.short_id.clone(),
            ..Default::default()
        };
        if acceptor {
            side.private_key = h.private_key.clone();
            side.target = h.target.clone();
            side.certificate = h.certificate.clone();
            side.key = h.key.clone();
        } else {
            side.public_key = h.public_key.clone();
            side.ca_file = h.ca_file.clone();
        }
        (!side.is_empty()).then_some(side)
    }

    /// This side's `[tunnel.spoof]` settings. Each side gets the shape and *its own*
    /// forged-source list (the entry server's `entry_pool`, the exit server's `exit_pool`),
    /// so the two servers never share a pool. Only the accepting side carries `peer` (the
    /// dialer's real address), since the dialing side learns the peer from the address it
    /// dials.
    fn spoof_for(&self, acceptor: bool, is_entry: bool) -> Option<crate::wire::SpoofSpec> {
        if self.transport != "spoof" {
            return None;
        }
        let base = self.spoof.clone().unwrap_or_default();
        let s = crate::wire::SpoofSpec {
            shape: base.shape,
            pool: if is_entry {
                base.entry_pool
            } else {
                base.exit_pool
            },
            // The split lists are wizard-only; the resolved per-side spec carries just `pool`.
            entry_pool: Vec::new(),
            exit_pool: Vec::new(),
            peer: acceptor.then_some(base.peer).flatten(),
            manage_firewall: base.manage_firewall,
        };
        (!s.is_empty()).then_some(s)
    }

    /// For the spoof transport, fills `spoof.peer` (the dialing server's real address) from
    /// the hub when the wizard left it empty, so the accepting side can address its replies.
    /// A borrowed no-op for other transports or when the peer is already set.
    fn with_spoof_peer<'a>(&'a self, hub: &Hub) -> std::borrow::Cow<'a, PairRequest> {
        use std::borrow::Cow;
        if self.transport != "spoof" {
            return Cow::Borrowed(self);
        }
        let set = self
            .spoof
            .as_ref()
            .and_then(|s| s.peer.as_deref())
            .is_some_and(|p| !p.trim().is_empty());
        if set {
            return Cow::Borrowed(self);
        }
        // The dialing server: reverse → the exit dials; direct → the entry dials.
        let dialer = if self.mode == "reverse" {
            &self.exit
        } else {
            &self.entry
        };
        let Some(addr) = hub.addr_of(dialer) else {
            return Cow::Borrowed(self);
        };
        let mut req = self.clone();
        req.spoof.get_or_insert_with(Default::default).peer = Some(addr);
        Cow::Owned(req)
    }

    /// This side's `[l3]` settings, with the auto-picked `10.10.N.0/30` address resolved
    /// (the accepting side is `.1`, the dialing side `.2`). Layer 2 (TAP) takes no address.
    fn l3_for(&self, acceptor: bool) -> Option<crate::wire::L3Spec> {
        if self.transport != "l3" {
            return None;
        }
        let layer = self.l3_layer.unwrap_or(3);
        let (local_ip, peer_ip) = if layer == 3 {
            let n = self.l3_net.unwrap_or_else(|| self.l3_auto_net());
            let (me, peer) = if acceptor { (1, 2) } else { (2, 1) };
            (
                Some(format!("10.10.{n}.{me}/30")),
                Some(format!("10.10.{n}.{peer}")),
            )
        } else {
            (None, None)
        };
        Some(crate::wire::L3Spec {
            carrier: self.l3_carrier.clone().unwrap_or_else(|| "udp".to_owned()),
            layer: Some(layer),
            local_ip,
            peer_ip,
            gre_key: self.l3_gre_key,
            mtu: self.l3_mtu,
            accept_udp: self.forwards.iter().any(|f| f.protocol.contains("udp")),
        })
    }

    /// An address-block index for `l3` derived from the tunnel's name, so two tunnels with
    /// different names rarely land on the same `10.10.N.0/30`.
    fn l3_auto_net(&self) -> u8 {
        self.name.bytes().fold(0u8, u8::wrapping_add)
    }

    /// Whether this tunnel uses a transport that only exists from 2.7 (an older agent
    /// refuses the config with a raw serde error, so the pair step checks it first).
    fn needs_2_7_transport(&self) -> bool {
        matches!(
            self.transport.as_str(),
            "stealth"
                | "wsmux"
                | "wssmux"
                | "udp"
                | "faketcp"
                | "icmp"
                | "naive"
                | "xhttp"
                | "reality"
                | "l3"
        )
    }

    /// The source-spoofing transport, which arrived with 2.9: an older agent does not know
    /// the name and refuses the whole config.
    fn needs_spoof_transport(&self) -> bool {
        self.transport == "spoof"
    }

    /// An error (`old_agent:SERVER:VERSION`, or `old_agent_enc:...` for a cipher,
    /// `old_agent_obfs:...` for sealed QUIC, `old_agent_limits:...` for 2.4's limits and
    /// `old_agent_proxy:...` for PROXY headers) naming the first server that is too old.
    fn require_new_enough(&self, hub: &Hub) -> Result<()> {
        let anything_new = self.needs_new_servers()
            || self.chosen_encryption().is_some()
            || self.sealed()
            || self.needs_2_4().0
            || self.proxy_version().is_some()
            || self.udp_flows().is_some()
            || self.needs_2_7_transport()
            || self.needs_spoof_transport()
            || self.quic_bandwidth.is_some();
        if !anything_new {
            return Ok(());
        }
        for server in hub.snapshot()? {
            if server.id == self.entry || server.id == self.exit {
                self.require_version(&server.id, &server.version)?;
            }
        }
        Ok(())
    }

    /// [`Self::require_new_enough`] for one of the two servers.
    fn require_version(&self, id: &str, version: &str) -> Result<()> {
        // A cipher setting came after 1.5.2; auto and mux settings with 1.5.0.
        if self.chosen_encryption().is_some() && !version_at_least(version, (1, 5, 3)) {
            bail!("old_agent_enc:{id}:{version}");
        }
        // Sealing QUIC came with 1.7: an older agent refuses a spec that has it.
        if self.sealed() && !version_at_least(version, (1, 7, 0)) {
            bail!("old_agent_obfs:{id}:{version}");
        }
        if self.needs_new_servers() && !version_at_least(version, (1, 5, 0)) {
            bail!("old_agent:{id}:{version}");
        }
        // The per-address limit and up to 16384 streams came with 2.4.
        let (entry_2_4, exit_2_4) = self.needs_2_4();
        let needs = if id == self.entry {
            entry_2_4
        } else {
            exit_2_4
        };
        if needs && !version_at_least(version, (2, 4, 0)) {
            bail!("old_agent_limits:{id}:{version}");
        }
        // PROXY headers came with 2.5, and both sides take part: the entry side sends the
        // user's address along (an older one refuses the spec), the exit side writes the
        // header (an older one refuses the open request, and every connection fails).
        if self.proxy_version().is_some() && !version_at_least(version, (2, 5, 0)) {
            bail!("old_agent_proxy:{id}:{version}");
        }
        // The BackPack-style transports and the l3 / GRE mode arrived with 2.7: an older
        // agent does not know the name and refuses the whole config.
        if self.needs_2_7_transport() && !release_at_least(version, TRANSPORTS_SINCE) {
            bail!("old_agent_transport:{id}:{version}");
        }
        // The source-spoofing transport arrived with 2.9: an older agent refuses the config.
        if self.needs_spoof_transport() && !release_at_least(version, SPOOF_SINCE) {
            bail!("old_agent_transport:{id}:{version}");
        }
        // Fixed-rate QUIC congestion came with 2.11: an older agent does not know the
        // congestion name and refuses the whole config.
        if self.quic_bandwidth.is_some() && !release_at_least(version, QUIC_FIXED_SINCE) {
            bail!("old_agent_quicrate:{id}:{version}");
        }
        // The panel writes the UDP flow limit from 2.6.0-beta.4 (the core had it before; an
        // older agent refuses the field). Only the entry side has UDP rules.
        if id == self.entry
            && self.udp_flows().is_some()
            && !release_at_least(version, UDP_FLOWS_SINCE)
        {
            bail!("old_agent_udp:{id}:{version}");
        }
        Ok(())
    }

    fn validate(&self) -> Result<()> {
        if !valid_name(&self.name) {
            bail!("bad_name");
        }
        if self.entry == self.exit {
            bail!("same_server");
        }
        if !matches!(self.mode.as_str(), "reverse" | "direct") {
            bail!("bad_mode");
        }
        if let Some(e) = &self.encryption {
            if !matches!(
                e.as_str(),
                "auto" | "aes-256-gcm" | "chacha20-poly1305" | "none"
            ) {
                bail!("bad_encryption");
            }
            // QUIC is always TLS 1.3: a cipher of its own does not exist there.
            if self.transport == "quic" && e != "auto" {
                bail!("encryption_quic");
            }
        }
        if let Some(host) = self.tls_host.as_deref().map(str::trim) {
            if !host.is_empty() && !crate::manage::valid_cert_host(&host.to_ascii_lowercase()) {
                bail!("bad_tls_host");
            }
        }
        if let Some(v) = &self.proxy_protocol {
            if !matches!(v.as_str(), "off" | "v1" | "v2") {
                bail!("bad_proxy_protocol");
            }
        }
        if self.udp_flows().is_some_and(|v| v > 65536) {
            bail!("bad_udp_flows");
        }
        // The l3 / GRE mode needs an unreliable carrier (a reliable one melts down under
        // TCP-over-TCP) and a layer the core knows.
        if self.transport == "l3" {
            let carrier = self.l3_carrier.as_deref().unwrap_or("udp");
            if !matches!(carrier, "udp" | "quic" | "faketcp" | "icmp" | "proto47") {
                bail!("bad_l3_carrier");
            }
            if self.l3_layer.is_some_and(|l| l != 2 && l != 3) {
                bail!("bad_l3_layer");
            }
        }
        // The spoof transport needs a known shape and a separate forged-source list for each
        // server (the two ends never share a pool).
        if self.transport == "spoof" {
            let spoof = self.spoof.as_ref();
            let shape = spoof.and_then(|s| s.shape.as_deref()).unwrap_or("udp");
            if kariz::config::SpoofShape::from_name(shape).is_none() {
                bail!("bad_spoof_shape");
            }
            let entry_pool = spoof.map(|s| s.entry_pool.as_slice()).unwrap_or_default();
            let exit_pool = spoof.map(|s| s.exit_pool.as_slice()).unwrap_or_default();
            if entry_pool.is_empty() || exit_pool.is_empty() {
                bail!("spoof_pool_required");
            }
            // Reject a malformed entry in either list up front (the core also rejects it).
            for pool in [entry_pool, exit_pool] {
                if kariz::config::expand_ipv4_specs(pool, kariz::config::SPOOF_POOL_MAX)
                    .map(|p| p.is_empty())
                    .unwrap_or(true)
                {
                    bail!("bad_spoof_pool");
                }
            }
        }
        // udp, faketcp, icmp, stealth, l3 and spoof seal nothing of their own: the tunnel's
        // own encryption carries it, so `none` is refused (as the core does).
        if self.encryption.as_deref() == Some("none")
            && matches!(
                self.transport.as_str(),
                "udp" | "faketcp" | "icmp" | "stealth" | "l3" | "spoof"
            )
        {
            bail!("encryption_required");
        }
        Ok(())
    }
}

/// The first release whose agent writes `tuning.udp_max_flows` from the panel.
const UDP_FLOWS_SINCE: &str = "2.6.0-beta.4";

/// The first release whose agent knows the BackPack-style transports (`stealth`, `wsmux`,
/// `wssmux`, `udp`, `faketcp`, `icmp`, `naive`, `xhttp`, `reality`) and the `l3` mode.
const TRANSPORTS_SINCE: &str = "2.7.0";

/// The first release whose agent knows the source-spoofing transport (`spoof`) and the IP
/// spoof tester.
const SPOOF_SINCE: &str = "2.9.0";
const QUIC_FIXED_SINCE: &str = "2.11.0";

/// The first release whose daemon counts an l3 tunnel's bytes, so it can have a limit.
pub const L3_COUNTS_SINCE: &str = "2.10.0";

/// A server's agent version as the hub last saw it; empty for one it does not know.
pub fn server_version(hub: &Hub, id: &str) -> String {
    hub.snapshot()
        .ok()
        .into_iter()
        .flatten()
        .find(|s| s.id == id)
        .map(|s| s.version)
        .unwrap_or_default()
}

/// Keeps the panel's copy of a tunnel that was just made or edited ([`crate::specs`]).
fn keep_copy(hub: &Hub, req: &PairRequest) {
    if let Err(e) = crate::specs::keep(&hub.db, req, "panel") {
        tracing::warn!(tunnel = %req.name, error = %format!("{e:#}"), "the tunnel's settings could not be kept");
    }
}

/// Whether `version` is `min` or a later release, prereleases in their order
/// (`2.6.0-beta.3` is before `2.6.0-beta.4`, which is before `2.6.0`). One that cannot be
/// read counts as too old.
fn release_at_least(version: &str, min: &str) -> bool {
    match (
        crate::update::Version::parse(version),
        crate::update::Version::parse(min),
    ) {
        (Some(v), Some(m)) => v >= m,
        _ => false,
    }
}

/// Whether `version` (`1.5.0`, maybe with a suffix after a dash) is at least `min`. One that
/// cannot be read counts as too old.
pub(crate) fn version_at_least(version: &str, min: (u32, u32, u32)) -> bool {
    let mut parts = version
        .trim_start_matches('v')
        .split('-')
        .next()
        .unwrap_or("")
        .split('.')
        .map(|p| p.parse::<u32>());
    match (parts.next(), parts.next(), parts.next()) {
        (Some(Ok(a)), Some(Ok(b)), Some(Ok(c))) => (a, b, c) >= min,
        _ => false,
    }
}

// ---- operations ----

#[derive(Debug, Clone, Serialize)]
pub struct Step {
    /// A stable key for the browser to translate: `check_entry`, `write_exit`, ...
    pub id: String,
    /// `run`, `ok` or `fail`.
    pub state: &'static str,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Op {
    pub id: String,
    /// `create`, `edit`, `control` or `delete`.
    pub kind: &'static str,
    pub name: String,
    /// `running`, `done` or `failed`.
    pub state: &'static str,
    pub steps: Vec<Step>,
    pub error: Option<String>,
    /// After a failure: whether the earlier steps were undone.
    pub undone: Option<bool>,
    /// Servers that could not be reached, and so were left out: a delete is kept for when
    /// they connect again, a start, stop or restart did not touch them.
    pub offline: Vec<String>,
    /// A side the panel could not reach, to set up by hand: the config file, the commands,
    /// and the token (shown only here, once). Lives only while this op is in memory.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bundle: Option<ManualBundle>,
}

/// Everything the operator needs to bring up a tunnel side by hand, on a server the panel
/// could not reach. Carried on the create op and shown once; never stored.
#[derive(Debug, Clone, Serialize)]
pub struct ManualBundle {
    /// The server to set up (id) and the side it is (`entry` or `exit`).
    pub server: String,
    pub role: String,
    /// The file to write as `/etc/kariz/NAME.toml` (its token is inside).
    pub config: String,
    /// A self-signed `wss` side also needs these, as `NAME.crt` and `NAME.key`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// The shell commands that write the files and start the service.
    pub commands: String,
}

/// The recent operations, for the browser to follow.
#[derive(Default)]
pub struct Ops(Mutex<Vec<Op>>);

impl Ops {
    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<Op>> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub(crate) fn begin(&self, kind: &'static str, name: &str) -> Result<String> {
        let id = random_hex(8)?;
        let mut ops = self.lock();
        // One operation per tunnel at a time.
        if ops.iter().any(|o| o.name == name && o.state == "running") {
            bail!("busy");
        }
        if ops.len() >= 30 {
            ops.remove(0);
        }
        ops.push(Op {
            id: id.clone(),
            kind,
            name: name.to_owned(),
            state: "running",
            steps: Vec::new(),
            error: None,
            undone: None,
            offline: Vec::new(),
            bundle: None,
        });
        Ok(id)
    }

    fn with(&self, id: &str, f: impl FnOnce(&mut Op)) {
        if let Some(op) = self.lock().iter_mut().find(|o| o.id == id) {
            f(op);
        }
    }

    /// A step starts.
    pub(crate) fn run(&self, id: &str, step: &str) {
        self.with(id, |op| {
            op.steps.push(Step {
                id: step.to_owned(),
                state: "run",
                detail: None,
            })
        });
    }

    /// A server could not be reached and was left out.
    pub(crate) fn left_out(&self, id: &str, server: &str) {
        self.with(id, |op| op.offline.push(server.to_owned()));
    }

    /// Attaches the bundle for a side to be set up by hand.
    pub(crate) fn set_bundle(&self, id: &str, bundle: ManualBundle) {
        self.with(id, |op| op.bundle = Some(bundle));
    }

    /// The last step ends.
    pub(crate) fn end(&self, id: &str, ok: bool, detail: Option<String>) {
        self.with(id, |op| {
            if let Some(step) = op.steps.last_mut() {
                step.state = if ok { "ok" } else { "fail" };
                step.detail = detail;
            }
        });
    }

    pub(crate) fn finish(&self, id: &str, error: Option<String>, undone: Option<bool>) {
        self.with(id, |op| {
            op.state = if error.is_some() { "failed" } else { "done" };
            op.error = error;
            op.undone = undone;
        });
    }

    /// Whether an operation of this kind is running.
    pub fn running(&self, kind: &str) -> bool {
        self.lock()
            .iter()
            .any(|o| o.kind == kind && o.state == "running")
    }

    /// How many operations of a kind there have been (for the tests).
    #[cfg(test)]
    pub(crate) fn count(&self, kind: &str) -> usize {
        self.lock().iter().filter(|o| o.kind == kind).count()
    }

    pub fn get(&self, id: &str) -> Option<Op> {
        self.lock().iter().find(|o| o.id == id).cloned()
    }
}

/// Where a tunnel's two sides are, from what the servers last reported.
struct Placement {
    /// `(server id, its tunnel)` for each server that has a tunnel of that name.
    sides: Vec<(String, TunnelInfo)>,
}

fn place(hub: &Hub, name: &str) -> Result<Placement> {
    let mut sides = Vec::new();
    for server in hub.snapshot()? {
        if let Some(t) = server.tunnels.into_iter().find(|t| t.info.name == name) {
            sides.push((server.id, t.info));
        }
    }
    Ok(Placement { sides })
}

fn fail_text(reply: &Ack) -> String {
    reply.error.clone().unwrap_or_else(|| "failed".into())
}

/// Checks a request on both servers (nothing is written).
pub async fn check(hub: &Hub, req: &PairRequest) -> Result<(CheckReply, CheckReply)> {
    req.validate()?;
    req.require_new_enough(hub)?;
    let req = req.with_spoof_peer(hub);
    let (entry, exit) = req.specs(None, None);
    let a = hub
        .ask_as(&req.entry, &Request::TunnelCheck { spec: entry })
        .await?;
    let b = hub
        .ask_as(&req.exit, &Request::TunnelCheck { spec: exit })
        .await?;
    Ok((a, b))
}

/// Waits until both sides say they are connected; the reason if they do not in time.
async fn wait_connected(hub: &Hub, req: &PairRequest, limit: Duration) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + limit;
    let mut last = String::new();
    loop {
        let mut connected = 0;
        // The dialing side last, so its error is the one kept: it says why (a certificate
        // it refused, an address it cannot reach), where the listening side only sees the
        // connection end.
        for server in req.acceptor_first() {
            let tunnels: Vec<TunnelInfo> = match hub.ask_as(server, &Request::Tunnels).await {
                Ok(t) => t,
                Err(e) => {
                    last = format!("{e:#}");
                    continue;
                }
            };
            let Some(t) = tunnels.into_iter().find(|t| t.name == req.name) else {
                last = "the tunnel is not there".into();
                continue;
            };
            if let Some(e) = &t.error {
                last = e.clone();
            } else if t.active == Some(false) {
                last = "the service stopped".into();
            } else if let Some(status) = &t.status {
                if status.peer.connected {
                    connected += 1;
                } else if let Some(err) = &status.peer.last_error {
                    last = err.text.clone();
                }
            }
        }
        if connected == 2 {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(if last.is_empty() {
                "the two sides did not connect in time".into()
            } else {
                last
            });
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

pub async fn ctl(hub: &Hub, server: &str, name: &str, action: &str) -> Result<(), String> {
    // Stop disables the service too, so a stopped tunnel stays stopped at boot, as the page
    // says; Start enables it again. Every agent knows both (`manage::ctl_args`).
    let action = match action {
        "stop" => "disable",
        "start" => "enable",
        other => other,
    };
    let r: Ack = hub
        .ask_as(
            server,
            &Request::TunnelCtl {
                name: name.to_owned(),
                action: action.to_owned(),
            },
        )
        .await
        .map_err(|e| format!("{e:#}"))?;
    if r.ok {
        Ok(())
    } else {
        Err(fail_text(&r))
    }
}

async fn put(hub: &Hub, server: &str, spec: Spec) -> Result<Option<String>, String> {
    let r: PutReply = hub
        .ask_as(server, &Request::TunnelPut { spec })
        .await
        .map_err(|e| format!("{e:#}"))?;
    if r.ok {
        Ok(r.pin)
    } else {
        Err(r.error.unwrap_or_else(|| "failed".into()))
    }
}

async fn remove(hub: &Hub, server: &str, name: &str) -> Result<(), String> {
    let r: Ack = hub
        .ask_as(
            server,
            &Request::TunnelDelete {
                name: name.to_owned(),
            },
        )
        .await
        .map_err(|e| format!("{e:#}"))?;
    if r.ok {
        Ok(())
    } else {
        Err(fail_text(&r))
    }
}

fn describe(check: &CheckReply) -> String {
    let mut text = check.error.clone().unwrap_or_default();
    for c in &check.conflicts {
        text.push_str(&format!(
            "; {} {} is used by {}",
            c.proto,
            c.port,
            c.process.as_deref().unwrap_or("another program")
        ));
    }
    text
}

/// Starts making a tunnel. The operation's id comes back at once.
pub fn create(hub: &Arc<Hub>, req: PairRequest) -> Result<String> {
    req.validate()?;
    if let Some(q) = &req.quota {
        crate::quota::check(q.limit_bytes, q.reset_day, q.expires_at())?;
        // An l3 tunnel's bytes are counted from 2.10.0: on an older entry a limit would
        // never be reached.
        if req.transport == "l3"
            && !release_at_least(&server_version(hub, &req.entry), L3_COUNTS_SINCE)
        {
            bail!("bad_input");
        }
    }
    if req.manual.is_some() {
        // A side set up by hand: the manual server must be one of the two, and the things that
        // need that server online are refused.
        let Some((_, manual_role, reachable_server, _)) = req.manual_side() else {
            bail!("bad_manual");
        };
        if req.network.is_some() {
            bail!("manual_no_network");
        }
        if manual_role == req.acceptor_role() && req.tls_cert.is_some() {
            bail!("manual_no_real_cert");
        }
        // Only the reachable side can be version-checked; the operator installs the other.
        for server in hub.snapshot()? {
            if server.id == reachable_server {
                req.require_version(&server.id, &server.version)?;
            }
        }
    } else {
        req.require_new_enough(hub)?;
    }
    let id = hub.ops.begin("create", &req.name)?;
    let hub = hub.clone();
    let op = id.clone();
    tokio::spawn(async move {
        // A link made for this tunnel goes again if the tunnel cannot be made.
        let mut made_link = None;
        let outcome = if req.manual.is_some() {
            run_create_manual(&hub, &op, &req).await
        } else {
            run_create(&hub, &op, &req, &mut made_link).await
        };
        match outcome {
            Ok(()) => {
                keep_copy(&hub, &req);
                hub.ops.finish(&op, None, None)
            }
            Err((error, undone)) => {
                if let Some(link) = made_link {
                    crate::netops::tear_down(&hub, &link).await;
                }
                hub.ops.finish(&op, Some(error), Some(undone));
            }
        }
    });
    Ok(id)
}

/// A request that asks for a private network, with its addresses filled in: the link between
/// the two servers is found (or made now, and put in `made_link`), and the tunnel listens on
/// and dials the address of its end on the server that accepts the connections (the exit in
/// direct mode, the entry in reverse mode). `None` when the request names no network.
pub async fn over_network(
    hub: &Hub,
    op: &str,
    req: &PairRequest,
    made_link: &mut Option<crate::networks::Link>,
) -> Result<Option<PairRequest>, String> {
    let Some(network) = &req.network else {
        return Ok(None);
    };
    let (link, fresh) = crate::netops::ensure_link(hub, op, network, &req.entry, &req.exit).await?;
    if fresh {
        *made_link = Some(link.clone());
    }
    let [acceptor, _] = req.acceptor_first();
    let endpoint = crate::netops::tunnel_endpoint(&link, acceptor, &req.listen);
    Ok(Some(PairRequest {
        listen: endpoint.clone(),
        dial: endpoint,
        network: None,
        ..req.clone()
    }))
}

async fn run_create(
    hub: &Hub,
    op: &str,
    req: &PairRequest,
    made_link: &mut Option<crate::networks::Link>,
) -> Result<(), (String, bool)> {
    let ops = &hub.ops;
    let step_fail = |ops: &Ops, e: String| {
        ops.end(op, false, Some(e.clone()));
        e
    };

    // Nothing of that name exists yet, on either server.
    ops.run(op, "look");
    if hub.delete_pending_for(&req.name) {
        return Err((step_fail(ops, "name_pending".into()), true));
    }
    match place(hub, &req.name) {
        Ok(p) if p.sides.is_empty() => ops.end(op, true, None),
        Ok(_) => return Err((step_fail(ops, "name_taken".into()), true)),
        Err(e) => return Err((step_fail(ops, format!("{e:#}")), true)),
    }

    // Over a private network: the link between the two servers (made now if it is not
    // there), and the tunnel listens on and dials its addresses.
    let resolved = match over_network(hub, op, req, made_link).await {
        Ok(r) => r,
        Err(e) => return Err((e, true)),
    };
    let req = resolved.as_ref().unwrap_or(req);
    // For spoof, the accepting side needs the dialer's real address; fill it from the hub.
    let spoofed = req.with_spoof_peer(hub);
    let req = &*spoofed;

    // Both servers agree it is valid, and its ports are free.
    for (step, server, spec) in [
        ("check_entry", &req.entry, req.specs(None, None).0),
        ("check_exit", &req.exit, req.specs(None, None).1),
    ] {
        ops.run(op, step);
        match hub
            .ask_as::<CheckReply>(server, &Request::TunnelCheck { spec })
            .await
        {
            Ok(c) if c.ok => ops.end(op, true, None),
            Ok(c) => return Err((step_fail(ops, describe(&c)), true)),
            Err(e) => return Err((step_fail(ops, format!("{e:#}")), true)),
        }
    }

    let token = match random_hex(24) {
        Ok(t) => t,
        Err(e) => return Err((step_fail(ops, format!("{e:#}")), true)),
    };
    let [first, second] = req.acceptor_first();
    let (first_role, second_role) = if req.mode == "reverse" {
        ("entry", "exit")
    } else {
        ("exit", "entry")
    };
    let mut written: Vec<&str> = Vec::new();
    let pin;

    // The accepting side first: the dialing side needs its address (and its pin) to be up.
    let (entry_spec, exit_spec) = req.specs(Some(&token), None);
    let first_spec = if first_role == "entry" {
        entry_spec
    } else {
        exit_spec
    };
    ops.run(op, &format!("write_{first_role}"));
    match put(hub, first, first_spec).await {
        Ok(p) => {
            pin = p;
            written.push(first);
            ops.end(op, true, None);
        }
        Err(e) => return Err((step_fail(ops, e), true)),
    }
    let (entry_spec, exit_spec) = req.specs(Some(&token), pin.as_deref());
    let second_spec = if second_role == "entry" {
        entry_spec
    } else {
        exit_spec
    };
    ops.run(op, &format!("write_{second_role}"));
    match put(hub, second, second_spec).await {
        Ok(_) => {
            written.push(second);
            ops.end(op, true, None);
        }
        Err(e) => {
            let undone = undo(hub, &written, &req.name).await;
            return Err((step_fail(ops, e), undone));
        }
    }

    for (role, server) in [(first_role, first), (second_role, second)] {
        ops.run(op, &format!("start_{role}"));
        match ctl(hub, server, &req.name, "enable").await {
            Ok(()) => ops.end(op, true, None),
            Err(e) => {
                let undone = undo(hub, &written, &req.name).await;
                return Err((step_fail(ops, e), undone));
            }
        }
    }

    ops.run(op, "connect");
    match wait_connected(hub, req, hub.connect_wait).await {
        Ok(()) => {
            ops.end(op, true, None);
            // The limit the wizard asked for, from the first byte.
            if let Some(q) = &req.quota {
                if let Err(e) = crate::quota::write(
                    &hub.db,
                    &req.name,
                    q.limit_bytes,
                    q.reset_day,
                    q.expires_at(),
                ) {
                    tracing::warn!(tunnel = %req.name, error = %format!("{e:#}"), "the new tunnel's traffic limit could not be set");
                }
            }
            Ok(())
        }
        Err(e) => {
            let undone = undo(hub, &written, &req.name).await;
            Err((step_fail(ops, e), undone))
        }
    }
}

/// Makes a tunnel with one side set up by hand. The reachable side is written and started;
/// the other side's config, certificate and the commands to apply it go into the op's bundle
/// (shown once), and the tunnel waits (`crate::manual`) until that server reports it.
async fn run_create_manual(hub: &Hub, op: &str, req: &PairRequest) -> Result<(), (String, bool)> {
    let ops = &hub.ops;
    let step_fail = |ops: &Ops, e: String| {
        ops.end(op, false, Some(e.clone()));
        e
    };
    let (manual_server, manual_role, reachable_server, reachable_role) =
        req.manual_side().expect("a manual side, checked in create");

    // Nothing of that name is on the reachable side (the manual side is offline, so its own
    // clashes are the operator's to see when applying the file).
    ops.run(op, "look");
    if hub.delete_pending_for(&req.name) {
        return Err((step_fail(ops, "name_pending".into()), true));
    }
    match place(hub, &req.name) {
        Ok(p) if p.sides.is_empty() => ops.end(op, true, None),
        Ok(_) => return Err((step_fail(ops, "name_taken".into()), true)),
        Err(e) => return Err((step_fail(ops, format!("{e:#}")), true)),
    }

    // For spoof, the accepting side needs the dialer's real address; fill it from the hub.
    let spoofed = req.with_spoof_peer(hub);
    let req = &*spoofed;

    // Both sides valid: the reachable one on its server, the manual one locally.
    let (entry_check, exit_check) = req.specs(None, None);
    let (manual_check, reachable_check) = if manual_role == "entry" {
        (entry_check, exit_check)
    } else {
        (exit_check, entry_check)
    };
    ops.run(op, &format!("check_{reachable_role}"));
    match hub
        .ask_as::<CheckReply>(
            reachable_server,
            &Request::TunnelCheck {
                spec: reachable_check,
            },
        )
        .await
    {
        Ok(c) if c.ok => ops.end(op, true, None),
        Ok(c) => return Err((step_fail(ops, describe(&c)), true)),
        Err(e) => return Err((step_fail(ops, format!("{e:#}")), true)),
    }
    ops.run(op, &format!("check_{manual_role}"));
    let mut probe = manual_check;
    probe.token = Some("0".repeat(48));
    if let Err(e) = crate::manage::validate_text(std::path::Path::new("/etc/kariz"), &probe) {
        return Err((step_fail(ops, format!("{e:#}")), true));
    }
    ops.end(op, true, None);

    let token = match random_hex(24) {
        Ok(t) => t,
        Err(e) => return Err((step_fail(ops, format!("{e:#}")), true)),
    };

    // Only a self-signed wss acceptor needs a pin on the dialer. If the manual side is that
    // acceptor, the panel makes the certificate so the reachable dialer can be pinned.
    let needs_pin = req.transport == "wss" && req.tls_cert.is_none();
    let manual_is_acceptor = manual_role == req.acceptor_role();
    let mut gen_cert: Option<(String, String)> = None;
    let pin: Option<String>;

    if reachable_role == req.acceptor_role() {
        // The reachable side accepts: writing it gives the pin.
        let (entry_spec, exit_spec) = req.specs(Some(&token), None);
        let spec = if reachable_role == "entry" {
            entry_spec
        } else {
            exit_spec
        };
        ops.run(op, &format!("write_{reachable_role}"));
        match put(hub, reachable_server, spec).await {
            Ok(p) => {
                pin = p;
                ops.end(op, true, None);
            }
            Err(e) => return Err((step_fail(ops, e), true)),
        }
    } else {
        // The reachable side dials: it needs the acceptor's pin, which the offline manual
        // acceptor cannot give, so the panel makes the certificate here (wss only).
        if needs_pin && manual_is_acceptor {
            match crate::cert::make() {
                Ok((c, k, p)) => {
                    gen_cert = Some((c, k));
                    pin = Some(p);
                }
                Err(e) => return Err((step_fail(ops, format!("{e:#}")), true)),
            }
        } else {
            pin = None;
        }
        let (entry_spec, exit_spec) = req.specs(Some(&token), pin.as_deref());
        let spec = if reachable_role == "entry" {
            entry_spec
        } else {
            exit_spec
        };
        ops.run(op, &format!("write_{reachable_role}"));
        match put(hub, reachable_server, spec).await {
            Ok(_) => ops.end(op, true, None),
            Err(e) => return Err((step_fail(ops, e), true)),
        }
    }

    let written = [reachable_server];
    ops.run(op, &format!("start_{reachable_role}"));
    if let Err(e) = ctl(hub, reachable_server, &req.name, "enable").await {
        let undone = undo(hub, &written, &req.name).await;
        return Err((step_fail(ops, e), undone));
    }
    ops.end(op, true, None);

    // Build the manual side's bundle: its config (with the token), any certificate, and the
    // commands to apply it.
    let cert_files = gen_cert.as_ref().map(|_| {
        (
            std::path::PathBuf::from(format!("/etc/kariz/{}.crt", req.name)),
            std::path::PathBuf::from(format!("/etc/kariz/{}.key", req.name)),
        )
    });
    let (entry_spec, exit_spec) = req.specs(Some(&token), pin.as_deref());
    let manual_spec = if manual_role == "entry" {
        entry_spec
    } else {
        exit_spec
    };
    let config = match crate::manage::render(
        &manual_spec,
        &token,
        cert_files.as_ref().map(|(c, k)| (c.as_path(), k.as_path())),
    ) {
        Ok(t) => t,
        Err(e) => {
            let undone = undo(hub, &written, &req.name).await;
            return Err((step_fail(ops, format!("{e:#}")), undone));
        }
    };
    let (cert, key) = match gen_cert {
        Some((c, k)) => (Some(c), Some(k)),
        None => (None, None),
    };
    let commands = manual_commands(&req.name, cert.is_some());

    ops.run(op, "bundle");
    if let Err(e) = crate::manual::set(&hub.db, &req.name, manual_role, manual_server) {
        tracing::warn!(tunnel = %req.name, error = %format!("{e:#}"), "could not record the manual-side wait");
    }
    ops.set_bundle(
        op,
        ManualBundle {
            server: manual_server.to_owned(),
            role: manual_role.to_owned(),
            config,
            cert,
            key,
            commands,
        },
    );
    ops.left_out(op, manual_server);
    ops.end(op, true, None);

    // The limit the wizard asked for, from the first byte.
    if let Some(q) = &req.quota {
        if let Err(e) = crate::quota::write(
            &hub.db,
            &req.name,
            q.limit_bytes,
            q.reset_day,
            q.expires_at(),
        ) {
            tracing::warn!(tunnel = %req.name, error = %format!("{e:#}"), "the new tunnel's traffic limit could not be set");
        }
    }
    Ok(())
}

/// The commands the operator runs on the manual side after writing the files.
fn manual_commands(name: &str, has_cert: bool) -> String {
    let mut s = String::from("sudo install -d -m 700 /etc/kariz\n");
    if has_cert {
        s.push_str(&format!(
            "sudo chmod 600 /etc/kariz/{name}.toml /etc/kariz/{name}.key\n\
             sudo chmod 644 /etc/kariz/{name}.crt\n"
        ));
    } else {
        s.push_str(&format!("sudo chmod 600 /etc/kariz/{name}.toml\n"));
    }
    s.push_str(&format!(
        "sudo kariz check -c /etc/kariz/{name}.toml\n\
         sudo systemctl enable --now kariz@{name}\n\
         # no systemd? run: sudo touch /etc/kariz/{name}.enabled && restart the Kariz agent\n"
    ));
    s
}

/// Removes what a failed operation made; whether all of it went.
async fn undo(hub: &Hub, servers: &[&str], name: &str) -> bool {
    let mut all = true;
    for server in servers.iter().rev() {
        all &= remove(hub, server, name).await.is_ok();
    }
    all
}

/// Starts editing a tunnel: both sides get the new settings, and if they do not connect
/// again the old ones are put back.
pub fn edit(hub: &Arc<Hub>, req: PairRequest) -> Result<String> {
    req.validate()?;
    req.require_new_enough(hub)?;
    let id = hub.ops.begin("edit", &req.name)?;
    let hub = hub.clone();
    let op = id.clone();
    tokio::spawn(async move {
        // A link made for this edit goes again if the edit cannot be made.
        let mut made_link = None;
        match run_edit(&hub, &op, &req, &mut made_link).await {
            Ok(()) => {
                keep_copy(&hub, &req);
                hub.ops.finish(&op, None, None)
            }
            Err((error, undone)) => {
                if let Some(link) = made_link {
                    crate::netops::tear_down(&hub, &link).await;
                }
                hub.ops.finish(&op, Some(error), Some(undone));
            }
        }
    });
    Ok(id)
}

async fn run_edit(
    hub: &Hub,
    op: &str,
    req: &PairRequest,
    made_link: &mut Option<crate::networks::Link>,
) -> Result<(), (String, bool)> {
    let ops = &hub.ops;
    let step_fail = |ops: &Ops, e: String| {
        ops.end(op, false, Some(e.clone()));
        e
    };
    // What is there now, to put back.
    ops.run(op, "look");
    let mut before = Vec::new();
    for server in [&req.entry, &req.exit] {
        match hub
            .ask_as::<Spec>(
                server,
                &Request::TunnelGet {
                    name: req.name.clone(),
                },
            )
            .await
        {
            Ok(spec) => before.push((server.clone(), spec)),
            Err(e) => return Err((step_fail(ops, format!("{e:#}")), true)),
        }
    }
    ops.end(op, true, None);

    // Over a private network (or back off it, when the request names none): the addresses
    // the tunnel listens on and dials.
    let resolved = match over_network(hub, op, req, made_link).await {
        Ok(r) => r,
        Err(e) => return Err((e, true)),
    };
    let req = resolved.as_ref().unwrap_or(req);
    // For spoof, the accepting side needs the dialer's real address; fill it from the hub.
    let spoofed = req.with_spoof_peer(hub);
    let req = &*spoofed;

    let token = if req.rotate {
        match random_hex(24) {
            Ok(t) => Some(t),
            Err(e) => return Err((step_fail(ops, format!("{e:#}")), true)),
        }
    } else {
        None
    };
    for (step, server, spec) in [
        ("check_entry", &req.entry, req.specs(None, None).0),
        ("check_exit", &req.exit, req.specs(None, None).1),
    ] {
        ops.run(op, step);
        match hub
            .ask_as::<CheckReply>(server, &Request::TunnelCheck { spec })
            .await
        {
            Ok(c) if c.ok => ops.end(op, true, None),
            Ok(c) => return Err((step_fail(ops, describe(&c)), true)),
            Err(e) => return Err((step_fail(ops, format!("{e:#}")), true)),
        }
    }

    let [first, second] = req.acceptor_first();
    // The dialing side's pin stays what it is when the listening side is not written.
    let pin_before = before
        .iter()
        .find(|(server, _)| server == second)
        .and_then(|(_, spec)| spec.tls_pin.clone());
    // Without a new token, the sides are asked what the new settings change: a side whose
    // file would come out the same is left alone, and an entry that differs only in its
    // forward rules takes them on a reload instead of a restart, so its users' connections
    // stay up. An agent older than the reload answers neither question, which reads as
    // "write it and restart", as before.
    let plan = if token.is_none() {
        plan_edit(hub, req, pin_before.as_deref()).await
    } else {
        EditPlan::default()
    };
    let mut pin = if plan.untouched(first) {
        pin_before
    } else {
        None
    };
    let mut changed: Vec<(&str, bool)> = Vec::new();
    for (i, server) in [first, second].into_iter().enumerate() {
        if plan.untouched(server) {
            continue;
        }
        let (entry_spec, exit_spec) = req.specs(token.as_deref(), pin.as_deref());
        let spec = if server == req.entry {
            entry_spec
        } else {
            exit_spec
        };
        let role = if server == req.entry { "entry" } else { "exit" };
        ops.run(op, &format!("write_{role}"));
        match put(hub, server, spec).await {
            Ok(p) => {
                if i == 0 {
                    pin = p;
                }
                changed.push((server, plan.reloads(req, server)));
                ops.end(op, true, None);
            }
            Err(e) => {
                let undone = restore(hub, &before, &changed, token.is_some()).await;
                return Err((step_fail(ops, e), undone));
            }
        }
    }
    for server in [first, second] {
        let role = if server == req.entry { "entry" } else { "exit" };
        if plan.untouched(server) {
            // Left as it was; brought up only when it is down (an edit leaves the tunnel
            // running, as it always has).
            if is_active(hub, server, &req.name).await {
                continue;
            }
        } else if plan.reloads(req, server) {
            ops.run(op, "reload_entry");
            match reload_entry(hub, server, &req.name).await {
                Ok(Reloaded::Applied(report)) => {
                    ops.end(op, true, Some(report.to_string()));
                    continue;
                }
                // The daemon will not (older than the reload, or not running): a restart
                // does it, as before.
                Ok(Reloaded::Refused(reason)) => {
                    tracing::info!(tunnel = %req.name, %reason, "the entry's daemon did not take the reload; restarting it");
                    ops.end(op, true, Some(reason));
                }
                Err(e) => {
                    let undone = restore(hub, &before, &changed, token.is_some()).await;
                    return Err((step_fail(ops, e), undone));
                }
            }
        }
        ops.run(op, &format!("start_{role}"));
        match run_again(hub, server, &req.name).await {
            Ok(()) => ops.end(op, true, None),
            Err(e) => {
                let undone = restore(hub, &before, &changed, token.is_some()).await;
                return Err((step_fail(ops, e), undone));
            }
        }
    }
    ops.run(op, "connect");
    match wait_connected(hub, req, hub.connect_wait).await {
        Ok(()) => {
            ops.end(op, true, None);
            Ok(())
        }
        Err(e) => {
            let undone = restore(hub, &before, &changed, token.is_some()).await;
            Err((step_fail(ops, e), undone))
        }
    }
}

/// Puts the earlier settings back on the sides that were written (`changed`: each with
/// whether it was to take them on a reload, which the way back uses too) and restarts the
/// rest. A new token cannot be put back (the panel never keeps tokens), so a failed
/// rotation is reported as not undone.
async fn restore(
    hub: &Hub,
    before: &[(String, Spec)],
    changed: &[(&str, bool)],
    rotated: bool,
) -> bool {
    let mut all = !rotated;
    for (server, spec) in before {
        let Some((_, by_reload)) = changed.iter().find(|(s, _)| *s == server.as_str()) else {
            continue;
        };
        all &= put(hub, server, spec.clone()).await.is_ok();
        all &= if *by_reload {
            reload_or_restart(hub, server, &spec.name).await.is_ok()
        } else {
            run_again(hub, server, &spec.name).await.is_ok()
        };
    }
    all
}

/// What an edit leaves alone and what it reloads, from what the two sides say the new
/// settings change ([`Request::TunnelDiff`]).
#[derive(Default)]
struct EditPlan {
    /// Sides whose file would come out the same: neither written nor restarted.
    same: Vec<String>,
    /// The entry differs only in its forward rules (or its limits): written, then told to
    /// read the file again instead of restarted.
    reload_entry: bool,
}

impl EditPlan {
    fn untouched(&self, server: &str) -> bool {
        self.same.iter().any(|s| s == server)
    }

    fn reloads(&self, req: &PairRequest, server: &str) -> bool {
        self.reload_entry && server == req.entry
    }
}

async fn plan_edit(hub: &Hub, req: &PairRequest, pin_before: Option<&str>) -> EditPlan {
    let mut plan = EditPlan::default();
    let (entry_spec, exit_spec) = req.specs(None, pin_before);
    for (server, spec) in [(&req.entry, entry_spec), (&req.exit, exit_spec)] {
        match hub
            .ask_as::<DiffReply>(server, &Request::TunnelDiff { spec })
            .await
        {
            Ok(d) if d.ok && d.same => plan.same.push(server.clone()),
            Ok(d) if d.ok && d.reloadable && server == &req.entry => plan.reload_entry = true,
            Ok(d) => tracing::debug!(
                server,
                error = ?d.error,
                "the edit writes this side and restarts it"
            ),
            Err(e) => tracing::debug!(
                server,
                error = %e,
                "the edit writes this side and restarts it"
            ),
        }
    }
    plan
}

/// Whether the tunnel's service runs on `server` right now (asked, not read from the last
/// snapshot). One that cannot be asked reads as running.
async fn is_active(hub: &Hub, server: &str, name: &str) -> bool {
    match hub
        .ask_as::<Vec<TunnelInfo>>(server, &Request::Tunnels)
        .await
    {
        Ok(tunnels) => tunnels
            .iter()
            .find(|t| t.name == name)
            .is_some_and(|t| t.active != Some(false)),
        Err(_) => true,
    }
}

/// How a reload was answered.
enum Reloaded {
    /// Applied: the daemon's report (what it added, removed and changed).
    Applied(kariz::control::ReloadReport),
    /// The daemon (or an agent older than the reload) will not, and says why. A restart
    /// does it instead.
    Refused(String),
}

/// Tells a written entry to apply its new forward rules. A rule whose port could not be
/// bound fails the step (the rest of the reload stands; the way back undoes it).
async fn reload_entry(hub: &Hub, server: &str, name: &str) -> Result<Reloaded, String> {
    let r: ReloadReply = hub
        .ask_as(
            server,
            &Request::TunnelReload {
                name: name.to_owned(),
            },
        )
        .await
        .map_err(|e| format!("{e:#}"))?;
    match (r.ok, r.report) {
        (true, Some(report)) if report.failed.is_empty() => Ok(Reloaded::Applied(report)),
        (true, Some(report)) => Err(report.to_string()),
        (true, None) => Err("the reload was not reported".into()),
        (false, _) => Ok(Reloaded::Refused(
            r.error.unwrap_or_else(|| "refused".into()),
        )),
    }
}

/// Reloads a written entry, or restarts it when its daemon will not.
async fn reload_or_restart(hub: &Hub, server: &str, name: &str) -> Result<(), String> {
    match reload_entry(hub, server, name).await? {
        Reloaded::Applied(_) => Ok(()),
        Reloaded::Refused(_) => run_again(hub, server, name).await,
    }
}

/// Runs a tunnel with the settings just written: enabled (a tunnel that was stopped, and so
/// disabled, comes back at boot again like a started one) and restarted (a running one takes
/// the new settings).
async fn run_again(hub: &Hub, server: &str, name: &str) -> Result<(), String> {
    ctl(hub, server, name, "enable").await?;
    ctl(hub, server, name, "restart").await
}

/// Starts, stops or restarts both sides, in the order that never leaves a dialer without
/// its acceptor.
pub fn control(hub: &Arc<Hub>, name: &str, action: &str) -> Result<String> {
    if !valid_name(name) {
        bail!("bad_name");
    }
    if !matches!(action, "start" | "stop" | "restart") {
        bail!("bad_action");
    }
    let id = hub.ops.begin("control", name)?;
    let hub = hub.clone();
    let (op, name, action) = (id.clone(), name.to_owned(), action.to_owned());
    tokio::spawn(async move {
        let error = run_control(&hub, &op, &name, &action).await.err();
        hub.ops.finish(&op, error, None);
    });
    Ok(id)
}

/// Waits for an operation to end, up to two minutes: `Ok` when it worked, else why.
pub async fn wait(hub: &Hub, op: &str) -> Result<(), String> {
    for _ in 0..240 {
        tokio::time::sleep(Duration::from_millis(500)).await;
        match hub.ops.get(op) {
            Some(o) if o.state == "running" => {}
            Some(o) => return o.error.map_or(Ok(()), Err),
            None => return Ok(()),
        }
    }
    Err("timeout".into())
}

/// The tunnel's servers, the accepting side first.
fn ordered(p: &Placement) -> Vec<(String, TunnelInfo)> {
    let mut sides = p.sides.clone();
    sides.sort_by_key(|(_, t)| {
        let accepts = matches!(
            (t.role.as_str(), t.mode.as_str()),
            ("entry", "reverse") | ("exit", "direct")
        );
        !accepts
    });
    sides
}

async fn run_control(hub: &Hub, op: &str, name: &str, action: &str) -> Result<(), String> {
    let ops = &hub.ops;
    ops.run(op, "look");
    let mut sides = match place(hub, name) {
        Ok(p) if !p.sides.is_empty() => ordered(&p),
        Ok(_) => {
            ops.end(op, false, Some("no_such_tunnel".into()));
            return Err("no_such_tunnel".into());
        }
        Err(e) => {
            ops.end(op, false, Some(format!("{e:#}")));
            return Err(format!("{e:#}"));
        }
    };
    ops.end(op, true, None);
    if action == "stop" {
        sides.reverse();
    }
    // A tunnel can be stopped (or started) from the side that is reachable.
    if sides.iter().all(|(s, _)| !hub.is_online(s)) {
        ops.run(op, "look");
        ops.end(op, false, Some("that server is not connected".into()));
        return Err("that server is not connected".into());
    }
    for (server, info) in sides {
        ops.run(op, &format!("{action}_{}", info.role));
        if !hub.is_online(&server) {
            ops.end(op, true, Some("offline".into()));
            ops.left_out(op, &server);
            continue;
        }
        match ctl(hub, &server, name, action).await {
            Ok(()) => ops.end(op, true, None),
            Err(e) => {
                ops.end(op, false, Some(e.clone()));
                return Err(e);
            }
        }
    }
    Ok(())
}

/// Stops and removes both sides.
pub fn delete(hub: &Arc<Hub>, name: &str) -> Result<String> {
    if !valid_name(name) {
        bail!("bad_name");
    }
    let id = hub.ops.begin("delete", name)?;
    let hub = hub.clone();
    let (op, name) = (id.clone(), name.to_owned());
    tokio::spawn(async move {
        let error = run_delete(&hub, &op, &name).await.err();
        hub.ops.finish(&op, error, None);
    });
    Ok(id)
}

async fn run_delete(hub: &Hub, op: &str, name: &str) -> Result<(), String> {
    let ops = &hub.ops;
    ops.run(op, "look");
    let mut sides = match place(hub, name) {
        Ok(p) if !p.sides.is_empty() => ordered(&p),
        Ok(_) => {
            ops.end(op, false, Some("no_such_tunnel".into()));
            return Err("no_such_tunnel".into());
        }
        Err(e) => {
            ops.end(op, false, Some(format!("{e:#}")));
            return Err(format!("{e:#}"));
        }
    };
    ops.end(op, true, None);
    // The dialing side goes first, so it does not retry against a closed acceptor.
    sides.reverse();
    let mut failed = None;
    for (server, info) in sides {
        ops.run(op, &format!("delete_{}", info.role));
        // A server that is away cannot be asked. The delete is kept for it (its agent does
        // it when it connects again) and the tunnel is gone from the lists now.
        if !hub.is_online(&server) {
            match hub.queue_delete(&server, name) {
                Ok(()) => {
                    ops.end(op, true, Some("queued".into()));
                    ops.left_out(op, &server);
                }
                Err(e) => {
                    ops.end(op, false, Some(format!("{e:#}")));
                    failed = Some(format!("{e:#}"));
                }
            }
            continue;
        }
        match remove(hub, &server, name).await {
            Ok(()) => ops.end(op, true, None),
            Err(e) => {
                ops.end(op, false, Some(e.clone()));
                failed = Some(e);
            }
        }
    }
    // A tunnel that is gone needs no automatic restart, no traffic limit, and no copy.
    if failed.is_none() {
        let _ = hub.db.conn().execute(
            "DELETE FROM schedules WHERE kind = 'tunnel' AND subject = ?1",
            [name],
        );
        crate::quota::forget(&hub.db, name);
        let _ = crate::specs::forget(&hub.db, name);
        let _ = crate::manual::clear(&hub.db, name);
    }
    failed.map_or(Ok(()), Err)
}

/// One line of a tunnel's log, from one of its sides.
#[derive(Debug, Clone, Serialize)]
pub struct LogLine {
    pub server: String,
    pub role: String,
    pub text: String,
}

/// The last `lines` lines of a tunnel's log from both sides, in time order (the journal's
/// lines start with an ISO time, which sorts as text).
pub async fn logs(hub: &Hub, name: &str, lines: u32) -> Result<Vec<LogLine>> {
    if !valid_name(name) {
        bail!("bad_name");
    }
    let placement = place(hub, name)?;
    if placement.sides.is_empty() {
        bail!("no_such_tunnel");
    }
    let mut all: Vec<LogLine> = Vec::new();
    for (server, info) in placement.sides {
        let reply: TextReply = match hub
            .ask_as(
                &server,
                &Request::Logs {
                    name: name.to_owned(),
                    lines,
                },
            )
            .await
        {
            Ok(r) => r,
            Err(_) => continue,
        };
        all.extend(
            reply
                .text
                .lines()
                .filter(|l| !l.trim().is_empty() && !l.starts_with("-- "))
                .map(|l| LogLine {
                    server: server.clone(),
                    role: info.role.clone(),
                    text: l.to_owned(),
                }),
        );
    }
    all.sort_by(|a, b| a.text.cmp(&b.text));
    let skip = all.len().saturating_sub(lines as usize);
    Ok(all.split_off(skip))
}

/// Runs the speed test of a tunnel on its entry side and returns what it printed.
/// Gets a Let's Encrypt certificate for `host` on `server` (for a wss tunnel that listens
/// there). It can take a minute: certbot is installed first if the server has none.
pub async fn certificate(
    hub: &Hub,
    server: &str,
    host: &str,
    email: Option<&str>,
) -> Result<crate::wire::CertReply> {
    let raw = hub
        .ask_within(
            server,
            &Request::TunnelCert {
                domain: host.to_owned(),
                email: email.map(str::to_owned),
            },
            Duration::from_secs(660),
        )
        .await?;
    serde_json::from_slice(&raw)
        .map_err(|_| anyhow::anyhow!("the server's answer was not understood (an older agent cannot get certificates: update it)"))
}

/// The server that runs a tunnel's speed test: the one with its entry side.
fn speedtest_server(hub: &Hub, name: &str) -> Result<String> {
    if !valid_name(name) {
        bail!("bad_name");
    }
    let placement = place(hub, name)?;
    let (server, info) = placement
        .sides
        .into_iter()
        .find(|(_, t)| t.role == "entry")
        .ok_or_else(|| anyhow::anyhow!("no_such_tunnel"))?;
    // The l3 / GRE tunnel is a raw packet pump with no mux stream path, so the channel speed
    // test (which opens mux streams through the tunnel) cannot run on it; the UI points at
    // measuring over the kzN interface instead.
    if info.transport == "l3" {
        bail!("l3_no_speedtest");
    }
    Ok(server)
}

/// Starts a speed test that can be followed while it runs; its id comes back.
pub async fn speedtest_start(
    hub: &Hub,
    name: &str,
    seconds: u32,
    streams: u32,
    udp: bool,
) -> Result<crate::wire::SpeedStarted> {
    let server = speedtest_server(hub, name)?;
    let raw = hub
        .ask(
            &server,
            &Request::SpeedtestStart {
                name: name.to_owned(),
                seconds,
                streams,
                udp,
            },
        )
        .await?;
    serde_json::from_slice(&raw)
        .map_err(|_| anyhow::anyhow!("the server's answer was not understood"))
}

/// Stops a started speed test.
pub async fn speedtest_stop(hub: &Hub, name: &str, id: &str) -> Result<()> {
    let server = speedtest_server(hub, name)?;
    let raw = hub
        .ask(&server, &Request::SpeedtestStop { id: id.to_owned() })
        .await?;
    let ack: Ack = serde_json::from_slice(&raw)
        .map_err(|_| anyhow::anyhow!("the server's answer was not understood"))?;
    if ack.ok {
        Ok(())
    } else {
        bail!(ack.error.unwrap_or_else(|| "failed".into()))
    }
}

/// What a started speed test has said since `after` lines.
pub async fn speedtest_poll(
    hub: &Hub,
    name: &str,
    id: &str,
    after: u32,
) -> Result<crate::wire::SpeedPoll> {
    let server = speedtest_server(hub, name)?;
    let raw = hub
        .ask(
            &server,
            &Request::SpeedtestPoll {
                id: id.to_owned(),
                after,
            },
        )
        .await?;
    serde_json::from_slice(&raw)
        .map_err(|_| anyhow::anyhow!("the server's answer was not understood"))
}

pub async fn speedtest(
    hub: &Hub,
    name: &str,
    seconds: u32,
    streams: u32,
    udp: bool,
) -> Result<SpeedReply> {
    if !valid_name(name) {
        bail!("bad_name");
    }
    let placement = place(hub, name)?;
    let Some((server, info)) = placement.sides.iter().find(|(_, t)| t.role == "entry") else {
        bail!("no_such_tunnel");
    };
    // No mux stream path on the l3 / GRE tunnel, so the channel speed test cannot run on it.
    if info.transport == "l3" {
        bail!("l3_no_speedtest");
    }
    let seconds = seconds.clamp(1, 60);
    let limit = Duration::from_secs(u64::from(seconds) * 3 + 50);
    let raw = hub
        .ask_within(
            server,
            &Request::Speedtest {
                name: name.to_owned(),
                seconds,
                streams,
                udp,
            },
            limit,
        )
        .await?;
    serde_json::from_slice(&raw)
        .map_err(|_| anyhow::anyhow!("the server's answer was not understood"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_are_compared_by_their_numbers() {
        let min = (1, 5, 0);
        assert!(version_at_least("1.5.0", min) && version_at_least("v1.10.2", min));
        assert!(version_at_least("2.0.0-rc1", min) && version_at_least("1.5.0-dev", min));
        assert!(!version_at_least("1.4.0", min) && !version_at_least("1.4.99", min));
        assert!(!version_at_least("", min) && !version_at_least("unknown", min));
    }

    /// The specs of a request's two sides give the request back.
    #[test]
    fn a_request_comes_back_from_the_specs_of_its_two_sides() {
        let mut req = PairRequest {
            name: "t".into(),
            entry: "a".into(),
            exit: "b".into(),
            mode: "reverse".into(),
            transport: "tcpmux".into(),
            profile: Some("throughput".into()),
            listen: "0.0.0.0:3080".into(),
            dial: "198.51.100.7:3080".into(),
            mux: Some(crate::wire::MuxSpec {
                connections: Some(4),
                ..Default::default()
            }),
            encryption: Some("chacha20-poly1305".into()),
            max_conns_per_ip: Some(20),
            udp_max_flows: Some(500),
            proxy_protocol: Some("v2".into()),
            forwards: vec![
                ForwardInfo {
                    listen: "0.0.0.0:443".into(),
                    target: "127.0.0.1:443".into(),
                    protocol: "tcp".into(),
                },
                ForwardInfo {
                    listen: "0.0.0.0:53".into(),
                    target: "127.0.0.1:53".into(),
                    protocol: "udp".into(),
                },
            ],
            ..Default::default()
        };
        for (mode, transport) in [("reverse", "tcpmux"), ("direct", "kcp"), ("direct", "wss")] {
            req.mode = mode.into();
            req.transport = transport.into();
            req.tls_sni = (transport == "wss").then(|| "www.example.com".to_owned());
            let (entry, exit) = req.specs(None, Some("pin"));
            let back = PairRequest::from_specs("t", "a", "b", &entry, &exit)
                .unwrap_or_else(|| panic!("{mode} {transport}"));
            let (entry_again, exit_again) = back.specs(None, Some("pin"));
            assert_eq!(entry, entry_again, "{mode} {transport}");
            assert_eq!(exit, exit_again, "{mode} {transport}");
            assert_eq!(back.max_conns_per_ip, Some(20));
            assert_eq!(back.forwards.len(), 2);
        }
        // A real certificate on the listening side: its files and the name it was issued for.
        req.mode = "direct".into();
        req.transport = "wss".into();
        req.tls_sni = None;
        req.tls_cert = Some("/etc/kariz/t.crt".into());
        req.tls_key = Some("/etc/kariz/t.key".into());
        req.tls_host = Some("tunnel.example.com".into());
        let (entry, exit) = req.specs(None, None);
        let back = PairRequest::from_specs("t", "a", "b", &entry, &exit).unwrap();
        assert_eq!(back.tls_host.as_deref(), Some("tunnel.example.com"));
        assert_eq!(back.specs(None, None), (entry, exit));
        // Not a pair.
        let (entry, _) = req.specs(None, None);
        let (_, other) = {
            let mut r = req.clone();
            r.transport = "kcp".into();
            r.specs(None, None)
        };
        assert!(PairRequest::from_specs("t", "a", "b", &entry, &other).is_none());
    }

    #[test]
    fn spoof_gives_each_server_its_own_forged_list() {
        let req = PairRequest {
            name: "t".into(),
            entry: "a".into(),
            exit: "b".into(),
            mode: "direct".into(),
            transport: "spoof".into(),
            listen: "0.0.0.0:3080".into(),
            dial: "1.2.3.4:3080".into(),
            spoof: Some(crate::wire::SpoofSpec {
                shape: Some("udp".into()),
                entry_pool: vec!["203.0.113.1".into(), "203.0.113.2".into()],
                exit_pool: vec!["198.51.100.9".into()],
                manage_firewall: Some(true),
                ..Default::default()
            }),
            forwards: Vec::new(),
            ..Default::default()
        };
        // Two non-empty lists are accepted.
        assert!(req.validate().is_ok());

        let (entry, exit) = req.specs(Some("tok"), None);
        let es = entry.spoof.expect("entry spoof");
        let xs = exit.spoof.expect("exit spoof");
        // Each side forges from its OWN list, and neither carries the other's.
        assert_eq!(
            es.pool,
            vec!["203.0.113.1".to_string(), "203.0.113.2".to_string()]
        );
        assert_eq!(xs.pool, vec!["198.51.100.9".to_string()]);
        // The split lists are wizard-only and never reach a resolved per-side spec.
        assert!(es.entry_pool.is_empty() && es.exit_pool.is_empty());
        assert!(xs.entry_pool.is_empty() && xs.exit_pool.is_empty());

        // Leaving either server's list empty is refused: the two never share a pool.
        let mut bad = req.clone();
        bad.spoof.as_mut().unwrap().exit_pool.clear();
        assert_eq!(
            bad.validate().unwrap_err().to_string(),
            "spoof_pool_required"
        );
    }

    #[test]
    fn a_cipher_must_be_one_the_core_knows_and_not_on_quic() {
        let req = |transport: &str, enc: Option<&str>| PairRequest {
            name: "t".into(),
            entry: "a".into(),
            exit: "b".into(),
            mode: "reverse".into(),
            transport: transport.into(),
            profile: None,
            listen: "0.0.0.0:3080".into(),
            dial: "1.2.3.4:3080".into(),
            pool: None,
            ws_path: None,
            ws_host: None,
            tls_sni: None,
            mux: None,
            tls_cert: None,
            tls_key: None,
            tls_host: None,
            encryption: enc.map(str::to_owned),
            quic_obfs: false,
            max_conns_per_ip: None,
            udp_max_flows: None,
            proxy_protocol: None,
            forwards: Vec::new(),
            rotate: false,
            network: None,
            ..Default::default()
        };
        for ok in ["auto", "aes-256-gcm", "chacha20-poly1305", "none"] {
            assert!(req("tcpmux", Some(ok)).validate().is_ok(), "{ok}");
        }
        assert!(req("tcpmux", None).validate().is_ok());
        assert_eq!(
            req("tcpmux", Some("rot13"))
                .validate()
                .unwrap_err()
                .to_string(),
            "bad_encryption"
        );
        // QUIC has no cipher of its own to choose, and auto is always fine.
        assert_eq!(
            req("quic", Some("none"))
                .validate()
                .unwrap_err()
                .to_string(),
            "encryption_quic"
        );
        assert!(req("quic", Some("auto")).validate().is_ok());
        // `auto` is not written: the side stays on the default.
        assert_eq!(
            req("tcpmux", Some("auto")).specs(None, None).0.encryption,
            None
        );
        assert_eq!(
            req("tcpmux", Some("none"))
                .specs(None, None)
                .1
                .encryption
                .as_deref(),
            Some("none")
        );
    }

    #[test]
    fn sealed_quic_is_for_quic_only_and_needs_a_new_agent() {
        let req = |transport: &str, obfs: bool| PairRequest {
            name: "t".into(),
            entry: "a".into(),
            exit: "b".into(),
            mode: "reverse".into(),
            transport: transport.into(),
            profile: None,
            listen: "0.0.0.0:3080".into(),
            dial: "1.2.3.4:3080".into(),
            pool: None,
            ws_path: None,
            ws_host: None,
            tls_sni: None,
            mux: None,
            encryption: None,
            quic_obfs: obfs,
            max_conns_per_ip: None,
            udp_max_flows: None,
            proxy_protocol: None,
            tls_cert: None,
            tls_key: None,
            tls_host: None,
            forwards: Vec::new(),
            rotate: false,
            network: None,
            ..Default::default()
        };
        // Both sides get it over quic, and nobody over another transport.
        let (entry, exit) = req("quic", true).specs(None, None);
        assert!(entry.quic_obfs && exit.quic_obfs);
        let (entry, exit) = req("tcpmux", true).specs(None, None);
        assert!(!entry.quic_obfs && !exit.quic_obfs);
        let (entry, _) = req("quic", false).specs(None, None);
        assert!(!entry.quic_obfs);
        assert!(req("quic", true).validate().is_ok());
        // Before 1.7 an agent does not know the field, and 1.7 and later do.
        assert!(!version_at_least("1.6.0", (1, 7, 0)));
        assert!(version_at_least("1.7.0", (1, 7, 0)));
        assert!(version_at_least("v1.8.2", (1, 7, 0)));
    }

    #[test]
    fn the_per_address_limit_goes_to_the_entry_side_and_needs_2_4() {
        let req = |limit: Option<u32>, max_streams: Option<u32>| PairRequest {
            name: "t".into(),
            entry: "a".into(),
            exit: "b".into(),
            mode: "reverse".into(),
            transport: "tcpmux".into(),
            profile: None,
            listen: "0.0.0.0:3080".into(),
            dial: "1.2.3.4:3080".into(),
            pool: None,
            ws_path: None,
            ws_host: None,
            tls_sni: None,
            mux: max_streams.map(|v| crate::wire::MuxSpec {
                max_streams: Some(v),
                ..Default::default()
            }),
            encryption: None,
            quic_obfs: false,
            max_conns_per_ip: limit,
            udp_max_flows: None,
            proxy_protocol: None,
            tls_cert: None,
            tls_key: None,
            tls_host: None,
            forwards: Vec::new(),
            rotate: false,
            network: None,
            ..Default::default()
        };
        let (entry, exit) = req(Some(300), None).specs(None, None);
        assert_eq!(
            (entry.max_conns_per_ip, exit.max_conns_per_ip),
            (Some(300), None)
        );
        // 0 is no limit: nothing is written, and nothing new is needed.
        let (entry, _) = req(Some(0), None).specs(None, None);
        assert_eq!(entry.max_conns_per_ip, None);
        assert_eq!(req(Some(0), None).needs_2_4(), (false, false));
        // Which side must run 2.4: the entry for the limit, both for many streams.
        assert_eq!(req(Some(300), None).needs_2_4(), (true, false));
        assert_eq!(req(None, Some(4096)).needs_2_4(), (false, false));
        assert_eq!(req(None, Some(8192)).needs_2_4(), (true, true));
        // A beta of 2.4 is 2.4.
        assert!(version_at_least("2.4.0-beta.1", (2, 4, 0)));
        assert!(!version_at_least("2.3.0", (2, 4, 0)));
    }

    #[test]
    fn the_udp_flow_limit_goes_to_the_entry_side_and_needs_the_release_that_writes_it() {
        let req = |flows: Option<u32>| PairRequest {
            name: "t".into(),
            entry: "a".into(),
            exit: "b".into(),
            mode: "reverse".into(),
            transport: "wss".into(),
            profile: None,
            listen: "0.0.0.0:3080".into(),
            dial: "1.2.3.4:3080".into(),
            pool: None,
            ws_path: None,
            ws_host: None,
            tls_sni: None,
            mux: None,
            encryption: None,
            quic_obfs: false,
            max_conns_per_ip: None,
            udp_max_flows: flows,
            proxy_protocol: None,
            tls_cert: None,
            tls_key: None,
            tls_host: None,
            forwards: Vec::new(),
            rotate: false,
            network: None,
            ..Default::default()
        };
        let (entry, exit) = req(Some(8192)).specs(None, None);
        assert_eq!(
            (entry.udp_max_flows, exit.udp_max_flows),
            (Some(8192), None)
        );
        // Left out or 0: nothing is written, and any version will do.
        for none in [None, Some(0)] {
            let (entry, _) = req(none).specs(None, None);
            assert_eq!(entry.udp_max_flows, None);
            assert!(req(none).require_version("a", "2.3.0").is_ok());
        }
        // The entry side must know the field: 2.6.0-beta.3 does not, beta.4 and 2.6.0 do.
        let why = |v: &str| {
            req(Some(4096))
                .require_version("a", v)
                .err()
                .map(|e| e.to_string())
        };
        assert_eq!(
            why("2.6.0-beta.3").as_deref(),
            Some("old_agent_udp:a:2.6.0-beta.3")
        );
        assert_eq!(why("2.5.1").as_deref(), Some("old_agent_udp:a:2.5.1"));
        assert_eq!(why("nonsense").as_deref(), Some("old_agent_udp:a:nonsense"));
        for ok in ["2.6.0-beta.4", "2.6.0-beta.10", "2.6.0", "2.7.1"] {
            assert_eq!(why(ok), None, "{ok}");
        }
        // The exit side writes nothing of it: an old one is fine.
        assert!(req(Some(4096)).require_version("b", "2.5.1").is_ok());
        // The core takes 1 to 65536.
        assert!(req(Some(65536)).validate().is_ok());
        assert_eq!(
            req(Some(70000)).validate().unwrap_err().to_string(),
            "bad_udp_flows"
        );
    }

    #[test]
    fn the_proxy_header_goes_to_the_entry_side_and_needs_2_5_on_both() {
        let req = |proxy: Option<&str>| PairRequest {
            name: "t".into(),
            entry: "a".into(),
            exit: "b".into(),
            mode: "reverse".into(),
            transport: "tcpmux".into(),
            profile: None,
            listen: "0.0.0.0:3080".into(),
            dial: "1.2.3.4:3080".into(),
            pool: None,
            ws_path: None,
            ws_host: None,
            tls_sni: None,
            mux: None,
            encryption: None,
            quic_obfs: false,
            max_conns_per_ip: None,
            udp_max_flows: None,
            proxy_protocol: proxy.map(str::to_owned),
            tls_cert: None,
            tls_key: None,
            tls_host: None,
            forwards: Vec::new(),
            rotate: false,
            network: None,
            ..Default::default()
        };
        let (entry, exit) = req(Some("v1")).specs(None, None);
        assert_eq!(
            (entry.proxy_protocol.as_deref(), exit.proxy_protocol),
            (Some("v1"), None)
        );
        // `off`, or left out: nothing is written, and any version will do.
        for off in [None, Some("off")] {
            let (entry, _) = req(off).specs(None, None);
            assert_eq!(entry.proxy_protocol, None);
            for server in ["a", "b"] {
                assert!(req(off).require_version(server, "2.3.0").is_ok());
            }
        }
        // Both sides must run 2.5: a beta of 2.4 does not know it.
        for server in ["a", "b"] {
            for old in ["2.4.0", "2.4.0-beta.1", "1.9.5"] {
                let err = req(Some("v2")).require_version(server, old).unwrap_err();
                assert_eq!(err.to_string(), format!("old_agent_proxy:{server}:{old}"));
            }
            for new in ["2.5.0", "2.5.0-beta.1", "v3.0.0"] {
                assert!(
                    req(Some("v2")).require_version(server, new).is_ok(),
                    "{new}"
                );
            }
        }
        assert!(req(Some("v2")).validate().is_ok());
        assert_eq!(
            req(Some("v3")).validate().unwrap_err().to_string(),
            "bad_proxy_protocol"
        );
    }

    #[test]
    fn auto_and_mux_settings_need_new_servers() {
        let req = |transport: &str, mux: Option<crate::wire::MuxSpec>| PairRequest {
            name: "t".into(),
            entry: "a".into(),
            exit: "b".into(),
            mode: "reverse".into(),
            transport: transport.into(),
            profile: None,
            listen: "0.0.0.0:3080".into(),
            dial: "1.2.3.4:3080".into(),
            pool: None,
            ws_path: None,
            ws_host: None,
            tls_sni: None,
            mux,
            quic_obfs: false,
            max_conns_per_ip: None,
            udp_max_flows: None,
            proxy_protocol: None,
            tls_cert: None,
            tls_key: None,
            tls_host: None,
            encryption: None,
            forwards: Vec::new(),
            rotate: false,
            network: None,
            ..Default::default()
        };
        assert!(req("auto", None).needs_new_servers());
        let tuned = crate::wire::MuxSpec {
            connections: Some(4),
            ..Default::default()
        };
        assert!(req("tcpmux", Some(tuned)).needs_new_servers());
        assert!(!req("tcpmux", Some(Default::default())).needs_new_servers());
        assert!(!req("kcp", None).needs_new_servers());
    }

    /// The `BadCertificate` of a wss tunnel with a Let's Encrypt certificate: the dialing
    /// side checked it against another name than the one it was issued for.
    #[test]
    fn a_real_certificate_is_checked_against_the_name_it_was_issued_for() {
        let req = |sni: Option<&str>, ws_host: Option<&str>, real: bool| PairRequest {
            name: "t".into(),
            entry: "a".into(),
            exit: "b".into(),
            mode: "reverse".into(),
            transport: "wss".into(),
            profile: None,
            listen: "0.0.0.0:3080".into(),
            // A private (GRE) address, or another address of the server.
            dial: "10.77.0.2:3080".into(),
            pool: None,
            ws_path: Some("/".into()),
            ws_host: ws_host.map(str::to_owned),
            tls_sni: sni.map(str::to_owned),
            mux: None,
            encryption: None,
            quic_obfs: false,
            max_conns_per_ip: None,
            udp_max_flows: None,
            proxy_protocol: None,
            tls_cert: real
                .then(|| "/etc/letsencrypt/live/kariz-panel-t-example-com/fullchain.pem".into()),
            tls_key: real
                .then(|| "/etc/letsencrypt/live/kariz-panel-t-example-com/privkey.pem".into()),
            tls_host: real.then(|| "T.example.com".into()),
            forwards: Vec::new(),
            rotate: false,
            network: None,
            ..Default::default()
        };
        // Reverse: the entry listens, the exit dials.
        let dialer = |r: PairRequest| r.specs(None, None).1;
        for (sni, host) in [
            (None, None),
            (Some("www.google.com"), None),
            (None, Some("cdn.example.net")),
        ] {
            let d = dialer(req(sni, host, true));
            assert_eq!(
                d.tls_sni.as_deref(),
                Some("t.example.com"),
                "{sni:?} {host:?}"
            );
            assert_eq!(d.tls_pin, None, "a real certificate is not pinned");
        }
        // Self-signed: the name typed (if any) is what it sends, and the pin is what counts.
        assert_eq!(
            dialer(req(Some("www.google.com"), None, false))
                .tls_sni
                .as_deref(),
            Some("www.google.com")
        );
        assert_eq!(dialer(req(None, None, false)).tls_sni, None);
        // The listening side never gets a server name.
        assert_eq!(req(None, None, true).specs(None, None).0.tls_sni, None);
        // The name must be one a certificate can be for.
        let mut bad = req(None, None, true);
        bad.tls_host = Some("not a host".into());
        assert_eq!(bad.validate().unwrap_err().to_string(), "bad_tls_host");
        assert!(req(None, None, true).validate().is_ok());
    }

    /// A minimal request for one of the 2.7 transports.
    fn req_transport(transport: &str) -> PairRequest {
        PairRequest {
            name: "t".into(),
            entry: "a".into(),
            exit: "b".into(),
            mode: "reverse".into(),
            transport: transport.into(),
            listen: "0.0.0.0:3080".into(),
            dial: "1.2.3.4:3080".into(),
            ..Default::default()
        }
    }

    #[test]
    fn the_new_transports_need_a_2_7_agent_on_both_sides() {
        for t in [
            "stealth", "wsmux", "wssmux", "udp", "faketcp", "icmp", "naive", "xhttp", "reality",
            "l3",
        ] {
            for server in ["a", "b"] {
                // A beta of 2.7.0 is before the release that ships the full set.
                for old in ["2.6.1", "2.6.0-beta.4", "2.5.0", "1.9.0", "2.7.0-beta.1"] {
                    let err = req_transport(t).require_version(server, old).unwrap_err();
                    assert_eq!(
                        err.to_string(),
                        format!("old_agent_transport:{server}:{old}"),
                        "{t} on {old}"
                    );
                }
                for new in ["2.7.0", "2.7.1", "v3.0.0"] {
                    assert!(
                        req_transport(t).require_version(server, new).is_ok(),
                        "{t} on {new}"
                    );
                }
            }
        }
        // The old transports still need nothing new.
        for t in ["tcp", "ws", "wss", "kcp"] {
            assert!(
                req_transport(t).require_version("a", "2.5.0").is_ok(),
                "{t}"
            );
        }
    }

    #[test]
    fn an_l3_tunnel_auto_picks_the_two_ends_of_a_30() {
        let mut r = req_transport("l3");
        r.l3_carrier = Some("quic".into());
        r.l3_net = Some(7);
        let (entry, exit) = r.specs(None, None);
        // The accepting side (entry in reverse) is `.1`; the dialing side is `.2`.
        let e = entry.l3.unwrap();
        let x = exit.l3.unwrap();
        assert_eq!(e.local_ip.as_deref(), Some("10.10.7.1/30"));
        assert_eq!(e.peer_ip.as_deref(), Some("10.10.7.2"));
        assert_eq!(x.local_ip.as_deref(), Some("10.10.7.2/30"));
        assert_eq!(x.peer_ip.as_deref(), Some("10.10.7.1"));
        assert_eq!(e.carrier, "quic");
        // Layer 2 (TAP) carries no address.
        r.l3_layer = Some(2);
        let (entry2, _) = r.specs(None, None);
        let e2 = entry2.l3.unwrap();
        assert!(e2.local_ip.is_none() && e2.peer_ip.is_none());
    }

    #[test]
    fn a_managed_helper_splits_server_and_client_secrets() {
        let mut r = req_transport("reality");
        r.helper = Some(crate::wire::HelperSpec {
            uuid: Some("123e4567-e89b-12d3-a456-426614174000".into()),
            server_name: Some("example.com".into()),
            private_key: Some("priv".into()),
            public_key: Some("pub".into()),
            target: Some("example.com:443".into()),
            ..Default::default()
        });
        let (entry, exit) = r.specs(None, None);
        // entry accepts in reverse mode: it keeps the server secret and cover target.
        let acc = entry.helper.unwrap();
        assert_eq!(acc.private_key.as_deref(), Some("priv"));
        assert_eq!(acc.target.as_deref(), Some("example.com:443"));
        assert!(acc.public_key.is_none(), "the server keeps no client key");
        // exit dials: it keeps only the public key.
        let dial = exit.helper.unwrap();
        assert_eq!(dial.public_key.as_deref(), Some("pub"));
        assert!(dial.private_key.is_none(), "the client keeps no server key");
        // The shared identity reaches both.
        assert_eq!(acc.uuid, dial.uuid);
    }

    #[test]
    fn l3_and_mandatory_encryption_are_validated() {
        let mut r = req_transport("l3");
        r.l3_carrier = Some("tcp".into());
        assert_eq!(r.validate().unwrap_err().to_string(), "bad_l3_carrier");
        r.l3_carrier = Some("udp".into());
        assert!(r.validate().is_ok());
        r.l3_layer = Some(4);
        assert_eq!(r.validate().unwrap_err().to_string(), "bad_l3_layer");
        // The sealing-less transports refuse `encryption = "none"`.
        for t in ["udp", "faketcp", "icmp", "stealth", "l3"] {
            let mut r = req_transport(t);
            if t == "l3" {
                r.l3_carrier = Some("udp".into());
            }
            r.encryption = Some("none".into());
            assert_eq!(
                r.validate().unwrap_err().to_string(),
                "encryption_required",
                "{t}"
            );
        }
        // A cipher or auto is fine.
        let mut r = req_transport("stealth");
        r.encryption = Some("chacha20-poly1305".into());
        assert!(r.validate().is_ok());
    }
}
