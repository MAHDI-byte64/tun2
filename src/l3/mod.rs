//! The layer-3 / GRE direct tunnel (`[l3]`): a TUN or TAP interface on each host carrying
//! whole IP packets (`layer = 3`) or Ethernet frames (`layer = 2`, an encrypted GRETAP)
//! between two peers.
//!
//! The packets are GRE-encapsulated ([`gre`], RFC 2784 + RFC 2890 key), sealed inside the
//! tunnel's own authenticated, encrypted session ([`session`], reusing `crate::crypto` /
//! `crate::channel`), and handed to an unreliable carrier (udp / quic / faketcp / icmp).
//! There is no bare IP protocol 47 on the wire. TCP SYNs leaving a layer-3 interface have
//! their MSS clamped ([`mss`]).
//!
//! Both directions: `mode = "listen"` waits for the inbound connection (the acceptor side),
//! `mode = "dial"` reaches out, and either host may dial — the user's "direct and reverse"
//! requirement. The interface is created once at start and removed on stop (RAII, when the
//! device fd closes); the session reconnects underneath it, which also rekeys.

pub mod forward;
pub mod gre;
pub mod mss;
pub mod session;
pub mod tun;

use std::io;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::time::{sleep, timeout};
use tracing::{info, warn};

use crate::config::{Config, L3Carrier, L3Config, L3Mode, TransportKind};
use crate::crypto::Crypto;
use crate::stats::{Peer, Stats};
use crate::transport::Settings;

use session::{L3Dialer, L3Listener, L3Params, L3Session};
use tun::{DeviceConfig, Layer, TunDevice};

/// A packet buffer big enough for any interface read (MTU plus Ethernet framing, rounded up).
const PACKET_BUFFER: usize = 65_536;
/// A re-handshake is forced this often, giving the session fresh keys (a hard rekey: the
/// carrier reconnects, so a few packets may be lost, which an IP tunnel tolerates).
const REKEY_INTERVAL: Duration = Duration::from_secs(15 * 60);
/// The largest interface MTU used over the `quic` carrier: a QUIC DATAGRAM frame starts
/// near 1200 bytes, and the GRE header plus the datagram's own framing take their cut, so a
/// bigger interface would drop full-size packets. Conservative, since auto-MTU is deferred.
const QUIC_SAFE_MTU: u16 = 1150;
/// After a dial failure, wait this long before trying again.
const DIAL_BACKOFF: Duration = Duration::from_secs(3);

/// The resolved parameters of one l3 tunnel end.
pub struct L3Runner {
    mode: L3Mode,
    addr: String,
    layer: Layer,
    iface: Option<String>,
    local_ip: Option<String>,
    peer_ip: Option<String>,
    mtu: u16,
    gre_key: u32,
    carrier: L3Carrier,
    params: L3Params,
    ports: Vec<crate::config::Forward>,
    accept_udp: bool,
}

impl L3Runner {
    /// Builds a runner from a validated config (`config.l3` is `Some`).
    pub fn from_config(config: &Config) -> io::Result<Self> {
        let l3: &L3Config = config
            .l3
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no [l3] section"))?;
        let token = l3
            .token
            .clone()
            .unwrap_or_else(|| config.tunnel.token.clone());
        let params = build_params(l3, &token, config)?;
        Ok(Self {
            mode: l3.mode,
            addr: l3.addr.clone(),
            layer: Layer::from_config(l3.layer),
            iface: l3.iface.clone(),
            local_ip: l3.local_ip.clone(),
            peer_ip: l3.peer_ip.clone(),
            mtu: l3.mtu,
            gre_key: l3.gre_key,
            carrier: l3.carrier,
            params,
            ports: l3.ports.clone(),
            accept_udp: l3.accept_udp,
        })
    }

    /// Runs the tunnel until a fatal error. `stats` is the shared status the control socket
    /// serves: the session coming up or failing is recorded on `stats.peer`, so `kariz
    /// status` and the panel's "waiting for both sides" see this end connect.
    pub async fn run(self, stats: Arc<Stats>) -> io::Result<()> {
        tun::host_supports_l3()?;
        stats.set_active_transport(Some(self.carrier.name()));
        info!(
            mode = self.mode.name(),
            carrier = self.carrier.name(),
            layer = self.layer.name(),
            local_ip = self.local_ip.as_deref().unwrap_or("-"),
            peer_ip = self.peer_ip.as_deref().unwrap_or("-"),
            mtu = self.mtu,
            "l3 / GRE direct tunnel"
        );

        // A QUIC DATAGRAM frame carries only what the connection's packet size allows,
        // which starts near 1200 bytes; a 1400-byte interface would have its full-size
        // packets silently dropped (auto-MTU probing is deferred — see the unit report), so
        // the effective MTU is capped to a QUIC-safe value here. The other carriers use the
        // configured MTU as is.
        let mtu = match self.carrier {
            L3Carrier::Quic => self.mtu.min(QUIC_SAFE_MTU),
            _ => self.mtu,
        };
        if mtu != self.mtu {
            info!(
                configured = self.mtu,
                effective = mtu,
                "l3 MTU lowered for the quic carrier"
            );
        }

        // The interface is created once and lives for the whole run; the session beneath it
        // reconnects without disturbing it.
        let device = TunDevice::create(&DeviceConfig {
            iface: self.iface.as_deref(),
            layer: self.layer,
            local_ip: self.local_ip.as_deref(),
            mtu,
        })?;
        info!(iface = device.name(), "l3 interface up");

        // MSS clamp: an IP concern, so layer 3, or a layer-2 TAP that carries an address.
        let _mss = (self.layer == Layer::Ip || self.local_ip.is_some())
            .then(|| mss::install(device.name(), mtu));

        // Optional port forwarding over the link (ordinary userspace forwarding to the peer).
        let _forwarders = if self.ports.is_empty() {
            None
        } else {
            Some(forward::start(&self.ports, self.accept_udp, self.peer_ip.as_deref()).await?)
        };

        let peer = stats.peer.clone();
        match self.mode {
            L3Mode::Dial => self.run_dial(&device, &peer).await,
            L3Mode::Listen => self.run_listen(&device, &peer).await,
        }
    }

    /// Dial side: keep a session up, reconnecting on failure and rekeying periodically.
    async fn run_dial(&self, device: &TunDevice, peer: &Arc<Peer>) -> io::Result<()> {
        let dialer = L3Dialer::new(&self.params, &self.addr)?;
        loop {
            match dialer.dial().await {
                Ok(session) => {
                    peer.link_up();
                    info!(peer = %self.addr, "l3 session established");
                    // The rekey timer ends the session so the next loop re-handshakes.
                    let _ = timeout(REKEY_INTERVAL, pump(device, &session, self.gre_key)).await;
                    info!("l3 session ended; re-handshaking");
                }
                Err(e) => {
                    peer.failed(&e);
                    warn!(peer = %self.addr, error = %e, "l3 dial failed; retrying");
                    sleep(DIAL_BACKOFF).await;
                }
            }
        }
    }

    /// Listen side: accept one peer at a time (a tunnel is point-to-point); when it ends,
    /// accept the next.
    async fn run_listen(&self, device: &TunDevice, peer: &Arc<Peer>) -> io::Result<()> {
        let listener = L3Listener::bind(&self.params, &self.addr).await?;
        info!(addr = ?listener.local_addr().ok(), "l3 listening");
        loop {
            match listener.accept().await {
                Ok(session) => {
                    peer.link_up();
                    info!("l3 session established");
                    if let Err(e) = pump(device, &session, self.gre_key).await {
                        warn!(error = %e, "l3 session ended");
                    }
                }
                Err(e) => {
                    // A peer that failed to authenticate is dropped; keep listening. A fatal
                    // listener error (the socket is gone) stops the tunnel.
                    if e.kind() == io::ErrorKind::BrokenPipe {
                        return Err(e);
                    }
                    peer.failed(&e);
                    warn!(error = %e, "l3 accept failed; waiting for the next peer");
                }
            }
        }
    }
}

/// Moves packets between `device` and `session` until either side ends. Each packet from
/// the interface is GRE-wrapped and sealed; each sealed packet is opened, GRE-stripped and
/// written to the interface. A packet whose GRE key does not match is dropped.
async fn pump(device: &TunDevice, session: &L3Session, gre_key: u32) -> io::Result<()> {
    let layer = device.layer();
    let up = async {
        let mut buf = vec![0u8; PACKET_BUFFER];
        loop {
            let n = device.recv(&mut buf).await?;
            let mut out = Vec::with_capacity(gre::HEADER_LEN + n);
            match layer {
                Layer::Ip => {
                    // A non-IP packet (not IPv4/IPv6) cannot be framed; drop it.
                    if !gre::encode(gre_key, &buf[..n], &mut out) {
                        continue;
                    }
                }
                Layer::Ethernet => gre::encode_eth(gre_key, &buf[..n], &mut out),
            }
            // A full carrier drops the packet, as a congested link would.
            session.send_gre(&out);
        }
    };
    let down = async {
        loop {
            let Some(packet): Option<Bytes> = session.recv_gre().await else {
                return Ok(());
            };
            let decoded = match layer {
                Layer::Ip => gre::decode(&packet),
                Layer::Ethernet => gre::decode_eth(&packet),
            };
            if let Some((key, inner)) = decoded {
                if key == gre_key {
                    device.send(inner).await?;
                }
            }
        }
    };
    tokio::select! {
        r = up => r,
        r = down => r,
    }
}

/// Builds the carrier settings and crypto for an l3 endpoint, reusing Kariz's own config
/// defaults by parsing a small synthetic tunnel config for the chosen carrier.
fn build_params(l3: &L3Config, token: &str, config: &Config) -> io::Result<L3Params> {
    let kind = match l3.carrier {
        L3Carrier::Udp => TransportKind::Udp,
        L3Carrier::Quic => TransportKind::Quic,
        L3Carrier::Faketcp => TransportKind::Faketcp,
        L3Carrier::Icmp => TransportKind::Icmp,
    };
    let synthetic = synthetic_config(kind, token, l3)?;
    let crypto = Crypto::new(token, config.tunnel.encryption).with_mux(true);
    let settings = Settings::new(&synthetic.tunnel, synthetic.kcp());
    let tuning = synthetic.tuning();
    let fec = l3.fec_data.unwrap_or(0) > 0;

    #[cfg(feature = "quic")]
    let quic = if kind == TransportKind::Quic {
        let quic = synthetic.tunnel.quic.clone().unwrap_or_default();
        Some(crate::transport::quic::QuicSettings::new(
            crypto.psk(),
            &quic,
            &synthetic.mux(),
            &tuning,
        )?)
    } else {
        None
    };

    Ok(L3Params {
        carrier: l3.carrier,
        crypto,
        tuning,
        settings,
        #[cfg(feature = "quic")]
        quic,
        layer: l3.layer,
        gre_key: l3.gre_key,
        fec,
    })
}

/// A minimal tunnel-only config for `kind`, so the carrier picks up Kariz's usual defaults
/// (KCP timing, datagram path, QUIC endpoint). The l3 session's own encryption, token and
/// framing are applied on top; the address/role here are placeholders only.
fn synthetic_config(kind: TransportKind, token: &str, l3: &L3Config) -> io::Result<Config> {
    let mut toml = format!(
        "role = \"exit\"\nmode = \"direct\"\n[tunnel]\n\
         transport = {:?}\nlisten = \"0.0.0.0:0\"\ntoken = {token:?}\n",
        kind.name()
    );
    if kind == TransportKind::Quic {
        // A real QUIC session (TLS 1.3, h3 ALPN): it looks like HTTP/3 on the wire. The
        // peer is still authenticated by the token-derived identity.
        toml.push_str("[tunnel.quic]\n");
    }
    // Carry FEC into the KCP carrier when both keys are set (validation accepts the pair).
    if let (Some(data), Some(parity)) = (l3.fec_data, l3.fec_parity) {
        if data > 0 && parity > 0 {
            toml.push_str(&format!(
                "[tunnel.kcp]\nfec_data = {data}\nfec_parity = {parity}\n"
            ));
        }
    }
    Config::parse(&toml).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("{e:#}")))
}

/// Entry point dispatched from [`crate::run`] when `[l3]` is present.
pub async fn run(config: Config) -> anyhow::Result<()> {
    let runner = L3Runner::from_config(&config)?;
    let stats = Stats::new(&config);

    // Serve the control socket, exactly as the entry/exit modes do, so `kariz status` and the
    // panel can read this end's connected / last-error state. Without it an l3 tunnel can be
    // fully up yet report nothing, and the panel's "waiting for both sides to connect" times
    // out even though the link is live. The `[l3]` tunnel leaves `[tunnel].transport` at its
    // default (`tcp`), so the peer status is the non-mux kind, set by `Peer::link_up`.
    #[cfg(unix)]
    if let Some(socket) = config.control_socket() {
        tokio::spawn(crate::control::serve(
            socket,
            None::<crate::control::NoOpen>,
            stats.clone(),
        ));
    }

    runner.run(stats).await?;
    Ok(())
}
