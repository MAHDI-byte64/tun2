//! The layer-3 / GRE direct tunnel (`[l3]`): a TUN interface on each host carrying whole
//! IP packets between two peers.
//!
//! The packets are GRE-encapsulated ([`gre`], RFC 2784 + RFC 2890 key), sealed inside the
//! tunnel's own handshake + record session ([`session`], reusing `crate::crypto`), and
//! handed to an unreliable carrier (udp / quic / faketcp / icmp). There is no bare IP
//! protocol 47 on the wire. TCP SYNs leaving the TUN have their MSS clamped ([`mss`]).
//!
//! Both directions: `mode = "listen"` waits for the inbound connection (the acceptor side),
//! `mode = "dial"` reaches out, and either host may dial — the user's "direct and reverse"
//! requirement.
//!
//! Scaffold: the config, validation, mode dispatch and feature flag are wired completely;
//! the GRE framing and the lifecycle are implemented or stubbed per module. The packet
//! loop ([`run`]) returns [`io::ErrorKind::Unsupported`] until the l3 unit lands the TUN
//! device and carrier plumbing (it must also add the pinned pure-Rust TUN + netlink
//! crates; none are added by the scaffold — see the unit report).

pub mod gre;
pub mod mss;
pub mod session;
pub mod tun;

use std::io;

use tracing::info;

use crate::config::{Config, L3Config, L3Mode};

/// The resolved parameters of one l3 tunnel end.
#[derive(Debug, Clone)]
pub struct L3Runner {
    pub mode: L3Mode,
    pub addr: String,
    pub local_ip: String,
    pub peer_ip: String,
    pub mtu: u16,
    pub carrier: crate::config::L3Carrier,
    pub token: String,
}

impl L3Runner {
    /// Builds a runner from a validated config (`config.l3` is `Some`).
    pub fn from_config(config: &Config) -> io::Result<Self> {
        let l3: &L3Config = config
            .l3
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no [l3] section"))?;
        Ok(Self {
            mode: l3.mode,
            addr: l3.addr.clone(),
            local_ip: l3.local_ip.clone(),
            peer_ip: l3.peer_ip.clone(),
            mtu: l3.mtu,
            carrier: l3.carrier,
            token: l3
                .token
                .clone()
                .unwrap_or_else(|| config.tunnel.token.clone()),
        })
    }

    /// Runs the tunnel until a fatal error. Not built yet.
    pub async fn run(self) -> io::Result<()> {
        info!(
            mode = self.mode.name(),
            carrier = self.carrier.name(),
            local_ip = %self.local_ip,
            peer_ip = %self.peer_ip,
            mtu = self.mtu,
            "l3 / GRE direct tunnel"
        );
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "the l3 / GRE direct tunnel runner is not built yet",
        ))
    }
}

/// Entry point dispatched from [`crate::run`] when `[l3]` is present.
pub async fn run(config: Config) -> anyhow::Result<()> {
    L3Runner::from_config(&config)?.run().await?;
    Ok(())
}
