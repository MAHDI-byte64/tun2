//! Kariz: a high-performance, resource-efficient tunnel core.

pub mod allocator;
pub mod bench;
pub mod config;
pub mod control;
pub mod crypto;
pub mod link;
pub mod mux;
pub mod proto;
pub mod proxy_header;
pub mod session;
pub mod transport;

mod auto;
mod channel;
mod entry;
mod exit;
mod fallback;
#[cfg(feature = "l3")]
pub mod l3;
mod limit;
mod relay;
pub mod speedtest;
#[cfg(feature = "rawlink")]
pub mod spooftest;
pub mod stats;
mod udp;

use config::{Config, Role};

/// Runs one side of the tunnel until a fatal error occurs.
pub async fn run(config: Config) -> anyhow::Result<()> {
    // The l3 / GRE direct tunnel is its own mode: it carries whole IP packets over a TUN
    // interface rather than forwarding ports, so it is dispatched before the entry/exit
    // split. Config validation rejects `[l3]` when the feature is off.
    #[cfg(feature = "l3")]
    if config.l3.is_some() {
        return l3::run(config).await;
    }
    match config.role {
        Role::Entry => entry::run(config).await,
        Role::Exit => exit::run(config).await,
    }
}
