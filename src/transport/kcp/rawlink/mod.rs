//! Shared raw-socket support for the ICMP and fake-TCP carriers: today, the RAII iptables
//! rule-set type ([`firewall`]). The icmp and faketcp units add the raw sockets and, for
//! faketcp, the interface / next-hop lookup here.
//!
//! Linux only; gated on the `rawlink` cargo feature.

pub mod firewall;

pub use firewall::{unique_suffix, FirewallRules, Rule};

/// Egress-path lookup for the fake-TCP carrier (Linux only).
#[cfg(all(feature = "rawlink", target_os = "linux"))]
pub(crate) mod netinfo;
