//! MSS clamping for the l3 tunnel: TCP SYNs leaving the TUN interface get their MSS
//! rewritten so sessions fit the tunnel MTU without relying on path-MTU discovery. The
//! rules are tagged iptables mangle rules, installed and removed with the RAII type in
//! [`crate::transport::kcp::rawlink`].

use crate::transport::kcp::rawlink::{FirewallRules, Rule};

/// The comment tag the clamp rules carry.
const TAG: &str = "kariz-l3-mss";

/// The MSS a tunnel MTU leaves for TCP: MTU minus the IPv4 (20) and TCP (20) headers.
pub fn mss_for_mtu(mtu: u16) -> u16 {
    mtu.saturating_sub(40)
}

/// The mangle rules that clamp the MSS of TCP SYNs on `interface` to `mss`, on both the
/// `FORWARD` and `OUTPUT` chains (traffic routed through and originated locally).
pub fn clamp_rules(interface: &str, mss: u16) -> Vec<Rule> {
    let mss = mss.to_string();
    ["FORWARD", "OUTPUT"]
        .into_iter()
        .map(|chain| {
            Rule::new(
                "mangle",
                chain,
                &[
                    "-o",
                    interface,
                    "-p",
                    "tcp",
                    "--tcp-flags",
                    "SYN,RST",
                    "SYN",
                    "-j",
                    "TCPMSS",
                    "--set-mss",
                    &mss,
                ],
            )
        })
        .collect()
}

/// Installs the MSS clamp for `interface` at the MTU-derived MSS (RAII; removed on drop).
pub fn install(interface: &str, mtu: u16) -> FirewallRules {
    FirewallRules::install(TAG, clamp_rules(interface, mss_for_mtu(mtu)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mss_leaves_room_for_headers() {
        assert_eq!(mss_for_mtu(1400), 1360);
        assert_eq!(mss_for_mtu(10), 0);
    }

    #[test]
    fn clamp_covers_forward_and_output() {
        let rules = clamp_rules("kz0", 1360);
        assert_eq!(rules.len(), 2);
    }
}
