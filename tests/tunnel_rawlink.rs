//! End-to-end tunnel tests for the raw-packet KCP carriers (`faketcp`, `icmp`).
//!
//! These need Linux, root / `CAP_NET_RAW`, and iptables; the repo's sudo CI job runs them.
//! The faketcp and icmp units add their rows here (modelled on the `kcp_*` rows in
//! `tests/tunnel.rs`: `faketcp_reverse`, `faketcp_direct`, `icmp_reverse`, ... each with a
//! `proxy_protocol = "v2"` variant), plus the RAII-firewall assertions (`iptables -S`
//! shows the tagged rules while a tunnel runs and they are gone after it stops).
//!
//! The file lives apart from `tests/tunnel.rs` because its `tunnel_tests!` macro emits
//! modules unconditionally and cannot be gated on a non-default feature. It is compiled
//! only with the `rawlink` feature so the default `cargo test` stays unchanged.
#![cfg(feature = "rawlink")]

/// True when the raw-packet carriers could run here: root (iptables usable) and Linux. The
/// unit's e2e rows call this and skip with a printed reason when it is false, unless
/// `KARIZ_REQUIRE_RAWLINK=1` forces a failure.
fn rawlink_ready() -> bool {
    let ok = cfg!(target_os = "linux")
        && std::process::Command::new("iptables")
            .arg("-S")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
    if !ok && std::env::var("KARIZ_REQUIRE_RAWLINK").as_deref() == Ok("1") {
        panic!(
            "rawlink tests are required (KARIZ_REQUIRE_RAWLINK=1) but the environment is not ready"
        );
    }
    ok
}

#[test]
fn placeholder_until_the_faketcp_and_icmp_units_land() {
    if !rawlink_ready() {
        eprintln!("skipping: raw-packet carriers need Linux + root + iptables");
        return;
    }
    // The faketcp/icmp units replace this with real end-to-end tunnel rows.
    eprintln!("rawlink e2e scaffold: no carrier rows yet");
}
