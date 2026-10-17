//! End-to-end tests for the l3 / GRE direct tunnel.
//!
//! The l3 unit adds the real rows here: create two TUN devices in this container (root +
//! `/dev/net/tun`), bring the link up in both directions (`mode = "dial"` and
//! `mode = "listen"`, either host dialing), ping across, and forward a port over the link;
//! carrier = udp and quic at least. They skip cleanly when not root or `/dev/net/tun` is
//! missing, unless `KARIZ_REQUIRE_L3=1`.
//!
//! Compiled only with the `l3` feature.
#![cfg(feature = "l3")]

/// Whether an l3 tunnel could run here: Linux, `/dev/net/tun` present.
fn l3_ready() -> bool {
    let ok = cfg!(target_os = "linux") && std::path::Path::new("/dev/net/tun").exists();
    if !ok && std::env::var("KARIZ_REQUIRE_L3").as_deref() == Ok("1") {
        panic!("l3 tests are required (KARIZ_REQUIRE_L3=1) but /dev/net/tun is missing");
    }
    ok
}

#[test]
fn placeholder_until_the_l3_unit_lands() {
    if !l3_ready() {
        eprintln!("skipping: the l3 tunnel needs Linux + /dev/net/tun + root");
        return;
    }
    eprintln!("l3 e2e scaffold: no tunnel rows yet");
}
