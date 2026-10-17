//! End-to-end tunnel tests for the managed-helper transports (`naive`, `xhttp`,
//! `reality`).
//!
//! These run real helper binaries (sing-box / Xray / naive). They run when the helpers are
//! installed (env `KARIZ_HELPERS_DIR` or the default install path) and skip with a printed
//! reason otherwise, unless `KARIZ_REQUIRE_HELPERS=1`. The helpers unit adds the rows
//! (tunnels through each helper, with self-signed certs made in-test via rcgen and a
//! `ca_file`; the reality row uses a local TLS1.3 + h2 cover server or skips).
//!
//! Compiled only with the `helpers` feature.
#![cfg(feature = "helpers")]

/// Whether the helper binaries are available to run the e2e tests.
fn helpers_ready() -> bool {
    let ok = std::env::var_os("KARIZ_HELPERS_DIR").is_some();
    if !ok && std::env::var("KARIZ_REQUIRE_HELPERS").as_deref() == Ok("1") {
        panic!("helper tests are required (KARIZ_REQUIRE_HELPERS=1) but no helpers are installed");
    }
    ok
}

#[test]
fn placeholder_until_the_helpers_unit_lands() {
    if !helpers_ready() {
        eprintln!("skipping: set KARIZ_HELPERS_DIR to run the managed-helper e2e tests");
        return;
    }
    eprintln!("helpers e2e scaffold: no helper rows yet");
}
