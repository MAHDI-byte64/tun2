//! End-to-end tunnel tests for the raw-packet KCP carriers (`faketcp`, `icmp`).
//!
//! These need Linux, root / `CAP_NET_RAW`, and iptables; the repo's sudo CI job runs them.
//! Each carrier is driven over the real kariz entry/exit runners in-process on loopback, in
//! reverse and direct modes, with and without mux, with FEC, with ChaCha, and with a
//! `proxy_protocol = "v2"` forward rule. Every row also checks that the RAII firewall rules
//! appear in `iptables -S` while the tunnel is up and are gone once it stops.
//!
//! The file lives apart from `tests/tunnel.rs` because that file's `tunnel_tests!` macro
//! emits modules unconditionally and cannot be gated on a non-default feature. It is
//! compiled only with the `rawlink` feature so the default `cargo test` stays unchanged.
//!
//! Loopback caveat: over `lo` a fake-TCP segment is transmitted and immediately received on
//! the same interface, so these exercise `AF_PACKET` on `lo` plus the RST-drop rule, not a
//! two-host L2 path; real-NIC validation is left to a manual soak test.
#![cfg(feature = "rawlink")]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Mutex;
use std::time::Duration;

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

/// Raw sockets, iptables rules and the token-derived fake-TCP source port are global to the
/// host, so only one raw-packet tunnel runs at a time.
static SERIAL: Mutex<()> = Mutex::new(());

/// One raw-carrier end-to-end scenario.
struct Spec {
    transport: &'static str,
    /// `reverse` (entry listens) or `direct` (exit listens).
    mode: &'static str,
    mux: bool,
    /// `auto` or `chacha20-poly1305`.
    encryption: &'static str,
    fec: (usize, usize),
    /// `""` or `"v2"`.
    proxy_protocol: &'static str,
    /// A unique token per test, so source ports and tags do not collide.
    token: &'static str,
    /// The firewall comment prefix the rules carry while the tunnel is up.
    fw_prefix: &'static str,
}

/// Runs one scenario: brings the tunnel up, echoes a payload through it, checks the RAII
/// firewall rules are present, then tears it down and checks they are gone.
fn run(spec: &Spec) {
    if !rawlink_ready() {
        eprintln!(
            "skipping {}_{}: raw-packet carriers need Linux + root + iptables",
            spec.transport, spec.mode
        );
        return;
    }
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());

    // A plain TCP echo target; with proxy_protocol it strips the PROXY v2 header first.
    let target = echo_target(!spec.proxy_protocol.is_empty());
    let user_port = free_port();
    let tunnel_port = free_port();

    let (entry_addr, exit_addr) = match spec.mode {
        "reverse" => (
            format!("listen = \"127.0.0.1:{tunnel_port}\""),
            format!("remote = \"127.0.0.1:{tunnel_port}\"\npool = 2"),
        ),
        _ => (
            format!("remote = \"127.0.0.1:{tunnel_port}\""),
            format!("listen = \"127.0.0.1:{tunnel_port}\""),
        ),
    };
    let proxy = match spec.proxy_protocol {
        "" => String::new(),
        v => format!("proxy_protocol = \"{v}\""),
    };
    let options = spec.tunnel_options();
    let entry = format!(
        r#"
        role = "entry"
        mode = "{mode}"
        [[forward]]
        listen = "127.0.0.1:{user_port}"
        target = "127.0.0.1:{target}"
        protocol = "tcp"
        {proxy}
        [tunnel]
        {entry_addr}
        token = "{token}"
        {options}
        "#,
        mode = spec.mode,
        token = spec.token,
    );
    let exit = format!(
        r#"
        role = "exit"
        mode = "{mode}"
        [tunnel]
        {exit_addr}
        token = "{token}"
        {options}
        "#,
        mode = spec.mode,
        token = spec.token,
    );

    // Start the listening side first so the dialing side connects right away.
    let (_a, _b) = if spec.mode == "reverse" {
        let e = Side::start(&entry);
        std::thread::sleep(Duration::from_millis(150));
        (e, Side::start(&exit))
    } else {
        let x = Side::start(&exit);
        std::thread::sleep(Duration::from_millis(150));
        (Side::start(&entry), x)
    };

    // Wait for the tunnel to carry traffic (KCP handshake + mux session setup).
    let payload = b"a payload that rides the raw-packet carrier end to end".to_vec();
    let mut echoed = None;
    for _ in 0..80 {
        if let Ok(got) = echo_once(user_port, &payload) {
            echoed = Some(got);
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let got = echoed.unwrap_or_else(|| panic!("tunnel never carried traffic for {}", spec.token));
    assert_eq!(got, payload, "payload round-trips for {}", spec.token);

    // The RAII firewall rules are present while the tunnel is up.
    assert!(
        firewall_dump().contains(spec.fw_prefix),
        "firewall rules ({}) should be installed while the tunnel is up",
        spec.fw_prefix
    );

    // Tear down and confirm the rules are removed.
    drop(_a);
    drop(_b);
    let mut gone = false;
    for _ in 0..40 {
        if !firewall_dump().contains(spec.fw_prefix) {
            gone = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        gone,
        "firewall rules ({}) should be gone after the tunnel stops",
        spec.fw_prefix
    );
}

impl Spec {
    fn tunnel_options(&self) -> String {
        let mut o = format!(
            "transport = \"{}\"\nencryption = \"{}\"\n[tunnel.mux]\nenabled = {}\nconnections = 1\n",
            self.transport, self.encryption, self.mux,
        );
        if self.fec.0 > 0 {
            o += &format!(
                "[tunnel.kcp]\nfec_data = {}\nfec_parity = {}\n",
                self.fec.0, self.fec.1
            );
        }
        o += "[tuning]\nkeepalive_secs = 5\n";
        o
    }
}

/// `iptables -S` across the filter and raw tables, concatenated.
fn firewall_dump() -> String {
    let mut out = String::new();
    for args in [vec!["-S"], vec!["-t", "raw", "-S"]] {
        if let Ok(o) = std::process::Command::new("iptables").args(&args).output() {
            out.push_str(&String::from_utf8_lossy(&o.stdout));
        }
    }
    out
}

/// A free loopback TCP port (nothing is listening on it after this returns).
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Connects to `port`, writes `payload`, reads the same number of bytes back.
fn echo_once(port: u16, payload: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut s = TcpStream::connect(("127.0.0.1", port))?;
    s.set_read_timeout(Some(Duration::from_secs(5)))?;
    s.set_write_timeout(Some(Duration::from_secs(5)))?;
    s.write_all(payload)?;
    let mut got = vec![0u8; payload.len()];
    s.read_exact(&mut got)?;
    Ok(got)
}

/// A TCP echo target on its own thread. When `strip_proxy` is set it reads and discards a
/// PROXY v2 header before echoing, so the proxy-protocol rows round-trip cleanly.
fn echo_target(strip_proxy: bool) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || serve_echo(stream, strip_proxy));
        }
    });
    port
}

fn serve_echo(mut stream: TcpStream, strip_proxy: bool) {
    if strip_proxy && skip_proxy_header(&mut stream).is_err() {
        return;
    }
    let mut buf = [0u8; 8192];
    loop {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(n) => {
                if stream.write_all(&buf[..n]).is_err() {
                    return;
                }
            }
        }
    }
}

/// Reads and discards a PROXY protocol v2 header from `stream`.
fn skip_proxy_header(stream: &mut TcpStream) -> std::io::Result<()> {
    const SIG: [u8; 12] = [
        0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
    ];
    let mut head = [0u8; 16];
    stream.read_exact(&mut head)?;
    assert_eq!(
        head[..12],
        SIG,
        "a proxy_protocol = v2 forward sends a v2 header"
    );
    let addr_len = u16::from_be_bytes([head[14], head[15]]) as usize;
    let mut rest = vec![0u8; addr_len];
    stream.read_exact(&mut rest)
}

/// One tunnel side (entry or exit), run on its own thread and runtime, stopped on drop.
struct Side {
    stop: Option<std::sync::mpsc::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Side {
    fn start(text: &str) -> Self {
        if std::env::var_os("KARIZ_TEST_LOG").is_some() {
            let _ = tracing_subscriber::fmt()
                .with_env_filter(
                    std::env::var("KARIZ_TEST_LOG")
                        .ok()
                        .filter(|f| f.contains('='))
                        .unwrap_or_else(|| "kariz=debug".into()),
                )
                .try_init();
        }
        let config = kariz::config::Config::parse(text).unwrap_or_else(|e| panic!("{e:#}\n{text}"));
        let (stop, stopped) = std::sync::mpsc::channel::<()>();
        let thread = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .unwrap();
            rt.spawn(async move {
                if let Err(e) = kariz::run(config).await {
                    eprintln!("tunnel side stopped: {e:#}");
                }
            });
            let _ = stopped.recv();
            rt.shutdown_timeout(Duration::from_secs(2));
        });
        Self {
            stop: Some(stop),
            thread: Some(thread),
        }
    }
}

impl Drop for Side {
    fn drop(&mut self) {
        drop(self.stop.take());
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

macro_rules! rawlink_tests {
    ($($name:ident: $spec:expr;)*) => {
        $(
            #[test]
            fn $name() {
                run(&$spec);
            }
        )*
    };
}

const fn icmp(mode: &'static str, token: &'static str) -> Spec {
    Spec {
        transport: "icmp",
        mode,
        mux: true,
        encryption: "auto",
        fec: (0, 0),
        proxy_protocol: "",
        token,
        fw_prefix: "kariz-icmp-",
    }
}

const fn faketcp(mode: &'static str, token: &'static str) -> Spec {
    Spec {
        transport: "faketcp",
        fw_prefix: "kariz-faketcp-",
        ..icmp(mode, token)
    }
}

rawlink_tests! {
    icmp_reverse: icmp("reverse", "kariz-e2e-icmp-reverse");
    icmp_direct: icmp("direct", "kariz-e2e-icmp-direct");
    icmp_reverse_no_mux: Spec { mux: false, ..icmp("reverse", "kariz-e2e-icmp-nomux") };
    icmp_reverse_fec: Spec { fec: (10, 3), ..icmp("reverse", "kariz-e2e-icmp-fec") };
    icmp_reverse_proxy_v2: Spec { proxy_protocol: "v2", ..icmp("reverse", "kariz-e2e-icmp-rev-proxy") };
    icmp_direct_proxy_v2: Spec { proxy_protocol: "v2", ..icmp("direct", "kariz-e2e-icmp-dir-proxy") };
    icmp_reverse_no_mux_proxy_v2: Spec { mux: false, proxy_protocol: "v2", ..icmp("reverse", "kariz-e2e-icmp-nomux-proxy") };
    icmp_reverse_fec_proxy_v2: Spec { fec: (10, 3), proxy_protocol: "v2", ..icmp("reverse", "kariz-e2e-icmp-fec-proxy") };

    faketcp_reverse: faketcp("reverse", "kariz-e2e-faketcp-reverse");
    faketcp_direct: faketcp("direct", "kariz-e2e-faketcp-direct");
    faketcp_reverse_no_mux: Spec { mux: false, ..faketcp("reverse", "kariz-e2e-faketcp-nomux") };
    faketcp_direct_chacha: Spec { encryption: "chacha20-poly1305", ..faketcp("direct", "kariz-e2e-faketcp-chacha") };
    faketcp_reverse_fec: Spec { fec: (10, 3), ..faketcp("reverse", "kariz-e2e-faketcp-fec") };
    faketcp_reverse_proxy_v2: Spec { proxy_protocol: "v2", ..faketcp("reverse", "kariz-e2e-faketcp-rev-proxy") };
    faketcp_direct_proxy_v2: Spec { proxy_protocol: "v2", ..faketcp("direct", "kariz-e2e-faketcp-dir-proxy") };
    faketcp_reverse_no_mux_proxy_v2: Spec { mux: false, proxy_protocol: "v2", ..faketcp("reverse", "kariz-e2e-faketcp-nomux-proxy") };
    faketcp_direct_chacha_proxy_v2: Spec { encryption: "chacha20-poly1305", proxy_protocol: "v2", ..faketcp("direct", "kariz-e2e-faketcp-chacha-proxy") };
    faketcp_reverse_fec_proxy_v2: Spec { fec: (10, 3), proxy_protocol: "v2", ..faketcp("reverse", "kariz-e2e-faketcp-fec-proxy") };
}
