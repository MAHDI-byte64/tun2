//! End-to-end tests: user -> entry -> tunnel -> exit -> echo server, on localhost.

mod link;

use std::time::{Duration, Instant};

use kariz::config::Config;
use link::{Counts, Impairment, TcpLink, UdpLink};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

const TOKEN: &str = "test-token-0123456789abcdef";

/// The tunnel runs inside this process, so the benchmarks use the binary's allocator.
#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// A port free for both TCP and UDP: tunnel ports of UDP transports and `tcp+udp`
/// forward ports need both.
fn free_port() -> u16 {
    free_ports(1)
}

/// A port like [`free_port`] whose next `following` ports are free (and kept) too: an
/// `auto` tunnel also listens on the port after its own (WebSocket).
fn free_ports(following: u16) -> u16 {
    // Every port handed out is kept, so tests running side by side never get the same one
    // or each other's neighbour.
    use std::hash::{BuildHasher, Hasher};
    static KEPT: std::sync::Mutex<Vec<u16>> = std::sync::Mutex::new(Vec::new());
    let mut kept = KEPT.lock().unwrap_or_else(|e| e.into_inner());
    loop {
        // Below the range the kernel hands out to outgoing connections (32768 and up): a port
        // taken from there can be grabbed by another test's connection before it is bound.
        let port = 20_000
            + (std::collections::hash_map::RandomState::new()
                .build_hasher()
                .finish()
                % 10_000) as u16;
        let Ok(_held) = std::net::TcpListener::bind(("127.0.0.1", port)) else {
            continue;
        };
        let span = || port..=port.saturating_add(following.saturating_sub(1));
        if port.checked_add(following).is_none()
            || span().any(|p| kept.contains(&p))
            || std::net::UdpSocket::bind(("127.0.0.1", port)).is_err()
            || (1..following).any(|i| std::net::TcpListener::bind(("127.0.0.1", port + i)).is_err())
        {
            continue;
        }
        kept.extend(span());
        return port;
    }
}

/// Echoes TCP and UDP on the same port.
async fn echo_server() -> u16 {
    loop {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        // The same port number may be taken for UDP; then try another.
        let Ok(udp) = UdpSocket::bind(("127.0.0.1", port)).await else {
            continue;
        };
        tokio::spawn(async move {
            loop {
                let (mut s, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let (mut r, mut w) = s.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });
        tokio::spawn(udp_echo(udp));
        return port;
    }
}

async fn udp_echo(udp: UdpSocket) {
    // Several clients send 60 KB packets at once: with the kernel's default buffer
    // (about 208 KB) the target itself would drop some, and the tests are strict.
    let _ = socket2::SockRef::from(&udp).set_recv_buffer_size(4 << 20);
    let mut buf = vec![0u8; 65_536];
    while let Ok((n, from)) = udp.recv_from(&mut buf).await {
        let _ = udp.send_to(&buf[..n], from).await;
    }
}

/// A UDP target that answers every packet with the source port it came from, so a test
/// can tell whether packets used the same flow (same exit socket).
async fn udp_port_reporter() -> u16 {
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = udp.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        while let Ok((_, from)) = udp.recv_from(&mut buf).await {
            let _ = udp.send_to(&from.port().to_be_bytes(), from).await;
        }
    });
    port
}

/// One way to set up the tunnel. The scenarios below run for every setup listed in
/// `tunnel_tests!`, so a new transport or layer only needs a new row there.
#[derive(Clone, Copy, Debug)]
struct Setup {
    mode: &'static str,
    transport: &'static str,
    mux: bool,
    encryption: &'static str,
    /// `tunnel.ws.path`, for `ws` and `wss`.
    ws_path: &'static str,
    /// `wss` dialer: pin a certificate the listener does not have.
    wrong_pin: bool,
    /// `ws` / `wss` dialer: `tunnel.ws.early_data`.
    early_data: bool,
    /// `tuning.keepalive_secs` (mux ping interval); 0 keeps the profile default.
    keepalive_secs: u64,
    /// `tuning.udp_timeout_secs` / `udp_max_flows`; 0 keeps the default.
    udp_timeout_secs: u64,
    udp_max_flows: usize,
    /// `tunnel.mux.connections`; 0 keeps the default.
    mux_connections: usize,
    /// `tunnel.quic.congestion`; empty keeps the default.
    congestion: &'static str,
    /// `tunnel.quic.bandwidth_mbps` (with `congestion = "fixed"`); 0 leaves it out.
    bandwidth_mbps: u32,
    /// `tunnel.quic.obfs`.
    obfs: bool,
    /// `tunnel.mux.stream_window`; 0 keeps the default.
    stream_window: usize,
    /// `tunnel.kcp.fec_data` / `fec_parity`; 0 keeps FEC off.
    fec: (usize, usize),
    /// More `[tunnel.kcp]` lines.
    kcp_options: &'static str,
    /// The forward rule's `duplicate` / `duplicate_gap_ms`; 0 copies leaves them out.
    duplicate: (u8, u8),
    /// `profile`, on both sides; empty keeps the default.
    profile: &'static str,
    /// Both sides serve a control socket (`[control] socket`), for `kariz speedtest` and
    /// `kariz status`.
    control: bool,
    /// `tunnel.speedtest = false`.
    no_speedtest: bool,
    /// `tunnel.mux.max_streams`; 0 keeps the default.
    max_streams: usize,
    /// `tuning.max_conns_per_ip`; 0 keeps it off.
    max_conns_per_ip: u32,
    /// `tuning.dial_timeout_secs` and `handshake_timeout_secs`; 0 keeps the defaults.
    timeouts_secs: u64,
    /// The forward rule's `proxy_protocol` (`v1`, `v2`); empty leaves it out.
    proxy_protocol: &'static str,
    /// The forward rule's `protocol`; the `udp` transport forwards UDP only.
    forward_protocol: &'static str,
}

impl Setup {
    const fn tcp(mode: &'static str) -> Self {
        Self {
            mode,
            transport: "tcp",
            mux: false,
            encryption: "auto",
            ws_path: "/kariz-e2e",
            wrong_pin: false,
            early_data: false,
            keepalive_secs: 0,
            udp_timeout_secs: 0,
            udp_max_flows: 0,
            mux_connections: 0,
            congestion: "",
            bandwidth_mbps: 0,
            obfs: false,
            stream_window: 0,
            fec: (0, 0),
            kcp_options: "",
            duplicate: (0, 0),
            profile: "",
            control: false,
            no_speedtest: false,
            max_streams: 0,
            max_conns_per_ip: 0,
            timeouts_secs: 0,
            proxy_protocol: "",
            forward_protocol: "tcp+udp",
        }
    }

    const fn proxy_protocol(self, proxy_protocol: &'static str) -> Self {
        Self {
            proxy_protocol,
            ..self
        }
    }

    const fn max_streams(self, max_streams: usize) -> Self {
        Self {
            max_streams,
            ..self
        }
    }

    const fn max_conns_per_ip(self, max_conns_per_ip: u32) -> Self {
        Self {
            max_conns_per_ip,
            ..self
        }
    }

    const fn timeouts(self, timeouts_secs: u64) -> Self {
        Self {
            timeouts_secs,
            ..self
        }
    }

    #[cfg_attr(not(unix), allow(dead_code))]
    const fn control(self) -> Self {
        Self {
            control: true,
            ..self
        }
    }

    #[cfg_attr(not(unix), allow(dead_code))]
    const fn no_speedtest(self) -> Self {
        Self {
            no_speedtest: true,
            ..self
        }
    }

    const fn profile(self, profile: &'static str) -> Self {
        Self { profile, ..self }
    }

    const fn duplicate(self, copies: u8, gap_ms: u8) -> Self {
        Self {
            duplicate: (copies, gap_ms),
            ..self
        }
    }

    const fn kcp_options(self, kcp_options: &'static str) -> Self {
        Self {
            kcp_options,
            ..self
        }
    }

    const fn fec(self, data: usize, parity: usize) -> Self {
        Self {
            fec: (data, parity),
            ..self
        }
    }

    const fn obfs(self) -> Self {
        Self { obfs: true, ..self }
    }

    const fn congestion(self, congestion: &'static str) -> Self {
        Self { congestion, ..self }
    }

    /// Fixed-rate QUIC: `congestion = "fixed"` with this bandwidth.
    const fn bandwidth_mbps(self, bandwidth_mbps: u32) -> Self {
        Self {
            congestion: "fixed",
            bandwidth_mbps,
            ..self
        }
    }

    const fn stream_window(self, stream_window: usize) -> Self {
        Self {
            stream_window,
            ..self
        }
    }

    const fn mux_connections(self, mux_connections: usize) -> Self {
        Self {
            mux_connections,
            ..self
        }
    }

    const fn udp_timeout(self, udp_timeout_secs: u64) -> Self {
        Self {
            udp_timeout_secs,
            ..self
        }
    }

    const fn udp_max_flows(self, udp_max_flows: usize) -> Self {
        Self {
            udp_max_flows,
            ..self
        }
    }

    const fn keepalive(self, keepalive_secs: u64) -> Self {
        Self {
            keepalive_secs,
            ..self
        }
    }

    const fn early_data(self) -> Self {
        Self {
            early_data: true,
            ..self
        }
    }

    const fn wss(mode: &'static str) -> Self {
        Self {
            transport: "wss",
            ..Self::ws(mode)
        }
    }

    const fn wrong_pin(self) -> Self {
        Self {
            wrong_pin: true,
            ..self
        }
    }

    const fn ws(mode: &'static str) -> Self {
        Self {
            transport: "ws",
            mux: true,
            ..Self::tcp(mode)
        }
    }

    /// `wsmux` / `wssmux`: `ws` / `wss` with mux forced on.
    const fn wsmux(mode: &'static str) -> Self {
        Self {
            transport: "wsmux",
            ..Self::ws(mode)
        }
    }

    const fn wssmux(mode: &'static str) -> Self {
        Self {
            transport: "wssmux",
            ..Self::wss(mode)
        }
    }

    /// `stealth`: an encrypted TCP stream (the record-padding layer is added later; here it
    /// behaves as encrypted TCP). Mux optional, on by default.
    const fn stealth(mode: &'static str) -> Self {
        Self {
            transport: "stealth",
            mux: true,
            ..Self::tcp(mode)
        }
    }

    /// QUIC: its own streams, datagrams and TLS. A short keepalive, since a QUIC peer
    /// that dies is only noticed by its silence (idle timeout = keepalive).
    const fn quic(mode: &'static str) -> Self {
        Self {
            transport: "quic",
            mux: true,
            keepalive_secs: 5,
            ..Self::tcp(mode)
        }
    }

    /// KCP: a stream transport over UDP. The same short keepalive as QUIC, since a KCP
    /// peer that dies is also only noticed by its silence.
    const fn kcp(mode: &'static str) -> Self {
        Self {
            transport: "kcp",
            mux: true,
            keepalive_secs: 5,
            ..Self::tcp(mode)
        }
    }

    /// The `udp` transport: the tunnel rides plain UDP (KCP carrier), forwards UDP only on
    /// the unreliable datagram path, mux forced on, FEC off. Short keepalive like KCP.
    const fn udp(mode: &'static str) -> Self {
        Self {
            transport: "udp",
            mux: true,
            keepalive_secs: 5,
            forward_protocol: "udp",
            ..Self::tcp(mode)
        }
    }

    const fn no_mux(self) -> Self {
        Self { mux: false, ..self }
    }

    const fn ws_path(self, ws_path: &'static str) -> Self {
        Self { ws_path, ..self }
    }

    const fn encryption(self, encryption: &'static str) -> Self {
        Self { encryption, ..self }
    }

    const fn mux(self) -> Self {
        Self { mux: true, ..self }
    }

    const fn transport(self, transport: &'static str) -> Self {
        Self { transport, ..self }
    }

    /// Transport lines and sub-tables of `[tunnel]` for the listening or dialing side.
    fn tunnel_options(&self, listening: bool) -> String {
        let mut options = format!(
            "transport = \"{}\"\nencryption = \"{}\"\n{}[tunnel.mux]\nenabled = {}\n",
            self.transport,
            self.encryption,
            if self.no_speedtest {
                "speedtest = false\n"
            } else {
                ""
            },
            self.mux
        );
        if self.mux_connections > 0 {
            options += &format!("connections = {}\n", self.mux_connections);
        }
        if self.stream_window > 0 {
            options += &format!("stream_window = {}\n", self.stream_window);
        }
        if self.max_streams > 0 {
            options += &format!("max_streams = {}\n", self.max_streams);
        }
        if self.transport.starts_with("ws") {
            options += &format!("[tunnel.ws]\npath = \"{}\"\n", self.ws_path);
            if self.early_data && !listening {
                options += "early_data = true\n";
            }
        }
        if self.transport == "wss" || self.transport == "wssmux" {
            let cert = test_cert();
            options += &if listening {
                format!(
                    "[tunnel.tls]\ncert = {:?}\nkey = {:?}\n",
                    cert.cert, cert.key
                )
            } else {
                let pin = if self.wrong_pin {
                    &cert.other_pin
                } else {
                    &cert.pin
                };
                format!("[tunnel.tls]\nsni = \"tunnel.example\"\npin_sha256 = \"{pin}\"\n")
            };
        }
        if self.fec.0 > 0 || !self.kcp_options.is_empty() {
            options += "[tunnel.kcp]\n";
            if self.fec.0 > 0 {
                options += &format!("fec_data = {}\nfec_parity = {}\n", self.fec.0, self.fec.1);
            }
            options += self.kcp_options;
            options += "\n";
        }
        if !self.congestion.is_empty() || self.obfs {
            options += "[tunnel.quic]\n";
            if !self.congestion.is_empty() {
                options += &format!("congestion = \"{}\"\n", self.congestion);
            }
            if self.bandwidth_mbps > 0 {
                options += &format!("bandwidth_mbps = {}\n", self.bandwidth_mbps);
            }
            if self.obfs {
                options += "obfs = true\n";
            }
        }
        options += "[tuning]\n";
        if self.keepalive_secs > 0 {
            options += &format!("keepalive_secs = {}\n", self.keepalive_secs);
        }
        if self.udp_timeout_secs > 0 {
            options += &format!("udp_timeout_secs = {}\n", self.udp_timeout_secs);
        }
        if self.udp_max_flows > 0 {
            options += &format!("udp_max_flows = {}\n", self.udp_max_flows);
        }
        if self.max_conns_per_ip > 0 {
            options += &format!("max_conns_per_ip = {}\n", self.max_conns_per_ip);
        }
        if self.timeouts_secs > 0 {
            options += &format!(
                "dial_timeout_secs = {0}\nhandshake_timeout_secs = {0}\n",
                self.timeouts_secs
            );
        }
        options
    }
}

/// A self-signed certificate for the `wss` listener, written once per test run.
struct TestCert {
    cert: std::path::PathBuf,
    key: std::path::PathBuf,
    pin: String,
    /// Pin of a different certificate.
    other_pin: String,
}

fn test_cert() -> &'static TestCert {
    static CERT: std::sync::OnceLock<TestCert> = std::sync::OnceLock::new();
    CERT.get_or_init(|| {
        let generate =
            || rcgen::generate_simple_self_signed(vec!["tunnel.example".into()]).unwrap();
        let (c, other) = (generate(), generate());
        let dir = std::env::temp_dir().join(format!("kariz-e2e-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (cert, key) = (dir.join("cert.pem"), dir.join("key.pem"));
        std::fs::write(&cert, c.cert.pem()).unwrap();
        std::fs::write(&key, c.signing_key.serialize_pem()).unwrap();
        TestCert {
            cert,
            key,
            pin: kariz::transport::tls::cert_sha256(c.cert.der()),
            other_pin: kariz::transport::tls::cert_sha256(other.cert.der()),
        }
    })
}

/// One side of the tunnel in its own runtime, like a separate process: dropping it
/// shuts the runtime down, which drops every task and closes every socket the side had.
struct Side {
    stop: Option<std::sync::mpsc::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Side {
    fn start(text: &str) -> Self {
        let config = Config::parse(text).unwrap_or_else(|e| panic!("{e:#}\n{text}"));
        Self::run(config)
    }

    /// A side loaded from a config file, as the daemon does: it can be told to reload it.
    fn start_from_file(path: &std::path::Path) -> Self {
        Self::run(Config::load(path).unwrap_or_else(|e| panic!("{e:#}")))
    }

    fn run(config: Config) -> Self {
        if std::env::var_os("KARIZ_TEST_LOG").is_some() {
            let _ = tracing_subscriber::fmt()
                .with_env_filter(
                    std::env::var("KARIZ_TEST_LOG")
                        .ok()
                        .filter(|f| f.contains('='))
                        .unwrap_or_else(|| "kariz=debug".into()),
                )
                .with_thread_names(true)
                .try_init();
        }
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

/// Something between the two sides (nginx, a link emulator) that runs while it is held.
type Proxy = Box<dyn Send + Sync>;

struct Tunnel {
    user_port: u16,
    /// Held only to keep a proxy between the two sides running.
    _proxy: Option<Proxy>,
    /// Held only to keep the entry side running.
    _entry: Side,
    exit: Option<Side>,
    exit_config: String,
    /// The entry side's control socket, when the setup asked for one.
    #[cfg_attr(not(unix), allow(dead_code))]
    control: Option<std::path::PathBuf>,
    /// The exit side's control socket, when the setup asked for one.
    #[cfg_attr(not(unix), allow(dead_code))]
    exit_control: Option<std::path::PathBuf>,
}

impl Tunnel {
    fn kill_exit(&mut self) {
        drop(self.exit.take());
    }

    fn restart_exit(&mut self) {
        self.exit = Some(Side::start(&self.exit_config));
    }
}

async fn start(setup: Setup, entry_token: &str, exit_token: &str, target_port: u16) -> Tunnel {
    start_pair(setup, setup, entry_token, exit_token, target_port).await
}

/// Like [`start`], with separate settings for each side (for mismatch tests).
async fn start_pair(
    setup: Setup,
    exit_setup: Setup,
    entry_token: &str,
    exit_token: &str,
    target_port: u16,
) -> Tunnel {
    let direct = |port| (port, None);
    start_via(
        setup,
        exit_setup,
        entry_token,
        exit_token,
        target_port,
        direct,
    )
    .await
}

/// Like [`start_pair`], with a proxy between the sides: `proxy` gets the port the
/// listening side uses and returns the port the dialing side should connect to.
async fn start_via(
    setup: Setup,
    exit_setup: Setup,
    entry_token: &str,
    exit_token: &str,
    target_port: u16,
    proxy: impl FnOnce(u16) -> (u16, Option<Proxy>),
) -> Tunnel {
    // Auto also listens on the port after the tunnel's (WebSocket).
    let tunnel_port = free_ports(2);
    let (dial_port, proxy) = proxy(tunnel_port);
    let user_port = free_port();
    let mode = setup.mode;
    let (entry_tunnel, exit_tunnel) = match mode {
        "reverse" => (
            format!("listen = \"127.0.0.1:{tunnel_port}\""),
            format!("remote = \"127.0.0.1:{dial_port}\"\npool = 2"),
        ),
        _ => (
            format!("remote = \"127.0.0.1:{dial_port}\""),
            format!("listen = \"127.0.0.1:{tunnel_port}\""),
        ),
    };
    let entry_listens = mode == "reverse";
    let options = setup.tunnel_options(entry_listens);
    let exit_options = exit_setup.tunnel_options(!entry_listens);
    let control = setup
        .control
        .then(|| std::env::temp_dir().join(format!("kariz-e2e-{user_port}.sock")));
    let exit_control = setup
        .control
        .then(|| std::env::temp_dir().join(format!("kariz-e2e-{user_port}-exit.sock")));
    let socket_table = |path: &Option<std::path::PathBuf>| {
        path.as_ref().map_or(String::new(), |path| {
            format!("[control]\nsocket = {:?}", path.display().to_string())
        })
    };
    let (control_table, exit_control_table) = (socket_table(&control), socket_table(&exit_control));
    let duplicate = match setup.duplicate {
        (0, _) => String::new(),
        (copies, gap) => format!("duplicate = {copies}\nduplicate_gap_ms = {gap}"),
    };
    let proxy_protocol = match setup.proxy_protocol {
        "" => String::new(),
        v => format!("proxy_protocol = \"{v}\""),
    };
    let forward_protocol = setup.forward_protocol;
    let profile = |setup: Setup| match setup.profile {
        "" => String::new(),
        p => format!("profile = \"{p}\""),
    };
    let (entry_profile, exit_profile) = (profile(setup), profile(exit_setup));
    let entry = format!(
        r#"
        role = "entry"
        mode = "{mode}"
        {entry_profile}
        [[forward]]
        listen = "127.0.0.1:{user_port}"
        target = "127.0.0.1:{target_port}"
        protocol = "{forward_protocol}"
        {duplicate}
        {proxy_protocol}
        [tunnel]
        {entry_tunnel}
        token = "{entry_token}"
        {options}
        {control_table}
        "#
    );
    let exit = format!(
        r#"
        role = "exit"
        mode = "{mode}"
        {exit_profile}
        [tunnel]
        {exit_tunnel}
        token = "{exit_token}"
        {exit_options}
        {exit_control_table}
        "#
    );
    // Start the listening side first so the dialing side connects right away.
    let (entry_side, exit_side) = if mode == "reverse" {
        let e = Side::start(&entry);
        tokio::time::sleep(Duration::from_millis(100)).await;
        (e, Side::start(&exit))
    } else {
        let x = Side::start(&exit);
        tokio::time::sleep(Duration::from_millis(100)).await;
        (Side::start(&entry), x)
    };
    tokio::time::sleep(Duration::from_millis(300)).await;
    Tunnel {
        user_port,
        _proxy: proxy,
        _entry: entry_side,
        exit: Some(exit_side),
        exit_config: exit,
        control,
        exit_control,
    }
}

async fn echo_roundtrip(port: u16, payload: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).await?;
    let (mut r, mut w) = s.split();
    let write = async {
        w.write_all(payload).await?;
        w.shutdown().await
    };
    let mut out = Vec::with_capacity(payload.len());
    let read = r.read_to_end(&mut out);
    let (a, b) = tokio::join!(write, read);
    a?;
    b?;
    Ok(out)
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 31 % 251) as u8).collect()
}

async fn check_echo(setup: Setup) {
    let target = echo_server().await;
    let tunnel = start(setup, TOKEN, TOKEN, target).await;

    // Several concurrent connections, including more than the reverse pool size.
    let mut handles = Vec::new();
    for i in 0..10 {
        let port = tunnel.user_port;
        handles.push(tokio::spawn(async move {
            let payload = pattern(1000 + i * 7919);
            let got = echo_roundtrip(port, &payload).await.unwrap();
            assert_eq!(got, payload);
        }));
    }
    for h in handles {
        h.await.unwrap();
    }

    // Large transfer integrity.
    let payload = pattern(8 * 1024 * 1024);
    let got = echo_roundtrip(tunnel.user_port, &payload).await.unwrap();
    assert!(got == payload, "large payload corrupted");
}

/// The user connection must be closed without passing data, not left hanging.
async fn expect_closed_without_data(tunnel: &Tunnel) {
    let result = tokio::time::timeout(
        Duration::from_secs(30),
        echo_roundtrip(tunnel.user_port, b"hello"),
    )
    .await
    .expect("user connection should be closed, not hang");
    if let Ok(data) = result {
        assert!(data.is_empty(), "no data may pass");
    }
}

async fn check_token_mismatch(setup: Setup) {
    let target = echo_server().await;
    let tunnel = start(setup, TOKEN, "another-token-0123456789", target).await;
    expect_closed_without_data(&tunnel).await;
}

async fn check_unreachable_target(setup: Setup) {
    let dead_port = free_port();
    let tunnel = start(setup, TOKEN, TOKEN, dead_port).await;
    expect_closed_without_data(&tunnel).await;
}

/// The exit side dies in the middle of a transfer: the user connection must end instead
/// of hanging, and once the exit is back, new connections work again.
async fn check_exit_restart(setup: Setup) {
    let target = echo_server().await;
    let mut tunnel = start(setup, TOKEN, TOKEN, target).await;
    assert_eq!(
        echo_roundtrip(tunnel.user_port, b"warm up").await.unwrap(),
        b"warm up"
    );

    let user = TcpStream::connect(("127.0.0.1", tunnel.user_port))
        .await
        .unwrap();
    let (mut r, mut w) = user.into_split();
    let writer = tokio::spawn(async move {
        let chunk = pattern(16 * 1024);
        while w.write_all(&chunk).await.is_ok() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    });
    let mut buf = vec![0u8; 64 * 1024];
    let mut echoed = 0;
    while echoed < 256 * 1024 {
        echoed += r.read(&mut buf).await.unwrap();
    }

    tunnel.kill_exit();
    let ended = tokio::time::timeout(Duration::from_secs(20), async {
        while matches!(r.read(&mut buf).await, Ok(n) if n > 0) {}
    })
    .await;
    assert!(
        ended.is_ok(),
        "user connection hung after the exit side died"
    );
    writer.abort();

    tunnel.restart_exit();
    let recovered = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let attempt = tokio::time::timeout(
                Duration::from_secs(5),
                echo_roundtrip(tunnel.user_port, b"back again"),
            );
            if let Ok(Ok(data)) = attempt.await {
                if data == b"back again" {
                    return;
                }
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await;
    assert!(
        recovered.is_ok(),
        "tunnel did not recover after the exit side came back"
    );
}

/// A UDP client socket talking to the tunnel's user port.
async fn udp_client(port: u16) -> UdpSocket {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sock.connect(("127.0.0.1", port)).await.unwrap();
    sock
}

/// Sends `payload` and waits for the answer.
async fn udp_roundtrip(sock: &UdpSocket, payload: &[u8], wait: Duration) -> Option<Vec<u8>> {
    sock.send(payload).await.unwrap();
    let mut buf = vec![0u8; 65_536];
    match tokio::time::timeout(wait, sock.recv(&mut buf)).await {
        Ok(Ok(n)) => Some(buf[..n].to_vec()),
        _ => None,
    }
}

/// Several UDP clients at once, each with its own flow, packets from 1 byte to 60 KB.
async fn check_udp_echo(setup: Setup) {
    let target = echo_server().await;
    let tunnel = start(setup, TOKEN, TOKEN, target).await;
    let mut handles = Vec::new();
    for client in 0..8u8 {
        let port = tunnel.user_port;
        handles.push(tokio::spawn(async move {
            let sock = udp_client(port).await;
            for (i, len) in [1, 100, 1400, 8000, 60_000, 1].into_iter().enumerate() {
                let mut payload = pattern(len);
                payload[0] = client;
                if len > 1 {
                    payload[1] = i as u8;
                }
                let got = udp_roundtrip(&sock, &payload, Duration::from_secs(10))
                    .await
                    .unwrap_or_else(|| panic!("client {client}: no answer for {len} bytes"));
                assert!(
                    got == payload,
                    "client {client}: {len}-byte packet corrupted"
                );
            }
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
}

macro_rules! tunnel_tests {
    ($($name:ident: $setup:expr;)*) => {
        $(
            mod $name {
                use super::*;

                #[tokio::test(flavor = "multi_thread")]
                async fn echo() {
                    check_echo($setup).await;
                }

                #[tokio::test(flavor = "multi_thread")]
                async fn rejects_wrong_token() {
                    check_token_mismatch($setup).await;
                }

                #[tokio::test(flavor = "multi_thread")]
                async fn unreachable_target_closes_user_connection() {
                    check_unreachable_target($setup).await;
                }

                #[tokio::test(flavor = "multi_thread")]
                async fn recovers_after_exit_restart() {
                    check_exit_restart($setup).await;
                }

                #[tokio::test(flavor = "multi_thread")]
                async fn udp_echo() {
                    check_udp_echo($setup).await;
                }
            }
        )*

        /// Every setup above, for the throughput run.
        const ALL_SETUPS: &[(&str, Setup)] = &[$((stringify!($name), $setup)),*];
    };
}

tunnel_tests! {
    tcp_reverse: Setup::tcp("reverse");
    tcp_direct: Setup::tcp("direct");
    tcp_reverse_chacha: Setup::tcp("reverse").encryption("chacha20-poly1305");
    tcp_direct_aes: Setup::tcp("direct").encryption("aes-256-gcm");
    tcp_reverse_plain: Setup::tcp("reverse").encryption("none");
    tcp_direct_plain: Setup::tcp("direct").encryption("none");
    mux_reverse: Setup::tcp("reverse").mux();
    mux_direct: Setup::tcp("direct").mux();
    tcpmux_reverse_plain: Setup::tcp("reverse").transport("tcpmux").mux().encryption("none");
    tcpmux_direct_chacha: Setup::tcp("direct").transport("tcpmux").mux().encryption("chacha20-poly1305");
    ws_reverse: Setup::ws("reverse");
    ws_direct: Setup::ws("direct");
    ws_reverse_no_mux: Setup::ws("reverse").no_mux();
    ws_direct_no_mux_plain: Setup::ws("direct").no_mux().encryption("none");
    wss_reverse: Setup::wss("reverse");
    wss_direct: Setup::wss("direct");
    wss_reverse_no_mux: Setup::wss("reverse").no_mux();
    wss_direct_no_mux_chacha: Setup::wss("direct").no_mux().encryption("chacha20-poly1305");
    ws_direct_no_mux_early: Setup::ws("direct").no_mux().early_data();
    ws_reverse_early: Setup::ws("reverse").early_data();
    wss_direct_early: Setup::wss("direct").early_data();
    quic_reverse: Setup::quic("reverse");
    quic_direct: Setup::quic("direct");
    quic_reverse_obfs: Setup::quic("reverse").obfs();
    quic_direct_obfs: Setup::quic("direct").obfs();
    quic_direct_fixed: Setup::quic("direct").bandwidth_mbps(50);
    quic_reverse_fixed: Setup::quic("reverse").bandwidth_mbps(50);
    kcp_reverse: Setup::kcp("reverse");
    kcp_direct: Setup::kcp("direct");
    kcp_reverse_no_mux: Setup::kcp("reverse").no_mux();
    kcp_direct_no_mux_chacha: Setup::kcp("direct").no_mux().encryption("chacha20-poly1305");
    kcp_reverse_fec: Setup::kcp("reverse").fec(10, 3);
    auto_reverse: Setup::tcp("reverse").transport("auto").mux();
    auto_direct: Setup::tcp("direct").transport("auto").mux();
    stealth_reverse: Setup::stealth("reverse");
    stealth_direct: Setup::stealth("direct");
    stealth_reverse_no_mux_chacha: Setup::stealth("reverse").no_mux().encryption("chacha20-poly1305");
    wsmux_reverse: Setup::wsmux("reverse");
    wsmux_direct: Setup::wsmux("direct");
    wssmux_reverse: Setup::wssmux("reverse");
    wssmux_direct: Setup::wssmux("direct");
}

/// Sends `payload` and waits for the answer, resending every 500 ms until one comes or
/// `budget` runs out: a real UDP client retransmits, and the `udp` transport forwards on
/// the unreliable path only, so the first datagrams of a flow may be lost before the path
/// is up.
async fn udp_roundtrip_retry(
    sock: &UdpSocket,
    payload: &[u8],
    budget: Duration,
) -> Option<Vec<u8>> {
    let deadline = Instant::now() + budget;
    while Instant::now() < deadline {
        if let Some(got) = udp_roundtrip(sock, payload, Duration::from_millis(500)).await {
            return Some(got);
        }
    }
    None
}

/// The `udp` transport forwards UDP services only, on the unreliable datagram path. The
/// payloads stay within one datagram (the path does not fragment, and there is no reliable
/// fallback), and the client retransmits as a real UDP client would.
async fn check_udp_transport(setup: Setup) {
    let target = echo_server().await;
    let tunnel = start(setup, TOKEN, TOKEN, target).await;
    let mut handles = Vec::new();
    for client in 0..4u8 {
        let port = tunnel.user_port;
        handles.push(tokio::spawn(async move {
            let sock = udp_client(port).await;
            for (i, len) in [1usize, 64, 512, 1000, 1].into_iter().enumerate() {
                let mut payload = pattern(len);
                payload[0] = client;
                if len > 1 {
                    payload[1] = i as u8;
                }
                let got = udp_roundtrip_retry(&sock, &payload, Duration::from_secs(15))
                    .await
                    .unwrap_or_else(|| {
                        panic!("udp transport client {client}: no answer for {len} bytes")
                    });
                assert!(
                    got == payload,
                    "udp transport client {client}: {len}-byte packet corrupted"
                );
            }
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn udp_transport_reverse() {
    check_udp_transport(Setup::udp("reverse")).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn udp_transport_direct() {
    check_udp_transport(Setup::udp("direct")).await;
}

/// A fallback chain `[tcpmux, kcp]` on both ends converges on the working fallback when the
/// primary cannot come up: a blocker holds the primary's TCP port, so the acceptor's
/// tcpmux listener fails to bind and the dialer's tcpmux attempts stall, and both sides
/// rotate to the kcp (UDP) candidate and carry traffic. An empty chain is unchanged
/// behaviour (every other test here runs with no chain).
#[tokio::test(flavor = "multi_thread")]
async fn fallback_converges_past_a_blocked_primary() {
    let target = echo_server().await;
    let tunnel_port = free_port();
    let user_port = free_port();
    // Hold the primary's TCP port so tcpmux can never bind or complete a handshake there;
    // the kcp candidate rides UDP on the same port and is free to come up.
    let blocker = std::net::TcpListener::bind(("127.0.0.1", tunnel_port)).unwrap();

    let chain = "transport = \"tcpmux\"\n\
                 fallback_transports = [\"kcp\"]\n\
                 fallback_dwell_secs = 10\n\
                 [tunnel.mux]\n\
                 enabled = true\n";
    let tuning =
        "[tuning]\nkeepalive_secs = 5\ndial_timeout_secs = 2\nhandshake_timeout_secs = 2\n";
    let entry = format!(
        "role = \"entry\"\nmode = \"reverse\"\n\
         [[forward]]\nlisten = \"127.0.0.1:{user_port}\"\ntarget = \"127.0.0.1:{target}\"\nprotocol = \"tcp\"\n\
         [tunnel]\nlisten = \"127.0.0.1:{tunnel_port}\"\ntoken = \"{TOKEN}\"\n{chain}{tuning}"
    );
    let exit = format!(
        "role = \"exit\"\nmode = \"reverse\"\n\
         [tunnel]\nremote = \"127.0.0.1:{tunnel_port}\"\ntoken = \"{TOKEN}\"\n{chain}{tuning}"
    );
    let _entry = Side::start(&entry);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let _exit = Side::start(&exit);

    let payload = pattern(4096);
    let deadline = Instant::now() + Duration::from_secs(45);
    loop {
        assert!(
            Instant::now() < deadline,
            "fallback never converged on the working transport"
        );
        if let Ok(got) = echo_roundtrip(user_port, &payload).await {
            if got == payload {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    drop(blocker);
}

/// A `wss` dialer that pins another certificate refuses the listener, so nothing passes.
#[tokio::test(flavor = "multi_thread")]
async fn wss_wrong_pin_is_rejected() {
    let target = echo_server().await;
    let runs = ["reverse", "direct"].map(|mode| {
        tokio::spawn(async move {
            let setup = Setup::wss(mode);
            let (entry, exit) = if mode == "reverse" {
                (setup, setup.wrong_pin())
            } else {
                (setup.wrong_pin(), setup)
            };
            let tunnel = start_pair(entry, exit, TOKEN, TOKEN, target).await;
            expect_closed_without_data(&tunnel).await;
        })
    });
    for run in runs {
        run.await.unwrap();
    }
}

/// Both sides must agree on the WebSocket path; the listener answers any other path
/// with a 404, so nothing passes.
#[tokio::test(flavor = "multi_thread")]
async fn ws_path_mismatch_is_rejected() {
    let target = echo_server().await;
    let runs = ["reverse", "direct"].map(|mode| {
        tokio::spawn(async move {
            let entry = Setup::ws(mode);
            let exit = entry.ws_path("/somewhere-else");
            let tunnel = start_pair(entry, exit, TOKEN, TOKEN, target).await;
            expect_closed_without_data(&tunnel).await;
        })
    });
    for run in runs {
        run.await.unwrap();
    }
}

/// Mux must be on or off on both sides; a mismatch fails the handshake, it does not
/// turn into garbage on the wire.
#[tokio::test(flavor = "multi_thread")]
async fn mux_mismatch_is_rejected() {
    let target = echo_server().await;
    let mut cases = Vec::new();
    for mode in ["reverse", "direct"] {
        cases.push((Setup::tcp(mode).mux(), Setup::tcp(mode)));
        cases.push((Setup::tcp(mode), Setup::tcp(mode).mux()));
    }
    let runs = cases.into_iter().map(|(entry, exit)| {
        tokio::spawn(async move {
            let tunnel = start_pair(entry, exit, TOKEN, TOKEN, target).await;
            expect_closed_without_data(&tunnel).await;
        })
    });
    for run in runs.collect::<Vec<_>>() {
        run.await.unwrap();
    }
}

/// Rough localhost throughput check: `cargo test --release -- --ignored --nocapture`.
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn throughput() {
    kariz::allocator::tune();
    for &(name, setup) in ALL_SETUPS {
        let target = echo_server().await;
        let tunnel = start(setup, TOKEN, TOKEN, target).await;
        let payload = pattern(256 * 1024 * 1024);
        let start = Instant::now();
        let got = echo_roundtrip(tunnel.user_port, &payload).await.unwrap();
        let secs = start.elapsed().as_secs_f64();
        assert_eq!(got.len(), payload.len());
        let mbps = (payload.len() as f64 * 8.0) / secs / 1e6;
        println!("{name}: 256 MiB echoed in {secs:.2}s = {mbps:.0} Mbit/s each way");
    }
}

/// nginx as a stand-in for a CDN: it proxies the WebSocket (optionally terminating TLS)
/// and closes connections idle for `idle_secs`. Killed on drop.
struct Nginx {
    child: std::process::Child,
    port: u16,
    dir: std::path::PathBuf,
}

impl Nginx {
    /// The nginx binary, or `None` to skip nginx tests. `KARIZ_REQUIRE_NGINX=1` (set in
    /// CI) turns a missing nginx into a failure instead.
    fn binary() -> Option<String> {
        let bin = std::env::var("KARIZ_NGINX").unwrap_or_else(|_| "nginx".into());
        let found = std::process::Command::new(&bin)
            .arg("-v")
            .output()
            .is_ok_and(|o| o.status.success());
        if found {
            return Some(bin);
        }
        assert!(
            std::env::var_os("KARIZ_REQUIRE_NGINX").is_none(),
            "nginx not found ({bin}) but KARIZ_REQUIRE_NGINX is set"
        );
        eprintln!("nginx not found, skipping (set KARIZ_NGINX to its path)");
        None
    }

    fn start(bin: &str, upstream: u16, path: &str, tls: bool, idle_secs: u64) -> Self {
        let port = free_port();
        let dir = std::env::temp_dir().join(format!("kariz-nginx-{}-{port}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (listen, certs) = if tls {
            let cert = test_cert();
            (
                format!("{port} ssl"),
                format!(
                    "ssl_certificate {};\nssl_certificate_key {};",
                    cert.cert.display(),
                    cert.key.display()
                ),
            )
        } else {
            (port.to_string(), String::new())
        };
        let d = dir.display();
        let conf = format!(
            r#"
            daemon off;
            master_process off;
            worker_processes 1;
            pid {d}/nginx.pid;
            error_log {d}/error.log info;
            events {{ worker_connections 256; }}
            http {{
                access_log off;
                client_body_temp_path {d}/body;
                proxy_temp_path {d}/proxy;
                fastcgi_temp_path {d}/fastcgi;
                uwsgi_temp_path {d}/uwsgi;
                scgi_temp_path {d}/scgi;
                map $http_upgrade $connection_upgrade {{ default upgrade; '' close; }}
                server {{
                    listen 127.0.0.1:{listen};
                    {certs}
                    location {path} {{
                        proxy_pass http://127.0.0.1:{upstream};
                        proxy_http_version 1.1;
                        proxy_set_header Upgrade $http_upgrade;
                        proxy_set_header Connection $connection_upgrade;
                        proxy_set_header Host $host;
                        proxy_set_header X-Forwarded-For $remote_addr;
                        proxy_buffering off;
                        proxy_read_timeout {idle_secs}s;
                        proxy_send_timeout {idle_secs}s;
                    }}
                }}
            }}
            "#
        );
        let conf_path = dir.join("nginx.conf");
        std::fs::write(&conf_path, conf).unwrap();
        let child = std::process::Command::new(bin)
            .arg("-p")
            .arg(&dir)
            .arg("-e")
            .arg(dir.join("error.log"))
            .arg("-c")
            .arg(&conf_path)
            .stdin(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let ready = (0..100).any(|_| {
            std::thread::sleep(Duration::from_millis(50));
            std::net::TcpStream::connect(("127.0.0.1", port)).is_ok()
        });
        let log = || std::fs::read_to_string(dir.join("error.log")).unwrap_or_default();
        assert!(ready, "nginx did not start:\n{}", log());
        Self { child, port, dir }
    }
}

impl Drop for Nginx {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Idle time nginx allows before it closes a proxied WebSocket.
const NGINX_IDLE_SECS: u64 = 3;

/// Runs `entry` / `exit` through nginx and keeps one user connection idle for longer
/// than nginx allows. With `survives`, the same connection must still work afterwards
/// (mux pings kept the WebSocket busy); without, it must be broken (the control case,
/// proving the idle timeout is real). New connections must work in both cases.
async fn check_through_nginx(entry: Setup, exit: Setup, survives: bool) {
    let Some(bin) = Nginx::binary() else {
        return;
    };
    let dialer = if entry.mode == "direct" { entry } else { exit };
    let tls = dialer.transport == "wss";
    let path = dialer.ws_path;
    let target = echo_server().await;
    let tunnel = start_via(entry, exit, TOKEN, TOKEN, target, |upstream| {
        let nginx = Nginx::start(&bin, upstream, path, tls, NGINX_IDLE_SECS);
        (nginx.port, Some(Box::new(nginx)))
    })
    .await;

    // Bulk data through the proxy.
    let payload = pattern(4 * 1024 * 1024);
    let got = echo_roundtrip(tunnel.user_port, &payload).await.unwrap();
    assert!(got == payload, "payload corrupted through nginx");

    // UDP rides the same WebSocket sessions.
    let sock = udp_client(tunnel.user_port).await;
    for len in [1, 1400, 30_000] {
        let packet = pattern(len);
        let got = udp_roundtrip(&sock, &packet, Duration::from_secs(10)).await;
        assert!(
            got.as_deref() == Some(&packet[..]),
            "UDP through nginx ({len} bytes)"
        );
    }

    let mut user = TcpStream::connect(("127.0.0.1", tunnel.user_port))
        .await
        .unwrap();
    let mut buf = [0u8; 6];
    user.write_all(b"before").await.unwrap();
    user.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"before");

    tokio::time::sleep(Duration::from_secs(NGINX_IDLE_SECS + 3)).await;
    let after = tokio::time::timeout(Duration::from_secs(5), async {
        user.write_all(b"after!").await?;
        user.read_exact(&mut buf).await?;
        std::io::Result::Ok(buf)
    })
    .await;
    match after {
        Ok(Ok(buf)) => assert!(
            survives,
            "idle connection survived: control case is broken ({buf:?})"
        ),
        _ => assert!(
            !survives,
            "idle connection did not survive nginx's idle timeout"
        ),
    }

    let recovered = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let attempt = tokio::time::timeout(
                Duration::from_secs(5),
                echo_roundtrip(tunnel.user_port, b"again"),
            );
            if let Ok(Ok(data)) = attempt.await {
                if data == b"again" {
                    return;
                }
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await;
    assert!(recovered.is_ok(), "no new connections through nginx");
}

/// The tunnel behind nginx as a CDN stand-in (`cargo test nginx`; CI job `cdn`).
mod nginx {
    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn ws_direct_survives_idle() {
        let setup = Setup::ws("direct").keepalive(1).early_data();
        check_through_nginx(setup, setup, true).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn ws_reverse_survives_idle() {
        let setup = Setup::ws("reverse").keepalive(1).early_data();
        check_through_nginx(setup, setup, true).await;
    }

    /// Like a CDN: TLS from the dialer to nginx, plain WebSocket from nginx to the origin.
    #[tokio::test(flavor = "multi_thread")]
    async fn wss_to_proxy_ws_to_origin() {
        let exit = Setup::ws("direct").keepalive(1);
        let entry = Setup::wss("direct").keepalive(1).early_data();
        check_through_nginx(entry, exit, true).await;
    }

    /// Control: with the default 30 s keepalive nginx does cut the idle connection, so
    /// the cases above prove something.
    #[tokio::test(flavor = "multi_thread")]
    async fn control_idle_connections_are_cut_without_frequent_pings() {
        let setup = Setup::ws("direct");
        check_through_nginx(setup, setup, false).await;
    }
}

/// A quiet flow is closed after `udp_timeout_secs` on both sides: the next packet from
/// the same client opens a new flow, which reaches the target from a new source port.
#[tokio::test(flavor = "multi_thread")]
async fn udp_idle_flows_are_closed() {
    let target = udp_port_reporter().await;
    let runs = [Setup::tcp("direct").mux(), Setup::tcp("reverse")].map(|setup| {
        tokio::spawn(async move {
            let setup = setup.udp_timeout(5);
            let tunnel = start(setup, TOKEN, TOKEN, target).await;
            let sock = udp_client(tunnel.user_port).await;
            let wait = Duration::from_secs(10);
            let first = udp_roundtrip(&sock, b"a", wait)
                .await
                .expect("first answer");
            tokio::time::sleep(Duration::from_secs(2)).await;
            let again = udp_roundtrip(&sock, b"b", wait)
                .await
                .expect("second answer");
            assert_eq!(first, again, "{setup:?}: same flow within the timeout");
            tokio::time::sleep(Duration::from_secs(7)).await;
            let later = udp_roundtrip(&sock, b"c", wait)
                .await
                .expect("answer after idle");
            assert_ne!(first, later, "{setup:?}: new flow after the timeout");
        })
    });
    for run in runs {
        run.await.unwrap();
    }
}

/// Clients beyond `udp_max_flows` are not served; the others keep working.
#[tokio::test(flavor = "multi_thread")]
async fn udp_max_flows_is_enforced() {
    let target = echo_server().await;
    let tunnel = start(
        Setup::tcp("direct").mux().udp_max_flows(2),
        TOKEN,
        TOKEN,
        target,
    )
    .await;
    let wait = Duration::from_secs(5);
    let (a, b, c) = (
        udp_client(tunnel.user_port).await,
        udp_client(tunnel.user_port).await,
        udp_client(tunnel.user_port).await,
    );
    assert!(udp_roundtrip(&a, b"a", wait).await.is_some());
    assert!(udp_roundtrip(&b, b"b", wait).await.is_some());
    let short = Duration::from_secs(2);
    assert!(
        udp_roundtrip(&c, b"c", short).await.is_none(),
        "third flow must be refused"
    );
    assert!(udp_roundtrip(&a, b"a2", wait).await.is_some());
}

/// An open connection through the tunnel that has echoed once: it holds a stream.
async fn held_connection(port: u16) -> TcpStream {
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    s.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(5), s.read_exact(&mut buf))
        .await
        .expect("echo in time")
        .unwrap();
    assert_eq!(&buf, b"ping");
    s
}

/// A client address gets `max_conns_per_ip` connections; more are closed at once, and a
/// slot that frees up can be used again.
#[tokio::test(flavor = "multi_thread")]
async fn connections_beyond_the_per_address_limit_are_closed() {
    let target = echo_server().await;
    let setup = Setup::tcp("direct")
        .transport("tcpmux")
        .mux()
        .max_conns_per_ip(2);
    let tunnel = start(setup, TOKEN, TOKEN, target).await;
    let first = held_connection(tunnel.user_port).await;
    let _second = held_connection(tunnel.user_port).await;
    let started = std::time::Instant::now();
    expect_closed_without_data(&tunnel).await;
    assert!(started.elapsed() < Duration::from_secs(2), "closed at once");
    drop(first);
    tokio::time::sleep(Duration::from_millis(200)).await;
    held_connection(tunnel.user_port).await;
}

/// A target that reads a PROXY header (v1 or v2), the way Xray with `acceptProxyProtocol`
/// does, then the client's `hello`, and answers with the two addresses the header named
/// (`v1 SRC DST` / `v2 SRC DST`), or `none` when the connection had no header.
async fn proxy_header_reporter() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else {
                continue;
            };
            tokio::spawn(async move {
                let answer = read_proxy_header(&mut s).await;
                let _ = s.write_all(answer.as_bytes()).await;
                let _ = s.shutdown().await;
            });
        }
    });
    port
}

async fn read_proxy_header(s: &mut TcpStream) -> String {
    // Both headers and the client's `hello` are at least 5 bytes long.
    let mut first = [0u8; 5];
    s.read_exact(&mut first).await.unwrap();
    let answer = if &first == b"PROXY" {
        let mut line = first.to_vec();
        while !line.ends_with(b"\r\n") {
            line.push(s.read_u8().await.unwrap());
            assert!(line.len() <= 107, "a v1 header is at most 107 bytes");
        }
        let line = String::from_utf8(line).unwrap();
        let f: Vec<&str> = line.trim_end().split(' ').collect();
        assert_eq!((f.len(), f[1]), (6, "TCP4"), "{line:?}");
        format!("v1 {}:{} {}:{}", f[2], f[4], f[3], f[5])
    } else if &first == b"\r\n\r\n\0" {
        let mut head = [0u8; 11];
        s.read_exact(&mut head).await.unwrap();
        assert_eq!(&head[..7], b"\r\nQUIT\n", "the rest of the signature");
        assert_eq!((head[7], head[8]), (0x21, 0x11), "v2 PROXY, TCP over IPv4");
        let len = u16::from_be_bytes([head[9], head[10]]);
        assert_eq!(len, 12);
        let mut a = [0u8; 12];
        s.read_exact(&mut a).await.unwrap();
        let ip = |at: usize| std::net::Ipv4Addr::new(a[at], a[at + 1], a[at + 2], a[at + 3]);
        let port = |at: usize| u16::from_be_bytes([a[at], a[at + 1]]);
        format!("v2 {}:{} {}:{}", ip(0), port(8), ip(4), port(10))
    } else {
        assert_eq!(&first, b"hello");
        return "none".into();
    };
    // Then the user's own bytes, untouched.
    let mut hello = [0u8; 5];
    s.read_exact(&mut hello).await.unwrap();
    assert_eq!(&hello, b"hello");
    answer
}

/// What the target behind the tunnel heard about a user connection.
async fn proxy_header_seen(tunnel: &Tunnel) -> (String, std::net::SocketAddr) {
    let mut s = TcpStream::connect(("127.0.0.1", tunnel.user_port))
        .await
        .unwrap();
    let me = s.local_addr().unwrap();
    s.write_all(b"hello").await.unwrap();
    let mut answer = String::new();
    tokio::time::timeout(Duration::from_secs(10), s.read_to_string(&mut answer))
        .await
        .expect("an answer in time")
        .unwrap();
    (answer, me)
}

/// With `proxy_protocol`, the target sees each user's own address and port (and the
/// entry port they connected to), over every way an open request travels: in the hello
/// (direct, no mux), on a pooled link (reverse, no mux), in a mux SYN and on a QUIC
/// stream.
#[tokio::test(flavor = "multi_thread")]
async fn the_target_sees_the_users_address_in_a_proxy_header() {
    let target = proxy_header_reporter().await;
    for (setup, version) in [
        (Setup::tcp("direct"), "v1"),
        (Setup::tcp("reverse"), "v2"),
        (Setup::tcp("direct").transport("tcpmux").mux(), "v2"),
        (Setup::tcp("reverse").transport("tcpmux").mux(), "v1"),
        (Setup::quic("direct"), "v2"),
        (Setup::stealth("direct"), "v2"),
        (Setup::wsmux("reverse"), "v1"),
        (Setup::wssmux("direct"), "v2"),
    ] {
        let tunnel = start(setup.proxy_protocol(version), TOKEN, TOKEN, target).await;
        for _ in 0..3 {
            let (answer, me) = proxy_header_seen(&tunnel).await;
            let want = format!("{version} {me} 127.0.0.1:{}", tunnel.user_port);
            assert_eq!(answer, want, "{setup:?}");
        }
    }
}

/// A rule without `proxy_protocol` sends the target nothing but the user's bytes.
#[tokio::test(flavor = "multi_thread")]
async fn without_the_option_the_target_gets_no_header() {
    let target = proxy_header_reporter().await;
    for setup in [
        Setup::tcp("direct"),
        Setup::tcp("direct").transport("tcpmux").mux(),
    ] {
        let tunnel = start(setup, TOKEN, TOKEN, target).await;
        assert_eq!(proxy_header_seen(&tunnel).await.0, "none", "{setup:?}");
    }
}

/// The case of a busy evening: every stream of every session is taken. New connections
/// fail (after the open timeout) while the ones already open keep working.
#[tokio::test(flavor = "multi_thread")]
async fn a_full_tunnel_fails_new_connections_and_keeps_the_open_ones() {
    let target = echo_server().await;
    let setup = Setup::tcp("direct")
        .transport("tcpmux")
        .mux()
        .mux_connections(1)
        .max_streams(2)
        .timeouts(1);
    let tunnel = start(setup, TOKEN, TOKEN, target).await;
    let mut a = held_connection(tunnel.user_port).await;
    let _b = held_connection(tunnel.user_port).await;
    expect_closed_without_data(&tunnel).await;
    a.write_all(b"more").await.unwrap();
    let mut buf = [0u8; 4];
    a.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"more");
}

/// A TCP proxy that forwards at most `rate` bytes per second each way, with small
/// socket buffers, like a slow link between the servers: a sender that writes faster
/// queues the rest in its own socket buffer, as it would on a real path.
fn throttled_proxy(to: u16, rate: u64) -> u16 {
    let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
    socket.set_recv_buffer_size(64 * 1024).unwrap();
    socket.set_reuse_address(true).unwrap();
    socket
        .bind(
            &"127.0.0.1:0"
                .parse::<std::net::SocketAddr>()
                .unwrap()
                .into(),
        )
        .unwrap();
    socket.listen(64).unwrap();
    socket.set_nonblocking(true).unwrap();
    let listener = TcpListener::from_std(socket.into()).unwrap();
    let port = listener.local_addr().unwrap().port();
    async fn pump(
        mut from: tokio::net::tcp::OwnedReadHalf,
        mut to: tokio::net::tcp::OwnedWriteHalf,
        rate: u64,
    ) {
        let start = Instant::now();
        let mut sent = 0u64;
        let mut buf = vec![0u8; 16 * 1024];
        while let Ok(n @ 1..) = from.read(&mut buf).await {
            if to.write_all(&buf[..n]).await.is_err() {
                return;
            }
            sent += n as u64;
            let due = start + Duration::from_secs_f64(sent as f64 / rate as f64);
            tokio::time::sleep_until(due.into()).await;
        }
        let _ = to.shutdown().await;
    }
    tokio::spawn(async move {
        while let Ok((down, _)) = listener.accept().await {
            let up = tokio::net::TcpSocket::new_v4().unwrap();
            up.set_recv_buffer_size(64 * 1024).unwrap();
            let Ok(up) = up.connect(([127, 0, 0, 1], to).into()).await else {
                continue;
            };
            let (dr, dw) = down.into_split();
            let (ur, uw) = up.into_split();
            tokio::spawn(pump(dr, uw, rate));
            tokio::spawn(pump(ur, dw, rate));
        }
    });
    port
}

fn percentile(sorted: &[Duration], p: f64) -> Duration {
    sorted[((sorted.len() - 1) as f64 * p).round() as usize]
}

/// UDP round trips while idle and while a bulk TCP transfer shares the same mux session,
/// over a throttled link. Returns (idle, loaded) sorted round trips and lost pings.
async fn udp_rtt_under_load(
    setup: Setup,
    rate: u64,
    bulk: usize,
) -> (Vec<Duration>, Vec<Duration>, usize) {
    let target = echo_server().await;
    let tunnel = start_via(setup, setup, TOKEN, TOKEN, target, |upstream| {
        (throttled_proxy(upstream, rate), None)
    })
    .await;
    let sock = udp_client(tunnel.user_port).await;
    async fn pings(sock: &UdpSocket, until: impl Fn() -> bool) -> (Vec<Duration>, usize) {
        let (mut rtts, mut lost) = (Vec::new(), 0);
        let mut seq = 0u32;
        while !until() {
            seq += 1;
            let sent = Instant::now();
            match udp_roundtrip(sock, &seq.to_be_bytes(), Duration::from_secs(2)).await {
                Some(r) if r == seq.to_be_bytes() => rtts.push(sent.elapsed()),
                _ => lost += 1,
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        rtts.sort();
        (rtts, lost)
    }
    let idle_until = Instant::now() + Duration::from_secs(2);
    let (idle, _) = pings(&sock, || Instant::now() >= idle_until).await;

    let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let d = done.clone();
    let port = tunnel.user_port;
    // Several transfers at once, like a few downloads next to the real-time traffic.
    let transfer = tokio::spawn(async move {
        let each = bulk / 4;
        let transfers = (0..4).map(|_| {
            tokio::spawn(async move {
                let got = echo_roundtrip(port, &pattern(each)).await.unwrap();
                assert_eq!(got.len(), each);
            })
        });
        for t in transfers.collect::<Vec<_>>() {
            t.await.unwrap();
        }
        d.store(true, std::sync::atomic::Ordering::SeqCst);
    });
    // Let the transfer fill the buffers first.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let (loaded, lost) = pings(&sock, || done.load(std::sync::atomic::Ordering::SeqCst)).await;
    transfer.await.unwrap();
    drop(tunnel);
    (idle, loaded, lost)
}

/// Latency report: `cargo test --release --test tunnel udp_latency -- --ignored --nocapture`.
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn udp_latency_under_load() {
    // 20 Mbit/s link, 12 MiB echoed (about 5 s each way at once).
    let (rate, bulk) = (2_500_000, 12 << 20);
    for (name, setup) in [
        (
            "tcpmux",
            Setup::tcp("direct")
                .transport("tcpmux")
                .mux()
                .mux_connections(1),
        ),
        ("ws + mux", Setup::ws("direct").mux_connections(1)),
    ] {
        let (idle, loaded, lost) = udp_rtt_under_load(setup, rate, bulk).await;
        let ms = |d: Duration| d.as_secs_f64() * 1000.0;
        println!(
            "{name}: idle p50 {:.1} ms p99 {:.1} ms | under bulk TCP p50 {:.1} ms p99 {:.1} ms max {:.1} ms, {} pings, {lost} lost",
            ms(percentile(&idle, 0.5)),
            ms(percentile(&idle, 0.99)),
            ms(percentile(&loaded, 0.5)),
            ms(percentile(&loaded, 0.99)),
            ms(*loaded.last().unwrap()),
            loaded.len()
        );
    }
}

/// UDP packets per second through the tunnel, 8 clients each keeping 32 packets in
/// flight: `cargo test --release --test tunnel udp_throughput -- --ignored --nocapture`.
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn udp_throughput() {
    kariz::allocator::tune();
    const CLIENTS: usize = 8;
    const WINDOW: usize = 32;
    let run = Duration::from_secs(3);
    for (name, setup) in [
        ("tcpmux", Setup::tcp("direct").transport("tcpmux").mux()),
        ("tcp, no mux", Setup::tcp("direct")),
        ("ws + mux", Setup::ws("direct")),
        ("wss + mux", Setup::wss("direct")),
        ("quic", Setup::quic("direct")),
        ("kcp + mux", Setup::kcp("direct")),
    ] {
        for size in [100usize, 1400] {
            let target = echo_server().await;
            let tunnel = start(setup, TOKEN, TOKEN, target).await;
            let deadline = Instant::now() + run;
            let clients = (0..CLIENTS).map(|_| {
                let port = tunnel.user_port;
                tokio::spawn(async move {
                    let sock = udp_client(port).await;
                    let packet = vec![7u8; size];
                    let mut buf = vec![0u8; 2048];
                    let mut received = 0u64;
                    for _ in 0..WINDOW {
                        sock.send(&packet).await.unwrap();
                    }
                    while Instant::now() < deadline {
                        match tokio::time::timeout(Duration::from_millis(100), sock.recv(&mut buf))
                            .await
                        {
                            Ok(Ok(_)) => {
                                received += 1;
                                sock.send(&packet).await.unwrap();
                            }
                            // Lost packets would shrink the window: refill it.
                            _ => {
                                for _ in 0..WINDOW {
                                    sock.send(&packet).await.unwrap();
                                }
                            }
                        }
                    }
                    received
                })
            });
            let mut total = 0;
            for c in clients.collect::<Vec<_>>() {
                total += c.await.unwrap();
            }
            let pps = total as f64 / run.as_secs_f64();
            println!(
                "{name}, {size}-byte packets: {:.0} packets/s each way ({:.0} Mbit/s)",
                pps,
                pps * size as f64 * 8.0 / 1e6
            );
        }
    }
}

/// UDP round trip on an idle tunnel versus straight to the target:
/// `cargo test --release --test tunnel udp_idle_latency -- --ignored --nocapture`.
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn udp_idle_latency() {
    async fn rtts(port: u16) -> Vec<Duration> {
        let sock = udp_client(port).await;
        let mut out = Vec::new();
        for i in 0..2000u32 {
            let sent = Instant::now();
            udp_roundtrip(&sock, &i.to_be_bytes(), Duration::from_secs(2))
                .await
                .expect("answer");
            out.push(sent.elapsed());
        }
        out.sort();
        out
    }
    let us = |d: Duration| d.as_secs_f64() * 1e6;
    let target = echo_server().await;
    let direct = rtts(target).await;
    println!(
        "direct to the target: p50 {:.0} us, p99 {:.0} us",
        us(percentile(&direct, 0.5)),
        us(percentile(&direct, 0.99))
    );
    for (name, setup) in [
        ("tcpmux", Setup::tcp("direct").transport("tcpmux").mux()),
        ("tcp, no mux", Setup::tcp("direct")),
        ("wss + mux", Setup::wss("direct")),
        ("quic", Setup::quic("direct")),
        ("kcp + mux", Setup::kcp("direct")),
    ] {
        let tunnel = start(setup, TOKEN, TOKEN, target).await;
        let t = rtts(tunnel.user_port).await;
        println!(
            "{name}: p50 {:.0} us (+{:.0}), p99 {:.0} us",
            us(percentile(&t, 0.5)),
            us(percentile(&t, 0.5)) - us(percentile(&direct, 0.5)),
            us(percentile(&t, 0.99))
        );
    }
}

/// A target for the lossy-link benchmark: each TCP connection gets an endless download,
/// UDP packets on the same port are echoed.
async fn download_server() -> u16 {
    loop {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let Ok(udp) = UdpSocket::bind(("127.0.0.1", port)).await else {
            continue;
        };
        tokio::spawn(async move {
            while let Ok((mut s, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let chunk = pattern(64 * 1024);
                    while s.write_all(&chunk).await.is_ok() {}
                });
            }
        });
        tokio::spawn(udp_echo(udp));
        return port;
    }
}

/// Download rate in Mbit/s, measured over `window` after `warmup`.
async fn download(port: u16, warmup: Duration, window: Duration) -> f64 {
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let mut buf = vec![0u8; 256 * 1024];
    let from = Instant::now() + warmup;
    let until = from + window;
    let mut total = 0;
    while let Ok(read) = tokio::time::timeout_at(until.into(), s.read(&mut buf)).await {
        let n = read.expect("download failed");
        assert!(n > 0, "download ended early");
        if Instant::now() >= from {
            total += n;
        }
    }
    total as f64 * 8.0 / window.as_secs_f64() / 1e6
}

/// UDP round trips of a flow, sorted, and how many packets were sent.
struct Pings {
    rtts: Vec<Duration>,
    sent: usize,
}

impl std::fmt::Display for Pings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ms = |p| percentile(&self.rtts, p).as_secs_f64() * 1000.0;
        let lost = 100.0 * (1.0 - self.rtts.len() as f64 / self.sent as f64);
        if self.rtts.is_empty() {
            return write!(f, "{:>34}", "no answers");
        }
        write!(
            f,
            "p50 {:>4.0} p99 {:>4.0} ms, {lost:>4.1} % lost",
            ms(0.5),
            ms(0.99)
        )
    }
}

/// Sends `count` 100-byte packets on one flow, one every `every` without waiting for
/// answers (a lost packet is lost, not waited for), like a game or a voice call.
async fn pings(port: u16, count: u32, every: Duration) -> Pings {
    let sock = std::sync::Arc::new(udp_client(port).await);
    let deadline = Instant::now() + every * count + Duration::from_secs(2);
    let receiver = {
        let sock = sock.clone();
        tokio::spawn(async move {
            let mut got = Vec::new();
            let mut buf = [0u8; 2048];
            while let Ok(Ok(4..)) =
                tokio::time::timeout_at(deadline.into(), sock.recv(&mut buf)).await
            {
                got.push((
                    u32::from_be_bytes(buf[..4].try_into().unwrap()),
                    Instant::now(),
                ));
            }
            got
        })
    };
    let mut sent = Vec::new();
    let mut packet = [0u8; 100];
    let mut interval = tokio::time::interval(every);
    for seq in 0..count {
        interval.tick().await;
        packet[..4].copy_from_slice(&seq.to_be_bytes());
        sent.push(Instant::now());
        let _ = sock.send(&packet).await;
    }
    let mut seen = std::collections::HashSet::new();
    let mut rtts: Vec<_> = receiver
        .await
        .unwrap()
        .into_iter()
        .filter(|&(seq, _)| seen.insert(seq))
        .map(|(seq, at)| at - sent[seq as usize])
        .collect();
    rtts.sort();
    Pings {
        rtts,
        sent: count as usize,
    }
}

/// One cell of the lossy-link benchmark.
struct LinkRun {
    mbps: f64,
    idle: Pings,
    loaded: Pings,
    link: Counts,
}

fn is_udp(setup: Setup) -> bool {
    matches!(setup.transport, "quic" | "kcp")
}

/// Runs the tunnel over an emulated link (UDP for `quic` and `kcp`, TCP otherwise): UDP pings on
/// the idle tunnel, then a download with pings next to it.
async fn over_link(setup: Setup, imp: Impairment) -> LinkRun {
    const WARMUP: Duration = Duration::from_secs(3);
    const EVERY: Duration = Duration::from_millis(20);
    const PINGS: u32 = 500;
    let target = download_server().await;
    let mut stats = None;
    let tunnel = start_via(setup, setup, TOKEN, TOKEN, target, |upstream| {
        let (port, link_stats, proxy): (_, _, Proxy) = if is_udp(setup) {
            let link = UdpLink::start(upstream, imp);
            (link.port, link.stats(), Box::new(link))
        } else {
            let link = TcpLink::start(upstream, imp);
            (link.port, link.stats(), Box::new(link))
        };
        stats = Some(link_stats);
        (port, Some(proxy))
    })
    .await;
    let idle = pings(tunnel.user_port, PINGS, EVERY).await;
    let window = EVERY * PINGS;
    let download = tokio::spawn(download(tunnel.user_port, WARMUP, window));
    tokio::time::sleep(WARMUP).await;
    let loaded = pings(tunnel.user_port, PINGS, EVERY).await;
    let mbps = download.await.unwrap();
    LinkRun {
        mbps,
        idle,
        loaded,
        link: stats.unwrap().counts(),
    }
}

/// Transports over a long, lossy path: 60 ms RTT, 50 Mbit/s each
/// way with a 50 ms queue, random loss of 0, 1 and 5 % in both directions:
/// `cargo test --release --test tunnel lossy_link -- --ignored --nocapture`.
/// `KARIZ_BENCH_LOSS=1` (in percent) runs one loss rate only, `KARIZ_BENCH_ONLY=kcp` the
/// rows whose name contains `kcp`.
///
/// Streams get a 4 MiB window, above the path's bandwidth-delay product plus its queue
/// (about 690 KB), so congestion control sets the rate. With the default 256 KiB a
/// stream cannot go faster than 256 KiB per round trip, about 30 Mbit/s here; the
/// `default window` rows show that cap.
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn lossy_link() {
    link::fine_timers();
    const WINDOW: usize = 4 << 20;
    let tcpmux = Setup::tcp("direct").transport("tcpmux").mux();
    let setups = [
        ("tcpmux", tcpmux.stream_window(WINDOW)),
        ("quic cubic", Setup::quic("direct").stream_window(WINDOW)),
        (
            "quic bbr",
            Setup::quic("direct")
                .congestion("bbr")
                .stream_window(WINDOW),
        ),
        (
            "quic fixed 50",
            Setup::quic("direct")
                .bandwidth_mbps(50)
                .stream_window(WINDOW),
        ),
        ("kcp fast2", Setup::kcp("direct").stream_window(WINDOW)),
        (
            "kcp fast2, fec 10/3",
            Setup::kcp("direct").fec(10, 3).stream_window(WINDOW),
        ),
        (
            "kcp fast2, window 256",
            Setup::kcp("direct")
                .kcp_options("send_window = 256\nrecv_window = 256")
                .stream_window(WINDOW),
        ),
    ];
    let only = std::env::var("KARIZ_BENCH_ONLY").unwrap_or_default();
    let default_window = [
        ("tcpmux, default window", tcpmux),
        ("quic cubic, default window", Setup::quic("direct")),
    ];
    let losses: Vec<f64> = match std::env::var("KARIZ_BENCH_LOSS") {
        Ok(percent) => vec![percent.parse::<f64>().expect("KARIZ_BENCH_LOSS") / 100.0],
        Err(_) => vec![0.0, 0.01, 0.05],
    };
    println!(
        "RTT 60 ms, 50 Mbit/s, 50 ms queue. Download over 10 s; UDP: 100-byte packets every 20 ms"
    );
    println!(
        "{:<5} {:<26} {:>13}   {:<33}   {:<33}   link (lost / queue drops)",
        "loss", "transport", "download", "UDP, idle tunnel", "UDP, during the download"
    );
    for loss in losses {
        let extra = if loss == 0.0 {
            &default_window[..]
        } else {
            &[]
        };
        for &(name, setup) in setups.iter().chain(extra) {
            if !name.contains(only.as_str()) {
                continue;
            }
            let imp = Impairment {
                delay: Duration::from_millis(30),
                loss,
                rate: 50_000_000,
                queue: Duration::from_millis(50),
                ..Default::default()
            };
            let run = over_link(setup, imp).await;
            println!(
                "{:<5} {name:<26} {:>7.1} Mbit/s   {}   {}   {} / {}",
                format!("{} %", loss * 100.0),
                run.mbps,
                run.idle,
                run.loaded,
                run.link.lost,
                run.link.dropped
            );
        }
    }
}

/// Round trips of game-like traffic on one flow.
struct Game {
    /// Round trips of the packets that came back, sorted.
    rtts: Vec<Duration>,
    sent: usize,
    /// Longest run of consecutive packets that never came back.
    longest_loss: usize,
    /// Round trip of every packet by sequence number; `None`: never came back.
    by_seq: Vec<Option<Duration>>,
    /// The interval the packets were sent at.
    every: Duration,
}

impl Game {
    /// Where the longest loss run starts, and when packets slower than `slow` were
    /// sent (seconds into the run), for `KARIZ_BENCH_DETAIL`.
    fn detail(&self, slow: Duration) -> String {
        let every = self.every.as_secs_f64();
        let mut longest = (0, 0);
        let mut run_start = 0;
        for (seq, rtt) in self.by_seq.iter().enumerate() {
            if rtt.is_some() {
                run_start = seq + 1;
            } else if seq + 1 - run_start > longest.1 {
                longest = (run_start, seq + 1 - run_start);
            }
        }
        let slow: Vec<f64> = (self.by_seq.iter().enumerate())
            .filter(|(_, rtt)| rtt.is_some_and(|r| r > slow))
            .map(|(seq, _)| seq as f64 * every)
            .collect();
        let spans = slow
            .chunk_by(|a, b| b - a < 0.5)
            .map(|s| format!("{:.1}-{:.1} s ({})", s[0], s[s.len() - 1], s.len()));
        format!(
            "longest loss run: {} from {:.1} s; slow packets sent at: {}",
            longest.1,
            longest.0 as f64 * every,
            spans.collect::<Vec<_>>().join(", ")
        )
    }
}

impl std::fmt::Display for Game {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.rtts.is_empty() {
            return write!(f, "{:>44}", "no answers");
        }
        let ms = |p| percentile(&self.rtts, p).as_secs_f64() * 1000.0;
        let delivered = 100.0 * self.rtts.len() as f64 / self.sent as f64;
        write!(
            f,
            "{:>4.0} {:>4.0} {:>4.0} ms {delivered:>6.2} % {:>3}",
            ms(0.5),
            ms(0.99),
            ms(0.999),
            self.longest_loss
        )
    }
}

/// Game traffic: 128-byte packets at 64 Hz on one flow for
/// `duration`, each echoed by the target, without waiting for answers.
async fn game(port: u16, duration: Duration) -> Game {
    udp_flow(port, 128, Duration::from_micros(15_625), duration).await
}

/// One UDP flow of `size`-byte packets, one every `every` for `duration`, each echoed by the
/// target, sent without waiting for answers (a lost packet is lost, not waited for).
async fn udp_flow(port: u16, size: usize, every: Duration, duration: Duration) -> Game {
    let count = (duration.as_secs_f64() / every.as_secs_f64()) as u32;
    let sock = std::sync::Arc::new(udp_client(port).await);
    let deadline = Instant::now() + duration + Duration::from_secs(2);
    let receiver = {
        let sock = sock.clone();
        tokio::spawn(async move {
            let mut got = Vec::new();
            let mut buf = [0u8; 65_536];
            while let Ok(Ok(4..)) =
                tokio::time::timeout_at(deadline.into(), sock.recv(&mut buf)).await
            {
                got.push((
                    u32::from_be_bytes(buf[..4].try_into().unwrap()),
                    Instant::now(),
                ));
            }
            got
        })
    };
    let mut sent = Vec::new();
    let mut packet = vec![0u8; size.max(4)];
    let mut interval = tokio::time::interval(every);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Burst);
    for seq in 0..count {
        interval.tick().await;
        packet[..4].copy_from_slice(&seq.to_be_bytes());
        sent.push(Instant::now());
        let _ = sock.send(&packet).await;
    }
    let mut by_seq = vec![None; count as usize];
    for (seq, at) in receiver.await.unwrap() {
        let seq = seq as usize;
        if seq < by_seq.len() && by_seq[seq].is_none() {
            by_seq[seq] = Some(at - sent[seq]);
        }
    }
    let mut rtts: Vec<Duration> = by_seq.iter().flatten().copied().collect();
    rtts.sort();
    let longest_loss = by_seq
        .split(Option::is_some)
        .map(<[Option<Duration>]>::len)
        .max()
        .unwrap_or(0);
    Game {
        rtts,
        sent: count as usize,
        longest_loss,
        by_seq,
        every,
    }
}

/// Download rate in Mbit/s over `connections` parallel downloads, measured over
/// `window` after `warmup`.
async fn downloads(port: u16, connections: usize, warmup: Duration, window: Duration) -> f64 {
    let runs: Vec<_> = (0..connections)
        .map(|_| tokio::spawn(download(port, warmup, window)))
        .collect();
    let mut total = 0.0;
    for run in runs {
        total += run.await.unwrap();
    }
    total
}

/// Game traffic over a long, lossy path: 60 ms RTT,
/// 50 Mbit/s each way with a 50 ms queue, random loss of 0, 1 and 5 % and bursty loss
/// of 2 % (mean burst 3). 128-byte packets at 64 Hz on an idle tunnel, then during four
/// downloads on the same tunnel. Every row uses the gaming profile.
/// `cargo test --release --test tunnel game_traffic -- --ignored --nocapture`;
/// `KARIZ_BENCH_ONLY=kcp` runs the rows whose name contains `kcp`, `KARIZ_BENCH_LOSS=1`
/// one loss rate (`b` for the bursty one), `KARIZ_BENCH_SECS` sets the length of each
/// measurement (default 30). `KARIZ_BENCH_ONLY` starting with `=` takes exact row names
/// separated by `|`; `KARIZ_BENCH_SEED` changes the link's random draws;
/// `KARIZ_BENCH_DETAIL` prints where the losses and the slow packets were.
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn game_traffic() {
    link::fine_timers();
    let gaming = |setup: Setup| setup.profile("gaming");
    // The gaming profile turns FEC 10 / 3 on over kcp; rows without it say so.
    let kcp = |options: &'static str| gaming(Setup::kcp("direct").kcp_options(options));
    const NO_FEC: &str = "fec_data = 0\nfec_parity = 0";
    let setups = [
        (
            "tcpmux",
            gaming(Setup::tcp("direct").transport("tcpmux").mux()),
        ),
        (
            "kcp, datagrams off (v0.4)",
            kcp("datagrams = false\nfec_data = 0\nfec_parity = 0"),
        ),
        ("kcp, fec off", kcp(NO_FEC)),
        ("kcp (fec 10/3)", gaming(Setup::kcp("direct"))),
        ("kcp, fec off, 2 copies", kcp(NO_FEC).duplicate(2, 5)),
        (
            "kcp (fec 10/3), 2 copies",
            gaming(Setup::kcp("direct")).duplicate(2, 5),
        ),
        (
            "kcp, fec off, window 256",
            kcp("fec_data = 0\nfec_parity = 0\nsend_window = 256\nrecv_window = 256"),
        ),
        (
            "kcp fast3, fec off, window 256",
            kcp("fec_data = 0\nfec_parity = 0\nmode = \"fast3\"\n\
                 send_window = 256\nrecv_window = 256"),
        ),
        ("quic", gaming(Setup::quic("direct"))),
        (
            "quic, 2 copies",
            gaming(Setup::quic("direct").duplicate(2, 5)),
        ),
    ];
    let only = std::env::var("KARIZ_BENCH_ONLY").unwrap_or_default();
    let selected = |name: &str| match only.strip_prefix('=') {
        Some(names) => names.split('|').any(|n| n == name),
        None => name.contains(only.as_str()),
    };
    let seed = std::env::var("KARIZ_BENCH_SEED")
        .ok()
        .map(|s| s.parse().expect("seed"));
    let detail = std::env::var_os("KARIZ_BENCH_DETAIL").is_some();
    let secs = std::env::var("KARIZ_BENCH_SECS").map_or(30, |s| s.parse().expect("seconds"));
    let measure = Duration::from_secs(secs);
    let conditions = [
        ("0", "0 %", 0.0, 1.0),
        ("1", "1 %", 0.01, 1.0),
        ("5", "5 %", 0.05, 1.0),
        ("b", "2 % x3", 0.02, 3.0),
    ];
    let loss_filter = std::env::var("KARIZ_BENCH_LOSS").ok();
    println!(
        "RTT 60 ms, 50 Mbit/s, 50 ms queue; 128-byte packets at 64 Hz for {secs} s, echoed; \
         gaming profile"
    );
    println!(
        "{:<8} {:<31} {:<34} {:<34} {:>12}",
        "loss",
        "transport",
        "idle: p50 p99 p99.9, delivered, run",
        "4 downloads: same",
        "downloads"
    );
    for (key, label, loss, burst) in conditions {
        if loss_filter.as_deref().is_some_and(|f| f != key) {
            continue;
        }
        for &(name, setup) in &setups {
            if !selected(name) {
                continue;
            }
            let mut imp = Impairment {
                delay: Duration::from_millis(30),
                loss,
                burst,
                rate: 50_000_000,
                queue: Duration::from_millis(50),
                ..Default::default()
            };
            if let Some(seed) = seed {
                imp.seed = seed;
            }
            let target = download_server().await;
            let tunnel = start_via(setup, setup, TOKEN, TOKEN, target, |upstream| {
                if is_udp(setup) {
                    let link = UdpLink::start(upstream, imp);
                    (link.port, Some(Box::new(link) as Proxy))
                } else {
                    let link = TcpLink::start(upstream, imp);
                    (link.port, Some(Box::new(link) as Proxy))
                }
            })
            .await;
            // Sessions up and the datagram path's probes across before measuring.
            let _ = game(tunnel.user_port, Duration::from_secs(2)).await;
            let idle = game(tunnel.user_port, measure).await;
            let warmup = Duration::from_secs(3);
            let load = tokio::spawn(downloads(tunnel.user_port, 4, warmup, measure));
            tokio::time::sleep(warmup).await;
            let loaded = game(tunnel.user_port, measure).await;
            let mbps = load.await.unwrap();
            println!("{label:<8} {name:<31} {idle}   {loaded}   {mbps:>6.1} Mbit/s");
            if detail {
                let slow = Duration::from_millis(150);
                println!("         idle: {}", idle.detail(slow));
                println!("         4 downloads: {}", loaded.detail(slow));
            }
        }
    }
}

/// `kariz speedtest` through real daemons (Unix only: the control socket is a Unix
/// socket): speed in both directions, latency, and UDP where the tunnel has mux, in both
/// modes and over the transports.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn speedtest_through_the_daemon() {
    use kariz::speedtest::Options;
    let setups = [
        (
            "tcpmux direct",
            Setup::tcp("direct").transport("tcpmux").mux(),
        ),
        (
            "tcpmux reverse",
            Setup::tcp("reverse").transport("tcpmux").mux(),
        ),
        ("tcp direct, no mux", Setup::tcp("direct")),
        ("tcp reverse, no mux", Setup::tcp("reverse")),
        ("kcp direct", Setup::kcp("direct")),
        ("quic reverse", Setup::quic("reverse")),
    ];
    let runs = setups.map(|(name, setup)| {
        tokio::spawn(async move {
            let setup = setup.control();
            let target = echo_server().await;
            let tunnel = start(setup, TOKEN, TOKEN, target).await;
            let socket = tunnel.control.clone().expect("a control socket");
            // The daemon binds its socket a moment after it starts.
            let mut connection = None;
            for _ in 0..50 {
                match kariz::control::connect(&socket).await {
                    Ok(c) => {
                        connection = Some(c);
                        break;
                    }
                    Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
                }
            }
            let options = Options {
                seconds: 1,
                streams: 2,
                udp: true,
            };
            let report = kariz::control::request(
                connection.unwrap_or_else(|| panic!("{name}: no control socket")),
                options,
                |_| {},
            )
            .await
            .unwrap_or_else(|e| panic!("{name}: {e}"));
            assert!(report.download.mbps > 0.0, "{name}: {report:?}");
            assert!(report.upload.mbps > 0.0, "{name}: {report:?}");
            assert!(report.idle.received > 0, "{name}: {report:?}");
            assert!(report.download_latency.received > 0, "{name}: {report:?}");
            if setup.mux {
                let udp = report
                    .udp
                    .as_ref()
                    .unwrap_or_else(|| panic!("{name}: no UDP"));
                assert!(udp.received > 0, "{name}: {report:?}");
            } else {
                assert!(report.udp.is_none(), "{name}");
                assert!(report.notes.iter().any(|n| n.contains("mux")), "{name}");
            }
        })
    });
    for run in runs {
        run.await.unwrap();
    }
}

/// Asks the daemon behind a control socket for its status; the daemon binds its socket a
/// moment after it starts.
#[cfg(unix)]
async fn status_of(socket: &std::path::Path) -> kariz::stats::Status {
    for _ in 0..50 {
        if let Ok(c) = kariz::control::connect(socket).await {
            return kariz::control::status(c).await.unwrap();
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("no control socket at {}", socket.display());
}

/// `kariz reload` on an entry loaded from a file: the forward rules of the file are
/// applied to the running daemon, and a connection through a rule that stays is kept.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn a_reload_applies_the_file_s_forward_rules_without_a_restart() {
    let target = echo_server().await;
    let tunnel_port = free_port();
    let (a, b, c) = (free_port(), free_port(), free_port());
    let dir = std::env::temp_dir().join(format!("kariz-reload-{tunnel_port}"));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("entry.toml");
    let socket = dir.join("entry.sock");
    let entry_text = |rules: &[(u16, u16)], remote: u16| {
        let rules: String = rules
            .iter()
            .map(|(listen, target)| {
                format!(
                    "[[forward]]\nlisten = \"127.0.0.1:{listen}\"\ntarget = \"127.0.0.1:{target}\"\n"
                )
            })
            .collect();
        format!(
            "role = \"entry\"\nmode = \"direct\"\n{rules}[tunnel]\nremote = \"127.0.0.1:{remote}\"\n\
             token = \"{TOKEN}\"\ntransport = \"tcpmux\"\n[control]\nsocket = {:?}\n",
            socket.display().to_string()
        )
    };
    let exit = format!(
        "role = \"exit\"\nmode = \"direct\"\n[tunnel]\nlisten = \"127.0.0.1:{tunnel_port}\"\n\
         token = \"{TOKEN}\"\ntransport = \"tcpmux\"\n"
    );
    let _exit = Side::start(&exit);
    tokio::time::sleep(Duration::from_millis(100)).await;
    std::fs::write(&path, entry_text(&[(a, target), (b, target)], tunnel_port)).unwrap();
    let _entry = Side::start_from_file(&path);
    tokio::time::sleep(Duration::from_millis(300)).await;

    // One connection through a, kept open across the reloads.
    let mut kept = TcpStream::connect(("127.0.0.1", a)).await.unwrap();
    kept.write_all(b"before").await.unwrap();
    let mut back = [0; 6];
    tokio::time::timeout(Duration::from_secs(5), kept.read_exact(&mut back))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&back, b"before");

    let reload = || async {
        for _ in 0..50 {
            if let Ok(c) = kariz::control::connect(&socket).await {
                return kariz::control::reload(c).await;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("no control socket at {}", socket.display());
    };
    // b retargeted, c added.
    std::fs::write(
        &path,
        entry_text(&[(a, target), (b, 9), (c, target)], tunnel_port),
    )
    .unwrap();
    let report = reload().await.unwrap();
    assert_eq!(report.added, vec![format!("127.0.0.1:{c}")]);
    assert_eq!(report.changed, vec![format!("127.0.0.1:{b}")]);
    assert!(
        report.removed.is_empty() && report.failed.is_empty(),
        "{report}"
    );
    kept.write_all(b"after!").await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), kept.read_exact(&mut back))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        &back, b"after!",
        "the connection through a survived the reload"
    );
    let payload = pattern(5000);
    assert_eq!(echo_roundtrip(c, &payload).await.unwrap(), payload);

    // Something else changed: refused.
    std::fs::write(
        &path,
        entry_text(&[(a, target), (b, 9), (c, target)], tunnel_port + 1),
    )
    .unwrap();
    let err = reload().await.unwrap_err();
    assert!(
        err.to_string().starts_with("restart needed: tunnel"),
        "{err}"
    );

    // a removed: its connection ends and its port refuses.
    std::fs::write(&path, entry_text(&[(b, 9), (c, target)], tunnel_port)).unwrap();
    let report = reload().await.unwrap();
    assert_eq!(report.removed, vec![format!("127.0.0.1:{a}")]);
    let n = tokio::time::timeout(Duration::from_secs(5), kept.read(&mut back))
        .await
        .unwrap()
        .unwrap_or(0);
    assert_eq!(n, 0, "the removed rule's connection ends");
    assert!(TcpStream::connect(("127.0.0.1", a)).await.is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

/// `status` on both sides counts what went through, and says the other side is there.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn status_counts_traffic_on_both_sides() {
    let setups = [
        (
            "tcpmux reverse",
            Setup::tcp("reverse").transport("tcpmux").mux(),
        ),
        ("tcp direct, no mux", Setup::tcp("direct")),
        ("quic reverse", Setup::quic("reverse")),
        ("kcp direct", Setup::kcp("direct")),
    ];
    let runs = setups.map(|(name, setup)| {
        tokio::spawn(async move {
            let target = echo_server().await;
            let tunnel = start(setup.control(), TOKEN, TOKEN, target).await;
            let payload = pattern(1 << 20);
            for _ in 0..3 {
                let got = echo_roundtrip(tunnel.user_port, &payload).await.unwrap();
                assert_eq!(got.len(), payload.len(), "{name}");
            }
            let sock = udp_client(tunnel.user_port).await;
            let echoed = udp_roundtrip(&sock, &[5; 700], Duration::from_secs(5)).await;
            assert!(echoed.is_some(), "{name}: UDP");

            // A connection's counters close a moment after its user sees the end.
            tokio::time::sleep(Duration::from_millis(300)).await;
            let entry = status_of(tunnel.control.as_ref().unwrap()).await;
            assert_eq!(entry.role, "entry", "{name}");
            assert!(entry.peer.connected, "{name}: {entry:?}");
            let rule = &entry.forwards[0];
            assert_eq!(rule.tcp_total, 3, "{name}: {rule:?}");
            assert_eq!(rule.tcp_open, 0, "{name}: {rule:?}");
            assert_eq!(rule.udp_total, 1, "{name}: {rule:?}");
            // 3 MiB each way over TCP, and the UDP packet.
            assert_eq!(rule.bytes_up, 3 * (1 << 20) + 700, "{name}: {rule:?}");
            assert_eq!(rule.bytes_down, 3 * (1 << 20) + 700, "{name}: {rule:?}");
            if setup.mux {
                assert!(entry.peer.sessions.unwrap() >= 1, "{name}: {entry:?}");
                assert!(entry.peer.rtt_ms.is_some(), "{name}: {entry:?}");
            } else {
                assert_eq!(entry.peer.sessions, None, "{name}");
            }

            let exit = status_of(tunnel.exit_control.as_ref().unwrap()).await;
            assert_eq!(exit.role, "exit", "{name}");
            assert!(exit.peer.connected, "{name}: {exit:?}");
            let served = exit.exit.as_ref().unwrap();
            assert_eq!(served.streams_total, 4, "{name}: {exit:?}");
            assert_eq!(served.dial_failures, 0, "{name}: {exit:?}");
            assert_eq!(
                exit.totals.bytes_up,
                3 * (1 << 20) + 700,
                "{name}: {exit:?}"
            );
            assert_eq!(
                exit.totals.bytes_down,
                3 * (1 << 20) + 700,
                "{name}: {exit:?}"
            );
        })
    });
    for run in runs {
        run.await.unwrap();
    }
}

/// The entry side's health probe gets through to the target in every kind of tunnel and
/// says so in `status`, with the capacity; a target that is down is named.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn status_reports_health_and_capacity() {
    use kariz::stats::ProbeOutcome;
    let setups = [
        (
            "tcpmux direct",
            Setup::tcp("direct").transport("tcpmux").mux(),
            true,
        ),
        ("tcp reverse, no mux", Setup::tcp("reverse"), true),
        ("tcp direct, no mux", Setup::tcp("direct"), true),
        ("quic direct", Setup::quic("direct"), true),
        (
            "tcpmux, target down",
            Setup::tcp("direct").transport("tcpmux").mux(),
            false,
        ),
    ];
    let runs = setups.map(|(name, setup, target_up)| {
        tokio::spawn(async move {
            let target = if target_up {
                echo_server().await
            } else {
                free_port()
            };
            let tunnel = start(setup.control(), TOKEN, TOKEN, target).await;
            let socket = tunnel.control.clone().unwrap();
            // The first probe goes a few seconds after the start.
            let mut status = status_of(&socket).await;
            for _ in 0..100 {
                if status.probe.is_some() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
                status = status_of(&socket).await;
            }
            let probe = status
                .probe
                .clone()
                .unwrap_or_else(|| panic!("{name}: no probe"));
            assert_eq!(probe.target, format!("127.0.0.1:{target}"), "{name}");
            if target_up {
                assert_eq!(probe.outcome, ProbeOutcome::Ok, "{name}: {probe:?}");
                assert!(probe.ms.is_some(), "{name}: {probe:?}");
            } else {
                assert_eq!(
                    probe.outcome,
                    ProbeOutcome::TargetFailed,
                    "{name}: {probe:?}"
                );
                assert_eq!(probe.target_fails, 1, "{name}: {probe:?}");
            }
            if setup.mux {
                let max = status.peer.streams_max.unwrap_or_default();
                assert!(max >= 4096, "{name}: {:?}", status.peer);
                assert!(status.peer.streams.is_some(), "{name}");
            } else {
                assert_eq!(status.peer.streams_max, None, "{name}");
            }
            // Probes are no user's: the exit side does not count them.
            let exit = status_of(tunnel.exit_control.as_ref().unwrap()).await;
            assert_eq!(exit.exit.unwrap().streams_total, 0, "{name}");
        })
    });
    for run in runs {
        run.await.unwrap();
    }
}

/// When the other side goes away, `status` says so, with why it cannot connect again.
/// (A token mismatch shows up too, but only after the listening side has drained the
/// failed connection for 5-30 s and the dialer's handshake has timed out: too slow here.)
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn status_shows_why_the_other_side_is_missing() {
    let setup = Setup::tcp("direct").transport("tcpmux").mux().control();
    let target = echo_server().await;
    let mut tunnel = start(setup, TOKEN, TOKEN, target).await;
    let socket = tunnel.control.clone().unwrap();
    let before = status_of(&socket).await;
    assert!(before.peer.connected, "{before:?}");
    assert_eq!(before.peer.last_error, None, "{before:?}");

    // The entry sees its sessions end, and nothing listens when it dials again.
    tunnel.kill_exit();
    let mut after = status_of(&socket).await;
    for _ in 0..200 {
        if !after.peer.connected && after.peer.last_error.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        after = status_of(&socket).await;
    }
    assert!(!after.peer.connected, "{after:?}");
    assert_eq!(after.peer.sessions, Some(0), "{after:?}");
    assert!(after.peer.handshakes_failed > 0, "{after:?}");
    let error = after.peer.last_error.unwrap();
    assert!(error.text.contains("refused"), "{error:?}");
}

/// A direct tunnel without mux keeps no connection open, yet `status` must say whether the
/// exit side can be reached (a panel making the tunnel waits for exactly that): the entry
/// looks for it by itself, and says so again when the exit goes away.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn a_direct_tunnel_without_mux_says_it_is_connected_before_any_traffic() {
    let setup = Setup::tcp("direct").control();
    let target = echo_server().await;
    let mut tunnel = start(setup, TOKEN, TOKEN, target).await;
    let socket = tunnel.control.clone().unwrap();
    let mut status = status_of(&socket).await;
    for _ in 0..100 {
        if status.peer.connected {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        status = status_of(&socket).await;
    }
    assert!(status.peer.connected, "{status:?}");

    tunnel.kill_exit();
    for _ in 0..200 {
        if !status.peer.connected {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        status = status_of(&socket).await;
    }
    assert!(!status.peer.connected, "{status:?}");
}

/// An `auto` tunnel says which transport its sessions use now, on both sides.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn an_auto_tunnel_says_which_transport_it_uses() {
    for mode in ["reverse", "direct"] {
        let setup = Setup::tcp(mode).transport("auto").mux().control();
        let target = echo_server().await;
        let tunnel = start(setup, TOKEN, TOKEN, target).await;
        for socket in [
            tunnel.control.clone().unwrap(),
            tunnel.exit_control.clone().unwrap(),
        ] {
            let mut status = status_of(&socket).await;
            for _ in 0..50 {
                if status.peer.transport.is_some() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
                status = status_of(&socket).await;
            }
            // The first transport that gets through on localhost is tcpmux.
            assert_eq!(
                status.peer.transport.as_deref(),
                Some("tcpmux"),
                "{mode}: {status:?}"
            );
        }
    }
}

/// An exit with `speedtest = false` refuses the test streams, and the client says why.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn speedtest_can_be_turned_off_on_the_exit() {
    use kariz::speedtest::Options;
    let entry = Setup::tcp("direct").transport("tcpmux").mux().control();
    let exit = Setup::tcp("direct")
        .transport("tcpmux")
        .mux()
        .no_speedtest();
    let target = echo_server().await;
    let tunnel = start_pair(entry, exit, TOKEN, TOKEN, target).await;
    let socket = tunnel.control.clone().unwrap();
    let mut connection = None;
    for _ in 0..50 {
        if let Ok(c) = kariz::control::connect(&socket).await {
            connection = Some(c);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let err = kariz::control::request(
        connection.expect("a control socket"),
        Options {
            seconds: 1,
            streams: 1,
            udp: false,
        },
        |_| {},
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("speedtest = false"), "{err}");
}

/// Game-like traffic (100-byte packets every 10 ms, echoed) over a link that drops 10 %
/// of the packets each way, so about 19 % of the round trips fail. With each packet sent
/// twice, both ways, a round trip fails only when both copies are lost on one of its
/// two legs: about 2 %. Over kcp's datagram path and QUIC datagrams, in both modes.
#[tokio::test(flavor = "multi_thread")]
async fn duplication_hides_random_loss() {
    let runs = [
        (Setup::kcp("direct"), 2),
        (Setup::kcp("reverse"), 2),
        (Setup::quic("direct"), 2),
        (Setup::kcp("direct"), 1),
    ]
    .map(|(setup, copies)| {
        tokio::spawn(async move {
            let setup = if copies > 1 {
                setup.duplicate(copies, 5)
            } else {
                setup
            };
            let target = echo_server().await;
            let imp = Impairment {
                delay: Duration::from_millis(5),
                loss: 0.10,
                ..Default::default()
            };
            let tunnel = start_via(setup, setup, TOKEN, TOKEN, target, |upstream| {
                let link = UdpLink::start(upstream, imp);
                (link.port, Some(Box::new(link)))
            })
            .await;
            // Let the datagram path's probes cross (they can be lost too), then measure.
            let _ = pings(tunnel.user_port, 100, Duration::from_millis(10)).await;
            let run = pings(tunnel.user_port, 400, Duration::from_millis(10)).await;
            let lost = 1.0 - run.rtts.len() as f64 / run.sent as f64;
            (setup, copies, lost)
        })
    });
    for run in runs {
        let (setup, copies, lost) = run.await.unwrap();
        eprintln!(
            "{} {} copies {copies}: {:.1} % of round trips lost",
            setup.transport,
            setup.mode,
            lost * 100.0
        );
        if copies > 1 {
            assert!(lost < 0.06, "{setup:?}: {:.1} % lost", lost * 100.0);
        } else {
            assert!(lost > 0.10, "{setup:?}: {:.1} % lost", lost * 100.0);
        }
    }
}

/// KCP over a link that loses 5 % of the packets each way: everything still arrives, in
/// both modes, with and without mux, with and without FEC.
#[tokio::test(flavor = "multi_thread")]
async fn kcp_transfer_survives_loss() {
    let runs = [
        Setup::kcp("direct"),
        Setup::kcp("reverse"),
        Setup::kcp("direct").no_mux(),
        Setup::kcp("direct").fec(10, 3),
    ]
    .map(|setup| {
        tokio::spawn(async move {
            let target = echo_server().await;
            let imp = Impairment {
                delay: Duration::from_millis(5),
                loss: 0.05,
                ..Default::default()
            };
            let tunnel = start_via(setup, setup, TOKEN, TOKEN, target, |upstream| {
                let link = UdpLink::start(upstream, imp);
                (link.port, Some(Box::new(link)))
            })
            .await;
            let payload = pattern(4 << 20);
            let got = tokio::time::timeout(
                Duration::from_secs(60),
                echo_roundtrip(tunnel.user_port, &payload),
            )
            .await
            .unwrap_or_else(|_| panic!("{setup:?}: transfer did not finish"))
            .unwrap();
            assert!(got == payload, "{setup:?}: payload corrupted");
        })
    });
    for run in runs {
        run.await.unwrap();
    }
}

/// Download rate in Mbit/s like [`download`], but `None` when the connection fails or ends
/// early (a benchmark row, not a test: the table says "failed" and the run goes on).
async fn download_rate(port: u16, warmup: Duration, window: Duration) -> Option<f64> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.ok()?;
    let mut buf = vec![0u8; 256 * 1024];
    let from = Instant::now() + warmup;
    let until = from + window;
    let mut total = 0;
    while let Ok(read) = tokio::time::timeout_at(until.into(), s.read(&mut buf)).await {
        match read {
            Ok(n) if n > 0 => {
                if Instant::now() >= from {
                    total += n;
                }
            }
            _ => return None,
        }
    }
    Some(total as f64 * 8.0 / window.as_secs_f64() / 1e6)
}

/// [`download_rate`] over `connections` downloads at once; `None` if any of them failed.
async fn download_rates(
    port: u16,
    connections: usize,
    warmup: Duration,
    window: Duration,
) -> Option<f64> {
    let runs: Vec<_> = (0..connections)
        .map(|_| tokio::spawn(download_rate(port, warmup, window)))
        .collect();
    let mut total = 0.0;
    for run in runs {
        total += run.await.unwrap()?;
    }
    Some(total)
}

/// One row of the benchmark table.
struct BenchRow {
    name: String,
    one: Option<f64>,
    eight: Option<f64>,
    udp: Game,
}

impl BenchRow {
    fn markdown(&self) -> String {
        let rate = |r: Option<f64>| r.map_or("failed".to_string(), |r| format!("{r:.1}"));
        let ms = |p| percentile(&self.udp.rtts, p).as_secs_f64() * 1000.0;
        let (p50, p99, delivered) = if self.udp.rtts.is_empty() {
            ("-".to_string(), "-".to_string(), 0.0)
        } else {
            (
                format!("{:.1}", ms(0.5)),
                format!("{:.1}", ms(0.99)),
                100.0 * self.udp.rtts.len() as f64 / self.udp.sent as f64,
            )
        };
        format!(
            "| {} | {} | {} | {p50} | {p99} | {delivered:.2} |",
            self.name,
            rate(self.one),
            rate(self.eight)
        )
    }
}

const BENCH_HEADER: &str = "| transport profile path | 1 stream Mbit/s | 8 streams Mbit/s | \
                            UDP p50 ms | UDP p99 ms | UDP delivered % |\n\
                            |---|---:|---:|---:|---:|---:|";

/// The benchmark matrix behind `scripts/bench.sh`: four transports, the three profiles and
/// five paths (localhost; 40 ms RTT; 40 ms with 1 % loss; 100 ms with 2 ms jitter and
/// 0.3 % loss; 40 ms at 50 Mbit/s with a 50 ms queue), each measured with a one-stream
/// download, an eight-stream download and a UDP flow of 1200-byte packets at 4000 a second
/// (echoed; round trips and delivery). Each measurement runs `KARIZ_BENCH_SECS` seconds
/// (default 10). `cargo test --release --test tunnel bench_matrix -- --ignored --nocapture`.
/// `KARIZ_BENCH_ONLY=kcp,quic` keeps the rows whose name (`transport profile path`) contains
/// one of the comma-separated parts (`=a|b` takes exact names); `KARIZ_BENCH_OUT=file` also
/// writes the markdown table there; `KARIZ_BENCH_SEED` changes the links' random draws.
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn bench_matrix() {
    link::fine_timers();
    let transports = [
        ("tcpmux", Setup::tcp("direct").transport("tcpmux").mux()),
        ("wss", Setup::wss("direct")),
        ("kcp", Setup::kcp("direct")),
        ("quic", Setup::quic("direct")),
    ];
    let profiles = ["balanced", "ultraspeed", "gaming"];
    let ms = Duration::from_millis;
    let paths: [(&str, Option<Impairment>); 5] = [
        ("local", None),
        (
            "wan40",
            Some(Impairment {
                delay: ms(20),
                ..Default::default()
            }),
        ),
        (
            "wan40-loss1",
            Some(Impairment {
                delay: ms(20),
                loss: 0.01,
                ..Default::default()
            }),
        ),
        (
            "wan100-jitter",
            Some(Impairment {
                delay: ms(50),
                jitter: ms(2),
                loss: 0.003,
                ..Default::default()
            }),
        ),
        (
            "rate50",
            Some(Impairment {
                delay: ms(20),
                rate: 50_000_000,
                queue: ms(50),
                ..Default::default()
            }),
        ),
    ];
    let only = std::env::var("KARIZ_BENCH_ONLY").unwrap_or_default();
    let selected = |name: &str| match only.strip_prefix('=') {
        Some(names) => names.split('|').any(|n| n == name),
        None => only.split(',').any(|part| name.contains(part)),
    };
    let seed = std::env::var("KARIZ_BENCH_SEED")
        .ok()
        .map(|s| s.parse().expect("seed"));
    let secs = std::env::var("KARIZ_BENCH_SECS").map_or(10, |s| s.parse().expect("seconds"));
    let measure = Duration::from_secs(secs);
    let warmup = Duration::from_secs(2);
    println!(
        "{secs} s per measurement; UDP: 1200-byte packets at 4000/s on one flow, echoed\n\
         {BENCH_HEADER}"
    );
    let mut rows = Vec::new();
    for (transport, setup) in transports {
        for profile in profiles {
            for (path, imp) in paths {
                let name = format!("{transport} {profile} {path}");
                if !selected(&name) {
                    continue;
                }
                let setup = setup.profile(profile);
                let target = download_server().await;
                let tunnel = match imp {
                    None => start(setup, TOKEN, TOKEN, target).await,
                    Some(mut imp) => {
                        if let Some(seed) = seed {
                            imp.seed = seed;
                        }
                        start_via(setup, setup, TOKEN, TOKEN, target, |upstream| {
                            if is_udp(setup) {
                                let link = UdpLink::start(upstream, imp);
                                (link.port, Some(Box::new(link) as Proxy))
                            } else {
                                let link = TcpLink::start(upstream, imp);
                                (link.port, Some(Box::new(link) as Proxy))
                            }
                        })
                        .await
                    }
                };
                // Sessions up and the datagram path's probes across before measuring.
                let _ = game(tunnel.user_port, Duration::from_secs(2)).await;
                let one = download_rate(tunnel.user_port, warmup, measure).await;
                let eight = download_rates(tunnel.user_port, 8, warmup, measure).await;
                let udp =
                    udp_flow(tunnel.user_port, 1200, Duration::from_micros(250), measure).await;
                drop(tunnel);
                let row = BenchRow {
                    name,
                    one,
                    eight,
                    udp,
                };
                println!("{}", row.markdown());
                rows.push(row);
            }
        }
    }
    if let Ok(path) = std::env::var("KARIZ_BENCH_OUT") {
        let mut table = format!("{BENCH_HEADER}\n");
        for row in &rows {
            table += &row.markdown();
            table.push('\n');
        }
        std::fs::write(&path, table).expect("KARIZ_BENCH_OUT");
    }
}
