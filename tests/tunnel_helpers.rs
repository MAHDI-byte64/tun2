//! End-to-end tunnel tests for the managed-helper transports (`naive`, `xhttp`,
//! `reality`).
//!
//! These run the real helper binaries (sing-box for the naive server, NaiveProxy for the
//! naive client, Xray for xhttp/reality). They run when the helpers are installed (env
//! `KARIZ_HELPERS_DIR`, or the default install path) and skip with a printed reason
//! otherwise, unless `KARIZ_REQUIRE_HELPERS=1`. Self-signed certificates are made in-test
//! with rcgen and trusted through `ca_file`; the reality row uses a local TLS1.3 + h2 cover
//! (OpenSSL's `s_server`) or skips when none is available.
//!
//! Compiled only with the `helpers` feature.
#![cfg(feature = "helpers")]

use std::io::{Read, Write};
use std::net::{TcpListener as StdTcpListener, TcpStream as StdTcpStream};
use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use kariz::config::Config;
use kariz::transport::helper::install;

const TOKEN: &str = "helper-token-0123456789abcdef";

/// The PROXY protocol v2 signature.
const PROXY_V2_SIG: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];

/// Whether the helper binaries are installed; panics if required but missing.
fn helpers_ready() -> bool {
    let present = install::installed_binary("xray").is_some()
        || install::installed_binary("sing-box").is_some();
    if !present && std::env::var("KARIZ_REQUIRE_HELPERS").as_deref() == Ok("1") {
        panic!("helper tests are required (KARIZ_REQUIRE_HELPERS=1) but no helpers are installed");
    }
    present
}

/// A free loopback TCP port (bound then released).
fn free_port() -> u16 {
    StdTcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Certificates for `tunnel.example` and `cover.example`, written once per run.
struct Certs {
    /// Server leaf for `tunnel.example`, signed by `ca`.
    cert: PathBuf,
    key: PathBuf,
    /// The CA that signed the leaf; trusted through `ca_file` / `SSL_CERT_FILE`.
    ca: PathBuf,
    cover_cert: PathBuf,
    cover_key: PathBuf,
}

fn certs() -> &'static Certs {
    use rcgen::{
        BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
        KeyUsagePurpose,
    };
    static CERTS: OnceLock<Certs> = OnceLock::new();
    CERTS.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!("kariz-helper-e2e-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        // A CA, used as the trust anchor (NaiveProxy's Chromium stack needs a CA, not a
        // bare self-signed leaf), plus a leaf for tunnel.example signed by it.
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca_key = KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let ca = dir.join("ca.pem");
        std::fs::write(&ca, ca_cert.pem()).unwrap();

        let mut leaf_params = CertificateParams::new(vec!["tunnel.example".to_string()]).unwrap();
        leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let leaf_key = KeyPair::generate().unwrap();
        let issuer = Issuer::new(ca_params, ca_key);
        let leaf_cert = leaf_params.signed_by(&leaf_key, &issuer).unwrap();
        let (cert, key) = (dir.join("cert.pem"), dir.join("key.pem"));
        std::fs::write(&cert, leaf_cert.pem()).unwrap();
        std::fs::write(&key, leaf_key.serialize_pem()).unwrap();

        // The REALITY cover is a plain self-signed TLS endpoint; REALITY borrows its
        // handshake, it is not verified as a CA.
        let (cover_cert, cover_key) = (dir.join("cover.pem"), dir.join("cover.key"));
        let v = rcgen::generate_simple_self_signed(vec!["cover.example".into()]).unwrap();
        std::fs::write(&cover_cert, v.cert.pem()).unwrap();
        std::fs::write(&cover_key, v.signing_key.serialize_pem()).unwrap();

        Certs {
            cert,
            key,
            ca,
            cover_cert,
            cover_key,
        }
    })
}

/// A blocking TCP echo server on a thread; returns its port.
fn echo_server() -> u16 {
    let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || relay_echo(stream, false));
        }
    });
    port
}

/// A TCP server that first verifies a PROXY v2 header, then echoes the rest; returns its
/// port. A connection without the header is dropped.
fn proxy_echo_server() -> u16 {
    let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || relay_echo(stream, true));
        }
    });
    port
}

fn relay_echo(mut stream: StdTcpStream, expect_proxy: bool) {
    stream.set_read_timeout(Some(Duration::from_secs(30))).ok();
    if expect_proxy {
        // PROXY v2: 12-byte signature, ver/cmd, family, 2-byte length, then that many bytes.
        let mut head = [0u8; 16];
        if stream.read_exact(&mut head).is_err() || head[..12] != PROXY_V2_SIG {
            return;
        }
        let addr_len = u16::from_be_bytes([head[14], head[15]]) as usize;
        let mut addr = vec![0u8; addr_len];
        if stream.read_exact(&mut addr).is_err() {
            return;
        }
    }
    let mut buf = [0u8; 65536];
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

/// One side of the tunnel in its own runtime; dropping it shuts the side down.
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
        let config = Config::parse(text).unwrap_or_else(|e| panic!("{e:#}\n{text}"));
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

/// A local TLS1.3 + h2 cover server via OpenSSL `s_server`; `None` if openssl is missing.
struct Cover {
    child: Child,
}

impl Cover {
    fn start(port: u16) -> Option<Self> {
        let c = certs();
        let child = Command::new("openssl")
            .args([
                "s_server", "-quiet", "-tls1_3", "-alpn", "h2", "-naccept", "1000", "-cert",
            ])
            .arg(&c.cover_cert)
            .arg("-key")
            .arg(&c.cover_key)
            .arg("-accept")
            .arg(format!("127.0.0.1:{port}"))
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .ok()?;
        Some(Self { child })
    }
}

impl Drop for Cover {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Connects to `port`, writes `payload`, reads `payload.len()` bytes back; retries until it
/// succeeds or `budget` passes. The tunnel and helpers take a moment to come up.
fn echo_roundtrip(port: u16, payload: &[u8], budget: Duration) -> Vec<u8> {
    let deadline = Instant::now() + budget;
    let mut last = String::from("never connected");
    while Instant::now() < deadline {
        match try_roundtrip(port, payload) {
            Ok(got) => return got,
            Err(e) => {
                last = e;
                std::thread::sleep(Duration::from_millis(400));
            }
        }
    }
    panic!("no echo through the tunnel within {budget:?}: {last}");
}

fn try_roundtrip(port: u16, payload: &[u8]) -> Result<Vec<u8>, String> {
    let mut stream =
        StdTcpStream::connect(("127.0.0.1", port)).map_err(|e| format!("connect: {e}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(10))).ok();
    stream
        .write_all(payload)
        .map_err(|e| format!("write: {e}"))?;
    let mut got = vec![0u8; payload.len()];
    stream
        .read_exact(&mut got)
        .map_err(|e| format!("read: {e}"))?;
    if got != payload {
        return Err("payload mismatch".into());
    }
    Ok(got)
}

/// Builds the `[tunnel.helper]` body for one side of a tunnel.
fn helper_table(
    transport: &str,
    acceptor: bool,
    cover_port: u16,
    keys: &(String, String),
) -> String {
    let c = certs();
    let cert = c.cert.display();
    let key = c.key.display();
    let ca = c.ca.display();
    match transport {
        "naive" if acceptor => format!(
            "[tunnel.helper]\nusername = \"user\"\npassword = \"pass\"\n\
             certificate = \"{cert}\"\nkey = \"{key}\"\n"
        ),
        "naive" => format!(
            "[tunnel.helper]\nusername = \"user\"\npassword = \"pass\"\n\
             server_name = \"tunnel.example\"\nca_file = \"{ca}\"\n"
        ),
        "xhttp" if acceptor => format!(
            "[tunnel.helper]\nuuid = \"{UUID}\"\npath = \"/kariz-e2e\"\n\
             server_name = \"tunnel.example\"\ncertificate = \"{cert}\"\nkey = \"{key}\"\n"
        ),
        "xhttp" => format!(
            "[tunnel.helper]\nuuid = \"{UUID}\"\npath = \"/kariz-e2e\"\n\
             server_name = \"tunnel.example\"\nca_file = \"{ca}\"\n"
        ),
        "reality" if acceptor => format!(
            "[tunnel.helper]\nuuid = \"{UUID}\"\nserver_name = \"cover.example\"\n\
             short_id = \"abcd1234\"\nprivate_key = \"{priv}\"\ntarget = \"127.0.0.1:{cover_port}\"\n",
            priv = keys.0,
        ),
        "reality" => format!(
            "[tunnel.helper]\nuuid = \"{UUID}\"\nserver_name = \"cover.example\"\n\
             short_id = \"abcd1234\"\npublic_key = \"{pub}\"\n",
            pub = keys.1,
        ),
        other => panic!("unknown helper transport {other}"),
    }
}

const UUID: &str = "123e4567-e89b-12d3-a456-426614174000";

/// Runs one reverse-mode helper tunnel (entry = acceptor/helper server, exit =
/// dialer/helper client) and returns the live sides plus the user-facing port.
struct Tunnel {
    user_port: u16,
    _entry: Side,
    _exit: Side,
    _cover: Option<Cover>,
}

fn start_tunnel(transport: &str, target_port: u16, proxy_v2: bool) -> Option<Tunnel> {
    let keys = if transport == "reality" {
        install::reality_keys().expect("xray x25519 for the reality keys")
    } else {
        (String::new(), String::new())
    };
    let cover_port = free_port();
    let cover = if transport == "reality" {
        match Cover::start(cover_port) {
            Some(c) => {
                std::thread::sleep(Duration::from_millis(300));
                Some(c)
            }
            None => {
                eprintln!("skipping reality: no openssl s_server for a local TLS1.3 + h2 cover");
                return None;
            }
        }
    } else {
        None
    };

    let pub_port = free_port();
    let user_port = free_port();
    let proxy_line = if proxy_v2 {
        "proxy_protocol = \"v2\"\n"
    } else {
        ""
    };

    let entry = format!(
        "role = \"entry\"\nmode = \"reverse\"\n\
         [tunnel]\ntransport = \"{transport}\"\nlisten = \"127.0.0.1:{pub_port}\"\n\
         token = \"{TOKEN}\"\n{helper}\
         [[forward]]\nlisten = \"127.0.0.1:{user_port}\"\ntarget = \"127.0.0.1:{target_port}\"\n\
         protocol = \"tcp\"\n{proxy_line}\
         [log]\nlevel = \"warn\"\n",
        helper = helper_table(transport, true, cover_port, &keys),
    );
    let exit = format!(
        "role = \"exit\"\nmode = \"reverse\"\n\
         [tunnel]\ntransport = \"{transport}\"\nremote = \"127.0.0.1:{pub_port}\"\n\
         token = \"{TOKEN}\"\npool = 2\n{helper}\
         [log]\nlevel = \"warn\"\n",
        helper = helper_table(transport, false, cover_port, &keys),
    );

    // The listening side (the acceptor/helper server) first.
    let entry = Side::start(&entry);
    std::thread::sleep(Duration::from_millis(500));
    let exit = Side::start(&exit);

    Some(Tunnel {
        user_port,
        _entry: entry,
        _exit: exit,
        _cover: cover,
    })
}

#[test]
fn naive_tunnels_an_echo() {
    if !helpers_ready() {
        eprintln!("skipping: set KARIZ_HELPERS_DIR to the installed helpers to run these tests");
        return;
    }
    if install::installed_binary("sing-box").is_none()
        || install::installed_binary("naive").is_none()
    {
        eprintln!("skipping naive: sing-box and naive must both be installed");
        return;
    }
    let echo = echo_server();
    let tunnel = start_tunnel("naive", echo, false).unwrap();
    let payload = vec![0x5au8; 64 * 1024];
    let got = echo_roundtrip(tunnel.user_port, &payload, Duration::from_secs(40));
    assert_eq!(got, payload);
}

#[test]
fn naive_carries_the_proxy_v2_header() {
    if !helpers_ready() {
        eprintln!("skipping: set KARIZ_HELPERS_DIR to the installed helpers to run these tests");
        return;
    }
    if install::installed_binary("sing-box").is_none()
        || install::installed_binary("naive").is_none()
    {
        eprintln!("skipping naive proxy_v2: sing-box and naive must both be installed");
        return;
    }
    let target = proxy_echo_server();
    let tunnel = start_tunnel("naive", target, true).unwrap();
    let payload = b"proxy-v2-echo".to_vec();
    let got = echo_roundtrip(tunnel.user_port, &payload, Duration::from_secs(40));
    assert_eq!(got, payload);
}

#[test]
fn xhttp_tunnels_an_echo() {
    if !helpers_ready() {
        eprintln!("skipping: set KARIZ_HELPERS_DIR to the installed helpers to run these tests");
        return;
    }
    if install::installed_binary("xray").is_none() {
        eprintln!("skipping xhttp: xray must be installed");
        return;
    }
    let echo = echo_server();
    let tunnel = start_tunnel("xhttp", echo, false).unwrap();
    let payload = vec![0xa5u8; 64 * 1024];
    let got = echo_roundtrip(tunnel.user_port, &payload, Duration::from_secs(40));
    assert_eq!(got, payload);
}

#[test]
fn reality_tunnels_an_echo() {
    if !helpers_ready() {
        eprintln!("skipping: set KARIZ_HELPERS_DIR to the installed helpers to run these tests");
        return;
    }
    if install::installed_binary("xray").is_none() {
        eprintln!("skipping reality: xray must be installed");
        return;
    }
    let echo = echo_server();
    let Some(tunnel) = start_tunnel("reality", echo, false) else {
        return; // no cover available; reason already printed
    };
    let payload = vec![0x3cu8; 32 * 1024];
    let got = echo_roundtrip(tunnel.user_port, &payload, Duration::from_secs(40));
    assert_eq!(got, payload);
}

#[test]
fn the_pin_table_has_an_entry_per_helper() {
    // Pure logic: the compiled-in pin table is well formed. (Config generation is covered
    // by the unit tests in the helper module.)
    let names: Vec<_> = install::PINS.iter().map(|p| p.name).collect();
    assert!(names.contains(&"sing-box"));
    assert!(names.contains(&"naive"));
    assert!(names.contains(&"xray"));
    for pin in install::PINS {
        assert_eq!(pin.amd64.sha256.len(), 64);
        assert_eq!(pin.arm64.sha256.len(), 64);
    }
}
