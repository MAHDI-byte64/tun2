//! End-to-end tests for the l3 / GRE direct tunnel.
//!
//! Two TUN (or TAP) endpoints cannot talk to each other inside one network namespace — the
//! kernel delivers a packet addressed to a locally-assigned tunnel IP over loopback instead
//! of across the tunnel. So each test puts the listening endpoint in its own network
//! namespace, connected to the root namespace by a veth pair that carries the (sealed)
//! tunnel. The dialing endpoint and the test client stay in the root namespace.
//!
//! Connectivity is proven with a real TCP connection across the tunnel rather than `ping`
//! (no ping binary is guaranteed in the container, and a TCP flow also exercises the MSS
//! clamp). Each test brings its own interfaces and namespace up and tears them down.
//!
//! They skip cleanly when not root, `/dev/net/tun` is missing, or `ip`/netns are
//! unavailable, unless `KARIZ_REQUIRE_L3=1`.
#![cfg(feature = "l3")]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use kariz::config::Config;

const TOKEN: &str = "l3-end-to-end-test-token-0123456789";

/// The `ip` binary, wherever it is (iproute2 is often in `/usr/sbin`, off a test's PATH).
fn ip_bin() -> Option<PathBuf> {
    for dir in ["/usr/sbin", "/sbin", "/usr/bin", "/bin"] {
        let p = PathBuf::from(dir).join("ip");
        if p.exists() {
            return Some(p);
        }
    }
    None
}

fn run_ip(args: &[&str]) -> std::io::Result<std::process::Output> {
    std::process::Command::new(ip_bin().expect("ip present"))
        .args(args)
        .output()
}

fn ip_ok(args: &[&str]) -> bool {
    run_ip(args).map(|o| o.status.success()).unwrap_or(false)
}

/// Whether an l3 tunnel end-to-end test can run here.
fn l3_ready() -> bool {
    let ok = cfg!(target_os = "linux")
        && std::path::Path::new("/dev/net/tun").exists()
        && is_root()
        && ip_bin().is_some()
        && netns_works();
    if !ok && std::env::var("KARIZ_REQUIRE_L3").as_deref() == Ok("1") {
        panic!("l3 tests are required (KARIZ_REQUIRE_L3=1) but the host cannot run them");
    }
    ok
}

fn is_root() -> bool {
    // SAFETY: getuid is always safe.
    unsafe { nix::libc::getuid() == 0 }
}

/// Probes that a network namespace can actually be created and removed here. The probe
/// name is unique per call so parallel tests do not race on it.
fn netns_works() -> bool {
    use std::sync::atomic::AtomicU32;
    static N: AtomicU32 = AtomicU32::new(0);
    let name = format!(
        "kzprobe{}_{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    );
    let _ = run_ip(&["netns", "del", &name]);
    let ok = ip_ok(&["netns", "add", &name]);
    let _ = run_ip(&["netns", "del", &name]);
    ok
}

/// One test's network: a namespace for the listener, and a veth carrying the tunnel.
struct TestNet {
    ns: String,
    veth_root: String,
    tun_subnet: u8,
    carrier_subnet: u8,
}

impl TestNet {
    /// `tag` must be short (interface names are capped at 15 bytes). `tun_subnet` and
    /// `carrier_subnet` are the second octets of two private /24 blocks unique to this test.
    fn setup(tag: &str, tun_subnet: u8, carrier_subnet: u8) -> Self {
        let net = Self {
            ns: format!("kz{tag}"),
            veth_root: format!("kva{tag}"),
            tun_subnet,
            carrier_subnet,
        };
        net.teardown(); // clear any leftovers from a crashed run
        let veth_ns = format!("kvb{tag}");
        assert!(ip_ok(&["netns", "add", &net.ns]), "create netns");
        assert!(
            ip_ok(&[
                "link",
                "add",
                &net.veth_root,
                "type",
                "veth",
                "peer",
                "name",
                &veth_ns
            ]),
            "create veth"
        );
        assert!(
            ip_ok(&["link", "set", &veth_ns, "netns", &net.ns]),
            "move veth"
        );
        let root_ip = format!("10.{carrier_subnet}.0.1/24");
        assert!(
            ip_ok(&["addr", "add", &root_ip, "dev", &net.veth_root]),
            "root veth addr"
        );
        assert!(
            ip_ok(&["link", "set", &net.veth_root, "up"]),
            "root veth up"
        );
        let ns_ip = format!("10.{carrier_subnet}.0.2/24");
        assert!(ip_ok(&[
            "netns", "exec", &net.ns, "ip", "addr", "add", &ns_ip, "dev", &veth_ns
        ]));
        assert!(ip_ok(&[
            "netns", "exec", &net.ns, "ip", "link", "set", &veth_ns, "up"
        ]));
        assert!(ip_ok(&[
            "netns", "exec", &net.ns, "ip", "link", "set", "lo", "up"
        ]));
        net
    }

    /// The carrier address the listener binds / the dialer reaches.
    fn carrier_listen(&self, port: u16) -> String {
        format!("0.0.0.0:{port}")
    }
    fn carrier_dial(&self, port: u16) -> String {
        format!("10.{}.0.2:{port}", self.carrier_subnet)
    }

    fn local_ip_dial(&self) -> String {
        format!("10.{}.0.1/30", self.tun_subnet)
    }
    fn peer_ip_dial(&self) -> String {
        format!("10.{}.0.2", self.tun_subnet)
    }
    fn local_ip_listen(&self) -> String {
        format!("10.{}.0.2/30", self.tun_subnet)
    }
    fn peer_ip_listen(&self) -> String {
        format!("10.{}.0.1", self.tun_subnet)
    }

    fn teardown(&self) {
        let _ = run_ip(&["netns", "del", &self.ns]);
        let _ = run_ip(&["link", "del", &self.veth_root]);
    }
}

impl Drop for TestNet {
    fn drop(&mut self) {
        self.teardown();
    }
}

/// Builds an `[l3]` config as a TOML string.
#[allow(clippy::too_many_arguments)]
fn l3_config(
    mode: &str,
    addr: &str,
    layer: u8,
    iface: &str,
    local_ip: Option<&str>,
    peer_ip: Option<&str>,
    carrier: &str,
    gre_key: u32,
    ports: &str,
) -> Config {
    let mut toml = format!(
        "role = \"entry\"\nmode = \"direct\"\n[tunnel]\ntoken = \"{TOKEN}\"\n\
         [l3]\nmode = \"{mode}\"\naddr = \"{addr}\"\nlayer = {layer}\niface = \"{iface}\"\n\
         carrier = \"{carrier}\"\ngre_key = {gre_key}\nmtu = 1400\n"
    );
    if let Some(local_ip) = local_ip {
        toml.push_str(&format!("local_ip = \"{local_ip}\"\n"));
    }
    if let Some(peer_ip) = peer_ip {
        toml.push_str(&format!("peer_ip = \"{peer_ip}\"\n"));
    }
    toml.push_str(ports);
    Config::parse(&toml).expect("config parses")
}

/// A running endpoint on its own thread and runtime; set the flag and join to stop it.
struct Endpoint {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl Endpoint {
    /// Runs `config`'s l3 endpoint (and optionally a TCP echo server) in network namespace
    /// `ns` (or the root namespace when `None`).
    fn spawn(config: Config, ns: Option<String>, echo_port: Option<u16>) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let handle = std::thread::spawn(move || {
            if let Some(ns) = &ns {
                enter_netns(ns);
            }
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime");
            rt.block_on(async move {
                let stopper = wait_stop(flag);
                let endpoint = async {
                    if let Err(e) = kariz::l3::run(config).await {
                        eprintln!("l3 endpoint exited early: {e:#}");
                    }
                };
                match echo_port {
                    Some(port) => {
                        tokio::select! {
                            _ = endpoint => {}
                            _ = echo_server(port) => {}
                            _ = stopper => {}
                        }
                    }
                    None => {
                        tokio::select! {
                            _ = endpoint => {}
                            _ = stopper => {}
                        }
                    }
                }
            });
        });
        Self {
            stop,
            handle: Some(handle),
        }
    }
}

impl Drop for Endpoint {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Enters network namespace `name` on the current thread.
fn enter_netns(name: &str) {
    use nix::sched::{setns, CloneFlags};
    let path = format!("/var/run/netns/{name}");
    let file = std::fs::File::open(&path).unwrap_or_else(|e| panic!("open {path}: {e}"));
    setns(file, CloneFlags::CLONE_NEWNET).expect("setns");
}

async fn wait_stop(flag: Arc<AtomicBool>) {
    while !flag.load(Ordering::Relaxed) {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// A TCP echo server that bounces back whatever it is sent.
async fn echo_server(port: u16) {
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port))
        .await
        .expect("bind echo server");
    loop {
        if let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    match socket.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if socket.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    }
}

/// Tries to connect to `addr` and echo a probe across it, retrying until `deadline`.
fn tcp_echo_across(addr: &str, deadline: Instant) -> bool {
    let probe = b"kariz-l3-probe";
    let target: std::net::SocketAddr = addr.parse().expect("addr");
    while Instant::now() < deadline {
        if let Ok(mut stream) = TcpStream::connect_timeout(&target, Duration::from_secs(1)) {
            stream.set_read_timeout(Some(Duration::from_secs(2))).ok();
            stream.set_write_timeout(Some(Duration::from_secs(2))).ok();
            if stream.write_all(probe).is_ok() {
                let mut got = [0u8; 32];
                if let Ok(n) = stream.read(&mut got) {
                    if &got[..n] == probe {
                        return true;
                    }
                }
            }
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    false
}

/// Brings up a layer-3 tunnel over `carrier` and checks TCP flows across it.
fn tunnel_e2e(
    tag: &str,
    carrier: &str,
    tun_sub: u8,
    carr_sub: u8,
    carrier_port: u16,
    echo_port: u16,
) {
    if !l3_ready() {
        eprintln!("skipping l3 {carrier} test: needs Linux + /dev/net/tun + root + ip + netns");
        return;
    }
    let net = TestNet::setup(tag, tun_sub, carr_sub);
    let iface_a = format!("kza{tag}");
    let iface_b = format!("kzb{tag}");

    // Dialer in the root namespace, with a userspace port forward to the peer's echo server.
    let fwd_port = echo_port + 1;
    let ports =
        format!("[[l3.ports]]\nlisten = \"127.0.0.1:{fwd_port}\"\ntarget = \"{echo_port}\"\n");
    let dial = l3_config(
        "dial",
        &net.carrier_dial(carrier_port),
        3,
        &iface_a,
        Some(&net.local_ip_dial()),
        Some(&net.peer_ip_dial()),
        carrier,
        0,
        &ports,
    );
    // Listener in its own namespace, running the echo server the dialer reaches.
    let listen = l3_config(
        "listen",
        &net.carrier_listen(carrier_port),
        3,
        &iface_b,
        Some(&net.local_ip_listen()),
        Some(&net.peer_ip_listen()),
        carrier,
        0,
        "",
    );

    let _listener = Endpoint::spawn(listen, Some(net.ns.clone()), Some(echo_port));
    let _dialer = Endpoint::spawn(dial, None, None);

    let deadline = Instant::now() + Duration::from_secs(25);
    // Direct TCP across the tunnel (to the peer's tunnel IP).
    let direct = format!("10.{tun_sub}.0.2:{echo_port}");
    assert!(
        tcp_echo_across(&direct, deadline),
        "{carrier}: no TCP connectivity across the l3 tunnel"
    );
    // The userspace port forwarder over the link.
    let forwarded = format!("127.0.0.1:{fwd_port}");
    assert!(
        tcp_echo_across(&forwarded, Instant::now() + Duration::from_secs(10)),
        "{carrier}: the forwarded TCP port did not reach the peer over the link"
    );
}

#[test]
fn l3_tun_over_udp() {
    tunnel_e2e("u3", "udp", 31, 131, 52001, 52101);
}

#[test]
fn l3_tun_over_quic() {
    tunnel_e2e("q3", "quic", 32, 132, 52002, 52102);
}

/// Layer 2 (GRETAP): two TAP devices, addressed, so an Ethernet-level exchange (ARP then
/// the TCP flow) crosses the encrypted GRETAP tunnel.
#[test]
fn l3_tap_layer2() {
    if !l3_ready() {
        eprintln!("skipping l3 layer-2 test: needs Linux + /dev/net/tun + root + ip + netns");
        return;
    }
    let (tag, tun_sub, carr_sub, carrier_port, echo_port) = ("l2", 33u8, 133u8, 52003u16, 52103u16);
    let net = TestNet::setup(tag, tun_sub, carr_sub);
    let iface_a = format!("kza{tag}");
    let iface_b = format!("kzb{tag}");

    let dial = l3_config(
        "dial",
        &net.carrier_dial(carrier_port),
        2,
        &iface_a,
        Some(&net.local_ip_dial()),
        Some(&net.peer_ip_dial()),
        "udp",
        0,
        "",
    );
    let listen = l3_config(
        "listen",
        &net.carrier_listen(carrier_port),
        2,
        &iface_b,
        Some(&net.local_ip_listen()),
        Some(&net.peer_ip_listen()),
        "udp",
        0,
        "",
    );

    let _listener = Endpoint::spawn(listen, Some(net.ns.clone()), Some(echo_port));
    let _dialer = Endpoint::spawn(dial, None, None);

    let deadline = Instant::now() + Duration::from_secs(25);
    let direct = format!("10.{tun_sub}.0.2:{echo_port}");
    assert!(
        tcp_echo_across(&direct, deadline),
        "layer 2: no Ethernet-level connectivity across the GRETAP tunnel"
    );
}

/// A mismatched GRE key is refused by the control exchange, so no tunnel forms. (The encap
/// value itself is always "gre"; its by-name refusal is covered by the session unit tests.)
#[test]
fn l3_key_mismatch_refused() {
    if !l3_ready() {
        eprintln!("skipping l3 mismatch test: needs Linux + /dev/net/tun + root + ip + netns");
        return;
    }
    let (tag, tun_sub, carr_sub, carrier_port, echo_port) = ("em", 34u8, 134u8, 52004u16, 52104u16);
    let net = TestNet::setup(tag, tun_sub, carr_sub);
    let iface_a = format!("kza{tag}");
    let iface_b = format!("kzb{tag}");

    let dial = l3_config(
        "dial",
        &net.carrier_dial(carrier_port),
        3,
        &iface_a,
        Some(&net.local_ip_dial()),
        Some(&net.peer_ip_dial()),
        "udp",
        1, // key 1
        "",
    );
    let listen = l3_config(
        "listen",
        &net.carrier_listen(carrier_port),
        3,
        &iface_b,
        Some(&net.local_ip_listen()),
        Some(&net.peer_ip_listen()),
        "udp",
        2, // key 2 — a mismatch
        "",
    );

    let _listener = Endpoint::spawn(listen, Some(net.ns.clone()), Some(echo_port));
    let _dialer = Endpoint::spawn(dial, None, None);

    // With a key mismatch the control exchange refuses, so nothing crosses the tunnel.
    let direct = format!("10.{tun_sub}.0.2:{echo_port}");
    assert!(
        !tcp_echo_across(&direct, Instant::now() + Duration::from_secs(6)),
        "a GRE-key mismatch must not establish a working tunnel"
    );
}

/// Whether the l3 endpoint at `sock` reports its peer connected over the control socket.
async fn peer_connected_on(sock: &std::path::Path) -> bool {
    let Ok(stream) = kariz::control::connect(sock).await else {
        return false;
    };
    matches!(kariz::control::status(stream).await, Ok(s) if s.peer.connected)
}

/// Regression test for the panel's "waiting for both sides to connect": an l3 endpoint must
/// report its peer as connected over the control socket — the status `kariz status` and the
/// panel read — not merely move packets. Before this was wired, an l3 tunnel could be fully
/// up yet serve no control socket, so the panel timed out with an empty reason ("the two
/// sides did not connect in time") even though the link was live.
#[test]
fn l3_reports_connected_over_the_control_socket() {
    if !l3_ready() {
        eprintln!("skipping l3 status test: needs Linux + /dev/net/tun + root + ip + netns");
        return;
    }
    let (tag, tun_sub, carr_sub, carrier_port) = ("st", 35u8, 135u8, 52005u16);
    let net = TestNet::setup(tag, tun_sub, carr_sub);
    let iface_a = format!("kza{tag}");
    let iface_b = format!("kzb{tag}");

    let dir = std::env::temp_dir();
    let dial_sock = dir.join(format!("kz-l3-dial-{}.sock", std::process::id()));
    let listen_sock = dir.join(format!("kz-l3-listen-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&dial_sock);
    let _ = std::fs::remove_file(&listen_sock);

    let make = |mode: &str,
                addr: String,
                iface: &str,
                local: String,
                peer: String,
                sock: &std::path::Path| {
        let toml = format!(
            "role = \"entry\"\nmode = \"direct\"\n[tunnel]\ntoken = \"{TOKEN}\"\n\
             [control]\nsocket = \"{}\"\n\
             [l3]\nmode = \"{mode}\"\naddr = \"{addr}\"\nlayer = 3\niface = \"{iface}\"\n\
             carrier = \"udp\"\ngre_key = 0\nmtu = 1400\n\
             local_ip = \"{local}\"\npeer_ip = \"{peer}\"\n",
            sock.display()
        );
        Config::parse(&toml).expect("config parses")
    };

    let dial = make(
        "dial",
        net.carrier_dial(carrier_port),
        &iface_a,
        net.local_ip_dial(),
        net.peer_ip_dial(),
        &dial_sock,
    );
    let listen = make(
        "listen",
        net.carrier_listen(carrier_port),
        &iface_b,
        net.local_ip_listen(),
        net.peer_ip_listen(),
        &listen_sock,
    );

    let _listener = Endpoint::spawn(listen, Some(net.ns.clone()), None);
    let _dialer = Endpoint::spawn(dial, None, None);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let connected = rt.block_on(async {
        let deadline = Instant::now() + Duration::from_secs(25);
        loop {
            if peer_connected_on(&dial_sock).await && peer_connected_on(&listen_sock).await {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
    });
    let _ = std::fs::remove_file(&dial_sock);
    let _ = std::fs::remove_file(&listen_sock);
    assert!(
        connected,
        "both l3 ends must report peer.connected over the control socket (what the panel polls)"
    );
}
