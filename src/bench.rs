//! A transport benchmark between two servers: short-lived test links over each transport a
//! tunnel could use, made the way a tunnel's connections are (the token handshake, the
//! encrypted records, the mux, the tunnel's profile) and measured the way a tunnel's speed
//! test measures one ([`crate::speedtest`]).
//!
//! One end listens ([`listen`], then [`answer`]: one test session, then it goes away); the
//! other dials ([`dial`]), times the handshake, measures round trips ([`probe`]) and, if
//! asked, moves data both ways for a few seconds ([`speed`]). Nothing is written to disk and
//! no tunnel is made: the web panel runs this on two of its servers before a tunnel is built,
//! to find the transport that gets through best between them.

use std::io;
use std::path::Path;
use std::time::Duration;

use bytes::Bytes;
use tokio::task::JoinSet;
use tokio::time::{timeout, timeout_at, Instant};

use crate::config::TransportKind;
use crate::link::{Acceptor, Dialer, Shape};
use crate::mux::Side;
use crate::session::Session;
use crate::speedtest::{self, Latency, Options, Pipe, Rate};

/// The transports a benchmark measures, in the order it measures them. `tcp` without mux
/// moves data like `tcpmux` (one connection per user connection instead of one shared), and
/// `auto` switches between `tcpmux`, `kcp` and `ws`: all three are judged by those.
///
/// The always-mux WebSocket twins (`wsmux`, `wssmux`) move data exactly like `ws` / `wss`
/// but are measured under their own name, because a tunnel set to them cannot turn mux off.
/// `stealth` is measured like `tcpmux` (an encrypted TCP stream; its record padding and
/// jitter are on the link but add no handshake the benchmark has to arrange). `udp`,
/// `faketcp` and `icmp` all ride the KCP stack over a datagram carrier, so the benchmark
/// measures them over a reliable test stream the way `kcp` is measured; what differs is the
/// carrier (plain UDP, a raw fake-TCP segment, an ICMP echo), which is exactly the path
/// quality the pre-tunnel benchmark exists to compare.
///
/// The root-only raw carriers (`faketcp`, `icmp`) are left in the list but are skipped, not
/// failed, when they cannot be brought up: their listener/dialer returns a clear
/// `PermissionDenied` ("needs root or CAP_NET_RAW") or `Unsupported` (not Linux, or the
/// `rawlink` feature off), which the bench runner records as that candidate's reason while
/// the other candidates keep going (see `panel/src/bench.rs`). They are included only when
/// the `rawlink` feature is built in.
///
/// The managed-helper transports (`naive`, `xhttp`, `reality`) are deliberately **not**
/// here: a benchmark link is made from a token alone, but a helper needs a full
/// `[tunnel.helper]` credential set (certificates, UUIDs, keys, a cover target) and an
/// installed, supervised helper binary on both ends, none of which the synthetic benchmark
/// config can supply. They are validated by `kariz check` and exercised by the helper e2e
/// tests instead.
const fn transports_len() -> usize {
    // tcpmux, stealth, ws, wsmux, wss and wssmux are in every release build and need no
    // optional feature; the rest are added only when their feature is on.
    let mut n = 6;
    if cfg!(feature = "kcp") {
        n += 2; // kcp, udp
    }
    if cfg!(feature = "rawlink") {
        n += 2; // faketcp, icmp (rawlink implies kcp)
    }
    if cfg!(feature = "quic") {
        n += 1; // quic
    }
    n
}

pub const TRANSPORTS: [TransportKind; transports_len()] = [
    TransportKind::Tcpmux,
    TransportKind::Stealth,
    TransportKind::Ws,
    TransportKind::Wsmux,
    TransportKind::Wss,
    TransportKind::Wssmux,
    #[cfg(feature = "kcp")]
    TransportKind::Kcp,
    #[cfg(feature = "kcp")]
    TransportKind::Udp,
    #[cfg(feature = "rawlink")]
    TransportKind::Faketcp,
    #[cfg(feature = "rawlink")]
    TransportKind::Icmp,
    #[cfg(feature = "quic")]
    TransportKind::Quic,
];

/// Longest a test session lives on the listening end, whatever the dialing end does.
pub const MAX_SESSION: Duration = Duration::from_secs(45);

pub(crate) fn check(kind: TransportKind) -> io::Result<()> {
    if TRANSPORTS.contains(&kind) {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("a benchmark does not measure {}", kind.name()),
        ))
    }
}

/// A profile name a tunnel accepts.
fn profile(name: &str) -> io::Result<&str> {
    match name {
        "balanced" | "ultraspeed" | "gaming" => Ok(name),
        other => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unknown profile {other:?}"),
        )),
    }
}

fn shape<'a>(
    kind: TransportKind,
    profile_name: &'a str,
    sni: Option<&'a str>,
) -> io::Result<Shape<'a>> {
    Ok(Shape {
        kind,
        profile: Some(profile(profile_name)?),
        any: true,
        sni,
    })
}

/// Listens on `addr` over `kind` for one test session made with `token`. `tls` is the
/// certificate and key of a `wss` listener (any certificate: the dialing end does not check
/// it, the token handshake inside proves who is there).
pub async fn listen(
    addr: &str,
    token: &str,
    kind: TransportKind,
    profile_name: &str,
    tls: Option<(&Path, &Path)>,
) -> io::Result<Acceptor> {
    Acceptor::bind_shape(addr, token, shape(kind, profile_name, None)?, tls).await
}

/// Waits up to `wait` for the dialing end, then answers its test streams until it hangs up
/// (or [`MAX_SESSION`] has passed). Connections without the token are let go; the first one
/// that has it is the test session, and the listener closes when it ends.
pub async fn answer(acceptor: Acceptor, wait: Duration) -> io::Result<()> {
    let deadline = Instant::now() + wait;
    let mut handshakes = JoinSet::new();
    let session = loop {
        tokio::select! {
            accepted = timeout_at(deadline, acceptor.accept()) => {
                match accepted {
                    Ok(Ok(pending)) => {
                        handshakes.spawn(pending.establish(Side::Server));
                    }
                    Ok(Err(e)) => return Err(e),
                    Err(_) => {
                        return Err(io::Error::new(io::ErrorKind::TimedOut, "nobody came"));
                    }
                }
            }
            Some(done) = handshakes.join_next() => {
                if let Ok(Ok(session)) = done {
                    break session;
                }
            }
        }
    };
    // The listener stays until the session ends (a KCP session's packets come in through
    // its socket); it takes no other connection.
    handshakes.abort_all();
    let end = Instant::now() + MAX_SESSION;
    let mut streams = JoinSet::new();
    while let Ok(Some((stream, syn))) = timeout_at(end, session.accept()).await {
        let command = String::from_utf8_lossy(&syn).into_owned();
        streams.spawn(async move {
            let _ = speedtest::serve(Pipe::Stream(stream), &command).await;
        });
    }
    session.close();
    streams.abort_all();
    drop(acceptor);
    Ok(())
}

/// Dials `addr` over `kind` with `token`: the test session, and how long the connection and
/// its handshake took (in milliseconds). `sni` is the server name a `wss` link sends, as a
/// tunnel with a domain would (none: none is sent, as for an IP address).
pub async fn dial(
    addr: &str,
    token: &str,
    kind: TransportKind,
    profile_name: &str,
    sni: Option<&str>,
    limit: Duration,
) -> io::Result<(Session, f64)> {
    let dialer = Dialer::shaped(addr, token, shape(kind, profile_name, sni)?)?;
    let start = Instant::now();
    let session = timeout(limit, dialer.connect(Side::Client))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "no connection in time"))??;
    Ok((session, round1(start.elapsed().as_secs_f64() * 1000.0)))
}

/// Round trips on the test session for `over`.
pub async fn probe(session: &Session, over: Duration) -> io::Result<Latency> {
    let stream = session.open(Bytes::from_static(b"echo"))?;
    Ok(speedtest::latency(Pipe::Stream(stream), over).await)
}

/// What [`speed`] measured.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Speed {
    pub download: Rate,
    pub upload: Rate,
    /// Round trips while data moves (both directions together).
    pub loaded: Latency,
}

/// Moves data each way for `seconds` on `streams` streams.
pub async fn speed(session: &Session, seconds: u64, streams: usize) -> io::Result<Speed> {
    let open = |command: &'static str| {
        let stream = session.open(Bytes::from_static(command.as_bytes()));
        async move { Ok(Pipe::Stream(stream?)) }
    };
    let options = Options {
        seconds,
        streams,
        udp: false,
    };
    let ((download, down_latency), (upload, up_latency)) =
        speedtest::rates(open, options, |_| {}).await?;
    Ok(Speed {
        download,
        upload,
        loaded: worse(down_latency, up_latency),
    })
}

/// The two latencies under load as one: the slower middle and spread, all the samples.
fn worse(a: Latency, b: Latency) -> Latency {
    Latency {
        sent: a.sent + b.sent,
        received: a.received + b.received,
        p50_ms: a.p50_ms.max(b.p50_ms),
        p99_ms: a.p99_ms.max(b.p99_ms),
        jitter_ms: a.jitter_ms.max(b.jitter_ms),
    }
}

fn round1(x: f64) -> f64 {
    (x * 10.0).round() / 10.0
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "0123456789abcdef0123456789abcdef";

    async fn measured(kind: TransportKind, tls: Option<(&Path, &Path)>) -> (f64, Latency, Speed) {
        measured_at("127.0.0.1:0", kind, tls, None).await
    }

    async fn measured_at(
        at: &str,
        kind: TransportKind,
        tls: Option<(&Path, &Path)>,
        sni: Option<&str>,
    ) -> (f64, Latency, Speed) {
        measured_token(at, TOKEN, kind, tls, sni).await
    }

    async fn measured_token(
        at: &str,
        token: &str,
        kind: TransportKind,
        tls: Option<(&Path, &Path)>,
        sni: Option<&str>,
    ) -> (f64, Latency, Speed) {
        let acceptor = listen(at, token, kind, "balanced", tls).await.unwrap();
        let addr = acceptor.local_addr().unwrap().to_string();
        let server = tokio::spawn(answer(acceptor, Duration::from_secs(10)));
        let (session, ms) = dial(&addr, token, kind, "balanced", sni, Duration::from_secs(10))
            .await
            .unwrap();
        let latency = probe(&session, Duration::from_millis(500)).await.unwrap();
        let speed = speed(&session, 1, 2).await.unwrap();
        session.close();
        // The listening end goes away once its session ends.
        timeout(Duration::from_secs(10), server)
            .await
            .expect("the listener did not end")
            .unwrap()
            .unwrap();
        (ms, latency, speed)
    }

    fn sane(kind: TransportKind, (ms, latency, speed): (f64, Latency, Speed)) {
        assert!(ms > 0.0, "{kind:?}: {ms}");
        assert!(latency.received > 0, "{kind:?}: {latency:?}");
        assert!(
            speed.download.mbps > 0.0 && speed.upload.mbps > 0.0,
            "{kind:?}: {speed:?}"
        );
    }

    #[tokio::test]
    async fn tcpmux_and_ws_are_measured() {
        for kind in [TransportKind::Tcpmux, TransportKind::Ws] {
            sane(kind, measured(kind, None).await);
        }
    }

    /// `stealth` (encrypted TCP with record padding) and `wsmux` (ws that cannot turn mux
    /// off) are measured like `tcpmux` and `ws`, over plain TCP with no certificate.
    #[tokio::test]
    async fn stealth_and_wsmux_are_measured() {
        for kind in [TransportKind::Stealth, TransportKind::Wsmux] {
            sane(kind, measured(kind, None).await);
        }
    }

    #[cfg(feature = "kcp")]
    #[tokio::test]
    async fn kcp_is_measured() {
        sane(TransportKind::Kcp, measured(TransportKind::Kcp, None).await);
    }

    /// `udp` rides the KCP stack over a plain UDP carrier; the benchmark measures it over a
    /// reliable test stream, the way `kcp` is measured.
    #[cfg(feature = "kcp")]
    #[tokio::test]
    async fn udp_is_measured() {
        sane(TransportKind::Udp, measured(TransportKind::Udp, None).await);
    }

    #[cfg(feature = "quic")]
    #[tokio::test]
    async fn quic_is_measured() {
        sane(
            TransportKind::Quic,
            measured(TransportKind::Quic, None).await,
        );
    }

    #[tokio::test]
    async fn wss_is_measured_with_any_certificate() {
        let c = rcgen::generate_simple_self_signed(vec!["bench.example".to_owned()]).unwrap();
        let dir = std::env::temp_dir().join(format!("kariz-bench-wss-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (cert, key) = (dir.join("cert.pem"), dir.join("key.pem"));
        std::fs::write(&cert, c.cert.pem()).unwrap();
        std::fs::write(&key, c.signing_key.serialize_pem()).unwrap();
        // `wss`, and its always-mux twin `wssmux`, both with the same throwaway certificate.
        for kind in [TransportKind::Wss, TransportKind::Wssmux] {
            sane(kind, measured(kind, Some((&cert, &key))).await);
        }
        // A server name that is not the certificate's, as a tunnel with a domain sends it.
        sane(
            TransportKind::Wss,
            measured_at(
                "127.0.0.1:0",
                TransportKind::Wss,
                Some((&cert, &key)),
                Some("front.example"),
            )
            .await,
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn ipv6_is_measured_where_the_machine_has_it() {
        if std::net::TcpListener::bind("[::1]:0").is_err() {
            return;
        }
        sane(
            TransportKind::Tcpmux,
            measured_at("[::1]:0", TransportKind::Tcpmux, None, None).await,
        );
    }

    #[tokio::test]
    async fn nobody_coming_and_a_wrong_token_end_the_listener() {
        let acceptor = listen("127.0.0.1:0", TOKEN, TransportKind::Tcpmux, "gaming", None)
            .await
            .unwrap();
        let addr = acceptor.local_addr().unwrap().to_string();
        let server = tokio::spawn(answer(acceptor, Duration::from_millis(1500)));
        let wrong = dial(
            &addr,
            "another-token-0123456789abcdef",
            TransportKind::Tcpmux,
            "gaming",
            None,
            Duration::from_secs(1),
        )
        .await;
        assert!(wrong.is_err(), "a wrong token got a session");
        let ended = timeout(Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(ended.unwrap_err().kind(), io::ErrorKind::TimedOut);
    }

    /// The root-only raw carriers are measured here when the host can bring them up (Linux,
    /// root / `CAP_NET_RAW`, iptables), and otherwise skipped with a printed reason instead
    /// of failing: their listener returns a clear `PermissionDenied` / `Unsupported` that
    /// the bench runner records as that candidate's reason. Serialised, because the raw
    /// socket, the token-derived source port and the iptables rules are global to the host.
    #[cfg(feature = "rawlink")]
    #[tokio::test(flavor = "multi_thread")]
    async fn faketcp_and_icmp_are_measured_or_skipped_cleanly() {
        // An async mutex, so the guard may be held across the measurement's awaits.
        static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

        let ready = cfg!(target_os = "linux")
            && std::process::Command::new("iptables")
                .arg("-S")
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);

        for (kind, token) in [
            (TransportKind::Faketcp, "bench-faketcp-token-0123456789ab"),
            (TransportKind::Icmp, "bench-icmp-token-0123456789abcdef"),
        ] {
            // They are transports a benchmark measures, so a run reaches them at all.
            assert!(check(kind).is_ok(), "{kind:?} should be benchmarkable");
            if !ready {
                eprintln!(
                    "skipping {}: the raw-packet carriers need Linux + root + iptables",
                    kind.name()
                );
                continue;
            }
            let _serial = SERIAL.lock().await;
            // A real free TCP port: the raw carriers address a port but bind no kernel
            // socket on it, so nothing else must be listening there.
            let port = std::net::TcpListener::bind("127.0.0.1:0")
                .unwrap()
                .local_addr()
                .unwrap()
                .port();
            let at = format!("127.0.0.1:{port}");
            sane(kind, measured_token(&at, token, kind, None, None).await);
        }
    }

    #[test]
    fn only_tunnel_transports_and_profiles_are_taken() {
        // Not measured: plain tcp (judged by tcpmux), auto (judged by its members), and the
        // managed-helper transports (a token-only test link cannot carry their credentials).
        for kind in [
            TransportKind::Tcp,
            TransportKind::Auto,
            TransportKind::Naive,
            TransportKind::Xhttp,
            TransportKind::Reality,
        ] {
            assert!(check(kind).is_err(), "{kind:?} must not be measured");
        }
        // Measured: every transport a tunnel can actually be set to and benchmarked.
        assert!(check(TransportKind::Ws).is_ok());
        assert!(check(TransportKind::Stealth).is_ok());
        assert!(check(TransportKind::Wsmux).is_ok());
        assert!(check(TransportKind::Wssmux).is_ok());
        #[cfg(feature = "kcp")]
        assert!(check(TransportKind::Udp).is_ok());
        #[cfg(feature = "rawlink")]
        {
            assert!(check(TransportKind::Faketcp).is_ok());
            assert!(check(TransportKind::Icmp).is_ok());
        }
        assert!(profile("ultraspeed").is_ok());
        assert!(profile("fast").is_err());
    }
}
