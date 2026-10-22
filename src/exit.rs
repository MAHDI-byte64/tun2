//! Exit side: receives open requests through the tunnel and connects to the targets.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use bytes::Bytes;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;
use tokio::time::{sleep, timeout};
use tracing::{debug, error, info, warn};

use crate::auto::{self, Dial};
use crate::channel::{self, Channel, Link};
use crate::config::{Config, Mode, TransportKind, Tuning};
use crate::crypto::{Crypto, ReplayFilter};
use crate::fallback;
use crate::mux::{MuxSession, SessionConfig, Side};
use crate::proto::{
    self, Open, KIND_PROBE, KIND_SPEEDTEST, KIND_UDP, STATUS_DIAL_FAILED, STATUS_OK,
    STATUS_UNSUPPORTED,
};
use crate::relay::{relay, relay_stream, Counters};
#[cfg(feature = "quic")]
use crate::session::quic::{accept_sessions, QuicSession};
use crate::session::{maintain, ResetReason, Session, SessionStream};
use crate::speedtest::{self, Pipe};
use crate::stats::Stats;
#[cfg(feature = "quic")]
use crate::transport::quic::{QuicDialer, QuicListener, QuicSettings};
use crate::transport::{tcp, Dialer, Listener, Settings};
use crate::udp;

const BACKOFF_MIN: Duration = Duration::from_millis(500);
const BACKOFF_MAX: Duration = Duration::from_secs(10);

/// Speed test streams the exit serves at once.
const SPEEDTEST_STREAMS: usize = 48;
/// A health probe's connection to its target gives up after this long, well before the
/// entry side stops waiting for the answer.
const PROBE_DIAL: Duration = Duration::from_secs(5);
/// How long a probe stream waits for the entry side to close it after the answer.
const PROBE_LINGER: Duration = Duration::from_secs(10);

struct Exit {
    crypto: Crypto,
    tuning: Tuning,
    /// Slots for speed test streams; `None` when `tunnel.speedtest` is off.
    speedtest: Option<Arc<Semaphore>>,
    /// The udp transport forwards on the unreliable path only (see [`udp::relay`]).
    datagram_only: bool,
    stats: Arc<Stats>,
}

impl Exit {
    /// Counters for a relay with a target: what is read from the target goes down to the
    /// users, what is written to it came up from them.
    fn target_counters(&self) -> Counters<'_> {
        Counters {
            read: &self.stats.targets.traffic.down,
            written: &self.stats.targets.traffic.up,
        }
    }

    /// A slot for a speed test stream, or why there is none.
    fn speedtest_slot(&self) -> Result<OwnedSemaphorePermit, ResetReason> {
        let slots = self.speedtest.as_ref().ok_or(ResetReason::Unsupported)?;
        slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| ResetReason::Refused)
    }
}

pub async fn run(config: Config) -> Result<()> {
    let tuning = config.tuning();
    let mux = config.mux();
    let base = Settings::new(&config.tunnel, config.kcp());
    let sessions = SessionConfig::new(&mux);
    let stats = Stats::new(&config);
    let speedtest = config
        .tunnel
        .speedtest
        .then(|| Arc::new(Semaphore::new(SPEEDTEST_STREAMS)));
    let mut tasks = JoinSet::new();
    // The byte counters go on from where the last run left them (docs/status.md).
    if let Some(path) = config.traffic_file() {
        stats.restore(&path);
        tasks.spawn(crate::stats::persist(stats.clone(), path));
    }

    // `kariz status` reads the counters through this (Unix only). It uses the shared stats,
    // so it outlives any transport the fallback chain rotates through.
    #[cfg(unix)]
    if let Some(socket) = config.control_socket() {
        let serve = crate::control::serve(
            socket,
            None::<crate::control::NoOpen>,
            None::<crate::control::NoReload>,
            stats.clone(),
        );
        tasks.spawn(serve);
    }

    // Bring the tunnel up: one transport, or a fallback chain that rotates through its
    // candidates, each with its own `Exit` (its own crypto) over the shared stats.
    if config.tunnel.fallback_transports.is_empty() {
        let exit = Arc::new(Exit {
            crypto: fallback::crypto_for(&config, mux.enabled, &base),
            tuning: tuning.clone(),
            speedtest,
            datagram_only: config.tunnel.transport == TransportKind::Udp,
            stats,
        });
        build_exit(&config, &base, &exit, &sessions, &tuning, &mux, &mut tasks).await?;
    } else {
        let acceptor = config.is_acceptor();
        let candidates = fallback::candidates(&config);
        let dwell = Duration::from_secs(config.tunnel.fallback_dwell_secs);
        let (config, base, sessions, tuning, mux) = (
            config.clone(),
            base.clone(),
            sessions.clone(),
            tuning.clone(),
            mux.clone(),
        );
        tasks.spawn(async move {
            let peer = stats.peer.clone();
            let chain_stats = stats.clone();
            fallback::run_chain(
                acceptor,
                "exit",
                candidates,
                dwell,
                mux.enabled,
                peer,
                chain_stats,
                move |kind| {
                    let (config, base, sessions, tuning, mux, stats, speedtest) = (
                        config.clone(),
                        base.clone(),
                        sessions.clone(),
                        tuning.clone(),
                        mux.clone(),
                        stats.clone(),
                        speedtest.clone(),
                    );
                    async move {
                        let settings = fallback::settings_for(&base, &config.tunnel, kind);
                        let exit = Arc::new(Exit {
                            crypto: fallback::crypto_for(&config, mux.enabled, &settings),
                            tuning: tuning.clone(),
                            speedtest,
                            // The udp transport cannot be a fallback candidate.
                            datagram_only: false,
                            stats,
                        });
                        let mut set = JoinSet::new();
                        build_exit(
                            &config, &settings, &exit, &sessions, &tuning, &mux, &mut set,
                        )
                        .await?;
                        Ok(set)
                    }
                },
            )
            .await
        });
    }

    match tasks.join_next().await {
        Some(Ok(result)) => result,
        Some(Err(e)) => Err(e.into()),
        None => Ok(()),
    }
}

/// Builds the exit machinery for `transport` and spawns it into `tasks`: the QUIC
/// acceptor/dialer, the mux session loop (either mode), the non-mux reverse pool, or the
/// direct accept loop. Called once for a single transport, and once per candidate by the
/// fallback chain (with the candidate's own `transport` and `exit`, and its own `tasks`).
async fn build_exit(
    config: &Config,
    transport: &Settings,
    exit: &Arc<Exit>,
    sessions: &SessionConfig,
    tuning: &Tuning,
    mux: &crate::config::MuxSettings,
    tasks: &mut JoinSet<Result<()>>,
) -> Result<()> {
    if transport.kind == TransportKind::Quic {
        run_quic(config, exit, sessions, tasks).await?;
        return Ok(());
    }
    match config.mode {
        Mode::Reverse if mux.enabled => {
            let remote = config.tunnel.remote.as_deref().expect("validated");
            info!(
                remote,
                connections = mux.connections,
                "exit: reverse mode with mux, keeping sessions to the entry side"
            );
            let dialer = Arc::new(if config.tunnel.transport == TransportKind::Auto {
                Dial::auto(transport, &config.tunnel.token, remote, tuning)?
            } else {
                Dial::one(transport, remote, tuning)?
            });
            for _ in 0..mux.connections {
                let (exit, dialer) = (exit.clone(), dialer.clone());
                let connect = {
                    let (exit, sessions) = (exit.clone(), sessions.clone());
                    move || {
                        let (exit, dialer, sessions) =
                            (exit.clone(), dialer.clone(), sessions.clone());
                        async move {
                            let wait = exit.tuning.dial_timeout + exit.tuning.handshake_timeout;
                            let (link, via) = dialer.connect(&exit.crypto, wait).await?;
                            let session = MuxSession::over(link, Side::Server, sessions);
                            if let Some(via) = via {
                                session.set_transport(via);
                            }
                            Ok(Session::Kmux(session))
                        }
                    }
                };
                let (lifetime, link) = (mux.max_lifetime, exit.stats.peer.clone());
                tasks.spawn(async move {
                    let on_session = move |s| {
                        tokio::spawn(run_session(exit.clone(), s));
                    };
                    maintain("the entry side", link, connect, lifetime, on_session).await;
                    Ok(())
                });
            }
        }
        Mode::Reverse => {
            let remote = config.tunnel.remote.as_deref().expect("validated");
            info!(
                remote,
                pool = config.tunnel.pool,
                "exit: reverse mode, connecting to the entry side"
            );
            let dialer = Arc::new(Dialer::new(transport, remote, tuning)?);
            for _ in 0..config.tunnel.pool {
                tasks.spawn(pool_worker(exit.clone(), dialer.clone()));
            }
        }
        Mode::Direct => {
            let addr = config.tunnel.listen.as_deref().expect("validated");
            let listeners = if config.tunnel.transport == TransportKind::Auto {
                auto::bind_all(transport, &config.tunnel.token, addr, tuning).await?
            } else {
                vec![(
                    "",
                    Listener::bind(transport, addr, tuning)
                        .await
                        .with_context(|| {
                            format!("failed to listen for tunnel connections on {addr}")
                        })?,
                )]
            };
            info!(
                addr = %listeners[0].1.local_addr()?,
                mux = mux.enabled,
                "exit: direct mode, waiting for the entry side"
            );
            let sessions = mux.enabled.then(|| sessions.clone());
            for (via, listener) in listeners {
                tasks.spawn(accept_direct(exit.clone(), listener, sessions.clone(), via));
            }
        }
    }
    Ok(())
}

/// Config validation rejects `transport = "quic"` in a build without it.
#[cfg(not(feature = "quic"))]
async fn run_quic(
    _: &Config,
    _: &Arc<Exit>,
    _: &SessionConfig,
    _: &mut JoinSet<Result<()>>,
) -> Result<()> {
    anyhow::bail!("this build has no QUIC support (the `quic` feature is off)")
}

/// QUIC, either mode: sessions with the entry side, each served by `run_session`.
/// Reverse mode keeps `mux.connections` of them up; direct mode accepts them.
#[cfg(feature = "quic")]
async fn run_quic(
    config: &Config,
    exit: &Arc<Exit>,
    sessions: &SessionConfig,
    tasks: &mut JoinSet<Result<()>>,
) -> Result<()> {
    let (tuning, mux) = (config.tuning(), config.mux());
    let quic_config = config.tunnel.quic.clone().unwrap_or_default();
    let quic = QuicSettings::new(exit.crypto.psk(), &quic_config, &mux, &tuning)?;
    let open_timeout = tuning.handshake_timeout;
    match config.mode {
        Mode::Reverse => {
            let remote = config.tunnel.remote.as_deref().expect("validated");
            let dialer = Arc::new(QuicDialer::new(remote, quic_config.sni.as_deref(), &quic)?);
            info!(
                remote,
                connections = mux.connections,
                congestion = quic_config.congestion.name(),
                "exit: reverse mode over QUIC, keeping sessions to the entry side"
            );
            for _ in 0..mux.connections {
                let (exit, dialer, sessions) = (exit.clone(), dialer.clone(), sessions.clone());
                let connect = move || {
                    let (dialer, sessions) = (dialer.clone(), sessions.clone());
                    async move {
                        let conn = dialer.connect().await?;
                        Ok(Session::Quic(QuicSession::new(
                            conn,
                            &sessions,
                            open_timeout,
                        )))
                    }
                };
                let (lifetime, link) = (mux.max_lifetime, exit.stats.peer.clone());
                tasks.spawn(async move {
                    let on_session = move |s| {
                        tokio::spawn(run_session(exit.clone(), s));
                    };
                    maintain("the entry side", link, connect, lifetime, on_session).await;
                    Ok(())
                });
            }
        }
        Mode::Direct => {
            let addr = config.tunnel.listen.as_deref().expect("validated");
            let listener = QuicListener::bind(addr, &quic)
                .await
                .with_context(|| format!("failed to listen for QUIC on {addr}"))?;
            info!(
                addr = %listener.local_addr()?,
                "exit: direct mode over QUIC, waiting for the entry side"
            );
            let exit = exit.clone();
            let link = exit.stats.peer.clone();
            let on_session = move |session: QuicSession, peer: std::net::SocketAddr| {
                info!(%peer, "quic session from the entry side established");
                let session = Arc::new(Session::Quic(session));
                exit.stats.peer.session_up(&session);
                tokio::spawn(run_session(exit.clone(), session));
            };
            let sessions = sessions.clone();
            tasks.spawn(async move {
                accept_sessions(listener, sessions, open_timeout, link, on_session).await;
                Ok(())
            });
        }
    }
    Ok(())
}

/// Reverse mode: keeps one idle, authenticated channel open towards the entry side.
/// As soon as it is used, a new one is dialed.
async fn pool_worker(exit: Arc<Exit>, dialer: Arc<Dialer>) -> Result<()> {
    let mut backoff = BACKOFF_MIN;
    loop {
        let mut link = match connect_once(&exit, &dialer).await {
            Ok(link) => {
                exit.stats.peer.link_up();
                backoff = BACKOFF_MIN;
                link
            }
            Err(e) => {
                exit.stats.peer.failed(&e);
                if matches!(
                    e.kind(),
                    io::ErrorKind::PermissionDenied | io::ErrorKind::Unsupported
                ) {
                    error!(error = %e, "entry side rejected us or failed authentication");
                } else {
                    warn!(error = %e, "could not connect to the entry side");
                }
                sleep(backoff).await;
                backoff = (backoff * 2).min(BACKOFF_MAX);
                continue;
            }
        };

        // Waits as long as needed; TCP keepalive notices a dead entry side.
        match Open::read(&mut link).await {
            Ok(open) => {
                let exit = exit.clone();
                tokio::spawn(async move { serve(&exit, link, open).await });
            }
            Err(e) => debug!(error = %e, "idle tunnel connection closed"),
        }
    }
}

async fn connect_once(exit: &Exit, dialer: &Dialer) -> io::Result<Link> {
    timeout(
        exit.tuning.dial_timeout + exit.tuning.handshake_timeout,
        channel::connect(dialer, &exit.crypto, &[]),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "handshake timed out"))?
}

/// Direct mode: authenticates connections from the entry side and serves them, each as
/// one channel or, with `sessions`, as a mux session.
async fn accept_direct(
    exit: Arc<Exit>,
    listener: Listener,
    sessions: Option<SessionConfig>,
    via: &'static str,
) -> Result<()> {
    let replay = Arc::new(ReplayFilter::default());
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "tunnel accept failed");
                sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let (exit, replay, sessions) = (exit.clone(), replay.clone(), sessions.clone());
        tokio::spawn(async move {
            let hs_timeout = exit.tuning.handshake_timeout;
            let link = match channel::accept(stream, &exit.crypto, &replay, hs_timeout).await {
                Ok(link) => link,
                Err(e) => {
                    exit.stats.peer.failed(&e);
                    return warn!(%peer, error = %e, "tunnel handshake failed");
                }
            };
            if let Some(config) = sessions {
                info!(%peer, "mux session from the entry side established");
                let session = MuxSession::over(link, Side::Server, config);
                if !via.is_empty() {
                    session.set_transport(via);
                }
                let session = Arc::new(Session::Kmux(session));
                exit.stats.peer.session_up(&session);
                return run_session(exit, session).await;
            }
            exit.stats.peer.link_up();
            let mut link = link;
            match timeout(hs_timeout, Open::read(&mut link)).await {
                Ok(Ok(open)) => serve(&exit, link, open).await,
                // The entry side's probe connects and leaves: not a fault.
                Ok(Err(e)) if e.kind() == io::ErrorKind::UnexpectedEof => {
                    debug!(%peer, "the entry side checked the link")
                }
                Ok(Err(e)) => warn!(%peer, error = %e, "bad open request"),
                Err(_) => warn!(%peer, "open request timed out"),
            }
        });
    }
}

async fn serve(exit: &Exit, mut tunnel: Link, open: Open) {
    if open.kind == KIND_PROBE {
        let status = probe_target(exit, &open.target).await;
        let _ = proto::write_status(&mut tunnel, status).await;
        return;
    }
    if open.kind == KIND_SPEEDTEST {
        let Ok(_slot) = exit.speedtest_slot() else {
            let _ = proto::write_status(&mut tunnel, STATUS_UNSUPPORTED).await;
            return;
        };
        if proto::write_status(&mut tunnel, STATUS_OK).await.is_err() {
            return;
        }
        let pipe = Pipe::from(Channel::Link(tunnel));
        let _ = speedtest::serve(pipe, &open.target).await;
        return;
    }
    exit.stats.targets.stream();
    if open.kind == KIND_UDP {
        return serve_udp(exit, tunnel, open).await;
    }
    let mut target = match connect_target(exit, &open).await {
        Ok(t) => t,
        Err(e) => {
            exit.stats.targets.dial_failed(&open.target, &e);
            warn!(target = %open.target, error = %e, "could not connect to target");
            let _ = proto::write_status(&mut tunnel, STATUS_DIAL_FAILED).await;
            return;
        }
    };
    if proto::write_status(&mut tunnel, STATUS_OK).await.is_err() {
        return;
    }
    if let Err(e) = relay(
        &mut target,
        &mut tunnel,
        exit.tuning.buffer_size,
        exit.target_counters(),
    )
    .await
    {
        debug!(target = %open.target, error = %e, "connection ended with error");
    }
}

/// Serves every stream the entry side opens on `session`, then lets the session drain.
async fn run_session(exit: Arc<Exit>, session: Arc<Session>) {
    while let Some((stream, syn)) = session.accept().await {
        let exit = exit.clone();
        tokio::spawn(async move { serve_stream(&exit, stream, syn).await });
    }
    session.drain().await;
    debug!(
        reason = session.close_reason().unwrap_or_default(),
        "{} session ended",
        session.kind()
    );
}

/// Session counterpart of [`serve`]: no status byte, a failed dial resets the stream.
async fn serve_stream(exit: &Exit, stream: SessionStream, syn: Bytes) {
    let open = match Open::decode(&syn) {
        Ok(open) => open,
        Err(e) => {
            warn!(error = %e, "bad open request");
            return stream.reset(ResetReason::Protocol);
        }
    };
    if open.kind == KIND_PROBE {
        let status = probe_target(exit, &open.target).await;
        if stream.send(Bytes::copy_from_slice(&[status])).await.is_ok() && stream.finish().is_ok() {
            // Dropped before the entry side is done, the stream would be reset, which
            // can overtake the answer: wait for its end first.
            let _ = timeout(PROBE_LINGER, async {
                while let Ok(Some(_)) = stream.recv().await {}
            })
            .await;
        }
        return;
    }
    if open.kind == KIND_SPEEDTEST {
        let _slot = match exit.speedtest_slot() {
            Ok(slot) => slot,
            Err(reason) => return stream.reset(reason),
        };
        let _ = speedtest::serve(Pipe::Stream(stream), &open.target).await;
        return;
    }
    exit.stats.targets.stream();
    if open.kind == KIND_UDP {
        let socket = match udp::connect(&open.target, &exit.tuning).await {
            Ok(s) => s,
            Err(e) => {
                exit.stats.targets.dial_failed(&open.target, &e);
                warn!(target = %open.target, error = %e, "could not open UDP to target");
                return stream.reset(ResetReason::DialFailed);
            }
        };
        return relay_udp(exit, Channel::Stream(stream), socket, &open).await;
    }
    let mut target = match connect_target(exit, &open).await {
        Ok(t) => t,
        Err(e) => {
            exit.stats.targets.dial_failed(&open.target, &e);
            warn!(target = %open.target, error = %e, "could not connect to target");
            return stream.reset(ResetReason::DialFailed);
        }
    };
    let size = exit.tuning.buffer_size;
    if let Err(e) = relay_stream(&mut target, &stream, size, exit.target_counters()).await {
        debug!(target = %open.target, error = %e, "connection ended with error");
    }
}

/// Connects to the target of a TCP `open` and, when the entry side asked for one, writes
/// the PROXY header to it before anything of the user's.
async fn connect_target(exit: &Exit, open: &Open) -> io::Result<TcpStream> {
    let mut target = tcp::connect(&open.target, &exit.tuning).await?;
    if let Some(proxy) = &open.proxy {
        target.write_all(&proxy.to_bytes()).await?;
    }
    Ok(target)
}

/// What a health probe of `target` answers: whether it could be connected to (an empty
/// target asks about the tunnel alone). The connection is closed at once and, being no
/// user's, is not counted. It sends nothing, no PROXY header either: a target that
/// expects one (Xray with `acceptProxyProtocol`) sees a connection that ends before the
/// header would have come, and simply drops it.
async fn probe_target(exit: &Exit, target: &str) -> u8 {
    if target.is_empty() {
        return STATUS_OK;
    }
    match timeout(PROBE_DIAL, tcp::connect(target, &exit.tuning)).await {
        Ok(Ok(_)) => STATUS_OK,
        Ok(Err(e)) => {
            debug!(%target, error = %e, "health probe: could not connect to target");
            STATUS_DIAL_FAILED
        }
        Err(_) => {
            debug!(%target, "health probe: connecting to target timed out");
            STATUS_DIAL_FAILED
        }
    }
}

/// UDP counterpart of [`serve`] (a whole channel): the status byte says whether the
/// target could be resolved, then packets flow length-prefixed.
async fn serve_udp(exit: &Exit, mut tunnel: Link, open: Open) {
    let socket = match udp::connect(&open.target, &exit.tuning).await {
        Ok(s) => s,
        Err(e) => {
            exit.stats.targets.dial_failed(&open.target, &e);
            warn!(target = %open.target, error = %e, "could not open UDP to target");
            let _ = proto::write_status(&mut tunnel, STATUS_DIAL_FAILED).await;
            return;
        }
    };
    if proto::write_status(&mut tunnel, STATUS_OK).await.is_err() {
        return;
    }
    relay_udp(exit, Channel::Link(tunnel), socket, &open).await;
}

async fn relay_udp(exit: &Exit, tunnel: Channel, socket: tokio::net::UdpSocket, open: &Open) {
    debug!(target = %open.target, "UDP flow opened");
    let (source, sink) = udp::Connected::new(socket);
    let (idle, duplicate) = (exit.tuning.udp.timeout, open.duplicate);
    match udp::relay(
        tunnel,
        source,
        sink,
        idle,
        duplicate,
        exit.datagram_only,
        exit.target_counters(),
    )
    .await
    {
        Ok(()) => debug!(target = %open.target, "UDP flow closed"),
        Err(e) => debug!(target = %open.target, error = %e, "UDP flow ended with error"),
    }
}

/// Serves the streams of `session` as an exit side with `config` would (for tests of the
/// entry side against the real thing).
#[cfg(test)]
pub(crate) fn serve_for_test(config: &Config, session: Arc<Session>) {
    let exit = Arc::new(Exit {
        crypto: Crypto::new(&config.tunnel.token, config.tunnel.encryption),
        tuning: config.tuning(),
        speedtest: None,
        datagram_only: config.tunnel.transport == TransportKind::Udp,
        stats: Stats::new(config),
    });
    tokio::spawn(run_session(exit, session));
}
