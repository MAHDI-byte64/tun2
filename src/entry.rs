//! Entry side: accepts user connections on the `[[forward]]` ports and carries them
//! through the tunnel to the exit side.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use bytes::Bytes;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinSet;
use tokio::time::{sleep, timeout, timeout_at, Instant};
use tracing::{debug, info, warn};

use crate::auto::{self, Dial};
use crate::channel::{self, Channel, Link};
use crate::config::{Config, Forward, Mode, TransportKind, Tuning};
use crate::crypto::{Crypto, ReplayFilter};
use crate::fallback;
use crate::limit::PerIp;
use crate::mux::{MuxSession, SessionConfig, Side};
use crate::proto::{self, Open, STATUS_DIAL_FAILED, STATUS_OK};
use crate::proxy_header::ProxyHeader;
use crate::relay::{relay, relay_stream, Counters};
#[cfg(feature = "quic")]
use crate::session::quic::{accept_sessions, QuicSession};
use crate::session::{is_full, maintain, ResetReason, Session, SessionPool};
use crate::stats::{ForwardStats, ProbeOutcome, Stats};
#[cfg(feature = "quic")]
use crate::transport::quic::{QuicDialer, QuicListener, QuicSettings};
use crate::transport::{Dialer, Listener, Settings};
use crate::udp;

/// How many idle reverse connections the entry may queue before it starts dropping them.
const POOL_CAPACITY: usize = 1024;
/// Direct mode without mux: how often the entry tries the exit side when idle, so the
/// tunnel's state is the truth.
const PROBE_EVERY: Duration = Duration::from_secs(10);
/// How often the health probe goes through the tunnel to a target, the way a user's
/// connection does; the first one waits a little for the sessions to come up.
const HEALTH_EVERY: Duration = Duration::from_secs(15);
const HEALTH_FIRST: Duration = Duration::from_secs(5);
/// A probe without an answer by then failed.
const HEALTH_WAIT: Duration = Duration::from_secs(10);
/// An exit side too old to answer probes is asked again this rarely (it may be updated).
const HEALTH_UNSUPPORTED_EVERY: Duration = Duration::from_secs(600);
/// At most one warning about a full tunnel this often.
const FULL_WARN_INTERVAL: Duration = Duration::from_secs(30);

struct Entry {
    crypto: Crypto,
    tuning: Tuning,
    /// The current tunnel source. It is swapped by the transport fallback chain as it
    /// rotates through its candidates; without fallback it is set once and never changes.
    source: std::sync::RwLock<Arc<Source>>,
    stats: Arc<Stats>,
    /// `tuning.max_conns_per_ip`, shared by all forward rules.
    per_ip: Option<Arc<PerIp>>,
    last_full_warning: std::sync::Mutex<Option<Instant>>,
}

enum Source {
    /// No transport is up yet (the fallback chain has not brought one up).
    Pending,
    /// Direct mode: dial the exit side for every user connection.
    Direct(Dialer),
    /// Reverse mode: take an idle channel the exit side opened in advance.
    Reverse(Mutex<mpsc::Receiver<Link>>),
    /// Mux, either mode: open a stream on one of the sessions to the exit side.
    Mux(Arc<SessionPool>),
}

pub async fn run(config: Config) -> Result<()> {
    let tuning = config.tuning();
    let mux = config.mux();
    let base = Settings::new(&config.tunnel, config.kcp());
    let crypto = Crypto::new(&config.tunnel.token, config.tunnel.encryption)
        .with_mux(mux.enabled)
        .with_stealth(base.stealth.as_ref().map(|s| s.shaping()));
    let sessions = SessionConfig::new(&mux);
    let stats = Stats::new(&config);
    let mut tasks = JoinSet::new();
    // The byte counters go on from where the last run left them (docs/status.md).
    if let Some(path) = config.traffic_file() {
        stats.restore(&path);
        tasks.spawn(crate::stats::persist(stats.clone(), path));
    }

    let per_ip = tuning.max_conns_per_ip.map(PerIp::new);
    let entry = Arc::new(Entry {
        crypto: crypto.clone(),
        tuning: tuning.clone(),
        source: std::sync::RwLock::new(Arc::new(Source::Pending)),
        stats: stats.clone(),
        per_ip,
        last_full_warning: std::sync::Mutex::default(),
    });

    // Bring the tunnel source up. Without a fallback chain it is one transport, built here;
    // with one, a background task rotates through the candidates and swaps the source as a
    // candidate comes up or stays down (see `crate::fallback`), while the forward loops
    // below keep the user-facing ports across the rotation.
    if config.tunnel.fallback_transports.is_empty() {
        let source = build_source(
            &config, &base, &crypto, &sessions, &stats, &tuning, &mux, &mut tasks,
        )
        .await?;
        entry.set_source(source);
    } else {
        let acceptor = config.is_acceptor();
        let candidates = fallback::candidates(&config);
        let dwell = Duration::from_secs(config.tunnel.fallback_dwell_secs);
        let (config, base, sessions, stats, tuning, mux, entry) = (
            config.clone(),
            base.clone(),
            sessions.clone(),
            stats.clone(),
            tuning.clone(),
            mux.clone(),
            entry.clone(),
        );
        tasks.spawn(async move {
            let peer = stats.peer.clone();
            let chain_stats = stats.clone();
            fallback::run_chain(
                acceptor,
                "entry",
                candidates,
                dwell,
                mux.enabled,
                peer,
                chain_stats,
                move |kind| {
                    let (config, base, sessions, stats, tuning, mux, entry) = (
                        config.clone(),
                        base.clone(),
                        sessions.clone(),
                        stats.clone(),
                        tuning.clone(),
                        mux.clone(),
                        entry.clone(),
                    );
                    async move {
                        let settings = fallback::settings_for(&base, &config.tunnel, kind);
                        let crypto = fallback::crypto_for(&config, mux.enabled, &settings);
                        let mut set = JoinSet::new();
                        let source = build_source(
                            &config, &settings, &crypto, &sessions, &stats, &tuning, &mux, &mut set,
                        )
                        .await?;
                        entry.set_source(source);
                        Ok(set)
                    }
                },
            )
            .await
        });
    }

    // `kariz status` reads the counters and `kariz speedtest` reaches the live sessions
    // through this (Unix only).
    #[cfg(unix)]
    if let Some(socket) = config.control_socket() {
        let entry = entry.clone();
        let open = move |open: Bytes| {
            let entry = entry.clone();
            async move { entry.open_channel(&open).await }
        };
        tasks.spawn(crate::control::serve(socket, Some(open), stats.clone()));
    }

    for (forward, counters) in config.forward.iter().zip(&stats.forwards) {
        if forward.protocol.has_tcp() {
            let listener = TcpListener::bind(&forward.listen)
                .await
                .with_context(|| format!("failed to listen on forward port {}", forward.listen))?;
            let (entry, forward, counters) = (entry.clone(), forward.clone(), counters.clone());
            tasks.spawn(accept_users(entry, listener, forward, counters));
        }
        if forward.protocol.has_udp() {
            let socket = udp::bind(&forward.listen, &entry.tuning.udp)
                .await
                .with_context(|| format!("failed to bind UDP forward port {}", forward.listen))?;
            let open = encode_open(Open::udp(forward.target.clone(), forward.duplication()));
            let opener = {
                let entry = entry.clone();
                move || {
                    let (entry, open) = (entry.clone(), open.clone());
                    async move { entry.open_channel(&open).await }
                }
            };
            let (udp_tuning, target) = (entry.tuning.udp.clone(), forward.target.clone());
            let (listen, duplicate) = (forward.listen.clone(), forward.duplication());
            let (counters, per_ip) = (counters.clone(), entry.per_ip.clone());
            // The udp transport forwards on the unreliable path only (no retransmit); it
            // cannot share a fallback chain, so the active transport is always udp here.
            let datagram_only = config.tunnel.transport == TransportKind::Udp;
            tasks.spawn(async move {
                udp::serve(
                    socket,
                    udp_tuning,
                    target,
                    duplicate,
                    datagram_only,
                    counters,
                    per_ip,
                    opener,
                )
                .await
                .with_context(|| format!("UDP forward port {listen} failed"))
            });
        }
        info!(
            listen = %forward.listen,
            target = %forward.target,
            protocol = forward.protocol.name(),
            proxy_protocol = forward.proxy_protocol.map_or("off", |v| v.name()),
            "forward ready"
        );
    }

    tasks.spawn(health(entry.clone(), probe_targets(&config.forward)));

    // Accept loops only return on fatal errors.
    match tasks.join_next().await {
        Some(Ok(result)) => result,
        Some(Err(e)) => Err(e.into()),
        None => Ok(()),
    }
}

/// Builds the tunnel source for `transport` and spawns its maintenance into `tasks`: the
/// QUIC pool, the mux session pool (either mode), the per-connection dialer or the reverse
/// pool of links. Called once for a single transport, and once per candidate by the
/// fallback chain (with the candidate's own `transport` and `crypto`, and its own `tasks`).
#[allow(clippy::too_many_arguments)]
async fn build_source(
    config: &Config,
    transport: &Settings,
    crypto: &Crypto,
    sessions: &SessionConfig,
    stats: &Arc<Stats>,
    tuning: &Tuning,
    mux: &crate::config::MuxSettings,
    tasks: &mut JoinSet<Result<()>>,
) -> Result<Source> {
    let source = if transport.kind == TransportKind::Quic {
        Source::Mux(quic_pool(config, crypto, sessions, stats, tasks).await?)
    } else {
        match config.mode {
            Mode::Direct if mux.enabled => {
                let remote = config.tunnel.remote.as_deref().expect("validated");
                info!(
                    remote,
                    connections = mux.connections,
                    "entry: direct mode with mux, keeping sessions to the exit side"
                );
                let dialer = Arc::new(if config.tunnel.transport == TransportKind::Auto {
                    Dial::auto(transport, &config.tunnel.token, remote, tuning)?
                } else {
                    Dial::one(transport, remote, tuning)?
                });
                let pool = Arc::new(SessionPool::default());
                for _ in 0..mux.connections {
                    let (dialer, crypto, pool) = (dialer.clone(), crypto.clone(), pool.clone());
                    let wait = tuning.dial_timeout + tuning.handshake_timeout;
                    let sessions = sessions.clone();
                    let connect = move || {
                        let (dialer, crypto, sessions) =
                            (dialer.clone(), crypto.clone(), sessions.clone());
                        async move {
                            let (link, via) = dialer.connect(&crypto, wait).await?;
                            let session = MuxSession::over(link, Side::Client, sessions);
                            if let Some(via) = via {
                                session.set_transport(via);
                            }
                            Ok(Session::Kmux(session))
                        }
                    };
                    let (lifetime, link) = (mux.max_lifetime, stats.peer.clone());
                    tasks.spawn(async move {
                        maintain("the exit side", link, connect, lifetime, move |s| {
                            pool.add(s)
                        })
                        .await;
                        Ok(())
                    });
                }
                Source::Mux(pool)
            }
            Mode::Direct => {
                let remote = config.tunnel.remote.as_deref().expect("validated");
                info!(
                    remote,
                    "entry: direct mode, dialing the exit side per connection"
                );
                // Nothing keeps a connection open here, so without this the tunnel would
                // not say whether the exit side is reachable until someone used it (and a
                // panel creating the tunnel would wait for a "connected" that never comes).
                let probe = Dialer::new(transport, remote, tuning)?;
                let (crypto, link) = (crypto.clone(), stats.peer.clone());
                let wait = tuning.dial_timeout + tuning.handshake_timeout;
                tasks.spawn(async move {
                    loop {
                        match timeout(wait, channel::connect(&probe, &crypto, &[])).await {
                            Ok(Ok(_)) => link.link_up(),
                            Ok(Err(e)) => link.failed(&e),
                            Err(_) => link.failed(&"handshake timed out"),
                        }
                        sleep(PROBE_EVERY).await;
                    }
                });
                Source::Direct(Dialer::new(transport, remote, tuning)?)
            }
            Mode::Reverse => {
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
                    "entry: reverse mode, waiting for the exit side"
                );
                let hs = tuning.handshake_timeout;
                if mux.enabled {
                    let pool = Arc::new(SessionPool::default());
                    let (p, link_stats) = (pool.clone(), stats.peer.clone());
                    let sessions = sessions.clone();
                    let on_link =
                        Arc::new(move |link: Link, peer: SocketAddr, via: &'static str| {
                            let session = MuxSession::over(link, Side::Client, sessions.clone());
                            if !via.is_empty() {
                                session.set_transport(via);
                            }
                            let session = Arc::new(Session::Kmux(session));
                            link_stats.session_up(&session);
                            p.add(session);
                            info!(%peer, "mux session from the exit side established");
                        });
                    for (via, listener) in listeners {
                        let on_link = on_link.clone();
                        let accept = accept_reverse(
                            listener,
                            crypto.clone(),
                            hs,
                            stats.clone(),
                            move |link, peer| on_link(link, peer, via),
                        );
                        tasks.spawn(accept);
                    }
                    Source::Mux(pool)
                } else {
                    let (_, listener) = listeners.into_iter().next().expect("a listener");
                    let (tx, rx) = mpsc::channel(POOL_CAPACITY);
                    let link_stats = stats.peer.clone();
                    let on_link = move |link: Link, peer: SocketAddr| {
                        link_stats.link_up();
                        debug!(%peer, "tunnel connection added to pool");
                        if tx.try_send(link).is_err() {
                            warn!(%peer, "tunnel pool is full, dropping connection");
                        }
                    };
                    let accept =
                        accept_reverse(listener, crypto.clone(), hs, stats.clone(), on_link);
                    tasks.spawn(accept);
                    Source::Reverse(Mutex::new(rx))
                }
            }
        }
    };
    Ok(source)
}

/// QUIC, either mode: the pool of QUIC sessions to the exit side. Direct mode keeps
/// `mux.connections` of them up; reverse mode takes the ones the exit side opens.
#[cfg(feature = "quic")]
async fn quic_pool(
    config: &Config,
    crypto: &Crypto,
    sessions: &SessionConfig,
    stats: &Arc<Stats>,
    tasks: &mut JoinSet<Result<()>>,
) -> Result<Arc<SessionPool>> {
    let (tuning, mux) = (config.tuning(), config.mux());
    let quic_config = config.tunnel.quic.clone().unwrap_or_default();
    let quic = QuicSettings::new(crypto.psk(), &quic_config, &mux, &tuning)?;
    let pool = Arc::new(SessionPool::default());
    let open_timeout = tuning.handshake_timeout;
    match config.mode {
        Mode::Direct => {
            let remote = config.tunnel.remote.as_deref().expect("validated");
            let dialer = Arc::new(QuicDialer::new(remote, quic_config.sni.as_deref(), &quic)?);
            info!(
                remote,
                connections = mux.connections,
                congestion = quic_config.congestion.name(),
                "entry: direct mode over QUIC, keeping sessions to the exit side"
            );
            for _ in 0..mux.connections {
                let (dialer, pool, sessions) = (dialer.clone(), pool.clone(), sessions.clone());
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
                let (lifetime, link) = (mux.max_lifetime, stats.peer.clone());
                tasks.spawn(async move {
                    maintain("the exit side", link, connect, lifetime, move |s| {
                        pool.add(s)
                    })
                    .await;
                    Ok(())
                });
            }
        }
        Mode::Reverse => {
            let addr = config.tunnel.listen.as_deref().expect("validated");
            let listener = QuicListener::bind(addr, &quic)
                .await
                .with_context(|| format!("failed to listen for QUIC on {addr}"))?;
            info!(
                addr = %listener.local_addr()?,
                "entry: reverse mode over QUIC, waiting for the exit side"
            );
            let (p, link) = (pool.clone(), stats.peer.clone());
            let on_session = move |session: QuicSession, peer: SocketAddr| {
                let session = Arc::new(Session::Quic(session));
                link.session_up(&session);
                p.add(session);
                info!(%peer, "quic session from the exit side established");
            };
            let (sessions, link) = (sessions.clone(), stats.peer.clone());
            tasks.spawn(async move {
                accept_sessions(listener, sessions, open_timeout, link, on_session).await;
                Ok(())
            });
        }
    }
    Ok(pool)
}

/// Config validation rejects `transport = "quic"` in a build without it.
#[cfg(not(feature = "quic"))]
async fn quic_pool(
    _: &Config,
    _: &Crypto,
    _: &SessionConfig,
    _: &Arc<Stats>,
    _: &mut JoinSet<Result<()>>,
) -> Result<Arc<SessionPool>> {
    anyhow::bail!("this build has no QUIC support (the `quic` feature is off)")
}

/// Reverse mode: authenticates incoming tunnel connections and hands them to
/// `on_link` (the idle pool, or a new mux session).
async fn accept_reverse(
    listener: Listener,
    crypto: Crypto,
    handshake_timeout: Duration,
    stats: Arc<Stats>,
    on_link: impl Fn(Link, SocketAddr) + Send + Sync + 'static,
) -> Result<()> {
    let replay = Arc::new(ReplayFilter::default());
    let on_link = Arc::new(on_link);
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "tunnel accept failed");
                sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let (crypto, replay, on_link) = (crypto.clone(), replay.clone(), on_link.clone());
        let stats = stats.clone();
        tokio::spawn(async move {
            match channel::accept(stream, &crypto, &replay, handshake_timeout).await {
                Ok(link) => on_link(link, peer),
                Err(e) => {
                    stats.peer.failed(&e);
                    warn!(%peer, error = %e, "tunnel handshake failed")
                }
            }
        });
    }
}

async fn accept_users(
    entry: Arc<Entry>,
    listener: TcpListener,
    forward: Forward,
    counters: Arc<ForwardStats>,
) -> Result<()> {
    let open = encode_open(Open::tcp(forward.target.clone()));
    loop {
        let (user, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, listen = %forward.listen, "user accept failed");
                sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let slot = match &entry.per_ip {
            Some(limit) => match limit.acquire(peer.ip()) {
                Some(slot) => Some(slot),
                None => {
                    counters.refused_per_ip();
                    continue;
                }
            },
            None => None,
        };
        let open = match forward.proxy_protocol {
            None => open.clone(),
            // The header names this user and the address they reached, so the request is
            // theirs alone.
            Some(version) => match user.local_addr() {
                Ok(destination) => {
                    let proxy = ProxyHeader {
                        version,
                        source: peer,
                        destination,
                    };
                    encode_open(Open::tcp_proxied(forward.target.clone(), proxy))
                }
                Err(e) => {
                    debug!(%peer, error = %e, "user connection has no local address");
                    continue;
                }
            },
        };
        let entry = entry.clone();
        let (target, counters) = (forward.target.clone(), counters.clone());
        tokio::spawn(async move {
            let _slot = slot;
            if let Err(e) = handle_user(&entry, user, &open, &counters).await {
                debug!(%peer, %target, error = %e, "connection ended with error");
            }
        });
    }
}

fn encode_open(open: Open) -> Bytes {
    let mut frame = Vec::new();
    open.encode(&mut frame);
    frame.into()
}

async fn handle_user(
    entry: &Entry,
    mut user: TcpStream,
    open: &Bytes,
    stats: &Arc<ForwardStats>,
) -> io::Result<()> {
    let _open = stats.tcp_connection();
    user.set_nodelay(entry.tuning.nodelay)?;
    let size = entry.tuning.buffer_size;
    let channel = entry
        .open_channel(open)
        .await
        .inspect_err(|_| stats.open_failed())?;
    let counters = Counters {
        read: &stats.traffic.up,
        written: &stats.traffic.down,
    };
    let result = match channel {
        Channel::Stream(stream) => relay_stream(&mut user, &stream, size, counters).await,
        Channel::Link(mut link) => relay(&mut user, &mut link, size, counters).await,
    };
    // With mux the stream is used before the exit side answers; it resets the stream
    // when it cannot reach the target.
    if result
        .as_ref()
        .is_err_and(|e| e.kind() == io::ErrorKind::ConnectionRefused)
    {
        stats.open_failed();
    }
    result.map(|_| ())
}

impl Entry {
    /// The current tunnel source (cheap: an `Arc` clone), which the fallback chain may
    /// swap under it.
    fn source(&self) -> Arc<Source> {
        self.source
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Makes `source` the live tunnel source (the fallback chain calls this when a
    /// candidate comes up).
    fn set_source(&self, source: Source) {
        *self.source.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(source);
    }

    /// Gets a channel to the exit side and has the exit connect it to the target
    /// described by the encoded `open` request.
    async fn open_channel(&self, open: &Bytes) -> io::Result<Channel> {
        let deadline = Instant::now() + self.tuning.handshake_timeout + self.tuning.dial_timeout;
        self.open_channel_until(open, deadline, true).await
    }

    /// [`Self::open_channel`] giving up at `deadline`. `retry`: on a pooled link (reverse
    /// mode without mux) that fails, try the next one.
    async fn open_channel_until(
        &self,
        open: &Bytes,
        deadline: Instant,
        retry: bool,
    ) -> io::Result<Channel> {
        let source = self.source();
        match &*source {
            // The fallback chain has not brought a transport up yet.
            Source::Pending => Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "no tunnel transport is up yet",
            )),
            Source::Direct(dialer) => {
                let link = timeout_at(deadline, self.open_direct(dialer, open)).await;
                link.map_err(|_| exit_late())?.map(Channel::Link)
            }
            Source::Reverse(pool) => self
                .open_reverse(pool, open, deadline, retry)
                .await
                .map(Channel::Link),
            // Optimistic: the stream is used right away; if the exit cannot reach the
            // target it resets the stream, which ends the relay.
            Source::Mux(pool) => match pool.open(open.clone(), deadline).await {
                Ok(stream) => Ok(Channel::Stream(stream)),
                Err(e) => {
                    if is_full(&e) {
                        self.stats.peer.full();
                        self.warn_full(&e);
                    }
                    Err(e)
                }
            },
        }
    }

    /// Logs that the tunnel is full, at most every [`FULL_WARN_INTERVAL`]: users cannot
    /// connect while it is, and nothing else says so.
    fn warn_full(&self, e: &io::Error) {
        let now = Instant::now();
        let mut last = self
            .last_full_warning
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if last.map_or(true, |t| now.duration_since(t) >= FULL_WARN_INTERVAL) {
            *last = Some(now);
            warn!(error = %e, "new connections are failing");
        }
    }

    /// One health probe: opens a channel the way a user connection is opened and has
    /// the exit side connect to the target of `open` (an [`Open::probe`]). Errors:
    /// `ConnectionRefused` when the target could not be reached, `Unsupported` when the
    /// exit side does not know probes.
    async fn probe(&self, open: &Bytes, wait: Duration) -> io::Result<()> {
        let deadline = Instant::now() + wait;
        let late = || io::Error::new(io::ErrorKind::TimedOut, "no answer through the tunnel");
        let channel = timeout_at(deadline, self.open_channel_until(open, deadline, false))
            .await
            .map_err(|_| late())?
            .map_err(|e| match e.kind() {
                // An exit side that does not know the kind closes without a status byte.
                io::ErrorKind::UnexpectedEof => unsupported(),
                _ => e,
            })?;
        // Without mux the status byte was read when the channel was opened.
        let Channel::Stream(stream) = channel else {
            return Ok(());
        };
        let answer = match timeout_at(deadline, stream.recv()).await {
            Err(_) => return Err(late()),
            Ok(Err(_)) if stream.reset_reason() == Some(ResetReason::Protocol) => {
                return Err(unsupported())
            }
            Ok(Err(e)) => return Err(e),
            Ok(Ok(answer)) => answer,
        };
        // The exit side ends the stream after its answer; ending ours too closes it
        // cleanly on both sides.
        let _ = stream.finish();
        let _ = timeout_at(deadline, stream.recv()).await;
        match answer.as_deref() {
            Some([STATUS_OK, ..]) => Ok(()),
            Some([STATUS_DIAL_FAILED, ..]) => Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "exit side could not connect to the target",
            )),
            _ => Err(unsupported()),
        }
    }

    /// Dials the exit side and sends the open request along with the hello.
    async fn open_direct(&self, dialer: &Dialer, open: &[u8]) -> io::Result<Link> {
        let wait = self.tuning.handshake_timeout + self.tuning.dial_timeout;
        timeout(wait, async {
            let connected = channel::connect(dialer, &self.crypto, open).await;
            let mut link = connected.inspect_err(|e| self.stats.peer.failed(e))?;
            self.stats.peer.link_up();
            proto::read_status(&mut link).await?;
            Ok(link)
        })
        .await
        .map_err(|_| exit_late())?
    }

    /// Takes pooled links until one accepts the open request. Pooled links may have
    /// died while idle, so failures other than "target unreachable" are retried, unless
    /// `retry` is off: then the first link that took the request gives the answer.
    async fn open_reverse(
        &self,
        pool: &Mutex<mpsc::Receiver<Link>>,
        open: &[u8],
        deadline: Instant,
        retry: bool,
    ) -> io::Result<Link> {
        loop {
            let mut channel = timeout_at(deadline, async { pool.lock().await.recv().await })
                .await
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        "no tunnel connection available (is the exit side running?)",
                    )
                })?
                .ok_or_else(|| io::Error::other("tunnel pool closed"))?;

            if !channel.is_alive() {
                continue;
            }
            if proto::send(&mut channel, open).await.is_err() {
                continue;
            }
            match timeout_at(deadline, proto::read_status(&mut channel)).await {
                Ok(Ok(())) => return Ok(channel),
                Ok(Err(e)) if e.kind() == io::ErrorKind::ConnectionRefused || !retry => {
                    return Err(e)
                }
                Ok(Err(_)) => continue,
                Err(_) => return Err(exit_late()),
            }
        }
    }
}

fn exit_late() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "exit side did not answer in time")
}

fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "the other server does not answer health probes (update it)",
    )
}

/// What the health probe connects to: each TCP target once, in turn; the tunnel alone
/// when only UDP is forwarded (a UDP target cannot be checked by connecting).
fn probe_targets(forwards: &[Forward]) -> Vec<String> {
    let mut targets: Vec<String> = Vec::new();
    for f in forwards.iter().filter(|f| f.protocol.has_tcp()) {
        if !targets.contains(&f.target) {
            targets.push(f.target.clone());
        }
    }
    if targets.is_empty() {
        targets.push(String::new());
    }
    targets
}

/// Probes the way through the tunnel every [`HEALTH_EVERY`], one target at a time, and
/// keeps what it found in the stats (`status`). A tunnel can be up and still let no one
/// through (every session full, the target down); this is what tells.
async fn health(entry: Arc<Entry>, targets: Vec<String>) -> Result<()> {
    sleep(HEALTH_FIRST).await;
    for target in targets.iter().cycle() {
        let open = encode_open(Open::probe(target.clone()));
        let started = Instant::now();
        let result = entry.probe(&open, HEALTH_WAIT).await;
        let took = started.elapsed();
        let outcome = match &result {
            Ok(()) => ProbeOutcome::Ok,
            Err(e) => match e.kind() {
                io::ErrorKind::ConnectionRefused => ProbeOutcome::TargetFailed,
                io::ErrorKind::Unsupported => ProbeOutcome::Unsupported,
                _ => ProbeOutcome::Failed,
            },
        };
        if let Err(e) = &result {
            debug!(%target, error = %e, "health probe failed");
        }
        let answered = matches!(outcome, ProbeOutcome::Ok | ProbeOutcome::TargetFailed);
        let error = result.err().map(|e| e.to_string());
        entry
            .stats
            .probe
            .record(target, outcome, answered.then_some(took), error);
        sleep(if outcome == ProbeOutcome::Unsupported {
            HEALTH_UNSUPPORTED_EVERY
        } else {
            HEALTH_EVERY
        })
        .await;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mux::tests::config as session_config;
    use crate::session::is_full;

    const TOKEN: &str = "0123456789abcdef0123";

    fn config(role: &str) -> Config {
        let side = if role == "entry" {
            "remote = \"127.0.0.1:9\"\n[[forward]]\nlisten = \"127.0.0.1:0\"\ntarget = \"127.0.0.1:9\"\n"
        } else {
            "listen = \"127.0.0.1:9\"\n"
        };
        let text = format!(
            "role = \"{role}\"\nmode = \"direct\"\n[tunnel]\ntransport = \"tcpmux\"\n\
             token = \"{TOKEN}\"\n{side}"
        );
        Config::parse(&text).unwrap()
    }

    /// An entry whose pool has one session of at most `max_streams`; `serve` runs the
    /// other end of it.
    fn entry_with(max_streams: usize, serve: impl FnOnce(MuxSession)) -> Entry {
        let (a, b) = tokio::io::duplex(256 * 1024);
        let client = SessionConfig {
            max_streams,
            ..session_config()
        };
        let pool = Arc::new(SessionPool::default());
        pool.add(Arc::new(Session::Kmux(MuxSession::new(
            a,
            Side::Client,
            client,
        ))));
        serve(MuxSession::new(b, Side::Server, session_config()));
        let config = config("entry");
        Entry {
            crypto: Crypto::new(TOKEN, config.tunnel.encryption),
            tuning: config.tuning(),
            source: std::sync::RwLock::new(Arc::new(Source::Mux(pool))),
            stats: Stats::new(&config),
            per_ip: None,
            last_full_warning: std::sync::Mutex::default(),
        }
    }

    /// The other end served by a real exit side.
    fn entry_to_exit(max_streams: usize) -> Entry {
        entry_with(max_streams, |server| {
            crate::exit::serve_for_test(&config("exit"), Arc::new(Session::Kmux(server)));
        })
    }

    fn probe_of(target: &str) -> Bytes {
        encode_open(Open::probe(target))
    }

    const WAIT: Duration = Duration::from_secs(5);

    #[tokio::test]
    async fn a_probe_reaches_the_target_through_the_exit_side() {
        // One stream at a time: each probe gets through only if the last one let go of it.
        let entry = entry_to_exit(1);
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = target.local_addr().unwrap().to_string();
        entry.probe(&probe_of(&addr), WAIT).await.unwrap();
        // The tunnel alone (only UDP forwarded).
        entry.probe(&probe_of(""), WAIT).await.unwrap();
        // A target nobody listens on.
        drop(target);
        let err = entry.probe(&probe_of(&addr), WAIT).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused, "{err}");
        entry.probe(&probe_of(""), WAIT).await.unwrap();
    }

    #[tokio::test]
    async fn a_full_tunnel_fails_the_probe_and_is_counted() {
        let entry = entry_to_exit(1);
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = target.local_addr().unwrap().to_string();
        // A user connection takes the only stream.
        let user = entry
            .open_channel(&encode_open(Open::tcp(addr.clone())))
            .await
            .unwrap();
        let err = entry
            .probe(&probe_of(&addr), Duration::from_millis(300))
            .await
            .unwrap_err();
        assert!(is_full(&err), "{err}");
        assert_eq!(entry.stats.snapshot().peer.full, 1);
        drop(user);
        entry.probe(&probe_of(&addr), WAIT).await.unwrap();
    }

    #[tokio::test]
    async fn an_exit_side_without_probes_is_told_apart() {
        // An older exit side resets a stream of a kind it does not know.
        let entry = entry_with(16, |server| {
            tokio::spawn(async move {
                while let Some((stream, _)) = server.accept().await {
                    stream.reset(ResetReason::Protocol);
                }
            });
        });
        let err = entry.probe(&probe_of(""), WAIT).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported, "{err}");
    }

    #[tokio::test]
    async fn without_a_session_the_probe_fails() {
        let config = config("entry");
        let entry = Entry {
            crypto: Crypto::new(TOKEN, config.tunnel.encryption),
            tuning: config.tuning(),
            source: std::sync::RwLock::new(Arc::new(Source::Mux(Arc::new(SessionPool::default())))),
            stats: Stats::new(&config),
            per_ip: None,
            last_full_warning: std::sync::Mutex::default(),
        };
        let err = entry
            .probe(&probe_of(""), Duration::from_millis(200))
            .await
            .unwrap_err();
        assert!(
            !matches!(
                err.kind(),
                io::ErrorKind::ConnectionRefused | io::ErrorKind::Unsupported
            ),
            "{err}"
        );
        assert!(!is_full(&err));
    }

    #[test]
    fn probes_go_to_each_tcp_target_once() {
        let forwards = |text: &str| {
            Config::parse(&format!(
                "role = \"entry\"\nmode = \"reverse\"\n[tunnel]\nlisten = \"0.0.0.0:3080\"\n\
                 token = \"{TOKEN}\"\n{text}"
            ))
            .unwrap()
            .forward
        };
        let rule = |port: u16, target: &str, protocol: &str| {
            format!(
                "[[forward]]\nlisten = \"0.0.0.0:{port}\"\ntarget = \"{target}\"\n\
                 protocol = \"{protocol}\"\n"
            )
        };
        let mixed = forwards(&format!(
            "{}{}{}",
            rule(443, "127.0.0.1:443", "tcp"),
            rule(8443, "127.0.0.1:443", "tcp+udp"),
            rule(53, "127.0.0.1:53", "udp"),
        ));
        assert_eq!(probe_targets(&mixed), ["127.0.0.1:443"]);
        let udp_only = forwards(&rule(53, "127.0.0.1:53", "udp"));
        assert_eq!(probe_targets(&udp_only), [""]);
    }
}
