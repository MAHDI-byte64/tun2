//! Live counters of a running side, answered by `status` on the control socket
//! (docs/status.md).
//!
//! Everything is updated where the work already happens, with relaxed atomics; nothing
//! runs in the background. Reading them ([`Stats::snapshot`]) never touches the tunnel.

use std::fmt::Display;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::config::{mode_name, role_name, Config};
use crate::session::Session;

/// Version of the `status` document; readers ignore fields they do not know.
pub const STATUS_VERSION: u32 = 1;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Bytes moved in each direction. `up`: from users towards the targets; `down`: back.
#[derive(Debug, Default)]
pub struct Traffic {
    pub up: AtomicU64,
    pub down: AtomicU64,
}

impl Traffic {
    pub fn add_up(&self, n: usize) {
        self.up.fetch_add(n as u64, Relaxed);
    }

    pub fn add_down(&self, n: usize) {
        self.down.fetch_add(n as u64, Relaxed);
    }

    /// Starts the counters from what was kept across a restart.
    fn set(&self, up: u64, down: u64) {
        self.up.store(up, Relaxed);
        self.down.store(down, Relaxed);
    }

    fn get(&self) -> (u64, u64) {
        (self.up.load(Relaxed), self.down.load(Relaxed))
    }
}

/// Counters of one `[[forward]]` rule (entry side).
#[derive(Debug)]
pub struct ForwardStats {
    listen: String,
    target: String,
    protocol: &'static str,
    pub traffic: Arc<Traffic>,
    tcp_open: AtomicU64,
    tcp_total: AtomicU64,
    udp_open: AtomicU64,
    udp_total: AtomicU64,
    open_failures: AtomicU64,
    refused_per_ip: AtomicU64,
}

impl ForwardStats {
    pub fn new(listen: &str, target: &str, protocol: &'static str) -> Arc<Self> {
        Arc::new(Self {
            listen: listen.to_string(),
            target: target.to_string(),
            protocol,
            traffic: Arc::default(),
            tcp_open: AtomicU64::new(0),
            tcp_total: AtomicU64::new(0),
            udp_open: AtomicU64::new(0),
            udp_total: AtomicU64::new(0),
            open_failures: AtomicU64::new(0),
            refused_per_ip: AtomicU64::new(0),
        })
    }

    /// Counts a user connection as open until the guard is dropped.
    pub fn tcp_connection(self: &Arc<Self>) -> OpenGuard {
        self.tcp_total.fetch_add(1, Relaxed);
        self.tcp_open.fetch_add(1, Relaxed);
        OpenGuard(self.clone(), Kind::Tcp)
    }

    /// Counts a UDP flow as open until the guard is dropped.
    pub fn udp_flow(self: &Arc<Self>) -> OpenGuard {
        self.udp_total.fetch_add(1, Relaxed);
        self.udp_open.fetch_add(1, Relaxed);
        OpenGuard(self.clone(), Kind::Udp)
    }

    /// A channel for a user could not be opened, or the exit side refused it.
    pub fn open_failed(&self) {
        self.open_failures.fetch_add(1, Relaxed);
    }

    /// A user connection or UDP flow was closed: its address had `max_conns_per_ip` open.
    pub fn refused_per_ip(&self) {
        self.refused_per_ip.fetch_add(1, Relaxed);
    }
}

#[derive(Debug)]
enum Kind {
    Tcp,
    Udp,
}

/// An open user connection or UDP flow; counted down when dropped.
#[derive(Debug)]
pub struct OpenGuard(Arc<ForwardStats>, Kind);

impl Drop for OpenGuard {
    fn drop(&mut self) {
        match self.1 {
            Kind::Tcp => self.0.tcp_open.fetch_sub(1, Relaxed),
            Kind::Udp => self.0.udp_open.fetch_sub(1, Relaxed),
        };
    }
}

/// Bytes of one UDP flow in one direction, added to a shared counter every
/// [`Tally::BATCH`] packets, at least once a second while packets come, and when dropped,
/// so that busy flows on many cores do not all write the same counter for every packet.
pub struct Tally<'a> {
    target: &'a AtomicU64,
    bytes: u64,
    packets: u32,
    flushed: Instant,
    /// Nothing counted yet: the first packet is added at once.
    fresh: bool,
}

impl<'a> Tally<'a> {
    const BATCH: u32 = 64;
    /// The clock is read every this many packets, not for each.
    const CLOCK_EVERY: u32 = 8;

    pub fn new(target: &'a AtomicU64) -> Self {
        Self {
            target,
            bytes: 0,
            packets: 0,
            flushed: Instant::now(),
            fresh: true,
        }
    }

    pub fn add(&mut self, n: usize) {
        self.bytes += n as u64;
        self.packets += 1;
        // The first packet shows at once, so short flows (a DNS query) are seen too.
        if self.packets >= Self::BATCH
            || std::mem::take(&mut self.fresh)
            || (self.packets % Self::CLOCK_EVERY == 0
                && self.flushed.elapsed() >= Duration::from_secs(1))
        {
            self.flush();
        }
    }

    pub fn flush(&mut self) {
        if self.bytes > 0 {
            self.target.fetch_add(self.bytes, Relaxed);
        }
        self.bytes = 0;
        self.packets = 0;
        self.flushed = Instant::now();
    }
}

impl Drop for Tally<'_> {
    fn drop(&mut self) {
        self.flush();
    }
}

/// The link to the other side: its sessions, handshakes and the last error.
#[derive(Debug, Default)]
pub struct Peer {
    /// Sessions the dialing side keeps up (`mux.connections`); 0 without mux.
    wanted: u64,
    /// Sessions seen come up, with when; the closed ones are pruned when read.
    live: Mutex<Vec<(Instant, Weak<Session>)>>,
    handshakes_ok: AtomicU64,
    handshakes_failed: AtomicU64,
    last_ok: Mutex<Option<Instant>>,
    last_error: Mutex<Option<(Instant, String)>>,
    /// `mux.max_streams`: each live session takes this many streams; 0 without mux.
    max_streams: u64,
    /// New connections that found every session full.
    full: AtomicU64,
}

impl Peer {
    /// A user connection or flow could not be opened: every session had `max_streams`.
    pub fn full(&self) {
        self.full.fetch_add(1, Relaxed);
    }

    /// A session to the other side is up (the handshake succeeded).
    pub fn session_up(&self, session: &Arc<Session>) {
        self.link_up();
        let mut live = lock(&self.live);
        live.retain(|(_, s)| s.upgrade().is_some_and(|s| !s.is_closed()));
        live.push((Instant::now(), Arc::downgrade(session)));
    }

    /// A tunnel connection without mux passed its handshake.
    pub fn link_up(&self) {
        self.handshakes_ok.fetch_add(1, Relaxed);
        *lock(&self.last_ok) = Some(Instant::now());
    }

    /// Connecting to or authenticating the other side failed.
    pub fn failed(&self, error: &dyn Display) {
        self.handshakes_failed.fetch_add(1, Relaxed);
        *lock(&self.last_error) = Some((Instant::now(), error.to_string()));
    }

    /// Whether the control channel is up now: a live session with mux, or the last attempt
    /// having worked without it. The transport fallback chain polls this to tell a
    /// candidate that connected from one that is still trying.
    pub fn connected(&self, mux: bool) -> bool {
        if mux {
            let mut live = lock(&self.live);
            live.retain(|(_, s)| s.upgrade().is_some_and(|s| !s.is_closed()));
            !live.is_empty()
        } else {
            let last_ok = *lock(&self.last_ok);
            let last_error = lock(&self.last_error);
            last_ok.is_some_and(|ok| last_error.as_ref().map_or(true, |(e, _)| ok > *e))
        }
    }

    fn snapshot(&self, mux: bool) -> PeerStatus {
        let now = Instant::now();
        let mut live = lock(&self.live);
        live.retain(|(_, s)| s.upgrade().is_some_and(|s| !s.is_closed()));
        let sessions: Vec<(Instant, Arc<Session>)> = live
            .iter()
            .filter_map(|(since, s)| Some((*since, s.upgrade()?)))
            .collect();
        drop(live);
        let last_error = lock(&self.last_error).clone();
        let last_ok = *lock(&self.last_ok);
        let (connected, connected_since) = if mux {
            let since = sessions.iter().map(|(t, _)| *t).min();
            (!sessions.is_empty(), since)
        } else {
            // Without sessions, "connected" means the last attempt worked.
            let ok = last_ok.is_some_and(|ok| last_error.as_ref().map_or(true, |(e, _)| ok > *e));
            (ok, if ok { last_ok } else { None })
        };
        // The transports the live sessions run over (only an `auto` tunnel names them).
        let mut via: Vec<&'static str> =
            sessions.iter().filter_map(|(_, s)| s.transport()).collect();
        via.sort_unstable();
        via.dedup();
        let rtts: Vec<Duration> = sessions.iter().filter_map(|(_, s)| s.rtt()).collect();
        let rtt_ms = (!rtts.is_empty()).then(|| {
            let mean = rtts.iter().sum::<Duration>() / rtts.len() as u32;
            (mean.as_secs_f64() * 10_000.0).round() / 10.0
        });
        // A draining session still carries its streams but takes no new ones.
        let streams = sessions.iter().map(|(_, s)| s.stream_count() as u64).sum();
        let open_sessions = sessions.iter().filter(|(_, s)| !s.is_draining()).count() as u64;
        PeerStatus {
            transport: (!via.is_empty()).then(|| via.join("+")),
            connected,
            sessions: mux.then_some(sessions.len() as u64),
            sessions_wanted: (mux && self.wanted > 0).then_some(self.wanted),
            connected_secs: connected_since.map(|t| now.duration_since(t).as_secs()),
            rtt_ms,
            handshakes_ok: self.handshakes_ok.load(Relaxed),
            handshakes_failed: self.handshakes_failed.load(Relaxed),
            last_error: last_error.map(|(at, text)| LastError {
                secs_ago: now.duration_since(at).as_secs(),
                text,
            }),
            streams: mux.then_some(streams),
            streams_max: (mux && self.max_streams > 0).then_some(open_sessions * self.max_streams),
            full: self.full.load(Relaxed),
        }
    }
}

/// What the entry side's health probe found: every few seconds it opens a connection the
/// way a user's is opened and has the exit side connect to a target (`entry::probe`).
#[derive(Debug, Default)]
pub struct Probe {
    state: Mutex<Option<ProbeState>>,
}

#[derive(Debug)]
struct ProbeState {
    at: Instant,
    outcome: ProbeOutcome,
    ms: Option<u64>,
    target: String,
    error: Option<String>,
    fails: u32,
    target_fails: u32,
    ok_total: u64,
    failed_total: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeOutcome {
    /// Through the tunnel and connected to the target.
    Ok,
    /// Through the tunnel, but the exit side could not connect to the target.
    TargetFailed,
    /// No way through: no session, every session full, or no answer in time.
    Failed,
    /// The exit side is older than the probe.
    Unsupported,
}

impl Probe {
    /// Records one probe of `target`. `took`: until the answer came.
    pub fn record(
        &self,
        target: &str,
        outcome: ProbeOutcome,
        took: Option<Duration>,
        error: Option<String>,
    ) {
        let mut state = lock(&self.state);
        let (mut fails, mut target_fails, mut ok_total, mut failed_total) =
            state.as_ref().map_or((0, 0, 0, 0), |s| {
                (s.fails, s.target_fails, s.ok_total, s.failed_total)
            });
        match outcome {
            ProbeOutcome::Ok => {
                (fails, target_fails) = (0, 0);
                ok_total += 1;
            }
            ProbeOutcome::TargetFailed => {
                fails = 0;
                target_fails += 1;
                failed_total += 1;
            }
            ProbeOutcome::Failed => {
                fails += 1;
                failed_total += 1;
            }
            ProbeOutcome::Unsupported => {}
        }
        *state = Some(ProbeState {
            at: Instant::now(),
            outcome,
            ms: took.map(|d| d.as_millis() as u64),
            target: target.to_owned(),
            error,
            fails,
            target_fails,
            ok_total,
            failed_total,
        });
    }

    fn snapshot(&self) -> Option<ProbeStatus> {
        lock(&self.state).as_ref().map(|s| ProbeStatus {
            outcome: s.outcome,
            ms: s.ms,
            target: s.target.clone(),
            error: s.error.clone(),
            fails: s.fails,
            target_fails: s.target_fails,
            ok_total: s.ok_total,
            failed_total: s.failed_total,
            secs_ago: s.at.elapsed().as_secs(),
        })
    }
}

/// What the exit side counts about the targets it reaches.
#[derive(Debug, Default)]
pub struct Targets {
    streams_total: AtomicU64,
    dial_failures: AtomicU64,
    last_dial_error: Mutex<Option<(Instant, String)>>,
    pub traffic: Arc<Traffic>,
}

impl Targets {
    /// A stream (a user connection or a UDP flow) arrived to be served.
    pub fn stream(&self) {
        self.streams_total.fetch_add(1, Relaxed);
    }

    pub fn dial_failed(&self, target: &str, error: &dyn Display) {
        self.dial_failures.fetch_add(1, Relaxed);
        *lock(&self.last_dial_error) = Some((Instant::now(), format!("{target}: {error}")));
    }
}

/// The counters of one running side.
#[derive(Debug)]
pub struct Stats {
    started: Instant,
    role: &'static str,
    mode: &'static str,
    transport: &'static str,
    /// The transport actually running now, set by the fallback chain while it rotates
    /// through its candidates; `None` leaves [`Self::transport`] (the configured one).
    active_transport: Mutex<Option<&'static str>>,
    profile: &'static str,
    mux: bool,
    pub peer: Arc<Peer>,
    /// One per `[[forward]]` rule, in config order (entry side).
    pub forwards: Vec<Arc<ForwardStats>>,
    /// Exit side.
    pub targets: Targets,
    /// Entry side.
    pub probe: Probe,
    /// Bytes from the traffic file that belong to no `[[forward]]` rule of this run (rules
    /// that were edited away), so the totals never go down across a restart. Entry side.
    carry: Traffic,
    /// The id of the counters restored from the traffic file (`status`'s `counter_id`),
    /// empty without a file.
    counter_id: Mutex<String>,
}

impl Stats {
    /// Records the transport the fallback chain is running now (its canonical
    /// [`crate::config::TransportKind::name`]), which `status` reports instead of the
    /// configured one. `None` clears it.
    pub fn set_active_transport(&self, name: Option<&'static str>) {
        *lock(&self.active_transport) = name;
    }

    pub fn new(config: &Config) -> Arc<Self> {
        let mux = config.mux();
        let wanted = if mux.enabled && !config.is_acceptor() {
            mux.connections as u64
        } else {
            0
        };
        Arc::new(Self {
            started: Instant::now(),
            role: role_name(config.role),
            mode: mode_name(config.mode),
            transport: config.tunnel.transport.name(),
            active_transport: Mutex::new(None),
            profile: config.profile.name(),
            mux: mux.enabled,
            peer: Arc::new(Peer {
                wanted,
                max_streams: if mux.enabled {
                    mux.max_streams as u64
                } else {
                    0
                },
                ..Peer::default()
            }),
            forwards: config
                .forward
                .iter()
                .map(|f| ForwardStats::new(&f.listen, &f.target, f.protocol.name()))
                .collect(),
            targets: Targets::default(),
            probe: Probe::default(),
            carry: Traffic::default(),
            counter_id: Mutex::new(String::new()),
        })
    }

    /// Starts the byte counters from the traffic file at `path`, written by [`persist`] in
    /// an earlier run: on the entry side each `[[forward]]` rule gets its own bytes back and
    /// the bytes of rules that are gone go into the carry, so the totals go on from where
    /// they were; the exit side gets its target totals back. A file that is missing, cannot
    /// be read or does not add up starts the counters at zero, under a new counter id.
    pub fn restore(&self, path: &Path) {
        let file = match std::fs::read(path) {
            Ok(text) => match serde_json::from_slice::<TrafficFile>(&text) {
                Ok(f) if f.adds_up() => Some(f),
                Ok(_) => {
                    tracing::warn!(path = %path.display(), "the traffic file does not add up; counting from zero");
                    None
                }
                Err(e) => {
                    tracing::warn!(path = %path.display(), error = %e, "the traffic file cannot be read; counting from zero");
                    None
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "the traffic file cannot be read; counting from zero");
                None
            }
        };
        let Some(file) = file else {
            *lock(&self.counter_id) = new_counter_id();
            return;
        };
        if self.role == "exit" {
            self.targets.traffic.set(file.bytes_up, file.bytes_down);
        } else {
            let (mut up, mut down) = (0u64, 0u64);
            let mut taken = vec![false; file.forwards.len()];
            for f in &self.forwards {
                let found = file.forwards.iter().enumerate().find(|(i, saved)| {
                    !taken[*i]
                        && saved.listen == f.listen
                        && saved.target == f.target
                        && saved.protocol == f.protocol
                });
                if let Some((i, saved)) = found {
                    taken[i] = true;
                    f.traffic.set(saved.bytes_up, saved.bytes_down);
                    up += saved.bytes_up;
                    down += saved.bytes_down;
                }
            }
            self.carry.set(
                file.bytes_up.saturating_sub(up),
                file.bytes_down.saturating_sub(down),
            );
        }
        *lock(&self.counter_id) = if file.counter_id.is_empty() {
            new_counter_id()
        } else {
            file.counter_id
        };
        tracing::debug!(path = %path.display(), bytes_up = file.bytes_up, bytes_down = file.bytes_down, "byte counters restored");
    }

    /// What goes into the traffic file. Each counter is read once, and the totals are made
    /// from those same readings, so a file written while traffic flows always adds up.
    fn traffic_file(&self) -> TrafficFile {
        let forwards: Vec<ForwardTraffic> = self
            .forwards
            .iter()
            .map(|f| {
                let (bytes_up, bytes_down) = f.traffic.get();
                ForwardTraffic {
                    listen: f.listen.clone(),
                    target: f.target.clone(),
                    protocol: f.protocol.to_string(),
                    bytes_up,
                    bytes_down,
                }
            })
            .collect();
        let (bytes_up, bytes_down) = if self.role == "exit" {
            self.targets.traffic.get()
        } else {
            let (mut up, mut down) = self.carry.get();
            for f in &forwards {
                up += f.bytes_up;
                down += f.bytes_down;
            }
            (up, down)
        };
        TrafficFile {
            version: TRAFFIC_FILE_VERSION,
            counter_id: lock(&self.counter_id).clone(),
            bytes_up,
            bytes_down,
            forwards,
        }
    }

    /// The `status` document.
    pub fn snapshot(&self) -> Status {
        let forwards: Vec<ForwardStatus> = self
            .forwards
            .iter()
            .map(|f| ForwardStatus {
                listen: f.listen.clone(),
                target: f.target.clone(),
                protocol: f.protocol.to_string(),
                tcp_open: f.tcp_open.load(Relaxed),
                tcp_total: f.tcp_total.load(Relaxed),
                udp_flows: f.udp_open.load(Relaxed),
                udp_total: f.udp_total.load(Relaxed),
                bytes_up: f.traffic.up.load(Relaxed),
                bytes_down: f.traffic.down.load(Relaxed),
                open_failures: f.open_failures.load(Relaxed),
                refused_per_ip: f.refused_per_ip.load(Relaxed),
            })
            .collect();
        // The carry (bytes of forwards that are gone) is part of the entry's sum; the exit
        // side's totals are its targets' and replace the sum below.
        let (carry_up, carry_down) = self.carry.get();
        let mut totals = Totals {
            bytes_up: carry_up,
            bytes_down: carry_down,
            ..Totals::default()
        };
        for f in &forwards {
            totals.bytes_up += f.bytes_up;
            totals.bytes_down += f.bytes_down;
            totals.tcp_open += f.tcp_open;
            totals.tcp_total += f.tcp_total;
            totals.udp_flows += f.udp_flows;
            totals.udp_total += f.udp_total;
        }
        let exit = (self.role == "exit").then(|| {
            let t = &self.targets;
            totals.bytes_up = t.traffic.up.load(Relaxed);
            totals.bytes_down = t.traffic.down.load(Relaxed);
            ExitStatus {
                streams_total: t.streams_total.load(Relaxed),
                dial_failures: t.dial_failures.load(Relaxed),
                last_dial_error: lock(&t.last_dial_error)
                    .clone()
                    .map(|(at, text)| LastError {
                        secs_ago: at.elapsed().as_secs(),
                        text,
                    }),
            }
        });
        Status {
            status_version: STATUS_VERSION,
            kariz: env!("CARGO_PKG_VERSION").to_string(),
            role: self.role.to_string(),
            mode: self.mode.to_string(),
            transport: lock(&self.active_transport)
                .unwrap_or(self.transport)
                .to_string(),
            profile: self.profile.to_string(),
            uptime_secs: self.started.elapsed().as_secs(),
            counter_id: Some(lock(&self.counter_id).clone()).filter(|id| !id.is_empty()),
            peer: self.peer.snapshot(self.mux),
            totals,
            forwards,
            exit,
            probe: self.probe.snapshot(),
        }
    }
}

/// Version of the traffic file; a file of another version is not read.
const TRAFFIC_FILE_VERSION: u32 = 1;
/// How often the traffic file is written while the counters move.
const SAVE_EVERY: Duration = Duration::from_secs(5);

/// The traffic file: this side's byte totals, kept across restarts (`[control]
/// traffic_file`, next to the config by default). JSON, so a person can read it.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
struct TrafficFile {
    version: u32,
    /// Changes when the counters start again from zero (no file, or one that could not be
    /// used), so a reader that keeps its own running total can tell a counter that went
    /// back a little (a restore after a hard kill) from one that started over.
    #[serde(default)]
    counter_id: String,
    bytes_up: u64,
    bytes_down: u64,
    /// Entry side: each `[[forward]]` rule's own bytes.
    #[serde(default)]
    forwards: Vec<ForwardTraffic>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
struct ForwardTraffic {
    listen: String,
    target: String,
    protocol: String,
    bytes_up: u64,
    bytes_down: u64,
}

impl TrafficFile {
    /// The version is known and the forwards do not add up to more than the totals.
    fn adds_up(&self) -> bool {
        let (mut up, mut down) = (0u64, 0u64);
        for f in &self.forwards {
            up = up.saturating_add(f.bytes_up);
            down = down.saturating_add(f.bytes_down);
        }
        self.version == TRAFFIC_FILE_VERSION && up <= self.bytes_up && down <= self.bytes_down
    }
}

/// 16 hex characters that mark one life of the counters.
fn new_counter_id() -> String {
    let mut bytes = [0u8; 8];
    if getrandom::fill(&mut bytes).is_err() {
        // Not random, but still a new value: the clock.
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos() as u64);
        bytes = t.to_be_bytes();
    }
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Writes the traffic file in one piece: the new content goes to a temporary file next to
/// it, which then takes its place, so a reader (or a restart) never sees half a file.
fn write_traffic_file(path: &Path, file: &TrafficFile) -> std::io::Result<()> {
    let text = serde_json::to_vec_pretty(file)?;
    let tmp = path.with_extension("traffic.tmp");
    {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut f = options.open(&tmp)?;
        std::io::Write::write_all(&mut f, &text)?;
        f.sync_data()?;
    }
    std::fs::rename(&tmp, path)
}

/// One writer at a time to the traffic file: the periodic write runs on a blocking thread,
/// and the write at shutdown waits for it before it writes the final counters.
type WriteGate = Arc<Mutex<()>>;

/// Writes the counters once more when the task that keeps the traffic file is dropped: at
/// shutdown, when the runtime drops its tasks.
struct FlushOnDrop {
    stats: Arc<Stats>,
    path: PathBuf,
    gate: WriteGate,
}

impl Drop for FlushOnDrop {
    fn drop(&mut self) {
        let _held = lock(&self.gate);
        let _ = write_traffic_file(&self.path, &self.stats.traffic_file());
    }
}

/// Keeps the traffic file at `path` up to date: every few seconds while the byte counters
/// move (written off the runtime's threads, so the tunnel never waits on the disk), and
/// once more at shutdown. It never returns (a tunnel's tasks end the tunnel when they do):
/// a write that fails is logged, not more than once a minute, and tried again.
pub async fn persist(stats: Arc<Stats>, path: PathBuf) -> anyhow::Result<()> {
    let gate: WriteGate = Arc::new(Mutex::new(()));
    let _flush = FlushOnDrop {
        stats: stats.clone(),
        path: path.clone(),
        gate: gate.clone(),
    };
    let mut written = None;
    let mut last_warning: Option<Instant> = None;
    loop {
        tokio::time::sleep(SAVE_EVERY).await;
        let file = stats.traffic_file();
        let now = (file.bytes_up, file.bytes_down);
        if written == Some(now) {
            continue;
        }
        let (p, g) = (path.clone(), gate.clone());
        let result = tokio::task::spawn_blocking(move || {
            let _held = lock(&g);
            write_traffic_file(&p, &file)
        })
        .await;
        match result {
            Ok(Ok(())) => written = Some(now),
            Ok(Err(e)) => {
                if last_warning.map_or(true, |t| t.elapsed() >= Duration::from_secs(60)) {
                    tracing::warn!(path = %path.display(), error = %e, "the traffic file could not be written; the byte counters will not survive a restart");
                    last_warning = Some(Instant::now());
                }
            }
            // The write was cancelled with the runtime: the final write is the guard's.
            Err(_) => {}
        }
    }
}

/// The `status` document (docs/status.md).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Status {
    pub status_version: u32,
    pub kariz: String,
    pub role: String,
    pub mode: String,
    pub transport: String,
    pub profile: String,
    pub uptime_secs: u64,
    /// Marks one life of the byte counters (the traffic file's id): it changes when they
    /// start again from zero. Absent without a traffic file, and from older daemons.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counter_id: Option<String>,
    pub peer: PeerStatus,
    pub totals: Totals,
    #[serde(default)]
    pub forwards: Vec<ForwardStatus>,
    /// Exit side only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit: Option<ExitStatus>,
    /// Entry side, once the first probe is done.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probe: Option<ProbeStatus>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PeerStatus {
    /// An `auto` tunnel: the transport its live sessions use now (`kcp`, or `tcpmux+ws` while
    /// they differ); `null` for the other transports and while down.
    #[serde(default)]
    pub transport: Option<String>,
    pub connected: bool,
    /// Live sessions; `null` without mux.
    pub sessions: Option<u64>,
    /// Sessions the dialing side keeps up; `null` on the accepting side and without mux.
    pub sessions_wanted: Option<u64>,
    /// Seconds since the current connection came up; `null` while down.
    pub connected_secs: Option<u64>,
    /// Round-trip time to the other side, from mux pings or QUIC; `null` when unknown.
    pub rtt_ms: Option<f64>,
    pub handshakes_ok: u64,
    pub handshakes_failed: u64,
    pub last_error: Option<LastError>,
    /// With mux: streams open over all live sessions, and how many they can take.
    #[serde(default)]
    pub streams: Option<u64>,
    #[serde(default)]
    pub streams_max: Option<u64>,
    /// New connections that failed because every session was full.
    #[serde(default)]
    pub full: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LastError {
    pub secs_ago: u64,
    pub text: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Totals {
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub tcp_open: u64,
    pub tcp_total: u64,
    pub udp_flows: u64,
    pub udp_total: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ForwardStatus {
    pub listen: String,
    pub target: String,
    pub protocol: String,
    pub tcp_open: u64,
    pub tcp_total: u64,
    pub udp_flows: u64,
    pub udp_total: u64,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub open_failures: u64,
    /// Closed at once: the client's address had `tuning.max_conns_per_ip` open.
    #[serde(default)]
    pub refused_per_ip: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProbeStatus {
    pub outcome: ProbeOutcome,
    /// From starting to open until the exit side answered.
    pub ms: Option<u64>,
    /// The target the exit side was asked to connect to (empty: the tunnel alone).
    pub target: String,
    pub error: Option<String>,
    /// Probes in a row that found no way through, and that reached the exit side but not
    /// the target.
    pub fails: u32,
    pub target_fails: u32,
    pub ok_total: u64,
    pub failed_total: u64,
    pub secs_ago: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExitStatus {
    pub streams_total: u64,
    pub dial_failures: u64,
    pub last_dial_error: Option<LastError>,
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENTRY: &str = r#"
        role = "entry"
        mode = "reverse"
        [tunnel]
        transport = "tcpmux"
        listen = "0.0.0.0:3080"
        token = "0123456789abcdef0123"
        [[forward]]
        listen = "0.0.0.0:443"
        target = "127.0.0.1:443"
        [[forward]]
        listen = "0.0.0.0:53"
        target = "127.0.0.1:53"
        protocol = "tcp+udp"
    "#;

    #[test]
    fn forward_counters_add_up() {
        let stats = Stats::new(&Config::parse(ENTRY).unwrap());
        let (web, dns) = (&stats.forwards[0], &stats.forwards[1]);
        let a = web.tcp_connection();
        let b = web.tcp_connection();
        web.traffic.add_up(100);
        web.traffic.add_down(1000);
        drop(a);
        let flow = dns.udp_flow();
        {
            let mut tally = Tally::new(&dns.traffic.down);
            for _ in 0..70 {
                tally.add(10);
            }
            // The first packet at once, then a batch of 64; the rest when dropped.
            assert_eq!(dns.traffic.down.load(Relaxed), 650);
        }
        dns.open_failed();

        let s = stats.snapshot();
        assert_eq!((s.role.as_str(), s.transport.as_str()), ("entry", "tcpmux"));
        assert_eq!((s.forwards[0].tcp_open, s.forwards[0].tcp_total), (1, 2));
        assert_eq!((s.forwards[1].udp_flows, s.forwards[1].udp_total), (1, 1));
        assert_eq!(s.forwards[1].bytes_down, 700);
        assert_eq!(s.forwards[1].open_failures, 1);
        assert_eq!(s.forwards[1].protocol, "tcp+udp");
        assert_eq!(s.totals.bytes_up, 100);
        assert_eq!(s.totals.bytes_down, 1700);
        assert_eq!(s.totals.tcp_open, 1);
        assert!(s.exit.is_none());
        drop((b, flow));
        let s = stats.snapshot();
        assert_eq!((s.totals.tcp_open, s.totals.udp_flows), (0, 0));
    }

    #[test]
    fn the_peer_is_connected_while_a_session_lives() {
        let stats = Stats::new(&Config::parse(ENTRY).unwrap());
        let before = stats.snapshot().peer;
        assert!(!before.connected);
        assert_eq!(before.sessions, Some(0));
        // The accepting side does not choose how many sessions there are.
        assert_eq!(before.sessions_wanted, None);

        stats.peer.failed(&"authentication failed");
        let (a, _b) = tokio::io::duplex(1024);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let session = Arc::new(Session::Kmux(crate::mux::MuxSession::new(
                a,
                crate::mux::Side::Client,
                crate::mux::tests::config(),
            )));
            stats.peer.session_up(&session);
            let p = stats.snapshot().peer;
            assert!(p.connected);
            assert_eq!(
                (p.sessions, p.handshakes_ok, p.handshakes_failed),
                (Some(1), 1, 1)
            );
            assert_eq!(p.last_error.unwrap().text, "authentication failed");
            session.close();
            drop(session);
            let p = stats.snapshot().peer;
            assert!(!p.connected);
            assert_eq!(p.sessions, Some(0));
            assert_eq!(p.connected_secs, None);
        });
    }

    #[test]
    fn without_mux_the_last_attempt_decides() {
        let config = Config::parse(&ENTRY.replace("tcpmux", "tcp")).unwrap();
        let stats = Stats::new(&config);
        stats.peer.link_up();
        let p = stats.snapshot().peer;
        assert!(p.connected);
        assert_eq!((p.sessions, p.rtt_ms), (None, None));
        std::thread::sleep(Duration::from_millis(5));
        stats.peer.failed(&"connection refused");
        assert!(!stats.snapshot().peer.connected);
    }

    #[test]
    fn the_document_round_trips_through_json() {
        let stats = Stats::new(&Config::parse(ENTRY).unwrap());
        let s = stats.snapshot();
        let text = serde_json::to_string(&s).unwrap();
        assert!(text.contains("\"status_version\":1"), "{text}");
        assert!(!text.contains("\"exit\""), "{text}");
        assert_eq!(serde_json::from_str::<Status>(&text).unwrap(), s);
    }

    const ENTRY_ONE: &str = r#"
        role = "entry"
        mode = "reverse"
        [tunnel]
        transport = "tcpmux"
        listen = "0.0.0.0:3080"
        token = "0123456789abcdef0123"
        [[forward]]
        listen = "0.0.0.0:443"
        target = "127.0.0.1:443"
    "#;

    const EXIT: &str = r#"
        role = "exit"
        mode = "reverse"
        [tunnel]
        transport = "tcpmux"
        remote = "127.0.0.1:3080"
        token = "0123456789abcdef0123"
    "#;

    /// A fresh place for a test's traffic file (a leftover from an earlier run is removed).
    fn traffic_path(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("kariz-traffic-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("main.traffic")
    }

    /// A file written while the counters move still adds up: the forwards and the totals
    /// come from the same readings.
    #[test]
    fn a_traffic_file_written_under_load_adds_up() {
        let stats = Stats::new(&Config::parse(ENTRY).unwrap());
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let counting = {
            let (stats, stop) = (stats.clone(), stop.clone());
            std::thread::spawn(move || {
                while !stop.load(Relaxed) {
                    stats.forwards[0].traffic.add_up(3);
                    stats.forwards[1].traffic.add_down(5);
                }
            })
        };
        for _ in 0..2000 {
            let file = stats.traffic_file();
            assert!(file.adds_up(), "{file:?}");
            let (mut up, mut down) = (0, 0);
            for f in &file.forwards {
                up += f.bytes_up;
                down += f.bytes_down;
            }
            assert_eq!((up, down), (file.bytes_up, file.bytes_down));
        }
        stop.store(true, Relaxed);
        counting.join().unwrap();
    }

    fn totals(stats: &Stats) -> (u64, u64) {
        let s = stats.snapshot();
        (s.totals.bytes_up, s.totals.bytes_down)
    }

    #[test]
    fn the_byte_counters_come_back_from_the_traffic_file_on_the_entry_side() {
        let path = traffic_path("entry");
        let _ = std::fs::remove_file(&path);
        let first = Stats::new(&Config::parse(ENTRY).unwrap());
        // No file yet: the counters start at zero under a new id.
        first.restore(&path);
        let id = first.snapshot().counter_id.unwrap();
        assert_eq!(id.len(), 16);
        first.forwards[0].traffic.add_up(100);
        first.forwards[0].traffic.add_down(1000);
        first.forwards[1].traffic.add_up(5);
        write_traffic_file(&path, &first.traffic_file()).unwrap();

        // A new run: the same totals, per forward, under the same id.
        let again = Stats::new(&Config::parse(ENTRY).unwrap());
        again.restore(&path);
        let s = again.snapshot();
        assert_eq!(s.counter_id.as_deref(), Some(id.as_str()));
        assert_eq!((s.totals.bytes_up, s.totals.bytes_down), (105, 1000));
        assert_eq!(
            (s.forwards[0].bytes_up, s.forwards[0].bytes_down),
            (100, 1000)
        );
        assert_eq!(s.forwards[1].bytes_up, 5);
        again.forwards[1].traffic.add_down(7);
        assert_eq!(totals(&again), (105, 1007));
    }

    #[test]
    fn a_forward_that_was_edited_away_keeps_its_bytes_in_the_total() {
        let path = traffic_path("carry");
        let first = Stats::new(&Config::parse(ENTRY).unwrap());
        first.restore(&path);
        first.forwards[0].traffic.add_up(100);
        first.forwards[0].traffic.add_down(1000);
        first.forwards[1].traffic.add_up(50);
        first.forwards[1].traffic.add_down(500);
        write_traffic_file(&path, &first.traffic_file()).unwrap();

        // The tunnel is edited: only the first forward is left. The total stays, and goes on.
        let edited = Stats::new(&Config::parse(ENTRY_ONE).unwrap());
        edited.restore(&path);
        let s = edited.snapshot();
        assert_eq!((s.totals.bytes_up, s.totals.bytes_down), (150, 1500));
        assert_eq!(
            (s.forwards[0].bytes_up, s.forwards[0].bytes_down),
            (100, 1000)
        );
        edited.forwards[0].traffic.add_up(1);
        assert_eq!(totals(&edited), (151, 1500));
        // Written again, the carry is still in the totals, and a third run sees it.
        write_traffic_file(&path, &edited.traffic_file()).unwrap();
        let third = Stats::new(&Config::parse(ENTRY_ONE).unwrap());
        third.restore(&path);
        assert_eq!(totals(&third), (151, 1500));
    }

    #[test]
    fn the_exit_side_gets_its_totals_back_without_doubling_them() {
        let path = traffic_path("exit");
        let first = Stats::new(&Config::parse(EXIT).unwrap());
        first.restore(&path);
        first.targets.traffic.add_up(7);
        first.targets.traffic.add_down(9);
        write_traffic_file(&path, &first.traffic_file()).unwrap();
        for _ in 0..2 {
            let again = Stats::new(&Config::parse(EXIT).unwrap());
            again.restore(&path);
            assert_eq!(totals(&again), (7, 9));
            write_traffic_file(&path, &again.traffic_file()).unwrap();
        }
    }

    #[test]
    fn a_traffic_file_that_cannot_be_used_starts_the_counters_at_zero_under_a_new_id() {
        let path = traffic_path("bad");
        // The forwards add up to more than the totals: not trusted.
        let file = TrafficFile {
            version: TRAFFIC_FILE_VERSION,
            counter_id: "0123456789abcdef".into(),
            bytes_up: 10,
            bytes_down: 10,
            forwards: vec![ForwardTraffic {
                listen: "0.0.0.0:443".into(),
                target: "127.0.0.1:443".into(),
                protocol: "tcp".into(),
                bytes_up: 100,
                bytes_down: 0,
            }],
        };
        write_traffic_file(&path, &file).unwrap();
        let stats = Stats::new(&Config::parse(ENTRY_ONE).unwrap());
        stats.restore(&path);
        let s = stats.snapshot();
        assert_eq!((s.totals.bytes_up, s.totals.bytes_down), (0, 0));
        let id = s.counter_id.unwrap();
        assert!(!id.is_empty() && id != "0123456789abcdef");

        // Garbage: the same.
        std::fs::write(&path, b"{not json").unwrap();
        let stats = Stats::new(&Config::parse(ENTRY_ONE).unwrap());
        stats.restore(&path);
        assert_eq!(totals(&stats), (0, 0));
        assert!(stats.snapshot().counter_id.is_some());

        // Another version: not read.
        let other = TrafficFile {
            version: TRAFFIC_FILE_VERSION + 1,
            bytes_up: 5,
            bytes_down: 5,
            ..TrafficFile::default()
        };
        write_traffic_file(&path, &other).unwrap();
        let stats = Stats::new(&Config::parse(ENTRY_ONE).unwrap());
        stats.restore(&path);
        assert_eq!(totals(&stats), (0, 0));
    }

    #[test]
    fn a_file_without_an_id_gets_one_and_the_file_is_written_whole() {
        let path = traffic_path("noid");
        let file = TrafficFile {
            version: TRAFFIC_FILE_VERSION,
            bytes_up: 3,
            bytes_down: 4,
            ..TrafficFile::default()
        };
        write_traffic_file(&path, &file).unwrap();
        assert!(!path.with_extension("traffic.tmp").exists());
        let stats = Stats::new(&Config::parse(EXIT).unwrap());
        stats.restore(&path);
        let s = stats.snapshot();
        assert_eq!((s.totals.bytes_up, s.totals.bytes_down), (3, 4));
        assert_eq!(s.counter_id.map_or(0, |id| id.len()), 16);
        // The status of a side without a traffic file names no counter id.
        let plain = Stats::new(&Config::parse(EXIT).unwrap());
        assert_eq!(plain.snapshot().counter_id, None);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }
}
