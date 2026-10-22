//! The agent: what runs on every other server (`kariz-panel agent`). It dials the panel,
//! proves who it is, and answers the panel's requests: a fixed list, none of which runs anything the panel names.
//!
//! On a server the panel connects to (reverse, `listen` in its settings) it does not dial:
//! it listens on its own port, over the same link transports as a panel's agents port, and
//! the panel dials it. Everything after the link is made is the same.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use kariz::mux::Side;
use kariz::session::Session;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::collect::{self, Sampler};
use crate::join::{self, JoinCode};
use crate::manage::{self, Services};
use crate::wire::{Ack, HelloReply, Request, SpeedPoll, SpeedStarted, MAX_REQUEST};

pub const DEFAULT_AGENT_CONFIG: &str = "/etc/kariz-panel/agent.toml";
pub const DEFAULT_KARIZ_DIR: &str = "/etc/kariz";

/// The agent's identity and where the panel is: `/etc/kariz-panel/agent.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentConfig {
    /// The panel's address for agents: `host:port`.
    pub panel: String,
    /// The panel's link token.
    pub link_token: String,
    /// Until the agent is registered: the join secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub join: Option<String>,
    /// After that: who it is, and the key it proves it with.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// Where the Kariz tunnel configs are.
    #[serde(default = "default_kariz_dir")]
    pub kariz_dir: PathBuf,
    /// How tunnels are started: `systemd` (default) or `process`.
    #[serde(default)]
    pub services: manage::ServiceKind,
    /// A release public key (hex) of your own, instead of the one built in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_key: Option<String>,
    /// The one link transport to use (`tcpmux`, `kcp`, `wss`, `quic`); none: try them in turn.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,
    /// Reverse: listen here for the panel (`0.0.0.0:PORT`) instead of dialing `panel`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen: Option<String>,
    /// The panel may open a terminal (a root shell) on this server. Off unless set here.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub terminal: bool,
}

fn default_kariz_dir() -> PathBuf {
    PathBuf::from(DEFAULT_KARIZ_DIR)
}

impl AgentConfig {
    /// The settings a join code stands for.
    pub fn from_join(code: &JoinCode) -> Self {
        Self {
            panel: code.p.clone(),
            link_token: code.t.clone(),
            join: Some(code.j.clone()),
            id: None,
            key: None,
            kariz_dir: default_kariz_dir(),
            services: Default::default(),
            release_key: None,
            transport: code.x.clone(),
            listen: code.l.clone(),
            terminal: false,
        }
    }

    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        toml::from_str(&text).with_context(|| format!("invalid {}", path.display()))
    }

    /// Writes the file so that only its owner can read it (it holds a key).
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        write_private(path, toml::to_string_pretty(self)?.as_bytes())
    }
}

pub(crate) fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    // Written beside the file and renamed, so a crash never leaves half a key.
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".new");
    let tmp = PathBuf::from(tmp);
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        file.write_all(data)?;
        file.sync_all()?;
    }
    #[cfg(not(unix))]
    std::fs::write(&tmp, data)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// What the agent proves its key with: the keyed hash of the panel's challenge.
pub fn proof(key_hex: &str, challenge: &str) -> Option<String> {
    let key = hex_to_key(key_hex)?;
    Some(
        blake3::keyed_hash(&key, challenge.as_bytes())
            .to_hex()
            .to_string(),
    )
}

pub fn hex_to_key(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 || !hex.is_ascii() {
        return None;
    }
    let mut key = [0u8; 32];
    for (i, byte) in key.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(key)
}

/// A speed test running (or finished) in the background: what it has said, and its end.
#[derive(Default)]
struct SpeedJob {
    name: String,
    lines: Vec<String>,
    done: bool,
    error: Option<String>,
    report: Option<kariz::speedtest::Report>,
    started: Option<std::time::Instant>,
    /// Told to stop the test.
    stop: Arc<tokio::sync::Notify>,
}

/// The agent's state while it runs.
pub struct Agent {
    /// Its benchmark test listeners.
    bench: crate::bench::Listeners,
    speed_jobs: Arc<Mutex<std::collections::HashMap<String, SpeedJob>>>,
    path: PathBuf,
    config: Mutex<AgentConfig>,
    sampler: Mutex<Sampler>,
    services: Arc<dyn Services>,
    net: crate::net::Net,
    update: crate::agent_update::AgentUpdate,
}

impl Agent {
    pub fn new(path: &Path, config: AgentConfig) -> Arc<Self> {
        Self::with_services(path, config, Arc::new(manage::Systemd))
    }

    /// An agent that starts and stops tunnels through `services` (systemd by default).
    pub fn with_services(
        path: &Path,
        config: AgentConfig,
        services: Arc<dyn Services>,
    ) -> Arc<Self> {
        Self::with_exec(path, config, services, Arc::new(crate::net::Real))
    }

    /// Like [`Agent::with_services`], and the programs of the private network code (`ip`,
    /// `ping`) run through `exec` (the tests record them instead).
    pub fn with_exec(
        path: &Path,
        config: AgentConfig,
        services: Arc<dyn Services>,
        exec: Arc<dyn crate::net::Exec>,
    ) -> Arc<Self> {
        Self::with_launcher(
            path,
            config,
            services,
            exec,
            Box::new(crate::agent_update::SystemdRun),
        )
    }

    /// Like [`Agent::with_exec`], and the update helper is started through `launcher` (the
    /// tests record it instead of running systemd).
    pub fn with_launcher(
        path: &Path,
        config: AgentConfig,
        services: Arc<dyn Services>,
        exec: Arc<dyn crate::net::Exec>,
        launcher: Box<dyn crate::agent_update::Launcher>,
    ) -> Arc<Self> {
        let config_key = config.release_key.clone();
        Arc::new(Self {
            bench: crate::bench::Listeners::default(),
            speed_jobs: Arc::default(),
            path: path.to_path_buf(),
            config: Mutex::new(config),
            sampler: Mutex::new(Sampler::default()),
            services,
            // The links of private networks are kept beside the agent's own settings.
            net: crate::net::Net::with_exec(
                (!path.as_os_str().is_empty()).then(|| path.with_file_name("net.toml")),
                exec,
            ),
            update: crate::agent_update::AgentUpdate::new(
                path.with_file_name("updates"),
                path.to_path_buf(),
                config_key,
                std::env::current_exe().unwrap_or_default(),
                std::env::current_exe()
                    .unwrap_or_default()
                    .with_file_name("kariz"),
                launcher,
            ),
        })
    }

    fn config(&self) -> AgentConfig {
        self.config
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Whether the panel may open a terminal here (the panel's own server takes it from
    /// `panel.toml`).
    pub fn allow_terminal(&self, on: bool) {
        self.config
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .terminal = on;
    }

    /// A terminal on this server, in process (the panel's own server): one end of a pipe
    /// whose other end the shell is served on.
    pub fn open_shell(&self, cols: u16, rows: u16) -> crate::terminal::Pipe {
        let (mine, theirs) = crate::terminal::pipe();
        let allowed = self.config().terminal;
        tokio::spawn(crate::terminal::serve_stream(theirs, cols, rows, allowed));
        mine
    }

    /// Starts a speed test in the background; its id comes back at once.
    fn speedtest_start(&self, name: String, seconds: u32, streams: u32, udp: bool) -> SpeedStarted {
        let dir = self.config().kariz_dir;
        // Said now, before anything runs, if the test cannot be made at all.
        if let Err(e) = manage::speedtest_setup(&dir, &name, seconds, streams, udp) {
            return SpeedStarted {
                ok: false,
                error: Some(format!("{e:#}")),
                id: String::new(),
            };
        }
        let id = match crate::config::random_hex(8) {
            Ok(id) => id,
            Err(e) => {
                return SpeedStarted {
                    ok: false,
                    error: Some(format!("{e:#}")),
                    id: String::new(),
                }
            }
        };
        {
            let mut jobs = self.speed_jobs.lock().unwrap_or_else(|e| e.into_inner());
            // Old ones go, and a tunnel is tested by one test at a time.
            jobs.retain(|_, j| {
                j.started
                    .is_some_and(|t| t.elapsed() < Duration::from_secs(900))
            });
            if jobs.values().any(|j| j.name == name && !j.done) {
                return SpeedStarted {
                    ok: false,
                    error: Some("busy".into()),
                    id: String::new(),
                };
            }
            jobs.insert(
                id.clone(),
                SpeedJob {
                    name: name.clone(),
                    started: Some(std::time::Instant::now()),
                    ..Default::default()
                },
            );
        }
        let stop = {
            let jobs = self.speed_jobs.lock().unwrap_or_else(|e| e.into_inner());
            jobs.get(&id).map(|j| j.stop.clone()).unwrap_or_default()
        };
        let jobs = self.speed_jobs.clone();
        let job = id.clone();
        tokio::spawn(async move {
            let push = {
                let (jobs, job) = (jobs.clone(), job.clone());
                move |line: &str| {
                    let mut jobs = jobs.lock().unwrap_or_else(|e| e.into_inner());
                    if let Some(j) = jobs.get_mut(&job) {
                        j.lines.push(line.to_owned());
                    }
                }
            };
            // Stopping drops the test: its connection to the daemon closes, the daemon sees the
            // next write fail and ends the test.
            let reply = tokio::select! {
                reply = manage::speedtest_with(&dir, &name, seconds, streams, udp, push) => reply,
                () = stop.notified() => crate::wire::SpeedReply {
                    ok: false,
                    error: Some("stopped".into()),
                    text: String::new(),
                    report: None,
                },
            };
            let mut jobs = jobs.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(j) = jobs.get_mut(&job) {
                j.done = true;
                j.report = reply.report;
                j.error = if reply.ok { None } else { reply.error };
            }
        });
        SpeedStarted {
            ok: true,
            error: None,
            id,
        }
    }

    /// What a started speed test has said after the first `after` lines.
    fn speedtest_poll(&self, id: &str, after: u32) -> SpeedPoll {
        let jobs = self.speed_jobs.lock().unwrap_or_else(|e| e.into_inner());
        let Some(job) = jobs.get(id) else {
            return SpeedPoll {
                ok: false,
                error: Some("no_such_test".into()),
                ..Default::default()
            };
        };
        let from = (after as usize).min(job.lines.len());
        SpeedPoll {
            ok: true,
            error: job.error.clone(),
            lines: job.lines[from..].to_vec(),
            next: u32::try_from(job.lines.len()).unwrap_or(u32::MAX),
            done: job.done,
            report: job.report.clone(),
        }
    }

    /// The answer to one request, as JSON.
    pub async fn handle(&self, request: Request) -> Vec<u8> {
        match request {
            Request::Hello { challenge } => {
                let c = self.config();
                let proof = c.key.as_deref().and_then(|k| proof(k, &challenge));
                to_json(&HelloReply {
                    id: c.id.clone(),
                    proof,
                    join: c.join.clone(),
                    hostname: collect::hostname(),
                    version: crate::version().to_owned(),
                    arch: std::env::consts::ARCH.to_owned(),
                })
            }
            Request::Enroll { id, key } => {
                let saved = {
                    let mut c = self.config.lock().unwrap_or_else(|e| e.into_inner());
                    // Only an agent still waiting to be registered takes an identity.
                    if c.join.is_none() || hex_to_key(&key).is_none() {
                        Err(anyhow::anyhow!("not waiting to be registered"))
                    } else {
                        let mut next = c.clone();
                        next.join = None;
                        next.id = Some(id);
                        next.key = Some(key);
                        next.save(&self.path).map(|()| *c = next)
                    }
                };
                match saved {
                    Ok(()) => to_json(&Ack {
                        ok: true,
                        error: None,
                    }),
                    Err(e) => to_json(&Ack {
                        ok: false,
                        error: Some(format!("{e:#}")),
                    }),
                }
            }
            Request::Health => {
                let health = self
                    .sampler
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .sample();
                to_json(&health)
            }
            Request::Tunnels => {
                to_json(&collect::tunnels(&self.config().kariz_dir, &*self.services).await)
            }
            Request::TunnelCheck { spec } => {
                let dir = self.config().kariz_dir;
                let owners = tokio::task::spawn_blocking(manage::ports)
                    .await
                    .unwrap_or_default();
                to_json(&manage::check(&dir, &owners, &spec))
            }
            Request::TunnelPut { spec } => {
                let dir = self.config().kariz_dir;
                to_json(&match manage::put(&dir, &spec) {
                    Ok(pin) => crate::wire::PutReply {
                        ok: true,
                        error: None,
                        pin,
                    },
                    Err(e) => crate::wire::PutReply {
                        ok: false,
                        error: Some(format!("{e:#}")),
                        pin: None,
                    },
                })
            }
            Request::TunnelGet { name } => {
                let dir = self.config().kariz_dir;
                match manage::get(&dir, &name) {
                    Ok(spec) => to_json(&spec),
                    Err(e) => to_json(&Ack {
                        ok: false,
                        error: Some(format!("{e:#}")),
                    }),
                }
            }
            Request::TunnelDiff { spec } => {
                let dir = self.config().kariz_dir;
                to_json(&manage::diff(&dir, &spec))
            }
            Request::TunnelReload { name } => {
                let dir = self.config().kariz_dir;
                to_json(&manage::reload(&dir, &name).await)
            }
            Request::TunnelDelete { name } => {
                let dir = self.config().kariz_dir;
                ack(manage::delete(&dir, &*self.services, &name).await)
            }
            // Served on its own stream (see `serve_with`); never answered here.
            Request::Shell { .. } => to_json(&Ack {
                ok: false,
                error: Some("a terminal needs a stream of its own".into()),
            }),
            Request::TunnelCtl { name, action } => ack(self.services.ctl(name, action).await),
            Request::Ports => to_json(
                &tokio::task::spawn_blocking(manage::ports)
                    .await
                    .unwrap_or_default(),
            ),
            Request::NetUp { net } => ack(self.net.up(net).await),
            Request::NetDown { name } => ack(self.net.down(&name).await),
            Request::NetSync { links } => ack(self.net.sync(links).await),
            Request::NetPing { name } => to_json(&self.net.ping(&name).await),
            Request::NetStatus => to_json(&self.net.status().await),
            Request::BenchListen {
                token,
                transport,
                profile,
                port,
                wait_ms,
                bind,
            } => {
                let (cert, key) = (
                    self.path.with_file_name("link-cert.pem"),
                    self.path.with_file_name("link-key.pem"),
                );
                to_json(
                    &crate::bench::listen(
                        &self.bench,
                        &token,
                        &transport,
                        &profile,
                        port,
                        wait_ms,
                        bind.as_deref(),
                        (&cert, &key),
                    )
                    .await,
                )
            }
            Request::BenchDial {
                addr,
                token,
                transport,
                profile,
                ping_ms,
                seconds,
                sni,
            } => to_json(
                &crate::bench::dial(
                    &addr,
                    &token,
                    &transport,
                    &profile,
                    ping_ms,
                    seconds,
                    sni.as_deref(),
                )
                .await,
            ),
            Request::UpdateBegin { version, files } => ack(self.update.begin(&version, &files)),
            Request::UpdateChunk {
                version,
                name,
                offset,
                data,
            } => ack(self.update.chunk(&version, &name, offset, &data)),
            Request::UpdateApply { version } => ack(self.update.apply(&version)),
            Request::Logs { name, lines } => match self.services.logs(name.clone(), lines).await {
                Some(kept) => to_json(&kept),
                None => to_json(&manage::logs(&name, lines).await),
            },
            Request::Speedtest {
                name,
                seconds,
                streams,
                udp,
            } => {
                let dir = self.config().kariz_dir;
                to_json(&manage::speedtest(&dir, &name, seconds, streams, udp).await)
            }
            Request::TunnelCert { domain, email } => {
                to_json(&manage::issue_cert(&domain, email.as_deref()).await)
            }
            Request::SpeedtestStart {
                name,
                seconds,
                streams,
                udp,
            } => to_json(&self.speedtest_start(name, seconds, streams, udp)),
            Request::SpeedtestPoll { id, after } => to_json(&self.speedtest_poll(&id, after)),
            Request::SpeedtestStop { id } => {
                let jobs = self.speed_jobs.lock().unwrap_or_else(|e| e.into_inner());
                match jobs.get(&id) {
                    Some(job) => {
                        job.stop.notify_one();
                        ack(Ok(()))
                    }
                    None => ack(Err(anyhow::anyhow!("no_such_test"))),
                }
            }
            Request::IpTestReceiver {
                shape,
                bind,
                seconds,
                run_id,
                expect,
                loss,
            } => to_json(&ip_test_receive(shape, bind, seconds, run_id, expect, loss).await),
            Request::IpTestSender {
                to,
                shape,
                sources,
                count,
                interval_ms,
                run_id,
            } => to_json(&ip_test_send(to, shape, sources, count, interval_ms, run_id).await),
        }
    }

    /// Answers the requests on one session until it closes.
    /// Returns how many requests the panel made; `working` is called once it has made
    /// [`GOOD_LINK`] of them.
    pub async fn serve(self: &Arc<Self>, session: Session, working: impl FnOnce()) -> u32 {
        self.serve_with(session, working).await.0
    }

    /// Like [`Agent::serve`], and why the session ended.
    pub async fn serve_with(
        self: &Arc<Self>,
        session: Session,
        working: impl FnOnce(),
    ) -> (u32, String) {
        let mut asked = 0u32;
        let mut working = Some(working);
        let session = Arc::new(session);
        loop {
            // The panel asks every 2 s. A link where it has gone quiet is stalled on the
            // way (its close may not get through either): drop it now instead of waiting
            // for the keepalive, so a stalled transport is given up in seconds.
            let (stream, syn) = match tokio::time::timeout(QUIET_LINK, session.accept()).await {
                Ok(Some(next)) => next,
                Ok(None) => break,
                Err(_) => {
                    warn!(
                        secs = QUIET_LINK.as_secs(),
                        "the panel asked nothing for a while; dropping the link"
                    );
                    session.close();
                    return (asked, "the panel went quiet".into());
                }
            };
            asked = asked.saturating_add(1);
            if asked >= GOOD_LINK {
                if let Some(f) = working.take() {
                    f();
                }
            }
            let agent = self.clone();
            tokio::spawn(async move {
                // A terminal keeps its stream: the shell's bytes go both ways on it.
                if let Ok(Request::Shell { cols, rows }) = serde_json::from_slice::<Request>(&syn) {
                    if syn.len() <= MAX_REQUEST {
                        let allowed = agent.config().terminal;
                        crate::terminal::serve_stream(stream, cols, rows, allowed).await;
                        return;
                    }
                }
                let reply = match serde_json::from_slice::<Request>(&syn) {
                    Ok(request) if syn.len() <= MAX_REQUEST => {
                        // A request that panics is answered with an error (and logged), not
                        // left to reset its stream.
                        let doing = agent.clone();
                        match tokio::spawn(async move { doing.handle(request).await }).await {
                            Ok(reply) => reply,
                            Err(e) => {
                                warn!(error = %e, "a request failed inside the agent");
                                serde_json::to_vec(&Ack {
                                    ok: false,
                                    error: Some("internal error".into()),
                                })
                                .unwrap_or_default()
                            }
                        }
                    }
                    _ => {
                        warn!(bytes = syn.len(), "an unknown or oversized request");
                        serde_json::to_vec(&Ack {
                            ok: false,
                            error: Some("unknown request".into()),
                        })
                        .unwrap_or_default()
                    }
                };
                if stream.send(Bytes::from(reply)).await.is_ok() {
                    let _ = stream.finish();
                    // The panel finishes its side right after opening the stream. If the
                    // answer is quick, the stream can be dropped before that end-of-stream
                    // frame has arrived, and a stream dropped half open is reset: the panel
                    // would see an error for a request that was answered. So wait for it.
                    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), async {
                        while let Ok(Some(_)) = stream.recv().await {}
                    })
                    .await;
                }
            });
        }
        let why = session
            .close_reason()
            .unwrap_or_else(|| "closed by the panel".into());
        (asked, why)
    }

    /// Makes the private network links this server had (after a start or a reboot).
    pub async fn restore_net(&self) {
        for (name, result) in self.net.restore().await {
            match result {
                Ok(()) => info!(link = %name, "a private network link is up"),
                Err(e) => {
                    warn!(link = %name, error = %e, "a private network link could not be made")
                }
            }
        }
    }

    /// Keeps a session to the panel up, for ever.
    pub async fn run(self: Arc<Self>) -> Result<()> {
        let c = self.config();
        if c.join.is_none() && (c.id.is_none() || c.key.is_none()) {
            bail!(
                "the agent has no join code and no identity: run `kariz-panel agent --join CODE`"
            );
        }
        // The tunnels run as child processes come back with the agent (nothing to do under
        // systemd).
        tokio::spawn(self.services.clone().supervise());
        // The private network links this server had come back with the agent.
        for (name, result) in self.net.restore().await {
            match result {
                Ok(()) => info!(link = %name, "a private network link is up"),
                Err(e) => {
                    warn!(link = %name, error = %e, "a private network link could not be made")
                }
            }
        }
        if let Some(listen) = c.listen.clone() {
            return self.listen_for_panel(&listen).await;
        }
        // One transport if the join code named it, else all of them in turn.
        let kinds: Vec<_> = kariz::link::LINK_TRANSPORTS
            .into_iter()
            .filter(|k| !matches!(c.transport.as_deref(), Some(t) if t != k.name()))
            .collect();
        if kinds.is_empty() {
            bail!(
                "unknown transport {:?} in the agent's settings",
                c.transport.unwrap_or_default()
            );
        }
        let chosen = self.path.with_file_name(TRANSPORT_FILE);
        let mut at = std::fs::read_to_string(&chosen)
            .ok()
            .and_then(|t| kinds.iter().position(|k| k.name() == t.trim()))
            .unwrap_or(0);
        let mut misses = 0u32;
        let mut backoff = Duration::from_secs(1);
        loop {
            let kind = kinds[at];
            // wss and quic are on the port after the agents port, the others on it.
            let addr = &kariz::link::address_for(&c.panel, kind)?;
            let dialer = kariz::link::Dialer::via(addr, &c.link_token, kind)?;
            match dialer.connect(Side::Server).await {
                Ok(session) => {
                    info!(panel = %addr, transport = kind.name(), "connected to the panel");
                    crate::agent_update::touch(&self.path.with_file_name("connected"));
                    let started = std::time::Instant::now();
                    let (asked, why) = self
                        .serve_with(session, || {
                            // This transport gets through: the one to start with next time.
                            if at != 0 || chosen.exists() {
                                let _ = std::fs::write(&chosen, kind.name());
                            }
                        })
                        .await;
                    warn!(
                        transport = kind.name(),
                        requests = asked,
                        secs = started.elapsed().as_secs(),
                        reason = %why,
                        "the link to the panel ended; reconnecting"
                    );
                    if asked >= GOOD_LINK {
                        misses = 0;
                        backoff = Duration::from_secs(1);
                    } else {
                        misses += 1;
                        if asked == 0 && self.config().id.is_some() {
                            warn!(
                                "the panel asked this server nothing: the link is stalled on                                  the way, or the panel does not know this server (removed, or                                  reinstalled; then delete agent.toml and join with a new code)"
                            );
                        }
                    }
                    if started.elapsed() < Duration::from_secs(2) {
                        tokio::time::sleep(backoff).await;
                    }
                }
                Err(e) => {
                    warn!(transport = kind.name(), error = %e, "could not connect to the panel");
                    misses += 1;
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(30));
                }
            }
            // A transport that keeps failing is swapped for the next one, round and round,
            // so a network that stalls TCP (or blocks UDP) is got around without anyone
            // having to choose.
            if misses >= MISSES_BEFORE_SWITCH && kinds.len() > 1 {
                misses = 0;
                at = (at + 1) % kinds.len();
                backoff = Duration::from_secs(1);
                info!(
                    transport = kinds[at].name(),
                    "trying another transport to the panel"
                );
            }
        }
    }
}

impl Agent {
    /// Reverse: waits for the panel on `listen`, over every link transport (or the one the
    /// code named), the way a panel's agents port does: `tcpmux` and `kcp` on the port (TCP
    /// and UDP), `wss` and `quic` on the next. `wss` uses a self-signed certificate made
    /// here (the panel does not check it: the token handshake inside proves who is who).
    /// Each link the panel makes is served like one the agent dialed.
    async fn listen_for_panel(self: Arc<Self>, listen: &str) -> Result<()> {
        let c = self.config();
        let kinds: Vec<_> = kariz::link::LINK_TRANSPORTS
            .into_iter()
            .filter(|k| !matches!(c.transport.as_deref(), Some(t) if t != k.name()))
            .collect();
        if kinds.is_empty() {
            bail!(
                "unknown transport {:?} in the agent's settings",
                c.transport.unwrap_or_default()
            );
        }
        let (cert, key) = (
            self.path.with_file_name("link-cert.pem"),
            self.path.with_file_name("link-key.pem"),
        );
        let mut accepting = tokio::task::JoinSet::new();
        for kind in kinds {
            let addr = kariz::link::address_for(listen, kind)?;
            for one in listen_addresses(&addr) {
                let bound = if kind == kariz::config::TransportKind::Wss {
                    crate::cert::ensure(&cert, &key)?;
                    kariz::link::Acceptor::bind_wss(&one, &c.link_token, &cert, &key).await
                } else {
                    kariz::link::Acceptor::bind_via(&one, &c.link_token, kind).await
                };
                match bound {
                    Ok(acceptor) => {
                        info!(address = %one, transport = kind.name(), "waiting for the panel");
                        accepting.spawn(self.clone().serve_panel_links(acceptor));
                    }
                    Err(e) => {
                        tracing::debug!(address = %one, transport = kind.name(), error = %e, "could not listen")
                    }
                }
            }
        }
        if accepting.is_empty() {
            bail!("could not listen for the panel on {listen} (is the port in use?)");
        }
        while accepting.join_next().await.is_some() {}
        bail!("the agent stopped listening for the panel")
    }

    /// Takes the panel's links on one acceptor, for ever.
    async fn serve_panel_links(self: Arc<Self>, acceptor: kariz::link::Acceptor) {
        let kind = acceptor.kind().name();
        loop {
            let pending = match acceptor.accept().await {
                Ok(p) => p,
                Err(e) => {
                    warn!(transport = kind, error = %e, "accepting the panel's link failed");
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    continue;
                }
            };
            let agent = self.clone();
            tokio::spawn(async move {
                let peer = pending.peer();
                match pending.establish(Side::Server).await {
                    Ok(session) => {
                        info!(panel = %peer, transport = kind, "the panel connected");
                        crate::agent_update::touch(&agent.path.with_file_name("connected"));
                        let started = std::time::Instant::now();
                        let (asked, why) = agent.serve_with(session, || {}).await;
                        warn!(
                            transport = kind,
                            requests = asked,
                            secs = started.elapsed().as_secs(),
                            reason = %why,
                            "the panel's link ended; waiting for it again"
                        );
                    }
                    Err(e) => {
                        tracing::debug!(%peer, transport = kind, error = %e, "a link did not authenticate")
                    }
                }
            });
        }
    }
}

/// The addresses to listen on for `addr`: one for every IPv4 address (`0.0.0.0:P`) is taken
/// on IPv6 too (`[::]:P`), so either can reach it. Where the IPv6 socket takes IPv4 as well
/// (Linux), the IPv4 one is refused as in use, which is fine.
pub fn listen_addresses(addr: &str) -> Vec<String> {
    match addr.strip_prefix("0.0.0.0:") {
        Some(port) => vec![format!("[::]:{port}"), addr.to_owned()],
        None => vec![addr.to_owned()],
    }
}

/// Beside `agent.toml`: the link transport that last worked. A file of its own, so an
/// older agent (a rolled back update) still reads its settings.
const TRANSPORT_FILE: &str = "link-transport";
/// A link that served this many requests is working (the panel polls every 2 s).
const GOOD_LINK: u32 = 3;
/// Silence from the panel after which a link counts as stalled (it asks every 2 s).
const QUIET_LINK: Duration = Duration::from_secs(20);
/// Failed links in a row before the agent tries the next transport.
const MISSES_BEFORE_SWITCH: u32 = 2;

fn to_json<T: Serialize>(value: &T) -> Vec<u8> {
    serde_json::to_vec(value).unwrap_or_default()
}

/// Reads a join code, writes the agent's settings from it, and returns them.
///
/// A code for a server that reaches the panel through a private network carries its end of
/// the GRE link: it is saved with the links the agent makes when it starts, before it dials.
/// An interface of that name that is there with other settings is taken down, so the agent
/// makes it again with the code's.
pub fn enroll_from_code(code_text: &str, path: &Path) -> Result<AgentConfig> {
    let code = join::decode(code_text)?;
    if let Some(link) = code.g.clone() {
        let name = link.name.clone();
        let net = crate::net::Net::new(Some(path.with_file_name("net.toml")));
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        if net.keep(link)? && Path::new("/sys/class/net").join(&name).exists() {
            let _ = std::process::Command::new("ip")
                .args(["link", "del", name.as_str()])
                .status();
        }
    }
    let config = AgentConfig::from_join(&code);
    config.save(path)?;
    Ok(config)
}

fn ack(result: Result<()>) -> Vec<u8> {
    match result {
        Ok(()) => to_json(&Ack {
            ok: true,
            error: None,
        }),
        Err(e) => to_json(&Ack {
            ok: false,
            error: Some(format!("{e:#}")),
        }),
    }
}

/// Runs the spoof-test receiver on this server and wraps the report for the wire.
async fn ip_test_receive(
    shape: String,
    bind: String,
    seconds: u16,
    run_id: u32,
    expect: u16,
    loss: u8,
) -> crate::wire::IpTestReceiverReply {
    use crate::wire::IpTestReceiverReply;
    let Some(shape) = kariz::config::SpoofShape::from_name(&shape) else {
        return IpTestReceiverReply {
            ok: false,
            error: Some(format!("unknown shape {shape:?}")),
            report: None,
        };
    };
    let opts = kariz::spooftest::ReceiverOptions {
        bind,
        shape,
        seconds: seconds.clamp(1, 120),
        run_id,
        expect,
        loss_pct: loss.min(100),
        interface: String::new(),
    };
    match kariz::spooftest::receiver(opts).await {
        Ok(report) => IpTestReceiverReply {
            ok: true,
            error: None,
            report: Some(report),
        },
        Err(e) => IpTestReceiverReply {
            ok: false,
            error: Some(format!("{e}")),
            report: None,
        },
    }
}

/// Runs the spoof-test sender on this server and wraps the summary for the wire.
async fn ip_test_send(
    to: String,
    shape: String,
    sources: Vec<String>,
    count: u16,
    interval_ms: u16,
    run_id: u32,
) -> crate::wire::IpTestSenderReply {
    use crate::wire::IpTestSenderReply;
    let Some(shape) = kariz::config::SpoofShape::from_name(&shape) else {
        return IpTestSenderReply {
            ok: false,
            error: Some(format!("unknown shape {shape:?}")),
            sent: 0,
            sources: 0,
        };
    };
    let opts = kariz::spooftest::SenderOptions {
        to,
        shape,
        sources,
        count,
        interval_ms,
        run_id,
        interface: String::new(),
    };
    match kariz::spooftest::sender(opts).await {
        Ok(r) => IpTestSenderReply {
            ok: true,
            error: None,
            sent: r.sent,
            sources: r.sources,
        },
        Err(e) => IpTestSenderReply {
            ok: false,
            error: Some(format!("{e}")),
            sent: 0,
            sources: 0,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::Health;

    fn key() -> String {
        "ab".repeat(32)
    }

    #[test]
    fn a_proof_needs_the_key_and_the_challenge() {
        let a = proof(&key(), "challenge one").unwrap();
        assert_eq!(a.len(), 64);
        assert_eq!(proof(&key(), "challenge one").unwrap(), a);
        assert_ne!(proof(&key(), "challenge two").unwrap(), a);
        assert_ne!(proof(&"cd".repeat(32), "challenge one").unwrap(), a);
        assert_eq!(proof("short", "x"), None);
        assert_eq!(proof(&"zz".repeat(32), "x"), None);
    }

    #[tokio::test]
    async fn an_agent_is_enrolled_once_and_keeps_its_identity_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.toml");
        let code = JoinCode {
            p: "127.0.0.1:1".into(),
            t: "t".repeat(64),
            j: "j".repeat(32),
            n: None,
            x: None,
            g: None,
            l: None,
        };
        let config = enroll_from_code(&join::encode(&code), &path).unwrap();
        assert_eq!(config.join.as_deref(), Some(code.j.as_str()));
        let agent = Agent::new(&path, config);

        // Before enrolling, it shows the join secret and no proof.
        let hello = |agent: &Arc<Agent>| {
            let agent = agent.clone();
            async move {
                let raw = agent
                    .handle(Request::Hello {
                        challenge: "c".into(),
                    })
                    .await;
                serde_json::from_slice::<HelloReply>(&raw).unwrap()
            }
        };
        let before = hello(&agent).await;
        assert_eq!((before.id, before.proof), (None, None));
        assert_eq!(before.join.as_deref(), Some(code.j.as_str()));

        let ack: Ack = serde_json::from_slice(
            &agent
                .handle(Request::Enroll {
                    id: "id1".into(),
                    key: key(),
                })
                .await,
        )
        .unwrap();
        assert!(ack.ok, "{ack:?}");
        let after = hello(&agent).await;
        assert_eq!(after.id.as_deref(), Some("id1"));
        assert_eq!(after.proof, proof(&key(), "c"));
        assert_eq!(after.join, None);

        // The identity is on disk, and a second enrollment (a hijack) is refused.
        let saved = AgentConfig::load(&path).unwrap();
        assert_eq!((saved.id.as_deref(), saved.join), (Some("id1"), None));
        let again: Ack = serde_json::from_slice(
            &agent
                .handle(Request::Enroll {
                    id: "evil".into(),
                    key: "cd".repeat(32),
                })
                .await,
        )
        .unwrap();
        assert!(!again.ok);
        assert_eq!(AgentConfig::load(&path).unwrap().id.as_deref(), Some("id1"));
        // A key that is not 32 bytes of hex is refused too.
        let fresh = Agent::new(&path, AgentConfig::from_join(&code));
        let bad: Ack = serde_json::from_slice(
            &fresh
                .handle(Request::Enroll {
                    id: "x".into(),
                    key: "short".into(),
                })
                .await,
        )
        .unwrap();
        assert!(!bad.ok);
    }

    #[tokio::test]
    async fn a_speed_test_runs_in_the_background_and_is_followed_by_polling() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("main.toml"),
            "role = \"entry\"
mode = \"reverse\"
[tunnel]
transport = \"tcpmux\"
             listen = \"0.0.0.0:3080\"
token = \"a-secret-token-0123456789\"
             [[forward]]
listen = \"0.0.0.0:443\"
target = \"127.0.0.1:443\"
",
        )
        .unwrap();
        let mut config = AgentConfig::from_join(&JoinCode {
            p: "x:1".into(),
            t: "t".repeat(64),
            j: "j".into(),
            n: None,
            x: None,
            g: None,
            l: None,
        });
        config.kariz_dir = dir.path().to_path_buf();
        let agent = Agent::new(&dir.path().join("agent.toml"), config);
        let ask = |agent: &Arc<Agent>, request: Request| {
            let agent = agent.clone();
            async move { agent.handle(request).await }
        };
        let start = |name: &str| Request::SpeedtestStart {
            name: name.into(),
            seconds: 1,
            streams: 1,
            udp: false,
        };

        // A tunnel that is not there cannot be tested, and says so at once.
        let missing: SpeedStarted =
            serde_json::from_slice(&ask(&agent, start("nope")).await).unwrap();
        assert!(!missing.ok && missing.error.is_some());
        let unknown: SpeedPoll = serde_json::from_slice(
            &ask(
                &agent,
                Request::SpeedtestPoll {
                    id: "x".into(),
                    after: 0,
                },
            )
            .await,
        )
        .unwrap();
        assert!(!unknown.ok);

        // One that is there starts; its daemon is not running here, so it ends with why.
        let started: SpeedStarted =
            serde_json::from_slice(&ask(&agent, start("main")).await).unwrap();
        assert!(started.ok && !started.id.is_empty(), "{started:?}");
        let mut poll = SpeedPoll::default();
        for _ in 0..100 {
            poll = serde_json::from_slice(
                &ask(
                    &agent,
                    Request::SpeedtestPoll {
                        id: started.id.clone(),
                        after: 0,
                    },
                )
                .await,
            )
            .unwrap();
            if poll.done {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(poll.ok && poll.done, "{poll:?}");
        assert!(poll.error.is_some() && poll.report.is_none(), "{poll:?}");
        // A test can be told to stop (a finished one takes it quietly); an unknown one says so.
        let stopped: Ack = serde_json::from_slice(
            &ask(
                &agent,
                Request::SpeedtestStop {
                    id: started.id.clone(),
                },
            )
            .await,
        )
        .unwrap();
        assert!(stopped.ok, "{stopped:?}");
        let unknown: Ack = serde_json::from_slice(
            &ask(&agent, Request::SpeedtestStop { id: "nope".into() }).await,
        )
        .unwrap();
        assert!(!unknown.ok);
    }

    #[tokio::test]
    async fn health_and_tunnels_answer_as_json() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = AgentConfig::from_join(&JoinCode {
            p: "x:1".into(),
            t: "t".repeat(64),
            j: "j".into(),
            n: None,
            x: None,
            g: None,
            l: None,
        });
        config.kariz_dir = dir.path().to_path_buf();
        let agent = Agent::new(&dir.path().join("agent.toml"), config);
        let health: Health = serde_json::from_slice(&agent.handle(Request::Health).await).unwrap();
        let _ = health; // all None off Linux
        let tunnels: Vec<crate::wire::TunnelInfo> =
            serde_json::from_slice(&agent.handle(Request::Tunnels).await).unwrap();
        assert!(tunnels.is_empty());
    }
}
