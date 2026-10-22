//! The control socket: a local socket through which tools talk to the running daemon.
//! Both sides answer `status` (its counters, docs/status.md); the entry side also runs
//! `kariz speedtest` through its live sessions.
//!
//! Why a socket and not a second process that dials the exit itself: in reverse mode the
//! exit dials the entry, and the daemon owns the port it dials; and a test through the
//! daemon's own sessions measures exactly what users' traffic gets.
//!
//! Wire format, one request per connection:
//!
//! ```text
//! client -> daemon   status\n
//! daemon -> client   ---\n <the status, JSON> \n   or   ! error text \n
//!
//! client -> daemon   speedtest seconds=10 streams=4 udp=1 \n
//! daemon -> client   # progress text \n        (any number)
//!                    ---\n <the report, TOML>   or   ! error text \n
//!
//! client -> daemon   reload\n
//! daemon -> client   ---\n <the report, JSON> \n   or   ! error text \n
//! ```
//!
//! `reload` (2.10.0) makes the entry side read its config file again and apply the
//! `[[forward]]` rules (and `tuning.max_conns_per_ip` / `udp_max_flows`) without a
//! restart: unchanged rules keep their connections. A refusal (`! …`) means nothing was
//! applied: `restart needed: <section>` when something else in the file changed, `not an
//! entry` on the exit side, `unknown request` from a daemon older than 2.10.0.
//!
//! The socket is a Unix socket (Linux servers) that only its owner can open; on other
//! systems there is no control socket.

use std::future::Future;
use std::io;

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::{mpsc, Mutex};

use crate::channel::Channel;
use crate::proto::Open;
use crate::speedtest::{self, Options, Pipe, Report};
use crate::stats::{Stats, Status};

/// Longest request line the daemon reads.
const MAX_REQUEST: u64 = 1024;

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg.into())
}

/// `speedtest seconds=10 streams=4 udp=1`
pub fn format_request(options: &Options) -> String {
    format!(
        "speedtest seconds={} streams={} udp={}\n",
        options.seconds,
        options.streams,
        u8::from(options.udp)
    )
}

/// What a client asks for.
#[derive(Debug, PartialEq)]
enum Request {
    Status,
    Speedtest(Options),
    Reload,
}

/// What a reload did: the rules it added, removed and changed (by their listen
/// address), and the added ones whose port could not be bound (the rest stands).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReloadReport {
    #[serde(default)]
    pub added: Vec<String>,
    #[serde(default)]
    pub removed: Vec<String>,
    #[serde(default)]
    pub changed: Vec<String>,
    #[serde(default)]
    pub failed: Vec<ReloadFailure>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReloadFailure {
    pub listen: String,
    pub error: String,
}

impl std::fmt::Display for ReloadReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut parts = Vec::new();
        for (what, list) in [
            ("added", &self.added),
            ("removed", &self.removed),
            ("changed", &self.changed),
        ] {
            if !list.is_empty() {
                parts.push(format!("{what} {}", list.join(", ")));
            }
        }
        if parts.is_empty() {
            parts.push("nothing to change".into());
        }
        write!(f, "{}", parts.join("; "))?;
        for failure in &self.failed {
            write!(f, "; {} not bound: {}", failure.listen, failure.error)?;
        }
        Ok(())
    }
}

fn parse_request(line: &str) -> io::Result<Request> {
    let mut words = line.split_whitespace();
    match words.next() {
        Some("status") => {
            return match words.next() {
                None => Ok(Request::Status),
                Some(word) => Err(invalid(format!("status takes no settings ({word:?})"))),
            }
        }
        Some("reload") => {
            return match words.next() {
                None => Ok(Request::Reload),
                Some(word) => Err(invalid(format!("reload takes no settings ({word:?})"))),
            }
        }
        Some("speedtest") => {}
        _ => {
            return Err(invalid(
                "unknown request (this daemon knows `status`, `speedtest` and `reload`)",
            ))
        }
    }
    let mut options = Options::default();
    for word in words {
        let (key, value) = word
            .split_once('=')
            .ok_or_else(|| invalid(format!("bad setting {word:?}")))?;
        let number = || {
            value
                .parse::<u64>()
                .map_err(|_| invalid(format!("{key} needs a number")))
        };
        match key {
            "seconds" => options.seconds = number()?,
            "streams" => options.streams = number()? as usize,
            "udp" => options.udp = number()? != 0,
            _ => return Err(invalid(format!("unknown setting {key:?}"))),
        }
    }
    options.validate()?;
    Ok(Request::Speedtest(options))
}

/// A daemon without speed tests (the exit side) serves with `None::<NoOpen>`.
pub type NoOpen = fn(Bytes) -> std::future::Ready<io::Result<Channel>>;
/// A daemon without reloads (the exit side) serves with `None::<NoReload>`.
pub type NoReload = fn() -> std::future::Ready<io::Result<ReloadReport>>;

/// Serves one connection: reads the request and answers it. `status` reads `stats`. A
/// speed test runs through `open` (which opens a channel to the exit side for an
/// encoded open request; `None` on the exit side) and writes progress and the report
/// back; one test at a time (`busy`): a test uses the tunnel's bandwidth. `reload` runs
/// `reload` (`None` on the exit side) and answers with its report, or its refusal.
pub async fn handle<S, O, F, R, G>(
    stream: S,
    open: Option<&O>,
    reload: Option<&R>,
    busy: &Mutex<()>,
    stats: &Stats,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    O: Fn(Bytes) -> F,
    F: Future<Output = io::Result<Channel>> + Send,
    R: Fn() -> G,
    G: Future<Output = io::Result<ReloadReport>> + Send,
{
    let (reader, mut writer) = tokio::io::split(stream);
    let mut line = String::new();
    BufReader::new(reader.take(MAX_REQUEST))
        .read_line(&mut line)
        .await?;
    let options = match parse_request(&line) {
        Ok(Request::Speedtest(options)) => options,
        Ok(Request::Status) => {
            let doc = serde_json::to_string(&stats.snapshot()).map_err(io::Error::other)?;
            writer.write_all(format!("---\n{doc}\n").as_bytes()).await?;
            return writer.flush().await;
        }
        Ok(Request::Reload) => {
            let Some(reload) = reload else {
                return reply_error(
                    &mut writer,
                    "not an entry (only the entry side reloads its forward rules)",
                )
                .await;
            };
            return match reload().await {
                Ok(report) => {
                    let doc = serde_json::to_string(&report).map_err(io::Error::other)?;
                    writer.write_all(format!("---\n{doc}\n").as_bytes()).await?;
                    writer.flush().await
                }
                Err(e) => reply_error(&mut writer, &e.to_string()).await,
            };
        }
        Err(e) => return reply_error(&mut writer, &e.to_string()).await,
    };
    let Some(open) = open else {
        return reply_error(
            &mut writer,
            "run the speed test on the entry side (this is the exit side)",
        )
        .await;
    };
    let Ok(_running) = busy.try_lock() else {
        return reply_error(&mut writer, "another speed test is already running").await;
    };

    let opener = |command: &'static str| {
        let mut syn = Vec::new();
        Open::speedtest(command).encode(&mut syn);
        let opened = open(Bytes::from(syn));
        async move { opened.await.map(Pipe::from) }
    };
    let (progress_tx, mut progress_rx) = mpsc::unbounded_channel::<String>();
    let test = speedtest::run(opener, options, move |line| {
        let _ = progress_tx.send(line);
    });
    tokio::pin!(test);
    // A client that goes away ends the test: the write fails and `test` is dropped.
    let result = loop {
        tokio::select! {
            Some(line) = progress_rx.recv() => {
                writer.write_all(format!("# {line}\n").as_bytes()).await?;
            }
            result = &mut test => break result,
        }
    };
    while let Ok(line) = progress_rx.try_recv() {
        writer.write_all(format!("# {line}\n").as_bytes()).await?;
    }
    match result {
        Ok(report) => {
            let doc = toml::to_string(&report).map_err(io::Error::other)?;
            writer.write_all(format!("---\n{doc}").as_bytes()).await?;
            writer.flush().await
        }
        Err(e) => reply_error(&mut writer, &e.to_string()).await,
    }
}

async fn reply_error<W: AsyncWrite + Unpin>(writer: &mut W, text: &str) -> io::Result<()> {
    writer
        .write_all(format!("! {}\n", text.replace('\n', " ")).as_bytes())
        .await?;
    writer.flush().await
}

/// Asks a daemon for a speed test over `stream`; `on_progress` gets each progress line.
pub async fn request<S>(
    stream: S,
    options: Options,
    mut on_progress: impl FnMut(&str),
) -> io::Result<Report>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (reader, mut writer) = tokio::io::split(stream);
    writer
        .write_all(format_request(&options).as_bytes())
        .await?;
    writer.flush().await?;
    let mut lines = BufReader::new(reader).lines();
    while let Some(line) = lines.next_line().await? {
        if let Some(progress) = line.strip_prefix("# ") {
            on_progress(progress);
        } else if let Some(error) = line.strip_prefix("! ") {
            return Err(io::Error::other(error.to_string()));
        } else if line == "---" {
            let mut doc = String::new();
            while let Some(rest) = lines.next_line().await? {
                doc.push_str(&rest);
                doc.push('\n');
            }
            return toml::from_str(&doc)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()));
        }
    }
    Err(io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "the daemon closed the connection before the test finished",
    ))
}

/// Asks a daemon for its status over `stream`.
pub async fn status<S>(stream: S) -> io::Result<Status>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    one_line_json(stream, b"status\n").await
}

/// Asks the daemon to read its config file again and apply its forward rules (see the
/// module doc). A refusal comes back as an error whose text starts with the daemon's
/// reason (`restart needed: …`, `not an entry`, `unknown request …`).
pub async fn reload<S>(stream: S) -> io::Result<ReloadReport>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    one_line_json(stream, b"reload\n").await
}

/// A request answered with `---` and one line of JSON, or `! error`.
async fn one_line_json<S, T>(stream: S, request: &[u8]) -> io::Result<T>
where
    S: AsyncRead + AsyncWrite + Unpin,
    T: serde::de::DeserializeOwned,
{
    let (reader, mut writer) = tokio::io::split(stream);
    writer.write_all(request).await?;
    writer.flush().await?;
    let mut lines = BufReader::new(reader).lines();
    while let Some(line) = lines.next_line().await? {
        if let Some(error) = line.strip_prefix("! ") {
            return Err(io::Error::other(error.to_string()));
        }
        if line == "---" {
            let doc = lines.next_line().await?.unwrap_or_default();
            return serde_json::from_str(&doc)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()));
        }
    }
    Err(io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "the daemon closed the connection without an answer",
    ))
}

#[cfg(unix)]
pub use unix::{connect, serve};

#[cfg(unix)]
mod unix {
    use std::io;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    use bytes::Bytes;
    use tokio::net::{UnixListener, UnixStream};
    use tokio::sync::Mutex;
    use tracing::{info, warn};

    use super::{handle, Channel, Future, ReloadReport, Stats};

    /// Connects to a daemon's control socket.
    pub async fn connect(path: &Path) -> io::Result<UnixStream> {
        UnixStream::connect(path).await.map_err(|e| {
            let hint = match e.kind() {
                io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused => {
                    ": is this tunnel running?"
                }
                io::ErrorKind::PermissionDenied => ": run it as the user that runs Kariz",
                _ => "",
            };
            io::Error::new(
                e.kind(),
                format!(
                    "cannot reach the control socket {}: {e}{hint}",
                    path.display()
                ),
            )
        })
    }

    /// Runs the control socket for the daemon's whole life. It never returns: a problem
    /// with it (an unwritable directory) is logged, and the tunnel goes on without it.
    /// `open`: how speed tests reach the exit side; `reload`: how the entry applies its
    /// config file again; both `None` on the exit side.
    pub async fn serve<O, F, R, G>(
        path: PathBuf,
        open: Option<O>,
        reload: Option<R>,
        stats: Arc<Stats>,
    ) -> anyhow::Result<()>
    where
        O: Fn(Bytes) -> F + Send + Sync + 'static,
        F: Future<Output = io::Result<Channel>> + Send + 'static,
        R: Fn() -> G + Send + Sync + 'static,
        G: Future<Output = io::Result<ReloadReport>> + Send + 'static,
    {
        if let Err(e) = listen(&path, open, reload, stats).await {
            warn!(socket = %path.display(), error = %e, "no control socket (kariz status, speedtest and reload will not work)");
        }
        std::future::pending::<()>().await;
        Ok(())
    }

    async fn listen<O, F, R, G>(
        path: &Path,
        open: Option<O>,
        reload: Option<R>,
        stats: Arc<Stats>,
    ) -> io::Result<()>
    where
        O: Fn(Bytes) -> F + Send + Sync + 'static,
        F: Future<Output = io::Result<Channel>> + Send + 'static,
        R: Fn() -> G + Send + Sync + 'static,
        G: Future<Output = io::Result<ReloadReport>> + Send + 'static,
    {
        if UnixStream::connect(path).await.is_ok() {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "another Kariz is answering on this socket",
            ));
        }
        // Made private before it gets its name, so it is never open to others.
        let mut temporary = path.as_os_str().to_owned();
        temporary.push(".new");
        let temporary = PathBuf::from(temporary);
        let _ = std::fs::remove_file(&temporary);
        let listener = UnixListener::bind(&temporary)?;
        std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600))?;
        std::fs::rename(&temporary, path)?;
        info!(socket = %path.display(), "control socket ready");

        let open = Arc::new(open);
        let reload = Arc::new(reload);
        let busy = Arc::new(Mutex::new(()));
        loop {
            let (connection, _) = listener.accept().await?;
            let (open, reload, busy, stats) =
                (open.clone(), reload.clone(), busy.clone(), stats.clone());
            tokio::spawn(async move {
                let _ = handle(
                    connection,
                    (*open).as_ref(),
                    (*reload).as_ref(),
                    &busy,
                    &stats,
                )
                .await;
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use super::*;
    use crate::session::SessionStream;
    use crate::speedtest::tests::tunnel;

    /// The counters of a side with one forward rule.
    fn stats(role: &str) -> Stats {
        let forward = if role == "entry" {
            "[[forward]]\nlisten = \"127.0.0.1:1\"\ntarget = \"127.0.0.1:2\""
        } else {
            ""
        };
        let text = format!(
            "role = \"{role}\"\nmode = \"direct\"\n{forward}\n[tunnel]\ntransport = \"tcpmux\"\n\
             {}\ntoken = \"0123456789abcdef0123\"\n",
            if role == "entry" {
                "remote = \"127.0.0.1:3\""
            } else {
                "listen = \"127.0.0.1:3\""
            }
        );
        Arc::into_inner(Stats::new(&crate::config::Config::parse(&text).unwrap())).unwrap()
    }

    #[tokio::test]
    async fn status_answers_with_the_counters() {
        let stats = Arc::new(stats("entry"));
        stats.forwards()[0].traffic.add_up(1234);
        let _connection = stats.forwards()[0].tcp_connection();
        let (client_end, daemon_end) = tokio::io::duplex(1 << 16);
        let s = stats.clone();
        let busy = Mutex::new(());
        tokio::spawn(async move {
            handle(daemon_end, Some(&opener()), None::<&NoReload>, &busy, &s).await
        });
        let status = status(client_end).await.unwrap();
        assert_eq!(status.role, "entry");
        assert_eq!(status.forwards[0].bytes_up, 1234);
        assert_eq!(status.totals.tcp_open, 1);
        assert_eq!(status.kariz, env!("CARGO_PKG_VERSION"));
    }

    #[tokio::test]
    async fn the_exit_answers_status_but_no_speed_test() {
        let stats = Arc::new(stats("exit"));
        let ask = |line: &'static str| {
            let stats = stats.clone();
            async move {
                let (mut client, daemon_end) = tokio::io::duplex(1 << 16);
                let busy = Mutex::new(());
                tokio::spawn(async move {
                    handle(
                        daemon_end,
                        None::<&NoOpen>,
                        None::<&NoReload>,
                        &busy,
                        &stats,
                    )
                    .await
                });
                client.write_all(line.as_bytes()).await.unwrap();
                let mut answer = String::new();
                client.read_to_string(&mut answer).await.unwrap();
                answer
            }
        };
        let answer = ask("status\n").await;
        let doc = answer.strip_prefix("---\n").expect(&answer);
        let status: Status = serde_json::from_str(doc.trim()).unwrap();
        assert_eq!(status.role, "exit");
        assert!(status.exit.is_some() && status.forwards.is_empty());
        let refused = ask("speedtest\n").await;
        assert!(
            refused.starts_with("! run the speed test on the entry side"),
            "{refused}"
        );
        let refused = ask("reload\n").await;
        assert!(refused.starts_with("! not an entry"), "{refused}");
    }

    /// `reload` runs the daemon's reloader and answers with its report, or its refusal.
    #[tokio::test]
    async fn reload_answers_with_the_report_or_the_refusal() {
        let stats = Arc::new(stats("entry"));
        let report = ReloadReport {
            added: vec!["0.0.0.0:81".into()],
            removed: vec![],
            changed: vec!["0.0.0.0:80".into()],
            failed: vec![ReloadFailure {
                listen: "0.0.0.0:82".into(),
                error: "address in use".into(),
            }],
        };
        let (client_end, daemon_end) = tokio::io::duplex(1 << 16);
        let (s, r) = (stats.clone(), report.clone());
        tokio::spawn(async move {
            let reloader = || std::future::ready(Ok(r.clone()));
            let busy = Mutex::new(());
            handle(daemon_end, Some(&opener()), Some(&reloader), &busy, &s).await
        });
        assert_eq!(reload(client_end).await.unwrap(), report);
        assert_eq!(
            report.to_string(),
            "added 0.0.0.0:81; changed 0.0.0.0:80; 0.0.0.0:82 not bound: address in use"
        );
        let (client_end, daemon_end) = tokio::io::duplex(1 << 16);
        let s = stats.clone();
        tokio::spawn(async move {
            let reloader = || {
                std::future::ready(Err::<ReloadReport, _>(io::Error::other(
                    "restart needed: tunnel changed",
                )))
            };
            let busy = Mutex::new(());
            handle(daemon_end, Some(&opener()), Some(&reloader), &busy, &s).await
        });
        let err = reload(client_end).await.unwrap_err();
        assert_eq!(err.to_string(), "restart needed: tunnel changed");
    }

    /// Opens channels on the in-memory tunnel of the speed test's tests.
    fn opener() -> impl Fn(Bytes) -> std::future::Ready<io::Result<Channel>> + Send + Sync {
        let client = tunnel();
        move |syn| {
            std::future::ready(
                client
                    .open(syn)
                    .map(|s| Channel::Stream(SessionStream::Kmux(s))),
            )
        }
    }

    #[test]
    fn requests_round_trip_and_bad_ones_are_refused() {
        let options = Options {
            seconds: 7,
            streams: 3,
            udp: false,
        };
        assert_eq!(
            parse_request(&format_request(&options)).unwrap(),
            Request::Speedtest(options)
        );
        assert_eq!(
            parse_request("speedtest\n").unwrap(),
            Request::Speedtest(Options::default())
        );
        assert_eq!(parse_request("status\n").unwrap(), Request::Status);
        assert_eq!(parse_request("reload\n").unwrap(), Request::Reload);
        for bad in [
            "",
            "rm -rf /",
            "speedtest seconds",
            "speedtest seconds=x",
            "speedtest seconds=0",
            "speedtest streams=99",
            "speedtest color=red",
            "status now",
            "reload now",
        ] {
            assert!(parse_request(bad).is_err(), "{bad:?}");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_client_gets_progress_and_the_report() {
        let (client_end, daemon_end) = tokio::io::duplex(1 << 16);
        let (open, busy, stats) = (opener(), Mutex::new(()), stats("entry"));
        let daemon = tokio::spawn(async move {
            handle(daemon_end, Some(&open), None::<&NoReload>, &busy, &stats).await
        });
        let options = Options {
            seconds: 1,
            streams: 1,
            udp: true,
        };
        let mut lines = Vec::new();
        let report = request(client_end, options, |l| lines.push(l.to_string()))
            .await
            .unwrap();
        daemon.await.unwrap().unwrap();
        assert!(
            report.download.mbps > 0.0 && report.upload.mbps > 0.0,
            "{report:?}"
        );
        assert!(report.udp.is_some());
        assert!(lines.iter().any(|l| l.starts_with("latency")), "{lines:?}");
        assert!(lines.iter().any(|l| l.contains("Mbit/s")), "{lines:?}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn only_one_test_runs_at_a_time_and_bad_requests_get_an_error() {
        let open = Arc::new(opener());
        let busy = Arc::new(Mutex::new(()));
        let stats = Arc::new(stats("entry"));
        let start = |line: &'static str| {
            let (mut client, daemon_end) = tokio::io::duplex(1 << 16);
            let (open, busy, stats) = (open.clone(), busy.clone(), stats.clone());
            tokio::spawn(async move {
                handle(daemon_end, Some(&*open), None::<&NoReload>, &busy, &stats).await
            });
            async move {
                client.write_all(line.as_bytes()).await.unwrap();
                let mut answer = String::new();
                client.read_to_string(&mut answer).await.unwrap();
                answer
            }
        };
        let first = tokio::spawn(start("speedtest seconds=1 streams=1 udp=0\n"));
        tokio::time::sleep(Duration::from_millis(400)).await;
        let second = start("speedtest seconds=1\n").await;
        assert!(second.starts_with("! another speed test"), "{second}");
        let first = first.await.unwrap();
        assert!(first.contains("---\n"), "{first}");
        let bad = start("speedtest seconds=0\n").await;
        assert!(bad.starts_with("! seconds must be"), "{bad}");
        let unknown = start("shutdown\n").await;
        assert!(unknown.starts_with("! unknown request"), "{unknown}");
    }
}
