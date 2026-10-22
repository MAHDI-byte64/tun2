//! A terminal to a server, in the browser. The Logs page opens one to any server whose
//! agent allows it (`terminal = true` in `agent.toml`; `panel.toml` for the panel's own
//! server): the agent opens a pseudo-terminal running the login shell of the user it runs
//! as (root, as installed), and the panel bridges the browser's WebSocket to it over the
//! agent's link, on a stream of its own ([`Request::Shell`]) that stays open as long as the
//! terminal does. It is off on every server until switched on there: it is a root shell, so
//! the choice is the server's, not the panel's. Every open and close goes to the audit log
//! with who, where and for how long; one terminal per browser session per server; a
//! terminal quiet for fifteen minutes ends.
//!
//! On the stream, both ways: frames of a kind byte, a four-byte big-endian length and the
//! bytes. The kinds are [`DATA`], [`RESIZE`] (`cols` and `rows`, two bytes each), [`EXIT`]
//! (the shell's exit code, four bytes; the stream ends after it) and [`ACK`] (the agent's
//! answer to the open: an [`Ack`] as JSON, sent first). An agent older than the terminal
//! answers the open with a plain JSON `Ack` (`unknown request`) and finishes the stream.

use std::collections::HashSet;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, Extension, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use kariz::session::SessionStream;
use serde::Deserialize;
use serde_json::json;
use tokio::sync::mpsc;
use tracing::{debug, info};

use crate::http::AppState;
use crate::wire::Ack;

pub const DATA: u8 = 0;
pub const RESIZE: u8 = 1;
pub const EXIT: u8 = 2;
pub const ACK: u8 = 3;
/// The most bytes one frame carries.
const MAX_FRAME: usize = 1024 * 1024;
/// A terminal nobody typed in or that printed nothing for this long ends.
const IDLE: Duration = Duration::from_secs(15 * 60);
/// How long the panel waits for the agent's answer to the open.
const OPEN_WAIT: Duration = Duration::from_secs(15);

/// One frame, ready to send.
pub fn frame(kind: u8, payload: &[u8]) -> Bytes {
    let mut out = BytesMut::with_capacity(5 + payload.len());
    out.put_u8(kind);
    out.put_u32(payload.len() as u32);
    out.put_slice(payload);
    out.freeze()
}

/// A frame whose length is past [`MAX_FRAME`]: not one of ours.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BadFrame;

/// Splits what arrives into frames (a chunk may hold several, or part of one).
#[derive(Default)]
pub struct Frames {
    buf: BytesMut,
}

impl Frames {
    pub fn push(&mut self, chunk: &[u8]) {
        self.buf.extend_from_slice(chunk);
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// The next whole frame; `Err` for one that is too big to be honest.
    pub fn take_frame(&mut self) -> Result<Option<(u8, Bytes)>, BadFrame> {
        if self.buf.len() < 5 {
            return Ok(None);
        }
        let len = u32::from_be_bytes([self.buf[1], self.buf[2], self.buf[3], self.buf[4]]) as usize;
        if len > MAX_FRAME {
            return Err(BadFrame);
        }
        if self.buf.len() < 5 + len {
            return Ok(None);
        }
        let kind = self.buf[0];
        self.buf.advance(5);
        Ok(Some((kind, self.buf.split_to(len).freeze())))
    }
}

/// What carries the frames: the agent's link stream, or a pair of channels inside the
/// panel for its own server.
pub trait Link: Send + Sync + 'static {
    fn send(&self, data: Bytes) -> impl std::future::Future<Output = std::io::Result<()>> + Send;
    fn recv(&self) -> impl std::future::Future<Output = std::io::Result<Option<Bytes>>> + Send;
    fn finish(&self);
}

impl Link for SessionStream {
    async fn send(&self, data: Bytes) -> std::io::Result<()> {
        SessionStream::send(self, data).await
    }

    async fn recv(&self) -> std::io::Result<Option<Bytes>> {
        SessionStream::recv(self).await
    }

    fn finish(&self) {
        let _ = SessionStream::finish(self);
    }
}

/// One end of an in-process pair ([`pipe`]).
pub struct Pipe {
    tx: Mutex<Option<mpsc::Sender<Bytes>>>,
    rx: tokio::sync::Mutex<mpsc::Receiver<Bytes>>,
}

pub fn pipe() -> (Pipe, Pipe) {
    let (a_tx, a_rx) = mpsc::channel(64);
    let (b_tx, b_rx) = mpsc::channel(64);
    (
        Pipe {
            tx: Mutex::new(Some(a_tx)),
            rx: tokio::sync::Mutex::new(b_rx),
        },
        Pipe {
            tx: Mutex::new(Some(b_tx)),
            rx: tokio::sync::Mutex::new(a_rx),
        },
    )
}

impl Link for Pipe {
    async fn send(&self, data: Bytes) -> std::io::Result<()> {
        let tx = self.tx.lock().unwrap_or_else(|e| e.into_inner()).clone();
        match tx {
            Some(tx) => tx
                .send(data)
                .await
                .map_err(|_| std::io::Error::from(std::io::ErrorKind::BrokenPipe)),
            None => Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe)),
        }
    }

    async fn recv(&self) -> std::io::Result<Option<Bytes>> {
        Ok(self.rx.lock().await.recv().await)
    }

    fn finish(&self) {
        self.tx.lock().unwrap_or_else(|e| e.into_inner()).take();
    }
}

// ---- the agent's side: a pseudo-terminal and the shell ----

#[cfg(unix)]
mod pty {
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::process::Stdio;

    use tokio::io::unix::AsyncFd;

    /// A pseudo-terminal with the login shell on its far side.
    pub struct Pty {
        master: AsyncFd<OwnedFd>,
        child: tokio::process::Child,
    }

    /// The shell to run and its arguments: the user's (`$SHELL`), else bash, else sh.
    fn shell() -> (String, &'static [&'static str]) {
        let own = std::env::var("SHELL").ok().filter(|s| !s.is_empty());
        let path = own.unwrap_or_else(|| {
            if std::path::Path::new("/bin/bash").exists() {
                "/bin/bash".to_owned()
            } else {
                "/bin/sh".to_owned()
            }
        });
        let args: &[&str] = if path.ends_with("bash") || path.ends_with("zsh") {
            &["-l"]
        } else {
            &["-i"]
        };
        (path, args)
    }

    fn size(cols: u16, rows: u16) -> libc::winsize {
        libc::winsize {
            ws_row: rows.max(1),
            ws_col: cols.max(1),
            ws_xpixel: 0,
            ws_ypixel: 0,
        }
    }

    impl Pty {
        pub fn open(cols: u16, rows: u16) -> io::Result<Self> {
            let (mut master, mut slave): (libc::c_int, libc::c_int) = (-1, -1);
            let window = size(cols, rows);
            // SAFETY: openpty fills the two descriptors; the name buffer is not asked for.
            let rc = unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    &window,
                )
            };
            if rc != 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: both are fresh descriptors this process owns.
            let master = unsafe { OwnedFd::from_raw_fd(master) };
            let slave = unsafe { OwnedFd::from_raw_fd(slave) };
            // SAFETY: fcntl on a descriptor this process owns.
            unsafe {
                libc::fcntl(master.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC);
                let flags = libc::fcntl(master.as_raw_fd(), libc::F_GETFL);
                libc::fcntl(master.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK);
            }
            let (program, args) = shell();
            let mut command = tokio::process::Command::new(&program);
            command
                .args(args)
                .env("TERM", "xterm-256color")
                .env("COLORTERM", "truecolor")
                .stdin(Stdio::from(slave.try_clone()?))
                .stdout(Stdio::from(slave.try_clone()?))
                .stderr(Stdio::from(slave))
                .kill_on_drop(true);
            if std::env::var_os("LANG").is_none() {
                command.env("LANG", "C.UTF-8");
            }
            // SAFETY: only async-signal-safe calls between fork and exec: a new session,
            // and the terminal (now standard input) made its controlling one.
            unsafe {
                command.pre_exec(|| {
                    if libc::setsid() < 0 {
                        return Err(io::Error::last_os_error());
                    }
                    if libc::ioctl(0, libc::TIOCSCTTY as _, 0) < 0 {
                        return Err(io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            let child = command.spawn()?;
            Ok(Self {
                master: AsyncFd::new(master)?,
                child,
            })
        }

        /// What the shell printed; 0 once it is gone.
        pub async fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
            loop {
                let mut ready = self.master.readable().await?;
                let fd = self.master.as_raw_fd();
                match ready.try_io(|_| {
                    // SAFETY: a read into a buffer of the given length.
                    let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
                    if n < 0 {
                        Err(io::Error::last_os_error())
                    } else {
                        Ok(n as usize)
                    }
                }) {
                    // EIO: the slave side is closed, the shell has gone.
                    Ok(Err(e)) if e.raw_os_error() == Some(libc::EIO) => return Ok(0),
                    Ok(result) => return result,
                    Err(_would_block) => continue,
                }
            }
        }

        /// What was typed, to the shell.
        pub async fn write_all(&self, mut data: &[u8]) -> io::Result<()> {
            while !data.is_empty() {
                let mut ready = self.master.writable().await?;
                let fd = self.master.as_raw_fd();
                match ready.try_io(|_| {
                    // SAFETY: a write from a buffer of the given length.
                    let n = unsafe { libc::write(fd, data.as_ptr().cast(), data.len()) };
                    if n < 0 {
                        Err(io::Error::last_os_error())
                    } else {
                        Ok(n as usize)
                    }
                }) {
                    Ok(Ok(n)) => data = &data[n..],
                    Ok(Err(e)) => return Err(e),
                    Err(_would_block) => continue,
                }
            }
            Ok(())
        }

        pub fn resize(&self, cols: u16, rows: u16) {
            let window = size(cols, rows);
            // SAFETY: an ioctl with the matching argument type.
            unsafe {
                libc::ioctl(self.master.as_raw_fd(), libc::TIOCSWINSZ, &window);
            }
        }

        /// Ends the shell (if it has not ended itself) and says how it went.
        pub async fn end(mut self) -> i32 {
            if let Ok(Some(status)) = self.child.try_wait() {
                return status.code().unwrap_or(-1);
            }
            let _ = self.child.start_kill();
            match tokio::time::timeout(std::time::Duration::from_secs(3), self.child.wait()).await {
                Ok(Ok(status)) => status.code().unwrap_or(-1),
                _ => -1,
            }
        }
    }
}

/// Serves one terminal on `link`, the agent's side: the answer to the open, then the bytes
/// both ways until the browser lets go, the shell ends, or nothing happens for a while.
pub async fn serve_stream<L: Link>(link: L, cols: u16, rows: u16, allowed: bool) {
    let refuse = |error: &str| {
        frame(
            ACK,
            &serde_json::to_vec(&Ack {
                ok: false,
                error: Some(error.to_owned()),
            })
            .unwrap_or_default(),
        )
    };
    if !allowed {
        let _ = link.send(refuse("terminal_off")).await;
        link.finish();
        return;
    }
    #[cfg(not(unix))]
    {
        let _ = (cols, rows);
        let _ = link.send(refuse("no terminal on this platform")).await;
        link.finish();
    }
    #[cfg(unix)]
    {
        let pty = match pty::Pty::open(cols, rows) {
            Ok(p) => p,
            Err(e) => {
                let _ = link
                    .send(refuse(&format!("cannot open a terminal: {e}")))
                    .await;
                link.finish();
                return;
            }
        };
        let ok = serde_json::to_vec(&Ack {
            ok: true,
            error: None,
        })
        .unwrap_or_default();
        if link.send(frame(ACK, &ok)).await.is_err() {
            pty.end().await;
            return;
        }
        info!("a terminal was opened");
        let mut buf = vec![0u8; 16 * 1024];
        let mut frames = Frames::default();
        let mut deadline = tokio::time::Instant::now() + IDLE;
        let mut why = "closed";
        loop {
            tokio::select! {
                read = pty.read(&mut buf) => match read {
                    Ok(0) | Err(_) => {
                        why = "the shell ended";
                        break;
                    }
                    Ok(n) => {
                        if link.send(frame(DATA, &buf[..n])).await.is_err() {
                            break;
                        }
                    }
                },
                chunk = link.recv() => match chunk {
                    Ok(Some(chunk)) => {
                        frames.push(&chunk);
                        loop {
                            match frames.take_frame() {
                                Ok(Some((DATA, data))) => {
                                    if pty.write_all(&data).await.is_err() {
                                        break;
                                    }
                                }
                                Ok(Some((RESIZE, size))) if size.len() >= 4 => {
                                    pty.resize(
                                        u16::from_be_bytes([size[0], size[1]]),
                                        u16::from_be_bytes([size[2], size[3]]),
                                    );
                                }
                                Ok(Some(_)) => {}
                                Ok(None) => break,
                                Err(BadFrame) => {
                                    why = "a bad frame";
                                    break;
                                }
                            }
                        }
                        if why == "a bad frame" {
                            break;
                        }
                    }
                    _ => break,
                },
                _ = tokio::time::sleep_until(deadline) => {
                    why = "idle";
                    break;
                }
            }
            deadline = tokio::time::Instant::now() + IDLE;
        }
        let code = pty.end().await;
        let _ = link.send(frame(EXIT, &code.to_be_bytes())).await;
        link.finish();
        info!(why, code, "a terminal was closed");
    }
}

// ---- the panel's side: the WebSocket ----

type Peer = Option<Extension<ConnectInfo<std::net::SocketAddr>>>;

/// The terminals open now, as `SESSION:SERVER`: one per browser session per server.
static OPEN: Mutex<Option<HashSet<String>>> = Mutex::new(None);

struct OpenGuard(String);

impl Drop for OpenGuard {
    fn drop(&mut self) {
        if let Some(set) = OPEN.lock().unwrap_or_else(|e| e.into_inner()).as_mut() {
            set.remove(&self.0);
        }
    }
}

fn take(key: &str) -> Option<OpenGuard> {
    let mut guard = OPEN.lock().unwrap_or_else(|e| e.into_inner());
    let set = guard.get_or_insert_with(HashSet::new);
    set.insert(key.to_owned())
        .then(|| OpenGuard(key.to_owned()))
}

#[derive(Deserialize)]
pub struct TerminalQuery {
    server: String,
    csrf: String,
    #[serde(default = "default_cols")]
    cols: u16,
    #[serde(default = "default_rows")]
    rows: u16,
}

fn default_cols() -> u16 {
    80
}

fn default_rows() -> u16 {
    24
}

/// `GET /{secret}/api/terminal?server=ID&csrf=…&cols=&rows=`, upgraded to a WebSocket:
/// binary frames are the terminal's bytes both ways; a text frame from the browser is
/// `{"resize":[cols,rows]}`; the panel's text frames are `{"ok":true}` once the shell is
/// there, `{"error":"…"}` when it is not (`terminal_off`, `unknown request` from an older
/// agent, `busy`, `not connected`), and `{"exit":N}` when the shell ends.
pub async fn open(
    State(state): State<AppState>,
    peer: Peer,
    headers: HeaderMap,
    Query(query): Query<TerminalQuery>,
    ws: WebSocketUpgrade,
) -> Response {
    let me = match crate::api::authenticate(&state, &headers, false) {
        Ok(s) => s,
        Err(r) => return r,
    };
    if query.csrf != me.csrf {
        return (StatusCode::FORBIDDEN, "csrf").into_response();
    }
    let key = format!("{}:{}", me.id, query.server);
    let Some(guard) = take(&key) else {
        return (StatusCode::CONFLICT, "busy").into_response();
    };
    let ip = peer.as_ref().map_or_else(
        || "unknown".to_owned(),
        |Extension(ConnectInfo(a))| a.ip().to_string(),
    );
    let who = format!("session {}", me.id);
    ws.on_upgrade(move |socket| async move {
        let _guard = guard;
        let started = Instant::now();
        let _ = state.db.audit(
            &who,
            Some(&ip),
            &format!("opened a terminal to server {}", query.server),
        );
        let outcome = match state
            .hub
            .open_terminal(&query.server, query.cols, query.rows)
            .await
        {
            Ok(Backend::Remote(stream)) => bridge(socket, stream).await,
            Ok(Backend::Local(pipe)) => bridge(socket, pipe).await,
            Err(e) => {
                let mut socket = socket;
                let _ = socket
                    .send(Message::Text(
                        json!({ "error": format!("{e:#}") }).to_string().into(),
                    ))
                    .await;
                format!("{e:#}")
            }
        };
        let _ = state.db.audit(
            &who,
            Some(&ip),
            &format!(
                "closed the terminal to server {} after {} s ({outcome})",
                query.server,
                started.elapsed().as_secs()
            ),
        );
    })
}

/// Where a terminal's frames go: the agent's stream, or the panel's own server in process.
pub enum Backend {
    Remote(SessionStream),
    Local(Pipe),
}

/// Bridges the browser to the agent's side until either lets go. What happened, for the
/// audit log.
async fn bridge<L: Link>(mut socket: WebSocket, link: L) -> String {
    let mut frames = Frames::default();
    // The agent's answer first: a framed Ack, or an older agent's bare one.
    let answer: Result<(), String> = loop {
        match tokio::time::timeout(OPEN_WAIT, link.recv()).await {
            Ok(Ok(Some(chunk))) => {
                if frames.is_empty() && chunk.first() == Some(&b'{') {
                    break Err(serde_json::from_slice::<Ack>(&chunk)
                        .ok()
                        .and_then(|a| a.error)
                        .unwrap_or_else(|| "unknown request".into()));
                }
                frames.push(&chunk);
                match frames.take_frame() {
                    Ok(Some((ACK, payload))) => {
                        break match serde_json::from_slice::<Ack>(&payload) {
                            Ok(Ack { ok: true, .. }) => Ok(()),
                            Ok(Ack { error, .. }) => Err(error.unwrap_or_else(|| "refused".into())),
                            Err(_) => Err("the server's answer was not understood".into()),
                        };
                    }
                    Ok(Some(_)) | Err(BadFrame) => {
                        break Err("the server's answer was not understood".into())
                    }
                    Ok(None) => {}
                }
            }
            Ok(Ok(None)) => break Err("unknown request".into()),
            Ok(Err(e)) => break Err(format!("the link failed: {e}")),
            Err(_) => break Err("the server did not answer".into()),
        }
    };
    if let Err(error) = answer {
        let _ = socket
            .send(Message::Text(json!({ "error": error }).to_string().into()))
            .await;
        link.finish();
        let _ = socket.send(Message::Close(None)).await;
        return error;
    }
    let _ = socket
        .send(Message::Text(json!({ "ok": true }).to_string().into()))
        .await;
    let mut outcome = "closed by the browser".to_owned();
    'run: loop {
        tokio::select! {
            message = socket.recv() => match message {
                Some(Ok(Message::Binary(data))) => {
                    if link.send(frame(DATA, &data)).await.is_err() {
                        outcome = "the link ended".into();
                        break;
                    }
                }
                Some(Ok(Message::Text(text))) => {
                    if let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) {
                        if let Some(size) = value.get("resize").and_then(|r| r.as_array()) {
                            let cols = size.first().and_then(|v| v.as_u64()).unwrap_or(80).min(500) as u16;
                            let rows = size.get(1).and_then(|v| v.as_u64()).unwrap_or(24).min(200) as u16;
                            let mut payload = Vec::with_capacity(4);
                            payload.extend_from_slice(&cols.to_be_bytes());
                            payload.extend_from_slice(&rows.to_be_bytes());
                            let _ = link.send(frame(RESIZE, &payload)).await;
                        }
                    }
                }
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                Some(Ok(Message::Close(_))) | None => break,
                Some(Err(e)) => {
                    debug!(error = %e, "the terminal's websocket failed");
                    break;
                }
            },
            chunk = link.recv() => match chunk {
                Ok(Some(chunk)) => {
                    frames.push(&chunk);
                    loop {
                        match frames.take_frame() {
                            Ok(Some((DATA, data))) => {
                                if socket.send(Message::Binary(data)).await.is_err() {
                                    break 'run;
                                }
                            }
                            Ok(Some((EXIT, code))) => {
                                let code = if code.len() >= 4 {
                                    i32::from_be_bytes([code[0], code[1], code[2], code[3]])
                                } else {
                                    -1
                                };
                                let _ = socket
                                    .send(Message::Text(json!({ "exit": code }).to_string().into()))
                                    .await;
                                outcome = format!("the shell ended with code {code}");
                                break 'run;
                            }
                            Ok(Some(_)) => {}
                            Ok(None) => break,
                            Err(BadFrame) => {
                                outcome = "a bad frame from the server".into();
                                break 'run;
                            }
                        }
                    }
                }
                _ => {
                    outcome = "the link ended".into();
                    break;
                }
            },
        }
    }
    link.finish();
    let _ = socket.send(Message::Close(None)).await;
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_are_cut_from_any_chunking() {
        let a = frame(DATA, b"hello");
        let b = frame(RESIZE, &[0, 120, 0, 40]);
        let all = [a.as_ref(), b.as_ref()].concat();
        let mut frames = Frames::default();
        frames.push(&all[..3]);
        assert_eq!(frames.take_frame(), Ok(None));
        frames.push(&all[3..12]);
        assert_eq!(
            frames.take_frame(),
            Ok(Some((DATA, Bytes::from_static(b"hello"))))
        );
        assert_eq!(frames.take_frame(), Ok(None));
        frames.push(&all[12..]);
        assert_eq!(
            frames.take_frame(),
            Ok(Some((RESIZE, Bytes::from_static(&[0, 120, 0, 40]))))
        );
        assert!(frames.is_empty());
        // A length past the limit is refused, not waited for.
        let mut huge = Frames::default();
        huge.push(&[DATA, 0xff, 0xff, 0xff, 0xff]);
        assert_eq!(huge.take_frame(), Err(BadFrame));
    }

    #[tokio::test]
    async fn a_pipe_carries_frames_both_ways_and_ends_when_finished() {
        let (a, b) = pipe();
        a.send(frame(DATA, b"x")).await.unwrap();
        assert_eq!(b.recv().await.unwrap().unwrap(), frame(DATA, b"x"));
        b.send(Bytes::from_static(b"y")).await.unwrap();
        assert_eq!(a.recv().await.unwrap().unwrap(), Bytes::from_static(b"y"));
        a.finish();
        assert!(a.send(Bytes::new()).await.is_err());
        assert_eq!(b.recv().await.unwrap(), None);
    }

    #[tokio::test]
    async fn a_terminal_that_is_off_is_refused_over_the_pipe() {
        let (mine, theirs) = pipe();
        tokio::spawn(serve_stream(theirs, 80, 24, false));
        let chunk = mine.recv().await.unwrap().unwrap();
        let mut frames = Frames::default();
        frames.push(&chunk);
        let (kind, payload) = frames.take_frame().unwrap().unwrap();
        assert_eq!(kind, ACK);
        let ack: Ack = serde_json::from_slice(&payload).unwrap();
        assert_eq!(ack.error.as_deref(), Some("terminal_off"));
        assert_eq!(mine.recv().await.unwrap(), None, "finished");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_shell_echoes_what_is_typed_and_ends_on_exit() {
        let (mine, theirs) = pipe();
        tokio::spawn(serve_stream(theirs, 80, 24, true));
        let mut frames = Frames::default();
        let mut got = Vec::new();
        let mut acked = false;
        mine.send(frame(DATA, b"echo kariz-$((20+22))\nexit 7\n"))
            .await
            .unwrap();
        let mut exit = None;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        while exit.is_none() {
            let chunk = tokio::time::timeout_at(deadline, mine.recv())
                .await
                .expect("in time")
                .unwrap();
            let Some(chunk) = chunk else { break };
            frames.push(&chunk);
            while let Ok(Some((kind, payload))) = frames.take_frame() {
                match kind {
                    ACK => {
                        let ack: Ack = serde_json::from_slice(&payload).unwrap();
                        assert!(ack.ok, "{ack:?}");
                        acked = true;
                    }
                    DATA => got.extend_from_slice(&payload),
                    EXIT => {
                        exit = Some(i32::from_be_bytes([
                            payload[0], payload[1], payload[2], payload[3],
                        ]))
                    }
                    _ => {}
                }
            }
        }
        assert!(acked);
        let text = String::from_utf8_lossy(&got);
        assert!(text.contains("kariz-42"), "{text}");
        assert_eq!(exit, Some(7));
    }
}
