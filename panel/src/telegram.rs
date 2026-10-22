//! The Telegram bot: tells the user when a server or a tunnel goes down (and comes back),
//! and answers `/status` and the like in a chat.
//!
//! * The bot is the user's own (made with @BotFather); its token is kept in the panel's
//!   database and never sent back by the API.
//! * Only chats that were connected with a code from the panel are answered. Everyone else
//!   is ignored without a word. The commands only read; nothing here changes a tunnel.
//! * The panel's server may be unable to reach Telegram (blocked in some countries), so a
//!   request can go through an HTTP or SOCKS5 proxy, to another API address, or through a
//!   local port (a tunnel forward to `api.telegram.org:443`) while TLS still checks
//!   `api.telegram.org`.
//! * Telegram being down or blocked never slows the panel: sending and receiving each run
//!   in their own task, and what could not be sent is tried again for a while.

use std::collections::VecDeque;
use std::fmt::Write as _;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tracing::{debug, warn};

use crate::alerts::{Alerter, Notice, Rules};
use crate::auth::now;
use crate::db::Db;
use crate::hub::{Hub, ServerView};

const META: &str = "telegram";
const META_MUTE: &str = "telegram_mute";
const META_DIGEST: &str = "telegram_digest";
const DEFAULT_API: &str = "https://api.telegram.org";
/// How long a connect code is good for.
pub const PAIR_TTL: i64 = 600;
/// A message to Telegram is at most 4096 characters; longer text is sent in parts.
const PART: usize = 3500;
/// What waits to be sent while Telegram cannot be reached.
const OUTBOX_MAX: usize = 50;
const GIVE_UP_AFTER: u32 = 12;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Chat {
    pub id: i64,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Settings {
    pub enabled: bool,
    pub token: String,
    pub chats: Vec<Chat>,
    /// The language of the messages: `fa` or `en`.
    pub lang: String,
    /// Tell about servers going offline and coming back.
    pub servers: bool,
    /// Tell about tunnels going down and coming back.
    pub tunnels: bool,
    /// Seconds a server (a tunnel) has to stay down before it is told.
    pub server_grace: u32,
    pub tunnel_grace: u32,
    /// A status report every this many hours; 0: none.
    pub digest_hours: u32,
    /// Another API address (a relay), instead of `https://api.telegram.org`.
    pub api_base: String,
    /// `http://host:port` or `socks5://host:port` (with `user:password@` if it needs).
    pub proxy: String,
    /// `host:port` that connections to the API go to (a tunnel's forward to
    /// `api.telegram.org:443`); the certificate is still checked for `api.telegram.org`.
    pub connect_via: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            enabled: false,
            token: String::new(),
            chats: Vec::new(),
            lang: "fa".into(),
            servers: true,
            tunnels: true,
            server_grace: 60,
            tunnel_grace: 30,
            digest_hours: 0,
            api_base: String::new(),
            proxy: String::new(),
            connect_via: String::new(),
        }
    }
}

impl Settings {
    pub fn load(db: &Db) -> Settings {
        db.meta(META)
            .ok()
            .flatten()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, db: &Db) -> Result<()> {
        db.set_meta(META, &serde_json::to_string(self)?)
    }

    fn rules(&self) -> Rules {
        Rules {
            servers: self.servers,
            tunnels: self.tunnels,
            server_grace: i64::from(self.server_grace),
            tunnel_grace: i64::from(self.tunnel_grace),
        }
    }

    fn fa(&self) -> bool {
        self.lang != "en"
    }

    fn ready(&self) -> bool {
        self.enabled && !self.token.is_empty()
    }

    /// Checks what the user typed in, so nothing odd is stored.
    pub fn validate(&self) -> Result<(), &'static str> {
        if !self.token.is_empty() && !valid_token(&self.token) {
            return Err("bad_token");
        }
        if !matches!(self.lang.as_str(), "fa" | "en") {
            return Err("bad_input");
        }
        if !(5..=3600).contains(&self.server_grace) || !(5..=3600).contains(&self.tunnel_grace) {
            return Err("bad_input");
        }
        if self.digest_hours > 168 {
            return Err("bad_input");
        }
        if !self.api_base.is_empty() && !valid_api_base(&self.api_base) {
            return Err("bad_api_base");
        }
        if !self.proxy.is_empty() && !valid_proxy(&self.proxy) {
            return Err("bad_proxy");
        }
        if !self.connect_via.is_empty() && !valid_host_port(&self.connect_via) {
            return Err("bad_connect_via");
        }
        if !self.proxy.is_empty() && !self.connect_via.is_empty() {
            return Err("proxy_and_via");
        }
        Ok(())
    }
}

/// `123456:ABC...`, as @BotFather gives it.
pub fn valid_token(t: &str) -> bool {
    let Some((id, secret)) = t.split_once(':') else {
        return false;
    };
    !id.is_empty()
        && id.len() <= 15
        && id.bytes().all(|b| b.is_ascii_digit())
        && (20..=80).contains(&secret.len())
        && secret
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// https, or plain http to this very machine (a relay next to the panel, and the tests).
fn valid_api_base(url: &str) -> bool {
    let local = url.starts_with("http://127.0.0.1")
        || url.starts_with("http://localhost")
        || url.starts_with("http://[::1]");
    (url.starts_with("https://") || local) && url.len() <= 200 && !url.contains(char::is_whitespace)
}

fn valid_proxy(p: &str) -> bool {
    (p.starts_with("http://") || p.starts_with("socks5://"))
        && p.len() <= 200
        && !p.contains(char::is_whitespace)
}

fn valid_host_port(v: &str) -> bool {
    let Some((host, port)) = v.rsplit_once(':') else {
        return false;
    };
    !host.is_empty()
        && host.len() <= 100
        && !host.contains(char::is_whitespace)
        && port.parse::<u16>().is_ok_and(|p| p > 0)
}

/// The proxy address without its password, for showing.
pub fn mask_proxy(p: &str) -> String {
    match (p.find("://"), p.rfind('@')) {
        (Some(i), Some(at)) if at > i => format!("{}***@{}", &p[..i + 3], &p[at + 1..]),
        _ => p.to_owned(),
    }
}

// ---- state shared with the API ----

#[derive(Default)]
pub struct State {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    /// The code a chat sends to connect: `(code, expires)`.
    pair: Option<(String, i64)>,
    last_error: Option<String>,
    last_ok: Option<i64>,
}

impl State {
    fn inner(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A new connect code (the old one stops working).
    pub fn new_pair(&self) -> Result<(String, i64)> {
        let code = crate::config::random_hex(4)?.to_uppercase();
        self.inner().pair = Some((code.clone(), now() + PAIR_TTL));
        Ok((code, PAIR_TTL))
    }

    fn take_pair(&self, code: &str) -> bool {
        let mut inner = self.inner();
        match &inner.pair {
            Some((c, until)) if c.eq_ignore_ascii_case(code) && *until >= now() => {
                inner.pair = None;
                true
            }
            _ => false,
        }
    }

    fn ok(&self) {
        let mut i = self.inner();
        i.last_ok = Some(now());
        i.last_error = None;
    }

    fn failed(&self, why: &str) {
        self.inner().last_error = Some(why.to_owned());
    }

    /// What the API shows: the settings without the token, and how it is going.
    pub fn view(&self, s: &Settings, db: &Db) -> Value {
        let i = self.inner();
        let tail: String = s
            .token
            .chars()
            .rev()
            .take(4)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        json!({
            "enabled": s.enabled,
            "token_set": !s.token.is_empty(),
            "token_tail": if s.token.is_empty() { String::new() } else { tail },
            "chats": s.chats,
            "lang": s.lang,
            "servers": s.servers,
            "tunnels": s.tunnels,
            "server_grace": s.server_grace,
            "tunnel_grace": s.tunnel_grace,
            "digest_hours": s.digest_hours,
            "api_base": s.api_base,
            "proxy": mask_proxy(&s.proxy),
            "connect_via": s.connect_via,
            "muted_until": muted_until(db).filter(|&t| t > now()),
            "pair": i.pair.as_ref().filter(|(_, until)| *until >= now())
                .map(|(code, until)| json!({ "code": code, "expires_in": until - now() })),
            "last_ok": i.last_ok,
            "last_error": i.last_error,
        })
    }
}

/// Starts the periodic report's clock again (its interval changed).
pub fn reset_digest(db: &Db) {
    let _ = db.set_meta(META_DIGEST, "");
}

fn muted_until(db: &Db) -> Option<i64> {
    db.meta(META_MUTE).ok().flatten()?.parse().ok()
}

// ---- talking to Telegram ----

/// Sends connections for the API to one address, whatever the name says (the name is still
/// what TLS checks the certificate for).
struct Via(String);

impl ureq::Resolver for Via {
    fn resolve(&self, _netloc: &str) -> io::Result<Vec<SocketAddr>> {
        Ok(self.0.to_socket_addrs()?.collect())
    }
}

fn agent(s: &Settings, timeout: u64) -> Result<ureq::Agent, String> {
    let mut b = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(10))
        .timeout(Duration::from_secs(timeout))
        .redirects(0);
    if !s.proxy.is_empty() {
        let proxy = ureq::Proxy::new(&s.proxy).map_err(|_| "bad_proxy".to_owned())?;
        b = b.proxy(proxy);
    }
    if !s.connect_via.is_empty() {
        b = b.resolver(Via(s.connect_via.clone()));
    }
    Ok(b.build())
}

/// One call of the Bot API, blocking: the `result` of the answer, or why not. The token
/// never appears in the error.
fn call(s: &Settings, method: &str, body: &Value, timeout: u64) -> Result<Value, String> {
    let base = if s.api_base.is_empty() {
        DEFAULT_API
    } else {
        s.api_base.trim_end_matches('/')
    };
    let url = format!("{base}/bot{}/{method}", s.token);
    let scrub = |text: String| text.replace(&s.token, "<token>");
    let agent = agent(s, timeout)?;
    let answer = agent
        .post(&url)
        .set(
            "User-Agent",
            concat!("kariz-panel/", env!("CARGO_PKG_VERSION")),
        )
        .set("Content-Type", "application/json")
        .send_string(&body.to_string());
    let text = match answer {
        Ok(r) => r.into_string().map_err(|e| scrub(e.to_string()))?,
        // Telegram explains itself in the body of an error.
        Err(ureq::Error::Status(code, r)) => {
            let text = r.into_string().unwrap_or_default();
            let why = serde_json::from_str::<Value>(&text)
                .ok()
                .and_then(|v| v["description"].as_str().map(str::to_owned))
                .unwrap_or_else(|| format!("HTTP {code}"));
            return Err(scrub(format!("{why} ({code})")));
        }
        Err(e) => return Err(scrub(e.to_string())),
    };
    let v: Value = serde_json::from_str(&text).map_err(|_| "not a Telegram answer".to_owned())?;
    if v["ok"].as_bool() == Some(true) {
        Ok(v["result"].clone())
    } else {
        Err(scrub(
            v["description"]
                .as_str()
                .unwrap_or("Telegram refused")
                .to_owned(),
        ))
    }
}

async fn call_async(
    s: &Settings,
    method: &'static str,
    body: Value,
    timeout: u64,
) -> Result<Value, String> {
    let s = s.clone();
    tokio::task::spawn_blocking(move || call(&s, method, &body, timeout))
        .await
        .map_err(|e| e.to_string())?
}

/// Splits a long text at line ends into parts Telegram accepts.
fn parts(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for line in text.split_inclusive('\n') {
        if !cur.is_empty() && cur.chars().count() + line.chars().count() > PART {
            out.push(std::mem::take(&mut cur));
        }
        // A single line longer than a part is cut.
        if line.chars().count() > PART {
            cur.extend(line.chars().take(PART));
        } else {
            cur.push_str(line);
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur);
    }
    out
}

async fn send(s: &Settings, chat: i64, text: &str) -> Result<(), String> {
    for part in parts(text) {
        call_async(
            s,
            "sendMessage",
            json!({
                "chat_id": chat,
                "text": part,
                "parse_mode": "HTML",
                "disable_web_page_preview": true,
            }),
            20,
        )
        .await?;
    }
    Ok(())
}

/// The "Test" button: is the token good and the API reachable (the bot's name), and a
/// message to every connected chat.
pub async fn check(hub: &Hub) -> Result<String, String> {
    let s = Settings::load(&hub.db);
    if s.token.is_empty() {
        return Err("no_token".into());
    }
    let me = call_async(&s, "getMe", json!({}), 20)
        .await
        .inspect_err(|e| {
            hub.telegram.failed(e);
        })?;
    let name = me["username"].as_str().unwrap_or("").to_owned();
    let text = text::test(s.fa());
    for chat in &s.chats {
        send(&s, chat.id, &text).await.inspect_err(|e| {
            hub.telegram.failed(e);
        })?;
    }
    hub.telegram.ok();
    Ok(name)
}

// ---- the two tasks ----

/// Runs until the panel stops: the alerts, and the chat.
pub async fn run(hub: Arc<Hub>) {
    tokio::join!(alert_loop(hub.clone()), poll_loop(hub));
}

struct Pending {
    text: String,
    chats: Vec<i64>,
    tries: u32,
    next: i64,
}

async fn alert_loop(hub: Arc<Hub>) {
    let mut alerter = Alerter::new(now());
    let mut outbox: VecDeque<Pending> = VecDeque::new();
    let mut tick = tokio::time::interval(Duration::from_secs(5));
    loop {
        tick.tick().await;
        let s = Settings::load(&hub.db);
        let at = now();
        let views = match hub.snapshot() {
            Ok(v) => v,
            Err(e) => {
                debug!(error = %e, "no snapshot for the alerts");
                continue;
            }
        };
        let mut notices = alerter.step(&views, at, s.rules());
        // What the tunnels' traffic limits have to say (always, like a server going down).
        notices.extend(hub.take_notices());
        let speaking = s.ready()
            && !s.chats.is_empty()
            && !matches!(muted_until(&hub.db), Some(until) if until > at);
        if speaking {
            if !notices.is_empty() {
                queue(&mut outbox, &s, text::notices(s.fa(), &notices), at);
            }
            if digest_due(&hub.db, &s, at) {
                queue(&mut outbox, &s, text::status(s.fa(), &views), at);
            }
        } else if !s.ready() {
            outbox.clear();
        }
        flush(&hub, &s, &mut outbox, at).await;
    }
}

fn queue(outbox: &mut VecDeque<Pending>, s: &Settings, text: String, at: i64) {
    if outbox.len() >= OUTBOX_MAX {
        outbox.pop_front();
        warn!("a Telegram message was dropped: too many are waiting");
    }
    outbox.push_back(Pending {
        text,
        chats: s.chats.iter().map(|c| c.id).collect(),
        tries: 0,
        next: at,
    });
}

/// Whether the periodic report is due (and notes that it was sent). The first time it is
/// turned on only starts the clock.
fn digest_due(db: &Db, s: &Settings, at: i64) -> bool {
    if s.digest_hours == 0 {
        return false;
    }
    let last: Option<i64> = db
        .meta(META_DIGEST)
        .ok()
        .flatten()
        .and_then(|v| v.parse().ok());
    match last {
        Some(last) if at - last < i64::from(s.digest_hours) * 3600 => false,
        Some(_) => {
            let _ = db.set_meta(META_DIGEST, &at.to_string());
            true
        }
        None => {
            let _ = db.set_meta(META_DIGEST, &at.to_string());
            false
        }
    }
}

/// Sends what is waiting and due; what fails stays, with a longer wait each time.
async fn flush(hub: &Hub, s: &Settings, outbox: &mut VecDeque<Pending>, at: i64) {
    let mut keep = VecDeque::new();
    while let Some(mut p) = outbox.pop_front() {
        if p.next > at || !s.ready() {
            keep.push_back(p);
            continue;
        }
        let mut left = Vec::new();
        let mut last_error = None;
        for &chat in &p.chats {
            match send(s, chat, &p.text).await {
                Ok(()) => {}
                Err(e) => {
                    left.push(chat);
                    last_error = Some(e);
                }
            }
        }
        match last_error {
            None => hub.telegram.ok(),
            Some(e) => {
                hub.telegram.failed(&e);
                p.chats = left;
                p.tries += 1;
                if p.tries >= GIVE_UP_AFTER {
                    warn!(error = %e, "a Telegram message was given up on");
                } else {
                    p.next = at + (5i64 << p.tries.min(6)).min(300);
                    keep.push_back(p);
                }
            }
        }
    }
    *outbox = keep;
}

async fn poll_loop(hub: Arc<Hub>) {
    let mut offset: Option<i64> = None;
    let mut wait = 5u64;
    loop {
        let s = Settings::load(&hub.db);
        if !s.ready() {
            offset = None;
            tokio::time::sleep(Duration::from_secs(3)).await;
            continue;
        }
        // The first look takes the newest update's number and drops what came before the
        // panel was listening, so an old command is not answered now.
        let first = offset.is_none();
        let body = if first {
            json!({ "offset": -1, "timeout": 0, "allowed_updates": ["message"] })
        } else {
            json!({ "offset": offset, "timeout": 25, "allowed_updates": ["message"] })
        };
        match call_async(&s, "getUpdates", body, 40).await {
            Ok(Value::Array(updates)) => {
                wait = 5;
                hub.telegram.ok();
                let newest = updates.iter().filter_map(|u| u["update_id"].as_i64()).max();
                if first {
                    offset = Some(newest.map_or(0, |n| n + 1));
                    continue;
                }
                if let Some(n) = newest {
                    offset = Some(n + 1);
                }
                for u in &updates {
                    handle(&hub, &s, u).await;
                }
            }
            Ok(_) => {}
            Err(e) => {
                hub.telegram.failed(&e);
                debug!(error = %e, "Telegram did not answer");
                tokio::time::sleep(Duration::from_secs(wait)).await;
                wait = (wait * 2).min(60);
            }
        }
    }
}

/// One update from Telegram (a message from a chat).
pub async fn handle(hub: &Hub, s: &Settings, update: &Value) {
    let msg = &update["message"];
    let (Some(chat), Some(text)) = (msg["chat"]["id"].as_i64(), msg["text"].as_str()) else {
        return;
    };
    let (cmd, arg) = parse_command(text);
    let known = s.chats.iter().any(|c| c.id == chat);
    if !known {
        // Only `/start CODE` from a stranger, and only with the right code.
        if cmd == "/start" && !arg.is_empty() && hub.telegram.take_pair(arg) {
            let name = chat_name(&msg["chat"]);
            let mut now_s = Settings::load(&hub.db);
            if !now_s.chats.iter().any(|c| c.id == chat) {
                now_s.chats.push(Chat {
                    id: chat,
                    name: name.clone(),
                });
                if now_s.save(&hub.db).is_err() {
                    return;
                }
                let _ = hub
                    .db
                    .audit("telegram", None, &format!("chat connected: {name}"));
            }
            let _ = send(&now_s, chat, &text::connected(s.fa())).await;
        }
        return;
    }
    let reply = answer(hub, s, cmd, arg);
    if let Err(e) = send(s, chat, &reply).await {
        hub.telegram.failed(&e);
    }
}

fn chat_name(chat: &Value) -> String {
    ["title", "username", "first_name"]
        .iter()
        .find_map(|k| chat[*k].as_str().filter(|v| !v.is_empty()))
        .unwrap_or("chat")
        .chars()
        .take(60)
        .collect()
}

/// `/status@my_bot arg` into `("/status", "arg")`.
pub fn parse_command(text: &str) -> (String, &str) {
    let text = text.trim();
    let (head, arg) = text.split_once(char::is_whitespace).unwrap_or((text, ""));
    let head = head.split('@').next().unwrap_or(head).to_lowercase();
    (head, arg.trim())
}

/// "30m", "2h", "1d" (a bare number is minutes) as seconds.
pub fn parse_duration(v: &str) -> Option<i64> {
    let v = v.trim().to_lowercase();
    let (n, unit) = match v.char_indices().find(|(_, c)| !c.is_ascii_digit()) {
        Some((i, _)) => (&v[..i], &v[i..]),
        None => (v.as_str(), "m"),
    };
    let n: i64 = n.parse().ok()?;
    let per = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        _ => return None,
    };
    let secs = n.checked_mul(per)?;
    (1..=30 * 86400).contains(&secs).then_some(secs)
}

fn answer(hub: &Hub, s: &Settings, cmd: String, arg: &str) -> String {
    let fa = s.fa();
    let views = || hub.snapshot().unwrap_or_default();
    match cmd.as_str() {
        "/status" | "/report" => text::status(fa, &views()),
        "/servers" => text::servers(fa, &views()),
        "/tunnels" => text::tunnels(fa, &views()),
        "/server" => text::server(fa, &views(), arg),
        "/tunnel" => text::tunnel(fa, &views(), arg),
        "/mute" => match parse_duration(if arg.is_empty() { "1h" } else { arg }) {
            Some(secs) => {
                let until = now() + secs;
                let _ = hub.db.set_meta(META_MUTE, &until.to_string());
                text::muted(fa, secs)
            }
            None => text::help(fa),
        },
        "/unmute" => {
            let _ = hub.db.set_meta(META_MUTE, "0");
            text::unmuted(fa)
        }
        _ => text::help(fa),
    }
}

/// What the messages say, in Persian and in English.
pub mod text {
    use super::*;

    pub fn esc(s: &str) -> String {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
    }

    /// Persian digits in Persian text.
    fn n(fa: bool, v: impl std::fmt::Display) -> String {
        let s = v.to_string();
        if !fa {
            return s;
        }
        s.chars()
            .map(|c| match c {
                '0'..='9' => char::from_u32('۰' as u32 + (c as u32 - '0' as u32)).unwrap_or(c),
                '.' => '٫',
                c => c,
            })
            .collect()
    }

    pub fn duration(fa: bool, secs: i64) -> String {
        let secs = secs.max(0);
        let (d, h, m, s) = (
            secs / 86400,
            secs % 86400 / 3600,
            secs % 3600 / 60,
            secs % 60,
        );
        let parts: Vec<(i64, &str, &str)> = if d > 0 {
            vec![(d, "d", "روز"), (h, "h", "ساعت")]
        } else if h > 0 {
            vec![(h, "h", "ساعت"), (m, "m", "دقیقه")]
        } else if m > 0 {
            vec![(m, "m", "دقیقه"), (s, "s", "ثانیه")]
        } else {
            vec![(s, "s", "ثانیه")]
        };
        let shown: Vec<String> = parts
            .into_iter()
            .filter(|(v, _, _)| *v > 0)
            .map(|(v, en, fa_)| {
                if fa {
                    format!("{} {fa_}", n(fa, v))
                } else {
                    format!("{v}{en}")
                }
            })
            .collect();
        let joined = shown.join(if fa { " و " } else { " " });
        if joined.is_empty() {
            if fa {
                "۰ ثانیه".into()
            } else {
                "0s".into()
            }
        } else {
            joined
        }
    }

    pub fn notices(fa: bool, list: &[Notice]) -> String {
        let mut out = String::new();
        for notice in list {
            if !out.is_empty() {
                out.push('\n');
            }
            match notice {
                Notice::ServerDown { name, tunnels } => {
                    let name = esc(name);
                    if fa {
                        let _ = write!(out, "🔴 سرور <b>{name}</b> آفلاین شد");
                        if !tunnels.is_empty() {
                            let _ = write!(out, "\nتانل‌های روی آن: {}", esc(&tunnels.join("، ")));
                        }
                    } else {
                        let _ = write!(out, "🔴 Server <b>{name}</b> went offline");
                        if !tunnels.is_empty() {
                            let _ = write!(out, "\nTunnels on it: {}", esc(&tunnels.join(", ")));
                        }
                    }
                }
                Notice::ServerUp { name, down_secs } => {
                    let (name, d) = (esc(name), duration(fa, *down_secs));
                    if fa {
                        let _ = write!(out, "🟢 سرور <b>{name}</b> برگشت (آفلاین بود: {d})");
                    } else {
                        let _ = write!(out, "🟢 Server <b>{name}</b> is back (offline for {d})");
                    }
                }
                Notice::TunnelDown {
                    name,
                    server,
                    error,
                } => {
                    let (name, server) = (esc(name), esc(server));
                    if fa {
                        let _ = write!(out, "🔴 تانل <b>{name}</b> قطع شد (گزارش از {server})");
                    } else {
                        let _ = write!(
                            out,
                            "🔴 Tunnel <b>{name}</b> is down (reported by {server})"
                        );
                    }
                    if let Some(e) = error {
                        let _ = write!(out, "\n<i>{}</i>", esc(e));
                    }
                }
                Notice::TunnelUp { name, down_secs } => {
                    let (name, d) = (esc(name), duration(fa, *down_secs));
                    if fa {
                        let _ = write!(out, "🟢 تانل <b>{name}</b> دوباره وصل شد (قطع بود: {d})");
                    } else {
                        let _ = write!(out, "🟢 Tunnel <b>{name}</b> is up again (down for {d})");
                    }
                }
                Notice::QuotaNear { name, used, limit } => {
                    let (name, used, limit) = (esc(name), bytes(fa, *used), bytes(fa, *limit));
                    if fa {
                        let _ = write!(
                            out,
                            "⚠️ تانل <b>{name}</b> به ۸۰٪ سقف حجمش رسیده ({used} از {limit})"
                        );
                    } else {
                        let _ = write!(
                            out,
                            "⚠️ Tunnel <b>{name}</b> has used 80% of its traffic limit ({used} of {limit})"
                        );
                    }
                }
                Notice::QuotaStopped { name, used, limit } => {
                    let (name, used, limit) = (esc(name), bytes(fa, *used), bytes(fa, *limit));
                    if fa {
                        let _ = write!(
                            out,
                            "🛑 تانل <b>{name}</b> متوقف شد: سقف حجمش پر شده ({used} از {limit}). در پنل مصرف را بازنشانی کنید یا سقف را بالا ببرید."
                        );
                    } else {
                        let _ = write!(
                            out,
                            "🛑 Tunnel <b>{name}</b> was stopped: its traffic limit is reached ({used} of {limit}). Reset the usage or raise the limit in the panel."
                        );
                    }
                }
                Notice::Unstable { name } => {
                    let name = esc(name);
                    if fa {
                        let _ = write!(
                            out,
                            "⚠️ <b>{name}</b> مدام قطع و وصل می‌شود؛ پیام‌هایش تا پایدار شدن متوقف شد. پنل را ببینید."
                        );
                    } else {
                        let _ = write!(
                            out,
                            "⚠️ <b>{name}</b> keeps going up and down; its messages are paused until it settles. Look at the panel."
                        );
                    }
                }
                Notice::TunnelBlocked {
                    name,
                    server,
                    target,
                    error,
                } => {
                    let (name, server) = (esc(name), esc(server));
                    match (fa, target) {
                        (true, Some(target)) => {
                            let _ = write!(
                                out,
                                "🟠 تانل <b>{name}</b> وصل است، ولی سرور خارج به مقصد <code>{}</code> نمی‌رسد؛ کاربرها نمی‌توانند وصل شوند (گزارش از {server})",
                                esc(target)
                            );
                        }
                        (true, None) => {
                            let _ = write!(
                                out,
                                "🟠 تانل <b>{name}</b> وصل است، ولی اتصال تازه از آن رد نمی‌شود؛ کاربرها نمی‌توانند وصل شوند (گزارش از {server})"
                            );
                        }
                        (false, Some(target)) => {
                            let _ = write!(
                                out,
                                "🟠 Tunnel <b>{name}</b> is connected, but its exit side cannot reach <code>{}</code>: users cannot connect (reported by {server})",
                                esc(target)
                            );
                        }
                        (false, None) => {
                            let _ = write!(
                                out,
                                "🟠 Tunnel <b>{name}</b> is connected, but new connections do not get through: users cannot connect (reported by {server})"
                            );
                        }
                    }
                    if let Some(e) = error.as_ref().filter(|_| target.is_none()) {
                        let _ = write!(out, "\n<i>{}</i>", esc(e));
                    }
                }
                Notice::TunnelUnblocked { name, blocked_secs } => {
                    let (name, d) = (esc(name), duration(fa, *blocked_secs));
                    if fa {
                        let _ = write!(
                            out,
                            "🟢 کاربرها دوباره از تانل <b>{name}</b> وصل می‌شوند (مشکل بود: {d})"
                        );
                    } else {
                        let _ = write!(
                            out,
                            "🟢 Users get through tunnel <b>{name}</b> again (blocked for {d})"
                        );
                    }
                }
                Notice::TunnelBusy { name, streams, max } => {
                    let name = esc(name);
                    if fa {
                        let _ = write!(
                            out,
                            "🟡 تانل <b>{name}</b> نزدیک پر شدن است: {} از {} جریان در حال استفاده است. اگر پر شود اتصال‌های تازه رد می‌شوند؛ «جریان در هر اتصال» یا «تعداد اتصال» را در تنظیمات mux تانل بالا ببرید.",
                            n(fa, streams),
                            n(fa, max)
                        );
                    } else {
                        let _ = write!(
                            out,
                            "🟡 Tunnel <b>{name}</b> is nearly full: {streams} of {max} streams in use. When it is full new connections fail; raise \"Streams per connection\" or \"Connections\" in its mux settings."
                        );
                    }
                }
            }
        }
        out
    }

    fn dot(up: bool) -> &'static str {
        if up {
            "🟢"
        } else {
            "🔴"
        }
    }

    fn pct(fa: bool, v: f64) -> String {
        format!("{}{}", n(fa, v.round() as i64), if fa { "٪" } else { "%" })
    }

    /// One server's line: its name, CPU, memory, traffic.
    fn server_line(fa: bool, s: &ServerView) -> String {
        let mut line = format!("{} <b>{}</b>", dot(s.online), esc(&s.name));
        if !s.online {
            line.push_str(if fa {
                " · آفلاین"
            } else {
                " · offline"
            });
            return line;
        }
        if let Some(h) = &s.health {
            if let Some(c) = h.cpu_pct {
                let _ = write!(line, " · CPU {}", pct(fa, c));
            }
            if let (Some(total), Some(used)) = (h.mem_total, h.mem_used) {
                if total > 0 {
                    let _ = write!(
                        line,
                        " · {} {}",
                        if fa { "رم" } else { "RAM" },
                        pct(fa, used as f64 * 100.0 / total as f64)
                    );
                }
            }
            if let (Some(rx), Some(tx)) = (h.rx_bps, h.tx_bps) {
                let _ = write!(
                    line,
                    " · ↓{} ↑{}",
                    mbit(fa, rx * 8.0 / 1e6),
                    mbit(fa, tx * 8.0 / 1e6)
                );
            }
        }
        line
    }

    fn mbit(fa: bool, v: f64) -> String {
        if v >= 100.0 {
            format!("{} Mbit/s", n(fa, v.round() as i64))
        } else if v >= 0.1 {
            format!("{} Mbit/s", n(fa, format!("{v:.1}")))
        } else {
            format!("{} kbit/s", n(fa, (v * 1000.0).round() as i64))
        }
    }

    /// Every tunnel once (it is two configs, on two servers): the entry side stands for it
    /// when it is there.
    fn tunnel_rows(views: &[ServerView]) -> Vec<(&ServerView, &crate::hub::TunnelView, bool)> {
        let mut rows: Vec<(&ServerView, &crate::hub::TunnelView, bool)> = Vec::new();
        for s in views.iter().filter(|s| s.online) {
            for t in &s.tunnels {
                let up = t.info.status.as_ref().map(|st| st.peer.connected);
                match rows.iter_mut().find(|(_, o, _)| o.info.name == t.info.name) {
                    Some(row) => {
                        if t.info.role == "entry" {
                            row.0 = s;
                            row.1 = t;
                        }
                        row.2 = row.2 && up.unwrap_or(true);
                    }
                    None => rows.push((s, t, up.unwrap_or(true))),
                }
            }
        }
        rows.sort_by(|a, b| a.1.info.name.cmp(&b.1.info.name));
        rows
    }

    fn tunnel_line(fa: bool, t: &crate::hub::TunnelView, up: bool) -> String {
        let mut line = format!("{} <b>{}</b>", dot(up), esc(&t.info.name));
        if t.info.active == Some(false) {
            line.push_str(if fa { " · متوقف" } else { " · stopped" });
            return line;
        }
        let _ = write!(line, " · {}", esc(&t.info.transport));
        if let Some(st) = &t.info.status {
            if let Some(rtt) = st.peer.rtt_ms {
                let _ = write!(line, " · {} ms", n(fa, rtt.round() as i64));
            }
            if up {
                if let Some(r) = t.rate_mbps {
                    let _ = write!(line, " · {}", mbit(fa, r));
                }
                let open = st.totals.tcp_open + st.totals.udp_flows;
                if open > 0 {
                    let _ = write!(
                        line,
                        " · {} {}",
                        n(fa, open),
                        if fa { "اتصال" } else { "open" }
                    );
                }
            }
        }
        line
    }

    pub fn status(fa: bool, views: &[ServerView]) -> String {
        let online = views.iter().filter(|s| s.online).count();
        let rows = tunnel_rows(views);
        let up = rows.iter().filter(|(_, _, up)| *up).count();
        let mut out = if fa {
            format!(
                "📊 <b>وضعیت کاریز</b>\nسرورها: {} از {} آنلاین · تانل‌ها: {} از {} وصل\n",
                n(fa, online),
                n(fa, views.len()),
                n(fa, up),
                n(fa, rows.len())
            )
        } else {
            format!(
                "📊 <b>Kariz status</b>\nServers: {online} of {} online · Tunnels: {up} of {} up\n",
                views.len(),
                rows.len()
            )
        };
        out.push_str(if fa {
            "\n<b>سرورها</b>\n"
        } else {
            "\n<b>Servers</b>\n"
        });
        for s in views {
            let _ = writeln!(out, "{}", server_line(fa, s));
        }
        if !rows.is_empty() {
            out.push_str(if fa {
                "\n<b>تانل‌ها</b>\n"
            } else {
                "\n<b>Tunnels</b>\n"
            });
            for (_, t, up) in rows {
                let _ = writeln!(out, "{}", tunnel_line(fa, t, up));
            }
        }
        out
    }

    pub fn servers(fa: bool, views: &[ServerView]) -> String {
        let mut out = String::new();
        for s in views {
            let _ = writeln!(out, "{}", server_line(fa, s));
        }
        if out.is_empty() {
            out.push_str(if fa {
                "سروری نیست."
            } else {
                "No servers."
            });
        }
        out
    }

    pub fn tunnels(fa: bool, views: &[ServerView]) -> String {
        let mut out = String::new();
        for (_, t, up) in tunnel_rows(views) {
            let _ = writeln!(out, "{}", tunnel_line(fa, t, up));
        }
        if out.is_empty() {
            out.push_str(if fa {
                "تانلی نیست."
            } else {
                "No tunnels."
            });
        }
        out
    }

    /// The one that is meant by `arg`: exactly, or by the start of its name; or why not.
    fn pick<T>(
        fa: bool,
        kind_fa: &str,
        kind_en: &str,
        arg: &str,
        items: Vec<(&str, T)>,
    ) -> Result<T, String> {
        let want = arg.trim().to_lowercase();
        if want.is_empty() {
            return Err(if fa {
                format!("نام {kind_fa} را بنویسید، مثلاً /{kind_en} نام")
            } else {
                format!("Give the {kind_en}'s name, for example /{kind_en} name")
            });
        }
        let names: Vec<String> = items.iter().map(|(name, _)| (*name).to_owned()).collect();
        let exact: Vec<usize> = (0..items.len())
            .filter(|&i| items[i].0.to_lowercase() == want)
            .collect();
        let starts: Vec<usize> = (0..items.len())
            .filter(|&i| items[i].0.to_lowercase().starts_with(&want))
            .collect();
        let hit = if exact.len() == 1 { exact } else { starts };
        match hit.as_slice() {
            [i] => Ok(items
                .into_iter()
                .nth(*i)
                .map(|(_, t)| t)
                .expect("an index of the list")),
            [] => Err(if fa {
                format!(
                    "{kind_fa}ی با این نام نیست. موجود: {}",
                    esc(&names.join("، "))
                )
            } else {
                format!(
                    "No {kind_en} with that name. There are: {}",
                    esc(&names.join(", "))
                )
            }),
            _ => Err(if fa {
                format!("چند مورد پیدا شد: {}", esc(&names.join("، ")))
            } else {
                format!("More than one matches: {}", esc(&names.join(", ")))
            }),
        }
    }

    pub fn server(fa: bool, views: &[ServerView], arg: &str) -> String {
        let items = views.iter().map(|s| (s.name.as_str(), s)).collect();
        let s = match pick(fa, "سرور", "server", arg, items) {
            Ok(s) => s,
            Err(e) => return e,
        };
        let mut out = format!("{}\n", server_line(fa, s));
        if let Some(h) = &s.health {
            if let Some(l) = h.load1 {
                let _ = writeln!(
                    out,
                    "{}: {}",
                    if fa { "بار" } else { "Load" },
                    n(fa, format!("{l:.2}"))
                );
            }
            if let Some(up) = h.uptime_secs {
                let _ = writeln!(
                    out,
                    "{}: {}",
                    if fa { "روشن از" } else { "Up for" },
                    duration(fa, up as i64)
                );
            }
        }
        let _ = writeln!(
            out,
            "{}: {}",
            if fa { "نسخه" } else { "Version" },
            esc(&s.version)
        );
        for ip in [&s.ip4, &s.ip6].into_iter().flatten() {
            let _ = writeln!(out, "IP: <code>{}</code>", esc(ip));
        }
        if !s.tunnels.is_empty() {
            let names: Vec<&str> = s.tunnels.iter().map(|t| t.info.name.as_str()).collect();
            let _ = writeln!(
                out,
                "{}: {}",
                if fa { "تانل‌ها" } else { "Tunnels" },
                esc(&names.join(", "))
            );
        }
        out
    }

    pub fn tunnel(fa: bool, views: &[ServerView], arg: &str) -> String {
        let rows = tunnel_rows(views);
        let items = rows
            .iter()
            .map(|(s, t, up)| (t.info.name.as_str(), (*s, *t, *up)))
            .collect();
        let (s, t, up) = match pick(fa, "تانل", "tunnel", arg, items) {
            Ok(x) => x,
            Err(e) => return e,
        };
        let mut out = format!("{}\n", tunnel_line(fa, t, up));
        let _ = writeln!(
            out,
            "{}: {} · {} · {}",
            if fa {
                "نقش و حالت"
            } else {
                "Role and mode"
            },
            esc(&t.info.role),
            esc(&t.info.mode),
            esc(&t.info.profile)
        );
        let _ = writeln!(
            out,
            "{}: {}",
            if fa { "گزارش از" } else { "Reported by" },
            esc(&s.name)
        );
        if let Some(st) = &t.info.status {
            if let Some(secs) = st.peer.connected_secs {
                let _ = writeln!(
                    out,
                    "{}: {}",
                    if fa { "وصل از" } else { "Connected for" },
                    duration(fa, secs as i64)
                );
            }
            if let Some(ss) = st.peer.sessions {
                let _ = writeln!(
                    out,
                    "{}: {}",
                    if fa { "نشست‌ها" } else { "Sessions" },
                    n(fa, ss)
                );
            }
            let _ = writeln!(
                out,
                "{}: ↑{} ↓{}",
                if fa { "ترافیک" } else { "Traffic" },
                bytes(fa, st.totals.bytes_up),
                bytes(fa, st.totals.bytes_down)
            );
            if let Some(e) = &st.peer.last_error {
                let _ = writeln!(
                    out,
                    "{}: <i>{}</i> ({} {})",
                    if fa {
                        "آخرین خطا"
                    } else {
                        "Last error"
                    },
                    esc(&e.text),
                    duration(fa, e.secs_ago as i64),
                    if fa { "پیش" } else { "ago" }
                );
            }
        }
        out
    }

    fn bytes(fa: bool, b: u64) -> String {
        const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
        let mut v = b as f64;
        let mut i = 0;
        while v >= 1024.0 && i < UNITS.len() - 1 {
            v /= 1024.0;
            i += 1;
        }
        if i == 0 {
            format!("{} B", n(fa, b))
        } else {
            format!("{} {}", n(fa, format!("{v:.1}")), UNITS[i])
        }
    }

    pub fn help(fa: bool) -> String {
        if fa {
            "🤖 <b>ربات کاریز</b>\n\
             /status — وضعیت همهٔ سرورها و تانل‌ها\n\
             /servers — سرورها\n\
             /server نام — جزئیات یک سرور\n\
             /tunnels — تانل‌ها\n\
             /tunnel نام — جزئیات یک تانل\n\
             /mute 2h — ساکت کردن اعلان‌ها (30m، 2h، 1d)\n\
             /unmute — برگرداندن اعلان‌ها"
                .into()
        } else {
            "🤖 <b>Kariz bot</b>\n\
             /status — every server and tunnel at a glance\n\
             /servers — the servers\n\
             /server name — one server in detail\n\
             /tunnels — the tunnels\n\
             /tunnel name — one tunnel in detail\n\
             /mute 2h — silence the alerts (30m, 2h, 1d)\n\
             /unmute — turn them back on"
                .into()
        }
    }

    pub fn connected(fa: bool) -> String {
        if fa {
            format!(
                "✅ این چت به پنل کاریز وصل شد. از این به بعد اعلان‌ها اینجا می‌آید.\n\n{}",
                help(fa)
            )
        } else {
            format!(
                "✅ This chat is connected to the Kariz panel. Alerts will come here.\n\n{}",
                help(fa)
            )
        }
    }

    pub fn test(fa: bool) -> String {
        if fa {
            "✅ پیام آزمایشی از پنل کاریز".into()
        } else {
            "✅ A test message from the Kariz panel".into()
        }
    }

    pub fn muted(fa: bool, secs: i64) -> String {
        if fa {
            format!("🔕 اعلان‌ها {} ساکت شد. /unmute", duration(fa, secs))
        } else {
            format!("🔕 Alerts are silenced for {}. /unmute", duration(fa, secs))
        }
    }

    pub fn unmuted(fa: bool) -> String {
        if fa {
            "🔔 اعلان‌ها برگشت.".into()
        } else {
            "🔔 Alerts are back on.".into()
        }
    }
}

/// What the API needs to check before it stores a change.
pub fn check_new(new: &Settings) -> Result<(), &'static str> {
    new.validate()?;
    if new.enabled && new.token.is_empty() {
        return Err("no_token");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_command_is_split_from_its_argument_and_the_bot_name() {
        assert_eq!(parse_command("/status"), ("/status".into(), ""));
        assert_eq!(
            parse_command("/Server@my_bot  frankfurt "),
            ("/server".into(), "frankfurt")
        );
        assert_eq!(parse_command("/start A1B2"), ("/start".into(), "A1B2"));
    }

    #[test]
    fn durations_for_mute() {
        assert_eq!(parse_duration("30m"), Some(1800));
        assert_eq!(parse_duration("2h"), Some(7200));
        assert_eq!(parse_duration("1d"), Some(86400));
        assert_eq!(parse_duration("45"), Some(2700));
        assert_eq!(parse_duration("x"), None);
        assert_eq!(parse_duration("0m"), None);
        assert_eq!(parse_duration("99d"), None);
        assert_eq!(parse_duration("5w"), None);
    }

    #[test]
    fn the_token_is_checked_for_its_shape() {
        assert!(valid_token("123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw"));
        assert!(!valid_token("nonsense"));
        assert!(!valid_token("12:short"));
        assert!(!valid_token("abc:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw"));
        assert!(!valid_token(
            "123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PAL DsaW"
        ));
    }

    #[test]
    fn addresses_are_checked() {
        assert!(valid_api_base("https://relay.example.com"));
        assert!(valid_api_base("http://127.0.0.1:9999"));
        assert!(!valid_api_base("http://relay.example.com"));
        assert!(!valid_api_base("ftp://x"));
        assert!(valid_proxy("socks5://127.0.0.1:10808"));
        assert!(valid_proxy("http://u:p@proxy:3128"));
        assert!(!valid_proxy("127.0.0.1:10808"));
        assert!(valid_host_port("127.0.0.1:8443"));
        assert!(!valid_host_port("127.0.0.1"));
        assert!(!valid_host_port("127.0.0.1:0"));
    }

    #[test]
    fn a_proxy_password_is_not_shown() {
        assert_eq!(
            mask_proxy("socks5://user:secret@host:1080"),
            "socks5://***@host:1080"
        );
        assert_eq!(mask_proxy("http://host:3128"), "http://host:3128");
    }

    #[test]
    fn long_text_is_split_at_line_ends() {
        let line = "x".repeat(1000);
        let text = format!("{line}\n{line}\n{line}\n{line}\n{line}\n");
        let p = parts(&text);
        assert_eq!(p.len(), 2);
        assert!(p.iter().all(|s| s.chars().count() <= PART));
        assert_eq!(p.concat(), text);
        assert_eq!(parts("hi").len(), 1);
        assert!(parts("   ").is_empty());
    }

    #[test]
    fn messages_are_escaped_and_say_how_long_it_was() {
        let notes = [
            Notice::TunnelDown {
                name: "a<b>".into(),
                server: "s&s".into(),
                error: Some("x < y".into()),
            },
            Notice::TunnelUp {
                name: "t".into(),
                down_secs: 252,
            },
        ];
        let en = text::notices(false, &notes);
        assert!(en.contains("a&lt;b&gt;") && en.contains("s&amp;s") && en.contains("x &lt; y"));
        assert!(en.contains("down for 4m 12s"));
        let fa = text::notices(true, &notes);
        assert!(fa.contains("۴ دقیقه و ۱۲ ثانیه"));
    }

    #[test]
    fn a_blocked_or_busy_tunnel_says_what_users_see() {
        let notes = [
            Notice::TunnelBlocked {
                name: "t".into(),
                server: "ir".into(),
                target: Some("127.0.0.1:443".into()),
                error: Some("exit side could not connect to the target".into()),
            },
            Notice::TunnelBlocked {
                name: "t".into(),
                server: "ir".into(),
                target: None,
                error: Some("every tunnel connection is full (8192 streams open)".into()),
            },
            Notice::TunnelBusy {
                name: "t".into(),
                streams: 13200,
                max: 16384,
            },
            Notice::TunnelUnblocked {
                name: "t".into(),
                blocked_secs: 75,
            },
        ];
        let en = text::notices(false, &notes);
        assert!(
            en.contains("cannot reach <code>127.0.0.1:443</code>"),
            "{en}"
        );
        // The reason is shown only when there is no target to name.
        assert_eq!(en.matches("<i>").count(), 1, "{en}");
        assert!(en.contains("8192 streams open"), "{en}");
        assert!(en.contains("13200 of 16384 streams"), "{en}");
        assert!(en.contains("blocked for 1m 15s"), "{en}");
        let fa = text::notices(true, &notes);
        assert!(fa.contains("۱۳۲۰۰ از ۱۶۳۸۴"), "{fa}");
    }

    #[test]
    fn durations_read_well() {
        assert_eq!(text::duration(false, 35), "35s");
        assert_eq!(text::duration(false, 3725), "1h 2m");
        assert_eq!(text::duration(false, 90000), "1d 1h");
        assert_eq!(text::duration(true, 3600), "۱ ساعت");
    }

    #[test]
    fn settings_that_make_no_sense_are_refused() {
        let ok = Settings::default();
        assert!(ok.validate().is_ok());
        let bad = |f: &dyn Fn(&mut Settings)| {
            let mut s = Settings::default();
            f(&mut s);
            s.validate().is_err()
        };
        assert!(bad(&|s| s.token = "nope".into()));
        assert!(bad(&|s| s.lang = "de".into()));
        assert!(bad(&|s| s.server_grace = 1));
        assert!(bad(&|s| s.tunnel_grace = 99999));
        assert!(bad(&|s| s.digest_hours = 999));
        assert!(bad(&|s| s.proxy = "x".into()));
        assert!(bad(&|s| {
            s.proxy = "http://p:1".into();
            s.connect_via = "127.0.0.1:1".into();
        }));
    }

    #[test]
    fn a_connect_code_works_once_and_expires() {
        let st = State::default();
        let (code, _) = st.new_pair().unwrap();
        assert!(!st.take_pair("WRONG"));
        assert!(st.take_pair(&code.to_lowercase()));
        assert!(!st.take_pair(&code));
        st.inner().pair = Some(("OLD".into(), now() - 1));
        assert!(!st.take_pair("OLD"));
    }

    #[test]
    fn the_view_never_carries_the_token() {
        let db = Db::in_memory().unwrap();
        let s = Settings {
            token: "123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw".into(),
            ..Settings::default()
        };
        let v = State::default().view(&s, &db).to_string();
        assert!(!v.contains("AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw"));
        assert!(v.contains("\"token_tail\":\"Dsaw\""));
    }
}
