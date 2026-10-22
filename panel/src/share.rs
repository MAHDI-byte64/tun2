//! A page for the renter of a tunnel's port: how much of the limit is used, how many days
//! are left, whether the tunnel runs, its rate over the last day and week, and a button
//! that restarts it. The page has a link of its own (`/s/TOKEN`, outside the panel's secret
//! path), made and revoked on the tunnel's *Traffic limit* tab, and shows no server names,
//! ports or addresses. An unknown or revoked link answers 404 after a short, constant
//! delay, like any unknown address; each address may ask ten times a minute; a restart may
//! be asked once in five minutes, and not while the limit or the end keeps the tunnel
//! stopped. The page refreshes itself every half minute and runs no script.

// The handlers leave early with a ready `Response` as the `Err` of `lookup`, as in
// `api.rs`; it is built once, on the slow path.
#![allow(clippy::result_large_err)]

use std::collections::HashMap;
use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{bail, Result};
use axum::extract::{ConnectInfo, Extension, Path, Query, State};
use axum::http::{header, HeaderMap, HeaderName, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};

use crate::auth::now;
use crate::db::Db;
use crate::history::Range;
use crate::http::AppState;
use crate::hub::Hub;
use crate::manage::valid_name;

/// The least time between two restarts asked from the page.
const RESTART_EVERY: i64 = 5 * 60;
/// Requests a minute each address may make to the pages.
const PER_MINUTE: f64 = 10.0;
/// What an unknown link waits before its 404, so a guess learns nothing from the timing.
const UNKNOWN_DELAY: Duration = Duration::from_millis(300);
const MAX_TITLE: usize = 80;

/// One renter's page, the whole row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Share {
    pub name: String,
    pub token: String,
    pub title: String,
    pub created: i64,
    pub views: i64,
    pub last_restart: i64,
}

/// What the API shows of a page.
#[derive(Debug, Clone, Serialize)]
pub struct ShareView {
    pub token: String,
    pub title: String,
    pub created: i64,
    pub views: i64,
}

impl From<Share> for ShareView {
    fn from(s: Share) -> Self {
        Self {
            token: s.token,
            title: s.title,
            created: s.created,
            views: s.views,
        }
    }
}

const COLUMNS: &str = "name, token, title, created, views, last_restart";

fn read(r: &rusqlite::Row<'_>) -> rusqlite::Result<Share> {
    Ok(Share {
        name: r.get(0)?,
        token: r.get(1)?,
        title: r.get(2)?,
        created: r.get(3)?,
        views: r.get(4)?,
        last_restart: r.get(5)?,
    })
}

/// Makes the page of a tunnel that has a limit, or makes it again with a new link (the old
/// one stops at once). `None` when the tunnel has no limit.
pub fn make(db: &Db, name: &str, title: &str) -> Result<Option<Share>> {
    if !valid_name(name) {
        bail!("bad_name");
    }
    let title = title.trim();
    if title.chars().count() > MAX_TITLE || title.chars().any(char::is_control) {
        bail!("bad_input");
    }
    let limited: i64 = db.conn().query_row(
        "SELECT COUNT(*) FROM quotas WHERE name = ?1 AND (limit_bytes > 0 OR expires_at > 0)",
        [name],
        |r| r.get(0),
    )?;
    if limited == 0 {
        return Ok(None);
    }
    let token = crate::config::random_hex(16)?;
    db.conn().execute(
        "INSERT INTO shares (name, token, title, created) VALUES (?1, ?2, ?3, ?4) \
         ON CONFLICT(name) DO UPDATE SET token = excluded.token, title = excluded.title, \
         created = excluded.created, views = 0",
        params![name, token, title, now()],
    )?;
    of(db, name)
}

/// Takes a tunnel's page away; whether there was one.
pub fn revoke(db: &Db, name: &str) -> Result<bool> {
    Ok(db
        .conn()
        .execute("DELETE FROM shares WHERE name = ?1", [name])?
        > 0)
}

/// A tunnel (or its limit) is gone: so is its page.
pub fn forget(db: &Db, name: &str) {
    let _ = revoke(db, name);
}

pub fn of(db: &Db, name: &str) -> Result<Option<Share>> {
    Ok(db
        .conn()
        .query_row(
            &format!("SELECT {COLUMNS} FROM shares WHERE name = ?1"),
            [name],
            read,
        )
        .optional()?)
}

pub fn by_token(db: &Db, token: &str) -> Result<Option<Share>> {
    Ok(db
        .conn()
        .query_row(
            &format!("SELECT {COLUMNS} FROM shares WHERE token = ?1"),
            [token],
            read,
        )
        .optional()?)
}

/// Every page, by tunnel.
pub fn all(db: &Db) -> Result<HashMap<String, ShareView>> {
    let conn = db.conn();
    let mut stmt = conn.prepare(&format!("SELECT {COLUMNS} FROM shares"))?;
    let rows = stmt.query_map([], read)?;
    rows.map(|r| r.map(|s| (s.name.clone(), ShareView::from(s))))
        .collect::<rusqlite::Result<_>>()
        .map_err(Into::into)
}

fn viewed(db: &Db, name: &str) {
    let _ = db.conn().execute(
        "UPDATE shares SET views = views + 1 WHERE name = ?1",
        [name],
    );
}

fn restarted(db: &Db, name: &str, t: i64) {
    let _ = db.conn().execute(
        "UPDATE shares SET last_restart = ?2 WHERE name = ?1",
        params![name, t],
    );
}

/// What the page shows (also `/s/TOKEN/data`, as JSON).
#[derive(Debug, Clone, Serialize)]
pub struct PageData {
    pub title: String,
    pub used: i64,
    /// 0: a limit of time alone.
    pub limit_bytes: i64,
    pub pct: f64,
    /// 0: no end.
    pub expires_at: i64,
    pub days_left: Option<i64>,
    /// `running`, `stopped`, `limit` (stopped by the volume) or `expired` (by the end).
    pub state: &'static str,
    pub can_restart: bool,
    /// Seconds until a restart may be asked again (0: now).
    pub restart_wait: i64,
    /// Mbit/s, both directions, over the last day and the last week.
    pub rate_24h: Vec<(i64, f64)>,
    pub rate_7d: Vec<(i64, f64)>,
}

fn data(hub: &Hub, share: &Share) -> PageData {
    let t = now();
    let quota = crate::quota::list(&hub.db)
        .ok()
        .into_iter()
        .flatten()
        .find(|q| q.name == share.name);
    let (used, limit, pct, expires_at, expired, stopped) =
        quota.map_or((0, 0, 0.0, 0, 0, 0), |q| {
            (
                q.used,
                q.limit_bytes,
                q.pct,
                q.expires_at,
                q.expired,
                q.stopped,
            )
        });
    let sides: Vec<_> = hub
        .snapshot()
        .unwrap_or_default()
        .into_iter()
        .flat_map(|s| s.tunnels.into_iter().filter(|t| t.info.name == share.name))
        .collect();
    let running = !sides.is_empty()
        && sides.iter().all(|side| {
            side.info.active != Some(false)
                && side
                    .info
                    .status
                    .as_ref()
                    .is_some_and(|st| st.peer.connected)
        });
    let state = if expired > 0 || (expires_at > 0 && t >= expires_at) {
        "expired"
    } else if stopped > 0 || (limit > 0 && used >= limit) {
        "limit"
    } else if running {
        "running"
    } else {
        "stopped"
    };
    let restart_wait = (share.last_restart + RESTART_EVERY - t).max(0);
    let series = |range| {
        hub.history
            .series(&format!("tun:{}:rate", share.name), range)
            .unwrap_or_default()
    };
    PageData {
        title: if share.title.is_empty() {
            share.name.clone()
        } else {
            share.title.clone()
        },
        used,
        limit_bytes: limit,
        pct: pct.min(100.0),
        expires_at,
        days_left: (expires_at > 0).then(|| ((expires_at - t).max(0) + 86_399) / 86_400),
        state,
        can_restart: matches!(state, "running" | "stopped") && restart_wait == 0,
        restart_wait,
        rate_24h: series(Range::Day),
        rate_7d: series(Range::Week),
    }
}

// ---- the routes ----

type Peer = Option<Extension<ConnectInfo<SocketAddr>>>;

fn ip_of(peer: &Peer) -> IpAddr {
    peer.as_ref().map_or(
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        |Extension(ConnectInfo(a))| a.ip(),
    )
}

/// A token bucket per address: [`PER_MINUTE`] requests, refilled over the minute.
static BUCKETS: Mutex<Option<HashMap<IpAddr, (f64, Instant)>>> = Mutex::new(None);

fn allowed(ip: IpAddr) -> bool {
    let mut guard = BUCKETS.lock().unwrap_or_else(|e| e.into_inner());
    let map = guard.get_or_insert_with(HashMap::new);
    let at = Instant::now();
    if map.len() > 10_000 {
        map.retain(|_, (_, seen)| at.duration_since(*seen) < Duration::from_secs(60));
    }
    let entry = map.entry(ip).or_insert((PER_MINUTE, at));
    let refill = at.duration_since(entry.1).as_secs_f64() * PER_MINUTE / 60.0;
    entry.0 = (entry.0 + refill).min(PER_MINUTE);
    entry.1 = at;
    if entry.0 >= 1.0 {
        entry.0 -= 1.0;
        true
    } else {
        false
    }
}

pub fn routes(state: AppState) -> Router {
    Router::new()
        .route("/s/{token}", get(page))
        .route("/s/{token}/data", get(data_json))
        .route("/s/{token}/restart", post(restart))
        .with_state(state)
}

/// The page a link names, or the answer to give instead (slow down, or the plain 404).
async fn lookup(state: &AppState, peer: &Peer, token: &str) -> Result<Share, Response> {
    if !allowed(ip_of(peer)) {
        return Err((StatusCode::TOO_MANY_REQUESTS, "slow down").into_response());
    }
    let found = if token.len() == 32 && token.bytes().all(|b| b.is_ascii_hexdigit()) {
        by_token(&state.db, token).ok().flatten()
    } else {
        None
    };
    match found {
        Some(share) => Ok(share),
        None => {
            tokio::time::sleep(UNKNOWN_DELAY).await;
            Err(crate::http::not_found())
        }
    }
}

#[derive(Deserialize)]
struct PageQuery {
    #[serde(default)]
    msg: String,
}

async fn page(
    State(state): State<AppState>,
    peer: Peer,
    headers: HeaderMap,
    Path(token): Path<String>,
    Query(query): Query<PageQuery>,
) -> Response {
    let share = match lookup(&state, &peer, &token).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    viewed(&state.db, &share.name);
    let fa = headers
        .get(header::ACCEPT_LANGUAGE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|l| {
            let l = l.to_ascii_lowercase();
            l.starts_with("fa") || l.contains(",fa")
        });
    let html = render(&data(&state.hub, &share), &token, fa, &query.msg);
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (
                header::CONTENT_SECURITY_POLICY,
                "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'",
            ),
            (header::CACHE_CONTROL, "no-store"),
            (HeaderName::from_static("x-robots-tag"), "noindex"),
        ],
        html,
    )
        .into_response()
}

async fn data_json(
    State(state): State<AppState>,
    peer: Peer,
    Path(token): Path<String>,
) -> Response {
    match lookup(&state, &peer, &token).await {
        Ok(share) => Json(data(&state.hub, &share)).into_response(),
        Err(r) => r,
    }
}

async fn restart(State(state): State<AppState>, peer: Peer, Path(token): Path<String>) -> Response {
    let share = match lookup(&state, &peer, &token).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let d = data(&state.hub, &share);
    let msg = if !d.can_restart {
        match d.state {
            "limit" => "limit",
            "expired" => "expired",
            _ => "wait",
        }
    } else {
        match crate::pair::control(&state.hub, &share.name, "restart") {
            Ok(_) => {
                let t = now();
                restarted(&state.db, &share.name, t);
                let _ = state.db.audit(
                    "share",
                    Some(&ip_of(&peer).to_string()),
                    &format!("restarted tunnel {} from its renter's page", share.name),
                );
                state.hub.history.event("share_restart", &share.name, "");
                "restarting"
            }
            Err(e) if format!("{e:#}") == "busy" => "wait",
            Err(_) => "failed",
        }
    };
    Redirect::to(&format!("/s/{token}?msg={msg}")).into_response()
}

// ---- the page ----

fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            c => out.push(c),
        }
    }
    out
}

fn human(n: i64) -> String {
    let n = n.max(0) as f64;
    let units = ["B", "KB", "MB", "GB", "TB", "PB"];
    let mut v = n;
    let mut i = 0;
    while v >= 1024.0 && i < units.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 || v >= 100.0 {
        format!("{} {}", v.round() as i64, units[i])
    } else {
        format!("{v:.1} {}", units[i])
    }
}

fn date(unix: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(unix)
        .map(|d| format!("{:04}-{:02}-{:02}", d.year(), d.month() as u8, d.day()))
        .unwrap_or_default()
}

/// A line chart of a rate series, as inline SVG; a note when there is nothing to draw.
fn chart(points: &[(i64, f64)], empty: &str) -> String {
    const W: f64 = 600.0;
    const H: f64 = 140.0;
    const PAD: f64 = 8.0;
    if points.len() < 2 {
        return format!("<p class=\"muted\">{}</p>", esc(empty));
    }
    let (t0, t1) = (points[0].0, points[points.len() - 1].0);
    let span = (t1 - t0).max(1) as f64;
    let max = points.iter().map(|p| p.1).fold(0.0_f64, f64::max).max(0.01);
    let mut line = String::new();
    for (t, v) in points {
        let x = PAD + (*t - t0) as f64 / span * (W - 2.0 * PAD);
        let y = H - PAD - (v / max) * (H - 2.0 * PAD);
        let _ = write!(line, "{x:.1},{y:.1} ");
    }
    let area = format!(
        "{PAD:.1},{bottom:.1} {line}{right:.1},{bottom:.1}",
        bottom = H - PAD,
        right = PAD + (W - 2.0 * PAD)
    );
    format!(
        "<svg viewBox=\"0 0 {W} {H}\" role=\"img\" aria-label=\"chart\" preserveAspectRatio=\"none\">\
         <polygon class=\"area\" points=\"{area}\"/>\
         <polyline class=\"line\" fill=\"none\" points=\"{line}\"/>\
         <text x=\"{PAD}\" y=\"16\" class=\"max\">{max:.1} Mbit/s</text></svg>"
    )
}

struct Words {
    used: &'static str,
    of: &'static str,
    volume_only_time: &'static str,
    time: &'static str,
    days_left: &'static str,
    ends: &'static str,
    no_end: &'static str,
    state: [&'static str; 4],
    restart: &'static str,
    wait: &'static str,
    msg_restarting: &'static str,
    msg_wait: &'static str,
    msg_limit: &'static str,
    msg_expired: &'static str,
    msg_failed: &'static str,
    last_day: &'static str,
    last_week: &'static str,
    no_data: &'static str,
    refresh: &'static str,
}

const EN: Words = Words {
    used: "Usage",
    of: "of",
    volume_only_time: "No volume limit: this tunnel is limited by time.",
    time: "Time",
    days_left: "days left",
    ends: "ends on",
    no_end: "No end date.",
    state: [
        "Running",
        "Stopped",
        "Stopped: the volume is used up",
        "Stopped: the time is up",
    ],
    restart: "Restart the tunnel",
    wait: "A restart can be asked again in {m} minutes.",
    msg_restarting: "Restarting; this page refreshes by itself.",
    msg_wait: "Too soon: a restart can be asked once in five minutes.",
    msg_limit: "The volume is used up; the tunnel stays stopped until the limit is raised.",
    msg_expired: "The time is up; the tunnel stays stopped until it is extended.",
    msg_failed: "The restart could not be started; try again in a minute.",
    last_day: "Last 24 hours",
    last_week: "Last 7 days",
    no_data: "No data yet.",
    refresh: "This page refreshes every 30 seconds.",
};

const FA: Words = Words {
    used: "مصرف",
    of: "از",
    volume_only_time: "سقف حجمی ندارد: این تانل با زمان محدود است.",
    time: "زمان",
    days_left: "روز مانده",
    ends: "پایان در",
    no_end: "تاریخ پایان ندارد.",
    state: [
        "در حال اجرا",
        "متوقف",
        "متوقف: حجم تمام شده",
        "متوقف: مهلت تمام شده",
    ],
    restart: "راه‌اندازی دوبارهٔ تانل",
    wait: "راه‌اندازی دوباره تا {m} دقیقهٔ دیگر دوباره ممکن است.",
    msg_restarting: "در حال راه‌اندازی دوباره؛ این صفحه خودش تازه می‌شود.",
    msg_wait: "زود است: راه‌اندازی دوباره هر پنج دقیقه یک بار ممکن است.",
    msg_limit: "حجم تمام شده؛ تانل تا بالا رفتن سقف متوقف می‌ماند.",
    msg_expired: "مهلت تمام شده؛ تانل تا تمدید متوقف می‌ماند.",
    msg_failed: "راه‌اندازی دوباره شروع نشد؛ یک دقیقهٔ دیگر دوباره امتحان کنید.",
    last_day: "۲۴ ساعت گذشته",
    last_week: "۷ روز گذشته",
    no_data: "هنوز داده‌ای نیست.",
    refresh: "این صفحه هر ۳۰ ثانیه تازه می‌شود.",
};

const STYLE: &str = "\
:root{color-scheme:light dark;--bg:#0f1420;--card:#171e2e;--text:#e8edf5;--muted:#8a94a8;--line:#2a3348;--ok:#3ec98a;--warn:#f0b35a;--bad:#f06565;--accent:#5aa9ff}\
@media (prefers-color-scheme:light){:root{--bg:#f4f6fa;--card:#fff;--text:#172033;--muted:#5d6980;--line:#dde3ee}}\
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:16px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}\
main{max-width:640px;margin:0 auto;padding:24px 16px 48px}h1{font-size:1.4rem;margin:0 0 4px}h2{font-size:.85rem;color:var(--muted);text-transform:uppercase;letter-spacing:.04em;margin:0 0 8px}\
section{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px;margin:12px 0}\
.state{display:inline-block;padding:4px 10px;border-radius:999px;font-weight:600;margin:0 0 8px;background:var(--line)}\
.s-running{background:color-mix(in srgb,var(--ok) 20%,transparent);color:var(--ok)}.s-limit,.s-expired{background:color-mix(in srgb,var(--bad) 20%,transparent);color:var(--bad)}.s-stopped{background:color-mix(in srgb,var(--warn) 20%,transparent);color:var(--warn)}\
.bar{height:10px;border-radius:999px;background:var(--line);overflow:hidden;margin:8px 0}.bar i{display:block;height:100%;background:var(--accent)}.bar.over i{background:var(--bad)}\
.big{font-size:1.3rem;font-weight:600}.muted{color:var(--muted);margin:4px 0 0}\
svg{width:100%;height:140px;display:block}.area{fill:color-mix(in srgb,var(--accent) 18%,transparent)}.line{stroke:var(--accent);stroke-width:2}.max{fill:var(--muted);font-size:12px}\
button{font:inherit;font-weight:600;padding:10px 18px;border-radius:10px;border:1px solid var(--accent);background:var(--accent);color:#fff;cursor:pointer}button[disabled]{opacity:.5;cursor:default}\
.msg{margin:8px 0 0}footer{color:var(--muted);font-size:.85rem;text-align:center;margin-top:24px}";

fn render(d: &PageData, token: &str, fa: bool, msg: &str) -> String {
    let w = if fa { &FA } else { &EN };
    let (lang, dir) = if fa { ("fa", "rtl") } else { ("en", "ltr") };
    let state_text = match d.state {
        "running" => w.state[0],
        "stopped" => w.state[1],
        "limit" => w.state[2],
        _ => w.state[3],
    };
    let volume = if d.limit_bytes > 0 {
        format!(
            "<div class=\"bar{}\"><i style=\"width:{:.1}%\"></i></div><p class=\"big\">{} {} {}</p><p class=\"muted\">{:.0}%</p>",
            if d.used >= d.limit_bytes { " over" } else { "" },
            d.pct.clamp(0.5, 100.0),
            human(d.used),
            w.of,
            human(d.limit_bytes),
            d.pct
        )
    } else {
        format!(
            "<p class=\"big\">{}</p><p class=\"muted\">{}</p>",
            human(d.used),
            w.volume_only_time
        )
    };
    let time = match d.days_left {
        Some(days) => format!(
            "<p class=\"big\">{days} {}</p><p class=\"muted\">{} {}</p>",
            w.days_left,
            w.ends,
            date(d.expires_at)
        ),
        None => format!("<p class=\"muted\">{}</p>", w.no_end),
    };
    let note = match msg {
        "restarting" => w.msg_restarting,
        "wait" => w.msg_wait,
        "limit" => w.msg_limit,
        "expired" => w.msg_expired,
        "failed" => w.msg_failed,
        _ => "",
    };
    let wait = if d.restart_wait > 0 && matches!(d.state, "running" | "stopped") {
        format!(
            "<p class=\"muted\">{}</p>",
            w.wait
                .replace("{m}", &((d.restart_wait + 59) / 60).to_string())
        )
    } else {
        String::new()
    };
    format!(
        "<!doctype html><html lang=\"{lang}\" dir=\"{dir}\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <meta http-equiv=\"refresh\" content=\"30\"><meta name=\"robots\" content=\"noindex\">\
         <title>{title}</title><style>{STYLE}</style></head><body><main>\
         <h1>{title}</h1><p class=\"state s-{state}\">{state_text}</p>\
         <section><h2>{used}</h2>{volume}</section>\
         <section><h2>{time_h}</h2>{time}</section>\
         <section><h2>{last_day}</h2>{chart_day}</section>\
         <section><h2>{last_week}</h2>{chart_week}</section>\
         <section><form method=\"post\" action=\"/s/{token}/restart\"><button type=\"submit\"{disabled}>{restart}</button></form>{wait}\
         <p class=\"msg\">{note}</p></section>\
         <footer>{refresh}</footer></main></body></html>",
        title = esc(&d.title),
        state = d.state,
        used = w.used,
        time_h = w.time,
        last_day = w.last_day,
        last_week = w.last_week,
        chart_day = chart(&d.rate_24h, w.no_data),
        chart_week = chart(&d.rate_7d, w.no_data),
        disabled = if d.can_restart { "" } else { " disabled" },
        restart = w.restart,
        note = esc(note),
        refresh = w.refresh,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_page_is_made_for_a_limited_tunnel_found_by_its_link_and_revoked() {
        let db = Db::in_memory().unwrap();
        assert!(
            make(&db, "demo", "Office").unwrap().is_none(),
            "no limit yet"
        );
        crate::quota::write(&db, "demo", crate::quota::MIN_LIMIT, 0, 0).unwrap();
        let first = make(&db, "demo", " Office ").unwrap().expect("made");
        assert_eq!(first.title, "Office");
        assert_eq!(first.token.len(), 32);
        assert_eq!(by_token(&db, &first.token).unwrap().as_ref(), Some(&first));
        assert_eq!(of(&db, "demo").unwrap().as_ref(), Some(&first));
        assert_eq!(all(&db).unwrap().len(), 1);
        // Made again: a new link; the old one is dead.
        let again = make(&db, "demo", "Office").unwrap().unwrap();
        assert_ne!(again.token, first.token);
        assert!(by_token(&db, &first.token).unwrap().is_none());
        assert!(make(&db, "demo", &"x".repeat(81)).is_err());
        assert!(make(&db, "../x", "").is_err());
        assert!(revoke(&db, "demo").unwrap());
        assert!(!revoke(&db, "demo").unwrap());
        assert!(by_token(&db, &again.token).unwrap().is_none());
    }

    #[test]
    fn each_address_gets_ten_a_minute() {
        let ip: IpAddr = "203.0.113.77".parse().unwrap();
        let mut taken = 0;
        for _ in 0..12 {
            if allowed(ip) {
                taken += 1;
            }
        }
        assert_eq!(taken, 10);
        assert!(allowed("203.0.113.78".parse().unwrap()), "another address");
    }

    #[test]
    fn the_page_escapes_its_title_and_says_the_state() {
        let d = PageData {
            title: "A <b>\"renter\"</b>".into(),
            used: 3 << 30,
            limit_bytes: 10 << 30,
            pct: 30.0,
            expires_at: now() + 5 * 86_400,
            days_left: Some(5),
            state: "running",
            can_restart: true,
            restart_wait: 0,
            rate_24h: vec![(1, 0.5), (2, 1.5), (3, 1.0)],
            rate_7d: Vec::new(),
        };
        let html = render(&d, "0123456789abcdef0123456789abcdef", false, "");
        assert!(html.contains("A &lt;b&gt;&quot;renter&quot;&lt;/b&gt;"));
        assert!(html.contains("3.0 GB of 10.0 GB") && html.contains("5 days left"));
        assert!(html.contains("<polyline") && html.contains("No data yet."));
        assert!(html.contains("<button type=\"submit\">Restart the tunnel"));
        let fa = render(&d, "0123456789abcdef0123456789abcdef", true, "limit");
        assert!(fa.contains("dir=\"rtl\"") && fa.contains("حجم تمام شده"));
        assert_eq!(human(1536), "1.5 KB");
        assert_eq!(human(100 << 20), "100 MB");
    }
}
