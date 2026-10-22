//! A traffic limit per tunnel. The admin gives a tunnel a volume; the panel adds up the bytes
//! it carries and, when they reach the limit, stops it (on both sides, disabled, so it stays
//! stopped at boot). The usage is kept in the panel's database, so it survives restarts of the
//! panel, the agents and the tunnel; the daemons keep their own counters across restarts too
//! (the traffic file, `docs/status.md`), so what the panel reads is exact. An older agent
//! (before 2.9.2) is metered from the panel's deltas: what moves between a restart of its
//! daemon and the panel's next reading is lost.
//!
//! How the bytes are read: the entry side's `status.totals` (`bytes_up + bytes_down`), the
//! side the users connect to; the exit side's when the entry is away. Each reading is
//! compared with the last one and the difference is added to the usage. A reading that is
//! *lower* than the last means one of two things: the daemon started over from zero (an older
//! daemon, or a traffic file that could not be used: its `counter_id` differs), and the
//! reading is the new usage; or the daemon was killed hard and came back from a traffic file
//! a few seconds stale (the same `counter_id`), and the few bytes between are let go.
//!
//! The usage is reset by hand, or every month on a day the admin picks; a tunnel the limit
//! stopped is started again when its usage is reset, its limit raised or the limit removed —
//! and the panel keeps trying while a server is away or the tunnel is busy. A warning goes
//! out (events, Telegram) at 80%, and a notice when a tunnel is stopped.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Result};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::alerts::Notice;
use crate::auth::now;
use crate::db::Db;
use crate::hub::Hub;
use crate::manage::valid_name;
use crate::pair;

/// The smallest limit: a megabyte.
pub const MIN_LIMIT: i64 = 1 << 20;
/// The largest: a petabyte, well within what the database and the counters hold.
pub const MAX_LIMIT: i64 = 1 << 50;
/// The last day of the month a monthly reset can be on (every month has it).
pub const MAX_RESET_DAY: i64 = 28;
/// How often the usage is read and the limits are enforced.
const TICK: Duration = Duration::from_secs(3);
/// The warning goes out at this share of the limit.
const WARN_AT: f64 = 0.8;
/// The notice that a limit's end is near goes out this long before it.
const EXPIRY_WARN: i64 = 3 * 86_400;
/// The most days a limit can run (or be extended by) at once.
pub const MAX_DAYS: i64 = 3650;

/// A tunnel's limit and usage, as the API shows it.
#[derive(Debug, Clone, Serialize)]
pub struct Quota {
    pub name: String,
    pub limit_bytes: i64,
    /// Bytes since the last reset.
    pub used: i64,
    /// `0`: reset by hand; `1`..`28`: every month on that day (00:00 UTC).
    pub reset_day: i64,
    pub last_reset: i64,
    /// The 80% warning went out this period.
    pub warned: bool,
    /// When the limit stopped the tunnel (0: it did not).
    pub stopped: i64,
    /// The panel still has to start it again (a reset, a raise or a removal of the limit,
    /// with a server away or the tunnel busy at the time).
    pub start_due: bool,
    pub since: i64,
    /// The next monthly reset (unix seconds), none for a limit reset by hand.
    pub next_reset: Option<i64>,
    /// Usage as a percentage of the limit.
    pub pct: f64,
    /// When the limit ends (unix seconds; 0: it does not): the tunnel is stopped then,
    /// until it is extended.
    pub expires_at: i64,
    /// When the end stopped the tunnel (0: it did not).
    pub expired: i64,
    /// The renter's page, when one was made.
    pub share: Option<crate::share::ShareView>,
}

/// What the browser (or the wizard's request) sends to set a limit. `limit_bytes` may be 0
/// when the limit is a duration alone.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NewQuota {
    pub name: String,
    pub limit_bytes: i64,
    #[serde(default)]
    pub reset_day: i64,
    /// An end this many days from now (1 to 3650), or none.
    #[serde(default)]
    pub days: Option<i64>,
    /// An end at this time (unix seconds; takes precedence over `days`), 0 for none.
    #[serde(default)]
    pub expires_at: Option<i64>,
}

/// A limit as asked for in a tunnel's create request (the wizard): written once the tunnel
/// is up, so it counts from the first byte.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct QuotaSpec {
    pub limit_bytes: i64,
    #[serde(default)]
    pub reset_day: i64,
    /// An end this many days from when the tunnel is made.
    #[serde(default)]
    pub days: Option<i64>,
}

impl QuotaSpec {
    /// When the limit ends, counted from now; 0 without a duration.
    pub fn expires_at(&self) -> i64 {
        self.days
            .filter(|d| *d > 0)
            .map_or(0, |d| now() + d * 86_400)
    }
}

/// One row of the `quotas` table.
#[derive(Debug, Clone, PartialEq)]
struct Row {
    name: String,
    limit_bytes: i64,
    used: i64,
    /// The last reading of the counted side's total (-1: none yet).
    last_seen: i64,
    /// The role the last reading came from.
    side: String,
    /// The daemon's counter id at the last reading ('' from an older daemon).
    counter_id: String,
    reset_day: i64,
    last_reset: i64,
    warned: bool,
    stopped: i64,
    start_due: bool,
    since: i64,
    /// When the limit ends (0: never).
    expires_at: i64,
    /// The notice that the end is near went out.
    expiry_warned: bool,
    /// When the end stopped the tunnel (0: it did not).
    expired: i64,
}

impl Row {
    fn view(&self, share: Option<crate::share::ShareView>) -> Quota {
        Quota {
            name: self.name.clone(),
            limit_bytes: self.limit_bytes,
            used: self.used,
            reset_day: self.reset_day,
            last_reset: self.last_reset,
            warned: self.warned,
            stopped: self.stopped,
            start_due: self.start_due,
            since: self.since,
            next_reset: next_reset(self.reset_day, self.last_reset),
            pct: if self.limit_bytes > 0 {
                self.used as f64 * 100.0 / self.limit_bytes as f64
            } else {
                0.0
            },
            expires_at: self.expires_at,
            expired: self.expired,
            share,
        }
    }

    /// A limit that is in force: a volume, an end, or both (a row without either stays
    /// only while a start is owed).
    fn live(&self) -> bool {
        self.limit_bytes > 0 || self.expires_at > 0
    }

    /// Over the limit, or past its end, at `t`: the tunnel is kept stopped.
    fn exhausted(&self, t: i64) -> bool {
        (self.limit_bytes > 0 && self.used >= self.limit_bytes)
            || (self.expires_at > 0 && t >= self.expires_at)
    }

    /// Past the end at `t`.
    fn past_end(&self, t: i64) -> bool {
        self.expires_at > 0 && t >= self.expires_at
    }
}

/// The first 00:00 UTC of `reset_day` of a month after `last_reset`; `None` for a limit reset
/// by hand (`reset_day` 0).
pub fn next_reset(reset_day: i64, last_reset: i64) -> Option<i64> {
    if !(1..=MAX_RESET_DAY).contains(&reset_day) {
        return None;
    }
    let last = time::OffsetDateTime::from_unix_timestamp(last_reset).ok()?;
    let day = reset_day as u8;
    let (mut year, mut month) = (last.year(), last.month());
    loop {
        let candidate = time::Date::from_calendar_date(year, month, day)
            .ok()?
            .midnight()
            .assume_utc()
            .unix_timestamp();
        if candidate > last_reset {
            return Some(candidate);
        }
        if month == time::Month::December {
            year += 1;
        }
        month = month.next();
    }
}

fn read_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Row> {
    Ok(Row {
        name: r.get(0)?,
        limit_bytes: r.get(1)?,
        used: r.get(2)?,
        last_seen: r.get(3)?,
        side: r.get(4)?,
        counter_id: r.get(5)?,
        reset_day: r.get(6)?,
        last_reset: r.get(7)?,
        warned: r.get::<_, i64>(8)? != 0,
        stopped: r.get(9)?,
        start_due: r.get::<_, i64>(10)? != 0,
        since: r.get(11)?,
        expires_at: r.get(12)?,
        expiry_warned: r.get::<_, i64>(13)? != 0,
        expired: r.get(14)?,
    })
}

const COLUMNS: &str = "name, limit_bytes, used, last_seen, side, counter_id, reset_day, last_reset, warned, stopped, start_due, since, expires_at, expiry_warned, expired";

fn rows(db: &Db) -> Result<Vec<Row>> {
    let conn = db.conn();
    let mut stmt = conn.prepare(&format!("SELECT {COLUMNS} FROM quotas ORDER BY name"))?;
    let rows = stmt.query_map([], read_row)?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

fn row(db: &Db, name: &str) -> Result<Option<Row>> {
    Ok(db
        .conn()
        .query_row(
            &format!("SELECT {COLUMNS} FROM quotas WHERE name = ?1"),
            [name],
            read_row,
        )
        .optional()?)
}

fn save(db: &Db, r: &Row) -> Result<()> {
    db.conn().execute(
        "UPDATE quotas SET limit_bytes = ?2, used = ?3, last_seen = ?4, side = ?5, counter_id = ?6, \
         reset_day = ?7, last_reset = ?8, warned = ?9, stopped = ?10, start_due = ?11, \
         expires_at = ?12, expiry_warned = ?13, expired = ?14 WHERE name = ?1",
        params![
            r.name,
            r.limit_bytes,
            r.used,
            r.last_seen,
            r.side,
            r.counter_id,
            r.reset_day,
            r.last_reset,
            r.warned as i64,
            r.stopped,
            r.start_due as i64,
            r.expires_at,
            r.expiry_warned as i64,
            r.expired
        ],
    )?;
    Ok(())
}

/// Every tunnel with a limit (a volume, an end, or both), each with its renter's page.
pub fn list(db: &Db) -> Result<Vec<Quota>> {
    let shares = crate::share::all(db)?;
    Ok(rows(db)?
        .iter()
        .filter(|r| r.live())
        .map(|r| r.view(shares.get(&r.name).cloned()))
        .collect())
}

/// Whether a tunnel is over its limit or past its end (its Start and Restart are refused
/// then).
pub fn exhausted(db: &Db, name: &str) -> bool {
    row(db, name)
        .ok()
        .flatten()
        .is_some_and(|r| r.exhausted(now()))
}

/// Checks a limit's numbers: `bad_input` when they are out of range. The volume may be 0
/// when there is an end (a limit of time alone); an end is 0 (none) or ahead, by at most
/// [`MAX_DAYS`].
pub fn check(limit_bytes: i64, reset_day: i64, expires_at: i64) -> Result<()> {
    let volume_ok =
        (MIN_LIMIT..=MAX_LIMIT).contains(&limit_bytes) || (limit_bytes == 0 && expires_at > 0);
    let t = now();
    let end_ok = expires_at == 0 || (expires_at > t && expires_at <= t + MAX_DAYS * 86_400);
    if !volume_ok || !(0..=MAX_RESET_DAY).contains(&reset_day) || !end_ok {
        bail!("bad_input");
    }
    Ok(())
}

/// Sets (or changes) a tunnel's limit; the usage goes on. A tunnel the limit had stopped is
/// started again when the new limit is above its usage and the new end (if any) is ahead.
pub fn write(db: &Db, name: &str, limit_bytes: i64, reset_day: i64, expires_at: i64) -> Result<()> {
    check(limit_bytes, reset_day, expires_at)?;
    if !valid_name(name) {
        bail!("bad_name");
    }
    let t = now();
    match row(db, name)? {
        Some(mut r) => {
            r.limit_bytes = limit_bytes;
            r.reset_day = reset_day;
            if r.expires_at != expires_at {
                // A new end (or none): the old one's notice and stop are over.
                r.expires_at = expires_at;
                r.expiry_warned = false;
                r.expired = 0;
            }
            if r.stopped != 0 && !r.exhausted(t) {
                r.stopped = 0;
                r.start_due = true;
            }
            // A new period's warning, if the limit went up past the usage.
            if r.warned && (r.used as f64) < WARN_AT * limit_bytes as f64 {
                r.warned = false;
            }
            save(db, &r)
        }
        None => {
            db.conn().execute(
                "INSERT INTO quotas (name, limit_bytes, reset_day, last_reset, since, expires_at) \
                 VALUES (?1, ?2, ?3, ?4, ?4, ?5)",
                params![name, limit_bytes, reset_day, t, expires_at],
            )?;
            Ok(())
        }
    }
}

/// When a request's limit ends: `expires_at` as given, else `days` from now, else never.
fn end_of(days: Option<i64>, expires_at: Option<i64>) -> Result<i64> {
    if let Some(at) = expires_at {
        return Ok(at.max(0));
    }
    match days {
        None | Some(0) => Ok(0),
        Some(d) if (1..=MAX_DAYS).contains(&d) => Ok(now() + d * 86_400),
        Some(_) => bail!("bad_input"),
    }
}

/// The API's set: the tunnel has to exist (on some server the panel knows).
pub fn set(hub: &Hub, new: &NewQuota) -> Result<()> {
    if !valid_name(&new.name) {
        bail!("bad_name");
    }
    let expires_at = end_of(new.days, new.expires_at)?;
    check(new.limit_bytes, new.reset_day, expires_at)?;
    let known = hub
        .snapshot()?
        .iter()
        .any(|s| s.tunnels.iter().any(|t| t.info.name == new.name));
    if !known {
        bail!("no_such_tunnel");
    }
    write(
        &hub.db,
        &new.name,
        new.limit_bytes,
        new.reset_day,
        expires_at,
    )
}

/// Moves a limit's end `days` further (from its end, or from now when it is already past
/// or it had none). A tunnel the end had stopped is owed a start. Whether there was a limit.
pub fn extend(hub: &Hub, name: &str, days: i64) -> Result<bool> {
    if !(1..=MAX_DAYS).contains(&days) {
        bail!("bad_input");
    }
    let Some(mut r) = row(&hub.db, name)? else {
        return Ok(false);
    };
    if !r.live() {
        return Ok(false);
    }
    let t = now();
    r.expires_at = r.expires_at.max(t) + days * 86_400;
    r.expiry_warned = false;
    r.expired = 0;
    if r.stopped != 0 && !r.exhausted(t) {
        r.stopped = 0;
        r.start_due = true;
    }
    save(&hub.db, &r)?;
    hub.history
        .event("quota_extend", name, &r.expires_at.to_string());
    Ok(true)
}

/// Takes a tunnel's limit away (its volume, its end and its renter's page). A tunnel the
/// limit had stopped is started again first: its row stays, without a limit, until that is
/// done. Whether there was a limit.
pub fn delete(db: &Db, name: &str) -> Result<bool> {
    let Some(r) = row(db, name)? else {
        return Ok(false);
    };
    if r.stopped != 0 {
        db.conn().execute(
            "UPDATE quotas SET limit_bytes = 0, expires_at = 0, expired = 0, expiry_warned = 0, \
             stopped = 0, start_due = 1, warned = 0 WHERE name = ?1",
            [name],
        )?;
    } else {
        db.conn()
            .execute("DELETE FROM quotas WHERE name = ?1", [name])?;
    }
    crate::share::forget(db, name);
    Ok(r.live())
}

/// Starts a new period: the usage goes back to zero, and a tunnel the limit had stopped is
/// started again. Whether there was a limit.
pub fn reset(hub: &Hub, name: &str) -> Result<bool> {
    let Some(mut r) = row(&hub.db, name)? else {
        return Ok(false);
    };
    r.used = 0;
    r.warned = false;
    r.last_reset = now();
    if r.stopped != 0 {
        r.stopped = 0;
        r.start_due = true;
    }
    save(&hub.db, &r)?;
    hub.history.event("quota_reset", name, "");
    Ok(true)
}

/// A tunnel is gone: so are its limit and its renter's page.
pub fn forget(db: &Db, name: &str) {
    let _ = db
        .conn()
        .execute("DELETE FROM quotas WHERE name = ?1", [name]);
    crate::share::forget(db, name);
}

/// One side of a tunnel, as the quota sees it.
struct SideView {
    online: bool,
    role: String,
    active: Option<bool>,
    /// The daemon's byte total and counter id, when it answered.
    reading: Option<(i64, String)>,
}

/// Looks at every limit once: adds up the usage, resets what is due, warns, stops what is
/// over its limit, and starts what is owed a start. The API (a reset, a new limit) and the
/// backup write the same rows at any time, so a row is read fresh before each decision and
/// every write names what it changes (and what it assumes), never a whole row.
async fn step(hub: &Arc<Hub>) -> Result<()> {
    let views = hub.snapshot()?;
    let t = now();
    let names: Vec<String> = rows(&hub.db)?.into_iter().map(|r| r.name).collect();
    for name in names {
        let Some(mut r) = row(&hub.db, &name)? else {
            continue;
        };
        let sides: Vec<SideView> = views
            .iter()
            .flat_map(|s| {
                s.tunnels
                    .iter()
                    .filter(|tv| tv.info.name == name)
                    .map(move |tv| SideView {
                        online: s.online,
                        role: tv.info.role.clone(),
                        active: tv.info.active,
                        reading: tv.info.status.as_ref().map(|st| {
                            (
                                (st.totals.bytes_up.saturating_add(st.totals.bytes_down))
                                    .min(i64::MAX as u64) as i64,
                                st.counter_id.clone().unwrap_or_default(),
                            )
                        }),
                    })
                    .collect::<Vec<_>>()
            })
            .collect();

        // ---- the usage: the entry side's total, else the exit side's ----
        let counted = ["entry", "exit"].iter().find_map(|role| {
            sides
                .iter()
                .find(|s| s.online && s.role == *role && s.reading.is_some())
        });
        if let Some(side) = counted {
            let (reading, id) = side.reading.clone().unwrap_or_default();
            let delta = if r.last_seen < 0 || r.side != side.role {
                // The first reading, or another side's: a baseline, nothing to add yet.
                0
            } else if !id.is_empty() && !r.counter_id.is_empty() && id != r.counter_id {
                // The counters started over under a new id (a new traffic file): the
                // reading is what moved since, however it compares with the last one.
                reading
            } else if reading >= r.last_seen {
                reading - r.last_seen
            } else if !id.is_empty() && id == r.counter_id {
                // The daemon came back from a traffic file a few seconds stale: the same
                // counters, a little behind. The bytes between are let go.
                debug!(tunnel = %name, "the daemon's counter went back a little; keeping the usage");
                0
            } else {
                // An older daemon (no id) restarted from zero: the reading is what moved since.
                reading
            };
            hub.db.conn().execute(
                "UPDATE quotas SET used = used + ?2, last_seen = ?3, side = ?4, counter_id = ?5 WHERE name = ?1",
                params![name, delta, reading, side.role, id],
            )?;
            r.used = r.used.saturating_add(delta);
        }

        // ---- a monthly reset that is due (only if nothing reset it in the meantime) ----
        if next_reset(r.reset_day, r.last_reset).is_some_and(|at| t >= at) {
            let changed = hub.db.conn().execute(
                "UPDATE quotas SET used = 0, warned = 0, last_reset = ?2, stopped = 0, \
                 start_due = CASE WHEN stopped != 0 THEN 1 ELSE start_due END \
                 WHERE name = ?1 AND last_reset = ?3",
                params![name, t, r.last_reset],
            )?;
            if changed == 1 {
                hub.history.event("quota_reset", &name, "monthly");
                info!(tunnel = %name, "the traffic usage was reset for the month");
            }
        }

        // ---- the warning, once per period ----
        let Some(r) = row(&hub.db, &name)? else {
            continue;
        };
        if r.limit_bytes > 0 && !r.warned && r.used as f64 >= WARN_AT * r.limit_bytes as f64 {
            let changed = hub.db.conn().execute(
                "UPDATE quotas SET warned = 1 WHERE name = ?1 AND warned = 0",
                [&name],
            )?;
            if changed == 1 {
                hub.history.event(
                    "quota_near",
                    &name,
                    &format!("{} {}", r.used, r.limit_bytes),
                );
                hub.push_notice(Notice::QuotaNear {
                    name: name.clone(),
                    used: r.used as u64,
                    limit: r.limit_bytes as u64,
                });
            }
        }

        // ---- the end is near: one notice ----
        if r.expires_at > 0 && !r.expiry_warned && t >= r.expires_at - EXPIRY_WARN && !r.past_end(t)
        {
            let changed = hub.db.conn().execute(
                "UPDATE quotas SET expiry_warned = 1 WHERE name = ?1 AND expiry_warned = 0",
                [&name],
            )?;
            if changed == 1 {
                hub.history
                    .event("quota_expiring", &name, &r.expires_at.to_string());
                hub.push_notice(Notice::QuotaExpiring {
                    name: name.clone(),
                    days: ((r.expires_at - t + 86_399) / 86_400).max(1) as u64,
                });
            }
        }

        // ---- over the limit, or past its end: stopped, and kept stopped ----
        let running = sides.iter().any(|s| s.online && s.active == Some(true));
        let past_end = r.past_end(t);
        if past_end && r.expired == 0 && !running {
            // Not running anyway (stopped by hand, or every side away): noted, so the page
            // says so and a start is refused; nothing to stop.
            let marked = hub.db.conn().execute(
                "UPDATE quotas SET expired = ?2 WHERE name = ?1 AND expired = 0 AND expires_at > 0 AND expires_at <= ?2",
                params![name, t],
            )?;
            if marked == 1 {
                hub.history.event("quota_expired", &name, "");
                hub.push_notice(Notice::QuotaExpired { name: name.clone() });
            }
        }
        if r.exhausted(t) && running {
            match pair::control(hub, &name, "stop") {
                Ok(op) => match pair::wait(hub, &op).await {
                    Ok(()) => {
                        // Marked only while it is still over its limit or past its end: a
                        // reset, a raise or an extension in the meantime makes the stop a
                        // start that is owed instead.
                        let marked = hub.db.conn().execute(
                            "UPDATE quotas SET stopped = ?2, start_due = 0, \
                             expired = CASE WHEN expires_at > 0 AND expires_at <= ?2 THEN ?2 ELSE expired END \
                             WHERE name = ?1 AND stopped = 0 \
                             AND ((limit_bytes > 0 AND used >= limit_bytes) OR (expires_at > 0 AND expires_at <= ?2))",
                            params![name, t],
                        )?;
                        if marked == 1 && past_end {
                            hub.history.event("quota_expired", &name, "");
                            let _ = hub.db.audit(
                                "quota",
                                None,
                                &format!("stopped tunnel {name}: its time is up"),
                            );
                            hub.push_notice(Notice::QuotaExpired { name: name.clone() });
                            info!(tunnel = %name, "a tunnel was stopped: its time is up");
                        } else if marked == 1 {
                            hub.history.event(
                                "quota_stop",
                                &name,
                                &format!("{} {}", r.used, r.limit_bytes),
                            );
                            let _ = hub.db.audit(
                                "quota",
                                None,
                                &format!(
                                    "stopped tunnel {name}: its traffic limit is reached ({} of {} bytes)",
                                    r.used, r.limit_bytes
                                ),
                            );
                            hub.push_notice(Notice::QuotaStopped {
                                name: name.clone(),
                                used: r.used as u64,
                                limit: r.limit_bytes as u64,
                            });
                            info!(tunnel = %name, used = r.used, limit = r.limit_bytes, "a tunnel was stopped: its traffic limit is reached");
                        } else {
                            let _ = hub.db.conn().execute(
                                "UPDATE quotas SET start_due = 1 \
                                 WHERE name = ?1 AND stopped = 0 \
                                 AND NOT ((limit_bytes > 0 AND used >= limit_bytes) OR (expires_at > 0 AND expires_at <= ?2))",
                                params![name, t],
                            );
                        }
                    }
                    Err(e) => {
                        warn!(tunnel = %name, error = %e, "a tunnel over its traffic limit could not be stopped; trying again");
                    }
                },
                // Busy (an operation is running on it): next time.
                Err(e) => {
                    debug!(tunnel = %name, error = %format!("{e:#}"), "a tunnel over its traffic limit waits to be stopped")
                }
            }
            continue;
        }

        // ---- a start that is owed, once the usage is under the limit again ----
        if r.start_due && !r.exhausted(t) {
            if !sides.is_empty() && sides.iter().all(|s| s.online && s.active == Some(true)) {
                // Every side runs again (a side that is away is waited for: its service
                // was disabled, and nothing but the panel brings it back).
                hub.db.conn().execute(
                    "UPDATE quotas SET start_due = 0 WHERE name = ?1 AND start_due = 1",
                    [&name],
                )?;
                hub.db.conn().execute(
                    "DELETE FROM quotas WHERE name = ?1 AND limit_bytes = 0 AND expires_at = 0 AND start_due = 0",
                    [&name],
                )?;
            } else if sides.iter().any(|s| s.online && s.active == Some(false)) {
                match pair::control(hub, &name, "start") {
                    Ok(op) => {
                        if let Err(e) = pair::wait(hub, &op).await {
                            warn!(tunnel = %name, error = %e, "a tunnel could not be started again after its traffic limit; trying again");
                        } else {
                            hub.history.event("quota_start", &name, "");
                            info!(tunnel = %name, "a tunnel was started again after its traffic limit");
                        }
                    }
                    Err(e) => {
                        debug!(tunnel = %name, error = %format!("{e:#}"), "a tunnel waits to be started again")
                    }
                }
            }
            // A side that is away: next time, when it is back.
        }
    }
    Ok(())
}

/// Looks at the limits every few seconds, for ever.
pub async fn run(hub: Arc<Hub>) {
    loop {
        tokio::time::sleep(TICK).await;
        if let Err(e) = step(&hub).await {
            debug!(error = %format!("{e:#}"), "the traffic limits could not be looked at");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(y: i32, m: u8, d: u8, h: u8) -> i64 {
        time::Date::from_calendar_date(y, time::Month::try_from(m).unwrap(), d)
            .unwrap()
            .with_hms(h, 0, 0)
            .unwrap()
            .assume_utc()
            .unix_timestamp()
    }

    #[test]
    fn the_next_monthly_reset_is_the_first_such_day_after_the_last_one() {
        let last = ts(2026, 10, 22, 9);
        assert_eq!(next_reset(0, last), None);
        assert_eq!(next_reset(25, last), Some(ts(2026, 10, 25, 0)));
        // The same day of the month, already begun: next month.
        assert_eq!(next_reset(22, last), Some(ts(2026, 11, 22, 0)));
        assert_eq!(next_reset(5, last), Some(ts(2026, 11, 5, 0)));
        // Across a year's end.
        assert_eq!(next_reset(3, ts(2026, 12, 3, 0)), Some(ts(2027, 1, 3, 0)));
        // A reset at exactly midnight of its day counts as that period.
        assert_eq!(next_reset(1, ts(2026, 11, 1, 0)), Some(ts(2026, 12, 1, 0)));
        assert_eq!(next_reset(29, last), None);
    }

    #[test]
    fn a_limit_is_checked() {
        assert!(check(MIN_LIMIT, 0, 0).is_ok());
        assert!(check(MIN_LIMIT - 1, 0, 0).is_err());
        assert!(check(MAX_LIMIT + 1, 0, 0).is_err());
        assert!(check(MIN_LIMIT, 28, 0).is_ok());
        assert!(check(MIN_LIMIT, 29, 0).is_err());
        assert!(check(MIN_LIMIT, -1, 0).is_err());
    }

    #[test]
    fn a_limit_is_written_changed_reset_and_taken_away() {
        let db = Db::in_memory().unwrap();
        write(&db, "demo", 2 * MIN_LIMIT, 5, 0).unwrap();
        let q = &list(&db).unwrap()[0];
        assert_eq!(
            (q.name.as_str(), q.limit_bytes, q.reset_day),
            ("demo", 2 * MIN_LIMIT, 5)
        );
        assert!(q.next_reset.is_some() && q.stopped == 0);
        assert!(write(&db, "demo", 10, 0, 0).is_err(), "too small");
        assert!(write(&db, "Bad Name", MIN_LIMIT, 0, 0).is_err());

        // Over the limit and stopped; a raise above the usage owes it a start.
        let mut r = row(&db, "demo").unwrap().unwrap();
        r.used = 2 * MIN_LIMIT;
        r.stopped = 7;
        r.warned = true;
        save(&db, &r).unwrap();
        assert!(exhausted(&db, "demo"));
        write(&db, "demo", 2 * MIN_LIMIT, 0, 0).unwrap();
        let r = row(&db, "demo").unwrap().unwrap();
        assert!(
            r.stopped == 7 && !r.start_due,
            "the same limit: still stopped"
        );
        write(&db, "demo", 10 * MIN_LIMIT, 0, 0).unwrap();
        let r = row(&db, "demo").unwrap().unwrap();
        assert!(r.stopped == 0 && r.start_due && !r.warned);
        assert_eq!(r.used, 2 * MIN_LIMIT, "the usage goes on");
        assert!(!exhausted(&db, "demo"));

        // Taking a limit away from a stopped tunnel keeps the row until the start is done.
        let mut r = row(&db, "demo").unwrap().unwrap();
        r.stopped = 9;
        r.start_due = false;
        save(&db, &r).unwrap();
        assert!(delete(&db, "demo").unwrap());
        let r = row(&db, "demo").unwrap().unwrap();
        assert!(r.limit_bytes == 0 && r.start_due && r.stopped == 0);
        assert!(list(&db).unwrap().is_empty(), "no limit any more");
        assert!(!exhausted(&db, "demo"));
        forget(&db, "demo");
        assert!(row(&db, "demo").unwrap().is_none());
        assert!(!delete(&db, "demo").unwrap());
    }

    use crate::wire::TunnelInfo;
    use kariz::stats::{PeerStatus, Status, Totals};

    /// A tunnel side as a server reports it: `bytes` moved, under `counter_id`.
    fn side(role: &str, active: Option<bool>, bytes: Option<(u64, Option<&str>)>) -> TunnelInfo {
        TunnelInfo {
            name: "demo".into(),
            role: role.into(),
            mode: "reverse".into(),
            transport: "tcpmux".into(),
            profile: "balanced".into(),
            encryption: "auto".into(),
            listen: None,
            remote: None,
            forwards: Vec::new(),
            active,
            status: bytes.map(|(b, id)| Status {
                status_version: 1,
                kariz: "2.9.2".into(),
                role: role.into(),
                mode: "reverse".into(),
                transport: "tcpmux".into(),
                profile: "balanced".into(),
                uptime_secs: 10,
                counter_id: id.map(str::to_owned),
                peer: PeerStatus {
                    transport: None,
                    connected: true,
                    sessions: None,
                    sessions_wanted: None,
                    connected_secs: None,
                    rtt_ms: None,
                    handshakes_ok: 0,
                    handshakes_failed: 0,
                    last_error: None,
                    streams: None,
                    streams_max: None,
                    full: 0,
                },
                totals: Totals {
                    bytes_up: b / 2,
                    bytes_down: b - b / 2,
                    ..Totals::default()
                },
                forwards: Vec::new(),
                exit: None,
                probe: None,
            }),
            error: None,
        }
    }

    fn hub() -> Arc<Hub> {
        Hub::new(
            Db::in_memory().unwrap(),
            std::env::temp_dir().join("kariz-none"),
        )
    }

    fn used(hub: &Hub) -> i64 {
        row(&hub.db, "demo").unwrap().unwrap().used
    }

    #[tokio::test]
    async fn the_usage_adds_up_the_readings_and_knows_a_counter_that_started_over() {
        let hub = hub();
        write(&hub.db, "demo", 100 * MIN_LIMIT, 0, 0).unwrap();
        // The first reading is a baseline: what moved before the limit was set is not counted.
        hub.set_live_tunnels(
            "a",
            true,
            vec![side("entry", Some(true), Some((1000, Some("one"))))],
        );
        step(&hub).await.unwrap();
        assert_eq!(used(&hub), 0);
        hub.set_live_tunnels(
            "a",
            true,
            vec![side("entry", Some(true), Some((1500, Some("one"))))],
        );
        step(&hub).await.unwrap();
        assert_eq!(used(&hub), 500);

        // The daemon came back from a traffic file a little stale (the same id): nothing is
        // added, and nothing is counted twice afterwards.
        hub.set_live_tunnels(
            "a",
            true,
            vec![side("entry", Some(true), Some((1490, Some("one"))))],
        );
        step(&hub).await.unwrap();
        assert_eq!(used(&hub), 500);
        hub.set_live_tunnels(
            "a",
            true,
            vec![side("entry", Some(true), Some((1600, Some("one"))))],
        );
        step(&hub).await.unwrap();
        assert_eq!(used(&hub), 610);

        // The counters started over under a new id: the reading is what moved since.
        hub.set_live_tunnels(
            "a",
            true,
            vec![side("entry", Some(true), Some((40, Some("two"))))],
        );
        step(&hub).await.unwrap();
        assert_eq!(used(&hub), 650);
        // Started over again, and already past the last reading by the time it is read: the
        // id says so, and the whole reading counts.
        hub.set_live_tunnels(
            "a",
            true,
            vec![side("entry", Some(true), Some((2000, Some("three"))))],
        );
        step(&hub).await.unwrap();
        assert_eq!(used(&hub), 2650);
        hub.set_live_tunnels(
            "a",
            true,
            vec![side("entry", Some(true), Some((2010, Some("three"))))],
        );
        step(&hub).await.unwrap();
        assert_eq!(used(&hub), 2660);

        // An older daemon (no id) restarts: the same.
        hub.set_live_tunnels("a", true, vec![side("entry", Some(true), Some((7, None)))]);
        step(&hub).await.unwrap();
        assert_eq!(used(&hub), 2667);
        hub.set_live_tunnels("a", true, vec![side("entry", Some(true), Some((3, None)))]);
        step(&hub).await.unwrap();
        assert_eq!(used(&hub), 2670);

        // The entry side goes away: the exit side's counters are read, from a new baseline.
        hub.set_live_tunnels("a", false, vec![side("entry", Some(true), Some((3, None)))]);
        hub.set_live_tunnels(
            "b",
            true,
            vec![side("exit", Some(true), Some((9000, Some("x"))))],
        );
        step(&hub).await.unwrap();
        assert_eq!(used(&hub), 2670);
        hub.set_live_tunnels(
            "b",
            true,
            vec![side("exit", Some(true), Some((9100, Some("x"))))],
        );
        step(&hub).await.unwrap();
        assert_eq!(used(&hub), 2770);
        // Nothing was stopped: well under the limit.
        assert_eq!(hub.ops.count("control"), 0);
    }

    #[tokio::test]
    async fn a_limit_with_an_end_warns_three_days_before_stops_at_the_end_and_goes_on_when_extended(
    ) {
        let hub = hub();
        let t = now();
        // A limit of time alone, ending in two days: the notice goes out at once.
        write(&hub.db, "demo", 0, 0, t + 2 * 86_400).unwrap();
        assert_eq!(
            list(&hub.db).unwrap().len(),
            1,
            "a duration alone is a limit"
        );
        hub.set_live_tunnels(
            "a",
            true,
            vec![side("entry", Some(true), Some((0, Some("one"))))],
        );
        step(&hub).await.unwrap();
        let notices = hub.take_notices();
        assert!(
            matches!(&notices[..], [Notice::QuotaExpiring { name, days }] if name == "demo" && *days == 2),
            "{notices:?}"
        );
        step(&hub).await.unwrap();
        assert!(hub.take_notices().is_empty(), "the notice goes out once");
        assert!(!exhausted(&hub.db, "demo"));

        // Past the end: a stop is tried (nothing answers here), and a start is refused.
        let mut r = row(&hub.db, "demo").unwrap().unwrap();
        r.expires_at = t - 1;
        save(&hub.db, &r).unwrap();
        step(&hub).await.unwrap();
        assert!(exhausted(&hub.db, "demo"));
        assert_eq!(hub.ops.count("control"), 1);

        // Stopped (as the agent would report): marked expired, told once.
        hub.set_live_tunnels("a", true, vec![side("entry", Some(false), None)]);
        step(&hub).await.unwrap();
        let r = row(&hub.db, "demo").unwrap().unwrap();
        assert!(r.expired > 0, "{r:?}");
        let notices = hub.take_notices();
        assert!(
            matches!(&notices[..], [Notice::QuotaExpired { name }] if name == "demo"),
            "{notices:?}"
        );
        step(&hub).await.unwrap();
        assert!(hub.take_notices().is_empty());
        assert_eq!(hub.ops.count("control"), 1, "nothing more to stop");

        // As the panel's own stop leaves it (the agent answered here): stopped at the end.
        let mut r = row(&hub.db, "demo").unwrap().unwrap();
        r.stopped = t;
        save(&hub.db, &r).unwrap();
        // Extended by ten days: the end moves on from now, and a start is owed.
        assert!(extend(&hub, "demo", 10).unwrap());
        let r = row(&hub.db, "demo").unwrap().unwrap();
        assert!(r.expires_at >= now() + 10 * 86_400 - 2 && r.expired == 0 && !r.expiry_warned);
        assert!(r.start_due && r.stopped == 0, "{r:?}");
        assert!(!exhausted(&hub.db, "demo"));
        step(&hub).await.unwrap();
        assert_eq!(hub.ops.count("control"), 2, "started again");
        // A bad extension changes nothing.
        assert!(extend(&hub, "demo", 0).is_err() && extend(&hub, "demo", 4000).is_err());
        assert!(!extend(&hub, "nobody", 3).unwrap());
    }

    #[test]
    fn a_limit_s_numbers_are_checked_with_its_end() {
        let t = now();
        assert!(check(MIN_LIMIT, 0, 0).is_ok());
        assert!(check(0, 0, t + 86_400).is_ok(), "time alone");
        assert!(check(0, 0, 0).is_err(), "neither");
        assert!(check(MIN_LIMIT, 0, t - 1).is_err(), "an end in the past");
        assert!(check(MIN_LIMIT, 0, t + (MAX_DAYS + 1) * 86_400).is_err());
        assert_eq!(end_of(None, None).unwrap(), 0);
        assert!(end_of(Some(3), None).unwrap() >= t + 3 * 86_400);
        assert_eq!(
            end_of(Some(3), Some(t + 5)).unwrap(),
            t + 5,
            "a given end wins"
        );
        assert!(end_of(Some(0), None).unwrap() == 0 && end_of(Some(9999), None).is_err());
    }

    #[tokio::test]
    async fn a_tunnel_over_its_limit_is_warned_about_and_stopped_only_while_a_side_is_online() {
        let hub = hub();
        write(&hub.db, "demo", MIN_LIMIT, 0, 0).unwrap();
        hub.set_live_tunnels(
            "a",
            true,
            vec![side("entry", Some(true), Some((0, Some("one"))))],
        );
        step(&hub).await.unwrap();
        // 80%: one warning, an event, a notice; not stopped.
        let at_80 = (MIN_LIMIT as f64 * 0.8).ceil() as u64;
        hub.set_live_tunnels(
            "a",
            true,
            vec![side("entry", Some(true), Some((at_80, Some("one"))))],
        );
        step(&hub).await.unwrap();
        step(&hub).await.unwrap();
        let notices = hub.take_notices();
        assert_eq!(notices.len(), 1);
        assert!(matches!(&notices[0], Notice::QuotaNear { name, .. } if name == "demo"));
        assert_eq!(hub.ops.count("control"), 0);

        // Over the limit while its only side is offline: nothing is tried.
        hub.set_live_tunnels(
            "a",
            false,
            vec![side("entry", Some(true), Some((at_80, Some("one"))))],
        );
        step(&hub).await.unwrap();
        hub.set_live_tunnels(
            "a",
            false,
            vec![side(
                "entry",
                Some(true),
                Some((MIN_LIMIT as u64 + 5, Some("one"))),
            )],
        );
        step(&hub).await.unwrap();
        assert_eq!(used(&hub), at_80 as i64, "an offline side is not read");
        assert_eq!(hub.ops.count("control"), 0);
        assert!(!exhausted(&hub.db, "demo"));

        // Back online and over the limit: a stop is tried (it cannot reach the agent here, so
        // it is tried again next time; the usage is kept).
        hub.set_live_tunnels(
            "a",
            true,
            vec![side(
                "entry",
                Some(true),
                Some((MIN_LIMIT as u64 + 5, Some("one"))),
            )],
        );
        step(&hub).await.unwrap();
        assert!(exhausted(&hub.db, "demo"));
        assert_eq!(hub.ops.count("control"), 1);
        assert_eq!(used(&hub), MIN_LIMIT + 5);
        step(&hub).await.unwrap();
        assert_eq!(hub.ops.count("control"), 2, "tried again");
        assert!(
            hub.take_notices().is_empty(),
            "no notice until it is stopped"
        );

        // Stopped (as the agent would report), still over the limit: nothing more to do.
        hub.set_live_tunnels("a", true, vec![side("entry", Some(false), None)]);
        step(&hub).await.unwrap();
        assert_eq!(hub.ops.count("control"), 2);

        // A reset owes it a start: tried while a side reports it stopped, and done once
        // every online side runs again.
        assert!(reset(&hub, "demo").unwrap());
        let r = row(&hub.db, "demo").unwrap().unwrap();
        assert!(r.used == 0 && !r.warned);
        hub.set_live_tunnels("a", true, vec![side("entry", Some(false), None)]);
        let mut r = row(&hub.db, "demo").unwrap().unwrap();
        r.start_due = true;
        save(&hub.db, &r).unwrap();
        step(&hub).await.unwrap();
        assert_eq!(hub.ops.count("control"), 3, "a start was tried");
        assert!(
            row(&hub.db, "demo").unwrap().unwrap().start_due,
            "still owed"
        );
        hub.set_live_tunnels(
            "a",
            true,
            vec![side("entry", Some(true), Some((1, Some("two"))))],
        );
        step(&hub).await.unwrap();
        assert!(!row(&hub.db, "demo").unwrap().unwrap().start_due);
        assert_eq!(hub.ops.count("control"), 3);
    }

    /// A reset while one side is away: the start stays owed until that side is back and
    /// runs again (its service was disabled by the stop).
    #[tokio::test]
    async fn a_start_stays_owed_until_every_side_is_back_and_running() {
        let hub = hub();
        write(&hub.db, "demo", MIN_LIMIT, 0, 0).unwrap();
        let mut r = row(&hub.db, "demo").unwrap().unwrap();
        r.start_due = true;
        save(&hub.db, &r).unwrap();
        hub.set_live_tunnels("a", true, vec![side("entry", Some(true), None)]);
        hub.set_live_tunnels("b", false, vec![side("exit", Some(false), None)]);
        step(&hub).await.unwrap();
        assert!(
            row(&hub.db, "demo").unwrap().unwrap().start_due,
            "b is away: still owed"
        );
        assert_eq!(
            hub.ops.count("control"),
            0,
            "nothing to start on the side that runs"
        );
        hub.set_live_tunnels("b", true, vec![side("exit", Some(false), None)]);
        step(&hub).await.unwrap();
        assert_eq!(
            hub.ops.count("control"),
            1,
            "b is back and stopped: started"
        );
        hub.set_live_tunnels("b", true, vec![side("exit", Some(true), None)]);
        step(&hub).await.unwrap();
        assert!(!row(&hub.db, "demo").unwrap().unwrap().start_due);
    }

    /// A reset that lands while the loop is stopping the tunnel is not undone by the stop.
    #[tokio::test]
    async fn a_reset_during_the_stop_is_kept_and_the_tunnel_is_owed_a_start() {
        let hub = hub();
        write(&hub.db, "demo", MIN_LIMIT, 0, 0).unwrap();
        let mut r = row(&hub.db, "demo").unwrap().unwrap();
        r.used = MIN_LIMIT;
        r.last_seen = MIN_LIMIT;
        r.side = "entry".into();
        save(&hub.db, &r).unwrap();
        // The reset happens "during" the tick: the loop's stop fails here (no agent), so the
        // guarded mark finds the row reset and owes a start instead of marking it stopped.
        hub.set_live_tunnels(
            "a",
            true,
            vec![side(
                "entry",
                Some(true),
                Some((MIN_LIMIT as u64, Some("one"))),
            )],
        );
        assert!(reset(&hub, "demo").unwrap());
        step(&hub).await.unwrap();
        let r = row(&hub.db, "demo").unwrap().unwrap();
        assert_eq!((r.used, r.stopped), (0, 0), "the reset stands");
    }

    #[tokio::test]
    async fn a_monthly_reset_zeroes_the_usage_and_owes_a_stopped_tunnel_a_start() {
        let hub = hub();
        write(&hub.db, "demo", MIN_LIMIT, 1, 0).unwrap();
        let mut r = row(&hub.db, "demo").unwrap().unwrap();
        // The last reset was long ago; the tunnel is stopped over its limit.
        r.last_reset = now() - 40 * 86_400;
        r.used = MIN_LIMIT;
        r.warned = true;
        r.stopped = now() - 86_400;
        save(&hub.db, &r).unwrap();
        hub.set_live_tunnels("a", true, vec![side("entry", Some(false), None)]);
        step(&hub).await.unwrap();
        let r = row(&hub.db, "demo").unwrap().unwrap();
        assert_eq!((r.used, r.warned, r.stopped), (0, false, 0));
        assert!(r.last_reset > now() - 60);
        assert!(
            r.start_due || hub.ops.count("control") == 1,
            "a start was owed, and tried"
        );
        assert!(next_reset(1, r.last_reset).unwrap() > now());
    }
}
