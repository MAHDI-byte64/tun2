//! A copy of every tunnel's settings, kept in the panel's database: what the wizard sent
//! (a create or an edit), or, for a tunnel made before the panel kept copies, what its two
//! servers report, turned back into a request. A copy never holds the token (a create makes
//! a fresh one) nor the traffic limit (which lives on the tunnel's page). It is what makes
//! a tunnel that vanished from its servers (a reinstalled server, a file deleted by hand)
//! one click to make again, and it goes into backups.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use rusqlite::{params, OptionalExtension};
use serde::Serialize;
use tracing::{debug, info, warn};

use crate::auth::now;
use crate::db::Db;
use crate::hub::Hub;
use crate::pair::PairRequest;
use crate::wire::{Request, Spec};

/// One kept copy, as the API lists it.
#[derive(Debug, Clone, Serialize)]
pub struct Copy {
    pub name: String,
    /// The servers it was made on (ids; one may be gone since).
    pub entry: String,
    pub exit: String,
    pub updated: i64,
    /// `panel`: from a create or an edit; `server`: read back from the servers.
    pub source: String,
    /// Some server still lists the tunnel.
    pub present: bool,
}

/// Keeps `req` as the tunnel's copy, replacing an older one. A new token or a limit are
/// not settings of the tunnel and are left out.
pub fn keep(db: &Db, req: &PairRequest, source: &str) -> Result<()> {
    let mut kept = req.clone();
    kept.rotate = false;
    kept.quota = None;
    let json = serde_json::to_string(&kept)?;
    db.conn().execute(
        "INSERT INTO tunnel_specs (name, request, entry, exit, updated, source) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
         ON CONFLICT(name) DO UPDATE SET request = excluded.request, entry = excluded.entry, \
         exit = excluded.exit, updated = excluded.updated, source = excluded.source",
        params![kept.name, json, kept.entry, kept.exit, now(), source],
    )?;
    Ok(())
}

/// Drops a tunnel's copy; whether there was one.
pub fn forget(db: &Db, name: &str) -> Result<bool> {
    Ok(db
        .conn()
        .execute("DELETE FROM tunnel_specs WHERE name = ?1", [name])?
        > 0)
}

/// The kept request of a tunnel, if any.
pub fn get(db: &Db, name: &str) -> Result<Option<PairRequest>> {
    let json: Option<String> = db
        .conn()
        .query_row(
            "SELECT request FROM tunnel_specs WHERE name = ?1",
            [name],
            |r| r.get(0),
        )
        .optional()?;
    json.map(|j| serde_json::from_str(&j).context("the kept tunnel settings cannot be read"))
        .transpose()
}

fn names(db: &Db) -> Result<HashSet<String>> {
    let conn = db.conn();
    let mut stmt = conn.prepare("SELECT name FROM tunnel_specs")?;
    let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// Every copy, with whether some server still lists the tunnel.
pub fn list(hub: &Hub) -> Result<Vec<Copy>> {
    let present: HashSet<String> = hub
        .snapshot()?
        .iter()
        .flat_map(|s| s.tunnels.iter().map(|t| t.info.name.clone()))
        .collect();
    let conn = hub.db.conn();
    let mut stmt =
        conn.prepare("SELECT name, entry, exit, updated, source FROM tunnel_specs ORDER BY name")?;
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, i64>(3)?,
            r.get::<_, String>(4)?,
        ))
    })?;
    rows.map(|row| {
        let (name, entry, exit, updated, source) = row?;
        Ok(Copy {
            present: present.contains(&name),
            name,
            entry,
            exit,
            updated,
            source,
        })
    })
    .collect()
}

/// Makes a tunnel again from its copy, on the servers it was on, or on `entry` / `exit`
/// instead (a server that is gone). The operation is a create's: it fails with
/// `name_taken` while a server still has the tunnel.
pub fn recreate(
    hub: &Arc<Hub>,
    name: &str,
    entry: Option<&str>,
    exit: Option<&str>,
) -> Result<String> {
    let Some(mut req) = get(&hub.db, name)? else {
        bail!("no_copy");
    };
    if let Some(entry) = entry {
        req.entry = entry.to_owned();
    }
    if let Some(exit) = exit {
        req.exit = exit.to_owned();
    }
    crate::pair::create(hub, req)
}

/// Copies the tunnels made before the panel kept copies: for each tunnel without one whose
/// two sides are online, the sides' specs are read and turned back into a request
/// ([`PairRequest::from_specs`]). One whose specs cannot be mapped (made by hand, with
/// settings the wizard does not have) is left out and remembered in `skipped`, so it is
/// not asked for again while the panel runs.
pub async fn back_fill(hub: &Hub, skipped: &mut HashSet<String>) {
    let Ok(servers) = hub.snapshot() else {
        return;
    };
    let Ok(kept) = names(&hub.db) else {
        return;
    };
    // The online entry and exit of each tunnel name.
    let mut sides: HashMap<String, (Option<String>, Option<String>)> = HashMap::new();
    for server in servers.iter().filter(|s| s.online) {
        for t in &server.tunnels {
            let side = sides.entry(t.info.name.clone()).or_default();
            match t.info.role.as_str() {
                "entry" => side.0 = Some(server.id.clone()),
                "exit" => side.1 = Some(server.id.clone()),
                _ => {}
            }
        }
    }
    for (name, (entry, exit)) in sides {
        let (Some(entry), Some(exit)) = (entry, exit) else {
            continue;
        };
        if kept.contains(&name) || skipped.contains(&name) {
            continue;
        }
        let request = Request::TunnelGet { name: name.clone() };
        let (Ok(entry_spec), Ok(exit_spec)) = (
            hub.ask_as::<Spec>(&entry, &request).await,
            hub.ask_as::<Spec>(&exit, &request).await,
        ) else {
            continue;
        };
        match PairRequest::from_specs(&name, &entry, &exit, &entry_spec, &exit_spec) {
            Some(req) => match keep(&hub.db, &req, "server") {
                Ok(()) => {
                    info!(tunnel = %name, "kept a copy of the tunnel's settings, read from its servers")
                }
                Err(e) => {
                    warn!(tunnel = %name, error = %format!("{e:#}"), "the tunnel's settings could not be kept")
                }
            },
            None => {
                debug!(tunnel = %name, "the tunnel's settings do not map to the wizard's; no copy kept");
                skipped.insert(name);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::ForwardInfo;

    fn request() -> PairRequest {
        PairRequest {
            name: "copy-1".into(),
            entry: "a".into(),
            exit: "b".into(),
            mode: "reverse".into(),
            transport: "tcpmux".into(),
            listen: "0.0.0.0:3080".into(),
            dial: "198.51.100.7:3080".into(),
            forwards: vec![ForwardInfo {
                listen: "0.0.0.0:443".into(),
                target: "127.0.0.1:443".into(),
                protocol: "tcp".into(),
            }],
            rotate: true,
            quota: Some(crate::quota::QuotaSpec {
                limit_bytes: 1 << 30,
                reset_day: 0,
                days: None,
            }),
            ..Default::default()
        }
    }

    #[test]
    fn a_copy_is_kept_without_the_token_or_the_limit_and_read_back() {
        let db = Db::in_memory().unwrap();
        keep(&db, &request(), "panel").unwrap();
        let back = get(&db, "copy-1").unwrap().expect("kept");
        assert!(!back.rotate && back.quota.is_none());
        assert_eq!(back.forwards, request().forwards);
        assert_eq!(back.dial, "198.51.100.7:3080");
        // Kept again: replaced, not doubled.
        let mut edited = request();
        edited.dial = "198.51.100.8:3080".into();
        keep(&db, &edited, "panel").unwrap();
        assert_eq!(
            get(&db, "copy-1").unwrap().unwrap().dial,
            "198.51.100.8:3080"
        );
        assert_eq!(names(&db).unwrap().len(), 1);
        assert!(forget(&db, "copy-1").unwrap());
        assert!(!forget(&db, "copy-1").unwrap());
        assert!(get(&db, "copy-1").unwrap().is_none());
    }
}
