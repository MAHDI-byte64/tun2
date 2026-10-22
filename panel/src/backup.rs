//! A backup of the panel: the servers it knows (with the keys they prove themselves with),
//! the link token they dial with, and where the panel dials the ones it connects to
//! (reverse), in one file locked with a passphrase.
//!
//! The tunnels themselves live on the servers, in their own files, and the panel reads
//! them from there; what is in the backup is the panel's copy of each one's settings
//! (`crate::specs`, without tokens), so they can be made again. Sessions and login links
//! are not in it.
//!
//! The file is `KZB1`, a random salt, a random nonce, then the JSON sealed with
//! ChaCha20-Poly1305 under a key that Argon2id makes from the passphrase.

use anyhow::{anyhow, bail, Context, Result};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use rusqlite::params;
use serde::{Deserialize, Serialize};

use crate::auth::now;
use crate::db::Db;

const MAGIC: &[u8; 4] = b"KZB1";
pub const MIN_PASSPHRASE: usize = 10;

#[derive(Debug, Serialize, Deserialize)]
struct Server {
    id: String,
    name: String,
    key: String,
    created: i64,
    last_seen: i64,
    version: String,
    arch: String,
    host: String,
    /// Not in backups from before servers were arranged: then they keep the order of the
    /// list (oldest first).
    #[serde(default)]
    position: Option<i64>,
}

/// A server the panel connects to (reverse): where it dials it.
#[derive(Debug, Serialize, Deserialize)]
struct ReverseRow {
    server: String,
    host: String,
    port: u16,
    transport: Option<String>,
    /// Through the panel's proxy (not in backups from before it: then not).
    #[serde(default)]
    via_proxy: bool,
}

/// A server with an agents port of its own: the port its agent dials.
#[derive(Debug, Serialize, Deserialize)]
struct PortRow {
    server: String,
    port: u16,
}

/// A tunnel's traffic limit and usage (`crate::quota`), the whole row.
#[derive(Debug, Serialize, Deserialize)]
struct QuotaRow {
    name: String,
    limit_bytes: i64,
    used: i64,
    last_seen: i64,
    side: String,
    counter_id: String,
    reset_day: i64,
    last_reset: i64,
    warned: i64,
    stopped: i64,
    start_due: i64,
    since: i64,
    /// Not in backups from before limits had an end: then none.
    #[serde(default)]
    expires_at: i64,
    #[serde(default)]
    expiry_warned: i64,
    #[serde(default)]
    expired: i64,
}

/// A tunnel's renter page (`crate::share`), the whole row.
#[derive(Debug, Serialize, Deserialize)]
struct ShareRow {
    name: String,
    token: String,
    title: String,
    created: i64,
    views: i64,
    last_restart: i64,
}

/// The panel's copy of a tunnel's settings (`crate::specs`), the whole row.
#[derive(Debug, Serialize, Deserialize)]
struct TunnelRow {
    name: String,
    request: String,
    entry: String,
    exit: String,
    updated: i64,
    source: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Payload {
    format: u32,
    created: i64,
    panel: String,
    link_token: Option<String>,
    servers: Vec<Server>,
    /// Not in backups from before reverse links: then there are none.
    #[serde(default)]
    reverse: Vec<ReverseRow>,
    /// Not in backups from before agents ports of a server's own: then there are none.
    #[serde(default)]
    ports: Vec<PortRow>,
    /// Where the panel's own server stood among them; none: before them all.
    #[serde(default)]
    local_position: Option<i64>,
    /// The tunnels' traffic limits and usage. Not in backups from before them: then none.
    #[serde(default)]
    quotas: Vec<QuotaRow>,
    /// The copies of the tunnels' settings. Not in backups from before them: then none.
    #[serde(default)]
    tunnels: Vec<TunnelRow>,
    /// The tunnels' renter pages. Not in backups from before them: then none.
    #[serde(default)]
    shares: Vec<ShareRow>,
}

fn derive(passphrase: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let params = argon2::Params::new(19 * 1024, 2, 1, Some(32)).map_err(|e| anyhow!("{e}"))?;
    let argon = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut key = [0u8; 32];
    argon
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow!("{e}"))?;
    Ok(key)
}

fn sealing_key(key: &[u8; 32]) -> Result<LessSafeKey> {
    Ok(LessSafeKey::new(
        UnboundKey::new(&CHACHA20_POLY1305, key).map_err(|_| anyhow!("bad key"))?,
    ))
}

fn random<const N: usize>() -> Result<[u8; N]> {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).map_err(|e| anyhow!("no randomness: {e}"))?;
    Ok(b)
}

/// The backup file for `db`, locked with `passphrase`.
pub fn export(db: &Db, passphrase: &str) -> Result<Vec<u8>> {
    if passphrase.chars().count() < MIN_PASSPHRASE {
        bail!("short_passphrase");
    }
    let servers = {
        let conn = db.conn();
        let mut stmt = conn.prepare(
            "SELECT id, name, key, created, last_seen, version, arch, host, position FROM servers
             ORDER BY position, created, id",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(Server {
                id: r.get(0)?,
                name: r.get(1)?,
                key: r.get(2)?,
                created: r.get(3)?,
                last_seen: r.get(4)?,
                version: r.get(5)?,
                arch: r.get(6)?,
                host: r.get(7)?,
                position: r.get(8)?,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()?
    };
    let reverse = {
        let conn = db.conn();
        let mut stmt = conn.prepare(
            "SELECT server, host, port, transport, via_proxy FROM reverse_links ORDER BY server",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(ReverseRow {
                server: r.get(0)?,
                host: r.get(1)?,
                port: r.get(2)?,
                transport: r.get(3)?,
                via_proxy: r.get::<_, i64>(4)? != 0,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()?
    };
    let ports = {
        let conn = db.conn();
        let mut stmt = conn.prepare("SELECT server, port FROM agent_ports ORDER BY server")?;
        let rows = stmt.query_map([], |r| {
            Ok(PortRow {
                server: r.get(0)?,
                port: r.get(1)?,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()?
    };
    let quotas = {
        let conn = db.conn();
        let mut stmt = conn.prepare(
            "SELECT name, limit_bytes, used, last_seen, side, counter_id, reset_day, last_reset, warned, stopped, start_due, since, \
             expires_at, expiry_warned, expired FROM quotas ORDER BY name",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(QuotaRow {
                name: r.get(0)?,
                limit_bytes: r.get(1)?,
                used: r.get(2)?,
                last_seen: r.get(3)?,
                side: r.get(4)?,
                counter_id: r.get(5)?,
                reset_day: r.get(6)?,
                last_reset: r.get(7)?,
                warned: r.get(8)?,
                stopped: r.get(9)?,
                start_due: r.get(10)?,
                since: r.get(11)?,
                expires_at: r.get(12)?,
                expiry_warned: r.get(13)?,
                expired: r.get(14)?,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()?
    };
    let shares = {
        let conn = db.conn();
        let mut stmt = conn.prepare(
            "SELECT name, token, title, created, views, last_restart FROM shares ORDER BY name",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(ShareRow {
                name: r.get(0)?,
                token: r.get(1)?,
                title: r.get(2)?,
                created: r.get(3)?,
                views: r.get(4)?,
                last_restart: r.get(5)?,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()?
    };
    let tunnels = {
        let conn = db.conn();
        let mut stmt = conn.prepare(
            "SELECT name, request, entry, exit, updated, source FROM tunnel_specs ORDER BY name",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(TunnelRow {
                name: r.get(0)?,
                request: r.get(1)?,
                entry: r.get(2)?,
                exit: r.get(3)?,
                updated: r.get(4)?,
                source: r.get(5)?,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()?
    };
    let payload = Payload {
        format: 1,
        created: now(),
        panel: crate::version().to_owned(),
        link_token: db.meta("link_token")?,
        servers,
        reverse,
        ports,
        local_position: db.meta("local_position")?.and_then(|p| p.parse().ok()),
        quotas,
        tunnels,
        shares,
    };
    seal(serde_json::to_vec(&payload)?, passphrase)
}

/// `data` locked with `passphrase`, in the backup file's form.
fn seal(mut data: Vec<u8>, passphrase: &str) -> Result<Vec<u8>> {
    let salt = random::<16>()?;
    let nonce = random::<12>()?;
    let key = sealing_key(&derive(passphrase, &salt)?)?;
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(&MAGIC[..]),
        &mut data,
    )
    .map_err(|_| anyhow!("could not seal the backup"))?;
    let mut out = Vec::with_capacity(4 + 16 + 12 + data.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&data);
    Ok(out)
}

/// Reads a backup back into `db`. A panel that already has servers refuses unless
/// `replace` is set; then its servers are swapped for the backup's. Returns how many
/// servers came back.
pub fn import(db: &Db, passphrase: &str, file: &[u8], replace: bool) -> Result<usize> {
    if file.len() < 4 + 16 + 12 + 16 || &file[..4] != MAGIC {
        bail!("not_a_backup");
    }
    let (salt, rest) = file[4..].split_at(16);
    let (nonce, sealed) = rest.split_at(12);
    let key = sealing_key(&derive(passphrase, salt)?)?;
    let mut data = sealed.to_vec();
    let plain = key
        .open_in_place(
            Nonce::try_assume_unique_for_key(nonce).map_err(|_| anyhow!("bad nonce"))?,
            Aad::from(&MAGIC[..]),
            &mut data,
        )
        // A wrong passphrase and a damaged file look the same: the tag does not match.
        .map_err(|_| anyhow!("wrong_passphrase"))?;
    let payload: Payload = serde_json::from_slice(plain).context("bad_backup")?;
    if payload.format != 1 {
        bail!("bad_backup");
    }

    let mut conn = db.conn();
    let existing: i64 = conn.query_row("SELECT COUNT(*) FROM servers", [], |r| r.get(0))?;
    if existing > 0 && !replace {
        bail!("not_empty");
    }
    let tx = conn.transaction()?;
    tx.execute("DELETE FROM servers", [])?;
    for (at, s) in payload.servers.iter().enumerate() {
        tx.execute(
            "INSERT INTO servers (id, name, key, created, last_seen, version, arch, host, position) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                s.id,
                s.name,
                s.key,
                s.created,
                s.last_seen,
                s.version,
                s.arch,
                s.host,
                s.position.unwrap_or(at as i64)
            ],
        )?;
    }
    match payload.local_position {
        Some(p) => tx.execute(
            "INSERT INTO meta (key, value) VALUES ('local_position', ?1) ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            [p.to_string()],
        )?,
        None => tx.execute("DELETE FROM meta WHERE key = 'local_position'", [])?,
    };
    tx.execute("DELETE FROM reverse_links", [])?;
    for r in &payload.reverse {
        tx.execute(
            "INSERT INTO reverse_links (server, host, port, transport, via_proxy) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![r.server, r.host, r.port, r.transport, r.via_proxy as i64],
        )?;
    }
    tx.execute("DELETE FROM agent_ports", [])?;
    for p in &payload.ports {
        tx.execute(
            "INSERT INTO agent_ports (server, port) VALUES (?1, ?2)",
            params![p.server, p.port],
        )?;
    }
    tx.execute("DELETE FROM tunnel_specs", [])?;
    for t in &payload.tunnels {
        tx.execute(
            "INSERT INTO tunnel_specs (name, request, entry, exit, updated, source) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![t.name, t.request, t.entry, t.exit, t.updated, t.source],
        )?;
    }
    tx.execute("DELETE FROM quotas", [])?;
    for q in &payload.quotas {
        tx.execute(
            "INSERT INTO quotas (name, limit_bytes, used, last_seen, side, counter_id, reset_day, last_reset, warned, stopped, start_due, since, \
             expires_at, expiry_warned, expired) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
            params![
                q.name,
                q.limit_bytes,
                q.used,
                q.last_seen,
                q.side,
                q.counter_id,
                q.reset_day,
                q.last_reset,
                q.warned,
                q.stopped,
                q.start_due,
                q.since,
                q.expires_at,
                q.expiry_warned,
                q.expired
            ],
        )?;
    }
    tx.execute("DELETE FROM shares", [])?;
    for s in &payload.shares {
        tx.execute(
            "INSERT INTO shares (name, token, title, created, views, last_restart) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![s.name, s.token, s.title, s.created, s.views, s.last_restart],
        )?;
    }
    if let Some(token) = &payload.link_token {
        tx.execute(
            "INSERT INTO meta (key, value) VALUES ('link_token', ?1) ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            [token],
        )?;
    }
    tx.commit()?;
    Ok(payload.servers.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db_with_servers() -> Db {
        let db = Db::in_memory().unwrap();
        db.set_meta("link_token", "the-link-token").unwrap();
        db.conn()
            .execute(
                "INSERT INTO servers (id, name, key, created) VALUES ('a1', 'frankfurt', 'key-of-frankfurt-7f3a9c2e', 100), ('b2', 'istanbul', 'key-of-istanbul-5b1d8e04', 200)",
                [],
            )
            .unwrap();
        // The panel connects to istanbul (reverse).
        db.conn()
            .execute(
                "INSERT INTO reverse_links (server, host, port, transport) VALUES ('b2', 'ist.example.com', 29001, NULL)",
                [],
            )
            .unwrap();
        // frankfurt's agent dials a port of its own.
        db.conn()
            .execute(
                "INSERT INTO agent_ports (server, port) VALUES ('a1', 8443)",
                [],
            )
            .unwrap();
        db
    }

    #[test]
    fn a_backup_restores_the_servers_and_the_link_token_on_a_fresh_panel() {
        let file = export(&db_with_servers(), "a long enough passphrase").unwrap();
        // the file does not show what is in it (long enough strings that random bytes never
        // spell them by chance; a two-letter key once did)
        let text = String::from_utf8_lossy(&file);
        assert!(
            !text.contains("frankfurt")
                && !text.contains("key-of-frankfurt-7f3a9c2e")
                && !text.contains("the-link-token")
        );

        let fresh = Db::in_memory().unwrap();
        fresh.set_meta("link_token", "another-token").unwrap();
        assert_eq!(
            import(&fresh, "a long enough passphrase", &file, false).unwrap(),
            2
        );
        assert_eq!(
            fresh.meta("link_token").unwrap().as_deref(),
            Some("the-link-token")
        );
        let name: String = fresh
            .conn()
            .query_row("SELECT name FROM servers WHERE id = 'b2'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(name, "istanbul");
        // And where the panel dials the one it connects to.
        let at: (String, u16) = fresh
            .conn()
            .query_row(
                "SELECT host, port FROM reverse_links WHERE server = 'b2'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(at, ("ist.example.com".to_owned(), 29001));
        // And the agents port of its own one of them dials.
        let own: u16 = fresh
            .conn()
            .query_row(
                "SELECT port FROM agent_ports WHERE server = 'a1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(own, 8443);
    }

    fn order(db: &Db) -> Vec<String> {
        let conn = db.conn();
        let mut stmt = conn
            .prepare("SELECT id FROM servers ORDER BY position, created, id")
            .unwrap();
        stmt.query_map([], |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    }

    #[test]
    fn a_backup_carries_the_copies_of_the_tunnels() {
        let db = db_with_servers();
        let req = crate::pair::PairRequest {
            name: "kept-1".into(),
            entry: "a1".into(),
            exit: "b2".into(),
            mode: "reverse".into(),
            transport: "tcpmux".into(),
            listen: "0.0.0.0:3080".into(),
            dial: "ist.example.com:3080".into(),
            ..Default::default()
        };
        crate::specs::keep(&db, &req, "panel").unwrap();
        let file = export(&db, "a long enough passphrase").unwrap();
        let fresh = Db::in_memory().unwrap();
        import(&fresh, "a long enough passphrase", &file, false).unwrap();
        let back = crate::specs::get(&fresh, "kept-1")
            .unwrap()
            .expect("the copy came back");
        assert_eq!(back.dial, "ist.example.com:3080");
        assert_eq!(back.exit, "b2");
    }

    #[test]
    fn a_backup_keeps_the_order_the_servers_were_arranged_in() {
        let db = db_with_servers();
        // istanbul first, then the panel's own, then frankfurt.
        db.conn()
            .execute_batch(
                "UPDATE servers SET position = 2 WHERE id = 'a1';
                 UPDATE servers SET position = 0 WHERE id = 'b2';",
            )
            .unwrap();
        db.set_meta("local_position", "1").unwrap();
        let file = export(&db, "a long enough passphrase").unwrap();

        let fresh = Db::in_memory().unwrap();
        import(&fresh, "a long enough passphrase", &file, false).unwrap();
        assert_eq!(order(&fresh), ["b2", "a1"]);
        assert_eq!(fresh.meta("local_position").unwrap().as_deref(), Some("1"));
    }

    #[test]
    fn a_backup_from_before_arranging_keeps_its_list_order() {
        // As an older panel wrote it: no positions, the servers oldest first.
        let old = serde_json::json!({
            "format": 1, "created": 1, "panel": "2.5.1", "link_token": "t",
            "servers": [
                {"id": "z9", "name": "older", "key": "k1", "created": 50, "last_seen": 0,
                 "version": "", "arch": "", "host": ""},
                {"id": "a1", "name": "newer", "key": "k2", "created": 90, "last_seen": 0,
                 "version": "", "arch": "", "host": ""}
            ]
        });
        let file = seal(old.to_string().into_bytes(), "a long enough passphrase").unwrap();
        let fresh = Db::in_memory().unwrap();
        fresh.set_meta("local_position", "5").unwrap();
        assert_eq!(
            import(&fresh, "a long enough passphrase", &file, false).unwrap(),
            2
        );
        assert_eq!(order(&fresh), ["z9", "a1"]);
        // And the panel's own goes back to the top.
        assert_eq!(fresh.meta("local_position").unwrap(), None);
    }

    #[test]
    fn a_wrong_passphrase_a_damaged_file_and_a_stranger_are_refused() {
        let file = export(&db_with_servers(), "a long enough passphrase").unwrap();
        let fresh = Db::in_memory().unwrap();
        let why = |r: Result<usize>| format!("{:#}", r.unwrap_err());
        assert_eq!(
            why(import(&fresh, "not the passphrase!", &file, false)),
            "wrong_passphrase"
        );
        let mut damaged = file.clone();
        let last = damaged.len() - 1;
        damaged[last] ^= 1;
        assert_eq!(
            why(import(&fresh, "a long enough passphrase", &damaged, false)),
            "wrong_passphrase"
        );
        assert_eq!(
            why(import(
                &fresh,
                "a long enough passphrase",
                b"hello there, this is not one at all",
                false
            )),
            "not_a_backup"
        );
        assert_eq!(
            format!("{:#}", export(&fresh, "short").unwrap_err()),
            "short_passphrase"
        );
        let count: i64 = fresh
            .conn()
            .query_row("SELECT COUNT(*) FROM servers", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0, "a refused restore changes nothing");
    }

    #[test]
    fn a_panel_with_servers_needs_to_be_told_to_replace_them() {
        let file = export(&db_with_servers(), "a long enough passphrase").unwrap();
        let other = Db::in_memory().unwrap();
        other
            .conn()
            .execute(
                "INSERT INTO servers (id, name, key, created) VALUES ('z9', 'old', 'kz', 1)",
                [],
            )
            .unwrap();
        let why = import(&other, "a long enough passphrase", &file, false).unwrap_err();
        assert_eq!(format!("{why:#}"), "not_empty");
        assert_eq!(
            import(&other, "a long enough passphrase", &file, true).unwrap(),
            2
        );
        let ids: Vec<String> = {
            let conn = other.conn();
            let mut stmt = conn.prepare("SELECT id FROM servers ORDER BY id").unwrap();
            stmt.query_map([], |r| r.get(0))
                .unwrap()
                .map(Result::unwrap)
                .collect()
        };
        assert_eq!(ids, vec!["a1", "b2"]);
    }
}
