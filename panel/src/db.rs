//! The panel's SQLite database: one file, opened with migrations applied.
//!
//! The schema grows step by step (`MIGRATIONS`, one entry per version): sign-in tables
//! come with 11.2, servers with 11.4. Nothing is ever edited in place; a change is a
//! new migration.

use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

use anyhow::{Context, Result};
use rusqlite::Connection;

/// Each entry takes the database from version `index` to `index + 1`.
const MIGRATIONS: &[&str] = &[
    // 1: settings the panel keeps for itself, and the audit log.
    "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
     CREATE TABLE audit (
         id INTEGER PRIMARY KEY,
         at INTEGER NOT NULL,          -- unix seconds
         who TEXT NOT NULL,            -- a session or 'cli'
         ip TEXT,
         what TEXT NOT NULL
     );
     CREATE INDEX audit_at ON audit (at);",
    // 2: sign-in. Tokens are stored as hashes only (see auth.rs).
    "CREATE TABLE login_links (
         hash TEXT PRIMARY KEY,
         created INTEGER NOT NULL,
         expires INTEGER NOT NULL,
         used INTEGER NOT NULL DEFAULT 0
     );
     CREATE TABLE sessions (
         id INTEGER PRIMARY KEY,
         hash TEXT NOT NULL UNIQUE,
         csrf TEXT NOT NULL,
         created INTEGER NOT NULL,
         last_seen INTEGER NOT NULL,
         ip TEXT NOT NULL,
         agent TEXT NOT NULL
     );
     CREATE TABLE failures (ip TEXT NOT NULL, at INTEGER NOT NULL);
     CREATE INDEX failures_ip ON failures (ip, at);",
    // 3: agents. A server's key is what it proves itself with (the panel needs it to
    // check the proof), so it is stored as it is; the database file is private.
    "CREATE TABLE servers (
         id TEXT PRIMARY KEY,
         name TEXT NOT NULL,
         key TEXT NOT NULL,
         created INTEGER NOT NULL,
         last_seen INTEGER NOT NULL DEFAULT 0,
         version TEXT NOT NULL DEFAULT '',
         arch TEXT NOT NULL DEFAULT '',
         host TEXT NOT NULL DEFAULT ''
     );
     CREATE TABLE joins (
         hash TEXT PRIMARY KEY,
         name TEXT NOT NULL,
         created INTEGER NOT NULL,
         expires INTEGER NOT NULL,
         used INTEGER NOT NULL DEFAULT 0
     );",
    // 4: history for the charts (five-minute averages) and the events list.
    "CREATE TABLE metrics (
         key TEXT NOT NULL,
         ts INTEGER NOT NULL,
         v REAL NOT NULL,
         PRIMARY KEY (key, ts)
     ) WITHOUT ROWID;
     CREATE TABLE events (
         id INTEGER PRIMARY KEY,
         ts INTEGER NOT NULL,
         kind TEXT NOT NULL,
         subject TEXT NOT NULL,
         detail TEXT NOT NULL DEFAULT ''
     );
     CREATE INDEX events_ts ON events (ts);",
    // 5: private networks. Every subnet, address and interface name is
    // UNIQUE, so no address can be given twice whatever the code does.
    "CREATE TABLE networks (
         id TEXT PRIMARY KEY,
         name TEXT NOT NULL UNIQUE,
         cidr TEXT NOT NULL UNIQUE,
         created INTEGER NOT NULL
     );
     CREATE TABLE net_links (
         id TEXT PRIMARY KEY,
         network TEXT NOT NULL REFERENCES networks (id),
         a TEXT NOT NULL,
         b TEXT NOT NULL,
         subnet TEXT NOT NULL UNIQUE,
         addr_a TEXT NOT NULL UNIQUE,
         addr_b TEXT NOT NULL UNIQUE,
         gre_key INTEGER NOT NULL,
         ifname TEXT NOT NULL UNIQUE,
         created INTEGER NOT NULL,
         UNIQUE (a, b, gre_key),
         CHECK (a < b)
     );",
    // 6: the public address of each server, as the others reach it (GRE needs both ends).
    "CREATE TABLE server_addrs (server TEXT PRIMARY KEY, addr TEXT NOT NULL);",
    // 7: the server a join code registered, until its agent confirms the identity (a link
    // that drops during enrollment tries again with the same identity).
    "ALTER TABLE joins ADD COLUMN server TEXT;",
    // 8: tunnels deleted while their server was offline: the agent removes them when it
    // comes back.
    "CREATE TABLE pending_deletes (
         server TEXT NOT NULL,
         name TEXT NOT NULL,
         PRIMARY KEY (server, name)
     );",
    // 9: the address each server was last known by. After the panel restarts nothing is
    // connected yet, and a private network link whose other end has no address would be
    // left out of the list an agent is sent (and the agent removes what is not in it).
    "CREATE TABLE server_seen (server TEXT PRIMARY KEY, addr TEXT NOT NULL);",
    // 10: a join code made for a server the panel already knows: the agent that spends it
    // becomes that server again (same id, a new key), so its tunnels and networks stay.
    "ALTER TABLE joins ADD COLUMN rejoin TEXT;",
    // 11: automatic restarts of a tunnel, or of every running tunnel of a server.
    "CREATE TABLE schedules (
         kind TEXT NOT NULL,                      -- 'tunnel' or 'server'
         subject TEXT NOT NULL,                   -- the tunnel's name, or the server's id
         mode TEXT NOT NULL,                      -- 'every' or 'daily'
         every_secs INTEGER NOT NULL DEFAULT 0,
         daily_min INTEGER NOT NULL DEFAULT 0,    -- minutes after midnight, UTC
         enabled INTEGER NOT NULL DEFAULT 1,
         since INTEGER NOT NULL,                  -- when it was set
         last_run INTEGER NOT NULL DEFAULT 0,
         last_result TEXT NOT NULL DEFAULT '',
         PRIMARY KEY (kind, subject)
     );",
    // 12: servers the panel connects to (reverse): their agent listens, and the panel dials
    // it at this host and port, over one transport or (NULL) all of them in turn.
    "CREATE TABLE reverse_links (
         server TEXT PRIMARY KEY,
         host TEXT NOT NULL,
         port INTEGER NOT NULL,
         transport TEXT
     );",
    // 13: the last benchmark between two servers (entry, exit), as JSON.
    "CREATE TABLE benchmarks (
         entry TEXT NOT NULL,
         exit TEXT NOT NULL,
         created INTEGER NOT NULL,
         result TEXT NOT NULL,
         PRIMARY KEY (entry, exit)
     );",
    // 14: how a network's links are made: GRE, or VXLAN over a UDP port (0 for GRE).
    "ALTER TABLE networks ADD COLUMN kind TEXT NOT NULL DEFAULT 'gre';
     ALTER TABLE networks ADD COLUMN port INTEGER NOT NULL DEFAULT 0;",
    // 15: an agents port of a server's own, which the panel listens on for its agent alone.
    "CREATE TABLE agent_ports (server TEXT PRIMARY KEY, port INTEGER NOT NULL UNIQUE);",
    // 16: where a server stands in every list, as the admin arranged them. The servers there
    // are keep the order they had (oldest first); the panel's own stands before them until
    // it is moved (`local_position` in meta).
    "ALTER TABLE servers ADD COLUMN position INTEGER;
     UPDATE servers SET position = (
         SELECT count(*) FROM servers o
         WHERE o.created < servers.created OR (o.created = servers.created AND o.id < servers.id)
     );",
    // 17: the last IP spoof-test result for a (from, to) server pair; `result` is a JSON blob.
    "CREATE TABLE ip_tests (
         src TEXT NOT NULL,
         dst TEXT NOT NULL,
         created INTEGER NOT NULL,
         result TEXT NOT NULL,
         PRIMARY KEY (src, dst)
     );",
];

/// A shared handle to the database. SQLite calls are short, so one connection behind a
/// mutex is enough for a panel with a handful of users.
#[derive(Clone)]
pub struct Db(Arc<Mutex<Connection>>);

impl Db {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)
                .with_context(|| format!("failed to create {}", dir.display()))?;
        }
        let conn = Connection::open(path)
            .with_context(|| format!("failed to open the database {}", path.display()))?;
        // It holds the agents' keys and the hashes of the sessions: only its owner reads it,
        // whatever the umask of whoever started the panel.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let private =
                |p: &Path, mode| std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode));
            if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
                private(dir, 0o700).ok();
            }
            private(path, 0o600).ok();
        }
        Self::init(conn)
    }

    pub fn in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(mut conn: Connection) -> Result<Self> {
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        migrate(&mut conn)?;
        Ok(Self(Arc::new(Mutex::new(conn))))
    }

    pub fn conn(&self) -> MutexGuard<'_, Connection> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn meta(&self, key: &str) -> Result<Option<String>> {
        let conn = self.conn();
        let mut stmt = conn.prepare_cached("SELECT value FROM meta WHERE key = ?1")?;
        let mut rows = stmt.query([key])?;
        Ok(rows.next()?.map(|r| r.get(0)).transpose()?)
    }

    pub fn set_meta(&self, key: &str, value: &str) -> Result<()> {
        self.conn().execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2)
             ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            [key, value],
        )?;
        Ok(())
    }

    /// Adds a line to the audit log.
    pub fn audit(&self, who: &str, ip: Option<&str>, what: &str) -> Result<()> {
        let at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()) as i64;
        self.conn().execute(
            "INSERT INTO audit (at, who, ip, what) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![at, who, ip, what],
        )?;
        Ok(())
    }
}

fn migrate(conn: &mut Connection) -> Result<()> {
    let version: usize = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if version > MIGRATIONS.len() {
        anyhow::bail!(
            "the database is from a newer panel (schema {version}, this one knows {})",
            MIGRATIONS.len()
        );
    }
    for (i, sql) in MIGRATIONS.iter().enumerate().skip(version) {
        let tx = conn.transaction()?;
        tx.execute_batch(sql)
            .with_context(|| format!("migration {}", i + 1))?;
        tx.pragma_update(None, "user_version", i + 1)?;
        tx.commit()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_schema_is_made_once_and_reopened() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("panel.db");
        let db = Db::open(&path).unwrap();
        assert_eq!(db.meta("x").unwrap(), None);
        db.set_meta("x", "1").unwrap();
        db.set_meta("x", "2").unwrap();
        db.audit("cli", None, "installed").unwrap();
        drop(db);

        let db = Db::open(&path).unwrap();
        assert_eq!(db.meta("x").unwrap().as_deref(), Some("2"));
        let lines: i64 = db
            .conn()
            .query_row("SELECT count(*) FROM audit", [], |r| r.get(0))
            .unwrap();
        assert_eq!(lines, 1);
        let version: usize = db
            .conn()
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
        assert_eq!(version, MIGRATIONS.len());
    }

    #[test]
    fn servers_from_before_arranging_keep_the_order_they_had() {
        let mut conn = Connection::open_in_memory().unwrap();
        // A panel from before the position column, with three servers on it.
        for (i, sql) in MIGRATIONS.iter().enumerate().take(15) {
            conn.execute_batch(sql).unwrap();
            conn.pragma_update(None, "user_version", i + 1).unwrap();
        }
        conn.execute_batch(
            "INSERT INTO servers (id, name, key, created) VALUES
                 ('c3', 'third', 'k', 300), ('b2', 'second-b', 'k', 200),
                 ('a1', 'second-a', 'k', 200), ('z0', 'first', 'k', 100);",
        )
        .unwrap();
        migrate(&mut conn).unwrap();
        let order: Vec<(String, i64)> = conn
            .prepare("SELECT id, position FROM servers ORDER BY position")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(
            order,
            [("z0", 0), ("a1", 1), ("b2", 2), ("c3", 3)]
                .map(|(id, p)| (id.to_owned(), p))
                .to_vec()
        );
    }

    #[test]
    fn a_newer_database_is_refused() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "user_version", MIGRATIONS.len() + 1)
            .unwrap();
        let err = migrate(&mut conn).unwrap_err();
        assert!(err.to_string().contains("newer panel"), "{err}");
    }
}
