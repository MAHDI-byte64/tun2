//! A tunnel can have one side set up by hand, on a server the panel could not reach when
//! the tunnel was made. The panel writes the reachable side and records here that it is
//! waiting for the other; when that server's agent later reports the tunnel, the wait is
//! cleared (`crate::hub`). No token is kept — it appears once, in the bundle the operator
//! applies by hand (`crate::pair`).

use anyhow::Result;
use rusqlite::{params, OptionalExtension};
use serde::Serialize;

use crate::auth::now;
use crate::db::Db;

/// One tunnel waiting for its hand-applied side.
#[derive(Debug, Clone, Serialize)]
pub struct Pending {
    pub name: String,
    /// The side done by hand: `entry` or `exit`.
    pub role: String,
    /// The server it is on (id).
    pub server: String,
    pub created: i64,
}

/// Records that `name` waits for its `role` side on `server`.
pub fn set(db: &Db, name: &str, role: &str, server: &str) -> Result<()> {
    db.conn().execute(
        "INSERT INTO pending_manual (name, role, server, created) VALUES (?1, ?2, ?3, ?4) \
         ON CONFLICT(name) DO UPDATE SET role = excluded.role, server = excluded.server, \
         created = excluded.created",
        params![name, role, server, now()],
    )?;
    Ok(())
}

/// Clears the wait for a tunnel; whether there was one.
pub fn clear(db: &Db, name: &str) -> Result<bool> {
    Ok(db
        .conn()
        .execute("DELETE FROM pending_manual WHERE name = ?1", [name])?
        > 0)
}

/// The wait for one tunnel, if any.
pub fn get(db: &Db, name: &str) -> Result<Option<Pending>> {
    Ok(db
        .conn()
        .query_row(
            "SELECT name, role, server, created FROM pending_manual WHERE name = ?1",
            [name],
            row,
        )
        .optional()?)
}

/// Every tunnel waiting for a hand-applied side.
pub fn list(db: &Db) -> Result<Vec<Pending>> {
    let conn = db.conn();
    let mut stmt =
        conn.prepare("SELECT name, role, server, created FROM pending_manual ORDER BY created")?;
    let rows = stmt.query_map([], row)?.collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

fn row(r: &rusqlite::Row) -> rusqlite::Result<Pending> {
    Ok(Pending {
        name: r.get(0)?,
        role: r.get(1)?,
        server: r.get(2)?,
        created: r.get(3)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_wait_is_set_read_and_cleared() {
        let db = Db::in_memory().unwrap();
        assert!(get(&db, "t").unwrap().is_none());
        set(&db, "t", "exit", "srv-2").unwrap();
        let p = get(&db, "t").unwrap().unwrap();
        assert_eq!((p.role.as_str(), p.server.as_str()), ("exit", "srv-2"));
        assert_eq!(list(&db).unwrap().len(), 1);
        assert!(clear(&db, "t").unwrap());
        assert!(get(&db, "t").unwrap().is_none());
        assert!(!clear(&db, "t").unwrap());
    }
}
