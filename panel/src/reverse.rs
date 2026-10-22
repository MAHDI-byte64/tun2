//! Servers the panel connects to (reverse). Usually an agent dials the panel; for a server
//! whose agent cannot reach the panel (the panel's server takes no connections from outside,
//! or the way in is filtered) but which the panel can reach, the agent listens on a port of
//! its own and the panel dials it there. The link is the same either way: the same
//! transports (`tcpmux` and `kcp` on the port, `wss` and `quic` on the next), the same token
//! handshake, the panel opens the streams and the agent answers, and the agent still proves
//! who it is with its key (or, the first time, its join secret).
//!
//! One dialing loop per server keeps its link up. It starts with the panel and when a server
//! is added or switched to reverse, and stops when the server is removed or switched back:
//! every start takes a new generation number, and a loop whose number is no longer the
//! server's ends.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Result};
use kariz::mux::Side;
use rusqlite::{params, OptionalExtension};
use serde::Serialize;
use tracing::{debug, info, warn};

use crate::hub::{Hub, LOCAL};
use crate::join;

/// Where the panel dials a server's agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Reverse {
    /// A host name or an IP address (an IPv6 one without brackets).
    pub host: String,
    /// The agent's port: its link transports use it and the next one.
    pub port: u16,
    /// The one link transport to use; none: all of them in turn.
    pub transport: Option<String>,
}

impl Reverse {
    /// Checks what was typed: a host name or address, a port below 65535 (the next one is
    /// used too), and a link transport the panel knows (`auto` or none: all of them).
    pub fn new(host: &str, port: u16, transport: Option<&str>) -> Result<Self> {
        let host = host
            .trim()
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_ascii_lowercase();
        let transport = transport
            .map(str::trim)
            .filter(|t| !t.is_empty() && *t != "auto");
        if !join::valid_host(&host)
            || host.contains(['[', ']'])
            || port == 0
            || port == u16::MAX
            || transport.is_some_and(|t| !join::valid_transport(t))
        {
            bail!("bad_input");
        }
        Ok(Self {
            host,
            port,
            transport: transport.map(str::to_owned),
        })
    }

    /// `host:port`, an IPv6 address in brackets.
    pub fn addr(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    /// Where the agent listens for it: every address, on its port.
    pub fn listen(&self) -> String {
        format!("0.0.0.0:{}", self.port)
    }
}

/// A server added for the panel to connect to: the code its agent joins with.
#[derive(Debug, Clone, Serialize)]
pub struct ReverseJoin {
    pub code: String,
    /// The server (listed now, waiting for its agent).
    pub id: String,
    pub name: String,
}

/// After a link that worked for this long, a link that ends is not counted as a failure.
const GOOD_LINK: Duration = Duration::from_secs(10);
/// Failed tries in a row before the next transport is tried (with *auto*).
const MISSES_BEFORE_SWITCH: u32 = 2;

impl Hub {
    /// Where the panel dials `server`, if it is one the panel connects to.
    pub fn reverse_of(&self, server: &str) -> Option<Reverse> {
        self.db
            .conn()
            .query_row(
                "SELECT host, port, transport FROM reverse_links WHERE server = ?1",
                [server],
                |r| {
                    Ok(Reverse {
                        host: r.get(0)?,
                        port: r.get(1)?,
                        transport: r.get(2)?,
                    })
                },
            )
            .optional()
            .ok()
            .flatten()
    }

    /// Every server the panel connects to, with where.
    pub fn reverse_all(&self) -> Result<Vec<(String, Reverse)>> {
        let conn = self.db.conn();
        let mut stmt = conn.prepare("SELECT server, host, port, transport FROM reverse_links")?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get(0)?,
                Reverse {
                    host: r.get(1)?,
                    port: r.get(2)?,
                    transport: r.get(3)?,
                },
            ))
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Makes `server` one the panel connects to, at `target` (or, with `None`, one whose
    /// agent dials the panel again). Its dialing loop starts again, or stops.
    pub fn set_reverse(self: &Arc<Self>, server: &str, target: Option<&Reverse>) -> Result<()> {
        match target {
            Some(t) => {
                self.db.conn().execute(
                    "INSERT INTO reverse_links (server, host, port, transport) VALUES (?1, ?2, ?3, ?4)
                     ON CONFLICT (server) DO UPDATE SET host = excluded.host, port = excluded.port, transport = excluded.transport",
                    params![server, t.host, t.port, t.transport],
                )?;
                self.start_reverse(server);
            }
            None => {
                self.db
                    .conn()
                    .execute("DELETE FROM reverse_links WHERE server = ?1", [server])?;
                self.next_generation(server);
            }
        }
        Ok(())
    }

    /// Starts the dialing loop of every server the panel connects to (the panel's start).
    pub fn start_reverse_links(self: &Arc<Self>) {
        for (server, _) in self.reverse_all().unwrap_or_default() {
            self.start_reverse(&server);
        }
    }

    /// Stops the dialing loop of a server that is being removed.
    pub(crate) fn forget_reverse(&self, server: &str) {
        self.next_generation(server);
    }

    fn next_generation(&self, server: &str) -> u64 {
        let mut gens = self.reverse_gen.lock().unwrap_or_else(|e| e.into_inner());
        let gen = gens.entry(server.to_owned()).or_default();
        *gen += 1;
        *gen
    }

    fn generation_is(&self, server: &str, gen: u64) -> bool {
        self.reverse_gen
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(server)
            .is_some_and(|g| *g == gen)
    }

    /// (Re)starts `server`'s dialing loop: a loop that runs already stops at its next turn.
    fn start_reverse(self: &Arc<Self>, server: &str) {
        let gen = self.next_generation(server);
        let hub = self.clone();
        let server = server.to_owned();
        tokio::spawn(async move { hub.reverse_loop(server, gen).await });
    }

    /// Keeps a link to the server's agent up, until the server stops being one the panel
    /// connects to. A link that fails is tried again after 1 s, then up to 30 s (5 s while
    /// the server has never connected, so a new one comes in soon after its command runs);
    /// with *auto*, every second failure moves on to the next transport.
    async fn reverse_loop(self: Arc<Self>, server: String, gen: u64) {
        let mut at = 0usize;
        let mut misses = 0u32;
        let mut backoff = Duration::from_secs(1);
        loop {
            if !self.generation_is(&server, gen) {
                return;
            }
            let Some(target) = self.reverse_of(&server) else {
                return;
            };
            let kinds: Vec<_> = kariz::link::LINK_TRANSPORTS
                .into_iter()
                .filter(|k| !matches!(target.transport.as_deref(), Some(t) if t != k.name()))
                .collect();
            let Some(&kind) = kinds.get(at % kinds.len().max(1)) else {
                warn!(server = %server, "no link transport to dial this server with");
                return;
            };
            match self.reverse_once(&server, &target, kind).await {
                Ok(true) => {
                    misses = 0;
                    backoff = Duration::from_secs(1);
                }
                Ok(false) => misses += 1,
                Err(e) => {
                    misses += 1;
                    debug!(server = %server, transport = kind.name(), error = %format!("{e:#}"), "could not connect to the server");
                    self.note_error(
                        &server,
                        "link_ended",
                        format!(
                            "the panel could not connect to {} over {}: {e:#}",
                            target.addr(),
                            kind.name()
                        ),
                    );
                }
            }
            if !self.generation_is(&server, gen) {
                return;
            }
            if misses >= MISSES_BEFORE_SWITCH && kinds.len() > 1 {
                misses = 0;
                at = at.wrapping_add(1);
            }
            tokio::time::sleep(backoff).await;
            let waiting = self
                .db
                .conn()
                .query_row(
                    "SELECT last_seen FROM servers WHERE id = ?1",
                    [&server],
                    |r| r.get::<_, i64>(0),
                )
                .is_ok_and(|seen| seen == 0);
            let cap = Duration::from_secs(if waiting { 5 } else { 30 });
            backoff = (backoff * 2).min(cap);
        }
    }

    /// One link to the server, served until it ends. True when it worked for a while.
    async fn reverse_once(
        self: &Arc<Self>,
        server: &str,
        target: &Reverse,
        kind: kariz::config::TransportKind,
    ) -> Result<bool> {
        let addr = kariz::link::address_for(&target.addr(), kind)?;
        let peer = tokio::net::lookup_host(addr.as_str())
            .await
            .ok()
            .and_then(|mut a| a.next())
            .map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |a| a.ip().to_canonical());
        let dialer = kariz::link::Dialer::via(&addr, &self.link_token()?, kind)?;
        let session = dialer
            .connect(Side::Client)
            .await
            .map_err(|e| anyhow!("{e}"))?;
        info!(server = %server, address = %addr, transport = kind.name(), "connected to a server's agent (reverse)");
        let started = Instant::now();
        let result = self
            .run_session(Arc::new(session), kind.name(), peer, Some(server))
            .await;
        if let Err(e) = &result {
            debug!(server = %server, error = %format!("{e:#}"), "the link to the server ended");
        }
        Ok(started.elapsed() >= GOOD_LINK)
    }

    /// Adds a server for the panel to connect to: it is listed (waiting for its agent), the
    /// panel starts dialing `target`, and the code makes the agent on that server listen
    /// there. Errors: `bad_input`, `address_taken:ID` (another server is at that address).
    pub async fn create_reverse_join(
        self: &Arc<Self>,
        name: Option<&str>,
        target: Reverse,
    ) -> Result<ReverseJoin> {
        if name.is_some_and(|n| !join::valid_name(n)) {
            bail!("bad_input");
        }
        // A server the panel knows already is reconnected, not added a second time.
        for (other, at) in self.reverse_all()? {
            if at.host == target.host && at.port == target.port {
                bail!("address_taken:{other}");
            }
        }
        let known: Vec<String> = self
            .db
            .conn()
            .prepare("SELECT id FROM servers")?
            .query_map([], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        if let Some(other) = known
            .iter()
            .find(|s| self.addr_of(s).as_deref() == Some(target.host.as_str()))
        {
            bail!("address_taken:{other}");
        }
        let (id, name) = self.add_waiting(name, &target.host)?;
        let made: Result<ReverseJoin> = (|| {
            // An IPv4 address is also the server's address for private networks.
            if crate::netops::valid_addr(&target.host) {
                self.set_addr(&id, &target.host)?;
            }
            let code = self.rejoin_code(
                &id,
                "",
                target.transport.as_deref(),
                None,
                Some(target.listen()),
            )?;
            self.set_reverse(&id, Some(&target))?;
            Ok(ReverseJoin {
                code,
                id: id.clone(),
                name: name.clone(),
            })
        })();
        if made.is_err() {
            let _ = self.remove(&id);
        }
        made
    }

    /// A code that brings a known server back as one the panel connects to, at `target`
    /// (*Reconnect* or *Edit*): the server keeps its name, tunnels and links, and the panel
    /// dials the new address from now on. When that is the server's end of a GRE link to
    /// the panel's server, the code carries it, so the agent makes the link before it listens.
    pub fn create_reverse_rejoin(self: &Arc<Self>, id: &str, target: Reverse) -> Result<String> {
        if id == LOCAL {
            bail!("bad_input");
        }
        let code = self.rejoin_code(
            id,
            "",
            target.transport.as_deref(),
            self.gre_join_spec(id, &target.host, true),
            Some(target.listen()),
        )?;
        self.set_reverse(id, Some(&target))?;
        Ok(code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_target_is_checked_and_written_as_an_address() {
        let t = Reverse::new(" Fra.Example.com ", 29001, Some("auto")).unwrap();
        assert_eq!(
            (t.addr().as_str(), t.transport.as_deref()),
            ("fra.example.com:29001", None)
        );
        assert_eq!(t.listen(), "0.0.0.0:29001");
        let v6 = Reverse::new("[2001:db8::7]", 443, Some("quic")).unwrap();
        assert_eq!(v6.addr(), "[2001:db8::7]:443");
        assert_eq!(v6.transport.as_deref(), Some("quic"));
        for (host, port, x) in [
            ("", 29001, None),
            ("a b", 29001, None),
            ("a/b", 29001, None),
            ("203.0.113.5", 0, None),
            ("203.0.113.5", 65535, None),
            ("203.0.113.5", 29001, Some("pigeon")),
        ] {
            assert!(Reverse::new(host, port, x).is_err(), "{host} {port} {x:?}");
        }
    }
}
