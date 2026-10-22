//! The panel's side of the agents: it accepts their links, checks who they are, asks them
//! for their health and tunnels every couple of seconds, and keeps the latest of it for
//! the API.
//!
//! An agent proves itself in one of two ways. A registered one answers the panel's
//! random challenge with a keyed hash only its key makes. A new one shows the join
//! secret from its join code, which works once; the panel then makes it an identity (an
//! id and a key), sends it over the link, and forgets the secret. The link token in the
//! handshake is the first gate; the key is the second, so a leaked token alone opens no
//! server.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Result};
use bytes::Bytes;
use kariz::mux::Side;
use kariz::session::Session;
use rusqlite::{params, OptionalExtension};
use serde::Serialize;
use tracing::{debug, info, warn};

use crate::agent::{Agent, AgentConfig};
use crate::auth::{hash_token, now};
use crate::collect::{self, Sampler};
use crate::config::random_hex;
use crate::db::Db;
use crate::join::{self, JoinCode, JOIN_TTL};
use crate::manage::{Services, Systemd};
use crate::wire::{Ack, Health, HelloReply, LinkKind, NetSpec, Request, TunnelInfo, MAX_REPLY};

/// How often the panel asks an agent for its state.
pub const POLL: Duration = Duration::from_secs(2);
/// A request that takes longer than this ends the link.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// How many times in a row the list of tunnels may fail before the link is given up.
const LATE_TUNNELS: u32 = 3;

/// One tunnel as the panel shows it: its config and state, and its traffic as a rate.
#[derive(Debug, Clone, Serialize)]
pub struct TunnelView {
    #[serde(flatten)]
    pub info: TunnelInfo,
    /// Mbit/s, both directions together, from two readings of the daemon's counters.
    pub rate_mbps: Option<f64>,
}

/// The private (GRE) network link that a server's agent reaches the panel through.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct GreRef {
    /// The link's id.
    pub link: String,
    /// The name of its network.
    pub network: String,
    /// GRE or VXLAN.
    pub kind: LinkKind,
}

/// A GRE link between the panel's own server and another one, as an address to dial the
/// panel at: `addr` is the panel's end, `peer_addr` the other server's.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct GreAddr {
    pub link: String,
    pub network: String,
    /// The other server (id).
    pub server: String,
    pub addr: String,
    pub peer_addr: String,
    pub kind: LinkKind,
}

/// A server added to come in through a private (GRE) network: the code its agent joins
/// with, and what the panel set up for it.
#[derive(Debug, Clone, Serialize)]
pub struct GreJoin {
    pub code: String,
    /// The server (listed now, waiting for its agent).
    pub id: String,
    pub name: String,
    /// The private network the link's addresses come from (its name).
    pub network: String,
    /// The panel's end of the link (what the agent dials) and the new server's.
    pub panel_addr: String,
    pub server_addr: String,
    /// GRE or VXLAN, as the network makes its links.
    pub kind: LinkKind,
}

/// How a server that comes in over a GRE link is reached: its agent dials the panel's end
/// of the link (on the panel's agents port, or one of the server's own), or the panel dials
/// the agent at the server's end, on a port the agent listens on (reverse).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GreWay {
    /// `agent_port` is the panel's agents port; `own` the agents port the server's agent is
    /// to dial (as [`Hub::set_agent_port`]: the panel's own clears one it had). None: the
    /// one it has.
    Dial {
        agent_port: u16,
        own: Option<u16>,
    },
    Reverse {
        port: u16,
    },
}

/// The pools a private network made for *Add server* over GRE is tried on, in order (the
/// same the Networks page suggests).
const JOIN_POOLS: [&str; 5] = [
    "10.77.0.0/16",
    "10.88.0.0/16",
    "10.200.0.0/16",
    "172.30.0.0/16",
    "192.168.222.0/24",
];

/// Why a server's link last ended or was refused, for the Servers page to explain.
#[derive(Debug, Clone, Serialize)]
pub struct LinkError {
    /// Unix seconds.
    pub at: i64,
    /// `link_ended` (the link dropped or went quiet) or `wrong_key` (an agent came with this
    /// server's id and a key that does not match: it needs a new code).
    pub kind: &'static str,
    pub detail: String,
}

/// A server as the API shows it.
#[derive(Debug, Clone, Serialize)]
pub struct ServerView {
    pub id: String,
    pub name: String,
    pub local: bool,
    pub online: bool,
    pub version: String,
    pub arch: String,
    pub hostname: String,
    /// The address other servers reach this one at (for private networks), if one was set.
    pub addr: Option<String>,
    /// The address it is known by (its public IPv4, else IPv6): what private networks use
    /// while none was set.
    pub addr_default: Option<String>,
    pub seen_secs: Option<u64>,
    /// The transport its agent's link uses now (`tcpmux`, `kcp`, `wss` or `quic`); none for the panel's
    /// own server and for one that is offline.
    pub link: Option<String>,
    /// When the panel last heard from this server (unix seconds), also from before the panel
    /// started; none for the panel's own server and for one that never connected.
    pub last_seen: Option<i64>,
    /// Why its link last ended or was refused, until it connects again.
    pub last_error: Option<LinkError>,
    /// The private network link its agent connects through (its link to the panel comes from
    /// that link's address), when it does.
    pub gre: Option<GreRef>,
    /// Where the panel dials this server, for one it connects to (reverse).
    pub reverse: Option<crate::reverse::Reverse>,
    /// The agents port of its own its agent dials, if it has one (`crate::agent_ports`).
    pub agent_port: Option<u16>,
    pub health: Option<Health>,
    /// The server's public IPv4 and IPv6 addresses, when they are known: what its agent
    /// reports, or the address its link comes from.
    pub ip4: Option<String>,
    pub ip6: Option<String>,
    pub tunnels: Vec<TunnelView>,
}

/// The public addresses of a server: its own (as its health reports them) when they are
/// public, else the address its link was seen coming from.
fn addresses(
    health: Option<&Health>,
    peer: Option<std::net::IpAddr>,
) -> (Option<String>, Option<String>) {
    let mut v4 = health.and_then(|h| h.ip4.clone());
    let mut v6 = health.and_then(|h| h.ip6.clone());
    if let Some(ip) = peer {
        let text = ip.to_string();
        match ip {
            std::net::IpAddr::V4(_)
                if collect::public_ip4(&text)
                    && !v4.as_deref().is_some_and(collect::public_ip4) =>
            {
                v4 = Some(text);
            }
            std::net::IpAddr::V6(_)
                if collect::public_ip6(&text)
                    && !v6.as_deref().is_some_and(collect::public_ip6) =>
            {
                v6 = Some(text);
            }
            _ => {}
        }
    }
    (v4, v6)
}

/// The link between the panel's own server and `server` whose end on `server` is `ip`: the
/// agent's link comes from there when the agent was given the panel's address on that link.
fn gre_via(
    links: &[crate::networks::Link],
    names: &HashMap<String, String>,
    server: &str,
    ip: &str,
) -> Option<GreRef> {
    links
        .iter()
        .find(|l| {
            (l.a == server && l.b == LOCAL && l.addr_a == ip)
                || (l.b == server && l.a == LOCAL && l.addr_b == ip)
        })
        .map(|l| GreRef {
            link: l.id.clone(),
            network: names.get(&l.network).cloned().unwrap_or_default(),
            kind: l.kind,
        })
}

/// The link between the panel's own server and `server`, for a server whose agent has not
/// come in yet.
fn gre_waiting(
    links: &[crate::networks::Link],
    names: &HashMap<String, String>,
    server: &str,
) -> Option<GreRef> {
    links
        .iter()
        .find(|l| (l.a == server && l.b == LOCAL) || (l.b == server && l.a == LOCAL))
        .map(|l| GreRef {
            link: l.id.clone(),
            network: names.get(&l.network).cloned().unwrap_or_default(),
            kind: l.kind,
        })
}

/// What a join secret is good for.
enum Spent {
    /// A new server, with the name the code carried (empty: the agent's host name).
    New(String),
    /// The server it registered before, whose agent has not confirmed yet.
    Unconfirmed { id: String, key: String },
    /// A server the panel already knows, taken over by a new agent (a new key).
    Rejoin { id: String },
}

#[derive(Default)]
struct Live {
    online: bool,
    seen: Option<Instant>,
    hostname: String,
    version: String,
    arch: String,
    link: Option<&'static str>,
    health: Option<Health>,
    /// Where the last link of this server came from.
    peer_ip: Option<std::net::IpAddr>,
    tunnels: Vec<TunnelView>,
    /// Bytes counted at the last reading of each tunnel, for the rates.
    last_bytes: HashMap<String, (u64, Instant)>,
    session: Option<Arc<Session>>,
    /// Whether each tunnel was connected at the last reading, to notice it changing.
    connected: HashMap<String, bool>,
    /// Why the last link ended, until the server connects again.
    last_error: Option<LinkError>,
}

pub struct Hub {
    pub(crate) db: Db,
    kariz_dir: PathBuf,
    live: Mutex<HashMap<String, Live>>,
    /// Servers the panel dials (reverse): the generation of each one's dialing loop. A loop
    /// whose number is no longer the server's stops (`crate::reverse`).
    pub(crate) reverse_gen: Mutex<HashMap<String, u64>>,
    /// The panel's own server, which answers the same requests as an agent, in-process.
    local: Arc<Agent>,
    services: Arc<dyn Services>,
    /// The running and recent tunnel operations (`crate::pair`).
    pub ops: crate::pair::Ops,
    /// Benchmark runs: which transport gets through best between two servers.
    pub bench: crate::bench::Runs,
    /// Charts and events.
    pub history: crate::history::History,
    /// Private networks and their links.
    pub networks: crate::networks::Networks,
    /// How long a new tunnel has to connect (shortened in tests).
    pub connect_wait: Duration,
    /// Where the panel finds releases and its own files (set once the panel starts).
    pub update_settings: std::sync::OnceLock<crate::updater::UpdateSettings>,
    /// What the last check for a newer release found.
    pub checked: Mutex<crate::updater::Checked>,
    /// The Telegram bot's connect code and how it is going.
    pub telegram: crate::telegram::State,
    /// Agents ports of a server's own (`crate::agent_ports`).
    pub(crate) ports: crate::agent_ports::Ports,
    /// Things to tell the user that did not come from watching the servers (a tunnel's
    /// traffic limit); the Telegram alerts take them.
    notices: Mutex<Vec<crate::alerts::Notice>>,
}

pub const LOCAL: &str = "local";

/// The position a new server takes: after every other one, the panel's own included.
const NEXT_POSITION: &str = "(SELECT max(
     coalesce((SELECT max(position) FROM servers), -1),
     coalesce((SELECT CAST(value AS INTEGER) FROM meta WHERE key = 'local_position'), -1)
 ) + 1)";

impl Hub {
    pub fn new(db: Db, kariz_dir: PathBuf) -> Arc<Self> {
        Self::with_services(db, kariz_dir, Arc::new(Systemd))
    }

    /// A hub whose own server runs its tunnels through `services`.
    pub fn with_services(db: Db, kariz_dir: PathBuf, services: Arc<dyn Services>) -> Arc<Self> {
        Self::with_options(
            db,
            kariz_dir,
            services,
            crate::pair::CONNECT_WAIT,
            None,
            None,
        )
    }

    /// Like [`Hub::with_services`], and this server's private network links are kept in
    /// `state_dir`, so they come back after a reboot.
    pub fn with_state_dir(
        db: Db,
        kariz_dir: PathBuf,
        services: Arc<dyn Services>,
        state_dir: PathBuf,
    ) -> Arc<Self> {
        Self::with_options(
            db,
            kariz_dir,
            services,
            crate::pair::CONNECT_WAIT,
            Some(state_dir),
            None,
        )
    }

    /// Also sets how long a new tunnel has to connect.
    pub fn with_options(
        db: Db,
        kariz_dir: PathBuf,
        services: Arc<dyn Services>,
        connect_wait: Duration,
        state_dir: Option<PathBuf>,
        exec: Option<Arc<dyn crate::net::Exec>>,
    ) -> Arc<Self> {
        let config = AgentConfig {
            panel: String::new(),
            link_token: String::new(),
            join: None,
            id: None,
            key: None,
            kariz_dir: kariz_dir.clone(),
            services: Default::default(),
            release_key: None,
            transport: None,
            listen: None,
            terminal: false,
        };
        Arc::new(Self {
            history: crate::history::History::new(db.clone()),
            networks: crate::networks::Networks::new(db.clone()),
            db,
            local: Agent::with_exec(
                &state_dir.map_or_else(PathBuf::new, |d| d.join("local-agent.toml")),
                config,
                services.clone(),
                exec.unwrap_or_else(|| Arc::new(crate::net::Real)),
            ),
            services,
            ops: crate::pair::Ops::default(),
            bench: crate::bench::Runs::default(),
            connect_wait,
            update_settings: std::sync::OnceLock::new(),
            checked: Mutex::new(crate::updater::Checked::default()),
            telegram: crate::telegram::State::default(),
            ports: crate::agent_ports::Ports::default(),
            notices: Mutex::new(Vec::new()),
            kariz_dir,
            live: Mutex::new(HashMap::new()),
            reverse_gen: Mutex::new(HashMap::new()),
        })
    }

    /// One request to a server (the panel's own, or an agent that is connected), and its
    /// raw answer.
    pub async fn ask(&self, server: &str, request: &Request) -> Result<Vec<u8>> {
        self.ask_within(server, request, REQUEST_TIMEOUT).await
    }

    /// Like [`Hub::ask`], for a request that is allowed to take up to `limit`.
    pub async fn ask_within(
        &self,
        server: &str,
        request: &Request,
        limit: Duration,
    ) -> Result<Vec<u8>> {
        if server == LOCAL {
            return Ok(self.local.handle(request.clone()).await);
        }
        let session = self
            .live()
            .get(server)
            .filter(|l| l.online)
            .and_then(|l| l.session.clone())
            .ok_or_else(|| anyhow!("that server is not connected"))?;
        request_within(&session, request, limit).await
    }

    /// Whether the panel may open a terminal on its own server (`panel.toml`'s `terminal`).
    pub fn allow_terminal(&self, on: bool) {
        self.local.allow_terminal(on);
    }

    /// Opens a terminal on `server`: a stream of the agent's link that stays open, or, on
    /// the panel's own server, a pipe to a shell served in process.
    pub async fn open_terminal(
        &self,
        server: &str,
        cols: u16,
        rows: u16,
    ) -> Result<crate::terminal::Backend> {
        if server == LOCAL {
            return Ok(crate::terminal::Backend::Local(
                self.local.open_shell(cols, rows),
            ));
        }
        let session = self
            .live()
            .get(server)
            .filter(|l| l.online)
            .and_then(|l| l.session.clone())
            .ok_or_else(|| anyhow!("not connected"))?;
        let syn = serde_json::to_vec(&Request::Shell { cols, rows })?;
        Ok(crate::terminal::Backend::Remote(
            session.open(Bytes::from(syn))?,
        ))
    }

    /// Like [`Hub::ask`], with the answer read as `T`.
    pub async fn ask_as<T: serde::de::DeserializeOwned>(
        &self,
        server: &str,
        request: &Request,
    ) -> Result<T> {
        self.ask_as_within(server, request, REQUEST_TIMEOUT).await
    }

    /// Like [`Hub::ask_as`], for a request that is allowed to take up to `limit`.
    pub async fn ask_as_within<T: serde::de::DeserializeOwned>(
        &self,
        server: &str,
        request: &Request,
        limit: Duration,
    ) -> Result<T> {
        let raw = self.ask_within(server, request, limit).await?;
        serde_json::from_slice(&raw).map_err(|_| match serde_json::from_slice::<Ack>(&raw) {
            Ok(Ack { error: Some(e), .. }) => anyhow!(e),
            _ => anyhow!("the server's answer was not understood"),
        })
    }

    fn live(&self) -> MutexGuard<'_, HashMap<String, Live>> {
        self.live.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The panel's link token, made the first time it is asked for.
    pub fn link_token(&self) -> Result<String> {
        if let Some(t) = self.db.meta("link_token")? {
            return Ok(t);
        }
        let token = crate::auth::new_token()?;
        self.db.set_meta("link_token", &token)?;
        Ok(token)
    }

    /// The address other servers reach `server` at: the one that was set, else the address
    /// the server is known by (what it connected with), so a private network needs no typing.
    ///
    /// A server that is not connected (the panel has just restarted and its agents have not
    /// come back yet) is still known by the address it had last, so a link to it is never
    /// treated as one without an address.
    pub fn addr_of(&self, server: &str) -> Option<String> {
        if let Some(saved) = self.saved_addr(server) {
            return Some(saved);
        }
        match self.default_addr(server) {
            Some(addr) => {
                self.remember_seen(server, &addr);
                Some(addr)
            }
            None => self.seen_addr(server),
        }
    }

    /// The address `server` was last known by while it was connected.
    fn seen_addr(&self, server: &str) -> Option<String> {
        self.db
            .conn()
            .query_row(
                "SELECT addr FROM server_seen WHERE server = ?1",
                [server],
                |r| r.get(0),
            )
            .optional()
            .ok()
            .flatten()
    }

    /// Keeps the address a server is known by, for after a restart. Nothing is written
    /// while it is the same.
    fn remember_seen(&self, server: &str, addr: &str) {
        let _ = self.db.conn().execute(
            "INSERT INTO server_seen (server, addr) VALUES (?1, ?2)
             ON CONFLICT (server) DO UPDATE SET addr = excluded.addr WHERE addr != excluded.addr",
            params![server, addr],
        );
    }

    /// The address that was set for `server`, if one was.
    fn saved_addr(&self, server: &str) -> Option<String> {
        self.db
            .conn()
            .query_row(
                "SELECT addr FROM server_addrs WHERE server = ?1",
                [server],
                |r| r.get(0),
            )
            .optional()
            .ok()
            .flatten()
    }

    /// The address a server is known by: its public IPv4 (its own, or the one its link comes
    /// from), else its IPv6. `None` while the panel knows neither.
    fn default_addr(&self, server: &str) -> Option<String> {
        let live = self.live();
        let l = live.get(server)?;
        let (v4, v6) = addresses(l.health.as_ref(), l.peer_ip);
        v4.or(v6)
    }

    /// Sets (or with an empty address, clears) the address other servers reach `server`
    /// at. A server that is not known is refused.
    pub fn set_addr(&self, server: &str, addr: &str) -> Result<()> {
        if server != LOCAL
            && self
                .db
                .conn()
                .query_row("SELECT 1 FROM servers WHERE id = ?1", [server], |_| Ok(()))
                .optional()?
                .is_none()
        {
            bail!("no_such_server");
        }
        let addr = addr.trim();
        if addr.is_empty() {
            self.db
                .conn()
                .execute("DELETE FROM server_addrs WHERE server = ?1", [server])?;
            return Ok(());
        }
        if !crate::netops::valid_addr(addr) {
            bail!("bad_input");
        }
        self.db.conn().execute(
            "INSERT INTO server_addrs (server, addr) VALUES (?1, ?2)
             ON CONFLICT (server) DO UPDATE SET addr = excluded.addr",
            params![server, addr],
        )?;
        Ok(())
    }

    /// What the panel's own server is called: the name chosen at install (`kariz-manager panel
    /// install`, or `kariz-panel init --name`), else its host name.
    pub fn local_name(&self) -> String {
        self.db
            .meta("local_name")
            .ok()
            .flatten()
            .filter(|n| !n.is_empty())
            .unwrap_or_else(collect::hostname)
    }

    /// Whether a server can be asked right now (the panel's own always can).
    pub fn is_online(&self, server: &str) -> bool {
        server == LOCAL || self.live().get(server).is_some_and(|l| l.online)
    }

    /// Remembers that a tunnel is to be removed from a server that cannot be reached now:
    /// its agent does it when it connects again. The tunnel disappears from the lists at once.
    pub fn queue_delete(&self, server: &str, name: &str) -> Result<()> {
        self.db.conn().execute(
            "INSERT OR IGNORE INTO pending_deletes (server, name) VALUES (?1, ?2)",
            params![server, name],
        )?;
        Ok(())
    }

    /// The names waiting to be removed from `server`.
    fn pending_deletes(&self, server: &str) -> Vec<String> {
        let conn = self.db.conn();
        let Ok(mut stmt) = conn.prepare("SELECT name FROM pending_deletes WHERE server = ?1")
        else {
            return Vec::new();
        };
        stmt.query_map([server], |r| r.get(0))
            .map(|rows| rows.filter_map(Result::ok).collect())
            .unwrap_or_default()
    }

    /// Whether a tunnel of this name is waiting to be removed from some server (the name
    /// cannot be used again until it is gone).
    pub fn delete_pending_for(&self, name: &str) -> bool {
        self.db
            .conn()
            .query_row(
                "SELECT 1 FROM pending_deletes WHERE name = ?1",
                [name],
                |_| Ok(()),
            )
            .optional()
            .ok()
            .flatten()
            .is_some()
    }

    /// Removes the tunnels that were deleted while this server was away.
    async fn apply_pending_deletes(&self, id: &str) {
        for name in self.pending_deletes(id) {
            let done = self
                .ask_as::<Ack>(id, &Request::TunnelDelete { name: name.clone() })
                .await;
            match done {
                Ok(ack) if ack.ok => {
                    let _ = self.db.conn().execute(
                        "DELETE FROM pending_deletes WHERE server = ?1 AND name = ?2",
                        params![id, name],
                    );
                    info!(server = %id, tunnel = %name, "a tunnel deleted while the server was away is removed");
                }
                Ok(ack) => {
                    warn!(server = %id, tunnel = %name, error = ?ack.error, "could not remove a deleted tunnel")
                }
                Err(e) => {
                    warn!(server = %id, tunnel = %name, error = %e, "could not remove a deleted tunnel")
                }
            }
        }
    }

    /// The networks each connected server already routes, by server id.
    pub fn routes(&self) -> crate::networks::Routes {
        self.live()
            .iter()
            .filter_map(|(id, l)| Some((id.clone(), l.health.as_ref()?.routes.clone())))
            .collect()
    }

    /// A join code for a new server: `name` (optional) is what it will be called, and
    /// `panel` where it should dial.
    pub fn create_join(&self, name: Option<&str>, panel: &str) -> Result<String> {
        self.create_join_via(name, panel, None)
    }

    /// Like [`Hub::create_join`], for an agent that is to use only `transport`.
    pub fn create_join_via(
        &self,
        name: Option<&str>,
        panel: &str,
        transport: Option<&str>,
    ) -> Result<String> {
        if transport.is_some_and(|x| !join::valid_transport(x)) {
            bail!("unknown transport");
        }
        let secret = random_hex(16)?;
        let t = now();
        self.db.conn().execute(
            "INSERT INTO joins (hash, name, created, expires, used) VALUES (?1, ?2, ?3, ?4, 0)",
            params![hash_token(&secret), name.unwrap_or(""), t, t + JOIN_TTL],
        )?;
        Ok(join::encode(&JoinCode {
            p: panel.to_owned(),
            t: self.link_token()?,
            j: secret,
            n: name.map(str::to_owned),
            x: transport.map(str::to_owned),
            g: None,
            l: None,
        }))
    }

    /// A join code for a server the panel already knows. The agent that spends it becomes
    /// that server again (same id, a new key), so the server keeps its name, its tunnels and
    /// its private network links. It is for an agent that is lost, broken or reinstalled,
    /// and for one that is to use another link transport.
    ///
    /// When `panel` is the panel's end of a GRE link to this server, the code carries the
    /// server's end too, so the agent can make the link again before it dials across it.
    pub fn create_rejoin(&self, id: &str, panel: &str, transport: Option<&str>) -> Result<String> {
        let host = panel
            .rsplit_once(':')
            .map_or(panel, |(h, _)| h)
            .trim_start_matches('[')
            .trim_end_matches(']');
        let link = self.gre_join_spec(id, host, false);
        self.rejoin_code(id, panel, transport, link, None)
    }

    /// The server's end of a GRE link between it and the panel's server, for the link where
    /// `addr` is the panel's end (`at_server` false: the agent dials it) or the server's own
    /// (true: the panel dials the agent there, reverse): what a join code carries so the
    /// agent can make the link first. `None` when there is no such link, or an end's public
    /// address is not known.
    pub(crate) fn gre_join_spec(
        &self,
        server: &str,
        addr: &str,
        at_server: bool,
    ) -> Option<NetSpec> {
        let link = self.networks.links(None).ok()?.into_iter().find(|l| {
            let (panel_end, server_end) = if l.a == LOCAL && l.b == server {
                (&l.addr_a, &l.addr_b)
            } else if l.b == LOCAL && l.a == server {
                (&l.addr_b, &l.addr_a)
            } else {
                return false;
            };
            (if at_server { server_end } else { panel_end }) == addr
        })?;
        let (mine, panels) = (self.addr_of(server)?, self.addr_of(LOCAL)?);
        Some(crate::netops::spec_for(&link, server, &mine, &panels))
    }

    /// A code that makes the agent that spends it server `id` again: it dials `panel` (with
    /// the GRE `link` made first, if there is one), or, with `listen`, waits there for the
    /// panel to dial it (reverse; `panel` is then empty).
    pub(crate) fn rejoin_code(
        &self,
        id: &str,
        panel: &str,
        transport: Option<&str>,
        link: Option<NetSpec>,
        listen: Option<String>,
    ) -> Result<String> {
        if transport.is_some_and(|x| !join::valid_transport(x)) {
            bail!("unknown transport");
        }
        let name: Option<String> = self
            .db
            .conn()
            .query_row("SELECT name FROM servers WHERE id = ?1", [id], |r| r.get(0))
            .optional()?;
        let Some(name) = name else {
            bail!("no_such_server");
        };
        let secret = random_hex(16)?;
        let t = now();
        {
            let conn = self.db.conn();
            // An earlier code for this server that nobody used is no longer wanted.
            conn.execute("DELETE FROM joins WHERE rejoin = ?1 AND used = 0", [id])?;
            conn.execute(
                "INSERT INTO joins (hash, name, created, expires, used, rejoin) VALUES (?1, ?2, ?3, ?4, 0, ?5)",
                params![hash_token(&secret), name, t, t + JOIN_TTL, id],
            )?;
        }
        Ok(join::encode(&JoinCode {
            p: panel.to_owned(),
            t: self.link_token()?,
            j: secret,
            n: Some(name),
            x: transport.map(str::to_owned),
            g: link,
            l: listen,
        }))
    }

    /// Adds a server that reaches the panel only through a private (GRE) network: the panel
    /// cannot ask it anything until its agent is in, so it does its own half now. The server
    /// is listed (waiting for its agent), the link between the two gets its private
    /// addresses, and the panel's end of it is made on this server. The code carries the
    /// other end: the agent on the new server makes it, then dials the panel across it, or
    /// (`GreWay::Reverse`) listens on it for the panel to dial.
    ///
    /// `public_ip` is the new server's public IPv4 address (GRE runs between the two public
    /// addresses); `network` the private network to take the addresses from, else the first
    /// one, else a new one is made. Errors are codes the page explains (`no_address:local`,
    /// `no_gre:local`, `same_address`, `address_taken:ID`, `no_such_network`, `pool_full`).
    pub async fn create_gre_join(
        self: &Arc<Self>,
        name: Option<&str>,
        public_ip: &str,
        network: Option<&str>,
        transport: Option<&str>,
        way: GreWay,
    ) -> Result<GreJoin> {
        self.create_link_join(name, public_ip, network, None, transport, way)
            .await
    }

    /// [`Self::create_gre_join`] with the kind of link asked for: without a `network`, the
    /// first network of that kind, else a new one (`kariz`, or `kariz-vxlan` on UDP 4789).
    pub async fn create_link_join(
        self: &Arc<Self>,
        name: Option<&str>,
        public_ip: &str,
        network: Option<&str>,
        kind: Option<LinkKind>,
        transport: Option<&str>,
        way: GreWay,
    ) -> Result<GreJoin> {
        if name.is_some_and(|n| !join::valid_name(n)) {
            bail!("bad_input");
        }
        let kind = self.join_kind(network, kind)?;
        let panels = self
            .gre_ready(None, public_ip, transport, way, kind)
            .await?;
        let network = self.network_for_join(network, kind)?;
        let (id, name) = self.add_waiting(name, public_ip)?;
        let made = self
            .gre_join_code(&id, &name, public_ip, &panels, &network, transport, way)
            .await;
        if made.is_err() {
            // Nothing half made stays: the server, its address and its link go again (and
            // with the link, the panel's end of it).
            let _ = self.remove(&id);
        }
        made
    }

    /// A code that brings a known server back over a GRE link between it and the panel's
    /// server (*Edit*), for one that has no such link yet: the link is made in `network` (else
    /// the first one, else a new one), the panel's end comes up now, and the code carries
    /// the server's end. Its agent then dials the panel across it, or listens on it for the
    /// panel (reverse). The server keeps its name, tunnels and other links.
    pub async fn create_gre_rejoin(
        self: &Arc<Self>,
        id: &str,
        public_ip: &str,
        network: Option<&str>,
        transport: Option<&str>,
        way: GreWay,
    ) -> Result<GreJoin> {
        self.create_link_rejoin(id, public_ip, network, None, transport, way)
            .await
    }

    /// [`Self::create_gre_rejoin`] with the kind of link asked for (as
    /// [`Self::create_link_join`]).
    pub async fn create_link_rejoin(
        self: &Arc<Self>,
        id: &str,
        public_ip: &str,
        network: Option<&str>,
        kind: Option<LinkKind>,
        transport: Option<&str>,
        way: GreWay,
    ) -> Result<GreJoin> {
        let name: Option<String> = self
            .db
            .conn()
            .query_row("SELECT name FROM servers WHERE id = ?1", [id], |r| r.get(0))
            .optional()?;
        let Some(name) = name.filter(|_| id != LOCAL) else {
            bail!("no_such_server");
        };
        let kind = self.join_kind(network, kind)?;
        // The server's own agent makes its end: an agent older than VXLAN would refuse it.
        if kind == LinkKind::Vxlan {
            let version = self
                .snapshot()?
                .into_iter()
                .find(|s| s.id == id)
                .map(|s| s.version)
                .unwrap_or_default();
            if !crate::pair::version_at_least(&version, crate::netops::VXLAN_SINCE) {
                bail!("old_agent_vxlan:{id}:{version}");
            }
        }
        let panels = self
            .gre_ready(Some(id), public_ip, transport, way, kind)
            .await?;
        let network = self.network_for_join(network, kind)?;
        let before = self.saved_addr(id);
        let port_before = self.agent_port_of(id);
        let made = self
            .gre_join_code(id, &name, public_ip, &panels, &network, transport, way)
            .await;
        if made.is_err() {
            let _ = self.set_addr(id, before.as_deref().unwrap_or(""));
            if matches!(way, GreWay::Dial { own: Some(_), .. }) {
                let _ = self.set_agent_port(id, port_before).await;
            }
        }
        made
    }

    /// What a GRE (or VXLAN) join needs before anything is made: a valid public IPv4 address
    /// that no other server has, and a panel's server with an IPv4 address of its own
    /// (returned) that can make links of `kind`.
    async fn gre_ready(
        self: &Arc<Self>,
        server: Option<&str>,
        public_ip: &str,
        transport: Option<&str>,
        way: GreWay,
        kind: LinkKind,
    ) -> Result<String> {
        if transport.is_some_and(|x| !join::valid_transport(x))
            || !crate::netops::valid_addr(public_ip)
            || matches!(way, GreWay::Reverse { port } if port == 0 || port == u16::MAX)
        {
            bail!("bad_input");
        }
        let panels = self
            .addr_of(LOCAL)
            .filter(|a| a.parse::<std::net::Ipv4Addr>().is_ok())
            .ok_or_else(|| anyhow!("no_address:{LOCAL}"))?;
        if panels == public_ip {
            bail!("same_address");
        }
        // A server the panel knows already is reconnected, not added a second time.
        let known: Vec<String> = self
            .db
            .conn()
            .prepare("SELECT id FROM servers")?
            .query_map([], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        if let Some(other) = known
            .iter()
            .filter(|s| Some(s.as_str()) != server)
            .find(|s| self.addr_of(s).as_deref() == Some(public_ip))
        {
            bail!("address_taken:{other}");
        }
        if kind == LinkKind::Vxlan {
            crate::netops::check_kind(self, LOCAL, kind)
                .await
                .map_err(|e| anyhow!(e))?;
            return Ok(panels);
        }
        let status: crate::wire::NetStatus = self
            .ask_as(LOCAL, &Request::NetStatus)
            .await
            .map_err(|e| anyhow!("no_gre:{LOCAL}:{e:#}"))?;
        if !status.gre {
            bail!("no_gre:{LOCAL}");
        }
        Ok(panels)
    }

    /// The kind of link a join makes: that of the network asked for (which must be of the
    /// kind asked for, if one is), else the kind asked for, else that of the first network
    /// there is, or GRE for the network it would make.
    fn join_kind(&self, wanted: Option<&str>, asked: Option<LinkKind>) -> Result<LinkKind> {
        let all = self.networks.networks()?;
        if let Some(id) = wanted {
            let found = all
                .into_iter()
                .find(|n| n.id == id)
                .ok_or_else(|| anyhow!("no_such_network"))?;
            if asked.is_some_and(|k| k != found.kind) {
                bail!("bad_input");
            }
            return Ok(found.kind);
        }
        Ok(asked.unwrap_or_else(|| all.first().map(|n| n.kind).unwrap_or_default()))
    }

    /// Gives server `id` the address `public_ip`, makes its GRE link to the panel's server in
    /// `network` (or takes the one there is), brings up the panel's end and makes the code
    /// that carries the other. A link made here goes again when this fails.
    #[allow(clippy::too_many_arguments)]
    async fn gre_join_code(
        self: &Arc<Self>,
        id: &str,
        name: &str,
        public_ip: &str,
        panels: &str,
        network: &str,
        transport: Option<&str>,
        way: GreWay,
    ) -> Result<GreJoin> {
        // An agents port of its own is listened on first: one that cannot be fails before
        // any link is made.
        if let GreWay::Dial {
            own: Some(want), ..
        } = way
        {
            self.set_agent_port(id, Some(want)).await?;
        }
        self.set_addr(id, public_ip)?;
        let existing = self
            .networks
            .links(Some(network))?
            .into_iter()
            .find(|l| (l.a == LOCAL && l.b == id) || (l.b == LOCAL && l.a == id));
        let made_here = existing.is_none();
        let link = match existing {
            Some(l) => l,
            None => self
                .networks
                .create_links(
                    network,
                    &[(LOCAL.to_owned(), id.to_owned())],
                    &self.routes(),
                )?
                .remove(0),
        };
        let result: Result<GreJoin> = async {
            let ours = crate::netops::spec_for(&link, LOCAL, panels, public_ip);
            let ack: Ack = self.ask_as(LOCAL, &Request::NetUp { net: ours }).await?;
            if !ack.ok {
                bail!("{}", ack.error.unwrap_or_else(|| "failed".into()));
            }
            let theirs = crate::netops::spec_for(&link, id, public_ip, panels);
            let panel_addr = if link.a == LOCAL {
                link.addr_a.clone()
            } else {
                link.addr_b.clone()
            };
            let code = match way {
                GreWay::Dial { agent_port, .. } => {
                    let agent_port = self.agent_port_of(id).unwrap_or(agent_port);
                    let code = self.rejoin_code(
                        id,
                        &format!("{panel_addr}:{agent_port}"),
                        transport,
                        Some(theirs.clone()),
                        None,
                    )?;
                    // Its agent dials the panel: the panel does not dial it.
                    self.set_reverse(id, None)?;
                    code
                }
                GreWay::Reverse { port } => {
                    // A private link to the panel's own server is never dialed through the proxy.
                    let target =
                        crate::reverse::Reverse::new(&theirs.address, port, transport, false)?;
                    let code = self.rejoin_code(
                        id,
                        "",
                        target.transport.as_deref(),
                        Some(theirs.clone()),
                        Some(target.listen()),
                    )?;
                    self.set_reverse(id, Some(&target))?;
                    code
                }
            };
            Ok(GreJoin {
                code,
                id: id.to_owned(),
                name: name.to_owned(),
                panel_addr,
                server_addr: theirs.address,
                kind: link.kind,
                network: self
                    .networks
                    .networks()?
                    .into_iter()
                    .find(|n| n.id == network)
                    .map(|n| n.name)
                    .unwrap_or_default(),
            })
        }
        .await;
        if result.is_err() && made_here {
            crate::netops::tear_down(self, &link).await;
        }
        result
    }

    /// Lists a server that is waiting for its agent: a key nobody holds (the code it is
    /// added with gives the agent a new one). Without a name, it is named after `addr`.
    pub(crate) fn add_waiting(&self, name: Option<&str>, addr: &str) -> Result<(String, String)> {
        let id = random_hex(8)?;
        let wanted = name.map_or_else(
            || {
                let plain: String = addr
                    .chars()
                    .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
                    .collect();
                match plain.trim_matches('-') {
                    "" => "server".to_owned(),
                    plain => format!("server-{plain}"),
                }
            },
            str::to_owned,
        );
        let name = self.unique_name(&wanted)?;
        self.db.conn().execute(
            &format!(
                "INSERT INTO servers (id, name, key, created, last_seen, position)
                 VALUES (?1, ?2, ?3, ?4, 0, {NEXT_POSITION})"
            ),
            params![id, name, random_hex(32)?, now()],
        )?;
        Ok((id, name))
    }

    /// The private network a server added over a link takes its addresses from: the one
    /// asked for, else the first of `kind` there is, else a new one of that kind (`kariz` for
    /// GRE, `kariz-vxlan` on UDP 4789 for VXLAN, on a pool no server routes).
    fn network_for_join(&self, wanted: Option<&str>, kind: LinkKind) -> Result<String> {
        let all = self.networks.networks()?;
        if let Some(id) = wanted {
            return all
                .into_iter()
                .find(|n| n.id == id)
                .map(|n| n.id)
                .ok_or_else(|| anyhow!("no_such_network"));
        }
        if let Some(first) = all.iter().find(|n| n.kind == kind) {
            return Ok(first.id.clone());
        }
        let base = match kind {
            LinkKind::Gre => "kariz",
            LinkKind::Vxlan => "kariz-vxlan",
        };
        // A name taken by a network of the other kind gets a number.
        let name = (1..)
            .map(|i| {
                if i == 1 {
                    base.to_owned()
                } else {
                    format!("{base}-{i}")
                }
            })
            .find(|n| !all.iter().any(|x| &x.name == n))
            .unwrap_or_else(|| base.to_owned());
        let routes: Vec<(String, Vec<String>)> = self.routes().into_iter().collect();
        let mut last = anyhow!("pool_full");
        for pool in JOIN_POOLS {
            match self
                .networks
                .create_network_of(&name, pool, kind, 0, &routes)
            {
                Ok(made) => return Ok(made.id),
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    /// The panel's own address on each GRE link to another server, to offer as the address
    /// that server's agent dials (the agent then goes through the private network).
    pub fn gre_addresses(&self) -> Result<Vec<GreAddr>> {
        let names: HashMap<String, String> = self
            .networks
            .networks()?
            .into_iter()
            .map(|n| (n.id, n.name))
            .collect();
        let mut out = Vec::new();
        for l in self.networks.links(None)? {
            let (server, addr, peer_addr) = if l.a == LOCAL {
                (l.b.clone(), l.addr_a.clone(), l.addr_b.clone())
            } else if l.b == LOCAL {
                (l.a.clone(), l.addr_b.clone(), l.addr_a.clone())
            } else {
                continue;
            };
            out.push(GreAddr {
                link: l.id,
                network: names.get(&l.network).cloned().unwrap_or_default(),
                server,
                addr,
                peer_addr,
                kind: l.kind,
            });
        }
        Ok(out)
    }

    /// The automatic restarts that are set.
    pub fn schedules(&self) -> Result<Vec<crate::schedule::Schedule>> {
        crate::schedule::list(&self.db)
    }

    /// Renames a server (not the panel's own, whose name is set on that server).
    pub fn rename(&self, id: &str, wanted: &str) -> Result<()> {
        if id == LOCAL {
            bail!("local");
        }
        if !join::valid_name(wanted) {
            bail!("bad_name");
        }
        // Read before the database is locked below (the lock is not re-entrant).
        let local = self.local_name();
        let conn = self.db.conn();
        let taken: i64 = conn.query_row(
            "SELECT count(*) FROM servers WHERE name = ?1 AND id != ?2",
            params![wanted, id],
            |r| r.get(0),
        )?;
        if taken > 0 || wanted == local {
            bail!("name_taken");
        }
        if conn.execute(
            "UPDATE servers SET name = ?2 WHERE id = ?1",
            params![id, wanted],
        )? == 0
        {
            bail!("no_such_server");
        }
        Ok(())
    }

    /// Where the panel's own server stands among the others (before them all until it is
    /// moved).
    fn local_position(&self) -> i64 {
        self.db
            .meta("local_position")
            .ok()
            .flatten()
            .and_then(|p| p.parse().ok())
            .unwrap_or(-1)
    }

    /// Puts the servers in the order given: every server once, the panel's own (`LOCAL`)
    /// included, and nothing else (`bad_order`).
    pub fn reorder(&self, ids: &[String]) -> Result<()> {
        let mut conn = self.db.conn();
        let known: HashSet<String> = conn
            .prepare("SELECT id FROM servers")?
            .query_map([], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        let given: HashSet<&str> = ids.iter().map(String::as_str).collect();
        if given.len() != ids.len()
            || ids.len() != known.len() + 1
            || !given.contains(LOCAL)
            || !known.iter().all(|id| given.contains(id.as_str()))
        {
            bail!("bad_order");
        }
        let tx = conn.transaction()?;
        for (at, id) in ids.iter().enumerate() {
            if id == LOCAL {
                tx.execute(
                    "INSERT INTO meta (key, value) VALUES ('local_position', ?1)
                     ON CONFLICT (key) DO UPDATE SET value = excluded.value",
                    [at.to_string()],
                )?;
            } else {
                tx.execute(
                    "UPDATE servers SET position = ?2 WHERE id = ?1",
                    params![id, at as i64],
                )?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// The panel's database (the tests set things in it directly).
    pub fn db(&self) -> &Db {
        &self.db
    }

    /// What a server reported, as if it had been polled: for the tests of what reads the
    /// snapshot (the traffic limits).
    #[cfg(test)]
    pub(crate) fn set_live_tunnels(
        &self,
        id: &str,
        online: bool,
        tunnels: Vec<crate::wire::TunnelInfo>,
    ) {
        // The snapshot lists the servers the database knows.
        let _ = self.db.conn().execute(
            "INSERT OR IGNORE INTO servers (id, name, key, created) VALUES (?1, ?1, '', 0)",
            [id],
        );
        let mut live = self.live();
        let entry = live.entry(id.to_owned()).or_default();
        entry.online = online;
        entry.tunnels = tunnels
            .into_iter()
            .map(|info| TunnelView {
                info,
                rate_mbps: None,
            })
            .collect();
    }

    /// Queues something to tell the user (the Telegram alerts send it).
    pub fn push_notice(&self, notice: crate::alerts::Notice) {
        self.notices
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(notice);
    }

    /// What was queued since the last time, in order.
    pub fn take_notices(&self) -> Vec<crate::alerts::Notice> {
        std::mem::take(&mut *self.notices.lock().unwrap_or_else(|e| e.into_inner()))
    }

    /// Closes a server's current link, if it has one, so its loop (or its agent) connects
    /// again: for a server the panel dials, with whatever changed in the meantime.
    pub(crate) fn close_session(&self, id: &str) {
        // Left in place: `run_session` marks the server offline when its link ends, and only
        // while that link is still the current one.
        if let Some(session) = self.live().get(id).and_then(|l| l.session.clone()) {
            session.close();
        }
    }

    /// Remembers why a server's link failed, for the Servers page.
    pub(crate) fn note_error(&self, id: &str, kind: &'static str, detail: String) {
        self.live().entry(id.to_owned()).or_default().last_error = Some(LinkError {
            at: now(),
            kind,
            detail,
        });
    }

    /// Spends a join secret, if it is valid: a new server to register (with the name the
    /// code carried), or the server it already registered whose agent never confirmed.
    fn spend_join(&self, secret: &str) -> Result<Option<Spent>> {
        let conn = self.db.conn();
        let t = now();
        conn.execute("DELETE FROM joins WHERE expires < ?1 - 86400", [t])?;
        let hash = hash_token(secret);
        let row: Option<(String, bool, Option<String>, Option<String>)> = conn
            .query_row(
                "SELECT name, used, server, rejoin FROM joins WHERE hash = ?1 AND expires > ?2",
                params![hash, t],
                |r| Ok((r.get(0)?, r.get::<_, i64>(1)? != 0, r.get(2)?, r.get(3)?)),
            )
            .optional()?;
        match row {
            None => Ok(None),
            Some((_, false, _, Some(id))) => {
                let changed = conn.execute(
                    "UPDATE joins SET used = 1 WHERE hash = ?1 AND used = 0",
                    [&hash],
                )?;
                Ok((changed == 1).then_some(Spent::Rejoin { id }))
            }
            Some((name, false, _, None)) => {
                let changed = conn.execute(
                    "UPDATE joins SET used = 1 WHERE hash = ?1 AND used = 0",
                    [&hash],
                )?;
                Ok((changed == 1).then_some(Spent::New(name)))
            }
            Some((_, true, Some(id), _)) => {
                let key: Option<String> = conn
                    .query_row("SELECT key FROM servers WHERE id = ?1", [&id], |r| r.get(0))
                    .optional()?;
                Ok(key.map(|key| Spent::Unconfirmed { id, key }))
            }
            Some((_, true, None, _)) => Ok(None),
        }
    }

    pub(crate) fn unique_name(&self, wanted: &str) -> Result<String> {
        let base = if join::valid_name(wanted) {
            wanted.to_owned()
        } else {
            format!("server-{}", random_hex(2)?)
        };
        // Read before the database is locked below (the lock is not re-entrant).
        let local = self.local_name();
        let conn = self.db.conn();
        let exists = |n: &str| -> rusqlite::Result<bool> {
            conn.query_row("SELECT count(*) FROM servers WHERE name = ?1", [n], |r| {
                r.get::<_, i64>(0)
            })
            .map(|c| c > 0)
        };
        let mut name = base.clone();
        let mut n = 1;
        // Not the panel's own server's name either.
        while exists(&name)? || name == local {
            n += 1;
            name = format!("{base}-{n}");
        }
        Ok(name)
    }

    /// Registers a new server: an id, a key and a name.
    fn register(&self, name: &str, hello: &HelloReply) -> Result<(String, String, String)> {
        let id = random_hex(8)?;
        let key = random_hex(32)?;
        let name = self.unique_name(name)?;
        self.db.conn().execute(
            &format!(
                "INSERT INTO servers (id, name, key, created, last_seen, version, arch, host, position)
                 VALUES (?1, ?2, ?3, ?4, ?4, ?5, ?6, ?7, {NEXT_POSITION})"
            ),
            params![id, name, key, now(), hello.version, hello.arch, hello.hostname],
        )?;
        Ok((id, key, name))
    }

    fn server_key(&self, id: &str) -> Result<Option<String>> {
        Ok(self
            .db
            .conn()
            .query_row("SELECT key FROM servers WHERE id = ?1", [id], |r| r.get(0))
            .optional()?)
    }

    /// Removes a server: its row, and its link if it has one. False if there is none.
    pub fn remove(self: &Arc<Self>, id: &str) -> Result<bool> {
        if id == LOCAL {
            return Ok(false);
        }
        // Its private network links go with it; the servers on their other ends are
        // told at once.
        let peers: Vec<String> = self
            .networks
            .links(None)?
            .into_iter()
            .filter(|l| l.a == id || l.b == id)
            .map(|l| if l.a == id { l.b } else { l.a })
            .collect();
        {
            let conn = self.db.conn();
            conn.execute("DELETE FROM net_links WHERE a = ?1 OR b = ?1", [id])?;
            conn.execute("DELETE FROM reverse_links WHERE server = ?1", [id])?;
            conn.execute("DELETE FROM agent_ports WHERE server = ?1", [id])?;
            conn.execute("DELETE FROM server_addrs WHERE server = ?1", [id])?;
            conn.execute("DELETE FROM server_seen WHERE server = ?1", [id])?;
            conn.execute("DELETE FROM pending_deletes WHERE server = ?1", [id])?;
            conn.execute(
                "DELETE FROM schedules WHERE kind = 'server' AND subject = ?1",
                [id],
            )?;
        }
        let removed = self
            .db
            .conn()
            .execute("DELETE FROM servers WHERE id = ?1", [id])?
            == 1;
        // The panel stops dialing it, if it connected to it, and listening for it on a
        // port of its own.
        self.forget_reverse(id);
        self.close_agent_port(id);
        for peer in peers {
            let hub = self.clone();
            tokio::spawn(async move {
                let _ = hub.net_sync(&peer).await;
            });
        }
        if let Some(live) = self.live().remove(id) {
            if let Some(session) = live.session {
                session.close();
            }
        }
        Ok(removed)
    }

    // ---- the agents' links ----

    /// Accepts agents for ever. Each connection gets its own task, so a slow or hostile
    /// peer never holds up the others.
    pub async fn serve_agents(self: Arc<Self>, acceptor: kariz::link::Acceptor) {
        self.serve_agents_as(acceptor, None).await;
    }

    /// Like [`Hub::serve_agents`], for `expected`'s agent alone when it is set (an agents
    /// port of that server's own): another agent there is let go.
    pub async fn serve_agents_as(
        self: Arc<Self>,
        acceptor: kariz::link::Acceptor,
        expected: Option<String>,
    ) {
        let link = acceptor.kind().name();
        loop {
            match acceptor.accept().await {
                Ok(pending) => {
                    let hub = self.clone();
                    let peer = pending.peer();
                    let expected = expected.clone();
                    tokio::spawn(async move {
                        match pending.establish(Side::Client).await {
                            Ok(session) => {
                                let ip = peer.ip().to_canonical();
                                if let Err(e) = hub
                                    .run_session(Arc::new(session), link, ip, expected.as_deref())
                                    .await
                                {
                                    debug!(%peer, error = %e, "an agent session ended");
                                }
                            }
                            Err(e) => debug!(%peer, error = %e, "an agent did not authenticate"),
                        }
                    });
                }
                Err(e) => {
                    warn!(error = %e, "accepting an agent failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }

    /// Serves one agent's link until it ends. `expected`: the server the panel dialed (a
    /// reverse link); an agent there that turns out to be another server is let go.
    pub(crate) async fn run_session(
        self: &Arc<Self>,
        session: Arc<Session>,
        link: &'static str,
        peer_ip: std::net::IpAddr,
        expected: Option<&str>,
    ) -> Result<()> {
        let identified =
            tokio::time::timeout(Duration::from_secs(20), self.identify(&session, expected))
                .await
                .map_err(|_| anyhow!("the agent did not identify itself in time"))
                .and_then(|r| r);
        let (id, hello) = match identified {
            Ok(found) => found,
            Err(e) => {
                // Said at warn: this is why a new server never shows up.
                warn!(error = %format!("{e:#}"), "an agent could not be identified");
                return Err(e);
            }
        };
        info!(server = %id, "an agent is connected");
        {
            let mut live = self.live();
            let entry = live.entry(id.clone()).or_default();
            // A new link replaces an old one that has not noticed it is dead.
            if let Some(old) = entry.session.replace(session.clone()) {
                old.close();
            }
            entry.online = true;
            entry.last_error = None;
            entry.link = Some(link);
            entry.peer_ip = Some(peer_ip);
            entry.hostname = hello.hostname.clone();
            entry.version = hello.version.clone();
            entry.arch = hello.arch.clone();
        }
        self.history.event("server_up", &id, "");
        self.apply_pending_deletes(&id).await;
        // The server is told its private network links (they may have changed while it
        // was away).
        if let Err(e) = self.net_sync(&id).await {
            warn!(server = %id, error = %e, "the private network links could not be synced");
        }
        // And the servers at the other ends of those links: this one may have a new address,
        // and a link that went down on their side while it was away is made again.
        self.net_sync_peers(&id);
        let result = self.poll(&id, &session).await;
        // Said at warn, with the reason: when a server goes offline by itself, this is the
        // line that tells why (the agent's own log has the other end of it).
        if let Err(e) = &result {
            warn!(server = %id, transport = link, error = %format!("{e:#}"), "an agent link ended");
        }
        // Closed from this side too, so the agent sees it end at once and comes back.
        session.close();
        let mut live = self.live();
        if let Some(entry) = live.get_mut(&id) {
            // Only if this link is still the current one.
            if entry
                .session
                .as_ref()
                .is_some_and(|s| Arc::ptr_eq(s, &session))
            {
                entry.online = false;
                entry.link = None;
                entry.session = None;
                entry.last_error = result.as_ref().err().map(|e| LinkError {
                    at: now(),
                    kind: "link_ended",
                    detail: format!("{e:#}"),
                });
                self.history.event("server_down", &id, "");
            }
        }
        result
    }

    /// Checks who is on the other end of a new link: a registered agent proves its key, a
    /// new one is registered with its join secret. On a link the panel dialed (`expected`,
    /// reverse) it must be that server: another one is let go before anything is written.
    async fn identify(
        &self,
        session: &Arc<Session>,
        expected: Option<&str>,
    ) -> Result<(String, HelloReply)> {
        let other = |id: &str| -> Result<()> {
            match expected {
                Some(want) if want != id => {
                    bail!("the agent there is another server ({id}), not {want}")
                }
                _ => Ok(()),
            }
        };
        let challenge = random_hex(16)?;
        let raw = request_on(
            session,
            &Request::Hello {
                challenge: challenge.clone(),
            },
        )
        .await?;
        let hello: HelloReply = serde_json::from_slice(&raw)?;

        if let (Some(id), Some(proof)) = (&hello.id, &hello.proof) {
            other(id)?;
            let key = self
                .server_key(id)?
                .ok_or_else(|| anyhow!("an agent with an unknown id"))?;
            let expected =
                crate::agent::proof(&key, &challenge).ok_or_else(|| anyhow!("a bad stored key"))?;
            // The keyed hash is compared in constant time.
            let ok = blake3::Hash::from_hex(&expected)?
                == blake3::Hash::from_hex(proof).map_err(|_| anyhow!("a malformed proof"))?;
            if !ok {
                self.note_error(id, "wrong_key", String::new());
                bail!("an agent with a wrong proof for {id}");
            }
            self.db.conn().execute(
                "UPDATE servers SET last_seen = ?2, version = ?3, arch = ?4, host = ?5 WHERE id = ?1",
                params![id, now(), hello.version, hello.arch, hello.hostname],
            )?;
            return Ok((id.clone(), hello));
        }
        let Some(secret) = &hello.join else {
            bail!("an agent with neither an identity nor a join secret");
        };
        let Some(spent) = self.spend_join(secret)? else {
            bail!("an agent with a join secret that is wrong, used or expired");
        };
        match &spent {
            Spent::New(_) if expected.is_some() => {
                bail!("the agent there has a code for a new server, not for this one")
            }
            Spent::Rejoin { id } | Spent::Unconfirmed { id, .. } => other(id)?,
            Spent::New(_) => {}
        }
        let hash = hash_token(secret);
        let mut rejoined = false;
        let (id, key, name) = match spent {
            Spent::New(wanted) => {
                let wanted = if wanted.is_empty() {
                    hello.hostname.clone()
                } else {
                    wanted
                };
                let (id, key, name) = self.register(&wanted, &hello)?;
                self.db.conn().execute(
                    "UPDATE joins SET server = ?2 WHERE hash = ?1",
                    params![hash, id],
                )?;
                (id, key, name)
            }
            // A server the panel knows, taken over by a new agent: the same id and name, a
            // new key (the old agent's key no longer opens it). Written before the agent is
            // told, so a link that drops now is finished later with the same key, as below.
            Spent::Rejoin { id } => {
                let name: Option<String> = self
                    .db
                    .conn()
                    .query_row("SELECT name FROM servers WHERE id = ?1", [&id], |r| {
                        r.get(0)
                    })
                    .optional()?;
                let Some(name) = name else {
                    bail!("the server of this code was removed");
                };
                let key = random_hex(32)?;
                {
                    let conn = self.db.conn();
                    conn.execute(
                        "UPDATE servers SET key = ?2 WHERE id = ?1",
                        params![id, key],
                    )?;
                    conn.execute(
                        "UPDATE joins SET server = ?2 WHERE hash = ?1",
                        params![hash, id],
                    )?;
                }
                rejoined = true;
                (id, key, name)
            }
            // Registered on an earlier link that dropped before the agent answered: the
            // same identity again (the agent may or may not have kept it; if it has, it
            // comes with its proof instead and never gets here).
            Spent::Unconfirmed { id, key } => {
                let name: String = self.db.conn().query_row(
                    "SELECT name FROM servers WHERE id = ?1",
                    [&id],
                    |r| r.get(0),
                )?;
                (id, key, name)
            }
        };
        let raw = request_on(
            session,
            &Request::Enroll {
                id: id.clone(),
                key,
            },
        )
        .await?;
        let ack: Ack = serde_json::from_slice(&raw)?;
        if !ack.ok {
            bail!(
                "the agent did not keep its identity: {}",
                ack.error.unwrap_or_default()
            );
        }
        // Confirmed: the code can never give this identity out again.
        self.db
            .conn()
            .execute("UPDATE joins SET server = NULL WHERE hash = ?1", [&hash])?;
        let what = if rejoined { "re-paired" } else { "registered" };
        let _ = self
            .db
            .audit("hub", None, &format!("{what} server {name} ({id})"));
        Ok((id, hello))
    }

    /// Asks the agent for its state every [`POLL`] until the link ends.
    async fn poll(&self, id: &str, session: &Arc<Session>) -> Result<()> {
        let mut tunnels: Vec<TunnelInfo> = Vec::new();
        let mut late = 0u32;
        loop {
            let health: Health =
                serde_json::from_slice(&request_on(session, &Request::Health).await?)?;
            // The list of tunnels is the slow request (every daemon is asked). One that
            // comes late is no reason to drop a link that answers everything else: the
            // last list stays, and only a few in a row end the link.
            match request_on(session, &Request::Tunnels).await {
                Ok(raw) => {
                    tunnels = serde_json::from_slice(&raw)?;
                    late = 0;
                }
                Err(e) => {
                    late += 1;
                    if late >= LATE_TUNNELS {
                        return Err(e);
                    }
                    debug!(server = %id, error = %e, "the tunnel list came late");
                }
            }
            self.update(id, Some(health), tunnels.clone());
            let _ = self.db.conn().execute(
                "UPDATE servers SET last_seen = ?2 WHERE id = ?1",
                params![id, now()],
            );
            tokio::select! {
                () = tokio::time::sleep(POLL) => {}
                () = session.closed() => bail!("the link closed"),
            }
        }
    }

    fn update(&self, id: &str, health: Option<Health>, tunnels: Vec<TunnelInfo>) {
        let mut live = self.live();
        let entry = live.entry(id.to_owned()).or_default();
        let t = Instant::now();
        let at = now();
        entry.seen = Some(t);
        if let Some(h) = &health {
            let h_ = &self.history;
            if let Some(v) = h.cpu_pct {
                h_.record(&format!("srv:{id}:cpu"), at, v);
            }
            if let (Some(u), Some(total)) = (h.mem_used, h.mem_total) {
                if total > 0 {
                    h_.record(
                        &format!("srv:{id}:mem"),
                        at,
                        u as f64 * 100.0 / total as f64,
                    );
                }
            }
            if let Some(v) = h.rx_bps {
                h_.record(&format!("srv:{id}:rx"), at, v * 8.0 / 1e6);
            }
            if let Some(v) = h.tx_bps {
                h_.record(&format!("srv:{id}:tx"), at, v * 8.0 / 1e6);
            }
        }
        entry.health = health;
        entry.tunnels = tunnels
            .into_iter()
            .map(|info| {
                let bytes = info
                    .status
                    .as_ref()
                    .map(|s| s.totals.bytes_up + s.totals.bytes_down);
                let rate = match (bytes, entry.last_bytes.get(&info.name)) {
                    (Some(now_b), Some(&(before, at))) => {
                        let secs = t.duration_since(at).as_secs_f64();
                        (secs > 0.05)
                            .then(|| now_b.saturating_sub(before) as f64 * 8.0 / secs / 1e6)
                    }
                    _ => None,
                };
                match bytes {
                    Some(b) => entry.last_bytes.insert(info.name.clone(), (b, t)),
                    None => entry.last_bytes.remove(&info.name),
                };
                if let Some(status) = &info.status {
                    let up = status.peer.connected;
                    // Changes worth telling; the first reading of a tunnel is not one.
                    match entry.connected.insert(info.name.clone(), up) {
                        Some(was) if was != up => self.history.event(
                            if up { "tunnel_up" } else { "tunnel_down" },
                            &info.name,
                            &format!("{id} {}", info.role),
                        ),
                        _ => {}
                    }
                    // The entry side's numbers stand for the tunnel.
                    if info.role == "entry" {
                        let h_ = &self.history;
                        h_.record(
                            &format!("tun:{}:rate", info.name),
                            at,
                            if up { rate.unwrap_or(0.0) } else { 0.0 },
                        );
                        h_.record(
                            &format!("tun:{}:conns", info.name),
                            at,
                            (status.totals.tcp_open + status.totals.udp_flows) as f64,
                        );
                        if let Some(rtt) = status.peer.rtt_ms {
                            h_.record(&format!("tun:{}:rtt", info.name), at, rtt);
                        }
                    }
                }
                TunnelView {
                    info,
                    rate_mbps: rate,
                }
            })
            .collect();
    }

    /// The panel's own server, sampled here (no link).
    pub async fn run_local(self: Arc<Self>) {
        tokio::spawn(self.services.clone().supervise());
        self.local.restore_net().await;
        if let Err(e) = self.net_sync(LOCAL).await {
            warn!(error = %e, "the private network links could not be synced");
        }
        let mut sampler = Sampler::default();
        let mut round = 0u32;
        // Tunnels made before the panel kept copies of them that could not be read back.
        let mut uncopied = std::collections::HashSet::new();
        loop {
            // Old history goes about once an hour.
            if round % 1800 == 0 {
                let _ = self.history.prune();
            }
            // The copies of tunnels made before 2.10.0: half a minute in, then every two
            // minutes (a server may have come back with one).
            if round % 60 == 15 {
                crate::specs::back_fill(&self, &mut uncopied).await;
            }
            // A look for a newer release: a minute after the start, then every day. It
            // only looks; installing is always the user's button.
            if (round == 30 || round % 43_200 == 43_199) && self.update_auto() {
                let _ = self.check_update().await;
            }
            round = round.wrapping_add(1);
            let health = sampler.sample();
            let tunnels = collect::tunnels(&self.kariz_dir, &*self.services).await;
            {
                let mut live = self.live();
                let entry = live.entry(LOCAL.to_owned()).or_default();
                entry.online = true;
                entry.hostname = collect::hostname();
                entry.version = crate::version().to_owned();
                entry.arch = std::env::consts::ARCH.to_owned();
            }
            self.update(LOCAL, Some(health), tunnels);
            // The first sync went with the address this server had last; now it knows its own.
            if round == 1 {
                if let Err(e) = self.net_sync(LOCAL).await {
                    warn!(error = %e, "the private network links could not be synced");
                }
            }
            tokio::time::sleep(POLL).await;
        }
    }

    /// Every server, in the order the admin arranged them, for the API.
    pub fn snapshot(&self) -> Result<Vec<ServerView>> {
        let rows: Vec<(String, String, String, String, String, i64, i64)> = {
            let conn = self.db.conn();
            let mut stmt = conn.prepare(
                "SELECT id, name, version, arch, host, last_seen, coalesce(position, 0)
                 FROM servers ORDER BY position, created, id",
            )?;
            let rows = stmt.query_map([], |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                ))
            })?;
            rows.collect::<rusqlite::Result<_>>()?
        };
        // The panel's own stands before the first server whose position is not before its.
        let local_at = {
            let mine = self.local_position();
            rows.iter().position(|r| r.6 >= mine).unwrap_or(rows.len())
        };
        let links = self.networks.links(None).unwrap_or_default();
        let names: HashMap<String, String> = self
            .networks
            .networks()
            .unwrap_or_default()
            .into_iter()
            .map(|n| (n.id, n.name))
            .collect();
        let live = self.live();
        let view = |id: &str,
                    name: String,
                    local: bool,
                    version: String,
                    arch: String,
                    host: String,
                    last_seen: i64| {
            let l = live.get(id);
            let hidden = self.pending_deletes(id);
            let (ip4, ip6) =
                addresses(l.and_then(|l| l.health.as_ref()), l.and_then(|l| l.peer_ip));
            ServerView {
                id: id.to_owned(),
                name,
                local,
                online: l.is_some_and(|l| l.online),
                version: l
                    .filter(|l| !l.version.is_empty())
                    .map_or(version, |l| l.version.clone()),
                arch: l
                    .filter(|l| !l.arch.is_empty())
                    .map_or(arch, |l| l.arch.clone()),
                hostname: l
                    .filter(|l| !l.hostname.is_empty())
                    .map_or(host, |l| l.hostname.clone()),
                addr: None,
                addr_default: ip4.clone().or_else(|| ip6.clone()),
                seen_secs: l.and_then(|l| l.seen).map(|s| s.elapsed().as_secs()),
                link: l
                    .filter(|l| l.online)
                    .and_then(|l| l.link)
                    .map(str::to_owned),
                last_seen: (last_seen > 0).then_some(last_seen),
                last_error: l.and_then(|l| l.last_error.clone()),
                reverse: None,
                agent_port: None,
                gre: match l.and_then(|l| l.peer_ip) {
                    Some(ip) => gre_via(&links, &names, id, &ip.to_string()),
                    // Never connected, and linked to the panel's server: it was added to
                    // come in through that link (links are otherwise made between servers
                    // that are connected).
                    None if !local && last_seen == 0 => gre_waiting(&links, &names, id),
                    None => None,
                },
                health: l.and_then(|l| l.health.clone()),
                ip4,
                ip6,
                tunnels: l
                    .map(|l| {
                        l.tunnels
                            .iter()
                            .filter(|t| !hidden.contains(&t.info.name))
                            .cloned()
                            .collect()
                    })
                    .unwrap_or_default(),
            }
        };
        let local_name = self.local_name();
        let mut out = Vec::with_capacity(rows.len() + 1);
        for (id, name, version, arch, host, last_seen, _) in rows {
            out.push(view(&id, name, false, version, arch, host, last_seen));
        }
        out.insert(
            local_at,
            view(
                LOCAL,
                local_name,
                true,
                crate::version().to_owned(),
                std::env::consts::ARCH.to_owned(),
                String::new(),
                0,
            ),
        );
        let addrs: HashMap<String, String> = {
            let conn = self.db.conn();
            let mut stmt = conn.prepare("SELECT server, addr FROM server_addrs")?;
            let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
            rows.collect::<rusqlite::Result<_>>()?
        };
        let mut reverse: HashMap<String, crate::reverse::Reverse> =
            self.reverse_all()?.into_iter().collect();
        let own_ports: HashMap<String, u16> = {
            let conn = self.db.conn();
            let mut stmt = conn.prepare("SELECT server, port FROM agent_ports")?;
            let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
            rows.collect::<rusqlite::Result<_>>()?
        };
        for s in &mut out {
            s.addr = addrs.get(&s.id).cloned();
            s.reverse = reverse.remove(&s.id);
            s.agent_port = own_ports.get(&s.id).copied();
            // One the panel dials across a GRE link uses it, also while it is offline.
            if s.gre.is_none() {
                if let Some(r) = &s.reverse {
                    s.gre = gre_via(&links, &names, &s.id, &r.host);
                }
            }
        }
        Ok(out)
    }
}

/// One request to an agent: a stream with the request in its open bytes and the answer
/// in what comes back.
pub async fn request_on(session: &Session, request: &Request) -> Result<Vec<u8>> {
    request_within(session, request, REQUEST_TIMEOUT).await
}

/// Like [`request_on`], with its own time limit (a speed test takes a while).
pub async fn request_within(
    session: &Session,
    request: &Request,
    limit: Duration,
) -> Result<Vec<u8>> {
    let syn = serde_json::to_vec(request)?;
    if syn.len() > crate::wire::MAX_REQUEST {
        bail!("too_large");
    }
    let ask = async {
        let stream = session.open(Bytes::from(syn))?;
        // The request is all in the open bytes: this side has nothing more to send. Left
        // open, the agent's dropping the stream after its answer would reset it.
        stream.finish()?;
        let mut reply = Vec::new();
        while let Some(chunk) = stream.recv().await? {
            reply.extend_from_slice(&chunk);
            if reply.len() > MAX_REPLY {
                bail!("the agent's answer is too large");
            }
        }
        Ok(reply)
    };
    tokio::time::timeout(limit, ask)
        .await
        .map_err(|_| anyhow!("the agent did not answer in time"))?
}

#[cfg(test)]
mod tests {
    use super::*;

    fn health(ip4: Option<&str>, ip6: Option<&str>) -> Health {
        Health {
            ip4: ip4.map(str::to_owned),
            ip6: ip6.map(str::to_owned),
            ..Default::default()
        }
    }

    #[test]
    fn the_panels_own_server_is_called_what_was_chosen_at_install() {
        let hub = Hub::new(
            Db::in_memory().unwrap(),
            std::env::temp_dir().join("kariz-none"),
        );
        // Not chosen: the host name.
        assert_eq!(hub.local_name(), collect::hostname());
        assert_eq!(hub.snapshot().unwrap()[0].name, collect::hostname());
        hub.db.set_meta("local_name", "tehran-main").unwrap();
        assert_eq!(hub.snapshot().unwrap()[0].name, "tehran-main");
        // A new server never takes that name.
        assert_eq!(hub.unique_name("tehran-main").unwrap(), "tehran-main-2");
        assert_eq!(hub.unique_name("frankfurt").unwrap(), "frankfurt");
    }

    #[test]
    fn servers_stand_where_they_were_put_and_a_new_one_comes_last() {
        let hub = Hub::new(
            Db::in_memory().unwrap(),
            std::env::temp_dir().join("kariz-none"),
        );
        let ids = |hub: &Hub| -> Vec<String> {
            hub.snapshot().unwrap().into_iter().map(|s| s.id).collect()
        };
        let (a, _) = hub.add_waiting(Some("frankfurt"), "192.0.2.1").unwrap();
        let a = a.as_str();
        let (b, _) = hub.add_waiting(Some("istanbul"), "192.0.2.2").unwrap();
        let b = b.as_str();
        // Before anything is arranged: the panel's own, then the others oldest first.
        assert_eq!(ids(&hub), [LOCAL, a, b]);

        let order = |list: &[&str]| list.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        hub.reorder(&order(&[b, LOCAL, a])).unwrap();
        assert_eq!(ids(&hub), [b, LOCAL, a]);

        // Every server once and nothing else, or nothing changes.
        for bad in [
            order(&[b, a]),
            order(&[b, LOCAL, a, a]),
            order(&[b, LOCAL, a, "stranger"]),
            order(&[b, LOCAL, "stranger"]),
            Vec::new(),
        ] {
            assert_eq!(hub.reorder(&bad).unwrap_err().to_string(), "bad_order");
        }
        assert_eq!(ids(&hub), [b, LOCAL, a]);

        // A new one comes last, also when the panel's own was put last.
        let (c, _) = hub.add_waiting(Some("tabriz"), "192.0.2.3").unwrap();
        let c = c.as_str();
        assert_eq!(ids(&hub), [b, LOCAL, a, c]);
        hub.reorder(&order(&[a, b, c, LOCAL])).unwrap();
        let (d, _) = hub.add_waiting(Some("shiraz"), "192.0.2.4").unwrap();
        let d = d.as_str();
        assert_eq!(ids(&hub), [a, b, c, LOCAL, d]);
    }

    /// What an update of the panel looks like to it: it starts, and no agent is connected yet.
    #[test]
    fn after_a_restart_a_link_is_not_dropped_for_a_server_that_has_not_connected_yet() {
        let hub = Hub::new(
            Db::in_memory().unwrap(),
            std::env::temp_dir().join("kariz-none"),
        );
        let net = hub
            .networks
            .create_network("main", "10.77.0.0/24", &[])
            .unwrap();
        // The two servers were connected, and the panel knew where they were.
        hub.live().entry("far".into()).or_default().health =
            Some(health(Some("203.0.113.9"), None));
        hub.live().entry(LOCAL.into()).or_default().health = Some(health(Some("192.0.2.1"), None));
        assert_eq!(hub.addr_of("far").as_deref(), Some("203.0.113.9"));
        assert_eq!(hub.addr_of(LOCAL).as_deref(), Some("192.0.2.1"));
        hub.networks
            .create_links(
                &net.id,
                &[(LOCAL.to_owned(), "far".to_owned())],
                &Default::default(),
            )
            .unwrap();
        assert_eq!(hub.net_specs(LOCAL).unwrap().len(), 1);

        // The panel restarts: nothing is connected, and no health has come in.
        hub.live().clear();
        let specs = hub.net_specs(LOCAL).unwrap();
        assert_eq!(
            specs.len(),
            1,
            "the link is still in the list the agent gets"
        );
        assert_eq!(
            (specs[0].local.as_str(), specs[0].remote.as_str()),
            ("192.0.2.1", "203.0.113.9")
        );
        assert_eq!(hub.net_specs("far").unwrap().len(), 1);
        assert_eq!(hub.net_peers(LOCAL), vec!["far".to_owned()]);

        // A server whose address was never known gives no list at all, never a partial one.
        hub.db
            .conn()
            .execute("DELETE FROM server_seen WHERE server = 'far'", [])
            .unwrap();
        assert!(hub.net_specs(LOCAL).is_err());
        assert!(hub.net_specs("far").is_err());
        // A server with no link is not held back by it.
        assert!(hub.net_specs("other").unwrap().is_empty());
    }

    /// A server that joined through the panel's address on a private network link: the panel
    /// offers that address for the server, knows the agent comes through the link, and does
    /// not let the link be deleted under it.
    #[tokio::test]
    async fn a_server_that_joined_through_a_gre_link_is_known_by_it_and_its_link_is_kept() {
        let hub = Hub::new(
            Db::in_memory().unwrap(),
            std::env::temp_dir().join("kariz-none"),
        );
        let net = hub
            .networks
            .create_network("main", "10.77.0.0/24", &[])
            .unwrap();
        let link = hub
            .networks
            .create_links(
                &net.id,
                &[(LOCAL.to_owned(), "far".to_owned())],
                &Default::default(),
            )
            .unwrap()
            .remove(0);
        // "far" sorts before "local": it holds the first address, the panel the second.
        assert_eq!(
            (link.a.as_str(), link.addr_a.as_str(), link.addr_b.as_str()),
            ("far", "10.77.0.1", "10.77.0.2")
        );
        hub.db
            .conn()
            .execute(
                "INSERT INTO servers (id, name, key, created) VALUES ('far', 'far', 'k', 1)",
                [],
            )
            .unwrap();

        // The panel's address on the link is what the server's agent is to dial.
        let offered = hub.gre_addresses().unwrap();
        assert_eq!(
            offered,
            vec![GreAddr {
                link: link.id.clone(),
                network: "main".into(),
                server: "far".into(),
                addr: "10.77.0.2".into(),
                peer_addr: "10.77.0.1".into(),
                kind: LinkKind::Gre,
            }]
        );

        let far = |hub: &Hub| {
            hub.snapshot()
                .unwrap()
                .into_iter()
                .find(|s| s.id == "far")
                .unwrap()
        };
        // Its agent came in from the public address: not through the link.
        {
            let mut live = hub.live();
            let l = live.entry("far".into()).or_default();
            l.online = true;
            l.peer_ip = Some("203.0.113.9".parse().unwrap());
        }
        assert_eq!(far(&hub).gre, None);
        // Or from its end of the link: through it. A private address is never taken for the
        // server's public one.
        hub.live().get_mut("far").unwrap().peer_ip = Some("10.77.0.1".parse().unwrap());
        let s = far(&hub);
        assert_eq!(
            s.gre,
            Some(GreRef {
                link: link.id.clone(),
                network: "main".into(),
                kind: LinkKind::Gre,
            })
        );
        assert_eq!(s.ip4, None, "a GRE address is not a public address");

        // The link stays while that agent runs through it.
        let refused = crate::netops::delete_link(&hub, &link.id)
            .await
            .unwrap_err();
        assert_eq!(refused.to_string(), "agent_uses:far");
        assert_eq!(hub.networks.links(None).unwrap().len(), 1);
    }

    #[test]
    fn a_delete_for_a_server_that_is_away_is_kept_and_hides_the_tunnel() {
        let hub = Hub::new(
            Db::in_memory().unwrap(),
            std::env::temp_dir().join("kariz-none"),
        );
        assert!(hub.is_online(LOCAL) && !hub.is_online("a1"));
        assert!(!hub.delete_pending_for("main"));
        hub.queue_delete("a1", "main").unwrap();
        hub.queue_delete("a1", "main").unwrap();
        assert!(hub.delete_pending_for("main") && !hub.delete_pending_for("other"));
        assert_eq!(hub.pending_deletes("a1"), vec!["main".to_owned()]);
        assert!(hub.pending_deletes("a2").is_empty());
    }

    #[test]
    fn a_servers_public_addresses_are_its_own_or_the_ones_its_link_comes_from() {
        let v4 = |s: &str| Some(std::net::IpAddr::V4(s.parse().unwrap()));
        // Its own public address is kept.
        let h = health(Some("5.9.10.11"), Some("2a01:4f8::1"));
        assert_eq!(
            addresses(Some(&h), v4("203.0.113.9")),
            (Some("5.9.10.11".into()), Some("2a01:4f8::1".into()))
        );
        // Behind NAT (a private address), the address the link is seen from stands in.
        let h = health(Some("10.0.0.5"), None);
        assert_eq!(
            addresses(Some(&h), v4("203.0.113.9")),
            (Some("203.0.113.9".into()), None)
        );
        // A private peer (a test, a private network) says nothing.
        assert_eq!(addresses(None, v4("192.168.1.4")), (None, None));
        // No health yet: only the peer.
        assert_eq!(
            addresses(None, v4("203.0.113.9")),
            (Some("203.0.113.9".into()), None)
        );
    }
}
