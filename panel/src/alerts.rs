//! Deciding when a server or a tunnel going down is worth telling about.
//!
//! The panel already knows who is up (`Hub::snapshot`). This looks at that every few
//! seconds and keeps what would otherwise spam the user out of the way:
//!
//! * a server or tunnel has to stay down for a grace time before it is told about (a
//!   restart or a blip is not an incident), and a recovery is only told when the down was;
//! * for a while after the panel itself starts nothing is said (everything is offline for a
//!   moment); what is still down after that is said once;
//! * the tunnels of a server that is offline are not told one by one (the server's own
//!   message names them), and cannot be read anyway;
//! * a subject that goes down again and again is said to be unstable, then left alone
//!   until it settles.
//!
//! A tunnel can also be connected and still let no one through: every stream taken, or
//! the target down. The entry side's health probe finds that ([`ProbeStatus`]); a few
//! failed probes in a row are told like a tunnel going down. A tunnel whose streams are
//! nearly all taken is told about once, before it gets there.
//!
//! No clock and no network in here: `step` is given the time, so it is tested directly.

use std::collections::{HashMap, HashSet, VecDeque};

use kariz::stats::{ProbeOutcome, ProbeStatus};

use crate::hub::ServerView;

/// How many times one subject may be announced down in [`FLAP_WINDOW`] seconds before it
/// is called unstable and left alone.
const FLAP_MAX: usize = 4;
const FLAP_WINDOW: i64 = 3600;

/// How long after the panel starts nothing is said.
pub const STARTUP_GRACE: i64 = 60;

/// Failed health probes in a row (15 s apart) before a tunnel counts as letting no one
/// through.
const BLOCKED_AFTER: u32 = 3;
/// Share of the streams in use, in tenths, at which a tunnel is told to be nearly full,
/// and below which it may be told again.
const BUSY_AT: u64 = 8;
const BUSY_CLEAR: u64 = 7;

/// What the user chose to hear about, and how long a thing has to stay down first.
#[derive(Debug, Clone, Copy)]
pub struct Rules {
    pub servers: bool,
    pub tunnels: bool,
    pub server_grace: i64,
    pub tunnel_grace: i64,
}

impl Default for Rules {
    fn default() -> Self {
        Self {
            servers: true,
            tunnels: true,
            server_grace: 60,
            tunnel_grace: 30,
        }
    }
}

/// One thing to tell the user.
#[derive(Debug, Clone, PartialEq)]
pub enum Notice {
    ServerDown {
        name: String,
        /// The tunnels that run on it.
        tunnels: Vec<String>,
    },
    ServerUp {
        name: String,
        down_secs: i64,
    },
    TunnelDown {
        name: String,
        server: String,
        error: Option<String>,
    },
    TunnelUp {
        name: String,
        down_secs: i64,
    },
    /// A subject that keeps going down: its messages stop for now.
    Unstable {
        name: String,
    },
    /// Connected, but new connections do not get through: `target` when the exit side
    /// cannot reach it, otherwise `error` says why (every stream taken, no answer).
    TunnelBlocked {
        name: String,
        server: String,
        target: Option<String>,
        error: Option<String>,
    },
    TunnelUnblocked {
        name: String,
        blocked_secs: i64,
    },
    /// Most of the tunnel's streams are in use: soon new connections will wait and fail.
    TunnelBusy {
        name: String,
        streams: u64,
        max: u64,
    },
    /// A tunnel has used 80% of its traffic limit (`crate::quota`).
    QuotaNear {
        name: String,
        used: u64,
        limit: u64,
    },
    /// A tunnel was stopped: its traffic limit is reached.
    QuotaStopped {
        name: String,
        used: u64,
        limit: u64,
    },
    /// A tunnel's limit ends in `days` days (three or fewer).
    QuotaExpiring {
        name: String,
        days: u64,
    },
    /// A tunnel was stopped: its time is up.
    QuotaExpired {
        name: String,
    },
    /// A tunnel's hand-applied side has come up: it is no longer waiting.
    ManualSideUp {
        name: String,
    },
}

/// A subject that is down, since when, and whether the user was told.
#[derive(Debug)]
struct Track {
    name: String,
    since: i64,
    announced: bool,
    /// Where a tunnel runs, and why it is down; the tunnels of a server.
    server: String,
    error: Option<String>,
    tunnels: Vec<String>,
    /// A blocked tunnel: the target its exit side cannot reach.
    target: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Flap {
    Send,
    FirstHeldBack,
    HeldBack,
}

pub struct Alerter {
    started: i64,
    servers: HashMap<String, Track>,
    tunnels: HashMap<String, Track>,
    /// Tunnels that are connected but let no one through.
    blocked: HashMap<String, Track>,
    /// Tunnels told to be nearly full, until they are well below that again.
    busy: HashSet<String>,
    /// Nearly full tunnels found by the last look, to be told.
    busy_due: Vec<Notice>,
    /// When each subject was last announced down.
    announced: HashMap<String, VecDeque<i64>>,
    /// Subjects called unstable: their messages are held back.
    unstable: HashSet<String>,
    /// Recoveries found by the last look, to be told.
    recoveries: Vec<(String, bool, Notice)>,
}

/// What the readings say about one tunnel: down (with why), up, or not known (the server
/// is offline, or no daemon answered).
enum State {
    Down(Option<String>, String),
    Up,
    Unknown,
}

impl Alerter {
    pub fn new(now: i64) -> Self {
        Self {
            started: now,
            servers: HashMap::new(),
            tunnels: HashMap::new(),
            blocked: HashMap::new(),
            busy: HashSet::new(),
            busy_due: Vec::new(),
            announced: HashMap::new(),
            unstable: HashSet::new(),
            recoveries: Vec::new(),
        }
    }

    /// Looks at the servers as they are now and returns what is to be told. Tracking goes
    /// on whatever `rules` say: a thing that was down when the user turned a kind of
    /// message on is not announced late as if it had just happened.
    pub fn step(&mut self, views: &[ServerView], now: i64, rules: Rules) -> Vec<Notice> {
        self.look_at_servers(views, now);
        self.look_at_tunnels(views, now);
        self.look_at_health(views, now);

        let mut out = Vec::new();
        if now >= self.started + STARTUP_GRACE {
            let mut due: Vec<(bool, String)> = Vec::new();
            for (key, t) in &self.servers {
                if !t.announced && now - t.since >= rules.server_grace {
                    due.push((true, key.clone()));
                }
            }
            for (key, t) in &self.tunnels {
                if !t.announced && now - t.since >= rules.tunnel_grace {
                    due.push((false, key.clone()));
                }
            }
            // A stable order, so what comes out does not depend on the map.
            due.sort_by(|a, b| a.1.cmp(&b.1).then(b.0.cmp(&a.0)));
            for (is_server, key) in due {
                let subject = subject(is_server, &key);
                let flap = self.flap(&subject, now);
                let map = if is_server {
                    &mut self.servers
                } else {
                    &mut self.tunnels
                };
                let Some(t) = map.get_mut(&key) else { continue };
                t.announced = true;
                if !(if is_server {
                    rules.servers
                } else {
                    rules.tunnels
                }) {
                    continue;
                }
                match flap {
                    Flap::Send if is_server => out.push(Notice::ServerDown {
                        name: t.name.clone(),
                        tunnels: t.tunnels.clone(),
                    }),
                    Flap::Send => out.push(Notice::TunnelDown {
                        name: t.name.clone(),
                        server: t.server.clone(),
                        error: t.error.clone(),
                    }),
                    Flap::FirstHeldBack => out.push(Notice::Unstable {
                        name: t.name.clone(),
                    }),
                    Flap::HeldBack => {}
                }
            }
            // A few failed probes already took their time: no grace on top.
            let mut due: Vec<String> = self
                .blocked
                .iter()
                .filter(|(_, t)| !t.announced)
                .map(|(k, _)| k.clone())
                .collect();
            due.sort();
            for key in due {
                let flap = self.flap(&blocked_subject(&key), now);
                let Some(t) = self.blocked.get_mut(&key) else {
                    continue;
                };
                t.announced = true;
                if !rules.tunnels {
                    continue;
                }
                match flap {
                    Flap::Send => out.push(Notice::TunnelBlocked {
                        name: t.name.clone(),
                        server: t.server.clone(),
                        target: t.target.clone(),
                        error: t.error.clone(),
                    }),
                    Flap::FirstHeldBack => out.push(Notice::Unstable {
                        name: t.name.clone(),
                    }),
                    Flap::HeldBack => {}
                }
            }
            if rules.tunnels {
                out.append(&mut self.busy_due);
            }
        }
        // Found nearly full while nothing is said: not told late.
        self.busy_due.clear();
        for (subject, is_server, notice) in std::mem::take(&mut self.recoveries) {
            let wanted = if is_server {
                rules.servers
            } else {
                rules.tunnels
            };
            if wanted && !self.unstable.contains(&subject) {
                out.push(notice);
            }
        }
        out
    }

    fn look_at_servers(&mut self, views: &[ServerView], now: i64) {
        for s in views {
            let key = s.id.clone();
            if s.online {
                if let Some(t) = self.servers.remove(&key) {
                    if t.announced {
                        self.recoveries.push((
                            subject(true, &key),
                            true,
                            Notice::ServerUp {
                                name: s.name.clone(),
                                down_secs: now - t.since,
                            },
                        ));
                    }
                }
            } else if s.local || s.last_seen.is_some() {
                // (A server whose agent has never connected, one added and waiting for its
                // agent, is not down: there is nothing to tell about it yet.)
                self.servers.entry(key).or_insert_with(|| Track {
                    name: s.name.clone(),
                    since: now,
                    announced: false,
                    server: String::new(),
                    error: None,
                    tunnels: s.tunnels.iter().map(|t| t.info.name.clone()).collect(),
                    target: None,
                });
            }
        }
        // A server that was removed is not down any more, and is not told about.
        let ids: HashSet<&str> = views.iter().map(|s| s.id.as_str()).collect();
        self.servers.retain(|k, _| ids.contains(k.as_str()));
    }

    fn look_at_tunnels(&mut self, views: &[ServerView], now: i64) {
        let mut seen: HashMap<String, State> = HashMap::new();
        for s in views.iter().filter(|s| s.online) {
            for t in &s.tunnels {
                let state = match &t.info.status {
                    Some(status) if !status.peer.connected => State::Down(
                        status.peer.last_error.as_ref().map(|e| e.text.clone()),
                        s.name.clone(),
                    ),
                    Some(_) => State::Up,
                    // A daemon that does not answer, or a tunnel that was stopped on
                    // purpose: nothing to say about it.
                    None => State::Unknown,
                };
                // One tunnel is two configs on two servers: it is down when either side
                // says so (the entry's error is the one that explains it best).
                let merged = match (seen.remove(&t.info.name), state) {
                    (Some(State::Down(e, srv)), State::Down(e2, srv2)) => {
                        if t.info.role == "entry" {
                            State::Down(e2.or(e), srv2)
                        } else {
                            State::Down(e.or(e2), srv)
                        }
                    }
                    (Some(d @ State::Down(..)), _) => d,
                    (_, d @ State::Down(..)) => d,
                    (Some(State::Up), _) | (_, State::Up) => State::Up,
                    _ => State::Unknown,
                };
                seen.insert(t.info.name.clone(), merged);
            }
        }
        for (name, state) in seen {
            match state {
                State::Down(error, server) => {
                    let t = self.tunnels.entry(name.clone()).or_insert_with(|| Track {
                        name: name.clone(),
                        since: now,
                        announced: false,
                        server: server.clone(),
                        error: None,
                        tunnels: Vec::new(),
                        target: None,
                    });
                    t.error = error;
                    t.server = server;
                }
                State::Up => {
                    if let Some(t) = self.tunnels.remove(&name) {
                        if t.announced {
                            self.recoveries.push((
                                subject(false, &name),
                                false,
                                Notice::TunnelUp {
                                    name,
                                    down_secs: now - t.since,
                                },
                            ));
                        }
                    }
                }
                State::Unknown => {}
            }
        }
        // A tunnel that is gone from every server (deleted) is not down any more.
        let present: HashSet<&str> = views
            .iter()
            .flat_map(|s| s.tunnels.iter().map(|t| t.info.name.as_str()))
            .collect();
        self.tunnels.retain(|k, _| present.contains(k.as_str()));
    }

    /// The entry side's probe and both sides' streams, for tunnels that are connected (one
    /// that is down is told about as such, and is not also blocked).
    fn look_at_health(&mut self, views: &[ServerView], now: i64) {
        let mut blocked: HashMap<String, (String, Option<String>, Option<String>)> = HashMap::new();
        let mut healthy: HashSet<String> = HashSet::new();
        let mut fullest: HashMap<String, (u64, u64)> = HashMap::new();
        for s in views.iter().filter(|s| s.online) {
            for t in &s.tunnels {
                let Some(status) = t.info.status.as_ref().filter(|st| st.peer.connected) else {
                    continue;
                };
                let name = &t.info.name;
                if let (Some(n), Some(max)) = (status.peer.streams, status.peer.streams_max) {
                    let worst = fullest.entry(name.clone()).or_insert((n, max));
                    // n/max above the kept one (compared without dividing).
                    if max > 0
                        && u128::from(n) * u128::from(worst.1)
                            > u128::from(worst.0) * u128::from(max)
                    {
                        *worst = (n, max);
                    }
                }
                if t.info.role != "entry" {
                    continue;
                }
                match status.probe.as_ref().map(probe_state) {
                    Some(ProbeState::Blocked { target, error }) => {
                        blocked.insert(name.clone(), (s.name.clone(), target, error));
                    }
                    Some(ProbeState::Healthy) => {
                        healthy.insert(name.clone());
                    }
                    Some(ProbeState::Unsure) | None => {}
                }
            }
        }
        for (name, (server, target, error)) in blocked {
            let t = self.blocked.entry(name.clone()).or_insert_with(|| Track {
                name: name.clone(),
                since: now,
                announced: false,
                server: server.clone(),
                error: None,
                tunnels: Vec::new(),
                target: None,
            });
            (t.server, t.target, t.error) = (server, target, error);
        }
        for name in healthy {
            if let Some(t) = self.blocked.remove(&name) {
                if t.announced {
                    self.recoveries.push((
                        blocked_subject(&name),
                        false,
                        Notice::TunnelUnblocked {
                            name,
                            blocked_secs: now - t.since,
                        },
                    ));
                }
            }
        }
        // A tunnel that went down is told about as down; its "blocked" ends quietly.
        let down: HashSet<&String> = self.tunnels.keys().collect();
        self.blocked.retain(|k, _| !down.contains(k));

        for (name, (n, max)) in fullest {
            if max == 0 {
                continue;
            }
            if n * 10 >= max * BUSY_AT {
                if self.busy.insert(name.clone()) {
                    self.busy_due.push(Notice::TunnelBusy {
                        name,
                        streams: n,
                        max,
                    });
                }
            } else if n * 10 < max * BUSY_CLEAR {
                self.busy.remove(&name);
            }
        }
        let present: HashSet<&str> = views
            .iter()
            .flat_map(|s| s.tunnels.iter().map(|t| t.info.name.as_str()))
            .collect();
        self.blocked.retain(|k, _| present.contains(k.as_str()));
        self.busy.retain(|k| present.contains(k.as_str()));
    }

    /// Whether a subject going down may be told, or has been going down too often.
    fn flap(&mut self, subject: &str, now: i64) -> Flap {
        let times = self.announced.entry(subject.to_owned()).or_default();
        while times.front().is_some_and(|t| now - t > FLAP_WINDOW) {
            times.pop_front();
        }
        if times.len() >= FLAP_MAX {
            return if self.unstable.insert(subject.to_owned()) {
                Flap::FirstHeldBack
            } else {
                Flap::HeldBack
            };
        }
        times.push_back(now);
        self.unstable.remove(subject);
        Flap::Send
    }
}

fn subject(is_server: bool, key: &str) -> String {
    format!("{}:{key}", if is_server { "srv" } else { "tun" })
}

fn blocked_subject(key: &str) -> String {
    format!("blk:{key}")
}

/// What one probe reading says about a tunnel.
enum ProbeState {
    Blocked {
        target: Option<String>,
        error: Option<String>,
    },
    Healthy,
    /// A failure or two (not yet a pattern), or an exit side too old to answer.
    Unsure,
}

fn probe_state(p: &ProbeStatus) -> ProbeState {
    match p.outcome {
        ProbeOutcome::Ok => ProbeState::Healthy,
        ProbeOutcome::Failed if p.fails >= BLOCKED_AFTER => ProbeState::Blocked {
            target: None,
            error: p.error.clone(),
        },
        ProbeOutcome::TargetFailed if p.target_fails >= BLOCKED_AFTER => ProbeState::Blocked {
            target: Some(p.target.clone()),
            error: p.error.clone(),
        },
        _ => ProbeState::Unsure,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hub::TunnelView;
    use crate::wire::TunnelInfo;
    use kariz::stats::{PeerStatus, ProbeOutcome, ProbeStatus, Status, Totals};

    fn status(connected: bool) -> Status {
        Status {
            status_version: 1,
            kariz: "1".into(),
            role: "entry".into(),
            mode: "reverse".into(),
            transport: "tcpmux".into(),
            profile: "balanced".into(),
            uptime_secs: 10,
            counter_id: None,
            peer: PeerStatus {
                transport: None,
                connected,
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
                bytes_up: 0,
                bytes_down: 0,
                tcp_open: 0,
                tcp_total: 0,
                udp_flows: 0,
                udp_total: 0,
            },
            forwards: Vec::new(),
            exit: None,
            probe: None,
        }
    }

    fn tunnel(name: &str, role: &str, up: Option<bool>) -> TunnelView {
        TunnelView {
            info: TunnelInfo {
                name: name.into(),
                role: role.into(),
                mode: "reverse".into(),
                transport: "tcpmux".into(),
                profile: "balanced".into(),
                encryption: String::new(),
                listen: None,
                remote: None,
                forwards: Vec::new(),
                active: Some(true),
                status: up.map(status),
                error: None,
            },
            rate_mbps: None,
        }
    }

    fn server(id: &str, online: bool, tunnels: Vec<TunnelView>) -> ServerView {
        ServerView {
            id: id.into(),
            name: id.to_uppercase(),
            local: false,
            online,
            version: String::new(),
            arch: String::new(),
            hostname: String::new(),
            addr: None,
            addr_default: None,
            seen_secs: None,
            link: None,
            last_seen: Some(1),
            last_error: None,
            gre: None,
            reverse: None,
            agent_port: None,
            health: None,
            ip4: None,
            ip6: None,
            tunnels,
        }
    }

    const R: Rules = Rules {
        servers: true,
        tunnels: true,
        server_grace: 60,
        tunnel_grace: 30,
    };

    /// An alerter whose startup quiet time is over.
    fn settled() -> Alerter {
        Alerter::new(-1000)
    }

    #[test]
    fn a_server_waiting_for_its_first_agent_is_not_down() {
        let mut a = settled();
        let waiting = [ServerView {
            last_seen: None,
            ..server("w", false, vec![])
        }];
        assert!(a.step(&waiting, 0, R).is_empty());
        assert!(a.step(&waiting, 600, R).is_empty());
        // Once its agent has been in, it is a server like any other.
        let came = [server("w", true, vec![])];
        assert!(a.step(&came, 700, R).is_empty());
        let gone = [server("w", false, vec![])];
        a.step(&gone, 800, R);
        assert_eq!(a.step(&gone, 900, R).len(), 1);
    }

    #[test]
    fn a_tunnel_is_told_only_after_it_stayed_down_for_the_grace_time() {
        let mut a = settled();
        let down = [server("a", true, vec![tunnel("t", "entry", Some(false))])];
        assert!(a.step(&down, 0, R).is_empty());
        assert!(a.step(&down, 29, R).is_empty());
        assert_eq!(
            a.step(&down, 30, R),
            vec![Notice::TunnelDown {
                name: "t".into(),
                server: "A".into(),
                error: None
            }]
        );
        // Said once.
        assert!(a.step(&down, 60, R).is_empty());
    }

    #[test]
    fn a_blip_that_heals_in_time_says_nothing_at_all() {
        let mut a = settled();
        let down = [server("a", true, vec![tunnel("t", "entry", Some(false))])];
        let up = [server("a", true, vec![tunnel("t", "entry", Some(true))])];
        assert!(a.step(&down, 0, R).is_empty());
        assert!(a.step(&up, 10, R).is_empty());
        assert!(a.step(&up, 100, R).is_empty());
    }

    #[test]
    fn a_recovery_says_how_long_it_was_down() {
        let mut a = settled();
        let down = [server("a", true, vec![tunnel("t", "entry", Some(false))])];
        let up = [server("a", true, vec![tunnel("t", "entry", Some(true))])];
        a.step(&down, 0, R);
        a.step(&down, 40, R);
        assert_eq!(
            a.step(&up, 252, R),
            vec![Notice::TunnelUp {
                name: "t".into(),
                down_secs: 252
            }]
        );
    }

    #[test]
    fn either_side_saying_down_makes_the_tunnel_down() {
        let mut a = settled();
        let v = [
            server("a", true, vec![tunnel("t", "entry", Some(true))]),
            server("b", true, vec![tunnel("t", "exit", Some(false))]),
        ];
        a.step(&v, 0, R);
        assert_eq!(a.step(&v, 30, R).len(), 1);
    }

    #[test]
    fn nothing_is_said_for_a_while_after_the_panel_starts_and_what_is_still_down_then_is() {
        let mut a = Alerter::new(0);
        let down = [server("a", true, vec![tunnel("t", "entry", Some(false))])];
        assert!(a.step(&down, 5, R).is_empty());
        assert!(a.step(&down, 59, R).is_empty());
        assert_eq!(a.step(&down, 60, R).len(), 1);
    }

    #[test]
    fn an_offline_server_is_told_with_its_tunnels_and_they_are_not_told_again() {
        let mut a = settled();
        let up = [server("a", true, vec![tunnel("t", "entry", Some(true))])];
        a.step(&up, 0, R);
        // Offline, with its last reading still in the list.
        let off = [server("a", false, vec![tunnel("t", "entry", Some(false))])];
        assert!(a.step(&off, 10, R).is_empty());
        assert_eq!(
            a.step(&off, 70, R),
            vec![Notice::ServerDown {
                name: "A".into(),
                tunnels: vec!["t".into()]
            }]
        );
        assert!(a.step(&off, 200, R).is_empty());
    }

    #[test]
    fn a_server_that_never_comes_back_is_told_once_and_its_return_is_told() {
        let mut a = settled();
        let off = [server("a", false, vec![])];
        let on = [server("a", true, vec![])];
        a.step(&off, 0, R);
        assert_eq!(a.step(&off, 60, R).len(), 1);
        assert_eq!(
            a.step(&on, 90, R),
            vec![Notice::ServerUp {
                name: "A".into(),
                down_secs: 90
            }]
        );
    }

    #[test]
    fn a_tunnel_that_cannot_be_read_is_not_down() {
        let mut a = settled();
        let v = [server("a", true, vec![tunnel("t", "entry", None)])];
        a.step(&v, 0, R);
        assert!(a.step(&v, 500, R).is_empty());
    }

    #[test]
    fn a_kind_the_user_turned_off_is_tracked_but_not_told() {
        let mut a = settled();
        let off = Rules {
            tunnels: false,
            ..R
        };
        let down = [server("a", true, vec![tunnel("t", "entry", Some(false))])];
        let up = [server("a", true, vec![tunnel("t", "entry", Some(true))])];
        a.step(&down, 0, off);
        assert!(a.step(&down, 40, off).is_empty());
        assert!(a.step(&up, 60, off).is_empty());
    }

    #[test]
    fn a_tunnel_that_keeps_going_down_is_called_unstable_and_then_left_alone() {
        let mut a = settled();
        let down = [server("a", true, vec![tunnel("t", "entry", Some(false))])];
        let up = [server("a", true, vec![tunnel("t", "entry", Some(true))])];
        let mut said = Vec::new();
        for i in 0..6 {
            let t = i * 100;
            a.step(&down, t, R);
            said.extend(a.step(&down, t + 40, R));
            said.extend(a.step(&up, t + 50, R));
        }
        let downs = said
            .iter()
            .filter(|n| matches!(n, Notice::TunnelDown { .. }))
            .count();
        let unstable = said
            .iter()
            .filter(|n| matches!(n, Notice::Unstable { .. }))
            .count();
        assert_eq!(downs, FLAP_MAX);
        assert_eq!(unstable, 1);
        // Once it has been quiet for the window it is told again.
        let later = 10 * FLAP_WINDOW;
        a.step(&down, later, R);
        assert_eq!(a.step(&down, later + 40, R).len(), 1);
    }

    #[test]
    fn a_deleted_tunnel_stops_being_down() {
        let mut a = settled();
        let down = [server("a", true, vec![tunnel("t", "entry", Some(false))])];
        let gone = [server("a", true, vec![])];
        a.step(&down, 0, R);
        a.step(&gone, 10, R);
        assert!(a.step(&gone, 100, R).is_empty());
    }

    /// An entry side that is connected, with a probe reading and streams in use.
    fn probed(name: &str, probe: Option<(ProbeOutcome, u32)>, streams: (u64, u64)) -> TunnelView {
        let mut t = tunnel(name, "entry", Some(true));
        let status = t.info.status.as_mut().unwrap();
        status.peer.streams = Some(streams.0);
        status.peer.streams_max = Some(streams.1);
        status.probe = probe.map(|(outcome, fails)| ProbeStatus {
            outcome,
            ms: None,
            target: "127.0.0.1:443".into(),
            error: Some("every tunnel connection is full (16384 streams open)".into()),
            fails: if outcome == ProbeOutcome::Failed {
                fails
            } else {
                0
            },
            target_fails: if outcome == ProbeOutcome::TargetFailed {
                fails
            } else {
                0
            },
            ok_total: 1,
            failed_total: u64::from(fails),
            secs_ago: 1,
        });
        t
    }

    #[test]
    fn a_connected_tunnel_that_lets_no_one_through_is_told_and_its_recovery_too() {
        let mut a = settled();
        let at = |p| [server("a", true, vec![probed("t", p, (10, 16384))])];
        // One or two failures are not a pattern.
        assert!(a
            .step(&at(Some((ProbeOutcome::Failed, 2))), 0, R)
            .is_empty());
        assert_eq!(
            a.step(&at(Some((ProbeOutcome::Failed, 3))), 15, R),
            vec![Notice::TunnelBlocked {
                name: "t".into(),
                server: "A".into(),
                target: None,
                error: Some("every tunnel connection is full (16384 streams open)".into()),
            }]
        );
        // Said once, and a probe of an old exit side changes nothing.
        assert!(a
            .step(&at(Some((ProbeOutcome::Failed, 4))), 30, R)
            .is_empty());
        assert!(a
            .step(&at(Some((ProbeOutcome::Unsupported, 0))), 45, R)
            .is_empty());
        assert_eq!(
            a.step(&at(Some((ProbeOutcome::Ok, 0))), 90, R),
            vec![Notice::TunnelUnblocked {
                name: "t".into(),
                blocked_secs: 75,
            }]
        );
        // A target that is down names the target.
        a.step(&at(Some((ProbeOutcome::TargetFailed, 3))), 200, R);
        let notes = a.step(&at(Some((ProbeOutcome::TargetFailed, 4))), 215, R);
        assert!(notes.is_empty(), "already told: {notes:?}");
    }

    #[test]
    fn a_blocked_tunnel_that_goes_down_is_told_as_down_only() {
        let mut a = settled();
        let blocked = [server(
            "a",
            true,
            vec![probed("t", Some((ProbeOutcome::Failed, 3)), (0, 0))],
        )];
        assert_eq!(a.step(&blocked, 0, R).len(), 1);
        let down = [server("a", true, vec![tunnel("t", "entry", Some(false))])];
        a.step(&down, 10, R);
        assert!(matches!(
            a.step(&down, 40, R)[..],
            [Notice::TunnelDown { .. }]
        ));
        let up = [server(
            "a",
            true,
            vec![probed("t", Some((ProbeOutcome::Ok, 0)), (0, 0))],
        )];
        let notes = a.step(&up, 100, R);
        assert!(matches!(notes[..], [Notice::TunnelUp { .. }]), "{notes:?}");
    }

    #[test]
    fn a_nearly_full_tunnel_is_told_once_until_it_empties() {
        let mut a = settled();
        let at = |n| [server("a", true, vec![probed("t", None, (n, 16384))])];
        assert!(a.step(&at(12_000), 0, R).is_empty());
        assert_eq!(
            a.step(&at(13_200), 10, R),
            vec![Notice::TunnelBusy {
                name: "t".into(),
                streams: 13_200,
                max: 16_384,
            }]
        );
        assert!(a.step(&at(14_000), 20, R).is_empty());
        // Down a little is not enough to be told again.
        a.step(&at(12_000), 30, R);
        assert!(a.step(&at(13_500), 40, R).is_empty());
        // Well below, and full again: told again.
        a.step(&at(5_000), 50, R);
        assert_eq!(a.step(&at(13_500), 60, R).len(), 1);
        // Nothing while the panel has just started, and not late either.
        let mut fresh = Alerter::new(0);
        assert!(fresh.step(&at(15_000), 10, R).is_empty());
        assert!(fresh.step(&at(15_000), 100, R).is_empty());
    }
}
