//! A Prometheus endpoint, `GET /{secret}/metrics`: the servers' load, every tunnel's state,
//! bytes and connections, every forwarded port's counters and the traffic limits, as the hub
//! last saw them, in the text exposition format. Off until it is switched on in Settings →
//! Metrics (then the address answers 404, like any unknown one); on, it answers a request
//! that carries the token (`Authorization: Bearer …`, Prometheus' `bearer_token`) or a
//! signed-in browser session, and 401 to anything else. The settings are a `meta` row, like
//! the proxy's, and are not in backups.

use std::fmt::Write;

use anyhow::Result;
use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};

use crate::db::Db;
use crate::http::AppState;
use crate::hub::{Hub, ServerView, TunnelView};

const META: &str = "metrics";

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Settings {
    pub enabled: bool,
    /// What a scraper sends as the bearer token; made when the endpoint is first switched on.
    pub token: String,
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

    /// Switches the endpoint on, with a token when there is none yet.
    pub fn enable(&mut self) -> Result<()> {
        if self.token.is_empty() {
            self.token = crate::auth::new_token()?;
        }
        self.enabled = true;
        Ok(())
    }

    /// A new token; the old one stops working at once.
    pub fn regenerate(&mut self) -> Result<()> {
        self.token = crate::auth::new_token()?;
        Ok(())
    }

    /// Whether an `Authorization` header carries the token (compared in constant time).
    pub fn accepts(&self, authorization: Option<&str>) -> bool {
        let Some(sent) = authorization.and_then(|h| h.strip_prefix("Bearer ")) else {
            return false;
        };
        !self.token.is_empty() && same_bytes(sent.trim().as_bytes(), self.token.as_bytes())
    }
}

/// Whether two byte strings are equal, in time that does not depend on where they differ.
fn same_bytes(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// `GET /{secret}/metrics`.
pub async fn serve(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let settings = Settings::load(&state.db);
    if !settings.enabled {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }
    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    let allowed =
        settings.accepts(bearer) || crate::api::authenticate(&state, &headers, false).is_ok();
    if !allowed {
        return (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer")],
            "a bearer token or a signed-in session is needed",
        )
            .into_response();
    }
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        render(&state.hub),
    )
        .into_response()
}

/// A label value in the exposition format: backslashes, quotes and newlines escaped.
fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
    out
}

/// One metric family: its header once, then its samples.
struct Family<'a> {
    out: &'a mut String,
    name: &'static str,
    kind: &'static str,
    help: &'static str,
    started: bool,
}

impl<'a> Family<'a> {
    fn new(
        out: &'a mut String,
        name: &'static str,
        kind: &'static str,
        help: &'static str,
    ) -> Self {
        Self {
            out,
            name,
            kind,
            help,
            started: false,
        }
    }

    fn sample(&mut self, labels: &[(&str, &str)], value: impl std::fmt::Display) {
        if !self.started {
            self.started = true;
            let _ = writeln!(self.out, "# HELP {} {}", self.name, self.help);
            let _ = writeln!(self.out, "# TYPE {} {}", self.name, self.kind);
        }
        let _ = write!(self.out, "{}", self.name);
        if !labels.is_empty() {
            let _ = write!(self.out, "{{");
            for (i, (k, v)) in labels.iter().enumerate() {
                let _ = write!(
                    self.out,
                    "{}{k}=\"{}\"",
                    if i == 0 { "" } else { "," },
                    escape(v)
                );
            }
            let _ = write!(self.out, "}}");
        }
        let _ = writeln!(self.out, " {value}");
    }
}

/// The metrics as text, from what the hub last saw of its servers and tunnels, and the
/// traffic limits.
pub fn render(hub: &Hub) -> String {
    let servers = hub.snapshot().unwrap_or_default();
    let quotas = crate::quota::list(&hub.db).unwrap_or_default();
    let mut out = String::new();
    Family::new(
        &mut out,
        "kariz_panel_info",
        "gauge",
        "The panel's version.",
    )
    .sample(&[("version", crate::version())], 1);
    server_metrics(&mut out, &servers);
    tunnel_metrics(&mut out, &servers);
    forward_metrics(&mut out, &servers);
    let mut used = Family::new(
        &mut out,
        "kariz_quota_used_bytes",
        "gauge",
        "Bytes a tunnel with a traffic limit has moved since its last reset.",
    );
    for q in &quotas {
        used.sample(&[("tunnel", &q.name)], q.used);
    }
    let mut limit = Family::new(
        &mut out,
        "kariz_quota_limit_bytes",
        "gauge",
        "A tunnel's traffic limit (0: none).",
    );
    for q in &quotas {
        limit.sample(&[("tunnel", &q.name)], q.limit_bytes);
    }
    let mut stopped = Family::new(
        &mut out,
        "kariz_quota_stopped",
        "gauge",
        "1 while the tunnel is stopped by its traffic limit.",
    );
    for q in &quotas {
        stopped.sample(&[("tunnel", &q.name)], u8::from(q.stopped > 0));
    }
    out
}

fn server_metrics(out: &mut String, servers: &[ServerView]) {
    let mut online = Family::new(
        out,
        "kariz_server_online",
        "gauge",
        "1 while the server's agent is connected to the panel.",
    );
    for s in servers {
        online.sample(&[("server", &s.name)], u8::from(s.online));
    }
    let mut cpu = Family::new(
        out,
        "kariz_server_cpu_percent",
        "gauge",
        "Busy share of the server's CPUs, 0-100.",
    );
    for s in servers {
        if let Some(v) = s.health.as_ref().and_then(|h| h.cpu_pct) {
            cpu.sample(&[("server", &s.name)], v);
        }
    }
    let mut memory = Family::new(
        out,
        "kariz_server_memory_bytes",
        "gauge",
        "The server's memory, total and used.",
    );
    for s in servers {
        if let Some(h) = &s.health {
            if let Some(v) = h.mem_total {
                memory.sample(&[("server", &s.name), ("kind", "total")], v);
            }
            if let Some(v) = h.mem_used {
                memory.sample(&[("server", &s.name), ("kind", "used")], v);
            }
        }
    }
    let mut network = Family::new(
        out,
        "kariz_server_network_bytes_per_second",
        "gauge",
        "Bytes per second over the server's network interfaces, received and sent.",
    );
    for s in servers {
        if let Some(h) = &s.health {
            if let Some(v) = h.rx_bps {
                network.sample(&[("server", &s.name), ("direction", "rx")], v);
            }
            if let Some(v) = h.tx_bps {
                network.sample(&[("server", &s.name), ("direction", "tx")], v);
            }
        }
    }
    let mut load = Family::new(
        out,
        "kariz_server_load1",
        "gauge",
        "The server's one-minute load average.",
    );
    for s in servers {
        if let Some(v) = s.health.as_ref().and_then(|h| h.load1) {
            load.sample(&[("server", &s.name)], v);
        }
    }
    let mut uptime = Family::new(
        out,
        "kariz_server_uptime_seconds",
        "gauge",
        "Seconds since the server booted.",
    );
    for s in servers {
        if let Some(v) = s.health.as_ref().and_then(|h| h.uptime_secs) {
            uptime.sample(&[("server", &s.name)], v);
        }
    }
    let mut tunnels = Family::new(
        out,
        "kariz_server_tunnels",
        "gauge",
        "Tunnel sides configured on the server.",
    );
    for s in servers {
        tunnels.sample(&[("server", &s.name)], s.tunnels.len());
    }
}

/// The labels of one tunnel side.
fn side_labels<'a>(s: &'a ServerView, t: &'a TunnelView) -> [(&'static str, &'a str); 3] {
    [
        ("tunnel", t.info.name.as_str()),
        ("server", s.name.as_str()),
        ("role", t.info.role.as_str()),
    ]
}

fn tunnel_metrics(out: &mut String, servers: &[ServerView]) {
    let sides: Vec<(&ServerView, &TunnelView)> = servers
        .iter()
        .flat_map(|s| s.tunnels.iter().map(move |t| (s, t)))
        .collect();
    let mut active = Family::new(
        out,
        "kariz_tunnel_active",
        "gauge",
        "1 while this side's service runs (as its server reports).",
    );
    for (s, t) in &sides {
        if let Some(v) = t.info.active {
            active.sample(&side_labels(s, t), u8::from(v));
        }
    }
    let mut connected = Family::new(
        out,
        "kariz_tunnel_connected",
        "gauge",
        "1 while this side is connected to the other.",
    );
    for (s, t) in &sides {
        if let Some(st) = &t.info.status {
            connected.sample(&side_labels(s, t), u8::from(st.peer.connected));
        }
    }
    let mut rtt = Family::new(
        out,
        "kariz_tunnel_rtt_seconds",
        "gauge",
        "Round trip to the other side, as the daemon measures it.",
    );
    for (s, t) in &sides {
        if let Some(v) = t.info.status.as_ref().and_then(|st| st.peer.rtt_ms) {
            rtt.sample(&side_labels(s, t), v / 1000.0);
        }
    }
    let mut sessions = Family::new(
        out,
        "kariz_tunnel_sessions",
        "gauge",
        "Live connections between the two sides.",
    );
    for (s, t) in &sides {
        if let Some(v) = t.info.status.as_ref().and_then(|st| st.peer.sessions) {
            sessions.sample(&side_labels(s, t), v);
        }
    }
    let mut uptime = Family::new(
        out,
        "kariz_tunnel_uptime_seconds",
        "gauge",
        "Seconds since this side's daemon started.",
    );
    for (s, t) in &sides {
        if let Some(st) = &t.info.status {
            uptime.sample(&side_labels(s, t), st.uptime_secs);
        }
    }
    let mut rate = Family::new(
        out,
        "kariz_tunnel_rate_mbps",
        "gauge",
        "Megabits per second through the tunnel, both directions together, as the panel last measured.",
    );
    for (s, t) in &sides {
        if let Some(v) = t.rate_mbps {
            rate.sample(&side_labels(s, t), v);
        }
    }
    let mut bytes = Family::new(
        out,
        "kariz_tunnel_bytes_total",
        "counter",
        "Bytes through this side since its counters began, up (users to targets) and down.",
    );
    for (s, t) in &sides {
        if let Some(st) = &t.info.status {
            let [a, b, c] = side_labels(s, t);
            bytes.sample(&[a, b, c, ("direction", "up")], st.totals.bytes_up);
            bytes.sample(&[a, b, c, ("direction", "down")], st.totals.bytes_down);
        }
    }
    let mut conns = Family::new(
        out,
        "kariz_tunnel_connections",
        "gauge",
        "Open user connections (tcp) and UDP flows (udp) on this side.",
    );
    for (s, t) in &sides {
        if let Some(st) = &t.info.status {
            let [a, b, c] = side_labels(s, t);
            conns.sample(&[a, b, c, ("kind", "tcp")], st.totals.tcp_open);
            conns.sample(&[a, b, c, ("kind", "udp")], st.totals.udp_flows);
        }
    }
}

fn forward_metrics(out: &mut String, servers: &[ServerView]) {
    // The entry side's rules, with their counters, as its daemon reports them.
    let rules: Vec<(&ServerView, &TunnelView, &kariz::stats::ForwardStatus)> = servers
        .iter()
        .flat_map(|s| {
            s.tunnels
                .iter()
                .filter(|t| t.info.role == "entry")
                .filter_map(move |t| t.info.status.as_ref().map(move |st| (s, t, st)))
                .flat_map(move |(s, t, st)| st.forwards.iter().map(move |f| (s, t, f)))
        })
        .collect();
    let labels = |s: &ServerView, t: &TunnelView, f: &kariz::stats::ForwardStatus| {
        [
            ("tunnel", t.info.name.clone()),
            ("server", s.name.clone()),
            ("listen", f.listen.clone()),
            ("target", f.target.clone()),
            ("protocol", f.protocol.clone()),
        ]
    };
    let mut bytes = Family::new(
        out,
        "kariz_forward_bytes_total",
        "counter",
        "Bytes through a forwarded port, up and down.",
    );
    for (s, t, f) in &rules {
        let l = labels(s, t, f);
        let base: Vec<(&str, &str)> = l.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let mut up = base.clone();
        up.push(("direction", "up"));
        bytes.sample(&up, f.bytes_up);
        let mut down = base;
        down.push(("direction", "down"));
        bytes.sample(&down, f.bytes_down);
    }
    // Without the target: a retargeted rule keeps its series.
    let short = |l: &[(&'static str, String); 5]| -> Vec<(&'static str, String)> {
        l.iter().filter(|(k, _)| *k != "target").cloned().collect()
    };
    let with = |l: &[(&'static str, String)],
                extra: (&'static str, &'static str)|
     -> Vec<(&'static str, String)> {
        let mut v = l.to_vec();
        v.push((extra.0, extra.1.to_owned()));
        v
    };
    fn refs<'a>(l: &'a [(&'static str, String)]) -> Vec<(&'a str, &'a str)> {
        l.iter().map(|(k, v)| (*k, v.as_str())).collect()
    }
    let mut open = Family::new(
        out,
        "kariz_forward_connections",
        "gauge",
        "Open connections (tcp) and flows (udp) on a forwarded port.",
    );
    for (s, t, f) in &rules {
        let l = short(&labels(s, t, f));
        open.sample(&refs(&with(&l, ("kind", "tcp"))), f.tcp_open);
        open.sample(&refs(&with(&l, ("kind", "udp"))), f.udp_flows);
    }
    let mut total = Family::new(
        out,
        "kariz_forward_connections_total",
        "counter",
        "Connections (tcp) and flows (udp) a forwarded port has taken since its counters began.",
    );
    for (s, t, f) in &rules {
        let l = short(&labels(s, t, f));
        total.sample(&refs(&with(&l, ("kind", "tcp"))), f.tcp_total);
        total.sample(&refs(&with(&l, ("kind", "udp"))), f.udp_total);
    }
    let mut failures = Family::new(
        out,
        "kariz_forward_open_failures_total",
        "counter",
        "Connections to a forwarded port the tunnel could not open to the target.",
    );
    for (s, t, f) in &rules {
        failures.sample(&refs(&short(&labels(s, t, f))), f.open_failures);
    }
    let mut refused = Family::new(
        out,
        "kariz_forward_refused_total",
        "counter",
        "Connections to a forwarded port refused by the per-address limit.",
    );
    for (s, t, f) in &rules {
        refused.sample(&refs(&short(&labels(s, t, f))), f.refused_per_ip);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_are_escaped_and_families_have_one_header() {
        let mut out = String::new();
        let mut f = Family::new(&mut out, "x_total", "counter", "Help.");
        f.sample(&[("server", "a \"quoted\" \\ name\nline")], 3u64);
        f.sample(&[("server", "b")], 4.5);
        assert_eq!(
            out,
            "# HELP x_total Help.\n# TYPE x_total counter\n\
             x_total{server=\"a \\\"quoted\\\" \\\\ name\\nline\"} 3\n\
             x_total{server=\"b\"} 4.5\n"
        );
        // Nothing sampled: no header either.
        let mut empty = String::new();
        Family::new(&mut empty, "y", "gauge", "Help.");
        assert!(empty.is_empty());
    }

    #[test]
    fn the_token_is_checked_as_a_bearer() {
        let mut s = Settings::default();
        assert!(!s.accepts(Some("Bearer ")), "no token yet accepts nothing");
        s.enable().unwrap();
        let token = s.token.clone();
        assert!(s.accepts(Some(&format!("Bearer {token}"))));
        assert!(s.accepts(Some(&format!("Bearer {token} "))));
        assert!(!s.accepts(Some(&format!("Basic {token}"))));
        assert!(!s.accepts(Some("Bearer not-it")));
        assert!(!s.accepts(None));
        s.regenerate().unwrap();
        assert!(
            !s.accepts(Some(&format!("Bearer {token}"))),
            "the old token is dead"
        );
    }
}
