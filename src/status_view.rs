//! How `kariz status` shows a daemon's status (docs/status.md).

use kariz::stats::{ForwardStatus, LastError, ProbeOutcome, ProbeStatus, Status};

use crate::logging::{Style, AQUA, BOLD, DIM, RED, TEAL, YELLOW};

/// "38 s", "12 min", "3 h 5 min", "2 d 4 h".
fn duration(secs: u64) -> String {
    let (d, h, m) = (secs / 86_400, secs % 86_400 / 3600, secs % 3600 / 60);
    if d > 0 {
        format!("{d} d {h} h")
    } else if h > 0 {
        format!("{h} h {m} min")
    } else if m > 0 {
        format!("{m} min")
    } else {
        format!("{secs} s")
    }
}

/// "812 kbit/s", "41.8 Mbit/s", "1.24 Gbit/s".
fn rate(bits_per_sec: f64) -> String {
    if bits_per_sec >= 1e9 {
        format!("{:.2} Gbit/s", bits_per_sec / 1e9)
    } else if bits_per_sec >= 1e6 {
        format!("{:.1} Mbit/s", bits_per_sec / 1e6)
    } else {
        format!("{:.0} kbit/s", bits_per_sec / 1e3)
    }
}

/// "512 B", "3.4 MiB", "1.20 GiB".
fn bytes(n: u64) -> String {
    let n = n as f64;
    if n >= (1u64 << 30) as f64 {
        format!("{:.2} GiB", n / (1u64 << 30) as f64)
    } else if n >= (1u64 << 20) as f64 {
        format!("{:.1} MiB", n / (1u64 << 20) as f64)
    } else if n >= 1024.0 {
        format!("{:.1} KiB", n / 1024.0)
    } else {
        format!("{n} B")
    }
}

fn error_text(style: &Style, e: &LastError) -> String {
    style.paint(
        RED,
        &format!("last error {} ago: {}", duration(e.secs_ago), e.text),
    )
}

/// Traffic as rates between two readings `secs` apart, or as totals with one reading.
fn traffic(style: &Style, up: u64, down: u64, before: Option<(u64, u64, f64)>) -> String {
    let (up, down) = match before {
        Some((up0, down0, secs)) => (
            rate(up.saturating_sub(up0) as f64 * 8.0 / secs),
            rate(down.saturating_sub(down0) as f64 * 8.0 / secs),
        ),
        None => (bytes(up), bytes(down)),
    };
    format!(
        "{} {}  {} {}",
        style.paint(TEAL, "↑"),
        style.paint(AQUA, &format!("{up:>12}")),
        style.paint(TEAL, "↓"),
        style.paint(AQUA, &format!("{down:>12}"))
    )
}

fn forward_line(style: &Style, f: &ForwardStatus, before: Option<(&ForwardStatus, f64)>) -> String {
    let route = format!("{} -> {} ({})", f.listen, f.target, f.protocol);
    let mut open = format!("{} open", f.tcp_open);
    if f.protocol != "tcp" {
        open = if f.protocol == "udp" {
            format!("{} flows", f.udp_flows)
        } else {
            format!("{open} · {} flows", f.udp_flows)
        };
    }
    let before = before.map(|(b, secs)| (b.bytes_up, b.bytes_down, secs));
    let mut line = format!(
        "{route:<44} {}   {}",
        style.paint(BOLD, &format!("{open:>16}")),
        traffic(style, f.bytes_up, f.bytes_down, before)
    );
    if f.open_failures > 0 {
        line.push_str(&style.paint(RED, &format!("   {} failed", f.open_failures)));
    }
    if f.refused_per_ip > 0 {
        line.push_str(&style.paint(
            YELLOW,
            &format!("   {} over the per-address limit", f.refused_per_ip),
        ));
    }
    line
}

/// The health probe's last finding, entry side.
fn health_line(style: &Style, p: &ProbeStatus) -> String {
    let target = if p.target.is_empty() {
        "the tunnel".to_string()
    } else {
        p.target.clone()
    };
    let checked = format!("checked {} ago", duration(p.secs_ago));
    let in_a_row = |n: u32| {
        if n > 1 {
            format!(" ({n} in a row)")
        } else {
            String::new()
        }
    };
    let error = p.error.as_deref().unwrap_or_default();
    match p.outcome {
        ProbeOutcome::Ok => format!(
            "{} · {} to {target} · {checked}",
            style.paint(&format!("{BOLD}{TEAL}"), "● users can connect"),
            style.paint(AQUA, &format!("{} ms", p.ms.unwrap_or_default())),
        ),
        ProbeOutcome::TargetFailed => format!(
            "{} · {checked}",
            style.paint(
                RED,
                &format!(
                    "○ {target} cannot be reached from the exit side{}",
                    in_a_row(p.target_fails)
                )
            ),
        ),
        ProbeOutcome::Failed => format!(
            "{} · {checked}",
            style.paint(
                RED,
                &format!(
                    "○ new connections do not get through{}: {error}",
                    in_a_row(p.fails)
                )
            ),
        ),
        ProbeOutcome::Unsupported => style.paint(
            DIM,
            "not checked: the other server is too old to answer health probes",
        ),
    }
}

/// The whole view. `name`: the tunnel's name (its config file). `before`: an earlier
/// reading and how many seconds before this one, for rates.
pub fn render(style: &Style, name: &str, now: &Status, before: Option<(&Status, f64)>) -> String {
    let label = |text: &str| style.paint(DIM, &format!("{text:<11}"));
    let mut out = vec![format!(
        "  {} tunnel {} · {} · {} · {} · {} · up {}",
        style.paint(TEAL, "▸"),
        style.paint(BOLD, name),
        now.role,
        now.mode,
        now.transport,
        now.profile,
        duration(now.uptime_secs)
    )];

    let p = &now.peer;
    let other = if now.role == "entry" {
        "exit side"
    } else {
        "entry side"
    };
    let mut parts = Vec::new();
    if p.connected {
        parts.push(style.paint(&format!("{BOLD}{TEAL}"), "● connected"));
        if let Some(via) = &p.transport {
            parts.push(format!("via {}", style.paint(AQUA, via)));
        }
        match (p.sessions, p.sessions_wanted) {
            (Some(n), Some(w)) => parts.push(format!("{n} of {w} sessions")),
            (Some(1), None) => parts.push("1 session".into()),
            (Some(n), None) => parts.push(format!("{n} sessions")),
            _ => {}
        }
        if let Some(rtt) = p.rtt_ms {
            parts.push(format!(
                "rtt {}",
                style.paint(AQUA, &format!("{rtt:.1} ms"))
            ));
        }
        if let Some(secs) = p.connected_secs {
            parts.push(format!("for {}", duration(secs)));
        }
        if let (Some(n), Some(max)) = (p.streams, p.streams_max) {
            let text = format!("{n} of {max} streams");
            // Near the limit new connections start to wait and fail.
            parts.push(if max > 0 && n * 10 >= max * 8 {
                style.paint(YELLOW, &text)
            } else {
                text
            });
        }
    } else {
        parts.push(style.paint(&format!("{BOLD}{RED}"), "○ not connected"));
    }
    if p.handshakes_failed > 0 {
        parts.push(style.paint(
            YELLOW,
            &format!("{} failed handshakes", p.handshakes_failed),
        ));
    }
    if p.full > 0 {
        parts.push(style.paint(
            RED,
            &format!("{} connections failed: every session was full", p.full),
        ));
    }
    match &p.last_error {
        Some(e) if !p.connected || e.secs_ago < 60 => parts.push(error_text(style, e)),
        _ => {}
    }
    out.push(format!("  {} {}", label(other), parts.join(" · ")));
    if let Some(probe) = &now.probe {
        out.push(format!(
            "  {} {}",
            label("health"),
            health_line(style, probe)
        ));
    }

    if let Some(exit) = &now.exit {
        let before = before.map(|(b, secs)| (b.totals.bytes_up, b.totals.bytes_down, secs));
        let mut line = format!(
            "  {} {}   {} streams served",
            label("targets"),
            traffic(style, now.totals.bytes_up, now.totals.bytes_down, before),
            exit.streams_total
        );
        if exit.dial_failures > 0 {
            line.push_str(&style.paint(
                RED,
                &format!(" · {} could not be reached", exit.dial_failures),
            ));
        }
        out.push(line);
        if let Some(e) = &exit.last_dial_error {
            out.push(format!("  {} {}", label(""), error_text(style, e)));
        }
    }
    for (i, f) in now.forwards.iter().enumerate() {
        let before_f = before.and_then(|(b, secs)| b.forwards.get(i).map(|f0| (f0, secs)));
        let head = if i == 0 { "forward" } else { "" };
        out.push(format!(
            "  {} {}",
            label(head),
            forward_line(style, f, before_f)
        ));
    }
    out.push(String::new());
    out.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use kariz::stats::{ExitStatus, PeerStatus, Totals};
    use time::UtcOffset;

    fn plain() -> Style {
        Style {
            color: false,
            journal: false,
            offset: UtcOffset::UTC,
        }
    }

    fn entry(bytes_down: u64) -> Status {
        Status {
            status_version: 1,
            kariz: "0.7.0".into(),
            role: "entry".into(),
            mode: "direct".into(),
            transport: "tcpmux".into(),
            profile: "balanced".into(),
            uptime_secs: 93_600,
            counter_id: None,
            peer: PeerStatus {
                transport: None,
                connected: true,
                sessions: Some(2),
                sessions_wanted: Some(2),
                connected_secs: Some(3600),
                rtt_ms: Some(38.4),
                handshakes_ok: 2,
                handshakes_failed: 0,
                last_error: None,
                streams: Some(140),
                streams_max: Some(8192),
                full: 0,
            },
            totals: Totals::default(),
            forwards: vec![ForwardStatus {
                listen: "[::]:443".into(),
                target: "127.0.0.1:443".into(),
                protocol: "tcp+udp".into(),
                tcp_open: 12,
                tcp_total: 400,
                udp_flows: 3,
                udp_total: 9,
                bytes_up: 1 << 20,
                bytes_down,
                open_failures: 0,
                refused_per_ip: 0,
            }],
            exit: None,
            probe: None,
        }
    }

    #[test]
    fn rates_come_from_two_readings() {
        let before = entry(0);
        let now = entry(5_000_000);
        let text = render(&plain(), "main", &now, Some((&before, 1.0)));
        assert!(
            text.contains("tunnel main · entry · direct · tcpmux · balanced · up 1 d 2 h"),
            "{text}"
        );
        assert!(
            text.contains(
                "● connected · 2 of 2 sessions · rtt 38.4 ms · for 1 h 0 min · 140 of 8192 streams"
            ),
            "{text}"
        );
        assert!(!text.contains("health"), "no probe yet: {text}");
        assert!(
            text.contains("[::]:443 -> 127.0.0.1:443 (tcp+udp)"),
            "{text}"
        );
        assert!(text.contains("12 open · 3 flows"), "{text}");
        // 5 MB in one second, and nothing more up.
        assert!(text.contains("40.0 Mbit/s"), "{text}");
        assert!(text.contains("0 kbit/s"), "{text}");
        // One reading: totals instead of rates.
        let text = render(&plain(), "main", &now, None);
        assert!(
            text.contains("1.0 MiB") && text.contains("4.8 MiB"),
            "{text}"
        );
    }

    #[test]
    fn a_missing_peer_says_why() {
        let mut status = entry(0);
        status.peer.connected = false;
        status.peer.sessions = Some(0);
        status.peer.handshakes_failed = 3;
        status.peer.last_error = Some(LastError {
            secs_ago: 12,
            text: "authentication failed".into(),
        });
        let text = render(&plain(), "main", &status, None);
        assert!(text.contains("○ not connected · 3 failed handshakes · last error 12 s ago: authentication failed"), "{text}");
    }

    #[test]
    fn the_exit_side_shows_its_targets() {
        let mut status = entry(0);
        status.role = "exit".into();
        status.forwards.clear();
        status.totals.bytes_down = 3 << 30;
        status.exit = Some(ExitStatus {
            streams_total: 42,
            dial_failures: 1,
            last_dial_error: Some(LastError {
                secs_ago: 90,
                text: "10.0.0.5:22: connection refused".into(),
            }),
        });
        let text = render(&plain(), "main", &status, None);
        assert!(text.contains("entry side"), "{text}");
        assert!(text.contains("3.00 GiB"), "{text}");
        assert!(
            text.contains("42 streams served · 1 could not be reached"),
            "{text}"
        );
        assert!(
            text.contains("last error 1 min ago: 10.0.0.5:22: connection refused"),
            "{text}"
        );
    }

    #[test]
    fn health_capacity_and_refusals_are_shown() {
        let mut status = entry(0);
        let probe = |outcome, error: Option<&str>| ProbeStatus {
            outcome,
            ms: Some(46),
            target: "127.0.0.1:443".into(),
            error: error.map(str::to_owned),
            fails: 3,
            target_fails: 2,
            ok_total: 10,
            failed_total: 5,
            secs_ago: 4,
        };
        status.probe = Some(probe(ProbeOutcome::Ok, None));
        let text = render(&plain(), "main", &status, None);
        assert!(
            text.contains(
                "health      ● users can connect · 46 ms to 127.0.0.1:443 · checked 4 s ago"
            ),
            "{text}"
        );
        status.probe = Some(probe(
            ProbeOutcome::Failed,
            Some("every tunnel connection is full"),
        ));
        let text = render(&plain(), "main", &status, None);
        assert!(
            text.contains("○ new connections do not get through (3 in a row): every tunnel connection is full"),
            "{text}"
        );
        status.probe = Some(probe(ProbeOutcome::TargetFailed, None));
        let text = render(&plain(), "main", &status, None);
        assert!(
            text.contains("○ 127.0.0.1:443 cannot be reached from the exit side (2 in a row)"),
            "{text}"
        );
        status.peer.full = 7;
        status.forwards[0].refused_per_ip = 4;
        let text = render(&plain(), "main", &status, None);
        assert!(
            text.contains("7 connections failed: every session was full"),
            "{text}"
        );
        assert!(text.contains("4 over the per-address limit"), "{text}");
    }
}
