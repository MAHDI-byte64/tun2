//! Orchestrates the IP spoof tester across two servers, the way the benchmark orchestrates
//! a link test. The panel asks the destination server to receive and tally probes while it
//! asks the source server to send them from a set of forged source addresses, then returns
//! the destination's scored report: which forged sources reached it.
//!
//! Unlike the benchmark it is synchronous (one short run), so the HTTP request holds until
//! the report is ready. The last report for a (source, destination) pair is kept in the
//! database for the panel to show again.

use std::net::Ipv4Addr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use tokio::time::sleep;

use crate::hub::Hub;
use crate::wire::{IpTestReceiverReply, IpTestSenderReply, Request};
use kariz::spooftest::{Report, SourceResult, MAX_SOURCES};

/// A request to probe which forged sources get from one server to another.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Ask {
    /// The server that sends the probes (forges the sources).
    pub from: String,
    /// The server that receives and tallies them.
    pub to: String,
    /// The packet shape to probe with (`udp`, `tcp`, `icmp`, `gre`, `ipip`, `proto58`).
    #[serde(default)]
    pub shape: String,
    /// The forged source addresses to try (IPs, CIDR blocks or `a.b.c.d-e.f.g.h` ranges).
    #[serde(default)]
    pub sources: Vec<String>,
    /// The port for the `udp`/`tcp` shapes (0: a default).
    #[serde(default)]
    pub port: u16,
    /// Probes to send per source (0: a default).
    #[serde(default)]
    pub count: u16,
    /// Acceptable loss as a percentage (a source passes at `100 - loss`% arrival). Absent
    /// (not `0`) means the default — so an explicit `0` asks for strict 100% arrival.
    #[serde(default)]
    pub loss: Option<u8>,
}

/// The default probes per source, and the default destination port for the port shapes.
const DEFAULT_COUNT: u16 = 10;
const DEFAULT_PORT: u16 = 44300;
const DEFAULT_LOSS: u8 = 20;
/// The delay between probes on the sender, in milliseconds (small, for a quick run).
const INTERVAL_MS: u16 = 2;

/// A saved IP-test result for the panel to show again.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Saved {
    pub from: String,
    pub to: String,
    pub created: i64,
    pub report: Report,
}

/// Runs one IP spoof test and returns the destination's scored report.
pub async fn run(hub: &Hub, ask: Ask) -> Result<Report> {
    if ask.from == ask.to {
        bail!("same_server");
    }
    let shape = if ask.shape.is_empty() {
        "udp".to_string()
    } else {
        ask.shape.clone()
    };
    if kariz::config::SpoofShape::from_name(&shape).is_none() {
        bail!("bad_input");
    }
    let has_ports = matches!(shape.as_str(), "udp" | "tcp");
    // Expand the source list up front so we can report the ones that never arrive, too.
    let expanded = kariz::config::expand_ipv4_specs(&ask.sources, MAX_SOURCES)
        .map_err(|_| anyhow::anyhow!("bad_input"))?;
    if expanded.is_empty() {
        bail!("bad_input");
    }

    // Both servers must be reachable.
    let views = hub.snapshot()?;
    for id in [&ask.from, &ask.to] {
        match views.iter().find(|s| &s.id == id) {
            Some(s) if s.online || s.local => {}
            Some(_) => bail!("offline:{id}"),
            None => bail!("bad_input"),
        }
    }

    // The destination's real address, which the sender aims at.
    let dst_host = hub
        .addr_of(&ask.to)
        .and_then(|a| host_only(&a))
        .ok_or_else(|| anyhow::anyhow!("no_address:{}", ask.to))?;
    if dst_host.parse::<Ipv4Addr>().is_err() {
        // Spoofing is IPv4 only; a hostname or IPv6 address cannot be used.
        bail!("not_ipv4:{}", ask.to);
    }

    let count = if ask.count == 0 {
        DEFAULT_COUNT
    } else {
        ask.count.min(1000)
    };
    let loss = ask.loss.map(|v| v.min(100)).unwrap_or(DEFAULT_LOSS);
    let port = if has_ports {
        if ask.port == 0 {
            DEFAULT_PORT
        } else {
            ask.port
        }
    } else {
        0
    };
    let run_id = fresh_run_id();

    // The receiver must capture for at least as long as the sender takes, plus a margin.
    let sender_ms = (expanded.len() as u64) * (count as u64) * (INTERVAL_MS as u64);
    let seconds = ((sender_ms / 1000) + 4).clamp(5, 60) as u16;

    let bind = format!("0.0.0.0:{port}");
    let to_addr = format!("{dst_host}:{port}");

    // Start the receiver (it returns its report after `seconds`); a moment later start the
    // sender, so the receiver is already capturing when the probes arrive.
    let recv_req = Request::IpTestReceiver {
        shape: shape.clone(),
        bind,
        seconds,
        run_id,
        expect: count,
        loss,
    };
    let send_req = Request::IpTestSender {
        to: to_addr,
        shape: shape.clone(),
        sources: ask.sources.clone(),
        count,
        interval_ms: INTERVAL_MS,
        run_id,
    };
    let timeout = Duration::from_secs(u64::from(seconds) + 15);
    let receive = hub.ask_as_within::<IpTestReceiverReply>(&ask.to, &recv_req, timeout);
    let send = async {
        sleep(Duration::from_millis(800)).await;
        hub.ask_as_within::<IpTestSenderReply>(&ask.from, &send_req, timeout)
            .await
    };
    let (recv_res, send_res) = tokio::join!(receive, send);

    // A sender failure (e.g. the kernel refused every forged source) is worth surfacing.
    if let Ok(s) = &send_res {
        if !s.ok {
            if let Some(e) = &s.error {
                bail!("sender:{e}");
            }
        }
    }
    let reply = recv_res.map_err(|e| anyhow::anyhow!("{e:#}"))?;
    if !reply.ok {
        bail!(
            "receiver:{}",
            reply.error.unwrap_or_else(|| "failed".into())
        );
    }
    let mut report = reply
        .report
        .ok_or_else(|| anyhow::anyhow!("receiver returned no report"))?;

    // Add the sources that never arrived, so the panel shows the full picture.
    merge_missing(&mut report, &expanded);

    let _ = save(hub, &ask.from, &ask.to, &report);
    Ok(report)
}

/// Adds every tested source that the receiver never saw as a failed row, and re-counts.
fn merge_missing(report: &mut Report, tested: &[Ipv4Addr]) {
    use std::collections::HashSet;
    let seen: HashSet<String> = report.results.iter().map(|r| r.ip.clone()).collect();
    for ip in tested {
        let s = ip.to_string();
        if !seen.contains(&s) {
            report.results.push(SourceResult {
                ip: s,
                received: 0,
                ok: false,
            });
        }
    }
    report.usable = report.results.iter().filter(|r| r.ok).count() as u32;
    report.seen = report.results.iter().filter(|r| r.received > 0).count() as u32;
    // Best first: most received, then address order.
    report
        .results
        .sort_by(|a, b| b.received.cmp(&a.received).then(a.ip.cmp(&b.ip)));
}

/// The host part of an address that may carry a `:port` (IPv4 only; a bracketed IPv6
/// address is returned without brackets and will fail the later IPv4 parse).
fn host_only(addr: &str) -> Option<String> {
    let a = addr.trim();
    if a.parse::<Ipv4Addr>().is_ok() {
        return Some(a.to_string());
    }
    if let Some((host, _)) = a.rsplit_once(':') {
        return Some(host.trim_matches(['[', ']']).to_string());
    }
    Some(a.to_string())
}

/// A run id unlikely to collide with a concurrent run on the same destination.
fn fresh_run_id() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos() ^ (d.as_secs() as u32))
        .unwrap_or(1)
        .max(1)
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Keeps a finished run as the last between `from` and `to`.
fn save(hub: &Hub, from: &str, to: &str, report: &Report) -> Result<()> {
    hub.db.conn().execute(
        "INSERT INTO ip_tests (src, dst, created, result) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT (src, dst) DO UPDATE SET created = excluded.created, result = excluded.result",
        rusqlite::params![from, to, now(), serde_json::to_string(report)?],
    )?;
    Ok(())
}

/// The last IP test between `from` and `to` (in that order).
pub fn last(hub: &Hub, from: &str, to: &str) -> Result<Option<Saved>> {
    use rusqlite::OptionalExtension;
    let row: Option<(i64, String)> = hub
        .db
        .conn()
        .query_row(
            "SELECT created, result FROM ip_tests WHERE src = ?1 AND dst = ?2",
            [from, to],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    Ok(row.and_then(|(created, text)| {
        serde_json::from_str::<Report>(&text)
            .ok()
            .map(|report| Saved {
                from: from.to_string(),
                to: to.to_string(),
                created,
                report,
            })
    }))
}
