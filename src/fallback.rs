//! Transport fallback chain.
//!
//! A tunnel is pinned to one carrier; when that carrier is the one being filtered, the
//! tunnel retries it for ever and the operator is the failover mechanism. A fallback chain
//! is a list of carriers the tunnel may move to on its own: the candidate list is the
//! configured transport first, then `tunnel.fallback_transports` in order. Both ends must
//! carry the same list in the same order — there is no negotiation and nothing new on the
//! wire.
//!
//! The acceptor holds each candidate for the whole dwell until a tunnel establishes; the
//! dialer gives each candidate `dwell / candidates`, with a five-second floor, so it tries
//! every carrier at least once inside one acceptor dwell and the two meet. Only one
//! candidate runs at a time (they share the forwarded ports), and the outgoing one is
//! fully stopped before the next starts. Once a candidate is up it is kept; rotation
//! resumes only if a working candidate stays down for five minutes — the case where the
//! carrier really has been taken away, rather than a transient drop it can recover from
//! on its own.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio::task::JoinSet;
use tokio::time::{sleep, Instant};
use tracing::{info, warn};

use crate::config::{Config, TransportKind, TunnelConfig};
use crate::crypto::Crypto;
use crate::stats::{Peer, Stats};
use crate::transport::{Settings, StealthParams};

/// A working candidate is rotated away from only after it has been down this long: a
/// shorter outage is the carrier's own to recover from, not the chain's.
const WORKING_DOWN: Duration = Duration::from_secs(5 * 60);
/// The dialer gives a candidate at least this long, so it is never dropped just for being
/// slower than a dial timeout.
const MIN_WINDOW: Duration = Duration::from_secs(5);
/// How often the chain checks whether the control channel is up while still trying.
const POLL: Duration = Duration::from_millis(250);
/// How often a working candidate is checked (coarser: it is up, we are only watching for a
/// long outage).
const HOLD_POLL: Duration = Duration::from_secs(2);
/// After a candidate is stopped, this long for its ports to be released before the next
/// one binds them.
const RELEASE: Duration = Duration::from_millis(250);

/// The candidate list: the configured transport first, then `fallback_transports`.
pub fn candidates(config: &Config) -> Vec<TransportKind> {
    let mut list = Vec::with_capacity(1 + config.tunnel.fallback_transports.len());
    list.push(config.tunnel.transport);
    list.extend_from_slice(&config.tunnel.fallback_transports);
    list
}

/// The dialer's per-candidate window: a share of the dwell, with a five-second floor, so
/// every carrier is tried at least once inside one acceptor dwell.
fn dialer_window(dwell: Duration, candidates: usize) -> Duration {
    (dwell / candidates.max(1) as u32).max(MIN_WINDOW)
}

/// `base` (built for the configured transport) with `kind` swapped in: the record padding
/// of `stealth` applies only when `kind` is `stealth`, so no other candidate's wire is
/// padded. The shared `[tunnel.ws]`/`[tunnel.tls]`/`[tunnel.kcp]` tables carry over, so a
/// `wss` candidate still finds its certificate.
pub fn settings_for(base: &Settings, tunnel: &TunnelConfig, kind: TransportKind) -> Settings {
    let stealth = (kind == TransportKind::Stealth).then(|| {
        let s = tunnel.stealth.clone().unwrap_or_default();
        StealthParams {
            padding: s.padding,
            pad_max: s.pad_max,
            jitter: Duration::from_millis(u64::from(s.jitter_ms)),
        }
    });
    Settings {
        kind,
        stealth,
        ..base.clone()
    }
}

/// The handshake and record crypto for a candidate: the token, encryption and mux are the
/// tunnel's, and record padding is on only for `stealth`.
pub fn crypto_for(config: &Config, mux: bool, settings: &Settings) -> Crypto {
    Crypto::new(&config.tunnel.token, config.tunnel.encryption)
        .with_mux(mux)
        .with_stealth(settings.stealth.as_ref().map(|s| s.shaping()))
}

/// Runs the fallback chain until the side stops. `start` builds one candidate's machinery
/// into a fresh task set and returns it, having made it the live transport; the chain owns
/// that set and stops it (releasing the shared ports) before the next candidate starts.
/// `acceptor`: the listening side holds each candidate the whole dwell, the dialing side
/// gives each a share of it.
#[allow(clippy::too_many_arguments)]
pub async fn run_chain<S, Fut>(
    acceptor: bool,
    label: &'static str,
    candidates: Vec<TransportKind>,
    dwell: Duration,
    mux: bool,
    peer: Arc<Peer>,
    stats: Arc<Stats>,
    mut start: S,
) -> Result<()>
where
    S: FnMut(TransportKind) -> Fut,
    Fut: Future<Output = Result<JoinSet<Result<()>>>>,
{
    let window = if acceptor {
        dwell
    } else {
        dialer_window(dwell, candidates.len())
    };
    info!(
        side = label,
        candidates = candidates.len(),
        dwell_secs = dwell.as_secs(),
        window_secs = window.as_secs(),
        "transport fallback: rotating until a candidate comes up"
    );
    let mut idx = 0;
    loop {
        let kind = candidates[idx % candidates.len()];
        idx += 1;
        stats.set_active_transport(Some(kind.name()));
        let mut set = match start(kind).await {
            Ok(set) => set,
            Err(e) => {
                warn!(side = label, transport = kind.name(), error = %format!("{e:#}"),
                    "transport fallback: could not start this transport, trying the next");
                stats.set_active_transport(None);
                sleep(RELEASE).await;
                continue;
            }
        };
        if wait_up(&peer, mux, window, &mut set).await {
            info!(
                side = label,
                transport = kind.name(),
                "transport fallback: this transport is up"
            );
            hold(&peer, mux, &mut set).await;
            warn!(
                side = label,
                transport = kind.name(),
                down_secs = WORKING_DOWN.as_secs(),
                "transport fallback: this transport has been down too long, rotating"
            );
        }
        set.shutdown().await;
        stats.set_active_transport(None);
        sleep(RELEASE).await;
    }
}

/// Waits up to `window` for the control channel to come up. Returns `false` if the window
/// elapses first, or the candidate's machinery stops on its own (a listener that failed, an
/// accept loop that returned).
async fn wait_up(peer: &Peer, mux: bool, window: Duration, set: &mut JoinSet<Result<()>>) -> bool {
    let deadline = Instant::now() + window;
    loop {
        if peer.connected(mux) {
            return true;
        }
        let now = Instant::now();
        if now >= deadline {
            return peer.connected(mux);
        }
        tokio::select! {
            biased;
            joined = set.join_next(), if !set.is_empty() => {
                if let Some(Ok(Err(e))) = &joined {
                    warn!(error = %e, "transport fallback: a transport task ended");
                }
                if set.is_empty() {
                    return false;
                }
            }
            () = sleep(POLL.min(deadline - now)) => {}
        }
    }
}

/// Keeps the candidate while it works; returns once it has been down for [`WORKING_DOWN`]
/// (rotate), or all its tasks have ended.
async fn hold(peer: &Peer, mux: bool, set: &mut JoinSet<Result<()>>) {
    let mut down_since: Option<Instant> = None;
    loop {
        tokio::select! {
            biased;
            _ = set.join_next(), if !set.is_empty() => {
                if set.is_empty() {
                    return;
                }
            }
            () = sleep(HOLD_POLL) => {}
        }
        if peer.connected(mux) {
            down_since = None;
        } else if down_since.get_or_insert_with(Instant::now).elapsed() >= WORKING_DOWN {
            return;
        }
    }
}
