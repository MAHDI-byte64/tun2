//! A fixed-rate congestion controller for QUIC, in the spirit of Hysteria's "Brutal": the
//! sender holds a set bandwidth and treats loss as noise, compensating by how much of what it
//! sends comes back acknowledged. On a lossy path this keeps the rate where a loss-based
//! controller (Cubic, NewReno, even BBR) would collapse. It is deliberately unfair to other
//! flows, so it is meant for a path you control, with the rate set to what that path can carry.
//!
//! quinn gives a congestion controller a single lever on the send rate: [`Controller::window`],
//! the number of bytes it may keep in flight. quinn sends about `window / rtt` and paces a
//! little above it, so to deliver `rate` bytes a second over a path that drops a fraction
//! `1 - ack_rate` of what is sent, the window is held at `rate * min_rtt / ack_rate`. The base
//! (minimum) round trip is used, not the smoothed one, so a filling queue does not inflate it.

use std::any::Any;
use std::sync::Arc;
use std::time::{Duration, Instant};

use quinn::congestion::{Controller, ControllerFactory};
use quinn_proto::RttEstimator;

/// The delivered fraction is never read as lower than this, so one very lossy moment cannot
/// blow the window up without bound.
const MIN_ACK_RATE: f64 = 0.2;
/// The smoothed delivered fraction is recomputed at most this often (and never faster than the
/// path's round trip), so a single batch of losses does not swing it.
const MIN_INTERVAL: Duration = Duration::from_millis(50);
/// A floor on the round trip used in the window, so a near-zero measurement cannot shrink it to
/// nothing.
const MIN_RTT: Duration = Duration::from_millis(5);
/// A ceiling on the in-flight window: 1 GiB is past anything a real path needs, and keeps the
/// arithmetic away from overflow and from disabling quinn's pacer (which it does above u32 max).
const MAX_WINDOW: u64 = 1 << 30;

#[derive(Clone)]
struct FixedController {
    bytes_per_sec: f64,
    mtu: u64,
    window: u64,
    acked: u64,
    lost: u64,
    ack_rate: f64,
    min_rtt: Duration,
    last_update: Instant,
}

impl FixedController {
    fn new(bytes_per_sec: f64, mtu: u16, now: Instant) -> Self {
        let mtu = u64::from(mtu);
        // Start with a guessed 100 ms of data in flight (at least 16 packets), then adjust to
        // the measured round trip within a couple of them.
        let window = ((bytes_per_sec * 0.1) as u64).clamp(16 * mtu, MAX_WINDOW);
        Self {
            bytes_per_sec,
            mtu,
            window,
            acked: 0,
            lost: 0,
            ack_rate: 1.0,
            min_rtt: Duration::from_millis(100),
            last_update: now,
        }
    }

    fn recompute(&mut self, now: Instant) {
        let interval = self.min_rtt.max(MIN_INTERVAL);
        if now.saturating_duration_since(self.last_update) < interval {
            return;
        }
        let total = self.acked + self.lost;
        if total > 0 {
            let sample = self.acked as f64 / total as f64;
            self.ack_rate = 0.75 * self.ack_rate + 0.25 * sample;
        }
        self.acked = 0;
        self.lost = 0;
        self.last_update = now;
        let rate = self.ack_rate.clamp(MIN_ACK_RATE, 1.0);
        let srtt = self.min_rtt.max(MIN_RTT).as_secs_f64();
        let target = self.bytes_per_sec * srtt / rate;
        self.window = (target as u64).clamp(4 * self.mtu, MAX_WINDOW);
    }
}

impl Controller for FixedController {
    fn on_ack(
        &mut self,
        now: Instant,
        _sent: Instant,
        bytes: u64,
        _app_limited: bool,
        rtt: &RttEstimator,
    ) {
        self.acked += bytes;
        let m = rtt.min();
        if m > Duration::ZERO {
            self.min_rtt = m;
        }
        self.recompute(now);
    }

    fn on_end_acks(
        &mut self,
        now: Instant,
        _in_flight: u64,
        _app_limited: bool,
        _largest_packet_num_acked: Option<u64>,
    ) {
        self.recompute(now);
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        _sent: Instant,
        _is_persistent_congestion: bool,
        lost_bytes: u64,
    ) {
        // `lost_bytes` is 0 for an ECN mark; only real losses count toward the delivered
        // fraction, and loss never shrinks the window — that is the point.
        self.lost += lost_bytes;
        self.recompute(now);
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.mtu = u64::from(new_mtu);
        self.window = self.window.max(4 * self.mtu);
    }

    fn window(&self) -> u64 {
        self.window
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }

    fn initial_window(&self) -> u64 {
        self.window
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

/// Builds a fixed-rate controller for each QUIC connection.
#[derive(Debug, Clone)]
pub struct FixedConfig {
    bytes_per_sec: f64,
}

impl FixedConfig {
    pub fn from_mbps(mbps: u32) -> Self {
        Self {
            bytes_per_sec: f64::from(mbps) * 1_000_000.0 / 8.0,
        }
    }

    /// The rate in bytes a second, to size the connection's flow-control window to match.
    pub fn bytes_per_sec(&self) -> f64 {
        self.bytes_per_sec
    }
}

impl ControllerFactory for FixedConfig {
    fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        Box::new(FixedController::new(self.bytes_per_sec, current_mtu, now))
    }
}

// `RttEstimator`'s constructor is `pub(crate)` in quinn-proto, so these drive the controller
// through its own fields (this test module can see them) and `recompute`, rather than through
// `on_ack`, which would need an `RttEstimator` we cannot build.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_window_tracks_rate_times_rtt_and_grows_under_loss() {
        // 50 Mbit/s = 6.25 MB/s. At a 40 ms base round trip and no loss the window is about
        // one bandwidth-delay product (~250 KB).
        let rate = 50_000_000.0 / 8.0;
        let start = Instant::now();
        let mut c = FixedController::new(rate, 1200, start);
        c.min_rtt = Duration::from_millis(40);
        c.acked = 600_000;
        c.lost = 0;
        c.recompute(start + Duration::from_millis(100));
        let clean = c.window();
        let bdp = (rate * 0.040) as u64; // ~250 KB
        assert!(
            clean >= bdp / 2 && clean <= bdp * 3,
            "window {clean} near one BDP {bdp}"
        );

        // Sustained 25% loss drives the delivered fraction down, so the window grows to push
        // the same amount through, and stays bounded.
        let mut now = start + Duration::from_millis(100);
        for _ in 0..20 {
            now += Duration::from_millis(100);
            c.acked = 450_000;
            c.lost = 150_000;
            c.recompute(now);
        }
        assert!(
            c.window() > clean,
            "window grew under loss: {} > {clean}",
            c.window()
        );
        assert!(c.window() <= MAX_WINDOW);
    }

    #[test]
    fn the_window_never_falls_to_nothing() {
        let rate = 1_000_000.0 / 8.0;
        let start = Instant::now();
        let mut c = FixedController::new(rate, 1200, start);
        assert!(c.window() >= 4 * 1200);
        // A catastrophic-loss moment cannot be read below the floor, so the window is bounded.
        c.min_rtt = Duration::from_millis(20);
        c.acked = 1;
        c.lost = 1_000_000;
        c.recompute(start + Duration::from_millis(100));
        assert!(c.window() >= 4 * 1200 && c.window() <= MAX_WINDOW);
        c.on_mtu_update(1400);
        assert!(c.window() >= 4 * 1400);
    }
}
