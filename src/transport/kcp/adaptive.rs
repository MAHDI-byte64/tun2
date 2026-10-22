//! The send window that follows the path. KCP's presets run without congestion control,
//! so the send window alone decides how much is in flight: too small and a fat path is
//! left idle, too large and a narrow path's queue fills (then drops, then resends). The
//! window starts at the configured one and moves with what the acks say: it grows while
//! it is the limit and the round trip stays flat, and comes back down when the round trip
//! inflates (a queue is building), never below the configured window: that one is the
//! profile's (or the operator's) choice, and the adaptive part only adds headroom on a
//! fatter path. Resends only hold it back: KCP's fast modes resend on a couple of
//! duplicate acks, so some resends come without any loss, and a window that shrank on
//! them would starve a fat path. KCP acks on its flush tick, so a measured round trip is
//! the path's plus up to one interval: the thresholds allow for that interval, or a fast
//! path (where the interval is most of the round trip) would read as inflated for good.

use std::time::Duration;

use tokio::time::Instant;

/// How often the window is reconsidered.
const STEP: Duration = Duration::from_millis(100);
/// Length of the two buckets the minimum round trip is kept over.
const MIN_RTT_BUCKET: Duration = Duration::from_secs(10);
/// A round trip this much above the minimum means a queue is building.
const INFLATED: f64 = 1.25;
/// A round trip at most this much above the minimum is flat enough to grow.
const FLAT: f64 = 1.1;
/// Resends above this share of the packets sent since the last step hold the window
/// where it is (growing into loss helps nothing).
const LOSSY: f64 = 0.01;

/// What the last step decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Step {
    /// Too soon, or nothing known yet.
    None,
    /// Looked, and the window stays.
    Same,
    /// The window is now this.
    Window(u16),
}

pub(super) struct Adaptive {
    window: u16,
    /// The configured window: the floor.
    base: u16,
    max: u16,
    /// KCP's flush interval, ms: how late an ack can be through no fault of the path.
    interval: f64,
    /// Smoothed round trip, ms.
    srtt: Option<f64>,
    /// Lowest round trip seen in the current and the previous bucket.
    min_rtt: [Option<f64>; 2],
    bucket_start: Instant,
    last_step: Instant,
}

impl Adaptive {
    /// `base`: the configured send window, where it starts and the least it will be;
    /// `max`: how far it may grow (the receive window: the peer advertises its own, which
    /// caps the effective window anyway); `interval_ms`: KCP's flush interval.
    pub(super) fn new(base: u16, max: u16, interval_ms: u32, now: Instant) -> Self {
        Self {
            window: base,
            base,
            max: max.max(base),
            interval: f64::from(interval_ms),
            srtt: None,
            min_rtt: [None, None],
            bucket_start: now,
            last_step: now,
        }
    }

    #[cfg(test)]
    pub(super) fn window(&self) -> u16 {
        self.window
    }

    /// A round trip measured from an ack, in ms.
    pub(super) fn sample(&mut self, rtt_ms: f64, now: Instant) {
        let age = now - self.bucket_start;
        if age >= MIN_RTT_BUCKET * 2 {
            self.min_rtt = [None, None];
            self.bucket_start = now;
        } else if age >= MIN_RTT_BUCKET {
            self.min_rtt = [None, self.min_rtt[0]];
            self.bucket_start = now;
        }
        let bucket = &mut self.min_rtt[0];
        *bucket = Some(bucket.map_or(rtt_ms, |m| m.min(rtt_ms)));
        self.srtt = Some(self.srtt.map_or(rtt_ms, |s| s * 0.875 + rtt_ms * 0.125));
    }

    /// Reconsiders the window: `queued` is what KCP holds for sending (queued and in
    /// flight), `remote` the window the peer advertises, `resent` / `sent` the packets
    /// resent and sent since the last step.
    pub(super) fn decide(
        &mut self,
        now: Instant,
        queued: usize,
        remote: u16,
        resent: u64,
        sent: u64,
    ) -> Step {
        if now - self.last_step < STEP {
            return Step::None;
        }
        self.last_step = now;
        let (Some(srtt), Some(min)) = (
            self.srtt,
            self.min_rtt.iter().flatten().copied().reduce(f64::min),
        ) else {
            return Step::None;
        };
        let lossy = sent >= 20 && resent as f64 > sent as f64 * LOSSY;
        let before = self.window;
        if srtt > min * INFLATED + 2.0 + self.interval {
            self.window = (self.window - self.window / 8).max(self.base);
        } else if queued >= self.window as usize
            && remote >= self.window
            && srtt <= min * FLAT + 1.0 + self.interval
            && !lossy
        {
            self.window = self.window.saturating_add(self.window / 4).min(self.max);
        }
        if self.window == before {
            Step::Same
        } else {
            Step::Window(self.window)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(start: Instant, ms: u64) -> Instant {
        start + Duration::from_millis(ms)
    }

    /// Steps every 100 ms with a flat round trip of `rtt` ms and the window binding.
    fn run(
        a: &mut Adaptive,
        start: Instant,
        from_ms: u64,
        steps: u64,
        rtt: f64,
        remote: u16,
    ) -> Vec<Step> {
        (0..steps)
            .map(|i| {
                let now = at(start, from_ms + i * 100);
                a.sample(rtt, now);
                a.decide(now, usize::MAX, remote, 0, 100)
            })
            .collect()
    }

    #[test]
    fn grows_while_binding_and_flat_up_to_the_maximum() {
        let start = Instant::now();
        let mut a = Adaptive::new(1024, 4096, 10, start);
        assert_eq!(
            a.decide(start, usize::MAX, u16::MAX, 0, 0),
            Step::None,
            "no sample yet"
        );
        let steps = run(&mut a, start, 100, 12, 40.0, u16::MAX);
        assert_eq!(steps[0], Step::Window(1280));
        assert_eq!(a.window(), 4096, "{steps:?}");
        assert!(steps.contains(&Step::Same), "stays at the maximum");
    }

    #[test]
    fn does_not_grow_when_idle_or_peer_limited() {
        let start = Instant::now();
        let mut a = Adaptive::new(1024, 4096, 10, start);
        let now = at(start, 100);
        a.sample(40.0, now);
        assert_eq!(
            a.decide(now, 10, u16::MAX, 0, 100),
            Step::Same,
            "nothing queued"
        );
        let now = at(start, 200);
        a.sample(40.0, now);
        assert_eq!(
            a.decide(now, usize::MAX, 512, 0, 100),
            Step::Same,
            "peer window smaller"
        );
    }

    #[test]
    fn shrinks_on_an_inflated_round_trip_and_holds_on_resends() {
        let start = Instant::now();
        let mut a = Adaptive::new(1024, 4096, 10, start);
        run(&mut a, start, 100, 2, 40.0, u16::MAX);
        assert_eq!(a.window(), 1600);
        // The round trip climbs: a queue is building.
        let now = at(start, 400);
        for _ in 0..4 {
            a.sample(120.0, now);
        }
        assert_eq!(
            a.decide(now, usize::MAX, u16::MAX, 0, 100),
            Step::Window(1400)
        );
        // Flat, but every tenth packet resent: no growth (and no shrinking either).
        let mut a = Adaptive::new(1024, 4096, 10, start);
        let now = at(start, 100);
        a.sample(40.0, now);
        assert_eq!(a.decide(now, usize::MAX, u16::MAX, 10, 100), Step::Same);
        assert_eq!(
            a.decide(at(start, 200), usize::MAX, u16::MAX, 0, 100),
            Step::Window(1280)
        );
        // Inflated for long: back to the configured window, never below it.
        for i in 3..60 {
            let now = at(start, i * 100);
            a.sample(200.0, now);
            a.decide(now, usize::MAX, u16::MAX, 0, 100);
        }
        assert_eq!(a.window(), 1024);
    }

    #[test]
    fn a_fast_path_is_not_read_as_inflated_by_the_ack_tick() {
        // A local path: the round trip is 0.4 ms when an ack goes out at once and up to
        // the 10 ms interval otherwise. The average is well above 1.25 x the minimum,
        // yet nothing queues: the window must keep growing.
        let start = Instant::now();
        let mut a = Adaptive::new(1024, 16384, 10, start);
        for i in 0..40 {
            let now = at(start, 100 + i * 100);
            a.sample(0.4, now);
            for _ in 0..7 {
                a.sample(6.0, now);
            }
            a.decide(now, usize::MAX, u16::MAX, 0, 100);
        }
        assert_eq!(a.window(), 16384);
    }

    #[test]
    fn the_minimum_round_trip_is_forgotten_after_two_buckets() {
        let start = Instant::now();
        let mut a = Adaptive::new(1024, 4096, 10, start);
        a.sample(40.0, at(start, 0));
        // 25 s later the path is slower for good: 60 ms is the new normal, not inflation.
        for i in 0..5 {
            a.sample(60.0, at(start, 25_000 + i * 100));
        }
        assert_eq!(
            a.decide(at(start, 25_500), usize::MAX, u16::MAX, 0, 100),
            Step::Window(1280)
        );
    }

    #[test]
    fn steps_at_most_every_hundred_milliseconds() {
        let start = Instant::now();
        let mut a = Adaptive::new(1024, 4096, 10, start);
        a.sample(40.0, at(start, 100));
        assert_eq!(
            a.decide(at(start, 100), usize::MAX, u16::MAX, 0, 100),
            Step::Window(1280)
        );
        a.sample(40.0, at(start, 150));
        assert_eq!(
            a.decide(at(start, 150), usize::MAX, u16::MAX, 0, 100),
            Step::None
        );
    }
}
