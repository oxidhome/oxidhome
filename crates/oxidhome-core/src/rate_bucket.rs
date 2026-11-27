//! A leaky token bucket: the refill-and-take step of the MCP per-token
//! rate limit (14.7b).

use std::time::Instant;

/// Fractional tokens plus the instant they were last refilled, which
/// doubles as an LRU stamp for callers that evict idle buckets.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Bucket {
    pub(crate) tokens: f64,
    pub(crate) last_observed: Instant,
}

impl Bucket {
    /// A bucket holding `capacity` tokens as of `now`.
    pub(crate) fn full(capacity: f64, now: Instant) -> Self {
        Self {
            tokens: capacity,
            last_observed: now,
        }
    }

    /// Refill for the time since the last call (`refill_per_second`,
    /// capped at `capacity`) and stamp `now`.
    pub(crate) fn refill(&mut self, now: Instant, capacity: f64, refill_per_second: f64) {
        let elapsed = now
            .saturating_duration_since(self.last_observed)
            .as_secs_f64();
        self.tokens = (self.tokens + elapsed * refill_per_second).min(capacity);
        // Monotonic: a caller that sampled `now` before taking the
        // lock may arrive after a later sample; moving the stamp back
        // would credit the same interval twice.
        if now > self.last_observed {
            self.last_observed = now;
        }
    }

    /// Seconds until one token is available, at least 1. Meaningful
    /// after [`Self::refill`] left fewer than one token.
    pub(crate) fn wait_secs(&self, refill_per_second: f64) -> u64 {
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let wait = ((1.0 - self.tokens) / refill_per_second).ceil() as u64;
        wait.max(1)
    }

    /// Refill, then take one token. `Err(seconds)` until one is
    /// available when the bucket is empty.
    pub(crate) fn try_take(
        &mut self,
        now: Instant,
        capacity: f64,
        refill_per_second: f64,
    ) -> Result<(), u64> {
        self.refill(now, capacity, refill_per_second);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            Ok(())
        } else {
            Err(self.wait_secs(refill_per_second))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// An out-of-order sample neither refills nor moves the stamp back.
    #[test]
    fn refill_is_monotonic() {
        let t0 = Instant::now();
        let t1 = t0 + Duration::from_secs(10);
        let mut b = Bucket {
            tokens: 0.0,
            last_observed: t0,
        };
        b.refill(t1, 10.0, 0.1);
        assert!((b.tokens - 1.0).abs() < 1e-9);
        b.refill(t0, 10.0, 0.1);
        assert_eq!(b.last_observed, t1);
        b.refill(t1, 10.0, 0.1);
        assert!((b.tokens - 1.0).abs() < 1e-9, "no double credit");
    }

    #[test]
    fn drains_then_refills() {
        let t0 = Instant::now();
        let mut b = Bucket::full(2.0, t0);
        assert!(b.try_take(t0, 2.0, 1.0).is_ok());
        assert!(b.try_take(t0, 2.0, 1.0).is_ok());
        assert_eq!(b.try_take(t0, 2.0, 1.0), Err(1));
        let t1 = t0 + Duration::from_secs(1);
        assert!(b.try_take(t1, 2.0, 1.0).is_ok());
        // Refill is capped at capacity.
        let t2 = t1 + Duration::from_hours(1);
        b.refill(t2, 2.0, 1.0);
        assert!((b.tokens - 2.0).abs() < f64::EPSILON);
    }
}
