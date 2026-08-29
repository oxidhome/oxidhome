//! Phase 14.7b — per-bearer rate limits on the MCP mount.
//!
//! Sits **before** the bearer-auth layer so a rejected request
//! does zero durable work — no `SQLite` `last_used_ms` update, no
//! audit intent, no audit finalize. A runaway token that hits
//! 429s stops costing the daemon anything past a `HashMap` probe:
//!
//! ```text
//! request → rate_limit → require_token → admission_gate → mcp_service
//! ```
//!
//! # Bucket key
//!
//! The key is a SHA-256 fingerprint of the presented bearer, NOT
//! the resolved actor id. Two reasons:
//!
//! 1. **Zero-cost reject.** Running after `require_token` would
//!    force the auth path to complete (one `SQLite` lookup + one
//!    `last_used_ms` UPDATE + one audit-intent INSERT + one audit
//!    finalize UPDATE per rate-limited request — round-2 P1 on
//!    PR #140). Keying on the bearer fingerprint lets the middleware
//!    reject before any DB write.
//! 2. **Anonymous callers get bounded too.** A caller with no
//!    bearer (or a garbage bearer) still lands in a bucket. Without
//!    that, an unauthenticated attacker could push through
//!    unlimited 401s and grow the audit ledger. The eviction cap
//!    below bounds map size regardless of key entropy.
//!
//! The fingerprint is the first 16 bytes of `SHA-256(bearer)` as
//! hex — 128 bits of collision resistance is more than enough for
//! a rate-limit key that need only survive a few seconds of
//! reuse per bearer. Absent-bearer requests all share the sentinel
//! `"anonymous"` key so they don't inflate the map with unique
//! entries.
//!
//! # Algorithm
//!
//! Leaky bucket per key:
//!
//! - **Capacity** = [`DEFAULT_BUCKET_CAPACITY`] tokens. Bursts up
//!   to this many requests are served without throttling.
//! - **Refill rate** = [`DEFAULT_TOKENS_PER_SECOND`]. Sustained
//!   throughput past that latches into 429s.
//! - **Hard-capped map** = [`MAX_TRACKED_KEYS`] entries. When a
//!   NEW key would push the map over the cap, the least-recently-
//!   observed entry is evicted (round-2 P2 on PR #140). The
//!   previous idle-only sweep didn't remove anything when `1_025`
//!   recent bearers were rotating faster than
//!   [`IDLE_EVICTION_WINDOW`], and every subsequent request would
//!   walk the whole map under the global mutex without freeing a
//!   slot.
//!
//! # Wire shape
//!
//! Exceeded → plain HTTP `429 Too Many Requests` with a
//! `Retry-After: <seconds>` header. Mirrors the admission gate's
//! plain-HTTP 503 shape: the JSON-RPC session hasn't started yet,
//! so a full JSON-RPC error envelope would be misleading.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use sha2::{Digest, Sha256};

/// Default burst capacity per bearer. Two seconds worth of
/// sustained throughput at [`DEFAULT_TOKENS_PER_SECOND`], so
/// well-behaved clients that fan out a handful of parallel reads
/// see zero throttling.
pub(super) const DEFAULT_BUCKET_CAPACITY: u32 = 60;
/// Default refill: 30 requests/second/bearer sustained. Above
/// what any agentic-loop client should need against a household
/// hub, well below what a runaway loop can push.
pub(super) const DEFAULT_TOKENS_PER_SECOND: f64 = 30.0;
/// Idle threshold used by the opportunistic cheap-sweep path. An
/// entry idle for longer is a preferred eviction victim when the
/// map fills up. Not the sole enforcement mechanism — see
/// [`MAX_TRACKED_KEYS`] for the hard cap.
const IDLE_EVICTION_WINDOW: Duration = Duration::from_mins(5);
/// Hard cap on distinct bearer fingerprints tracked. Sized well
/// above any realistic per-hub bearer count. Enforced by
/// LRU-style eviction on insert — the round-2 P2 fix on PR #140
/// (a pure idle-sweep could leave the map at `1_025` forever if
/// rotation is faster than [`IDLE_EVICTION_WINDOW`]).
const MAX_TRACKED_KEYS: usize = 1024;
/// Sentinel key for requests without a bearer. Batching every
/// anonymous request into one bucket avoids inflating the map
/// with unique entries when attackers hit the endpoint without
/// credentials.
const ANONYMOUS_KEY: &str = "anonymous";

/// Per-bearer leaky bucket. `tokens` is fractional so refill
/// under low load isn't rounded to zero. `last_observed` doubles
/// as the LRU stamp for eviction.
#[derive(Debug)]
struct TokenBucket {
    tokens: f64,
    /// Wall-clock instant of the most recent probe against this
    /// bucket (accepted OR rejected). Both refill and LRU
    /// eviction use it.
    last_observed: Instant,
}

/// Shared state the [`rate_limit`] middleware pulls out via
/// `State`. Cheap to clone (single `Arc`).
#[derive(Clone)]
pub(super) struct RateLimiterState {
    inner: Arc<RateLimiterInner>,
}

struct RateLimiterInner {
    buckets: Mutex<HashMap<String, TokenBucket>>,
    capacity: f64,
    refill_per_second: f64,
    max_keys: usize,
}

impl RateLimiterState {
    /// Build a limiter with the default capacity + refill + map cap.
    pub(super) fn new() -> Self {
        Self::with_capacity_and_refill(DEFAULT_BUCKET_CAPACITY, DEFAULT_TOKENS_PER_SECOND)
    }

    /// Build a limiter with custom bucket parameters — public for
    /// tests that need to drive the 429 shape without waiting for
    /// 30 requests/second to accumulate.
    pub(super) fn with_capacity_and_refill(capacity: u32, refill_per_second: f64) -> Self {
        Self::with_all(capacity, refill_per_second, MAX_TRACKED_KEYS)
    }

    /// Fully-parametrized constructor — tests that exercise the
    /// LRU-eviction path need to override [`MAX_TRACKED_KEYS`]
    /// without spraying `1_025` real bearers at the mutex.
    pub(super) fn with_all(capacity: u32, refill_per_second: f64, max_keys: usize) -> Self {
        assert!(max_keys > 0, "rate limiter map cap must be > 0");
        Self {
            inner: Arc::new(RateLimiterInner {
                buckets: Mutex::new(HashMap::new()),
                capacity: f64::from(capacity),
                refill_per_second,
                max_keys,
            }),
        }
    }

    /// Refill the caller's bucket based on wall-clock elapsed
    /// since last observation, then attempt to consume one token.
    /// Returns `Err(seconds_until_refill)` when denied — the
    /// middleware uses that value for `Retry-After`.
    fn try_consume(&self, key: &str) -> Result<(), u64> {
        let now = Instant::now();
        let mut buckets = self
            .inner
            .buckets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        // Ensure room for a NEW entry before we probe: if we'd
        // be inserting and the map is at the hard cap, evict
        // the least-recently-observed entry. Existing keys skip
        // the eviction path entirely — no O(N) sweep on the hot
        // path.
        if !buckets.contains_key(key) && buckets.len() >= self.inner.max_keys {
            evict_one_lru(&mut buckets);
        }

        let bucket = buckets.entry(key.to_string()).or_insert(TokenBucket {
            tokens: self.inner.capacity,
            last_observed: now,
        });

        // Refill by elapsed_seconds * rate, capped at capacity.
        let elapsed_secs = now.duration_since(bucket.last_observed).as_secs_f64();
        bucket.tokens =
            (bucket.tokens + elapsed_secs * self.inner.refill_per_second).min(self.inner.capacity);
        bucket.last_observed = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            Ok(())
        } else {
            // Suggest a retry after enough time to refill one
            // token. Rounded up to the nearest second to keep
            // the header sane; a client polling faster than that
            // just re-hits 429.
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let wait_secs = ((1.0 - bucket.tokens) / self.inner.refill_per_second).ceil() as u64;
            Err(wait_secs.max(1))
        }
    }
}

/// Evict the least-recently-observed bucket. Called only when
/// the map is at [`MAX_TRACKED_KEYS`] AND we're about to insert a
/// NEW key — so the O(N) scan cost is bounded to "at most one
/// scan per new key past the cap." Existing-key probes skip it.
fn evict_one_lru(buckets: &mut HashMap<String, TokenBucket>) {
    let now = Instant::now();
    // Prefer an idle-window victim (cheap to justify) if one
    // exists. Otherwise fall back to the globally oldest entry.
    let idle_victim = buckets
        .iter()
        .find(|(_, b)| now.duration_since(b.last_observed) >= IDLE_EVICTION_WINDOW)
        .map(|(k, _)| k.clone());
    if let Some(k) = idle_victim {
        buckets.remove(&k);
        return;
    }
    if let Some((oldest_key, _)) = buckets
        .iter()
        .min_by_key(|(_, b)| b.last_observed)
        .map(|(k, b)| (k.clone(), b.last_observed))
    {
        buckets.remove(&oldest_key);
    }
}

/// Fingerprint the presented bearer (or the sentinel for
/// absent-bearer requests). Truncated SHA-256 — 128 bits of
/// collision resistance is more than a rate-limit key needs, and
/// the shorter string keeps `HashMap` memory low.
fn bucket_key_from_request(request: &Request) -> String {
    let Some(bearer) = extract_bearer(request) else {
        return ANONYMOUS_KEY.to_string();
    };
    let mut hasher = Sha256::new();
    hasher.update(bearer.as_bytes());
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(32);
    for byte in &digest[..16] {
        use std::fmt::Write as _;
        // `write!` on `String` is infallible.
        let _ = write!(hex, "{byte:02x}");
    }
    format!("bearer:{hex}")
}

/// Pull `Authorization: Bearer <secret>` off a request. Returns
/// `None` on missing header, non-UTF-8 value, or a value that
/// doesn't start with `Bearer `. Local to this module so the
/// rate limiter doesn't add a public dep on the auth crate's
/// extractor.
fn extract_bearer(request: &Request) -> Option<&str> {
    request
        .headers()
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

/// Middleware. Consumes one token per request per bearer
/// fingerprint. Runs OUTSIDE `require_token` so a rejected
/// request does zero `SQLite` writes.
pub(super) async fn rate_limit(
    State(state): State<RateLimiterState>,
    request: Request,
    next: Next,
) -> Response {
    let key = bucket_key_from_request(&request);
    match state.try_consume(&key) {
        Ok(()) => next.run(request).await,
        Err(retry_after) => {
            tracing::warn!(
                bucket_key = %key,
                retry_after,
                "MCP rate limit exceeded — replying 429 Too Many Requests",
            );
            (
                StatusCode::TOO_MANY_REQUESTS,
                [(header::RETRY_AFTER, retry_after.to_string())],
                Body::from(r#"{"error":"MCP per-bearer rate limit exceeded; retry shortly"}"#),
            )
                .into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_up_to_capacity_then_denies() {
        let limiter = RateLimiterState::with_capacity_and_refill(3, 0.0);
        for _ in 0..3 {
            limiter.try_consume("k").expect("within capacity");
        }
        let err = limiter.try_consume("k").expect_err("over capacity");
        assert!(err >= 1, "retry-after must be at least 1s; got {err}");
    }

    #[test]
    fn separate_keys_have_independent_buckets() {
        let limiter = RateLimiterState::with_capacity_and_refill(1, 0.0);
        limiter.try_consume("a").expect("first-a");
        limiter.try_consume("a").expect_err("second-a denied");
        limiter.try_consume("b").expect("first-b");
    }

    #[test]
    fn refill_replenishes_the_bucket_over_time() {
        let limiter = RateLimiterState::with_capacity_and_refill(1, 100.0);
        limiter.try_consume("k").expect("first drains");
        limiter
            .try_consume("k")
            .expect_err("immediate second denied");
        std::thread::sleep(Duration::from_millis(50));
        limiter.try_consume("k").expect("refill served");
    }

    #[test]
    fn refill_caps_at_capacity() {
        let limiter = RateLimiterState::with_capacity_and_refill(2, 1000.0);
        limiter.try_consume("k").expect("first");
        std::thread::sleep(Duration::from_millis(50));
        limiter.try_consume("k").expect("post-refill 1");
        limiter.try_consume("k").expect("post-refill 2");
        limiter
            .try_consume("k")
            .expect_err("cap prevents unbounded refill");
    }

    /// Round-2 P2 on PR #140: with a hard map cap of 3, five
    /// distinct keys must not grow the map past three entries.
    /// Prior implementation would leave 5 entries in the map and
    /// walk them all on every subsequent request.
    #[test]
    fn map_size_stays_bounded_under_key_pressure() {
        let limiter = RateLimiterState::with_all(1, 0.0, 3);
        for i in 0..5 {
            let _ = limiter.try_consume(&format!("k-{i}"));
        }
        let buckets = limiter.inner.buckets.lock().unwrap();
        assert!(
            buckets.len() <= 3,
            "map must not exceed hard cap; got {} entries",
            buckets.len(),
        );
    }

    /// Under key pressure the LRU should evict the oldest entry,
    /// preserving the most recent ones. `k-0` (touched first) is
    /// evicted when `k-3` arrives at cap.
    #[test]
    fn lru_eviction_preserves_recent_entries() {
        let limiter = RateLimiterState::with_all(1, 0.0, 3);
        for i in 0..3 {
            let _ = limiter.try_consume(&format!("k-{i}"));
            // Force distinct `last_observed` timestamps so LRU
            // picks a deterministic victim.
            std::thread::sleep(Duration::from_millis(2));
        }
        // Push one more — k-0 (oldest) should be evicted.
        let _ = limiter.try_consume("k-3");
        let buckets = limiter.inner.buckets.lock().unwrap();
        assert!(
            !buckets.contains_key("k-0"),
            "oldest key must be evicted at cap; got keys {:?}",
            buckets.keys().collect::<Vec<_>>(),
        );
        assert!(buckets.contains_key("k-3"), "newest key must be admitted");
        assert!(buckets.contains_key("k-2"));
    }

    #[test]
    fn fingerprint_is_stable_across_calls() {
        let make_req = |bearer: &str| {
            axum::http::Request::builder()
                .uri("/")
                .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
                .body(Body::empty())
                .unwrap()
        };
        let a = bucket_key_from_request(&make_req("secret-a"));
        let b = bucket_key_from_request(&make_req("secret-a"));
        assert_eq!(a, b, "same bearer must fingerprint identically");
        assert_ne!(a, bucket_key_from_request(&make_req("secret-b")));
    }

    #[test]
    fn absent_bearer_hits_the_shared_anonymous_bucket() {
        let make_req = || {
            axum::http::Request::builder()
                .uri("/")
                .body(Body::empty())
                .unwrap()
        };
        assert_eq!(bucket_key_from_request(&make_req()), ANONYMOUS_KEY);
        assert_eq!(bucket_key_from_request(&make_req()), ANONYMOUS_KEY);
    }
}
