//! Phase 14.7b — per-token rate limits on the MCP mount.
//!
//! Sits **before** the bearer-auth layer so a rejected request
//! does zero durable work — no `SQLite` `last_used_ms` update,
//! no audit intent, no audit finalize. A runaway token that
//! hits 429s stops costing the daemon anything past one
//! read-only `SQLite` SELECT + a `HashMap` probe:
//!
//! ```text
//! request → rate_limit → require_token → admission_gate → mcp_service
//! ```
//!
//! # Bucket key
//!
//! The key is the **resolved token id**, obtained via a
//! read-only [`TokenStore::verify_read_only`] before the audit
//! path is entered. Deriving the key server-side (rather than
//! from client-controlled bytes) means:
//!
//! 1. **Rotating garbage-bearer attackers land in ONE bucket.**
//!    Round-3 P1 on PR #140 flagged that a fingerprint-of-
//!    bearer key gave every `Bearer garbage-N` a fresh
//!    capacity-60 bucket, so 429s never triggered. Every
//!    unrecognized bearer now hits the shared
//!    [`UNAUTHENTICATED_KEY`] bucket, which is bounded by one
//!    single map entry regardless of key entropy.
//! 2. **Equivalent Authorization headers land in the SAME
//!    bucket.** Round-3 P1 on PR #140: the pre-fix parser was
//!    case-sensitive and space-strict, so `Bearer tok`,
//!    `Bearer  tok`, and `bearer tok` — all identical under
//!    RFC 6750 § 2.1 — got distinct buckets, letting a caller
//!    reset their rate limit by varying whitespace. Reusing
//!    the canonical extractor from `crate::api::auth::extract_bearer`
//!    keeps parsing consistent between the rate limiter and
//!    the auth layer.
//!
//! # Verify reuse
//!
//! To avoid a second SELECT downstream, the resolved token
//! record is stashed in the request extensions as
//! [`PreVerifiedBearer`]. `crate::api::auth::require_token`
//! reads it out and skips its own SELECT, doing only the
//! `last_used_ms` bump + audit intent + audit finalize on the
//! way through. Net cost per request: ONE `SQLite` SELECT
//! regardless of outcome (rate-limited or admitted).
//!
//! # Algorithm
//!
//! Two leaky buckets in series:
//!
//! 1. **Ingress bucket** — one shared bucket for the entire
//!    endpoint. Rate-caps at [`DEFAULT_INGRESS_TOKENS_PER_SECOND`]
//!    with burst [`DEFAULT_INGRESS_CAPACITY`]. Runs BEFORE the
//!    read-only bearer verification, so a flood of syntactically
//!    valid but unknown tokens (or a flood of the same valid
//!    token) can't force unlimited serialized `SQLite` SELECTs
//!    that would park tokio workers on the shared DB mutex
//!    (round-4 P1 on PR #140). This is a coarse ingress cap,
//!    not a per-caller policy — the per-token bucket below is
//!    the fairness layer.
//! 2. **Per-token bucket** — one bucket per resolved token id
//!    (or [`UNAUTHENTICATED_KEY`]).
//!    - **Capacity** = [`DEFAULT_BUCKET_CAPACITY`] tokens.
//!    - **Refill rate** = [`DEFAULT_TOKENS_PER_SECOND`].
//!    - **Hard-capped map** = [`MAX_TRACKED_KEYS`] entries.
//!      When a NEW key would push the map over the cap, the
//!      least-recently-observed entry is evicted (round-2 P2
//!      on PR #140). Anonymous / unrecognized requests share
//!      ONE map entry, so garbage-bearer rotation can't grow
//!      the map at all.
//!
//! Between the two buckets the `TokenStore::verify_read_only`
//! call runs off the async worker via
//! `tokio::task::spawn_blocking` — `Db::read` uses the shared
//! `SQLite` mutex and its own docs require blocking-pool
//! isolation for async callers (round-4 P1 on PR #140).
//!
//! # Wire shape
//!
//! Exceeded → plain HTTP `429 Too Many Requests` with a
//! `Retry-After: <seconds>` header. Mirrors the admission
//! gate's plain-HTTP 503 shape: the JSON-RPC session hasn't
//! started yet, so a full JSON-RPC error envelope would be
//! misleading.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use tokio::sync::Semaphore;

use crate::api::auth::extract_bearer;
use crate::state::TokenStore;
use crate::state::auth_token::TokenRecord;

/// Default burst capacity per token. Two seconds worth of
/// sustained throughput at [`DEFAULT_TOKENS_PER_SECOND`], so
/// well-behaved clients that fan out a handful of parallel
/// reads see zero throttling.
pub(super) const DEFAULT_BUCKET_CAPACITY: u32 = 60;
/// Default refill: 30 requests/second/token sustained. Above
/// what any agentic-loop client should need against a
/// household hub, well below what a runaway loop can push.
pub(super) const DEFAULT_TOKENS_PER_SECOND: f64 = 30.0;
/// Default burst capacity for the shared ingress bucket. Sized
/// well above [`DEFAULT_BUCKET_CAPACITY`] so a legitimate
/// operator with several agents on separate tokens all
/// bursting concurrently doesn't hit the coarse ingress cap
/// before the per-token cap.
pub(super) const DEFAULT_INGRESS_CAPACITY: u32 = 400;
/// Default ingress refill: 200 requests/second across the
/// entire endpoint. Roughly seven times the per-token rate so
/// a household with a handful of active tokens has headroom;
/// still bounded well below what an unbounded verify flood
/// could push through the shared `SQLite` mutex.
pub(super) const DEFAULT_INGRESS_TOKENS_PER_SECOND: f64 = 200.0;
/// Idle threshold used by the opportunistic cheap-sweep path.
/// An entry idle longer than this is a preferred eviction
/// victim when the map fills up. Not the sole enforcement
/// mechanism — see [`MAX_TRACKED_KEYS`] for the hard cap.
const IDLE_EVICTION_WINDOW: Duration = Duration::from_mins(5);
/// Hard cap on distinct token ids tracked. Sized well above
/// any realistic per-hub token count. Enforced by LRU-style
/// eviction on insert (round-2 P2 on PR #140). Anonymous
/// requests share ONE key, so this cap only bounds the
/// distinct-VALID-token axis.
const MAX_TRACKED_KEYS: usize = 1024;
/// Sentinel key for requests whose bearer failed
/// [`TokenStore::verify_read_only`] (missing header, malformed,
/// unknown, revoked). Sharing one bucket for all unrecognized
/// bearers means a rotating garbage-bearer attacker can't
/// grow the map with unique entries — round-3 P1 on PR #140.
const UNAUTHENTICATED_KEY: &str = "unauthenticated";
/// Hard cap on in-flight blocking verifications. Prevents
/// unbounded growth of the shared blocking-pool queue when
/// `SQLite` stalls and arrivals exceed completions — round-5
/// P1 on PR #140. Sized to comfortably exceed steady-state
/// under load; if we're saturating this AND `SQLite` is stalling
/// the whole daemon is unhealthy and returning 429 is correct.
const DEFAULT_VERIFY_INFLIGHT: usize = 32;
/// Rejected-request logging is aggregated: the middleware
/// emits at most one `warn!` per this window with the
/// accumulated count for each rejection reason. Prevents
/// log-storming a stdout consumer or the persistent tracing
/// layer under a rejection flood — round-5 P2 on PR #140.
const REJECT_LOG_WINDOW: Duration = Duration::from_secs(1);

/// Full result of the pre-auth verify. `require_token` reads
/// this off request extensions and skips its own SELECT
/// entirely — for BOTH success and failure paths. Round-5 P1
/// on PR #140: pre-fix, only `Ok` was cached, so unknown
/// tokens still forced a second synchronous SELECT downstream
/// (parking tokio workers on the shared `SQLite` mutex under
/// a garbage-bearer flood).
///
/// - `Verified(rec)` — bearer resolved to a live token; downstream
///   should stamp the actor + audit path but skip its own SELECT.
///   The `last_used_ms` bump still needs to happen; downstream
///   offloads it via `spawn_blocking` (round-5 P1 too).
/// - `Denied` — bearer was missing, malformed, unknown, or
///   revoked. Downstream records the anonymous probe and returns
///   401 without re-verifying.
/// - `Internal` — `SQLite` failure during verify (contrasted with
///   `Denied`). Downstream returns 500 without re-verifying.
#[derive(Clone)]
pub(crate) enum PreVerifiedBearer {
    Verified(TokenRecord),
    Denied,
    Internal,
}

/// Per-token leaky bucket. `tokens` is fractional so refill
/// under low load isn't rounded to zero. `last_observed`
/// doubles as the LRU stamp for eviction.
#[derive(Debug)]
struct TokenBucket {
    tokens: f64,
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
    /// Coarse global bucket applied BEFORE the per-token
    /// verification / bucket check. See the module-doc's
    /// "Algorithm" section for the rationale.
    ingress: Mutex<TokenBucket>,
    ingress_capacity: f64,
    ingress_refill_per_second: f64,
    capacity: f64,
    refill_per_second: f64,
    max_keys: usize,
    tokens: Arc<TokenStore>,
    /// Bounds the number of concurrent
    /// `spawn_blocking(verify_read_only)` tasks. Round-5 P1
    /// on PR #140: without this, a spike in arrivals past
    /// steady-state `SQLite` throughput piles up on the shared
    /// blocking-pool queue (disconnected requests don't cancel
    /// `spawn_blocking`). Permit MOVES into the closure so
    /// it's released only when the actual SELECT finishes,
    /// not when the outer future is dropped.
    verify_inflight: Arc<Semaphore>,
    /// Aggregated per-window rejection counters. Emitting one
    /// `warn!` per rejection is itself a `DoS` vector under a
    /// flood — round-5 P2 on PR #140. See [`RejectLogger`].
    ingress_reject_log: RejectLogger,
    per_token_reject_log: RejectLogger,
    verify_saturated_reject_log: RejectLogger,
}

/// Per-reason rejection aggregator. Emits at most one
/// `warn!` per [`REJECT_LOG_WINDOW`] with the accumulated
/// count. Concurrent probes race harmlessly via a single
/// atomic CAS on `window_start_ms`.
#[derive(Debug)]
struct RejectLogger {
    /// Millisecond timestamp of the current window's start
    /// (UNIX epoch). Zero means no window has opened yet;
    /// the first probe seeds it.
    window_start_ms: AtomicU64,
    /// Rejections observed in the current window (reset on
    /// window rollover).
    count: AtomicU64,
    /// Short label included in the emitted `warn!` so the
    /// operator can tell ingress from per-token from
    /// verify-saturated.
    reason: &'static str,
}

impl RejectLogger {
    const fn new(reason: &'static str) -> Self {
        Self {
            window_start_ms: AtomicU64::new(0),
            count: AtomicU64::new(0),
            reason,
        }
    }

    /// Record one rejection. Emits at most one `warn!` per
    /// window with the accumulated count; every rejection
    /// past that is a cheap atomic increment.
    fn record(&self) {
        self.count.fetch_add(1, Ordering::Relaxed);
        let now_ms = now_unix_ms();
        let start = self.window_start_ms.load(Ordering::Relaxed);
        let window_ms = REJECT_LOG_WINDOW.as_millis().try_into().unwrap_or(u64::MAX);
        if start == 0 || now_ms.saturating_sub(start) >= window_ms {
            // Try to claim the window rollover. Only the CAS
            // winner emits the warn — losers drop through and
            // just wait for the next window.
            if self
                .window_start_ms
                .compare_exchange(start, now_ms, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                let count = self.count.swap(0, Ordering::Relaxed);
                if count > 0 {
                    tracing::warn!(
                        reason = self.reason,
                        count,
                        window_secs = REJECT_LOG_WINDOW.as_secs(),
                        "MCP rate limit rejections in the last window",
                    );
                }
            }
        }
    }
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis().try_into().unwrap_or(u64::MAX))
}

impl RateLimiterState {
    /// Build a limiter with the default capacity + refill + map
    /// cap + ingress bucket, wired against `engine.auth_tokens()`.
    pub(super) fn new(tokens: Arc<TokenStore>) -> Self {
        Self::with_all(
            tokens,
            DEFAULT_BUCKET_CAPACITY,
            DEFAULT_TOKENS_PER_SECOND,
            MAX_TRACKED_KEYS,
            DEFAULT_INGRESS_CAPACITY,
            DEFAULT_INGRESS_TOKENS_PER_SECOND,
        )
    }

    /// Build a limiter with custom per-token bucket parameters
    /// but production ingress + map cap. Public for tests that
    /// need to drive the per-token 429 shape without waiting
    /// for 30 requests/second to accumulate.
    pub(super) fn with_capacity_and_refill(
        tokens: Arc<TokenStore>,
        capacity: u32,
        refill_per_second: f64,
    ) -> Self {
        Self::with_all(
            tokens,
            capacity,
            refill_per_second,
            MAX_TRACKED_KEYS,
            DEFAULT_INGRESS_CAPACITY,
            DEFAULT_INGRESS_TOKENS_PER_SECOND,
        )
    }

    /// Fully-parametrized constructor — tests that exercise
    /// the LRU-eviction path OR the ingress bucket need to
    /// override the corresponding cap without spraying real
    /// requests at the mutex.
    pub(super) fn with_all(
        tokens: Arc<TokenStore>,
        capacity: u32,
        refill_per_second: f64,
        max_keys: usize,
        ingress_capacity: u32,
        ingress_refill_per_second: f64,
    ) -> Self {
        assert!(max_keys > 0, "rate limiter map cap must be > 0");
        Self {
            inner: Arc::new(RateLimiterInner {
                buckets: Mutex::new(HashMap::new()),
                ingress: Mutex::new(TokenBucket {
                    tokens: f64::from(ingress_capacity),
                    last_observed: Instant::now(),
                }),
                ingress_capacity: f64::from(ingress_capacity),
                ingress_refill_per_second,
                capacity: f64::from(capacity),
                refill_per_second,
                max_keys,
                tokens,
                verify_inflight: Arc::new(Semaphore::new(DEFAULT_VERIFY_INFLIGHT)),
                ingress_reject_log: RejectLogger::new("ingress_bucket"),
                per_token_reject_log: RejectLogger::new("per_token_bucket"),
                verify_saturated_reject_log: RejectLogger::new("verify_saturated"),
            }),
        }
    }

    /// Attempt to consume one token from the coarse global
    /// ingress bucket. Returns `Err(seconds_until_refill)` when
    /// the bucket is empty — the middleware short-circuits with
    /// a 429 BEFORE any DB work, so a verify-flood attacker
    /// can't push through the shared `SQLite` mutex.
    fn try_consume_ingress(&self) -> Result<(), u64> {
        let now = Instant::now();
        let mut bucket = self
            .inner
            .ingress
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let elapsed_secs = now.duration_since(bucket.last_observed).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed_secs * self.inner.ingress_refill_per_second)
            .min(self.inner.ingress_capacity);
        bucket.last_observed = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            Ok(())
        } else {
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let wait_secs =
                ((1.0 - bucket.tokens) / self.inner.ingress_refill_per_second).ceil() as u64;
            Err(wait_secs.max(1))
        }
    }

    /// Refill the caller's bucket based on wall-clock elapsed
    /// since last observation, then attempt to consume one
    /// token. Returns `Err(seconds_until_refill)` when denied —
    /// the middleware uses that value for `Retry-After`.
    fn try_consume(&self, key: &str) -> Result<(), u64> {
        let now = Instant::now();
        let mut buckets = self
            .inner
            .buckets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        // Ensure room for a NEW entry before we probe: if
        // we'd be inserting and the map is at the hard cap,
        // evict the least-recently-observed entry. Existing
        // keys skip the eviction path entirely — no O(N) sweep
        // on the hot path.
        if !buckets.contains_key(key) && buckets.len() >= self.inner.max_keys {
            evict_one_lru(&mut buckets);
        }

        let bucket = buckets.entry(key.to_string()).or_insert(TokenBucket {
            tokens: self.inner.capacity,
            last_observed: now,
        });

        let elapsed_secs = now.duration_since(bucket.last_observed).as_secs_f64();
        bucket.tokens =
            (bucket.tokens + elapsed_secs * self.inner.refill_per_second).min(self.inner.capacity);
        bucket.last_observed = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            Ok(())
        } else {
            // Suggest a retry after enough time to refill one
            // token. Rounded up to the nearest second; a
            // client polling faster than that just re-hits 429.
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let wait_secs = ((1.0 - bucket.tokens) / self.inner.refill_per_second).ceil() as u64;
            Err(wait_secs.max(1))
        }
    }
}

/// Evict the least-recently-observed bucket. Called only when
/// the map is at [`MAX_TRACKED_KEYS`] AND we're about to
/// insert a NEW key — so the O(N) scan cost is bounded to "at
/// most one scan per new key past the cap." Existing-key
/// probes skip it.
fn evict_one_lru(buckets: &mut HashMap<String, TokenBucket>) {
    let now = Instant::now();
    let idle_victim = buckets
        .iter()
        .find(|(k, b)| {
            // Never evict the shared unauthenticated bucket —
            // it's the whole reason garbage-bearer rotation
            // can't grow the map. Falling back to LRU on it
            // would let an attacker flush a legitimate bucket
            // by racing past the cap.
            *k != UNAUTHENTICATED_KEY && now.duration_since(b.last_observed) >= IDLE_EVICTION_WINDOW
        })
        .map(|(k, _)| k.clone());
    if let Some(k) = idle_victim {
        buckets.remove(&k);
        return;
    }
    if let Some((oldest_key, _)) = buckets
        .iter()
        .filter(|(k, _)| *k != UNAUTHENTICATED_KEY)
        .min_by_key(|(_, b)| b.last_observed)
        .map(|(k, b)| (k.clone(), b.last_observed))
    {
        buckets.remove(&oldest_key);
    }
}

/// Middleware. Three-stage rate limit + verify:
///
/// 1. Coarse global ingress bucket — rejects a verify flood
///    before any DB work (round-4 P1 on PR #140).
/// 2. Bounded in-flight verify semaphore — caps concurrent
///    `spawn_blocking(verify_read_only)` tasks so the shared
///    blocking-pool queue can't grow unboundedly when `SQLite`
///    stalls (round-5 P1 on PR #140). Saturated → immediate
///    429 without submitting the blocking task.
/// 3. Per-resolved-token bucket — fairness across callers.
///
/// All verify outcomes (success / denied / `SQLite` error) are
/// cached on request extensions as [`PreVerifiedBearer`], so
/// `require_token` runs zero synchronous `SQLite` work
/// downstream — round-5 P1 on PR #140.
pub(super) async fn rate_limit(
    State(state): State<RateLimiterState>,
    mut request: Request,
    next: Next,
) -> Response {
    // Stage 1: coarse ingress bucket. Cheap in-memory check.
    if let Err(retry_after) = state.try_consume_ingress() {
        state.inner.ingress_reject_log.record();
        return too_many_requests(retry_after);
    }

    // Reuse the canonical bearer extractor so parsing is
    // consistent with `require_token` (round-3 P1 on PR #140).
    let bearer = extract_bearer(&request).map(str::to_owned);

    // Stage 2: bounded blocking verify. Skip entirely when
    // there's no bearer — nothing to verify.
    let pre_verified: PreVerifiedBearer = match bearer {
        Some(b) => {
            // Try to acquire an in-flight permit. Saturated
            // → immediate 429 with no blocking-task submission
            // (round-5 P1 on PR #140).
            let Ok(permit) = Arc::clone(&state.inner.verify_inflight).try_acquire_owned() else {
                state.inner.verify_saturated_reject_log.record();
                return too_many_requests(1);
            };
            let tokens = Arc::clone(&state.inner.tokens);
            // Permit MOVES into the closure so it's held for
            // the actual SELECT duration, not just the outer
            // future's lifetime. A disconnected outer future
            // doesn't cancel the blocking task; if we dropped
            // the permit at the await point we'd overcount
            // completions and let the queue overrun.
            let verify = tokio::task::spawn_blocking(move || {
                let _guard = permit;
                tokens.verify_read_only(&b)
            })
            .await;
            match verify {
                Ok(Ok(rec)) => PreVerifiedBearer::Verified(rec),
                Ok(Err(crate::state::auth_token::TokenError::Sqlite(err))) => {
                    tracing::error!(
                        %err,
                        "MCP rate-limit verify hit SQLite error; deferring to require_token",
                    );
                    PreVerifiedBearer::Internal
                }
                Ok(Err(_)) => PreVerifiedBearer::Denied,
                Err(join_err) => {
                    tracing::error!(
                        %join_err,
                        "MCP rate-limit verify task panicked; refusing request",
                    );
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Body::from(r#"{"error":"rate-limit verify task failed"}"#),
                    )
                        .into_response();
                }
            }
        }
        None => PreVerifiedBearer::Denied,
    };

    // Stage 3: per-token bucket. Successful verifies get their
    // own token-id bucket; every failure collapses to the
    // shared unauthenticated bucket (round-3 P1 on PR #140).
    let key = match &pre_verified {
        PreVerifiedBearer::Verified(rec) => rec.id.clone(),
        PreVerifiedBearer::Denied | PreVerifiedBearer::Internal => UNAUTHENTICATED_KEY.to_string(),
    };
    match state.try_consume(&key) {
        Ok(()) => {
            request.extensions_mut().insert(pre_verified);
            next.run(request).await
        }
        Err(retry_after) => {
            state.inner.per_token_reject_log.record();
            too_many_requests(retry_after)
        }
    }
}

fn too_many_requests(retry_after: u64) -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        [(header::RETRY_AFTER, retry_after.to_string())],
        Body::from(r#"{"error":"MCP rate limit exceeded; retry shortly"}"#),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::db::Db;

    fn store_with_one_token() -> (Arc<TokenStore>, String, String) {
        let db = Arc::new(Db::open_in_memory().expect("in-memory db"));
        let store = Arc::new(TokenStore::new(db));
        let issued = store.create("test", b"[\"*\"]").expect("mint");
        (store, issued.id, issued.plaintext)
    }

    #[test]
    fn allows_up_to_capacity_then_denies() {
        let (store, _, _) = store_with_one_token();
        let limiter = RateLimiterState::with_capacity_and_refill(store, 3, 0.0);
        for _ in 0..3 {
            limiter.try_consume("k").expect("within capacity");
        }
        let err = limiter.try_consume("k").expect_err("over capacity");
        assert!(err >= 1, "retry-after must be at least 1s; got {err}");
    }

    #[test]
    fn separate_keys_have_independent_buckets() {
        let (store, _, _) = store_with_one_token();
        let limiter = RateLimiterState::with_capacity_and_refill(store, 1, 0.0);
        limiter.try_consume("a").expect("first-a");
        limiter.try_consume("a").expect_err("second-a denied");
        limiter.try_consume("b").expect("first-b");
    }

    #[test]
    fn refill_replenishes_the_bucket_over_time() {
        let (store, _, _) = store_with_one_token();
        let limiter = RateLimiterState::with_capacity_and_refill(store, 1, 100.0);
        limiter.try_consume("k").expect("first drains");
        limiter
            .try_consume("k")
            .expect_err("immediate second denied");
        std::thread::sleep(Duration::from_millis(50));
        limiter.try_consume("k").expect("refill served");
    }

    #[test]
    fn refill_caps_at_capacity() {
        let (store, _, _) = store_with_one_token();
        let limiter = RateLimiterState::with_capacity_and_refill(store, 2, 1000.0);
        limiter.try_consume("k").expect("first");
        std::thread::sleep(Duration::from_millis(50));
        limiter.try_consume("k").expect("post-refill 1");
        limiter.try_consume("k").expect("post-refill 2");
        limiter
            .try_consume("k")
            .expect_err("cap prevents unbounded refill");
    }

    /// Round-2 P2 on PR #140: hard map cap.
    #[test]
    fn map_size_stays_bounded_under_key_pressure() {
        let (store, _, _) = store_with_one_token();
        let limiter = RateLimiterState::with_all(store, 1, 0.0, 3, 1000, 0.0);
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

    /// LRU eviction preserves recent entries (never touches
    /// [`UNAUTHENTICATED_KEY`] even if it's technically oldest).
    #[test]
    fn lru_eviction_preserves_recent_entries() {
        let (store, _, _) = store_with_one_token();
        let limiter = RateLimiterState::with_all(store, 1, 0.0, 3, 1000, 0.0);
        for i in 0..3 {
            let _ = limiter.try_consume(&format!("k-{i}"));
            std::thread::sleep(Duration::from_millis(2));
        }
        let _ = limiter.try_consume("k-3");
        let buckets = limiter.inner.buckets.lock().unwrap();
        assert!(
            !buckets.contains_key("k-0"),
            "oldest key must be evicted at cap; got {:?}",
            buckets.keys().collect::<Vec<_>>(),
        );
        assert!(buckets.contains_key("k-3"));
        assert!(buckets.contains_key("k-2"));
    }

    /// Round-3 P1 on PR #140: garbage-bearer rotation must
    /// NOT grow the bucket map. Every unrecognized bearer
    /// collapses to the shared unauthenticated bucket, so
    /// even 100 unique garbage bearers leave the map with
    /// at most a couple of entries (unauthenticated + any
    /// admitted probes).
    #[test]
    fn rotating_garbage_bearers_share_one_bucket() {
        let (store, _, _) = store_with_one_token();
        // Force feed unrecognized bearers directly via
        // try_consume against the sentinel key — mirrors what
        // the middleware would do after verify fails.
        let limiter = RateLimiterState::with_all(store, 3, 0.0, 3, 1000, 0.0);
        for _ in 0..100 {
            let _ = limiter.try_consume(UNAUTHENTICATED_KEY);
        }
        let buckets = limiter.inner.buckets.lock().unwrap();
        assert_eq!(
            buckets.len(),
            1,
            "unauthenticated requests must share ONE bucket; got {} keys: {:?}",
            buckets.len(),
            buckets.keys().collect::<Vec<_>>(),
        );
    }

    /// Round-3 P1 on PR #140: the LRU evictor must NOT
    /// remove the shared unauthenticated bucket, even under
    /// key pressure. Otherwise an attacker could flush a
    /// legitimate bucket by racing past the cap with fresh
    /// unauthenticated probes.
    #[test]
    fn unauthenticated_bucket_survives_lru_eviction() {
        let (store, _, _) = store_with_one_token();
        let limiter = RateLimiterState::with_all(store, 1, 0.0, 2, 1000, 0.0);
        // Seed the unauth bucket first — oldest.
        let _ = limiter.try_consume(UNAUTHENTICATED_KEY);
        std::thread::sleep(Duration::from_millis(2));
        let _ = limiter.try_consume("real-token");
        std::thread::sleep(Duration::from_millis(2));
        // Push past cap — this should evict `real-token`
        // (the oldest EVICTABLE), not the unauth bucket.
        let _ = limiter.try_consume("another-real");
        let buckets = limiter.inner.buckets.lock().unwrap();
        assert!(
            buckets.contains_key(UNAUTHENTICATED_KEY),
            "unauthenticated bucket must survive LRU; got {:?}",
            buckets.keys().collect::<Vec<_>>(),
        );
    }

    /// Round-4 P1 on PR #140: the ingress bucket is a coarse
    /// global cap that rejects a verify flood BEFORE any DB
    /// work. Two consumes on a capacity-2 ingress bucket
    /// admitted; the third is denied.
    #[test]
    fn ingress_bucket_rate_caps_before_verify() {
        let (store, _, _) = store_with_one_token();
        // Per-token bucket is generous; ingress bucket is
        // capacity 2 with no refill.
        let limiter = RateLimiterState::with_all(store, 1000, 0.0, 1024, 2, 0.0);
        limiter.try_consume_ingress().expect("first ingress admit");
        limiter.try_consume_ingress().expect("second ingress admit");
        let err = limiter
            .try_consume_ingress()
            .expect_err("third ingress must be denied");
        assert!(err >= 1);
    }
}
