//! Phase 14.7b — per-token rate limits on the MCP mount.
//!
//! Sits between the bearer-auth layer and the admission gate:
//!
//! ```text
//! request → require_token → rate_limit → admission_gate → mcp_service
//! ```
//!
//! Per-token because the audit ledger + scope model are already
//! keyed on the token's id (`Actor::id()`), and a household hub
//! wants fair share across operator agents rather than a single
//! bucket for the whole endpoint. The admission gate + pending-
//! body semaphore still bound aggregate memory; this layer
//! bounds *per-caller* request rate so one runaway agent can't
//! monopolize the concurrent-request slots.
//!
//! # Algorithm
//!
//! Simple leaky-bucket per actor id:
//!
//! - **Capacity** = [`DEFAULT_BUCKET_CAPACITY`] tokens. Bursts
//!   up to this many requests are served without throttling; a
//!   short spike from a well-behaved client (fanning out a
//!   `resources/list` + a per-resource `resources/read` pass)
//!   still fits.
//! - **Refill rate** = [`DEFAULT_TOKENS_PER_SECOND`]. Sustained
//!   throughput past that latches into 429s.
//! - **Eviction**: opportunistic — when the bucket map grows
//!   past [`MAX_TRACKED_ACTORS`], entries idle for more than
//!   [`IDLE_EVICTION_WINDOW`] are removed. Prevents unbounded
//!   growth from a stream of one-shot token ids without adding
//!   a background sweeper task.
//!
//! # Wire shape
//!
//! Exceeded → plain HTTP `429 Too Many Requests` with a
//! `Retry-After: <seconds>` header. Mirrors the admission
//! gate's plain-HTTP 503 shape: the JSON-RPC session hasn't
//! necessarily started yet, so a full JSON-RPC error envelope
//! would be misleading. Consistent with the rest of the
//! MCP mount's pre-service response types.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::auth::Actor;

/// Default burst capacity per token. Two seconds worth of
/// sustained throughput at [`DEFAULT_TOKENS_PER_SECOND`], so
/// well-behaved clients that fan out a handful of parallel
/// reads still see zero throttling.
pub(super) const DEFAULT_BUCKET_CAPACITY: u32 = 60;
/// Default refill: 30 requests/second/token sustained. Above
/// what any agentic-loop client should need against a household
/// hub, well below what a runaway loop can push.
pub(super) const DEFAULT_TOKENS_PER_SECOND: f64 = 30.0;
/// Idle threshold past which a bucket is eligible for eviction.
/// 5 minutes matches `LocalSessionManager`'s idle keep-alive so
/// a token that ends one session can start another without
/// immediately re-inheriting a full bucket (fine — capacity
/// isn't security-critical here, just fairness).
const IDLE_EVICTION_WINDOW: Duration = Duration::from_mins(5);
/// When the bucket map grows past this many entries, opportunistic
/// eviction runs on the next consume. Chosen well above any
/// realistic per-hub token count so the sweep is rare.
const MAX_TRACKED_ACTORS: usize = 1024;

/// Per-token leaky bucket. `tokens` is fractional so refill
/// under low load isn't rounded to zero.
#[derive(Debug)]
struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
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
}

impl RateLimiterState {
    /// Build a limiter with the default capacity + refill.
    pub(super) fn new() -> Self {
        Self::with_capacity_and_refill(
            DEFAULT_BUCKET_CAPACITY,
            DEFAULT_TOKENS_PER_SECOND,
        )
    }

    /// Build a limiter with custom parameters — public for tests
    /// that need to drive the 429 shape without waiting for 30
    /// requests/second to accumulate.
    pub(super) fn with_capacity_and_refill(capacity: u32, refill_per_second: f64) -> Self {
        Self {
            inner: Arc::new(RateLimiterInner {
                buckets: Mutex::new(HashMap::new()),
                capacity: f64::from(capacity),
                refill_per_second,
            }),
        }
    }

    /// Refill the caller's bucket based on wall-clock elapsed
    /// since last observation, then attempt to consume one
    /// token. Returns `Some(seconds_until_refill)` when
    /// denied — the middleware uses that for `Retry-After`.
    fn try_consume(&self, actor_id: &str) -> Result<(), u64> {
        let now = Instant::now();
        let mut buckets = self
            .inner
            .buckets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        // Opportunistic prune. Only walks when the map has
        // grown past `MAX_TRACKED_ACTORS`; the common path is
        // a bounded hash lookup + a couple of writes.
        if buckets.len() > MAX_TRACKED_ACTORS {
            buckets.retain(|_, b| now.duration_since(b.last_refill) < IDLE_EVICTION_WINDOW);
        }

        let bucket = buckets.entry(actor_id.to_string()).or_insert(TokenBucket {
            tokens: self.inner.capacity,
            last_refill: now,
        });

        // Refill by elapsed_seconds * rate, capped at capacity.
        let elapsed_secs = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed_secs * self.inner.refill_per_second)
            .min(self.inner.capacity);
        bucket.last_refill = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            Ok(())
        } else {
            // Suggest a retry after enough time to refill one
            // token. Rounded up to the nearest second to keep
            // the header sane; a client polling faster than
            // that just re-hits 429.
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let wait_secs = ((1.0 - bucket.tokens) / self.inner.refill_per_second).ceil() as u64;
            Err(wait_secs.max(1))
        }
    }
}

/// Middleware. Consumes one token per request per actor id.
/// Runs after [`crate::api::auth::require_token`] so the
/// `Actor` is already on the request extensions; runs before
/// the admission gate so a rate-limited request doesn't
/// consume a pending-body permit.
pub(super) async fn rate_limit(
    State(state): State<RateLimiterState>,
    request: Request,
    next: Next,
) -> Response {
    let actor_id = request
        .extensions()
        .get::<Actor>()
        .map(|a| a.id().to_string());
    // No actor → auth layer skipped us somehow. Let the
    // admission gate + service downstream decide the shape;
    // don't fail closed here because the audit ledger already
    // synthesizes an anonymous actor for that path (see
    // `handler::resolve_actor`).
    let Some(actor_id) = actor_id else {
        return next.run(request).await;
    };

    match state.try_consume(&actor_id) {
        Ok(()) => next.run(request).await,
        Err(retry_after) => {
            tracing::warn!(
                actor_id = %actor_id,
                retry_after,
                "MCP rate limit exceeded — replying 429 Too Many Requests",
            );
            (
                StatusCode::TOO_MANY_REQUESTS,
                [(header::RETRY_AFTER, retry_after.to_string())],
                Body::from(
                    r#"{"error":"MCP per-token rate limit exceeded; retry shortly"}"#,
                ),
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
            limiter.try_consume("token-a").expect("within capacity");
        }
        let err = limiter.try_consume("token-a").expect_err("over capacity");
        assert!(err >= 1, "retry-after must be at least 1s; got {err}");
    }

    #[test]
    fn separate_actors_have_independent_buckets() {
        let limiter = RateLimiterState::with_capacity_and_refill(1, 0.0);
        limiter.try_consume("token-a").expect("first-a");
        limiter.try_consume("token-a").expect_err("second-a denied");
        // token-b has its own bucket, still full.
        limiter.try_consume("token-b").expect("first-b");
    }

    #[test]
    fn refill_replenishes_the_bucket_over_time() {
        let limiter = RateLimiterState::with_capacity_and_refill(1, 100.0);
        limiter.try_consume("token-a").expect("first drains");
        limiter.try_consume("token-a").expect_err("immediate second denied");
        // Sleep well past 10 ms; refill at 100/sec = 1 token / 10 ms.
        std::thread::sleep(Duration::from_millis(50));
        limiter.try_consume("token-a").expect("refill served");
    }

    #[test]
    fn refill_caps_at_capacity() {
        let limiter = RateLimiterState::with_capacity_and_refill(2, 1000.0);
        // Prime the bucket entry.
        limiter.try_consume("token-a").expect("first");
        // Sleep long enough to refill many times capacity.
        std::thread::sleep(Duration::from_millis(50));
        // Only two tokens should be available; the third denies.
        limiter.try_consume("token-a").expect("post-refill 1");
        limiter.try_consume("token-a").expect("post-refill 2");
        limiter
            .try_consume("token-a")
            .expect_err("cap prevents unbounded refill");
    }
}
