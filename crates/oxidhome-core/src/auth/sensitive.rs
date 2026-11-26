//! Obligations of an allowed sensitive action (H6 slice 2): the
//! per-principal, per-category rate limit and the `warn` audit row.
//!
//! [`crate::auth::authorize()`] stays a pure decision. A transport that
//! acts on an allowed decision whose [`Obligations`] name sensitive
//! categories calls [`SensitiveGuard::discharge`] (or the async
//! [`SensitiveGuard::discharge_blocking`] wrapper) *before* acting:
//!
//! 1. **Rate limit.** One token per sensitive category from the
//!    principal's bucket for that category
//!    ([`RateLimit::for_category`]). All categories are checked before
//!    any is charged. A miss refuses the action
//!    ([`ObligationError::RateLimited`]); the transport answers 429 /
//!    `resource_exhausted` / an MCP error. The owner is not rate
//!    limited (the decision carries no `rate_limit`).
//! 2. **Audit.** One completed row at `level = warn`: `path`
//!    `authz.<action>` plus the target, `decision = allow`,
//!    `required_scope` the categories (`sensitive:lock`, or
//!    `owner:lock` when the owner's standing grant decided), and the
//!    invocation's `call_id`, so `GET /api/v1/audit?call_id=…` joins it
//!    to the request's own row. Fail-closed: if the row can't be
//!    written the action doesn't run.
//!
//! A device command splits the two: [`SensitiveGuard::reserve`] takes
//! the rate-limit charge at admission (so a refusal is still an
//! immediate 429) and returns a [`SensitiveCharge`] that rides with the
//! command; the supervisor [commits](SensitiveCharge::commit) it, writing
//! the `warn` row, only once the command has won `queued → started` and
//! passed re-authorization, before the plugin is entered. A command
//! withdrawn, timed out or refused before that drops the charge, which
//! refunds it and leaves no `warn` row.
//!
//! Byte releases inside reads (camera `bytes-val` in state, events and
//! command results) are discharged once per response or stream, not
//! per value (`api::bytes::BytesGate`).

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

use super::authorize::{Action, Decision, Obligations, RateLimit, Reason};
use super::category::{SensitiveCategory, SensitiveSet};
use super::invocation::InvocationContext;
use crate::rate_bucket::Bucket;
use crate::state::audit_log::AUDIT_LEVEL_WARN;
use crate::state::{AuditEntry, AuditLog, AuditLogError};

/// Audit `method` of the `warn` row a sensitive allow writes.
pub const AUDIT_METHOD_AUTHZ: &str = "AUTHZ";

/// Distinct (principal, category) buckets kept. Tokens are few; when
/// the map is full the least recently used bucket is dropped, which
/// only ever gives that principal a fresh allowance on a bucket it
/// hasn't touched for longest.
const MAX_BUCKETS: usize = 4096;

/// `Retry-After` when the bucket table is full of mid-window buckets.
const TABLE_FULL_RETRY_SECS: u64 = 60;

/// Why the obligations of an allowed sensitive action weren't met.
#[derive(Debug, thiserror::Error)]
pub enum ObligationError {
    /// The principal has used up its allowance for `category`.
    #[error("rate limit for sensitive category `{category}` reached; retry in {retry_after_secs}s")]
    RateLimited {
        /// The category whose bucket is empty.
        category: SensitiveCategory,
        /// Seconds until the next action is allowed.
        retry_after_secs: u64,
    },
    /// The `warn` audit row couldn't be written; the action must not
    /// run.
    #[error("recording the sensitive-action audit row failed: {0}")]
    Audit(#[from] AuditLogError),
    /// The blocking task running the obligations failed.
    #[error("sensitive-action obligations task failed: {0}")]
    Join(String),
}

/// Rate-limit state and audit sink for sensitive allows. One per
/// [`Engine`](crate::Engine), shared by every transport.
pub struct SensitiveGuard {
    audit: Arc<AuditLog>,
    buckets: Mutex<HashMap<(String, SensitiveCategory), Bucket>>,
    /// The engine clock (the audit log's), which the buckets refill on
    /// (see [`crate::clock`]).
    clock: crate::clock::Clock,
}

impl SensitiveGuard {
    /// A guard writing to `audit`.
    #[must_use]
    pub fn new(audit: Arc<AuditLog>) -> Self {
        Self {
            clock: audit.clock().clone(),
            audit,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Charge `principal`'s buckets for every category in `categories`
    /// at `limit`-per-category. All-or-nothing.
    ///
    /// # Errors
    ///
    /// [`ObligationError::RateLimited`] naming the first empty bucket.
    pub(crate) fn charge(
        &self,
        principal: &str,
        categories: SensitiveSet,
    ) -> Result<(), ObligationError> {
        let now = self.clock.std_instant();
        let mut buckets = self.buckets.lock().unwrap_or_else(PoisonError::into_inner);
        for category in categories.iter() {
            let key = (principal.to_owned(), category);
            if !buckets.contains_key(&key)
                && buckets.len() >= MAX_BUCKETS
                && !evict_refilled(&mut buckets, principal, now)
            {
                // Every tracked bucket is still mid-window: dropping
                // one would hand its principal a fresh allowance, so
                // refuse the newcomer instead.
                return Err(ObligationError::RateLimited {
                    category,
                    retry_after_secs: TABLE_FULL_RETRY_SECS,
                });
            }
            let (capacity, refill) = rate(RateLimit::for_category(category));
            let bucket = buckets
                .entry(key)
                .or_insert_with(|| Bucket::full(capacity, now));
            bucket.refill(now, capacity, refill);
            if bucket.tokens < 1.0 {
                return Err(ObligationError::RateLimited {
                    category,
                    retry_after_secs: bucket.wait_secs(refill),
                });
            }
        }
        for category in categories.iter() {
            let b = buckets
                .get_mut(&(principal.to_owned(), category))
                .expect("checked above; eviction spares the charging principal");
            b.tokens -= 1.0;
        }
        Ok(())
    }

    /// Give back one charge per category in `categories` (capped at
    /// capacity): a read that charged and then wasn't delivered.
    pub(crate) fn refund(&self, principal: &str, categories: SensitiveSet) {
        let mut buckets = self.buckets.lock().unwrap_or_else(PoisonError::into_inner);
        for category in categories.iter() {
            let (capacity, _) = rate(RateLimit::for_category(category));
            if let Some(b) = buckets.get_mut(&(principal.to_owned(), category)) {
                b.tokens = (b.tokens + 1.0).min(capacity);
            }
        }
    }

    /// Meet `decision`'s obligations for `action` on `target` (a
    /// device id, or `<instance>/<name>` for a blob): rate limit, then
    /// the `warn` row. A no-op for a decision without sensitive
    /// categories. Blocking (one `SQLite` insert).
    ///
    /// # Errors
    ///
    /// See [`ObligationError`].
    pub fn discharge(
        &self,
        ctx: &InvocationContext,
        action: Action,
        target: &str,
        decision: &Decision,
    ) -> Result<(), ObligationError> {
        let Obligations {
            sensitive,
            rate_limit,
            ..
        } = decision.obligations;
        if !decision.allow || sensitive.is_empty() {
            return Ok(());
        }
        let principal = ctx.root().audit_token_id();
        if rate_limit.is_some() {
            self.charge(principal, sensitive)?;
        }
        if let Err(err) = self.record(ctx, action, target, decision) {
            // The action is refused; don't keep its charge.
            if rate_limit.is_some() {
                self.refund(principal, sensitive);
            }
            return Err(err.into());
        }
        Ok(())
    }

    /// [`Self::discharge`] on the blocking pool, for async callers.
    ///
    /// # Errors
    ///
    /// See [`ObligationError`].
    pub async fn discharge_blocking(
        self: &Arc<Self>,
        ctx: &InvocationContext,
        action: Action,
        target: &str,
        decision: &Decision,
    ) -> Result<(), ObligationError> {
        if !decision.allow || decision.obligations.sensitive.is_empty() {
            return Ok(());
        }
        let this = Arc::clone(self);
        let ctx = ctx.clone();
        let target = target.to_owned();
        let decision = decision.clone();
        tokio::task::spawn_blocking(move || this.discharge(&ctx, action, &target, &decision))
            .await
            .map_err(|e| ObligationError::Join(e.to_string()))?
    }

    /// Take the rate-limit charge for an allowed sensitive `action` on
    /// `target` without writing its `warn` row: the row is written by
    /// [`SensitiveCharge::commit`], when the action actually runs.
    /// Dropping the returned charge uncommitted refunds it. `None` for
    /// a decision without sensitive categories.
    ///
    /// # Errors
    ///
    /// [`ObligationError::RateLimited`].
    pub fn reserve(
        self: &Arc<Self>,
        ctx: &InvocationContext,
        action: Action,
        target: &str,
        decision: &Decision,
    ) -> Result<Option<SensitiveCharge>, ObligationError> {
        let Obligations {
            sensitive,
            rate_limit,
            ..
        } = decision.obligations;
        if !decision.allow || sensitive.is_empty() {
            return Ok(None);
        }
        let charged = rate_limit.is_some();
        if charged {
            self.charge(ctx.root().audit_token_id(), sensitive)?;
        }
        Ok(Some(SensitiveCharge(Box::new(Pending {
            guard: Arc::clone(self),
            ctx: ctx.clone(),
            action,
            target: target.to_owned(),
            decision: decision.clone(),
            charged,
            committed: false,
        }))))
    }

    /// Write the `warn` row for an allowed sensitive `action`.
    ///
    /// # Errors
    ///
    /// Forwards the audit write's error.
    pub fn record(
        &self,
        ctx: &InvocationContext,
        action: Action,
        target: &str,
        decision: &Decision,
    ) -> Result<u64, AuditLogError> {
        let root = ctx.root();
        let label = grant_label(decision);
        tracing::warn!(
            target: "auth.sensitive",
            token_id = root.audit_token_id(),
            transport = root.transport().as_str(),
            call_id = ctx.call_id(),
            action = action.as_str(),
            target = super::invocation::audit_cap(target),
            grant = %label,
            "sensitive action allowed",
        );
        let entry = AuditEntry {
            id: 0,
            intent_ms: 0,
            finalized_ms: None,
            token_id: root.audit_token_id().to_owned(),
            actor_kind: root.kind().as_str().to_owned(),
            method: AUDIT_METHOD_AUTHZ.to_owned(),
            path: format!(
                "authz.{}:{}",
                action.as_str(),
                super::invocation::audit_cap(target)
            ),
            status: 200,
            decision: "allow".to_owned(),
            required_scope: Some(label),
            execution_outcome: None,
            domain_error: None,
            credential_fp: None,
            call_id: Some(ctx.call_id().to_owned()),
            invocation: Some(ctx.audit_json()),
            command_id: None,
            command_outcome: None,
            level: Some(AUDIT_LEVEL_WARN.to_owned()),
            caused_by: None,
        };
        // A command's row commits durably before the command runs:
        // a lock that moved must not lose its record to a power cut.
        if action == Action::DeviceCommand {
            self.audit.record_completed_durable(&entry)
        } else {
            self.audit.record_completed(&entry)
        }
    }
}

/// A rate-limit charge taken by [`SensitiveGuard::reserve`] for an
/// action that hasn't run yet. [`Self::commit`] writes the `warn` row
/// when it runs; dropping it uncommitted (the action was withdrawn,
/// timed out or refused first) refunds the charge.
pub struct SensitiveCharge(Box<Pending>);

/// The charge's state; boxed, as it rides in every queued command.
struct Pending {
    guard: Arc<SensitiveGuard>,
    ctx: InvocationContext,
    action: Action,
    target: String,
    decision: Decision,
    charged: bool,
    committed: bool,
}

impl std::fmt::Debug for SensitiveCharge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SensitiveCharge")
            .field("action", &self.0.action.as_str())
            .field("target", &self.0.target)
            .field("categories", &self.categories())
            .field("charged", &self.0.charged)
            .finish_non_exhaustive()
    }
}

impl SensitiveCharge {
    /// The sensitive categories the decision covered.
    #[must_use]
    pub fn categories(&self) -> SensitiveSet {
        self.0.decision.obligations.sensitive
    }

    /// The action is about to run: write its `warn` row (durably, on
    /// the blocking pool). On failure the charge is refunded and the
    /// action must not run.
    ///
    /// # Errors
    ///
    /// [`ObligationError::Audit`]; [`ObligationError::Join`].
    pub async fn commit(self) -> Result<(), ObligationError> {
        let mut pending = self.0;
        tokio::task::spawn_blocking(move || {
            let written = pending.guard.record(
                &pending.ctx,
                pending.action,
                &pending.target,
                &pending.decision,
            );
            pending.settle(written.is_ok());
            written.map(drop).map_err(ObligationError::from)
        })
        .await
        .map_err(|e| ObligationError::Join(e.to_string()))?
    }
}

impl Pending {
    /// Keep the charge (the row is written) or let `Drop` refund it.
    fn settle(&mut self, committed: bool) {
        self.committed = committed;
    }
}

impl Drop for Pending {
    fn drop(&mut self) {
        if self.charged && !self.committed {
            self.guard.refund(
                self.ctx.root().audit_token_id(),
                self.decision.obligations.sensitive,
            );
        }
    }
}

/// `sensitive:<cats>` or `owner:<cats>`, the decision's determining
/// grant as recorded in the `warn` row's `required_scope`.
fn grant_label(decision: &Decision) -> String {
    let (prefix, categories) = match decision.reason {
        Reason::Sensitive {
            categories, owner, ..
        } => (if owner { "owner" } else { "sensitive" }, categories),
        _ => ("sensitive", decision.obligations.sensitive),
    };
    format!("{prefix}:{}", categories.to_csv())
}

fn rate(limit: RateLimit) -> (f64, f64) {
    let capacity = f64::from(limit.max);
    (capacity, capacity / limit.per.as_secs_f64())
}

/// Drop the least recently used bucket, of another principal, that has
/// refilled completely (indistinguishable from a fresh one, so
/// forgetting it resets nothing). `false` when there is none.
fn evict_refilled(
    buckets: &mut HashMap<(String, SensitiveCategory), Bucket>,
    principal: &str,
    now: Instant,
) -> bool {
    let key = buckets
        .iter()
        // Never the charging principal's own buckets: a multi-category
        // charge must not evict the bucket it just checked.
        .filter(|((owner, _), _)| owner != principal)
        .filter(|((_, category), b)| {
            let (capacity, refill) = rate(RateLimit::for_category(*category));
            let mut b = **b;
            b.refill(now, capacity, refill);
            b.tokens >= capacity
        })
        // The key breaks ties (a frozen virtual clock stamps every
        // bucket alike), so eviction never depends on hash order.
        .min_by(|(ka, a), (kb, b)| {
            a.last_observed
                .cmp(&b.last_observed)
                .then_with(|| ka.cmp(kb))
        })
        .map(|(k, _)| k.clone());
    key.is_some_and(|k| buckets.remove(&k).is_some())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{Actor, ActorKind, DeviceClass, Principal, Resource, Transport, authorize};
    use crate::auth::{DeviceCategory, SensitiveGrant, TokenPolicy};
    use crate::state::{AuditQuery, Db};

    /// A full table of mid-window buckets refuses a newcomer rather
    /// than forgetting (and so refilling) someone's spent allowance.
    #[test]
    fn a_full_table_never_resets_a_spent_bucket() {
        let (g, _) = guard();
        let lock: SensitiveSet = [SensitiveCategory::Lock].into_iter().collect();
        for i in 0..MAX_BUCKETS {
            g.charge(&format!("p{i}"), lock).expect("room");
        }
        assert!(matches!(
            g.charge("newcomer", lock),
            Err(ObligationError::RateLimited { .. })
        ));
        // Known principals keep their own buckets.
        g.charge("p0", lock).expect("p0 still has allowance");
    }

    /// With one free slot, a two-category charge can't evict the
    /// bucket it just made for its first category.
    #[test]
    fn a_multi_category_charge_keeps_its_own_buckets() {
        let (g, _) = guard();
        let lock: SensitiveSet = [SensitiveCategory::Lock].into_iter().collect();
        for i in 0..MAX_BUCKETS - 1 {
            g.charge(&format!("p{i}"), lock).expect("room");
        }
        let both: SensitiveSet = [SensitiveCategory::Lock, SensitiveCategory::Opener]
            .into_iter()
            .collect();
        assert!(matches!(
            g.charge("newcomer", both),
            Err(ObligationError::RateLimited { .. })
        ));
    }

    #[test]
    fn buckets_refill_on_the_virtual_clock() {
        let v = crate::clock::VirtualClock::new();
        let audit = Arc::new(
            AuditLog::new(Arc::new(Db::open_in_memory().expect("db"))).with_clock(v.clone().into()),
        );
        let g = SensitiveGuard::new(audit);
        let lock: SensitiveSet = [SensitiveCategory::Lock].into_iter().collect();
        for _ in 0..10 {
            g.charge("p", lock).expect("allowance");
        }
        // Frozen time refills nothing; one virtual minute is one charge.
        assert!(g.charge("p", lock).is_err());
        v.advance(std::time::Duration::from_secs(60));
        g.charge("p", lock).expect("refilled");
        assert!(g.charge("p", lock).is_err());
    }

    /// Refilled buckets that all share one frozen `last_observed`
    /// are evicted in key order, not hash order.
    #[test]
    fn eviction_ties_break_by_key() {
        let v = crate::clock::VirtualClock::new();
        let audit = Arc::new(
            AuditLog::new(Arc::new(Db::open_in_memory().expect("db"))).with_clock(v.clone().into()),
        );
        let g = SensitiveGuard::new(audit);
        let lock: SensitiveSet = [SensitiveCategory::Lock].into_iter().collect();
        for i in 0..MAX_BUCKETS {
            g.charge(&format!("p{i}"), lock).expect("room");
        }
        v.advance(std::time::Duration::from_secs(60));
        g.charge("newcomer", lock)
            .expect("a refilled bucket is evicted");
        let buckets = g.buckets.lock().unwrap_or_else(PoisonError::into_inner);
        assert!(!buckets.contains_key(&("p0".to_owned(), SensitiveCategory::Lock)));
        assert!(buckets.contains_key(&("p1".to_owned(), SensitiveCategory::Lock)));
    }

    fn guard() -> (SensitiveGuard, Arc<AuditLog>) {
        let audit = Arc::new(AuditLog::new(Arc::new(Db::open_in_memory().expect("db"))));
        (SensitiveGuard::new(Arc::clone(&audit)), audit)
    }

    fn lock_token() -> InvocationContext {
        let actor = Actor::from_token_policy(
            "tok-lock",
            TokenPolicy {
                scopes: vec!["devices:command".into()],
                sensitive: vec![SensitiveGrant::all(SensitiveCategory::Lock)],
                ..TokenPolicy::default()
            },
            false,
        );
        InvocationContext::external(Principal::token(ActorKind::Api, &actor, Transport::Rest))
    }

    #[test]
    fn rate_limit_refuses_past_the_allowance_per_category() {
        let (guard, _) = guard();
        let lock: SensitiveSet = [SensitiveCategory::Lock].into_iter().collect();
        let max = RateLimit::for_category(SensitiveCategory::Lock).max;
        for _ in 0..max {
            guard.charge("tok", lock).expect("within the allowance");
        }
        match guard.charge("tok", lock) {
            Err(ObligationError::RateLimited {
                category,
                retry_after_secs,
            }) => {
                assert_eq!(category, SensitiveCategory::Lock);
                assert!(retry_after_secs >= 1);
            }
            other => panic!("expected rate limit, got {other:?}"),
        }
        // Another principal and another category have their own buckets.
        guard.charge("tok-2", lock).expect("other principal");
        let opener: SensitiveSet = [SensitiveCategory::Opener].into_iter().collect();
        guard.charge("tok", opener).expect("other category");
        // All-or-nothing: a lock+opener charge fails on lock and
        // leaves the opener bucket untouched.
        let both = lock.union(opener);
        assert!(guard.charge("tok", both).is_err());
        let opener_max = RateLimit::for_category(SensitiveCategory::Opener).max;
        for _ in 1..opener_max {
            guard
                .charge("tok", opener)
                .expect("opener bucket not charged by the failed call");
        }
    }

    #[test]
    fn discharge_writes_a_warn_row_linked_by_call_id() {
        let (guard, audit) = guard();
        let ctx = lock_token();
        let resource = Resource::device(
            "dev-0000000000000001",
            DeviceClass::of(DeviceCategory::Lock),
        );
        let decision = authorize(&ctx, Action::DeviceCommand, &resource);
        assert!(decision.allow);
        guard
            .discharge(
                &ctx,
                Action::DeviceCommand,
                "dev-0000000000000001",
                &decision,
            )
            .expect("discharged");
        let rows = audit
            .query(
                &AuditQuery {
                    level: Some("warn".into()),
                    ..AuditQuery::default()
                },
                10,
            )
            .expect("query");
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row.token_id, "tok-lock");
        assert_eq!(row.method, AUDIT_METHOD_AUTHZ);
        assert_eq!(row.path, "authz.device.command:dev-0000000000000001");
        assert_eq!(row.decision, "allow");
        assert_eq!(row.required_scope.as_deref(), Some("sensitive:lock"));
        assert_eq!(row.call_id.as_deref(), Some(ctx.call_id()));
        assert_eq!(row.level.as_deref(), Some("warn"));
    }

    /// A reserved charge writes its row only on commit; dropped
    /// uncommitted it is refunded and leaves no row.
    #[tokio::test]
    async fn a_reserved_charge_is_refunded_unless_committed() {
        let (guard, audit) = guard();
        let guard = Arc::new(guard);
        let ctx = lock_token();
        let lock = Resource::device(
            "dev-a1b2c3d4e5f60718",
            DeviceClass::of(DeviceCategory::Lock),
        );
        let decision = authorize(&ctx, Action::DeviceCommand, &lock);
        assert!(decision.allow);
        let warn_rows = || {
            audit
                .query(&AuditQuery::default(), 100)
                .unwrap()
                .into_iter()
                .filter(|r| r.method == AUDIT_METHOD_AUTHZ)
                .count()
        };
        // Far more withdrawn commands than the allowance: none count.
        for _ in 0..50 {
            let charge = guard
                .reserve(&ctx, Action::DeviceCommand, "dev-a1", &decision)
                .unwrap()
                .expect("sensitive");
            assert_eq!(charge.categories(), decision.obligations.sensitive);
            drop(charge);
        }
        assert_eq!(warn_rows(), 0);
        for _ in 0..10 {
            guard
                .reserve(&ctx, Action::DeviceCommand, "dev-a1", &decision)
                .unwrap()
                .unwrap()
                .commit()
                .await
                .unwrap();
        }
        assert_eq!(warn_rows(), 10);
        assert!(matches!(
            guard.reserve(&ctx, Action::DeviceCommand, "dev-a1", &decision),
            Err(ObligationError::RateLimited { .. })
        ));
        // A light needs nothing.
        let light = Resource::device(
            "dev-a1b2c3d4e5f60718",
            DeviceClass::of(DeviceCategory::Light),
        );
        let decision = authorize(&ctx, Action::DeviceCommand, &light);
        assert!(
            guard
                .reserve(&ctx, Action::DeviceCommand, "dev-a1", &decision)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn non_sensitive_and_denied_decisions_write_nothing() {
        let (guard, audit) = guard();
        let ctx = lock_token();
        let light = Resource::device(
            "dev-0000000000000002",
            DeviceClass::of(DeviceCategory::Light),
        );
        let d = authorize(&ctx, Action::DeviceCommand, &light);
        guard
            .discharge(&ctx, Action::DeviceCommand, "x", &d)
            .unwrap();
        let alarm = Resource::device(
            "dev-0000000000000003",
            DeviceClass::of(DeviceCategory::Alarm),
        );
        let d = authorize(&ctx, Action::DeviceCommand, &alarm);
        assert!(!d.allow);
        guard
            .discharge(&ctx, Action::DeviceCommand, "x", &d)
            .unwrap();
        assert_eq!(audit.count().unwrap(), 0);
    }
}
