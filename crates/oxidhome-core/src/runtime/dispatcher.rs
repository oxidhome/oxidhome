//! Cross-plugin service dispatch — Phase 7c.
//!
//! `call_service` is the host-side entry point for the WIT
//! `host-services::call-service` import. It resolves the target
//! service to its owning instance, rejects cycles at *instance*
//! granularity, races the owning instance's `execute-service-command`
//! against a deadline, and returns the result.
//!
//! ## Recursion-stack design (cross-task)
//!
//! Each supervisor task scopes the [`InvocationContext`] of the wasm it
//! is currently driving in a `tokio::task_local`
//! (`crate::auth::invocation::CURRENT`). The context's delegation
//! chain is the chain of in-flight `call-service` invocations *that led
//! to that wasm* (H6 folded the former `CALL_STACK` into it, so the
//! root principal, call id and deadline travel with the same value).
//! The dispatcher:
//!
//! 1. Resolves `target_service` → `target_instance` via the engine's
//!    [`ServiceRegistry`].
//! 2. Reads the *parent* chain from the current context (unset on
//!    host-origin calls — treated as empty) and runs the cycle check:
//!    **reject if `target_instance` would dispatch to a supervisor
//!    that is already parked awaiting a reply.** A supervisor is
//!    parked exactly while it is the `caller_instance` in some
//!    in-flight frame on the chain — that's the set we look up
//!    against, plus the current call's own caller (we're about to
//!    park them too). This is what catches both A→A self-calls
//!    (empty chain, caller == target) and A→B→A cycles (B's wasm
//!    calling back into A — A is `caller_instance` of the parent
//!    frame).
//! 3. Looks up the target's [`InstanceHandle`](crate::InstanceHandle)
//!    via `instances`; refuses with `Unavailable` if the owner isn't
//!    running.
//! 4. Acquires a [`crate::state::CallGuard`] (refcount on the target's
//!    `active_calls` map) so `remove-service` refuses while the call
//!    is in flight. The guard travels in the `ExecuteService`
//!    message and is dropped by the callee's supervisor when the
//!    wasm call actually finishes — *not* on the caller's wait
//!    future — so a dispatcher-side timeout can't release the
//!    refcount while the supervisor is still about to run the
//!    handler.
//! 5. Derives the callee context (`parent.delegate(hop)`, i.e. the
//!    parent chain plus this hop) and hands it through
//!    `ControlCommand::ExecuteService` to the owner's supervisor. The
//!    owner's supervisor **scopes that context on its own task** before
//!    invoking
//!    `instance.execute_service_command(...)`, so any nested
//!    `host::call_service` from inside the callee's wasm reads the
//!    full chain and the cycle check works across the task hop.
//! 6. Races the reply against `DISPATCH_TIMEOUT` (clamped to the
//!    invocation's remaining deadline) and returns the
//!    result. The guard is owned by the supervisor's match arm at
//!    this point and drops there when the wasm call returns (or when
//!    the message is dropped without being processed — e.g. on
//!    channel close).
//!
//! **Instance granularity, not service**: same-instance peer services
//! (e.g. two scripts inside a scripting plugin) are not supported by
//! `host-services::call-service` — dispatching to a supervisor
//! already parked on the same call chain is deadlock-by-construction.
//! Plugins colocating services in one instance dispatch between them
//! in plugin-local code. H10 upgraded the caller==target case from a
//! generic "recursion detected" to a documented `same-instance
//! dispatch is not supported` error, distinct from the multi-hop
//! A→B→…→A `cycle detected` message.
//!
//! **Caller-side capability gate (H10)**: before routing, the
//! dispatcher checks the target service's
//! `(owner_plugin_id, owner_instance, local_id)`, the actual
//! caller instance-id, and the requested command name against the
//! caller's structured `[capabilities] consumes_services` grants.
//! The check runs **twice** (H10 round-4): once against the
//! caller's manifest-declared *requested* list, once against the
//! operator's *granted* list from
//! `plugin_installation.granted_capabilities_json`. Both lists
//! must have at least one matching selector; a call is authorized
//! iff that's true. Semantically equivalent to requested ∩ granted
//! but with no materialized cross-product (the pre-fix
//! materialization was O(N²) in narrowed output and O(N²) again in
//! dedup work; this shape is O(|requested|+|granted|) per call,
//! and both lists are bounded by manifest validation caps).
//!
//! The check keys off the service's immutable `local-id` so a
//! callee that renames its service via `update-service` cannot
//! bypass or shadow a grant. The gate runs before `acquire_call`,
//! so a refused call spends no refcount and cannot influence
//! `remove-service` timing.
//!
//! **Delegation audit (H6)**: when the invocation is rooted at an
//! external principal (REST / Connect / MCP), every hop is written to
//! the audit ledger with the root's `token_id` / `actor_kind`, the
//! root's `call_id`, and the context JSON (root, executing actor,
//! chain). Allowed hops use the same two-phase intent/finalize contract
//! as API requests and fail closed if the intent cannot be written;
//! grant refusals are single-shot `deny` rows. Host-origin chains
//! (`init`, `tick`, `on-event`) are traced but not audited.

use std::sync::Arc;
use std::time::Duration;

use oxidhome_manifest::ServiceGrant;

use crate::auth::invocation::{self, DelegationHop, InvocationContext};
use crate::host_impl::plugin::oxidhome::plugin::devices::CommandResult;
use crate::host_impl::plugin::oxidhome::plugin::types::{Error as WitError, KeyValue, ServiceId};
use crate::state::{AuditEntry, AuditLog, ServiceRegistry};

use super::registry::InstanceRegistry;

/// Per-dispatcher-call wall-clock timeout. Independent of the
/// per-call liveness watchdog (which lives on the *callee's* store
/// and traps wasm that doesn't yield) — this one bounds how long the
/// caller waits for a reply on the dispatch channel. Generous on
/// purpose; a legitimate cross-plugin call shouldn't be slow.
///
/// The watchdog default and the dispatch timeout are deliberately
/// the same (30 s). The two bound *different* things: the watchdog
/// traps the wasm call site (via `Trap::Interrupt`), the dispatch
/// timeout unblocks the caller's supervisor. Either firing first is
/// fine. When the dispatch timeout fires, the caller's wait future
/// is dropped, but the [`CallGuard`] lives with the callee's
/// supervisor (inside `ControlCommand::ExecuteService`), so the
/// refcount only drops once the supervisor finishes the wasm —
/// `remove-service` can't succeed mid-handler.
///
/// An externally-rooted invocation additionally clamps this to its
/// remaining deadline (H6).
///
/// [`CallGuard`]: crate::state::CallGuard
pub(crate) const DISPATCH_TIMEOUT: Duration = Duration::from_secs(30);

/// Audit `method` for a delegated `call-service` hop.
pub const SERVICE_CALL_AUDIT_METHOD: &str = "CALL";

/// Public test-only entry point. The `host-services::call-service`
/// path runs from inside a wasm `execute-service-command`; an
/// integration test that wants to drive the dispatcher from the
/// outside (e.g. to set up a cross-instance call chain) goes
/// through here. Runs as a host-origin invocation.
///
/// **Not** a stable API — the `dispatcher` module is otherwise
/// `pub(crate)`. Keep this thin so the regular `call_service` path
/// is the single source of truth.
#[doc(hidden)]
pub async fn call_service_from_host(
    engine: &crate::Engine,
    caller_instance: impl Into<String>,
    caller_requested_grants: &[ServiceGrant],
    caller_granted_grants: &[ServiceGrant],
    target: ServiceId,
    command: impl Into<String>,
    args: Vec<KeyValue>,
) -> Result<CommandResult, WitError> {
    let services = engine.services();
    let instances = engine.instances();
    let audit = engine.audit_log();
    call_service(
        &services,
        &instances,
        Some(&audit),
        caller_instance.into(),
        caller_requested_grants,
        caller_granted_grants,
        target,
        command.into(),
        args,
    )
    .await
}

/// [`call_service_from_host`] run under an explicit
/// [`InvocationContext`] — lets tests drive a delegated chain on behalf
/// of an external principal. Same stability caveat.
#[doc(hidden)]
#[allow(clippy::too_many_arguments)]
pub async fn call_service_from_host_in(
    engine: &crate::Engine,
    ctx: InvocationContext,
    caller_instance: impl Into<String>,
    caller_requested_grants: &[ServiceGrant],
    caller_granted_grants: &[ServiceGrant],
    target: ServiceId,
    command: impl Into<String>,
    args: Vec<KeyValue>,
) -> Result<CommandResult, WitError> {
    invocation::CURRENT
        .scope(
            ctx,
            call_service_from_host(
                engine,
                caller_instance,
                caller_requested_grants,
                caller_granted_grants,
                target,
                command,
                args,
            ),
        )
        .await
}

/// Entry point for the `host-services::call-service` host impl.
///
/// `caller_instance` identifies *this* instance (from `PluginState`).
/// H10 round-4: authorization runs against **two** independent
/// selector lists — the caller's `[capabilities] consumes_services`
/// declared in the manifest (`caller_requested_grants`) and the
/// operator-narrowed grant from
/// `plugin_installation.granted_capabilities_json`
/// (`caller_granted_grants`). A call is authorized iff at least
/// one entry in each list matches the target-tuple, semantically
/// equivalent to intersection but with no materialized
/// cross-product (bounded O(N) per call in each list). Manifest
/// validation caps each list's length + each entry's `commands`
/// so this is bounded per-instance.
///
/// `target` is the host-minted `service-id` the caller passed;
/// the dispatcher resolves it through `services`, checks both
/// grant lists against the target's `(owner_plugin_id,
/// owner_instance, local_id, command)`, and hops to the owning
/// instance's supervisor via `instances`.
///
/// `audit` receives one row per hop of an externally-rooted invocation
/// (H6); `None` disables hop auditing (unit tests only).
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(crate) async fn call_service(
    services: &Arc<ServiceRegistry>,
    instances: &Arc<InstanceRegistry>,
    audit: Option<&Arc<AuditLog>>,
    caller_instance: String,
    caller_requested_grants: &[ServiceGrant],
    caller_granted_grants: &[ServiceGrant],
    target: ServiceId,
    command: String,
    args: Vec<KeyValue>,
) -> Result<CommandResult, WitError> {
    // 1. Resolve the target to its full identity tuple:
    //    `(owner_instance, owner_plugin_id, local_id)`. All three
    //    are needed — owner_instance to route + cycle-check,
    //    owner_plugin_id + local_id to authorize against the
    //    caller's grants on the immutable logical key (not the
    //    mutable `name`).
    let (target_instance, target_plugin_id, target_local_id) = services
        .get_owner_plugin_and_local_id(&target)
        .ok_or_else(|| WitError::NotFound(format!("service {target} not registered")))?;

    // H6: the invocation this call is part of. Unset ⇒ the caller's
    // wasm was entered by the host itself (`init` / `tick` /
    // `on-event`), so the hop is rooted at the caller instance.
    let parent = invocation::current_or_host(&caller_instance);

    // 2. Cycle detection at instance granularity.
    //
    //    The deadlock condition is: dispatching to a supervisor that
    //    is *currently parked* awaiting a reply from an upstream
    //    `call-service`. A supervisor is parked exactly while it is
    //    the **caller** in an in-flight hop — its `handle_control`
    //    is blocked on the oneshot. So the "blocked" set is the
    //    `caller_instance` of every hop on the chain *plus* this
    //    very call's caller (we're about to park them on the oneshot
    //    below). If `target_instance` is in that set, the dispatch
    //    would queue an `ExecuteService` to a supervisor that can't
    //    process it ⇒ 30s timeout deadlock. Reject up-front instead.
    //
    //    H10: split the historical "recursion detected" message into
    //    two — the caller==target case is a WIT-surface contract
    //    ("same-instance dispatch is not supported"), the multi-hop
    //    A→B→…→A case is a genuine cycle. Both stay
    //    `InvalidArgument` on the wire; the distinct messages let
    //    operators and plugin authors tell them apart.
    if caller_instance == target_instance {
        return Err(WitError::InvalidArgument(format!(
            "same-instance dispatch is not supported: target service `{target}` is \
             owned by the calling instance `{caller_instance}`; dispatch between \
             services colocated in one instance in plugin-local code instead of \
             going through host-services::call-service"
        )));
    }
    if parent
        .chain()
        .iter()
        .any(|h| h.caller_instance == target_instance)
    {
        return Err(WitError::InvalidArgument(format!(
            "cycle detected: instance `{target_instance}` is already on the \
             call chain (target service `{target}`); calling back into a \
             supervisor already parked on a reply would deadlock"
        )));
    }

    let callee_ctx = parent.delegate(DelegationHop {
        caller_instance: caller_instance.clone(),
        target_plugin: target_plugin_id.clone(),
        target_instance: target_instance.clone(),
        target_service: target_local_id.clone(),
    });
    let hop_audit = audit
        .filter(|_| callee_ctx.root().is_external())
        .map(|log| HopAudit::new(Arc::clone(log), &callee_ctx, &command));

    // H6: refuse work the root has already given up on — before the
    // grant gate, so an expired invocation can't queue deny-row
    // writes either. The budget left also bounds every wait below.
    let timeout = match callee_ctx.remaining() {
        Some(r) if r.is_zero() => {
            return Err(WitError::Unavailable(format!(
                "call-service to `{target}` refused: invocation `{}` deadline exceeded",
                callee_ctx.call_id(),
            )));
        }
        Some(r) => r.min(DISPATCH_TIMEOUT),
        None => DISPATCH_TIMEOUT,
    };
    // One absolute bound for everything the caller's supervisor waits
    // on from here: a deny-row write, or the audit intent write *and*
    // the dispatch.
    let wait_until = tokio::time::Instant::now() + timeout;
    // The caller stops waiting at `wait_until`, so the callee must not
    // start after it either: fold the cutoff into the callee's deadline,
    // which its supervisor checks on dequeue (and which bounds any
    // nested hop the callee makes).
    let callee_ctx = callee_ctx.with_deadline(Some(
        callee_ctx
            .deadline()
            .map_or(wait_until, |d| d.min(wait_until)),
    ));

    // 3. H10 structured capability gate. Runs before `acquire_call`
    //    so a refused call spends no refcount and cannot influence
    //    `remove-service` timing. Matches on the immutable
    //    `(caller_instance, target_plugin, target_instance,
    //    local_id, command)` 5-tuple — a callee's `update-service`
    //    can't shadow or bypass the grant by renaming `name`, and
    //    an operator can narrow a grant to specific caller
    //    instances via `caller_instance` (H10 round-3 finding 2).
    //
    //    H10 round-4: both lists are checked independently. Fast
    //    path — reject on the first list that has no match — so
    //    the total cost is O(|first list|) when the manifest
    //    doesn't declare a matching selector, and
    //    O(|requested|+|granted|) otherwise. No materialized
    //    cross-product.
    let matches_requested = crate::state::any_grant_matches(
        caller_requested_grants,
        &caller_instance,
        &target_plugin_id,
        &target_instance,
        &target_local_id,
        &command,
    );
    let matches_granted = crate::state::any_grant_matches(
        caller_granted_grants,
        &caller_instance,
        &target_plugin_id,
        &target_instance,
        &target_local_id,
        &command,
    );
    if !(matches_requested && matches_granted) {
        // Wording notes: this error also flows through
        // `call_service_from_host`, which passes explicit slices
        // and has no "manifest" behind it — the guidance below
        // covers both. Which of `matches_requested` or
        // `matches_granted` fired is included so an operator (or
        // test harness) can localize the fix instead of guessing.
        // The verb rides with the failing-list phrase so the
        // polarity is correct on every arm (round-6 review
        // fix: prior wording said "the requested list contains a
        // matching selector" when in fact it *didn't* — that arm
        // was inverted).
        let failed_clause = match (matches_requested, matches_granted) {
            (false, false) => "neither the caller's requested nor the granted list contains",
            (false, true) => "the caller's requested list does not contain",
            (true, false) => "the operator's granted list does not contain",
            (true, true) => unreachable!("both matched but guard fired"),
        };
        if let Some(hop_audit) = hop_audit {
            hop_audit.record_denied(wait_until).await;
        }
        return Err(WitError::PermissionDenied(format!(
            "caller `{caller_instance}` refused: {failed_clause} a matching \
             `consumes_services` selector for target \
             `{target_plugin_id}` instance `{target_instance}` service \
             `{target_local_id}` command `{command}` (caller_instance \
             `{caller_instance}` must match too). For plugin callers, add \
             a matching `[[capabilities.consumes_services]]` entry to the \
             caller's manifest and ensure the operator's granted copy \
             authorizes the same selector"
        )));
    }

    // 4. Resolve target instance handle; refuse if it isn't running.
    let target_handle = instances.get(&target_instance).ok_or_else(|| {
        WitError::Unavailable(format!(
            "service `{target}` owner instance `{target_instance}` is not running"
        ))
    })?;

    // H6: two-phase hop audit, fail-closed — the intent row must exist
    // before the callee can act on the root's behalf.
    // Bounded by `wait_until`: ledger contention must not hold the
    // caller past its deadline. A write that lands after we gave up
    // leaves a `pending` row — evidence of an attempt that never ran.
    let audit_id = match &hop_audit {
        Some(hop_audit) => {
            let intent = tokio::time::timeout_at(wait_until, hop_audit.record_intent())
                .await
                .unwrap_or_else(|_| Err("intent write timed out".into()));
            Some(intent.map_err(|msg| {
                WitError::Unavailable(format!(
                    "call-service to `{target}` refused: audit ledger unavailable ({msg})"
                ))
            })?)
        }
        None => None,
    };
    // The intent write may have finished right at the cutoff; don't
    // enqueue work the caller is about to stop waiting for.
    if tokio::time::Instant::now() >= wait_until {
        let outcome = Err(WitError::Unavailable(format!(
            "call-service to `{target}` refused: hop deadline reached before dispatch",
        )));
        if let (Some(hop_audit), Some(id)) = (hop_audit, audit_id) {
            hop_audit.finalize(id, &outcome);
        }
        return outcome;
    }

    // 5. Acquire the in-flight refcount. The guard travels in the
    //    `ExecuteService` message — the callee's supervisor holds it
    //    across the wasm call and `Drop` decrements when the work
    //    actually finishes. This is what makes the refcount track
    //    real execution rather than the caller's wait future: if we
    //    time out below, dropping the wait future doesn't release
    //    the refcount while the supervisor is still about to run the
    //    handler. If the supervisor's mpsc is closed (send fails),
    //    the `SendError` carries the message back and the guard
    //    drops with it.
    let outcome = match services.acquire_call(&target) {
        Ok(guard) => {
            // 6. Hand the callee context (parent chain + this hop) to
            //    the owner's supervisor, which scopes it on its own
            //    task so nested `call-service`s see the full chain.
            let dispatch_future = target_handle.execute_service_command(
                callee_ctx,
                guard,
                target.clone(),
                command,
                args,
            );
            match tokio::time::timeout_at(wait_until, dispatch_future).await {
                Ok(Ok(result)) => Ok(result),
                Ok(Err(trap)) => Err(WitError::Unavailable(format!(
                    "call-service to `{target}` (owner `{target_instance}`) failed: {trap:#}"
                ))),
                Err(_) => Err(WitError::Unavailable(format!(
                    "call-service to `{target}` (owner `{target_instance}`) timed out after {} ms",
                    timeout.as_millis(),
                ))),
            }
        }
        Err(err) => Err(err),
    };
    if let (Some(hop_audit), Some(id)) = (hop_audit, audit_id) {
        hop_audit.finalize(id, &outcome);
    }
    outcome
}

/// Audit writer for one delegated hop (H6). Built only for
/// externally-rooted invocations.
struct HopAudit {
    log: Arc<AuditLog>,
    entry: AuditEntry,
}

impl HopAudit {
    fn new(log: Arc<AuditLog>, callee_ctx: &InvocationContext, command: &str) -> Self {
        let root = callee_ctx.root();
        let hop = callee_ctx
            .chain()
            .last()
            .expect("delegate() always appends a hop");
        // Every segment is capped: command names come from wasm and
        // service `local-id`s from `register-service`, neither
        // otherwise length-bounded.
        let path = format!(
            "service.call/{}/{}/{}/{}",
            invocation::audit_cap(&hop.target_plugin),
            invocation::audit_cap(&hop.target_instance),
            invocation::audit_cap(&hop.target_service),
            invocation::audit_cap(command),
        );
        let entry = AuditEntry {
            id: 0,
            intent_ms: 0,
            finalized_ms: None,
            token_id: root.audit_token_id().to_owned(),
            actor_kind: root.kind().as_str().to_owned(),
            method: SERVICE_CALL_AUDIT_METHOD.to_owned(),
            path,
            status: 0,
            decision: "pending".into(),
            required_scope: None,
            execution_outcome: None,
            domain_error: None,
            credential_fp: None,
            call_id: Some(callee_ctx.call_id().to_owned()),
            invocation: Some(callee_ctx.audit_json()),
        };
        Self { log, entry }
    }

    /// Single-shot `deny` row. Awaited (up to `wait_until`) rather than
    /// detached: a refused call returns instantly, so without the wait
    /// a plugin looping on refused calls could queue blocking ledger
    /// writes without bound. The refusal itself never depends on the
    /// write.
    async fn record_denied(self, wait_until: tokio::time::Instant) {
        let Self { log, mut entry } = self;
        entry.status = 403;
        entry.decision = "deny".into();
        entry.required_scope = Some("consumes_services".into());
        let write = tokio::task::spawn_blocking(move || log.record_completed(&entry));
        match tokio::time::timeout_at(wait_until, write).await {
            Ok(Ok(Ok(_))) => {}
            Ok(Ok(Err(err))) => {
                tracing::error!(target: "host.audit", error = %err, "service-call deny row failed");
            }
            Ok(Err(err)) => {
                tracing::error!(target: "host.audit", error = %err, "service-call deny row panicked");
            }
            Err(_) => {
                tracing::warn!(target: "host.audit", "service-call deny row still pending at hop deadline");
            }
        }
    }

    async fn record_intent(&self) -> Result<u64, String> {
        let log = Arc::clone(&self.log);
        let entry = self.entry.clone();
        match tokio::task::spawn_blocking(move || log.record_intent(&entry)).await {
            Ok(Ok(id)) => Ok(id),
            Ok(Err(err)) => Err(err.to_string()),
            Err(err) => Err(err.to_string()),
        }
    }

    /// Best-effort finalize, detached so the caller's supervisor isn't
    /// held on the ledger after the hop finished (the intent row is
    /// already the durable evidence).
    fn finalize(self, id: u64, outcome: &Result<CommandResult, WitError>) {
        let (status, decision, execution_outcome, domain_error): (u16, &str, _, _) = match outcome {
            Ok(CommandResult::Ok | CommandResult::OkWithState(_)) => {
                (200, "allow", Some("success"), None)
            }
            Ok(CommandResult::Err(err)) => (
                200,
                "allow",
                Some("failed"),
                Some(crate::api::wit_error_kind(err)),
            ),
            Err(_) => (503, "error", None, None),
        };
        let log = self.log;
        tokio::task::spawn_blocking(move || {
            if let Err(err) =
                log.finalize(id, status, decision, None, execution_outcome, domain_error)
            {
                tracing::error!(target: "host.audit", error = %err, id, "service-call finalize failed");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_impl::plugin::oxidhome::plugin::services::ServiceInfo;

    /// Chain fixture: a context whose delegation chain holds one hop
    /// per `(caller, target)` pair.
    fn ctx_with_chain(pairs: &[(&str, &str)]) -> InvocationContext {
        pairs.iter().fold(
            InvocationContext::host_origin("root"),
            |ctx, (caller, target)| {
                ctx.delegate(DelegationHop {
                    caller_instance: (*caller).into(),
                    target_plugin: "irrelevant".into(),
                    target_instance: (*target).into(),
                    target_service: "irrelevant".into(),
                })
            },
        )
    }

    fn fixture_info(name: &str) -> ServiceInfo {
        ServiceInfo {
            local_id: name.into(),
            name: name.into(),
            metadata: Vec::new(),
            commands: Vec::new(),
        }
    }

    fn assert_msg_contains(err: &WitError, needle: &str) {
        let msg = format!("{err:?}").to_ascii_lowercase();
        assert!(msg.contains(needle), "expected `{needle}` in: {msg}");
    }

    /// Build a `ServiceGrant` that authorizes `command` on the
    /// `(plugin, instance='*', service=local_id)` tuple — used by
    /// tests that want a grant broad enough to authorize an
    /// arbitrary caller, so the assertion focuses on some other
    /// check (same-instance, cycle, target-not-registered, …).
    /// The dispatcher runs same-instance / cycle checks *before*
    /// the grant check, so tests exercising those defenses would
    /// hit their target even with an empty grant list — this
    /// helper's role is documentary, not required for correctness.
    fn grant_any(plugin: &str, local_id: &str, command: &str) -> ServiceGrant {
        ServiceGrant {
            plugin: plugin.into(),
            instance: ServiceGrant::ANY_INSTANCE.into(),
            service: local_id.into(),
            commands: vec![command.into()],
            caller_instance: ServiceGrant::ANY_CALLER_INSTANCE.into(),
        }
    }

    /// H10: outermost (empty chain) A→A self-call is rejected with a
    /// documented same-instance error, not "recursion". The
    /// dispatcher runs the same-instance check *before* the grant
    /// gate, so this test's rejection is unaffected by the grant
    /// list (a matching grant is passed here so a reader can't
    /// mis-attribute the rejection to a missing grant).
    #[tokio::test(flavor = "current_thread")]
    async fn rejects_outermost_self_call_as_same_instance() {
        let services = Arc::new(ServiceRegistry::new());
        let svc = services
            .register(
                "alpha".into(),
                "com.example.alpha".into(),
                fixture_info("ring"),
            )
            .expect("register");
        let instances = Arc::new(InstanceRegistry::new());
        let grants = [grant_any("com.example.alpha", "ring", "kick")];

        let err = call_service(
            &services,
            &instances,
            None,
            "alpha".into(),
            &grants,
            &grants,
            svc.clone(),
            "kick".into(),
            Vec::new(),
        )
        .await
        .expect_err("self-call must be rejected");

        assert!(
            matches!(err, WitError::InvalidArgument(_)),
            "expected InvalidArgument, got {err:?}",
        );
        assert_msg_contains(&err, "same-instance dispatch is not supported");
        assert_eq!(services.active_call_count(&svc), 0);
    }

    /// Cross-task A→B→A cycle. Kept as `cycle detected` (distinct
    /// from the same-instance case).
    #[tokio::test(flavor = "current_thread")]
    async fn rejects_blocked_caller_cycle() {
        let services = Arc::new(ServiceRegistry::new());
        let a_svc = services
            .register(
                "alpha".into(),
                "com.example.alpha".into(),
                fixture_info("ring"),
            )
            .expect("register");
        let _b_svc = services
            .register(
                "beta".into(),
                "com.example.beta".into(),
                fixture_info("ring"),
            )
            .expect("register");
        let instances = Arc::new(InstanceRegistry::new());
        let grants = [grant_any("com.example.alpha", "ring", "kick")];

        let chain = ctx_with_chain(&[("alpha", "beta")]);

        let err = invocation::CURRENT
            .scope(
                chain,
                call_service(
                    &services,
                    &instances,
                    None,
                    "beta".into(),
                    &grants,
                    &grants,
                    a_svc.clone(),
                    "kick".into(),
                    Vec::new(),
                ),
            )
            .await
            .expect_err("cycle must be rejected");

        assert!(
            matches!(err, WitError::InvalidArgument(_)),
            "expected InvalidArgument, got {err:?}",
        );
        assert_msg_contains(&err, "cycle detected");
        assert_eq!(services.active_call_count(&a_svc), 0);
    }

    /// H10: structured capability gate. Absent grant → refused
    /// before any routing / refcount work. Mismatched grant
    /// (wrong plugin, wrong instance, wrong service, or wrong
    /// command) → also refused. Refcount never bumped.
    #[tokio::test(flavor = "current_thread")]
    async fn rejects_call_without_matching_grant() {
        let services = Arc::new(ServiceRegistry::new());
        let target = services
            .register(
                "beta".into(),
                "com.example.beta".into(),
                fixture_info("ring"),
            )
            .expect("register");
        let instances = Arc::new(InstanceRegistry::new());

        // Empty grants — every call is refused.
        let err = call_service(
            &services,
            &instances,
            None,
            "alpha".into(),
            &[],
            &[],
            target.clone(),
            "kick".into(),
            Vec::new(),
        )
        .await
        .expect_err("empty grants must refuse");
        assert!(matches!(err, WitError::PermissionDenied(_)));
        assert_msg_contains(&err, "consumes_services");
        assert_eq!(services.active_call_count(&target), 0);

        // Right plugin, wrong command.
        let wrong_command = [ServiceGrant {
            plugin: "com.example.beta".into(),
            instance: "*".into(),
            service: "ring".into(),
            commands: vec!["not-kick".into()],
            caller_instance: "*".into(),
        }];
        let err = call_service(
            &services,
            &instances,
            None,
            "alpha".into(),
            &wrong_command,
            &wrong_command,
            target.clone(),
            "kick".into(),
            Vec::new(),
        )
        .await
        .expect_err("mismatched command must refuse");
        assert!(matches!(err, WitError::PermissionDenied(_)));
        assert_eq!(services.active_call_count(&target), 0);

        // Right plugin + command, but instance selector doesn't match.
        let wrong_instance = [ServiceGrant {
            plugin: "com.example.beta".into(),
            instance: "not-beta".into(),
            service: "ring".into(),
            commands: vec!["kick".into()],
            caller_instance: "*".into(),
        }];
        let err = call_service(
            &services,
            &instances,
            None,
            "alpha".into(),
            &wrong_instance,
            &wrong_instance,
            target.clone(),
            "kick".into(),
            Vec::new(),
        )
        .await
        .expect_err("mismatched instance must refuse");
        assert!(matches!(err, WitError::PermissionDenied(_)));
        assert_eq!(services.active_call_count(&target), 0);

        // Right plugin + command + instance, but service local_id
        // doesn't match.
        let wrong_service = [ServiceGrant {
            plugin: "com.example.beta".into(),
            instance: "*".into(),
            service: "other-service".into(),
            commands: vec!["kick".into()],
            caller_instance: "*".into(),
        }];
        let err = call_service(
            &services,
            &instances,
            None,
            "alpha".into(),
            &wrong_service,
            &wrong_service,
            target.clone(),
            "kick".into(),
            Vec::new(),
        )
        .await
        .expect_err("mismatched service local_id must refuse");
        assert!(matches!(err, WitError::PermissionDenied(_)));
        assert_eq!(services.active_call_count(&target), 0);
    }

    /// H10: the `"*"` wildcard on `commands` authorizes every
    /// command. The dispatcher then proceeds past the grant check
    /// and hits the next stop (`Unavailable` — beta has no live
    /// instance handle in this in-process test).
    #[tokio::test(flavor = "current_thread")]
    async fn wildcard_command_grant_authorizes_any_command() {
        let services = Arc::new(ServiceRegistry::new());
        let target = services
            .register(
                "beta".into(),
                "com.example.beta".into(),
                fixture_info("ring"),
            )
            .expect("register");
        let instances = Arc::new(InstanceRegistry::new());
        let grants = [ServiceGrant {
            plugin: "com.example.beta".into(),
            instance: "*".into(),
            service: "ring".into(),
            commands: vec!["*".into()],
            caller_instance: "*".into(),
        }];

        let err = call_service(
            &services,
            &instances,
            None,
            "alpha".into(),
            &grants,
            &grants,
            target.clone(),
            "anything".into(),
            Vec::new(),
        )
        .await
        .expect_err("beta isn't running, so we get Unavailable past the grant check");

        assert!(
            matches!(err, WitError::Unavailable(_)),
            "expected Unavailable, got {err:?}",
        );
    }

    /// Sanity: a linear, non-cyclic chain A→B→C→D — where D's owner
    /// is *not* on the existing caller-set {A,B,C} — passes both the
    /// `consumes_services` check (grant lists delta's plugin) and the
    /// cycle check. The call then reaches `instances.get(...)` and
    /// fails there with `Unavailable`.
    #[tokio::test(flavor = "current_thread")]
    async fn permits_non_cyclic_chain() {
        let services = Arc::new(ServiceRegistry::new());
        let instances = Arc::new(InstanceRegistry::new());
        let delta_svc = services
            .register(
                "delta".into(),
                "com.example.delta".into(),
                fixture_info("ring"),
            )
            .expect("register");
        let grants = [grant_any("com.example.delta", "ring", "kick")];

        let chain = ctx_with_chain(&[("alpha", "beta"), ("beta", "gamma")]);
        let err = invocation::CURRENT
            .scope(
                chain,
                call_service(
                    &services,
                    &instances,
                    None,
                    "gamma".into(),
                    &grants,
                    &grants,
                    delta_svc.clone(),
                    "kick".into(),
                    Vec::new(),
                ),
            )
            .await
            .expect_err("delta isn't a real instance, so we get Unavailable");

        assert!(
            matches!(err, WitError::Unavailable(_)),
            "expected Unavailable (delta not running), got {err:?}",
        );
        assert_eq!(services.active_call_count(&delta_svc), 0);
    }

    /// H10 round-4: authorization is `requested_matches ∧
    /// granted_matches` per call. Verifies both directions:
    ///
    /// - Requested is wildcard, granted narrows to a specific
    ///   command → the specific command authorizes, others don't.
    /// - Requested lists only `["get"]`, granted has `["*"]` →
    ///   only `get` authorizes (requested is a real ceiling too).
    /// - Same request matched by both → passes the auth gate and
    ///   proceeds (hits `Unavailable` because the target has no
    ///   live handle in this in-process test).
    #[tokio::test(flavor = "current_thread")]
    async fn requested_and_granted_both_gate_the_call() {
        let services = Arc::new(ServiceRegistry::new());
        let target = services
            .register(
                "beta".into(),
                "com.example.beta".into(),
                fixture_info("ring"),
            )
            .expect("register");
        let instances = Arc::new(InstanceRegistry::new());

        // Case 1: requested = "*"-any-command; granted = only `get`.
        // Call to `get` should pass; call to `set` should refuse.
        let requested_wildcard = [ServiceGrant {
            plugin: "com.example.beta".into(),
            instance: "*".into(),
            service: "ring".into(),
            commands: vec!["*".into()],
            caller_instance: "*".into(),
        }];
        let granted_get = [ServiceGrant {
            plugin: "com.example.beta".into(),
            instance: "*".into(),
            service: "ring".into(),
            commands: vec!["get".into()],
            caller_instance: "*".into(),
        }];
        // `get` matches both lists → passes auth, then fails on
        // Unavailable because beta isn't running.
        let err = call_service(
            &services,
            &instances,
            None,
            "alpha".into(),
            &requested_wildcard,
            &granted_get,
            target.clone(),
            "get".into(),
            Vec::new(),
        )
        .await
        .expect_err("beta not running → Unavailable past the gate");
        assert!(matches!(err, WitError::Unavailable(_)));
        // `set` fails granted-list match → PermissionDenied.
        let err = call_service(
            &services,
            &instances,
            None,
            "alpha".into(),
            &requested_wildcard,
            &granted_get,
            target.clone(),
            "set".into(),
            Vec::new(),
        )
        .await
        .expect_err("granted doesn't cover `set`");
        assert!(matches!(err, WitError::PermissionDenied(_)));

        // Case 2: requested narrower than granted. Requested only
        // authorizes `get`; granted authorizes `*`. Call to `set`
        // fails requested-list match, even though granted allows
        // it (the manifest ceiling still applies).
        let requested_get_only = [ServiceGrant {
            plugin: "com.example.beta".into(),
            instance: "*".into(),
            service: "ring".into(),
            commands: vec!["get".into()],
            caller_instance: "*".into(),
        }];
        let granted_wildcard = [ServiceGrant {
            plugin: "com.example.beta".into(),
            instance: "*".into(),
            service: "ring".into(),
            commands: vec!["*".into()],
            caller_instance: "*".into(),
        }];
        let err = call_service(
            &services,
            &instances,
            None,
            "alpha".into(),
            &requested_get_only,
            &granted_wildcard,
            target.clone(),
            "set".into(),
            Vec::new(),
        )
        .await
        .expect_err("requested is the ceiling; `set` isn't asked for");
        assert!(matches!(err, WitError::PermissionDenied(_)));
        assert_eq!(services.active_call_count(&target), 0);
    }

    fn api_root() -> InvocationContext {
        let actor = crate::auth::Actor::api("tok-root", vec!["*".into()]);
        InvocationContext::external(crate::auth::Principal::token(
            crate::auth::ActorKind::Api,
            &actor,
            crate::auth::Transport::Rest,
        ))
    }

    /// H6: a hop whose invocation deadline already passed is refused
    /// after the grant gate and before any routing or refcount work.
    #[tokio::test(flavor = "current_thread")]
    async fn refuses_hop_after_invocation_deadline() {
        let services = Arc::new(ServiceRegistry::new());
        let target = services
            .register(
                "beta".into(),
                "com.example.beta".into(),
                fixture_info("ring"),
            )
            .expect("register");
        let instances = Arc::new(InstanceRegistry::new());
        let grants = [grant_any("com.example.beta", "ring", "kick")];
        let expired = api_root().with_deadline(Some(tokio::time::Instant::now()));

        let err = invocation::CURRENT
            .scope(
                expired,
                call_service(
                    &services,
                    &instances,
                    None,
                    "alpha".into(),
                    &grants,
                    &grants,
                    target.clone(),
                    "kick".into(),
                    Vec::new(),
                ),
            )
            .await
            .expect_err("expired invocation must be refused");
        assert!(matches!(err, WitError::Unavailable(_)), "got {err:?}");
        assert_msg_contains(&err, "deadline exceeded");
        assert_eq!(services.active_call_count(&target), 0);
    }

    /// H6: a refused hop of an externally-rooted invocation lands in
    /// the ledger attributed to the root token, with the root's call id
    /// and the delegation chain; a host-origin refusal does not.
    #[tokio::test(flavor = "current_thread")]
    async fn audits_denied_hop_against_external_root_only() {
        use crate::state::{AuditQuery, Db};

        let services = Arc::new(ServiceRegistry::new());
        let target = services
            .register(
                "beta".into(),
                "com.example.beta".into(),
                fixture_info("ring"),
            )
            .expect("register");
        let instances = Arc::new(InstanceRegistry::new());
        let audit = Arc::new(AuditLog::new(Arc::new(Db::open_in_memory().expect("db"))));

        // Host-origin: refused, not audited.
        let _ = call_service(
            &services,
            &instances,
            Some(&audit),
            "alpha".into(),
            &[],
            &[],
            target.clone(),
            "kick".into(),
            Vec::new(),
        )
        .await
        .expect_err("no grant");
        // Deny rows are detached writes; give one a chance to land.
        tokio::task::yield_now().await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(audit.count().unwrap(), 0);

        let root = api_root().entering("alpha");
        let call_id = root.call_id().to_owned();
        let _ = invocation::CURRENT
            .scope(
                root,
                call_service(
                    &services,
                    &instances,
                    Some(&audit),
                    "alpha".into(),
                    &[],
                    &[],
                    target.clone(),
                    "kick".into(),
                    Vec::new(),
                ),
            )
            .await
            .expect_err("no grant");
        let mut rows = Vec::new();
        for _ in 0..200 {
            rows = audit.query(&AuditQuery::default(), 10).unwrap();
            if !rows.is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row.token_id, "tok-root");
        assert_eq!(row.actor_kind, "api");
        assert_eq!(row.method, SERVICE_CALL_AUDIT_METHOD);
        assert_eq!(row.path, "service.call/com.example.beta/beta/ring/kick");
        assert_eq!(row.decision, "deny");
        assert_eq!(row.status, 403);
        assert_eq!(row.required_scope.as_deref(), Some("consumes_services"));
        assert_eq!(row.call_id.as_deref(), Some(call_id.as_str()));
        let inv: serde_json::Value =
            serde_json::from_str(row.invocation.as_deref().unwrap()).unwrap();
        assert_eq!(inv["root"]["transport"], "rest");
        assert_eq!(inv["chain"][0]["caller"], "alpha");
        assert_eq!(inv["chain"][0]["instance"], "beta");
    }
}
