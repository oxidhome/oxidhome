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
//! are not supported by `host-services::call-service` — dispatching
//! to a supervisor already parked on the same call chain is
//! deadlock-by-construction. Plugins colocating services in one
//! instance dispatch between them in plugin-local code. Scripting
//! plugins run each script in its own sandbox instance
//! ([`super::sandbox`], ADR-0001), so two scripts of one plugin are
//! two instances here and their calls take this path like any other. H10 upgraded the caller==target case from a
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
//! **The hop decision (H6 slices 4 and 5)**: the grant gate is one
//! part of [`crate::auth::authorize_plugin`], which decides every hop
//! in the engine. The owner's deny list for the calling plugin, and for
//! every plugin that made a hop on the way to it, refuses the call
//! whatever grants it; and when the invocation is rooted at an external
//! principal, the root must hold `service.call` on the target (the
//! `services:call` scope, or a role grant whose `services` selector
//! covers it) and none of its denies may match. A narrow token can't
//! have a script call services on its behalf that the token itself
//! wasn't given. Host-rooted work is decided by the grant and the
//! chain's denies.
//!
//! **Delegation audit (H6)**: when the invocation is attributable
//! (rooted at an external principal, or an `on-event` reaction to an
//! event such an invocation published), every hop is written to the
//! audit ledger with the root's `token_id` / `actor_kind`, the
//! root's `call_id`, `caused_by` for a reaction, and the context JSON
//! (root, executing actor, chain). Allowed hops use the same two-phase
//! intent/finalize contract as API requests and fail closed if the
//! intent cannot be written; refusals are single-shot `deny` rows
//! whose `required_scope` names what was missing (`consumes_services`
//! for the plugin's grant, `plugin-deny` for a plugin deny list,
//! `services:call` or `deny` for the root).
//! Other host-origin chains (`init`, `tick`, reactions to unattributed
//! events) are traced but not audited.
//!
//! The finalize goes through the H5 command journal (it can come from a
//! `Drop` when the caller is cancelled, and the journal is drained at
//! shutdown). A result that reaches the callee's supervisor after the
//! caller stopped waiting (the hop row then says `unknown`) is recorded
//! as a [`SERVICE_CALL_RESULT_AUDIT_METHOD`] row sharing the `call_id`.

use std::sync::Arc;
use std::time::Duration;

use oxidhome_manifest::ServiceGrant;

use crate::auth::invocation::{self, DelegationHop, InvocationContext, audit_cap};
use crate::auth::{Action, PluginPrincipal, Reason, Resource, authorize_plugin};
use crate::host_impl::plugin::oxidhome::plugin::devices::CommandResult;
use crate::host_impl::plugin::oxidhome::plugin::types::{Error as WitError, KeyValue, ServiceId};
use crate::state::{AuditEntry, AuditLog, ServiceRegistry};

use super::command::{DispatchTicket, PendingCommands};
use super::command_journal::Finalize;
use super::lifecycle::ServiceCallOutcome;
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

/// Audit `method` of the row that records a service call's result when
/// it arrived after the caller stopped waiting (its hop row says
/// `unknown`). Same `path` and `call_id` as the hop row; the result is
/// in `execution_outcome`, `domain_error` and `command_outcome`.
pub const SERVICE_CALL_RESULT_AUDIT_METHOD: &str = "CALL_RESULT";

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
    let pending = engine.pending_commands();
    let denies = engine.plugin_denies();
    // The test driver is its own plugin: its id is its instance id.
    let caller_instance: String = caller_instance.into();
    let caller = PluginPrincipal {
        plugin_id: &caller_instance,
        instance_id: &caller_instance,
        requested_services: caller_requested_grants,
        granted_services: caller_granted_grants,
        reads_state: &[],
        subscribes_events: false,
        denies: &denies,
    };
    call_service(
        &services,
        &instances,
        Some(&audit),
        Some(&pending),
        &caller,
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
/// `caller` is *this* instance as a principal (from `PluginState`).
/// H10 round-4: the grant check runs against **two** independent
/// selector lists — the caller's `[capabilities] consumes_services`
/// declared in the manifest (`caller.requested_services`) and the
/// operator-narrowed grant from
/// `plugin_installation.granted_capabilities_json`
/// (`caller.granted_services`). A call is authorized iff at least
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
/// `audit` receives one row per hop of an attributable invocation (H6:
/// externally rooted, or a reaction to an attributed event); `None`
/// disables hop auditing (unit tests only). `journal` (the
/// engine's pending-command table) finalizes the hop rows; without one
/// the finalize is a detached blocking write.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(crate) async fn call_service(
    services: &Arc<ServiceRegistry>,
    instances: &Arc<InstanceRegistry>,
    audit: Option<&Arc<AuditLog>>,
    journal: Option<&Arc<PendingCommands>>,
    caller: &PluginPrincipal<'_>,
    target: ServiceId,
    command: String,
    args: Vec<KeyValue>,
) -> Result<CommandResult, WitError> {
    let caller_instance = caller.instance_id.to_owned();
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
        caller_plugin: caller.plugin_id.to_owned(),
        target_plugin: target_plugin_id.clone(),
        target_instance: target_instance.clone(),
        target_service: target_local_id.clone(),
    });
    let hop_audit = audit
        .filter(|_| callee_ctx.is_attributable())
        .map(|log| HopAudit::new(Arc::clone(log), journal.cloned(), &callee_ctx, &command));

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

    // 3. The hop decision (H6 slices 4 and 5), in the engine. Runs
    //    before `acquire_call` so a refused call spends no refcount and
    //    cannot influence `remove-service` timing. The plugin's grant
    //    (H10) matches on the immutable `(caller_instance,
    //    target_plugin, target_instance, local_id, command)` 5-tuple —
    //    a callee's `update-service` can't shadow or bypass it by
    //    renaming `name`, and an operator can narrow a grant to
    //    specific caller instances via `caller_instance` — in both the
    //    requested and the granted list (H10 round-4), with no
    //    materialized cross-product. The chain's plugin deny lists and
    //    an external root's own permit and denies apply on top.
    let decision = authorize_plugin(
        &callee_ctx,
        caller,
        Action::ServiceCall,
        // The command is caller-supplied and unchecked until after
        // authorization: bound it before it's copied or echoed.
        &Resource::service(
            target_plugin_id.as_str(),
            target_instance.as_str(),
            target_local_id.as_str(),
            audit_cap(&command),
        ),
    );
    if decision.allow {
        // `service.call` targets carry no sensitive category yet, so
        // an allowed hop has no obligations to meet. When services can
        // be marked sensitive, the charge is made here, at dispatch.
        debug_assert!(decision.obligations.sensitive.is_empty());
    } else {
        let label = decision.reason.audit_label().unwrap_or("no-permit");
        if let Some(hop_audit) = hop_audit {
            hop_audit.record_denied(wait_until, label).await;
        }
        return Err(hop_refused(
            &decision.reason,
            caller,
            &callee_ctx,
            (&target_plugin_id, &target_instance, &target_local_id),
            audit_cap(&command),
        ));
    }

    // M2: the command must be one the service declares, and `args`
    //    must match its `params` schema. Runs after authorization so
    //    an unauthorized caller learns nothing about the schema, and
    //    before the hop's audit intent: like the other pre-dispatch
    //    refusals that aren't authorization decisions (same-instance,
    //    cycle, deadline, owner not running), a malformed call never
    //    reaches the callee and writes no hop row. Only grant
    //    refusals produce H6 `deny` rows. The reply is checked
    //    against this same registration snapshot.
    let target_meta = services.get_any(&target)?;
    let command_spec = super::schema::find_command(&target_meta.info, &target, &command)?;
    super::schema::check_args(&target, command_spec, &args)?;

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
    // (or after the caller was cancelled) is finalized `error`: an
    // attempt that never ran.
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

    // From here the hop row is finalized even if this future is
    // dropped (the caller was cancelled mid-call), by the ticket's
    // verdict: never started → `error`, started → `unknown`.
    let ticket = DispatchTicket::default();
    let mut hop = HopFinalizer {
        pending: hop_audit.zip(audit_id),
        ticket: ticket.clone(),
    };

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
            //    H5: the dispatch ticket tells a call that timed out
            //    in the callee's queue (it never runs: `unavailable`,
            //    safe to retry) from one the callee had started (it
            //    may have acted: `unknown`).
            // The registration snapshot the call was checked against,
            // shared rather than copied.
            let check = {
                let (target, meta, name) =
                    (target.clone(), Arc::clone(&target_meta), command.clone());
                ResultCheck::new(move |result| {
                    super::schema::find_command(&meta.info, &target, &name)
                        .and_then(|spec| super::schema::check_result(&target, spec, result))
                })
            };
            let outcome = target_handle
                .execute_service_command(
                    callee_ctx,
                    guard,
                    target.clone(),
                    command,
                    args,
                    check,
                    ticket,
                    wait_until,
                )
                .await;
            match outcome {
                ServiceCallOutcome::Replied(result) => Ok(result),
                ServiceCallOutcome::NotRun(why) => Err(WitError::Unavailable(format!(
                    "call-service to `{target}` (owner `{target_instance}`) failed: {why}; \
                     it did not run"
                ))),
                ServiceCallOutcome::TimedOut => Err(WitError::Unavailable(format!(
                    "call-service to `{target}` (owner `{target_instance}`) timed out after {} ms \
                     before the callee started it; it did not run",
                    timeout.as_millis(),
                ))),
                ServiceCallOutcome::Unknown(why) => Ok(CommandResult::Unknown(format!(
                    "call-service to `{target}` (owner `{target_instance}`): {why}; \
                     it may have taken effect"
                ))),
            }
        }
        Err(err) => Err(err),
    };
    // M2: the callee's reply must match the command's `returns`
    // schema; a violation reaches the caller as `internal`. The hop
    // row still records that the callee ran (allow / failed /
    // `internal`), not a dispatch error.
    let (outcome, audited) = match outcome {
        Ok(result) => match super::schema::check_result(&target, command_spec, result) {
            Ok(result) => (Ok(result), None),
            Err(err) => (Err(err.clone()), Some(Ok(CommandResult::Err(err)))),
        },
        Err(err) => (Err(err), None),
    };
    hop.finish(audited.as_ref().unwrap_or(&outcome));
    outcome
}

/// The error a refused hop returns, by the reason the engine gave.
/// Grant refusals say which `consumes_services` list failed, so an
/// operator (or test harness) can localize the fix; the reason itself
/// is in the hop's audit row.
fn hop_refused(
    reason: &Reason,
    caller: &PluginPrincipal<'_>,
    callee_ctx: &InvocationContext,
    (target_plugin, target_instance, target_local_id): (&str, &str, &str),
    command: &str,
) -> WitError {
    let caller_instance = caller.instance_id;
    match reason {
        Reason::MissingPluginGrant { .. } => {
            let covers = |grants: &[ServiceGrant]| {
                crate::state::any_grant_matches(
                    grants,
                    caller_instance,
                    target_plugin,
                    target_instance,
                    target_local_id,
                    command,
                )
            };
            // This error also flows through `call_service_from_host`,
            // which passes explicit slices and has no "manifest" behind
            // it — the guidance below covers both.
            let failed_clause = match (
                covers(caller.requested_services),
                covers(caller.granted_services),
            ) {
                (false, false) => "neither the caller's requested nor the granted list contains",
                (false, true) => "the caller's requested list does not contain",
                (true, _) => "the operator's granted list does not contain",
            };
            WitError::PermissionDenied(format!(
                "caller `{caller_instance}` refused: {failed_clause} a matching \
                 `consumes_services` selector for target \
                 `{target_plugin}` instance `{target_instance}` service \
                 `{target_local_id}` command `{command}` (caller_instance \
                 `{caller_instance}` must match too). For plugin callers, add \
                 a matching `[[capabilities.consumes_services]]` entry to the \
                 caller's manifest and ensure the operator's granted copy \
                 authorizes the same selector",
            ))
        }
        Reason::PluginDenied { plugin } => WitError::PermissionDenied(format!(
            "caller `{caller_instance}` refused: the owner's deny list for plugin `{plugin}` \
             forbids `service.call` on target `{target_plugin}` service `{target_local_id}` \
             command `{command}` (invocation `{}`)",
            callee_ctx.call_id(),
        )),
        _ => WitError::PermissionDenied(format!(
            "caller `{caller_instance}` refused: invocation `{}` was not granted \
             `service.call` on target `{target_plugin}` service `{target_local_id}` \
             command `{command}` by its root principal (a token needs `services:call` or a \
             role grant naming the service for every hop it causes)",
            callee_ctx.call_id(),
        )),
    }
}

/// Finalizes a hop's intent row exactly once: with the call's outcome,
/// or — when the caller's future is dropped mid-dispatch — with what
/// the dispatch ticket says happened, so the row never stays `pending`.
/// A committed hop intent row nobody has claimed yet; dropped
/// unclaimed, it is finalized `error` (the call never ran).
struct ArmedIntent(Option<(HopAudit, u64)>);

impl ArmedIntent {
    fn claim(mut self) -> u64 {
        self.0.take().map_or(0, |(_, id)| id)
    }
}

impl Drop for ArmedIntent {
    fn drop(&mut self) {
        if let Some((audit, id)) = self.0.take() {
            audit.finalize(
                id,
                &Err(WitError::Unavailable(
                    "the caller stopped waiting before the call was dispatched".into(),
                )),
            );
        }
    }
}

struct HopFinalizer {
    pending: Option<(HopAudit, u64)>,
    ticket: DispatchTicket,
}

impl HopFinalizer {
    fn finish(&mut self, outcome: &Result<CommandResult, WitError>) {
        if let Some((hop_audit, id)) = self.pending.take() {
            hop_audit.finalize(id, outcome);
        }
    }
}

impl Drop for HopFinalizer {
    fn drop(&mut self) {
        if self.pending.is_none() {
            return;
        }
        // Settle the ticket first: a still-queued call won't start now.
        let _ = self.ticket.try_abandon();
        let outcome = if self.ticket.started() {
            Ok(CommandResult::Unknown(
                "the caller was cancelled while the callee ran the call".into(),
            ))
        } else {
            Err(WitError::Unavailable(
                "the caller was cancelled before the callee started the call".into(),
            ))
        };
        self.finish(&outcome);
    }
}

/// `path` of a hop's audit rows: `service.call/<plugin>/<instance>/
/// <service>/<command>`, from the callee context's last hop. Every
/// segment is capped: command names come from wasm and service
/// `local-id`s from `register-service`, neither otherwise
/// length-bounded.
fn hop_path(callee_ctx: &InvocationContext, command: &str) -> Option<String> {
    let hop = callee_ctx.chain().last()?;
    Some(format!(
        "service.call/{}/{}/{}/{}",
        invocation::audit_cap(&hop.target_plugin),
        invocation::audit_cap(&hop.target_instance),
        invocation::audit_cap(&hop.target_service),
        invocation::audit_cap(command),
    ))
}

/// M2's `returns` check of a service call's reply, carried with the
/// call so a late result is checked as an on-time one is. `Err` is the
/// violation of a reply that breaks the schema.
#[derive(Clone)]
pub(crate) struct ResultCheck(
    Arc<dyn Fn(CommandResult) -> Result<CommandResult, WitError> + Send + Sync>,
);

impl ResultCheck {
    pub(crate) fn new(
        check: impl Fn(CommandResult) -> Result<CommandResult, WitError> + Send + Sync + 'static,
    ) -> Self {
        Self(Arc::new(check))
    }

    pub(crate) fn apply(&self, result: CommandResult) -> Result<CommandResult, WitError> {
        (self.0)(result)
    }
}

impl std::fmt::Debug for ResultCheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ResultCheck")
    }
}

/// The [`SERVICE_CALL_RESULT_AUDIT_METHOD`] row for a service call's
/// `result` that reached the callee's supervisor after the caller
/// stopped waiting. `None` for invocations that aren't attributable
/// (host-origin work other than a reaction to an attributed event),
/// which stay out of the ledger as their hops do.
///
/// `result` is the reply after its schema check: an `Err` (the callee
/// ran but broke its `returns`) is `failed` / `internal` with outcome
/// `outcome_unknown`, since the callee may have acted.
pub(crate) fn late_result_entry(
    callee_ctx: &InvocationContext,
    command: &str,
    result: Result<&CommandResult, &WitError>,
) -> Option<AuditEntry> {
    let root = callee_ctx.root();
    if !callee_ctx.is_attributable() {
        return None;
    }
    let path = hop_path(callee_ctx, command)?;
    let ((execution_outcome, domain_error), outcome) = match result {
        Err(violation) => (
            (Some("failed"), Some(crate::api::wit_error_kind(violation))),
            "outcome_unknown",
        ),
        // The H5 outcome names, as on `COMMAND` rows.
        Ok(result) => (
            result_columns(result),
            match result {
                CommandResult::Ok | CommandResult::OkWithState(_) => "completed",
                CommandResult::Err(_) => "rejected",
                CommandResult::Unknown(_) | CommandResult::Accepted => "outcome_unknown",
            },
        ),
    };
    Some(AuditEntry {
        id: 0,
        intent_ms: 0,
        finalized_ms: None,
        token_id: root.audit_token_id().to_owned(),
        actor_kind: root.kind().as_str().to_owned(),
        method: SERVICE_CALL_RESULT_AUDIT_METHOD.to_owned(),
        path,
        status: 200,
        decision: "allow".into(),
        required_scope: None,
        execution_outcome: execution_outcome.map(str::to_owned),
        domain_error: domain_error.map(str::to_owned),
        credential_fp: None,
        call_id: Some(callee_ctx.call_id().to_owned()),
        invocation: Some(callee_ctx.audit_json()),
        command_id: None,
        level: None,
        command_outcome: Some(outcome.to_owned()),
        caused_by: callee_ctx.caused_by().map(str::to_owned),
    })
}

/// `execution_outcome` / `domain_error` of a callee's reply.
fn result_columns(result: &CommandResult) -> (Option<&'static str>, Option<&'static str>) {
    match result {
        CommandResult::Ok | CommandResult::OkWithState(_) => (Some("success"), None),
        CommandResult::Err(err) => (Some("failed"), Some(crate::api::wit_error_kind(err))),
        // H5: the callee may have acted; neither success nor a
        // refusal. (`accepted` never reaches here — the callee's
        // instance turns it into `unknown`.)
        CommandResult::Unknown(_) | CommandResult::Accepted => (None, None),
    }
}

/// Audit writer for one delegated hop (H6). Built only for
/// attributable invocations ([`InvocationContext::is_attributable`]).
#[derive(Clone)]
struct HopAudit {
    log: Arc<AuditLog>,
    /// Finalizes the row (see the module docs); `None` in unit tests.
    journal: Option<Arc<PendingCommands>>,
    entry: AuditEntry,
}

impl HopAudit {
    fn new(
        log: Arc<AuditLog>,
        journal: Option<Arc<PendingCommands>>,
        callee_ctx: &InvocationContext,
        command: &str,
    ) -> Self {
        let root = callee_ctx.root();
        let path = hop_path(callee_ctx, command).expect("delegate() always appends a hop");
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
            command_id: None,
            command_outcome: None,
            level: None,
            caused_by: callee_ctx.caused_by().map(str::to_owned),
        };
        Self {
            log,
            journal,
            entry,
        }
    }

    /// Single-shot `deny` row. Awaited (up to `wait_until`) rather than
    /// detached: a refused call returns instantly, so without the wait
    /// a plugin looping on refused calls could queue blocking ledger
    /// writes without bound. The refusal itself never depends on the
    /// write.
    async fn record_denied(self, wait_until: tokio::time::Instant, label: &str) {
        let Self { log, mut entry, .. } = self;
        entry.status = 403;
        entry.decision = "deny".into();
        entry.required_scope = Some(label.to_owned());
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

    /// Write the intent row. The row comes back armed, so one the
    /// caller never reads (cancelled, or past its deadline, while the
    /// write ran) is finalized `error` rather than left `pending`.
    async fn record_intent(&self) -> Result<u64, String> {
        let audit = self.clone();
        let write = move || {
            let id = audit.log.record_intent(&audit.entry)?;
            Ok::<_, crate::state::AuditLogError>(ArmedIntent(Some((audit, id))))
        };
        match tokio::task::spawn_blocking(write).await {
            Ok(Ok(armed)) => Ok(armed.claim()),
            Ok(Err(err)) => Err(err.to_string()),
            Err(err) => Err(err.to_string()),
        }
    }

    /// Finalize the intent row without holding the caller's supervisor
    /// on the ledger (the intent row is already the durable evidence):
    /// queued on the command journal, which a runtime teardown can't
    /// cancel and shutdown drains. Also reached from
    /// `HopFinalizer::drop`.
    fn finalize(self, id: u64, outcome: &Result<CommandResult, WitError>) {
        let (status, decision, (execution_outcome, domain_error)) = match outcome {
            Ok(result) => (200, "allow", result_columns(result)),
            Err(_) => (503, "error", (None, None)),
        };
        let finalize = Finalize {
            id,
            finalized_ms: self.log.clock().now_unix_ms(),
            status,
            decision,
            execution_outcome,
            domain_error,
        };
        // Only through a journal on the intent's own ledger: a row id
        // means nothing in another database.
        if let Some(journal) = self.journal.filter(|j| j.journals_into(&self.log)) {
            // A closed or full journal leaves the row `pending` (logged).
            let _ = journal.finalize_audit_row(finalize);
            return;
        }
        // No journal on this ledger (unit tests): a detached blocking
        // write.
        let log = self.log;
        let write = move || {
            if let Err(err) = log.finalize(
                id,
                finalize.status,
                finalize.decision,
                None,
                finalize.execution_outcome,
                finalize.domain_error,
            ) {
                tracing::error!(target: "host.audit", error = %err, id, "service-call finalize failed");
            }
        };
        match tokio::runtime::Handle::try_current() {
            Ok(rt) => drop(rt.spawn_blocking(write)),
            Err(_) => write(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The production entry point with a caller built from explicit
    /// grant lists (its plugin id is its instance id, and no plugin
    /// has a deny list): the shape these tests were written against.
    #[allow(clippy::too_many_arguments)]
    async fn call_service(
        services: &Arc<ServiceRegistry>,
        instances: &Arc<InstanceRegistry>,
        audit: Option<&Arc<AuditLog>>,
        journal: Option<&Arc<PendingCommands>>,
        caller_instance: String,
        requested: &[ServiceGrant],
        granted: &[ServiceGrant],
        target: ServiceId,
        command: String,
        args: Vec<KeyValue>,
    ) -> Result<CommandResult, WitError> {
        let denies = crate::state::PluginDenyStore::detached();
        let caller = PluginPrincipal {
            plugin_id: &caller_instance,
            instance_id: &caller_instance,
            requested_services: requested,
            granted_services: granted,
            reads_state: &[],
            subscribes_events: false,
            denies: &denies,
        };
        super::call_service(
            services, instances, audit, journal, &caller, target, command, args,
        )
        .await
    }
    use crate::host_impl::plugin::oxidhome::plugin::services::ServiceInfo;

    /// Chain fixture: a context whose delegation chain holds one hop
    /// per `(caller, target)` pair.
    fn ctx_with_chain(pairs: &[(&str, &str)]) -> InvocationContext {
        pairs.iter().fold(
            InvocationContext::host_origin("root"),
            |ctx, (caller, target)| {
                ctx.delegate(DelegationHop {
                    caller_instance: (*caller).into(),
                    caller_plugin: "example.caller".into(),
                    target_plugin: "irrelevant".into(),
                    target_instance: (*target).into(),
                    target_service: "irrelevant".into(),
                })
            },
        )
    }

    /// M2: the dispatcher refuses undeclared commands, so the
    /// fixture declares every command the tests below call (no
    /// params, plain-`ok` reply).
    fn fixture_info(name: &str) -> ServiceInfo {
        use crate::host_impl::plugin::oxidhome::plugin::services::CommandSpec;
        ServiceInfo {
            local_id: name.into(),
            name: name.into(),
            metadata: Vec::new(),
            commands: ["kick", "get", "set", "anything", "irrelevant"]
                .into_iter()
                .map(|c| CommandSpec {
                    name: c.into(),
                    description: None,
                    params: Vec::new(),
                    returns: Vec::new(),
                })
                .collect(),
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
            None,
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
                    None,
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

    /// H6 slice 4: the root's permit is asked on every hop, not just
    /// the first. A token that may call `ring` of `com.example.alpha`
    /// (the first hop) can't have alpha's wasm call beta's `ring`,
    /// although alpha's own grant allows it.
    #[tokio::test(flavor = "current_thread")]
    #[allow(clippy::too_many_lines)]
    async fn inner_hop_needs_the_roots_permit_too() {
        use crate::auth::{
            Action, ActionSet, Actor, ActorKind, Principal, RoleDef, RoleGrant, Transport,
        };
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
        let grants = [grant_any("com.example.beta", "ring", "kick")];
        let actor = Actor::api("tok-scene", Vec::new()).with_roles(vec![Arc::new(RoleDef {
            id: "role-0123456789abcdef".into(),
            name: "scene".into(),
            grants: vec![RoleGrant {
                actions: ActionSet::of(&[Action::ServiceCall]),
                categories: None,
                devices: None,
                services: Some(vec!["com.example.alpha/ring".into()]),
            }],
            sensitive: Vec::new(),
            deny: Vec::new(),
        })]);
        // The first hop (driver → alpha) is already on the chain.
        let ctx =
            InvocationContext::external(Principal::token(ActorKind::Api, &actor, Transport::Rest))
                .delegate(DelegationHop {
                    caller_instance: "driver".into(),
                    caller_plugin: "example.caller".into(),
                    target_plugin: "com.example.alpha".into(),
                    target_instance: "alpha".into(),
                    target_service: "ring".into(),
                });
        let call_id = ctx.call_id().to_owned();
        let err = invocation::CURRENT
            .scope(
                ctx,
                call_service(
                    &services,
                    &instances,
                    Some(&audit),
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
            .expect_err("the root may not call beta");
        assert!(matches!(err, WitError::PermissionDenied(_)), "got {err:?}");
        assert_msg_contains(&err, "root principal");
        assert_eq!(services.active_call_count(&target), 0);
        let rows = audit
            .query(
                &AuditQuery {
                    call_id: Some(call_id),
                    ..AuditQuery::default()
                },
                10,
            )
            .unwrap();
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0].required_scope.as_deref(), Some("no-permit"));
        assert_eq!(rows[0].token_id, "tok-scene");

        // A wildcard command grant lets an unchecked, oversized command
        // name reach the root check: the refusal doesn't echo it whole.
        let any = [grant_any("com.example.beta", "ring", "*")];
        let ctx =
            InvocationContext::external(Principal::token(ActorKind::Api, &actor, Transport::Rest))
                .delegate(DelegationHop {
                    caller_instance: "driver".into(),
                    caller_plugin: "example.caller".into(),
                    target_plugin: "com.example.alpha".into(),
                    target_instance: "alpha".into(),
                    target_service: "ring".into(),
                });
        let err = invocation::CURRENT
            .scope(
                ctx,
                call_service(
                    &services,
                    &instances,
                    Some(&audit),
                    None,
                    "alpha".into(),
                    &any,
                    &any,
                    target.clone(),
                    "x".repeat(100_000),
                    Vec::new(),
                ),
            )
            .await
            .expect_err("still refused");
        let WitError::PermissionDenied(msg) = &err else {
            panic!("got {err:?}")
        };
        assert!(msg.len() < 1_000, "{} bytes", msg.len());
    }

    /// H6 slice 4: a reaction to an attributed event is host-rooted —
    /// the plugin's own grant decides — but audited, with `caused_by`.
    #[tokio::test(flavor = "current_thread")]
    async fn reaction_hops_are_audited_with_caused_by() {
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
        let ctx = InvocationContext::reacting_to("alpha", "call-cause");
        assert!(ctx.is_attributable());
        let _ = invocation::CURRENT
            .scope(
                ctx,
                call_service(
                    &services,
                    &instances,
                    Some(&audit),
                    None,
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
        let rows = audit
            .query(
                &AuditQuery {
                    caused_by: Some("call-cause".into()),
                    ..AuditQuery::default()
                },
                10,
            )
            .unwrap();
        assert_eq!(rows.len(), 1, "{rows:?}");
        let row = &rows[0];
        assert_eq!(row.required_scope.as_deref(), Some("consumes_services"));
        assert_eq!(row.token_id, "alpha");
        assert_eq!(row.actor_kind, "plugin");
        assert_ne!(row.call_id.as_deref(), Some("call-cause"));
    }
}
