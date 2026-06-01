//! Cross-plugin service dispatch — Phase 7c.
//!
//! [`call_service`] is the host-side entry point for the WIT
//! `host-services::call-service` import. It resolves the target
//! service to its owning instance, rejects cycles at *instance*
//! granularity, races the owning instance's `execute-service-command`
//! against a deadline, and returns the result.
//!
//! ## Recursion-stack design (cross-task)
//!
//! Each supervisor task has its own `tokio::task_local` [`CALL_STACK`]
//! holding the chain of in-flight `call-service` invocations *that
//! led to whatever wasm it is currently driving*. The dispatcher:
//!
//! 1. Resolves `target_service` → `target_instance` via the engine's
//!    [`ServiceRegistry`].
//! 2. Reads the *parent* chain from `CALL_STACK` (unset on outermost
//!    calls — treated as empty) and runs the cycle check:
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
//! 5. Builds `chain = parent_chain ++ [(caller, target_instance,
//!    target_service)]` and hands it through `ControlCommand::ExecuteService`
//!    to the owner's supervisor. The owner's supervisor **scopes
//!    `CALL_STACK` to that chain on its own task** before invoking
//!    `instance.execute_service_command(...)`, so any nested
//!    `host::call_service` from inside the callee's wasm reads the
//!    full chain and the cycle check works across the task hop.
//! 6. Races the reply against [`DISPATCH_TIMEOUT`] and returns the
//!    result. The guard is owned by the supervisor's match arm at
//!    this point and drops there when the wasm call returns (or when
//!    the message is dropped without being processed — e.g. on
//!    channel close).
//!
//! **Instance granularity, not service**: same-instance peer services
//! (e.g. two scripts inside a scripting plugin) must use the plugin's
//! *internal* dispatch — going through the host's `call-service`
//! would queue an `ExecuteService` to the supervisor that's already
//! parked on us, i.e. deadlock-by-construction.

use std::sync::Arc;
use std::time::Duration;

use tokio::task_local;

use crate::host_impl::plugin::oxidhome::plugin::devices::CommandResult;
use crate::host_impl::plugin::oxidhome::plugin::types::{Error as WitError, KeyValue, ServiceId};
use crate::state::ServiceRegistry;

use super::registry::InstanceRegistry;

/// One frame on the recursion stack. `caller_instance` is the unit
/// of cycle detection (a parked-supervisor identifier — see
/// [`call_service`]); the other fields are kept for diagnostics and
/// for the Phase-12+ structured trace surface (audit-log per
/// `call-service` hop) that will consume them.
#[derive(Debug, Clone)]
pub(crate) struct CallFrame {
    pub caller_instance: String,
    #[allow(dead_code)] // diagnostic / future audit-log field
    pub target_instance: String,
    #[allow(dead_code)] // diagnostic / future audit-log field
    pub target_service: ServiceId,
}

task_local! {
    /// Chain of in-flight `call-service` invocations on the current
    /// tokio task. Outermost first. Unset / empty ⇒ no service call
    /// in progress (the normal case for `init`, `tick`,
    /// `execute-command`, `on-event` entry points).
    ///
    /// `pub(crate)` so the supervisor (in [`super::lifecycle`]) can
    /// re-scope it when receiving a `ControlCommand::ExecuteService`
    /// — that's how the chain rides across the task boundary.
    pub(crate) static CALL_STACK: Vec<CallFrame>;
}

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
pub(crate) const DISPATCH_TIMEOUT: Duration = Duration::from_secs(30);

/// Public test-only entry point. The `host-services::call-service`
/// path runs from inside a wasm `execute-service-command`; an
/// integration test that wants to drive the dispatcher from the
/// outside (e.g. to set up a cross-instance call chain) goes
/// through here.
///
/// **Not** a stable API — the `dispatcher` module is otherwise
/// `pub(crate)`. Keep this thin so the regular `call_service` path
/// is the single source of truth.
#[doc(hidden)]
pub async fn call_service_from_host(
    engine: &crate::Engine,
    caller_instance: impl Into<String>,
    target: ServiceId,
    command: impl Into<String>,
    args: Vec<KeyValue>,
) -> Result<CommandResult, WitError> {
    let services = engine.services();
    let instances = engine.instances();
    call_service(
        &services,
        &instances,
        caller_instance.into(),
        target,
        command.into(),
        args,
    )
    .await
}

/// Entry point for the `host-services::call-service` host impl.
///
/// `caller_instance` identifies *this* instance (from `PluginState`).
/// `target` is the host-minted `service-id` the caller passed; the
/// dispatcher resolves it through `services` and hops to the owning
/// instance's supervisor via `instances`.
pub(crate) async fn call_service(
    services: &Arc<ServiceRegistry>,
    instances: &Arc<InstanceRegistry>,
    caller_instance: String,
    target: ServiceId,
    command: String,
    args: Vec<KeyValue>,
) -> Result<CommandResult, WitError> {
    // 1. Resolve the target service to its owning instance. The
    //    dispatcher only needs the owner string to route, not the
    //    full meta (its `Vec<CommandSpec>` etc.) — `get_owner` is
    //    the cross-instance owner-only lookup.
    let target_instance = services
        .get_owner(&target)
        .ok_or_else(|| WitError::NotFound(format!("service {target} not registered")))?;

    // 2. Cycle detection at instance granularity.
    //
    //    The deadlock condition is: dispatching to a supervisor that
    //    is *currently parked* awaiting a reply from an upstream
    //    `call-service`. A supervisor is parked exactly while it is
    //    the **caller** in an in-flight frame — its `handle_control`
    //    is blocked on the oneshot. So the "blocked" set is the
    //    `caller_instance` of every frame on the chain *plus* this
    //    very call's caller (we're about to park them on the oneshot
    //    below). If `target_instance` is in that set, the dispatch
    //    would queue an `ExecuteService` to a supervisor that can't
    //    process it ⇒ 30s timeout deadlock. Reject up-front instead.
    //
    //    This also catches the first-hop self-call A→A (empty chain
    //    + caller == target).
    let parent_chain: Vec<CallFrame> = CALL_STACK.try_with(Clone::clone).unwrap_or_default();
    let blocked = caller_instance == target_instance
        || parent_chain
            .iter()
            .any(|f| f.caller_instance == target_instance);
    if blocked {
        return Err(WitError::InvalidArgument(format!(
            "recursion detected: instance `{target_instance}` is already on the \
             call chain (target service `{target}`); same-instance peer services \
             must use the plugin's internal dispatch, not host-services::call-service"
        )));
    }

    // 3. Resolve target instance handle; refuse if it isn't running.
    let target_handle = instances.get(&target_instance).ok_or_else(|| {
        WitError::Unavailable(format!(
            "service `{target}` owner instance `{target_instance}` is not running"
        ))
    })?;

    // 4. Acquire the in-flight refcount. The guard travels in the
    //    `ExecuteService` message — the callee's supervisor holds it
    //    across the wasm call and `Drop` decrements when the work
    //    actually finishes. This is what makes the refcount track
    //    real execution rather than the caller's wait future: if we
    //    time out below, dropping the wait future doesn't release
    //    the refcount while the supervisor is still about to run the
    //    handler. If the supervisor's mpsc is closed (send fails),
    //    the `SendError` carries the message back and the guard
    //    drops with it.
    let guard = services.acquire_call(&target)?;

    // 5. Build the chain we'll *hand to the callee*: parent + the
    //    frame for this call. The callee's supervisor wraps its
    //    `execute_service_command` in `CALL_STACK::scope(chain, ...)`
    //    on its own task, so any nested `call-service` from inside
    //    the callee's wasm sees the full chain (this is how cycle
    //    detection works across the task hop).
    let mut chain = parent_chain;
    chain.push(CallFrame {
        caller_instance,
        target_instance: target_instance.clone(),
        target_service: target.clone(),
    });

    let dispatch_future =
        target_handle.execute_service_command(chain, guard, target.clone(), command, args);
    match tokio::time::timeout(DISPATCH_TIMEOUT, dispatch_future).await {
        Ok(Ok(result)) => Ok(result),
        Ok(Err(trap)) => Err(WitError::Unavailable(format!(
            "call-service to `{target}` (owner `{target_instance}`) failed: {trap:#}"
        ))),
        Err(_) => Err(WitError::Unavailable(format!(
            "call-service to `{target}` (owner `{target_instance}`) timed out after {} ms",
            DISPATCH_TIMEOUT.as_millis(),
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_impl::plugin::oxidhome::plugin::services::ServiceInfo;

    #[tokio::test(flavor = "current_thread")]
    async fn task_local_default_to_empty_when_unset() {
        // Outside a scope, `try_with` is an Err — covered by the
        // dispatcher's `try_with(...).unwrap_or_default()` (empty
        // chain ⇒ no cycle check fires).
        assert!(CALL_STACK.try_with(Vec::is_empty).is_err());
        // Inside a scope, the stack is visible.
        let frame = CallFrame {
            caller_instance: "a".into(),
            target_instance: "b".into(),
            target_service: "svc-1".into(),
        };
        CALL_STACK
            .scope(vec![frame.clone()], async {
                let on_chain = CALL_STACK
                    .try_with(|s| s.iter().any(|f| f.target_instance == "b"))
                    .unwrap_or(false);
                assert!(on_chain);
            })
            .await;
    }

    fn fixture_info(name: &str) -> ServiceInfo {
        ServiceInfo {
            local_id: name.into(),
            name: name.into(),
            metadata: Vec::new(),
            commands: Vec::new(),
        }
    }

    fn assert_recursion(err: &WitError) {
        assert!(
            matches!(err, WitError::InvalidArgument(_)),
            "expected InvalidArgument, got {err:?}",
        );
        let msg = format!("{err:?}").to_ascii_lowercase();
        assert!(msg.contains("recursion"), "expected `recursion` in: {msg}");
    }

    /// Outermost (empty chain) A→A self-call is rejected — the
    /// predicate compares `caller_instance == target_instance` for
    /// the *current* call before consulting the chain.
    #[tokio::test(flavor = "current_thread")]
    async fn rejects_outermost_self_call() {
        let services = Arc::new(ServiceRegistry::new());
        let svc = services.register("alpha".into(), fixture_info("ring"));
        let instances = Arc::new(InstanceRegistry::new());

        let err = call_service(
            &services,
            &instances,
            "alpha".into(),
            svc.clone(),
            "kick".into(),
            Vec::new(),
        )
        .await
        .expect_err("self-call must be rejected");

        assert_recursion(&err);
        // Refcount stays 0 — the bail happens before `acquire_call`.
        assert_eq!(services.active_call_count(&svc), 0);
    }

    /// Cross-task cycle: A's supervisor is already parked awaiting
    /// B's reply (frame `{caller:A, target:B}` on the stack). B's
    /// wasm now tries to call back into A. The dispatcher must
    /// reject because A is on the *blocked-callers* set — without
    /// the fix, this would have queued an `ExecuteService` to A's
    /// already-parked supervisor and deadlocked for 30 s.
    #[tokio::test(flavor = "current_thread")]
    async fn rejects_blocked_caller_cycle() {
        let services = Arc::new(ServiceRegistry::new());
        let a_svc = services.register("alpha".into(), fixture_info("ring"));
        let _b_svc = services.register("beta".into(), fixture_info("ring"));
        let instances = Arc::new(InstanceRegistry::new());

        let chain = vec![CallFrame {
            caller_instance: "alpha".into(),
            target_instance: "beta".into(),
            target_service: "irrelevant".into(),
        }];

        // B's wasm calls A's service. `CALL_STACK` is scoped — exactly
        // what the callee's supervisor does in `handle_control`'s
        // `ExecuteService` arm.
        let err = CALL_STACK
            .scope(
                chain,
                call_service(
                    &services,
                    &instances,
                    "beta".into(),
                    a_svc.clone(),
                    "kick".into(),
                    Vec::new(),
                ),
            )
            .await
            .expect_err("cycle must be rejected");

        assert_recursion(&err);
        assert_eq!(services.active_call_count(&a_svc), 0);
    }

    /// Sanity: a linear, non-cyclic chain A→B→C→D — where D's owner
    /// is *not* on the existing caller-set {A,B,C} — passes the cycle
    /// check. The call then reaches `instances.get(...)` and fails
    /// there with `Unavailable` (delta has no real handle in this
    /// in-process test), which is the proof the check let it through.
    #[tokio::test(flavor = "current_thread")]
    async fn permits_non_cyclic_chain() {
        let services = Arc::new(ServiceRegistry::new());
        let instances = Arc::new(InstanceRegistry::new());
        let delta_svc = services.register("delta".into(), fixture_info("ring"));

        // Chain represents A→B→C in flight on gamma's task — gamma is
        // the current caller. The new target is delta, which is not
        // on the caller-set {alpha, beta, gamma}.
        let chain = vec![
            CallFrame {
                caller_instance: "alpha".into(),
                target_instance: "beta".into(),
                target_service: "irrelevant".into(),
            },
            CallFrame {
                caller_instance: "beta".into(),
                target_instance: "gamma".into(),
                target_service: "irrelevant".into(),
            },
        ];
        let err = CALL_STACK
            .scope(
                chain,
                call_service(
                    &services,
                    &instances,
                    "gamma".into(),
                    delta_svc.clone(),
                    "kick".into(),
                    Vec::new(),
                ),
            )
            .await
            .expect_err("delta isn't a real instance, so we get Unavailable");

        // Reached the `instances.get(...)` step — proves the cycle
        // check let it through.
        assert!(
            matches!(err, WitError::Unavailable(_)),
            "expected Unavailable (delta not running), got {err:?}",
        );
        assert_eq!(services.active_call_count(&delta_svc), 0);
    }
}
