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
//! `(owner_plugin_id, owner_instance, local_id)` and the requested
//! command name against the caller's structured
//! `[capabilities] consumes_services` grants. A call is authorized
//! when at least one grant entry matches all four axes (with
//! `instance` and `commands` supporting `"*"` wildcards). The check
//! keys off the service's immutable `local-id` so a callee that
//! renames its service via `update-service` cannot bypass or shadow
//! a grant. The gate runs before `acquire_call`, so a refused call
//! spends no refcount and cannot influence `remove-service` timing.

use std::sync::Arc;
use std::time::Duration;

use oxidhome_manifest::ServiceGrant;
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
    caller_grants: &[ServiceGrant],
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
        caller_grants,
        target,
        command.into(),
        args,
    )
    .await
}

/// Entry point for the `host-services::call-service` host impl.
///
/// `caller_instance` identifies *this* instance (from `PluginState`).
/// `caller_grants` is the caller's `[capabilities] consumes_services`
/// list, each entry a resource selector on `(plugin, instance,
/// service_local_id, commands)`. `target` is the host-minted
/// `service-id` the caller passed; the dispatcher resolves it through
/// `services`, checks the caller's grants against the target's
/// `(owner_plugin_id, owner_instance, local_id, command)`, and hops
/// to the owning instance's supervisor via `instances`.
pub(crate) async fn call_service(
    services: &Arc<ServiceRegistry>,
    instances: &Arc<InstanceRegistry>,
    caller_instance: String,
    caller_grants: &[ServiceGrant],
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
    //    H10: split the historical "recursion detected" message into
    //    two — the caller==target case is a WIT-surface contract
    //    ("same-instance dispatch is not supported"), the multi-hop
    //    A→B→…→A case is a genuine cycle. Both stay
    //    `InvalidArgument` on the wire; the distinct messages let
    //    operators and plugin authors tell them apart.
    let parent_chain: Vec<CallFrame> = CALL_STACK.try_with(Clone::clone).unwrap_or_default();
    if caller_instance == target_instance {
        return Err(WitError::InvalidArgument(format!(
            "same-instance dispatch is not supported: target service `{target}` is \
             owned by the calling instance `{caller_instance}`; dispatch between \
             services colocated in one instance in plugin-local code instead of \
             going through host-services::call-service"
        )));
    }
    if parent_chain
        .iter()
        .any(|f| f.caller_instance == target_instance)
    {
        return Err(WitError::InvalidArgument(format!(
            "cycle detected: instance `{target_instance}` is already on the \
             call chain (target service `{target}`); calling back into a \
             supervisor already parked on a reply would deadlock"
        )));
    }

    // 3. H10 structured capability gate. Runs before `acquire_call`
    //    so a refused call spends no refcount and cannot influence
    //    `remove-service` timing. Matches on the immutable
    //    `(plugin, instance, local_id, command)` tuple — a
    //    callee's `update-service` can't shadow or bypass the
    //    grant by renaming `name`.
    if !caller_grants.iter().any(|g| {
        g.matches(
            &target_plugin_id,
            &target_instance,
            &target_local_id,
            &command,
        )
    }) {
        return Err(WitError::PermissionDenied(format!(
            "caller `{caller_instance}` has no `consumes_services` grant \
             matching target `{target_plugin_id}` instance `{target_instance}` \
             service `{target_local_id}` command `{command}` — add a matching \
             `[[capabilities.consumes_services]]` entry to the caller's manifest"
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

    fn assert_msg_contains(err: &WitError, needle: &str) {
        let msg = format!("{err:?}").to_ascii_lowercase();
        assert!(msg.contains(needle), "expected `{needle}` in: {msg}");
    }

    /// Build a `ServiceGrant` that authorizes `command` on the
    /// `(plugin, instance='*', service=local_id)` tuple — used by
    /// the dispatcher tests that want to exercise the same-instance
    /// / cycle checks *after* the auth gate passes.
    fn grant_any(plugin: &str, local_id: &str, command: &str) -> ServiceGrant {
        ServiceGrant {
            plugin: plugin.into(),
            instance: ServiceGrant::ANY_INSTANCE.into(),
            service: local_id.into(),
            commands: vec![command.into()],
        }
    }

    /// H10: outermost (empty chain) A→A self-call is rejected with a
    /// documented same-instance error, not "recursion". The caller's
    /// grant authorizes the call so the same-instance check (which
    /// runs *after* the grant check) is what fires.
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
            "alpha".into(),
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

        let chain = vec![CallFrame {
            caller_instance: "alpha".into(),
            target_instance: "beta".into(),
            target_service: "irrelevant".into(),
        }];

        let err = CALL_STACK
            .scope(
                chain,
                call_service(
                    &services,
                    &instances,
                    "beta".into(),
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
            "alpha".into(),
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
        }];
        let err = call_service(
            &services,
            &instances,
            "alpha".into(),
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
        }];
        let err = call_service(
            &services,
            &instances,
            "alpha".into(),
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
        }];
        let err = call_service(
            &services,
            &instances,
            "alpha".into(),
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
        }];

        let err = call_service(
            &services,
            &instances,
            "alpha".into(),
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
}
