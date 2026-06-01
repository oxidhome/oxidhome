//! Cross-plugin service dispatch — Phase 7c.
//!
//! [`call_service`] is the host-side entry point for the WIT
//! `host-services::call-service` import. It resolves the target
//! service to its owning instance, rejects recursion (A→…→A) at
//! *instance* granularity, races the owning instance's
//! `execute-service-command` against a deadline, and returns the
//! result.
//!
//! ## Recursion-stack design
//!
//! The chain of in-flight `call-service` invocations on the *current
//! tokio task* lives in a [`tokio::task_local`]. The dispatcher:
//!
//! 1. Resolves `target_service` → `target_instance` via the engine's
//!    `ServiceRegistry`.
//! 2. Walks the task-local stack; if any frame's target instance is
//!    the same as `target_instance`, returns `Error::InvalidArgument`
//!    naming the cycle. **Instance granularity, not service**: a
//!    scripting plugin's same-instance peer scripts must use the
//!    plugin's *internal* dispatch — going through the host's
//!    `call-service` would deadlock the single `Store`.
//! 3. Pushes a frame with `(caller_instance, target_instance,
//!    target_service)`, bumps the registry's [`CallGuard`] refcount
//!    so `remove-service` refuses while this call is alive, sends an
//!    `ExecuteService` mpsc to the owner's supervisor task — the
//!    supervisor rebuilds the stack in `CALL_STACK::scope` on its own
//!    task before driving the wasm — races the result against the
//!    dispatcher timeout, then pops + releases.
//!
//! Cycle detection works across tasks: the caller's task-local frame
//! is *copied* into the `ExecuteService` message, and the callee's
//! supervisor enters a `CALL_STACK::scope(parent_frames, ...)` before
//! dispatching, so a deeper recursive `call-service` from inside the
//! callee sees the full chain.

use std::sync::Arc;
use std::time::Duration;

use tokio::task_local;

use crate::host_impl::plugin::oxidhome::plugin::devices::CommandResult;
use crate::host_impl::plugin::oxidhome::plugin::types::{Error as WitError, KeyValue, ServiceId};
use crate::state::ServiceRegistry;

use super::lifecycle::InstanceHandle;
use super::registry::InstanceRegistry;

/// One frame on the recursion stack. `target_instance` is the unit of
/// cycle detection; the other fields are kept for diagnostics and for
/// the Phase-12+ structured trace surface (audit-log per `call-service`
/// hop) that consumes them.
#[derive(Debug, Clone)]
pub(crate) struct CallFrame {
    #[allow(dead_code)] // diagnostic / future audit-log field
    pub caller_instance: String,
    pub target_instance: String,
    #[allow(dead_code)] // diagnostic / future audit-log field
    pub target_service: ServiceId,
}

task_local! {
    /// Chain of in-flight `call-service` invocations on the current
    /// tokio task. Outermost first; the current call is the last
    /// entry. Unset / empty ⇒ no service call in progress (the normal
    /// case for `init`, `tick`, `execute-command`, `on-event` entry
    /// points).
    static CALL_STACK: Vec<CallFrame>;
}

/// Per-dispatcher-call wall-clock timeout. Independent of the
/// per-call liveness watchdog (which lives on the *callee's* store
/// and traps wasm that doesn't yield) — this one bounds how long the
/// caller waits for a reply on the dispatch channel. Generous on
/// purpose; a legitimate cross-plugin call shouldn't be slow.
pub(crate) const DISPATCH_TIMEOUT: Duration = Duration::from_secs(30);

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
    // 1. Resolve the target service to its owning instance. Cross-
    //    instance lookup — the caller is allowed to see *this one*
    //    service it's about to call.
    let meta = services.get_any(&target).await?;
    let target_instance = meta.owner_instance.clone();

    // 2. Cycle detection at instance granularity. CALL_STACK isn't
    //    set on the outermost call (`try_with` returns Err); treat
    //    that as "empty chain, no cycle".
    let already_on_chain = CALL_STACK
        .try_with(|stack| stack.iter().any(|f| f.target_instance == target_instance))
        .unwrap_or(false);
    if already_on_chain {
        return Err(WitError::InvalidArgument(format!(
            "recursion detected: instance `{target_instance}` is already on the call chain \
             (target service `{target}`)"
        )));
    }

    // 3. Resolve target instance handle; refuse if it isn't running.
    let target_handle = instances.get(&target_instance).ok_or_else(|| {
        WitError::Unavailable(format!(
            "service `{target}` owner instance `{target_instance}` is not running"
        ))
    })?;

    // 4. Bump the active-call refcount so `remove-service` refuses
    //    while we're dispatching. Held across the whole call; the
    //    `release().await` below covers both Ok and Err paths.
    let guard = services.acquire_call(&target).await?;

    // 5. Build the next stack frame and dispatch under it. Inherit
    //    the parent stack (if any) so a deeper `call-service` from
    //    inside the callee's handler sees the full chain.
    let next_frame = CallFrame {
        caller_instance,
        target_instance,
        target_service: target.clone(),
    };
    let parent_stack: Vec<CallFrame> = CALL_STACK
        .try_with(Clone::clone)
        .unwrap_or_else(|_| Vec::new());
    let mut full_stack = parent_stack;
    full_stack.push(next_frame);

    let dispatch_future = CALL_STACK.scope(
        full_stack,
        dispatch_one(&target_handle, target, command, args),
    );

    let outcome = match tokio::time::timeout(DISPATCH_TIMEOUT, dispatch_future).await {
        Ok(result) => result,
        Err(_) => Err(WitError::Unavailable(format!(
            "call-service dispatch timed out after {} ms",
            DISPATCH_TIMEOUT.as_millis(),
        ))),
    };

    guard.release().await;
    outcome
}

/// Drive the actual handle call. Separated so [`call_service`] can
/// wrap it in `CALL_STACK::scope` cleanly.
async fn dispatch_one(
    target_handle: &InstanceHandle,
    target: ServiceId,
    command: String,
    args: Vec<KeyValue>,
) -> Result<CommandResult, WitError> {
    match target_handle
        .execute_service_command(target.clone(), command, args)
        .await
    {
        Ok(result) => Ok(result),
        Err(trap) => Err(WitError::Unavailable(format!(
            "call-service to `{target}` failed: {trap:#}"
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
        // `unwrap_or(false)` cycle check.
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

    /// Cycle detection fires *before* `instances.get(...)` so an
    /// in-process test (no wasm, no `InstanceHandle`) can prove the
    /// policy. Owner-instance "alpha" already on the stack ⇒
    /// `call_service(target: svc-0 owned by alpha)` → `InvalidArgument`.
    #[tokio::test(flavor = "current_thread")]
    async fn rejects_self_call_with_invalid_argument() {
        let services = Arc::new(ServiceRegistry::new());
        let svc_id = services
            .register(
                "alpha".into(),
                ServiceInfo {
                    local_id: "counter".into(),
                    name: "counter".into(),
                    metadata: Vec::new(),
                    commands: Vec::new(),
                },
            )
            .await;
        let instances = Arc::new(InstanceRegistry::new());

        // Pre-seed the task-local with a frame whose `target_instance`
        // matches what the dispatcher will resolve from `svc_id`'s
        // owner, simulating an in-flight outer call.
        let outer = vec![CallFrame {
            caller_instance: "outer".into(),
            target_instance: "alpha".into(),
            target_service: "outer-svc".into(),
        }];
        let outcome = CALL_STACK
            .scope(
                outer,
                call_service(
                    &services,
                    &instances,
                    "alpha".into(),
                    svc_id.clone(),
                    "increment".into(),
                    Vec::new(),
                ),
            )
            .await;

        let err = outcome.expect_err("self-call must be rejected");
        assert!(
            matches!(err, WitError::InvalidArgument(_)),
            "expected InvalidArgument, got {err:?}",
        );
        let msg = format!("{err:?}").to_ascii_lowercase();
        assert!(msg.contains("recursion"), "expected `recursion` in: {msg}");

        // Active-call refcount stays 0 — the bail happens before
        // `acquire_call`.
        assert_eq!(services.active_call_count(&svc_id).await, 0);
    }
}
