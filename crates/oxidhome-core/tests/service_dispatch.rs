//! Phase 7c — cross-plugin service dispatch.
//!
//! Drives two supervised instances (`service-counter` + `service-caller`)
//! against the dispatcher: the caller drives `counter.increment` × 3
//! → `counter.get` and stores the final value in KV; the test reads
//! it back to confirm the round-trip routed correctly.
//!
//! Also covers the dispatcher's defenses: instance-granularity
//! recursion detection (a counter that calls itself rejects with
//! `InvalidArgument`) and target-not-found (`call-service` against an
//! unknown `svc-N` returns `NotFound`).

#[path = "support.rs"]
mod support;

use std::time::{Duration, Instant};

use oxidhome_core::host_impl::plugin::oxidhome::plugin::types::Value;
use oxidhome_core::{Engine, InstanceState};

/// State directory + builds for the two examples. Returns the engine
/// and the plugin dirs.
fn setup() -> (
    Engine,
    std::path::PathBuf,
    std::path::PathBuf,
    support::TempDir,
) {
    let _counter_wasm = support::build_example("service-counter", "service_counter.wasm");
    let _caller_wasm = support::build_example("service-caller", "service_caller.wasm");
    let counter_dir = support::workspace_root()
        .join("examples")
        .join("service-counter");
    let caller_dir = support::workspace_root()
        .join("examples")
        .join("service-caller");
    let state_dir = support::tempdir("dispatch-state");
    let engine = Engine::with_state_dir(state_dir.path()).expect("engine");
    (engine, counter_dir, caller_dir, state_dir)
}

/// Wait for the registry to surface the counter's `svc-N` id; mirror
/// of the Phase-6 `wait_until_unregistered` polling helper.
async fn await_service_id(engine: &Engine) -> String {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let services = engine.services().list();
        if let Some(meta) = services.first() {
            return meta.id.clone();
        }
        assert!(
            Instant::now() < deadline,
            "service not registered within 5s",
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Happy path: caller's `init` drives `counter.increment` × 3 →
/// `counter.get` via the dispatcher, and the final value lands in KV.
#[tokio::test(flavor = "multi_thread")]
async fn cross_plugin_call_service_round_trips() {
    let (engine, counter_dir, caller_dir, _state) = setup();

    // 1. Start the counter; it registers `counter` in `init`.
    let counter = engine
        .start_instance(counter_dir, "counter", None)
        .await
        .expect("start counter");
    counter.wait_for_running().await.expect("counter Running");
    let target_id = await_service_id(&engine).await;

    // 2. Start the caller with the canonical `svc-N` plugged into its
    //    config. The caller's `init` makes the four host calls and
    //    persists the final value.
    let overrides: toml::Value =
        toml::from_str(&format!("target_service_id = \"{target_id}\"\n")).expect("overrides parse");
    let caller = engine
        .start_instance(caller_dir, "caller", Some(overrides))
        .await
        .expect("start caller");
    caller.wait_for_running().await.expect("caller Running");

    // 3. The caller's KV has the final value the counter returned.
    let stored = engine
        .kv()
        .get("caller", "final_value")
        .expect("read final_value");
    assert!(
        matches!(stored, Some(Value::IntVal(3))),
        "expected counter to be 3 after 3 increments, got {stored:?}",
    );

    // Active-call refcount should be 0 after the round-trip — the
    // dispatcher's `CallGuard::release` ran on each hop.
    assert_eq!(engine.services().active_call_count(&target_id), 0);

    caller.stop().await.expect("stop caller");
    counter.stop().await.expect("stop counter");
}

/// A `target_service_id` that doesn't exist surfaces `not-found`
/// through the dispatcher and back into the guest's `init` Result.
#[tokio::test(flavor = "multi_thread")]
async fn call_service_to_unknown_target_is_not_found() {
    let (engine, _counter_dir, caller_dir, _state) = setup();

    let overrides: toml::Value =
        toml::from_str("target_service_id = \"svc-999\"\n").expect("overrides parse");
    let caller = engine
        .start_instance(caller_dir, "caller", Some(overrides))
        .await
        .expect("start caller");

    match caller.wait_terminal().await {
        InstanceState::Failed { error } => {
            let lower = error.to_ascii_lowercase();
            assert!(
                lower.contains("not") && lower.contains("found") && lower.contains("svc-999"),
                "expected a not-found mentioning svc-999, got: {error}",
            );
        }
        other => panic!("expected Failed (caller's init returns Err), got {other:?}"),
    }
}

/// Cross-task A→B→A cycle, end-to-end through wasm. Two `service-bouncer`
/// instances are configured to bounce to each other; calling A.kick
/// runs A's wasm, which calls B.kick (A's supervisor parks),
/// which runs B's wasm, which calls A.kick — the dispatcher must
/// reject *that* with `InvalidArgument` rather than letting it
/// deadlock A's supervisor for the full 30s `DISPATCH_TIMEOUT`. The
/// error rides back through B's wasm into A's wasm, surfaces as a
/// `CommandResult::Err`, and the test asserts it landed promptly.
#[tokio::test(flavor = "multi_thread")]
async fn cross_task_cycle_is_rejected_promptly() {
    use oxidhome_core::host_impl::plugin::oxidhome::plugin::devices::CommandResult;
    use oxidhome_core::host_impl::plugin::oxidhome::plugin::types::{Error as WitError, Value};
    use oxidhome_core::runtime::dispatcher;

    let _wasm = support::build_example("service-bouncer", "service_bouncer.wasm");
    let bouncer_dir = support::workspace_root()
        .join("examples")
        .join("service-bouncer");
    let state_dir = support::tempdir("dispatch-cycle-state");
    let engine = Engine::with_state_dir(state_dir.path()).expect("engine");

    // Two bouncer instances, alpha and beta.
    let alpha = engine
        .start_instance(bouncer_dir.clone(), "alpha", None)
        .await
        .expect("start alpha");
    alpha.wait_for_running().await.expect("alpha Running");
    let beta = engine
        .start_instance(bouncer_dir, "beta", None)
        .await
        .expect("start beta");
    beta.wait_for_running().await.expect("beta Running");

    // Find the svc-N each instance registered.
    let services = engine.services().list();
    let svc_a = services
        .iter()
        .find(|m| m.owner_instance == "alpha")
        .expect("alpha registered a service")
        .id
        .clone();
    let svc_b = services
        .iter()
        .find(|m| m.owner_instance == "beta")
        .expect("beta registered a service")
        .id
        .clone();

    // Wire the cycle through each plugin's per-instance KV. The
    // bouncer reads `bounce_to` on every kick.
    let kv = engine.kv();
    kv.set("alpha", "bounce_to", Value::StringVal(svc_b.clone()))
        .expect("set alpha.bounce_to");
    kv.set("beta", "bounce_to", Value::StringVal(svc_a.clone()))
        .expect("set beta.bounce_to");

    // Drive A.kick from the host. Should round-trip *quickly* —
    // before the 30s DISPATCH_TIMEOUT — with the cycle error
    // surfaced via B's wasm to A's CommandResult::Err.
    let started = std::time::Instant::now();
    let outcome = tokio::time::timeout(
        Duration::from_secs(10),
        dispatcher::call_service_from_host(
            &engine,
            "test-driver",
            svc_a.clone(),
            "kick",
            Vec::new(),
        ),
    )
    .await
    .expect("call must not exceed the test timeout");
    let elapsed = started.elapsed();

    // The dispatcher returned (didn't deadlock).
    assert!(
        elapsed < Duration::from_secs(5),
        "cycle rejection should be near-instant; took {elapsed:?}",
    );

    // The shape: A's wasm propagated B's result, which propagated the
    // dispatcher's `InvalidArgument` from the cycle check. So the
    // outermost call returns `Ok(CommandResult::Err(InvalidArgument))`
    // — the dispatcher itself sees A's wasm finishing normally.
    match outcome {
        Ok(CommandResult::Err(WitError::InvalidArgument(msg))) => {
            assert!(
                msg.to_ascii_lowercase().contains("recursion"),
                "expected `recursion` in: {msg}",
            );
        }
        other => panic!(
            "expected the cycle to surface as Ok(CommandResult::Err(InvalidArgument(\"recursion ...\"))), got {other:?}",
        ),
    }

    // Refcounts back to 0 — both guards released.
    assert_eq!(engine.services().active_call_count(&svc_a), 0);
    assert_eq!(engine.services().active_call_count(&svc_b), 0);

    alpha.stop().await.expect("stop alpha");
    beta.stop().await.expect("stop beta");
}
