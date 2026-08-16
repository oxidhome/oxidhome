//! Phase 6d — instance registry + singleton + multi-instance.
//!
//! Drives `Engine::start_instance` against the registry: singleton
//! plugins reject a second start, multi-instance plugins coexist with
//! different config overrides, and an instance terminating frees its
//! slot (so a fresh `start_instance` for the same id succeeds).

#[path = "support.rs"]
mod support;

use std::time::{Duration, Instant};

use oxidhome_core::{Engine, InstanceState, SupervisorTuning};

/// simulated-switch manifest staged with a chosen `singleton` flag.
/// Mirrors the real example's `[capabilities].declares_devices` so
/// `init` actually registers a device.
fn switch_manifest(singleton: bool) -> String {
    format!(
        r#"manifest_version = 1
[plugin]
id = "example.simulated-switch"
name = "Simulated Switch"
version = "0.1.0"
world = "plugin"
sdk_version = "0.1.0"
[runtime]
wasm = "simulated_switch.wasm"
singleton = {singleton}
[capabilities]
declares_devices = ["switch"]
[config.default_state]
type = "bool"
default = false
description = "Initial state."
"#,
    )
}

/// A plugin declaring `singleton = true` rejects a second
/// `start_instance` — even with a different instance id.
#[tokio::test(flavor = "multi_thread")]
async fn singleton_rejects_second_instance() {
    let wasm = support::build_example("simulated-switch", "simulated_switch.wasm");
    let plugin = support::stage_plugin(
        "registry-singleton",
        &wasm,
        "simulated_switch.wasm",
        &switch_manifest(true),
    );
    let engine = Engine::new().expect("engine");

    let first = engine
        .start_instance(plugin.path().to_path_buf(), "switch-a", None)
        .await
        .expect("first start");
    first
        .wait_for_running()
        .await
        .expect("first reaches Running");

    let err = engine
        .start_instance(plugin.path().to_path_buf(), "switch-b", None)
        .await
        .expect_err("second singleton start must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("singleton") && msg.contains("example.simulated-switch"),
        "expected singleton rejection mentioning the plugin id: {msg}",
    );

    first.stop().await.expect("stop");
}

/// A non-singleton plugin runs two instances side by side, each with
/// its own config overrides — the device registry sees two devices
/// owned by the two instances.
#[tokio::test(flavor = "multi_thread")]
async fn multi_instance_runs_two_with_distinct_overrides() {
    let _wasm = support::build_example("simulated-switch", "simulated_switch.wasm");
    let switch_dir = support::workspace_root()
        .join("examples")
        .join("simulated-switch");
    let engine = Engine::new().expect("engine");

    // Each instance opts into a different `default_state` so the
    // registered devices end up with different initial state.
    let on_overrides: toml::Value =
        toml::from_str("default_state = true\n").expect("override blob parses");

    let inst_off = engine
        .start_instance(switch_dir.clone(), "switch-off", None)
        .await
        .expect("off start");
    let inst_on = engine
        .start_instance(switch_dir, "switch-on", Some(on_overrides))
        .await
        .expect("on start");
    inst_off.wait_for_running().await.expect("off Running");
    inst_on.wait_for_running().await.expect("on Running");

    let devices = engine.devices().list();
    assert_eq!(devices.len(), 2, "expected two devices, got {devices:?}");
    let mut owners: Vec<&str> = devices.iter().map(|d| d.owner_instance.as_str()).collect();
    owners.sort_unstable();
    assert_eq!(owners, vec!["switch-off", "switch-on"]);

    inst_off.stop().await.expect("stop off");
    inst_on.stop().await.expect("stop on");
}

/// Two `start_instance` calls with the same `instance_id` are
/// rejected at the registry, even for a non-singleton plugin.
#[tokio::test(flavor = "multi_thread")]
async fn duplicate_instance_id_rejected() {
    let _wasm = support::build_example("simulated-switch", "simulated_switch.wasm");
    let switch_dir = support::workspace_root()
        .join("examples")
        .join("simulated-switch");
    let engine = Engine::new().expect("engine");

    let first = engine
        .start_instance(switch_dir.clone(), "switch-dup", None)
        .await
        .expect("first start");
    first.wait_for_running().await.expect("first Running");

    let err = engine
        .start_instance(switch_dir, "switch-dup", None)
        .await
        .expect_err("duplicate id must be rejected");
    assert!(
        err.to_string().contains("switch-dup"),
        "expected the duplicate id in the error: {err}",
    );

    first.stop().await.expect("stop");
}

/// Once a singleton instance terminates, the reaper frees its slot —
/// a fresh `start_instance` for the same plugin then succeeds.
#[tokio::test(flavor = "multi_thread")]
async fn terminated_singleton_slot_is_reclaimed() {
    let wasm = support::build_example("simulated-switch", "simulated_switch.wasm");
    let plugin = support::stage_plugin(
        "registry-reclaim",
        &wasm,
        "simulated_switch.wasm",
        &switch_manifest(true),
    );
    let engine = Engine::new().expect("engine");

    let first = engine
        .start_instance(plugin.path().to_path_buf(), "switch-1", None)
        .await
        .expect("first start");
    first.wait_for_running().await.expect("first Running");
    first.stop().await.expect("stop");
    assert_eq!(first.wait_terminal().await, InstanceState::Stopped);

    // The reaper task runs as soon as `wait_terminal` resolves, but
    // it's a separate spawned task — poll the registry until it
    // unregisters the slot rather than racing it.
    wait_until_unregistered(&engine, "switch-1").await;

    let second = engine
        .start_instance(plugin.path().to_path_buf(), "switch-2", None)
        .await
        .expect("second start after the slot frees");
    second.wait_for_running().await.expect("second Running");
    second.stop().await.expect("stop");
}

async fn wait_until_unregistered(engine: &Engine, instance_id: &str) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if engine.instance(instance_id).is_none() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("instance `{instance_id}` not unregistered within 5s");
}

/// Phase 6 leftover: `Engine::drain_supervised_instances`
/// awaits every reaper's `JoinHandle` (previously discarded
/// as a fire-and-forget `tokio::spawn`) so graceful daemon
/// shutdown can wait for per-instance cleanup (device /
/// service registry eviction, device-state stale marking,
/// `instances.unregister`) before the process exits. Test
/// starts multiple instances, sends `stop` to each, then
/// drains — after drain, every instance is unregistered
/// AND every device is evicted.
#[tokio::test(flavor = "multi_thread")]
async fn drain_awaits_reaper_cleanup_for_every_instance() {
    let _wasm = support::build_example("simulated-switch", "simulated_switch.wasm");
    let switch_dir = support::workspace_root()
        .join("examples")
        .join("simulated-switch");
    let engine = Engine::new().expect("engine");

    let a = engine
        .start_instance(switch_dir.clone(), "drain-a", None)
        .await
        .expect("start a");
    let b = engine
        .start_instance(switch_dir.clone(), "drain-b", None)
        .await
        .expect("start b");
    let c = engine
        .start_instance(switch_dir, "drain-c", None)
        .await
        .expect("start c");
    a.wait_for_running().await.expect("a Running");
    b.wait_for_running().await.expect("b Running");
    c.wait_for_running().await.expect("c Running");
    assert_eq!(engine.devices().list().len(), 3);

    a.stop().await.expect("stop a");
    b.stop().await.expect("stop b");
    c.stop().await.expect("stop c");

    // Drain awaits every reaper — no polling loop, no
    // arbitrary sleep. Post-drain the tracker is empty and
    // every reaper's cleanup has completed.
    engine.drain_supervised_instances().await;

    assert!(engine.instance("drain-a").is_none());
    assert!(engine.instance("drain-b").is_none());
    assert!(engine.instance("drain-c").is_none());
    assert!(
        engine.devices().list().is_empty(),
        "reaper must have evicted every device",
    );

    // Idempotent: a second drain on a settled engine is a
    // no-op that returns immediately.
    engine.drain_supervised_instances().await;
}

/// Round-2 F2: a rapidly-recycled `instance_id` (start, stop,
/// start again) must NOT have its fresh tracker entry
/// clobbered by the old reaper's key-only remove. The fix
/// stamps each reaper spawn with a monotonic generation and
/// the reaper only removes if the map's stored gen still
/// matches. This test starts an instance under
/// `switch-recycle`, stops it, immediately starts a fresh
/// instance under the same id, then drains — the drain
/// must observe and await the fresh reaper.
#[tokio::test(flavor = "multi_thread")]
async fn drain_still_awaits_reaper_after_instance_id_recycle() {
    let _wasm = support::build_example("simulated-switch", "simulated_switch.wasm");
    let switch_dir = support::workspace_root()
        .join("examples")
        .join("simulated-switch");
    let engine = Engine::new().expect("engine");

    let first = engine
        .start_instance(switch_dir.clone(), "switch-recycle", None)
        .await
        .expect("first start");
    first.wait_for_running().await.expect("first Running");
    first.stop().await.expect("stop first");
    assert_eq!(first.wait_terminal().await, InstanceState::Stopped);
    wait_until_unregistered(&engine, "switch-recycle").await;

    // Fresh start on the same id — pre-fix, if the old
    // reaper hadn't yet removed its tracker entry, the new
    // entry would replace it; if the old reaper THEN fired
    // its key-only remove, the new entry vanished and a
    // subsequent drain silently skipped the new reaper.
    let second = engine
        .start_instance(switch_dir, "switch-recycle", None)
        .await
        .expect("second start reuses the id");
    second.wait_for_running().await.expect("second Running");
    second.stop().await.expect("stop second");

    // Drain must actually await the fresh reaper's cleanup
    // — asserted indirectly by checking the device registry
    // is empty post-drain (only the fresh reaper's cleanup
    // can evict the device it registered).
    engine.drain_supervised_instances().await;
    assert!(
        engine.instance("switch-recycle").is_none(),
        "post-drain, the recycled id must be unregistered by the fresh reaper",
    );
    assert!(
        engine.devices().list().is_empty(),
        "post-drain, the recycled instance's device must be evicted",
    );
}

/// Round-3 F1: an operator-requested shutdown that traps
/// mid-teardown must be terminal — regardless of the
/// manifest's `restart = "on-trap"` policy. Pre-fix, the
/// serve loop propagated the shutdown trap through `?`,
/// which funneled the outcome into `ServeOutcome::Crashed`
/// and the outer supervisor then restarted the instance
/// the operator had just asked to stop.
#[tokio::test(flavor = "multi_thread")]
async fn shutdown_trap_is_terminal_not_a_restart() {
    let _wasm = support::build_example("crasher", "crasher.wasm");
    let crasher_dir = support::workspace_root().join("examples").join("crasher");
    let engine = Engine::new().expect("engine");
    // Override picks the shutdown-panic mode; the real
    // crasher manifest declares `restart = "on-trap"`, so
    // pre-fix the shutdown trap would have restarted.
    let overrides: toml::Value =
        toml::from_str("crash_on = \"shutdown\"\n").expect("override blob parses");

    let handle = engine
        .start_instance(crasher_dir, "crasher-shutdown-trap", Some(overrides))
        .await
        .expect("start");
    handle.wait_for_running().await.expect("Running");

    // Operator asks to stop; the guest's shutdown panics.
    // `stop()` still returns Ok because the supervisor
    // acked before the trap propagated.
    let _ = handle.stop().await;

    match handle.wait_terminal().await {
        InstanceState::Failed { error } => {
            assert!(
                error.contains("shutdown trapped"),
                "expected the shutdown-trap reason on the Failed transition; got: {error}",
            );
            assert!(
                !error.contains("gave up") && !error.contains("on-trap"),
                "expected NO restart-policy language (proves the shutdown was terminal, not restarted then giving up); got: {error}",
            );
        }
        other => panic!("expected Failed (round-3 F1: shutdown trap is terminal); got {other:?}"),
    }
}

/// Round-3 F1 + round-6 F1/F2/F3: the bounded drain is
/// best-effort. It returns promptly on timeout, but it
/// does NOT reclaim registry state under a live
/// supervisor — that would either (a) unregister a
/// still-running supervisor and let a duplicate id start
/// under one identity (round-5 F1), (b) mis-target
/// cleanup at a recycled reaper generation (round-5 F2),
/// or (c) deadlock on the same lock that wedged the
/// reaper (round-5 F3). Test proves the contract: the
/// timeout returns quickly with `Err(count)`, and the
/// still-running supervisor's registry entry stays
/// intact.
#[tokio::test(flavor = "multi_thread")]
async fn drain_with_timeout_is_bounded_and_leaves_live_supervisor_untouched() {
    let _wasm = support::build_example("simulated-switch", "simulated_switch.wasm");
    let switch_dir = support::workspace_root()
        .join("examples")
        .join("simulated-switch");
    let engine = Engine::new().expect("engine");
    let handle = engine
        .start_instance(switch_dir, "drain-timeout", None)
        .await
        .expect("start");
    handle.wait_for_running().await.expect("Running");
    assert_eq!(engine.devices().list().len(), 1);

    // Intentionally NOT calling stop — the supervisor is
    // still running, its reaper is blocked at
    // `wait_terminal`. Pre-round-3 an unbounded drain
    // would await forever.
    let start = Instant::now();
    let result = engine
        .drain_supervised_instances_with_timeout(Duration::from_millis(200))
        .await;
    let elapsed = start.elapsed();
    assert!(
        result.is_err(),
        "expected the bounded drain to time out and return Err(count)",
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "expected the bounded drain to return promptly after the deadline; elapsed={elapsed:?}",
    );

    // Round-6 F1/F2/F3: the still-running supervisor MUST
    // remain registered. A drain that unregistered it
    // would let a duplicate `instance_id` start alongside
    // the live supervisor.
    assert!(
        engine.instance("drain-timeout").is_some(),
        "round-6 F1: bounded drain must NOT unregister a supervisor that is still running",
    );

    // Round-6 F3: proper test teardown — stop the
    // supervisor and then poll the registry until the
    // (still-alive, but detached from our tracker) reaper
    // wakes on the terminal transition and calls
    // `registry.unregister`. Calling
    // `drain_supervised_instances` here would be a no-op
    // because the bounded drain already emptied the
    // tracker; the reaper task is running but no longer
    // observable through the drain API.
    handle.stop().await.expect("stop");
    assert_eq!(handle.wait_terminal().await, InstanceState::Stopped);
    wait_until_unregistered(&engine, "drain-timeout").await;
    assert!(
        engine.instance("drain-timeout").is_none(),
        "reaper must eventually run its unregister step once the supervisor terminates",
    );
    assert!(
        engine.devices().list().is_empty(),
        "reaper must eventually evict devices once the supervisor terminates",
    );
}

/// Round-2 F3: the pinned manifest snapshot supplied at
/// pre-flight is used on EVERY load attempt (first load
/// and every restart), not just the first — so a manifest
/// atomically replaced during restart backoff can't sneak
/// a different plugin under the same registry slot. Test
/// starts a crasher plugin that traps repeatedly under
/// `restart = "on-trap"`, then during the crash loop
/// corrupts `manifest.toml` on disk with garbage bytes. If
/// the supervisor re-read on restart (pre-fix), the
/// corrupted read would surface as a `LoadFailed` with a
/// manifest-parse error before hitting the restart cap;
/// with the pin held across restarts, the supervisor
/// keeps loading the pinned bytes and reaches the cap on
/// normal traps.
#[tokio::test(flavor = "multi_thread")]
async fn pinned_manifest_survives_disk_mutation_across_restart_backoff() {
    let wasm = support::build_example("crasher", "crasher.wasm");
    let plugin = support::stage_plugin(
        "pin-across-restart",
        &wasm,
        "crasher.wasm",
        r#"manifest_version = 1
[plugin]
id = "example.crasher"
name = "Crasher"
version = "0.1.0"
world = "plugin"
sdk_version = "0.1.0"
[runtime]
wasm = "crasher.wasm"
tick_interval_ms = 10
restart = "on-trap"
"#,
    );
    let engine = Engine::new().expect("engine");
    // Fast tuning: low cap + short backoff so the test
    // converges in seconds instead of minutes.
    let tuning = SupervisorTuning {
        backoff_base: Duration::from_millis(10),
        backoff_max: Duration::from_millis(40),
        max_restarts: 2,
        healthy_reset: Duration::from_mins(1),
        ..SupervisorTuning::default()
    };
    let handle = engine
        .start_instance_with_tuning(
            plugin.path().to_path_buf(),
            "crasher-pinned",
            None,
            oxidhome_core::runtime::LoadMode::Dev,
            tuning,
        )
        .await
        .expect("start");
    // Immediately corrupt the on-disk manifest. A
    // pre-fix re-read on the next restart would fail
    // load with a manifest-parse error.
    std::fs::write(plugin.path().join("manifest.toml"), b"this is not toml [[[")
        .expect("corrupt manifest");

    match handle.wait_terminal().await {
        InstanceState::Failed { error } => {
            // Post-fix: the supervisor kept using the pinned
            // manifest across every restart. The crasher's
            // repeated trap eventually hits the restart cap
            // and Failed names the cap.
            assert!(
                error.contains("gave up") || error.contains("trap"),
                "expected the trap-restart-cap Failed reason (proves the supervisor kept loading the pinned manifest); got: {error}",
            );
            assert!(
                !error.contains("not toml") && !error.contains("parsing"),
                "expected NO manifest-parse error (a parse error means the pin was discarded on restart); got: {error}",
            );
        }
        other => panic!("expected Failed after the restart cap, got {other:?}"),
    }
}
