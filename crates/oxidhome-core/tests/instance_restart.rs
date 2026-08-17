//! Phase 6c — crash isolation + restart policy.
//!
//! Drives the `crasher` example (panics in `tick`, or fails `init`)
//! through the supervisor's restart machinery: `never` is terminal on
//! the first crash, `on-trap` restarts a real trap with backoff until
//! the cap, and `on-trap` treats a clean `init` failure as terminal.
//!
//! Each test injects a fast [`SupervisorTuning`] so the restart suite
//! runs in milliseconds — the production constants would make a cap
//! test take minutes of cumulative backoff.

#[path = "support.rs"]
mod support;

use std::time::Duration;

use oxidhome_core::{Engine, InstanceState, SupervisorTuning, supervise_with_tuning};

/// Fast backoff + a low restart cap so a full crash-loop completes
/// near-instantly.
fn fast_tuning() -> SupervisorTuning {
    SupervisorTuning {
        backoff_base: Duration::from_millis(10),
        backoff_max: Duration::from_millis(40),
        // Low cap: each restart reloads + recompiles the component,
        // which is the slow part under coverage instrumentation. Two
        // restarts still exercises the loop and the cap.
        max_restarts: 2,
        // Large enough that an always-crashing fixture never looks
        // "healthy" and resets the counter.
        healthy_reset: Duration::from_mins(1),
        ..SupervisorTuning::default()
    }
}

/// crasher manifest staged with a chosen `restart` policy and a fast
/// tick so the trap fires quickly.
fn crasher_manifest(restart: &str) -> String {
    format!(
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
restart = "{restart}"
"#,
    )
}

/// Under `restart = "never"`, the first tick trap is terminal — the
/// supervisor goes straight to `Failed` with no restart.
#[tokio::test(flavor = "multi_thread")]
async fn never_policy_fails_after_one_crash() {
    let wasm = support::build_example("crasher", "crasher.wasm");
    let plugin = support::stage_plugin(
        "crash-never",
        &wasm,
        "crasher.wasm",
        &crasher_manifest("never"),
    );
    let engine = Engine::new().expect("engine");

    let handle = supervise_with_tuning(
        engine,
        plugin.path().to_path_buf(),
        "crasher",
        "example.crasher",
        None,
        fast_tuning(),
    );

    match handle.wait_terminal().await {
        InstanceState::Failed { error } => {
            assert!(
                error.contains("never"),
                "expected the policy named: {error}"
            );
            assert!(error.contains("trap"), "expected a trap reason: {error}");
        }
        other => panic!("expected Failed, got {other:?}"),
    }
}

/// Under `restart = "on-trap"`, a tick trap is restarted with backoff.
/// The crasher traps every run, so the supervisor restarts until the
/// `max_restarts` cap, then goes `Failed` naming the cap.
#[tokio::test(flavor = "multi_thread")]
async fn on_trap_restarts_a_tick_trap_until_the_cap() {
    let wasm = support::build_example("crasher", "crasher.wasm");
    let plugin = support::stage_plugin(
        "crash-ontrap",
        &wasm,
        "crasher.wasm",
        &crasher_manifest("on-trap"),
    );
    let engine = Engine::new().expect("engine");
    let tuning = fast_tuning();
    let cap = tuning.max_restarts;

    let handle = supervise_with_tuning(
        engine,
        plugin.path().to_path_buf(),
        "crasher",
        "example.crasher",
        None,
        tuning,
    );

    match handle.wait_terminal().await {
        InstanceState::Failed { error } => {
            assert!(
                error.contains(&format!("gave up after {cap}")),
                "expected the cap ({cap}) named: {error}",
            );
        }
        other => panic!("expected Failed after the restart cap, got {other:?}"),
    }
}

/// Phase-6 leftover integration coverage — the
/// `healthy_reset` window resets the consecutive-restart
/// counter, so an instance that runs healthy longer than
/// `healthy_reset` before each crash can restart
/// indefinitely without hitting `max_restarts`. Unit
/// coverage of the reset decision already existed; this
/// test proves the reset is observably wired through the
/// supervisor loop end-to-end.
///
/// Setup: `max_restarts = 1`, `healthy_reset = 50ms`,
/// crasher `tick_interval_ms = 200ms` (well past
/// `healthy_reset`). Every life stays Running for
/// ~200ms before its first tick trap, which exceeds the
/// 50ms healthy window, so the counter resets to 0 on
/// each crash.
///
/// - Post-fix: the instance is still in the crash/restart
///   loop after 1s. State is one of Running / Crashed /
///   Restarting / Loading / Inited — NEVER Failed.
/// - Pre-fix (hypothetical regression where the reset is
///   dropped): after 1 crash the counter would be 1;
///   the second crash would hit `restarts >= max_restarts`
///   and Fail immediately. `Failed` would be observable
///   well within 1s.
#[tokio::test(flavor = "multi_thread")]
async fn healthy_reset_resets_consecutive_restart_counter() {
    let wasm = support::build_example("crasher", "crasher.wasm");
    let plugin = support::stage_plugin(
        "healthy-reset",
        &wasm,
        "crasher.wasm",
        // tick_interval_ms > healthy_reset so every life
        // exceeds the healthy window before crashing.
        r#"manifest_version = 1
[plugin]
id = "example.crasher"
name = "Crasher"
version = "0.1.0"
world = "plugin"
sdk_version = "0.1.0"
[runtime]
wasm = "crasher.wasm"
tick_interval_ms = 200
restart = "on-trap"
"#,
    );
    let engine = Engine::new().expect("engine");
    let tuning = SupervisorTuning {
        backoff_base: std::time::Duration::from_millis(10),
        backoff_max: std::time::Duration::from_millis(20),
        // Low cap — pre-fix, we'd Failed after the second
        // crash. Post-fix, the counter resets each life
        // and we keep going indefinitely.
        max_restarts: 1,
        // Small window; the 200ms tick interval guarantees
        // every life stays Running past this before its
        // trap.
        healthy_reset: std::time::Duration::from_millis(50),
        ..SupervisorTuning::default()
    };

    let handle = supervise_with_tuning(
        engine,
        plugin.path().to_path_buf(),
        "crasher-healthy-reset",
        "example.crasher",
        None,
        tuning,
    );
    // Round-2 F: observe THREE distinct Running states,
    // separated by two crash cycles. Pre-fix (no reset)
    // would Failed at the second crash (counter reaches
    // max_restarts=1) — the third `wait_for_running`
    // call would return Err instead of reaching Running.
    // Post-fix, every life resets the counter, so the
    // instance keeps cycling.
    //
    // Uses `tokio::time::timeout` on each phase so a
    // wedged test doesn't hang CI. Each life's Running
    // lasts ~200ms (tick_interval); reload + backoff
    // is small; 15s covers three lives plus the
    // instrumentation overhead comfortably.
    let overall = std::time::Duration::from_secs(15);
    let start = std::time::Instant::now();
    for life_ix in 1..=3u32 {
        // Wait for this life's Running. On pre-fix at
        // life 3, this returns Err(Failed) — the test
        // panics with a message pointing at the reset.
        tokio::time::timeout(
            overall.saturating_sub(start.elapsed()),
            handle.wait_for_running(),
        )
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for life {life_ix} to reach Running"))
        .unwrap_or_else(|err| {
            panic!(
                "life {life_ix} never reached Running (pre-fix: healthy_reset didn't fire, supervisor gave up); err: {err}",
            )
        });
        if life_ix == 3 {
            break;
        }
        // Wait for this life to leave Running (crash
        // starts). `watch` keeps only the latest value,
        // so we poll — the observable is "state != Running",
        // which covers every intermediate cycle state
        // even if we miss the exact Crashed→Restarting
        // transition. Bounded by the overall deadline.
        let phase_deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        while matches!(handle.state(), InstanceState::Running) {
            assert!(
                std::time::Instant::now() < phase_deadline,
                "life {life_ix} never left Running — the crasher didn't fire, so the reset property wasn't exercised",
            );
            if let InstanceState::Failed { error } = handle.state() {
                panic!(
                    "supervisor Failed while waiting for life {life_ix} to crash — pre-fix regression: {error}",
                );
            }
            tokio::task::yield_now().await;
        }
    }

    handle.stop().await.expect("stop");
}

/// Under `restart = "on-trap"`, a clean `init` failure is *not* a trap
/// — retrying a deterministic config error won't help, so it's
/// terminal. The crasher's `crash_on = "init"` override fails `init`.
#[tokio::test(flavor = "multi_thread")]
async fn on_trap_init_failure_is_terminal() {
    let _wasm = support::build_example("crasher", "crasher.wasm");
    let crasher_dir = support::workspace_root().join("examples").join("crasher");
    let engine = Engine::new().expect("engine");

    let overrides: toml::Value =
        toml::from_str("crash_on = \"init\"\n").expect("override blob parses");
    let handle = supervise_with_tuning(
        engine,
        crasher_dir,
        "crasher",
        "example.crasher",
        Some(overrides),
        fast_tuning(),
    );

    match handle.wait_terminal().await {
        InstanceState::Failed { error } => {
            assert!(
                error.contains("on-trap"),
                "expected the policy named: {error}"
            );
            assert!(
                error.contains("init failed"),
                "expected an init-failure reason: {error}",
            );
        }
        other => panic!("expected Failed, got {other:?}"),
    }
}
