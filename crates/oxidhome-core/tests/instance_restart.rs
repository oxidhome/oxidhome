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

    let handle =
        supervise_with_tuning(engine, plugin.path().to_path_buf(), "crasher", None, tuning);

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
