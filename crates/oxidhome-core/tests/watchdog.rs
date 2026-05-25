//! Phase 7a — liveness watchdog.
//!
//! `OxidHome` doesn't cap plugin resources, but it must always be able
//! to reclaim a wedged instance. These tests drive the `hang` example
//! (spins forever in `init` or `tick`) and assert the watchdog
//! interrupts the call so the supervisor reaches a terminal state
//! rather than hanging — covering both the `tick` and `init` hooks.
//!
//! A fast `SupervisorTuning::watchdog` keeps the suite quick; the
//! production default is a generous 30 s.

#[path = "support.rs"]
mod support;

use std::time::Duration;

use oxidhome_core::{Engine, InstanceState, SupervisorTuning, supervise_with_tuning};

/// Tuning with a sub-second watchdog so a hung call trips fast, and
/// `restart = never` semantics come from the staged manifest.
fn fast_watchdog_tuning() -> SupervisorTuning {
    SupervisorTuning {
        watchdog: Duration::from_millis(500),
        ..SupervisorTuning::default()
    }
}

/// `hang` manifest staged with the chosen `phase` so the spin happens
/// in `init` or `tick`.
fn hang_manifest(phase: &str) -> String {
    format!(
        r#"manifest_version = 1
[plugin]
id = "example.hang"
name = "Hang"
version = "0.1.0"
world = "plugin"
sdk_version = "0.1.0"
[runtime]
wasm = "hang.wasm"
tick_interval_ms = 10
restart = "never"
[config.phase]
type = "enum"
values = ["init", "tick"]
default = "{phase}"
"#,
    )
}

/// A `tick` that never returns is interrupted by the watchdog; the
/// supervisor records `Failed` (unresponsive) instead of hanging.
#[tokio::test(flavor = "multi_thread")]
async fn watchdog_interrupts_a_hung_tick() {
    let wasm = support::build_example("hang", "hang.wasm");
    let plugin = support::stage_plugin("watchdog-tick", &wasm, "hang.wasm", &hang_manifest("tick"));
    let engine = Engine::new().expect("engine");

    let handle = supervise_with_tuning(
        engine,
        plugin.path().to_path_buf(),
        "hang",
        None,
        fast_watchdog_tuning(),
    );

    match handle.wait_terminal().await {
        InstanceState::Failed { error } => {
            assert!(
                error.contains("unresponsive"),
                "expected the watchdog reason named: {error}",
            );
        }
        other => panic!("expected Failed, got {other:?}"),
    }
}

/// A hung `init` is interrupted too — `wait_for_running` surfaces the
/// failure rather than blocking forever.
#[tokio::test(flavor = "multi_thread")]
async fn watchdog_interrupts_a_hung_init() {
    let wasm = support::build_example("hang", "hang.wasm");
    let plugin = support::stage_plugin("watchdog-init", &wasm, "hang.wasm", &hang_manifest("init"));
    let engine = Engine::new().expect("engine");

    let handle = supervise_with_tuning(
        engine,
        plugin.path().to_path_buf(),
        "hang",
        None,
        fast_watchdog_tuning(),
    );

    let err = handle
        .wait_for_running()
        .await
        .expect_err("a hung init must not reach Running");
    assert!(err.to_string().contains("failed"), "got: {err}");

    match handle.wait_terminal().await {
        InstanceState::Failed { error } => {
            assert!(
                error.contains("unresponsive"),
                "expected the watchdog reason named: {error}",
            );
        }
        other => panic!("expected Failed, got {other:?}"),
    }
}
