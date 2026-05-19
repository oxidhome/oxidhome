//! Phase 6c — crash isolation + restart policy.
//!
//! Drives the `crasher` example (panics in `tick`, or fails `init`)
//! through the supervisor's restart machinery: `never` is terminal on
//! the first crash, `on-trap` restarts a real trap with backoff, and
//! `on-trap` treats a clean `init` failure as terminal.

#[path = "support.rs"]
mod support;

use std::time::{Duration, Instant};

use oxidhome_core::{Engine, InstanceHandle, InstanceState, supervise};

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

    let handle = supervise(engine, plugin.path().to_path_buf(), "crasher", None);

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
/// The crasher traps every run, so the supervisor keeps restarting —
/// observe it reach a second restart attempt, then stop it cleanly.
#[tokio::test(flavor = "multi_thread")]
async fn on_trap_restarts_a_tick_trap() {
    let wasm = support::build_example("crasher", "crasher.wasm");
    let plugin = support::stage_plugin(
        "crash-ontrap",
        &wasm,
        "crasher.wasm",
        &crasher_manifest("on-trap"),
    );
    let engine = Engine::new().expect("engine");

    let handle = supervise(engine, plugin.path().to_path_buf(), "crasher", None);

    let attempts = wait_for_restart_attempt(&handle, 2).await;
    assert!(
        attempts >= 2,
        "expected >=2 restart attempts, saw {attempts}"
    );

    handle.stop().await.expect("stop");
    assert_eq!(handle.wait_terminal().await, InstanceState::Stopped);
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
    let handle = supervise(engine, crasher_dir, "crasher", Some(overrides));

    match handle.wait_terminal().await {
        InstanceState::Failed { error } => {
            assert!(
                error.contains("on-trap"),
                "expected the policy named: {error}"
            );
            assert!(
                error.contains("init failed"),
                "expected an init-failure reason: {error}"
            );
        }
        other => panic!("expected Failed, got {other:?}"),
    }
}

/// Poll the handle until it reports a restart attempt `>= want` (or a
/// terminal state, or a 20s deadline). Returns the highest attempt
/// count observed across `Restarting` / `Crashed` states.
async fn wait_for_restart_attempt(handle: &InstanceHandle, want: u32) -> u32 {
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut max_seen = 0;
    loop {
        match handle.state() {
            InstanceState::Restarting { attempt } => max_seen = max_seen.max(attempt),
            InstanceState::Crashed { restarts, .. } => max_seen = max_seen.max(restarts),
            state if state.is_terminal() => return max_seen,
            _ => {}
        }
        if max_seen >= want || Instant::now() >= deadline {
            return max_seen;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}
