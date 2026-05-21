//! Phase 7a — per-instance Wasmtime sandbox limits.
//!
//! Drives the `fuel-hog` example through the three new
//! `TrapReason` variants the supervisor classifies into:
//!
//! - `OutOfFuel` — a tick that busy-loops past `fuel_per_call`.
//! - `OutOfTimeBudget` — same busy loop with `fuel_per_call` huge and
//!   `call_timeout_ms` tight (epoch interrupt fires first).
//! - `OutOfMemory` — a tick that grows a `Vec` past `memory_max_mb`.
//!
//! Each test stages a manifest that picks one budget to trip and
//! asserts the supervisor surfaces the matching `Failed` message.

#[path = "support.rs"]
mod support;

use oxidhome_core::{Engine, InstanceState};

/// Stage a fuel-hog manifest with the chosen sandbox knobs.
fn fuel_hog_manifest(
    mode: &str,
    phase: &str,
    fuel_per_call: u64,
    memory_max_mb: u64,
    call_timeout_ms: u64,
) -> String {
    format!(
        r#"manifest_version = 1
[plugin]
id = "example.fuel-hog"
name = "Fuel Hog"
version = "0.1.0"
world = "plugin"
sdk_version = "0.1.0"
[runtime]
wasm = "fuel_hog.wasm"
tick_interval_ms = 10
restart = "never"
fuel_per_call = {fuel_per_call}
memory_max_mb = {memory_max_mb}
call_timeout_ms = {call_timeout_ms}
[config.mode]
type = "enum"
values = ["fuel", "memory"]
default = "{mode}"
[config.phase]
type = "enum"
values = ["init", "tick"]
default = "{phase}"
"#,
    )
}

/// A tick that busy-loops drains its `fuel_per_call` budget and the
/// supervisor surfaces the trap as `Failed { ... out of fuel ... }`.
#[tokio::test(flavor = "multi_thread")]
async fn out_of_fuel_lands_in_failed() {
    let wasm = support::build_example("fuel-hog", "fuel_hog.wasm");
    let plugin = support::stage_plugin(
        "sandbox-fuel",
        &wasm,
        "fuel_hog.wasm",
        // 1M fuel, huge memory + timeout — fuel runs out first.
        &fuel_hog_manifest("fuel", "tick", 1_000_000, 256, 60_000),
    );
    let engine = Engine::new().expect("engine");

    let handle = engine
        .start_instance(plugin.path().to_path_buf(), "fuel-hog", None)
        .await
        .expect("start");

    match handle.wait_terminal().await {
        InstanceState::Failed { error } => {
            assert!(
                error.contains("out of fuel"),
                "expected the fuel reason named: {error}",
            );
        }
        other => panic!("expected Failed, got {other:?}"),
    }
}

/// Same busy loop, but `fuel_per_call` is huge — the epoch deadline
/// fires first and the supervisor classifies the trap as
/// `OutOfTimeBudget`.
#[tokio::test(flavor = "multi_thread")]
async fn out_of_time_budget_lands_in_failed() {
    let wasm = support::build_example("fuel-hog", "fuel_hog.wasm");
    let plugin = support::stage_plugin(
        "sandbox-timeout",
        &wasm,
        "fuel_hog.wasm",
        // Huge fuel + memory budgets so the call_timeout_ms cap fires
        // first via the epoch interrupt.
        &fuel_hog_manifest("fuel", "tick", u64::MAX, 256, 200),
    );
    let engine = Engine::new().expect("engine");

    let handle = engine
        .start_instance(plugin.path().to_path_buf(), "fuel-hog", None)
        .await
        .expect("start");

    match handle.wait_terminal().await {
        InstanceState::Failed { error } => {
            assert!(
                error.contains("out of time budget"),
                "expected the timeout reason named: {error}",
            );
        }
        other => panic!("expected Failed, got {other:?}"),
    }
}

/// A tick that allocates past `memory_max_mb` trips the
/// `ResourceLimiter`; the supervisor classifies it as `OutOfMemory`.
#[tokio::test(flavor = "multi_thread")]
async fn out_of_memory_lands_in_failed() {
    let wasm = support::build_example("fuel-hog", "fuel_hog.wasm");
    let plugin = support::stage_plugin(
        "sandbox-memory",
        &wasm,
        "fuel_hog.wasm",
        // Huge fuel + timeout, tight memory cap → memory growth
        // refused and classified as OutOfMemory.
        &fuel_hog_manifest("memory", "tick", u64::MAX, 16, 60_000),
    );
    let engine = Engine::new().expect("engine");

    let handle = engine
        .start_instance(plugin.path().to_path_buf(), "fuel-hog", None)
        .await
        .expect("start");

    match handle.wait_terminal().await {
        InstanceState::Failed { error } => {
            assert!(
                error.contains("out of memory"),
                "expected the memory reason named: {error}",
            );
        }
        other => panic!("expected Failed, got {other:?}"),
    }
}
