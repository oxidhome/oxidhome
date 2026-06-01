//! Phase 6d — instance registry + singleton + multi-instance.
//!
//! Drives `Engine::start_instance` against the registry: singleton
//! plugins reject a second start, multi-instance plugins coexist with
//! different config overrides, and an instance terminating frees its
//! slot (so a fresh `start_instance` for the same id succeeds).

#[path = "support.rs"]
mod support;

use std::time::{Duration, Instant};

use oxidhome_core::{Engine, InstanceState};

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
