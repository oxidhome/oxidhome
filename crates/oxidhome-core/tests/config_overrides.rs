//! Phase 4C end-to-end test for per-instance config overrides.
//!
//! Exercises the round trip a user override takes from
//! `host config TOML → oxidhome_manifest::merge → InstanceConfig →
//!  host_config::get_config WIT call → SDK host::config::get_typed →
//!  plugin code`.
//!
//! The simulated-switch plugin reads `default_state: bool` from
//! config in `init`, registers itself with that as the device's
//! initial state, and publishes the same value via
//! `register_device(... initial_state ...)`. We inspect the
//! registry to see what landed:
//!
//! - With no override → manifest default (`false`) → device's
//!   `Switch { state: false }`.
//! - With override `default_state = true` → device's
//!   `Switch { state: true }`.
//!
//! Closes the Phase-4C definition-of-done line in `02_sdk.md`'s
//! "Phase 4 — Configuration" entry.

#[path = "support.rs"]
mod support;

use oxidhome_core::host_impl::plugin::oxidhome::plugin::capabilities::{
    CapabilityState, Switchable,
};
use oxidhome_core::{Engine, PluginInstance};

/// Without an override, the manifest's `[config.default_state]
/// default = false` is what the plugin reads — the registered device
/// reflects that.
#[tokio::test(flavor = "current_thread")]
async fn no_override_uses_manifest_default() {
    let _wasm = support::build_example("simulated-switch", "simulated_switch.wasm");
    let plugin_dir = support::workspace_root()
        .join("examples")
        .join("simulated-switch");

    let engine = Engine::new().expect("engine");
    let mut instance = PluginInstance::load(&engine, &plugin_dir, "switch_default")
        .await
        .expect("load");
    instance.init().await.expect("init");

    let state = registered_switch_state(&engine, instance.instance_id());
    assert!(
        !state,
        "manifest default is `false`; expected initial state false, got {state}",
    );

    instance.shutdown().await.expect("shutdown");
}

/// A user override `default_state = true` flips the initial state.
/// Same wasm, same manifest — only the override changes.
#[tokio::test(flavor = "current_thread")]
async fn override_flips_default_state() {
    let _wasm = support::build_example("simulated-switch", "simulated_switch.wasm");
    let plugin_dir = support::workspace_root()
        .join("examples")
        .join("simulated-switch");

    // Build the per-instance override blob the host's loader merges
    // into the manifest's `[config]` defaults.
    let mut overrides = toml::value::Table::new();
    overrides.insert("default_state".into(), toml::Value::Boolean(true));
    let overrides = toml::Value::Table(overrides);

    let engine = Engine::new().expect("engine");
    let mut instance = PluginInstance::load_with_overrides(
        &engine,
        &plugin_dir,
        "switch_override",
        Some(&overrides),
    )
    .await
    .expect("load with override");
    instance.init().await.expect("init");

    let state = registered_switch_state(&engine, instance.instance_id());
    assert!(
        state,
        "override sets `default_state = true`; expected initial state true, got {state}",
    );

    instance.shutdown().await.expect("shutdown");
}

/// Look up the one device this instance registered and extract the
/// `Switch(state)` from its `initial_state`. Panics if anything
/// doesn't match — these are integration assertions about the
/// shape the plugin should have produced.
fn registered_switch_state(engine: &Engine, instance_id: &str) -> bool {
    let devices = engine.devices().list();
    let meta = devices
        .into_iter()
        .find(|m| m.owner_instance == instance_id)
        .expect("plugin registered exactly one device");
    meta.info
        .initial_state
        .iter()
        .find_map(|s| match s {
            CapabilityState::Switch(Switchable { state }) => Some(*state),
            _ => None,
        })
        .expect("device has a Switch capability state")
}
