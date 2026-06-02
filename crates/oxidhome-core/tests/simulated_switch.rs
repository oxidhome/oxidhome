//! Phase 3 end-to-end test.
//!
//! Loads `examples/simulated-switch`, drives `init` → `execute_command`
//! → `shutdown`, and verifies:
//!
//! 1. The plugin registered exactly one device with the `switch`
//!    capability against the host's [`DeviceRegistry`].
//! 2. The host can route a `switch::toggle` command back to that
//!    plugin instance via [`PluginInstance::execute_command`] and
//!    receive an `OkWithState` reply.
//! 3. A host-side bus subscriber sees the matching `state-changed`
//!    event with the new state.
//!
//! Like the Phase 2 test, this uses the
//! `#[tokio::test(flavor = "current_thread")]` runtime so the
//! thread-local `tracing` subscriber set up below stays active across
//! every host call. The example lives in its own Cargo workspace; the
//! test invokes `cargo build --target wasm32-wasip2 --locked` against
//! it before instantiating.

#[path = "support.rs"]
mod support;

use std::time::Duration;

use oxidhome_core::host_impl::plugin::oxidhome::plugin::devices::{
    Command as WitCommand, CommandResult,
};
use oxidhome_core::host_impl::plugin::oxidhome::plugin::events::EventPayload;
use oxidhome_core::host_impl::plugin::oxidhome::plugin::types::{KeyValue, Value};
use oxidhome_core::{Engine, PluginInstance};

#[tokio::test(flavor = "current_thread")]
async fn simulated_switch_round_trip() {
    let _ = tracing_subscriber::fmt::try_init();

    let wasm = support::build_example("simulated-switch", "simulated_switch.wasm");
    assert!(wasm.is_file(), "missing build artifact: {wasm:?}");
    let plugin_dir = support::workspace_root()
        .join("examples")
        .join("simulated-switch");

    let engine = Engine::new().expect("engine");
    let registry = engine.devices();
    let bus = engine.events();

    // Subscribe *before* loading the plugin so we don't miss the
    // first state-changed event. broadcast::Receiver is per-
    // subscriber, so this is independent of any plugin-side
    // subscribe call.
    let mut subscription = bus.subscribe_all();

    let mut instance = PluginInstance::load(&engine, &plugin_dir, "simulated_switch")
        .await
        .expect("load simulated-switch");
    instance.init().await.expect("init");

    // Plugin should have registered exactly one device, owned by
    // this instance, supporting the `switch` capability.
    let devices = registry.list();
    assert_eq!(
        devices.len(),
        1,
        "expected one registered device, got {devices:?}"
    );
    let dev = &devices[0];
    assert_eq!(dev.owner_instance, instance.instance_id());
    assert_eq!(dev.info.local_id, "switch-1");
    assert_eq!(dev.info.name, "Simulated Switch");
    assert!(
        dev.info
            .capabilities
            .iter()
            .any(|c| matches!(c, oxidhome_core::host_impl::plugin::oxidhome::plugin::capabilities::CapabilitySpec::Switch)),
        "expected `switch` capability, got {:?}",
        dev.info.capabilities,
    );
    let device_id = dev.id.clone();

    // Toggle the switch.
    let result = instance
        .execute_command(
            device_id.clone(),
            WitCommand {
                capability: "switch".into(),
                action: "toggle".into(),
                args: Vec::new(),
            },
        )
        .await
        .expect("execute_command call");

    match result {
        CommandResult::OkWithState(fields) => {
            assert_eq!(
                field_bool(&fields, "state"),
                Some(true),
                "expected new state=true after toggle, got {fields:?}"
            );
        }
        other => panic!("expected OkWithState, got {other:?}"),
    }

    // The plugin's `publish_state_change` should land on the bus.
    // `recv` is async; bound it with a timeout so a missing event
    // fails the test instead of hanging.
    let event = tokio::time::timeout(Duration::from_secs(1), subscription.receiver.recv())
        .await
        .expect("event arrived within 1s")
        .expect("subscription receiver was not lagging");

    assert_eq!(event.device.as_deref(), Some(device_id.as_str()));
    match event.payload {
        EventPayload::StateChanged(sc) => {
            assert_eq!(sc.capability, "switch");
            assert_eq!(field_bool(&sc.fields, "state"), Some(true));
        }
        other => panic!("expected StateChanged, got {other:?}"),
    }

    instance.shutdown().await.expect("shutdown");

    // After shutdown, the plugin's best-effort `remove_device`
    // should have cleared the registry.
    let devices_after = registry.list();
    assert!(
        devices_after.is_empty(),
        "expected registry empty after shutdown, got {devices_after:?}"
    );
}

fn field_bool(fields: &[KeyValue], key: &str) -> Option<bool> {
    fields.iter().find_map(|kv| {
        if kv.key == key {
            if let Value::BoolVal(b) = kv.value {
                Some(b)
            } else {
                None
            }
        } else {
            None
        }
    })
}
