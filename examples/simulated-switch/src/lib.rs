//! OxidHome Phase 3 example: a software-only switch.
//!
//! On `init` the plugin registers one device with the `switch`
//! capability and remembers the host-assigned `device-id`. Commands
//! addressed to that device are matched on `(capability, action)`:
//! `switch::set` accepts a `state` arg, `switch::toggle` flips the
//! current value. Every state change is published as a `state-changed`
//! event so host-side listeners (test harness, the future API/MCP
//! surface) can observe the lifecycle without polling.

use oxidhome_sdk::Plugin;
use oxidhome_sdk::bindings::oxidhome::plugin::capabilities::{
    CapabilitySpec, CapabilityState, Switchable,
};
use oxidhome_sdk::bindings::oxidhome::plugin::devices::{Command, CommandResult};
use oxidhome_sdk::bindings::oxidhome::plugin::types::{DeviceId, Error, KeyValue, Value};
use oxidhome_sdk::{Device, host};

#[derive(Default)]
struct SimulatedSwitch {
    /// Host-assigned id for the one device we register on `init`.
    /// `None` until init runs.
    device_id: Option<DeviceId>,
    /// Current switch state, kept in sync with what we publish.
    state: bool,
}

impl SimulatedSwitch {
    fn published_state_change(&self) -> Vec<KeyValue> {
        vec![KeyValue {
            key: "state".to_string(),
            value: Value::BoolVal(self.state),
        }]
    }
}

impl Plugin for SimulatedSwitch {
    fn init(&mut self) -> Result<(), String> {
        // Wire `tracing` into the host's logging import so the
        // `info!` calls below show up in operator output.
        let _ = oxidhome_sdk::logging::init();

        let id = host::register_device(
            Device::new("switch-1", "Simulated Switch")
                .manufacturer("OxidHome Example")
                .model("simulated-switch")
                .capability(CapabilitySpec::Switch)
                .initial_state(CapabilityState::Switch(Switchable { state: self.state })),
        )
        .map_err(|e| format!("register-device failed: {e:?}"))?;
        self.device_id = Some(id);
        oxidhome_sdk::tracing::info!("simulated-switch ready");
        Ok(())
    }

    fn shutdown(&mut self) {
        if let Some(id) = self.device_id.take() {
            // Best effort — host may already have torn the device
            // down on its own (e.g. plugin crash recovery in Phase 6).
            let _ = host::remove_device(&id);
        }
        oxidhome_sdk::tracing::info!("simulated-switch stopped");
    }

    fn execute_command(&mut self, device: String, cmd: Command) -> CommandResult {
        // Only one device per instance for now; mismatched ids are
        // a host-side routing bug.
        if self.device_id.as_deref() != Some(device.as_str()) {
            return CommandResult::Err(Error::NotFound(format!(
                "device {device} not owned by this plugin"
            )));
        }
        if cmd.capability != "switch" {
            return CommandResult::Err(Error::InvalidArgument(format!(
                "unsupported capability {}",
                cmd.capability
            )));
        }

        let new_state = match cmd.action.as_str() {
            "toggle" => !self.state,
            "set" => match arg_bool(&cmd, "state") {
                Some(v) => v,
                None => {
                    return CommandResult::Err(Error::InvalidArgument(
                        "switch::set requires a `state: bool` arg".into(),
                    ));
                }
            },
            other => {
                return CommandResult::Err(Error::InvalidArgument(format!(
                    "unsupported action switch::{other}"
                )));
            }
        };

        self.state = new_state;
        let fields = self.published_state_change();

        // The publish itself is best-effort — Phase 3's bus is
        // in-memory and never errors on a happy path, but if the
        // host gates publishes by capability (Phase 4+) we still
        // succeed the command so the device's local state is the
        // source of truth.
        if let Err(e) = host::publish_state_change(device, "switch", fields.clone()) {
            oxidhome_sdk::tracing::warn!("publish_state_change failed: {e:?}");
        }
        oxidhome_sdk::tracing::info!(state = self.state, "switch state changed");

        CommandResult::OkWithState(fields)
    }
}

/// Pull a `bool`-typed argument out of a `Command::args` list by key.
fn arg_bool(cmd: &Command, key: &str) -> Option<bool> {
    cmd.args.iter().find_map(|kv| {
        if kv.key == key {
            match kv.value {
                Value::BoolVal(b) => Some(b),
                _ => None,
            }
        } else {
            None
        }
    })
}

oxidhome_sdk::plugin!(SimulatedSwitch);
