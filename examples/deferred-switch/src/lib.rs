//! OxidHome example: a switch whose commands finish asynchronously
//! (architecture review H5, ADR-0003).
//!
//! Real devices often acknowledge a command later than the call that
//! sent it — a radio round trip, a cloud API with a job id. This plugin
//! models that: `switch::set { state }` and `switch::toggle` answer
//! [`CommandResult::Accepted`] and remember the host-minted
//! [`Command::id`]. On the next `tick` the "device" acknowledges and the
//! plugin reports the final result, with the new state, through
//! [`host::complete_command`]; the host projects that state exactly as
//! it would a synchronous `ok-with-state`. The caller sees `accepted`
//! right away; the final outcome lands in the host's audit trail.
//!
//! A `lost: true` argument simulates a device that never acknowledges:
//! the command stays pending until the host expires it and records
//! `outcome_unknown`. Any other capability or action is refused with
//! `err`, which the host reports as `rejected`.

use oxidhome_sdk::Plugin;
use oxidhome_sdk::bindings::oxidhome::plugin::capabilities::{
    CapabilitySpec, CapabilityState, Switchable,
};
use oxidhome_sdk::bindings::oxidhome::plugin::devices::{Command, CommandResult};
use oxidhome_sdk::bindings::oxidhome::plugin::types::{DeviceId, Error, KeyValue, Value};
use oxidhome_sdk::{Device, host};

#[derive(Default)]
struct DeferredSwitch {
    device_id: Option<DeviceId>,
    state: bool,
    /// Accepted commands waiting for the next tick: `(command id,
    /// requested state)`.
    in_flight: Vec<(String, bool)>,
}

impl Plugin for DeferredSwitch {
    fn init(&mut self) -> Result<(), String> {
        let _ = oxidhome_sdk::logging::init();
        let id = host::register_device(
            Device::new("switch-1", "Deferred Switch")
                .manufacturer("OxidHome Example")
                .model("deferred-switch")
                .capability(CapabilitySpec::Switch)
                .initial_state(CapabilityState::Switch(Switchable { state: false })),
        )
        .map_err(|e| format!("register-device failed: {e:?}"))?;
        self.device_id = Some(id);
        Ok(())
    }

    fn shutdown(&mut self) {
        if let Some(id) = self.device_id.take() {
            let _ = host::remove_device(&id);
        }
    }

    fn execute_command(&mut self, device: String, cmd: Command) -> CommandResult {
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
        // The state the device will end up in once this command and
        // every command already in flight land.
        let current = self.in_flight.last().map_or(self.state, |&(_, s)| s);
        let target = match cmd.action.as_str() {
            "toggle" => !current,
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
        // Simulated lost acknowledgement: hold the command forever.
        if arg_bool(&cmd, "lost") != Some(true) {
            self.in_flight.push((cmd.id, target));
        }
        CommandResult::Accepted
    }

    fn tick(&mut self) {
        if self.device_id.is_none() {
            return;
        }
        for (command_id, target) in std::mem::take(&mut self.in_flight) {
            self.state = target;
            let fields = vec![KeyValue {
                key: "state".to_string(),
                value: Value::BoolVal(target),
            }];
            if let Err(e) = host::complete_command(&command_id, &CommandResult::OkWithState(fields)) {
                // `not-found`: the host already expired the command.
                oxidhome_sdk::tracing::warn!("complete_command {command_id} failed: {e:?}");
            }
        }
    }
}

fn arg_bool(cmd: &Command, key: &str) -> Option<bool> {
    cmd.args.iter().find_map(|kv| match (&kv.value, kv.key == key) {
        (Value::BoolVal(b), true) => Some(*b),
        _ => None,
    })
}

oxidhome_sdk::plugin!(DeferredSwitch);
