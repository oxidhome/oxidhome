//! OxidHome Phase 3 example: a passive event recorder.
//!
//! Subscribes to every event on the bus during `init` and logs each
//! one through `on_event` — together with `examples/simulated-switch`
//! it exercises the plugin-side dispatch path. It also keeps a running
//! count of received events, readable via the `recorder::count`
//! command, so Phase 6's tokio supervisor can prove event delivery
//! through an [`InstanceHandle`] without scraping logs.
//!
//! H2: `recorder::read-state device=<id>` and `recorder::list-state`
//! read the host's device-state projection through `host-state`.
//! Reading another plugin's devices needs a
//! `[[capabilities.reads_state]]` grant, which the shipped manifest
//! deliberately leaves out (tests stage one in).

use oxidhome_sdk::Plugin;
use oxidhome_sdk::bindings::oxidhome::plugin::devices::{Command, CommandResult};
use oxidhome_sdk::bindings::oxidhome::plugin::events::{Event, EventPayload};
use oxidhome_sdk::bindings::oxidhome::plugin::types::{Error, KeyValue, Value};
use oxidhome_sdk::host;

#[derive(Default)]
struct EventRecorder {
    /// How many events `on_event` has received this run.
    count: i64,
}

impl Plugin for EventRecorder {
    fn init(&mut self) -> Result<(), String> {
        let _ = oxidhome_sdk::logging::init();
        host::subscribe_all().map_err(|e| format!("subscribe failed: {e:?}"))?;
        oxidhome_sdk::tracing::info!("event-recorder ready");
        Ok(())
    }

    fn shutdown(&mut self) {
        oxidhome_sdk::tracing::info!("event-recorder stopped");
    }

    fn on_event(&mut self, event: Event) {
        self.count += 1;
        // Render a stable shape on every event so the integration
        // test's log-capture assertion can match deterministically.
        let topic = match &event.payload {
            EventPayload::StateChanged(sc) => sc.capability.clone(),
            EventPayload::Button(_) => "button".to_string(),
            EventPayload::Inference(_) => "inference".to_string(),
            EventPayload::Custom(c) => c.topic.clone(),
        };
        let device = event.device.as_deref().unwrap_or("<no-device>");
        oxidhome_sdk::tracing::info!(
            topic = %topic,
            device = %device,
            count = self.count,
            "event-recorder received event",
        );
    }

    fn execute_command(&mut self, _device: String, cmd: Command) -> CommandResult {
        match (cmd.capability.as_str(), cmd.action.as_str()) {
            ("recorder", "count") => CommandResult::OkWithState(vec![KeyValue {
                key: "count".into(),
                value: Value::IntVal(self.count),
            }]),
            ("recorder", "read-state") => read_state(&cmd.args),
            ("recorder", "list-state") => {
                match host::state::list_all(&host::state::StateFilter {
                    device: None,
                    capability: None,
                }) {
                    Ok(entries) => CommandResult::OkWithState(vec![KeyValue {
                        key: "entries".into(),
                        value: Value::IntVal(i64::try_from(entries.len()).unwrap_or(i64::MAX)),
                    }]),
                    Err(e) => CommandResult::Err(e),
                }
            }
            _ => CommandResult::Err(Error::InvalidArgument(format!(
                "unsupported {}::{}",
                cmd.capability, cmd.action,
            ))),
        }
    }
}

/// `recorder::read-state device=<id>`: read another device's current
/// state through the H2 `host-state` import (needs a
/// `[[capabilities.reads_state]]` grant) and echo it back as
/// `<capability>.<field>` keys plus `<capability>.quality`.
fn read_state(args: &[KeyValue]) -> CommandResult {
    let Some(Value::StringVal(device)) = args
        .iter()
        .find(|kv| kv.key == "device")
        .map(|kv| &kv.value)
    else {
        return CommandResult::Err(Error::InvalidArgument("missing `device` argument".into()));
    };
    let entries = match host::state::get(device) {
        Ok(entries) => entries,
        Err(e) => return CommandResult::Err(e),
    };
    let mut out = Vec::new();
    for entry in entries {
        let quality = if host::state::is_fresh(&entry) {
            "fresh"
        } else {
            "stale"
        };
        out.push(KeyValue {
            key: format!("{}.quality", entry.capability),
            value: Value::StringVal(quality.into()),
        });
        for kv in entry.fields {
            out.push(KeyValue {
                key: format!("{}.{}", entry.capability, kv.key),
                value: kv.value,
            });
        }
    }
    CommandResult::OkWithState(out)
}

oxidhome_sdk::plugin!(EventRecorder);
