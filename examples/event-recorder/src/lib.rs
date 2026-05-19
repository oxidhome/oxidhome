//! OxidHome Phase 3 example: a passive event recorder.
//!
//! Subscribes to every event on the bus during `init` and logs each
//! one through `on_event` — together with `examples/simulated-switch`
//! it exercises the plugin-side dispatch path. It also keeps a running
//! count of received events, readable via the `recorder::count`
//! command, so Phase 6's tokio supervisor can prove event delivery
//! through an [`InstanceHandle`] without scraping logs.

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
        if cmd.capability != "recorder" || cmd.action != "count" {
            return CommandResult::Err(Error::InvalidArgument(format!(
                "unsupported {}::{}",
                cmd.capability, cmd.action,
            )));
        }
        CommandResult::OkWithState(vec![KeyValue {
            key: "count".into(),
            value: Value::IntVal(self.count),
        }])
    }
}

oxidhome_sdk::plugin!(EventRecorder);
