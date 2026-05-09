//! OxidHome Phase 3 example: a passive event recorder.
//!
//! Subscribes to every event on the bus during `init` and logs each
//! one through `on_event` — together with `examples/simulated-switch`
//! it exercises the plugin-side dispatch path, so a future Phase 6
//! tokio-driven scheduler swaps in cleanly. No devices, no commands,
//! no state; the plugin exists purely to make plugin-side event
//! delivery observable in the integration test.

use oxidhome_sdk::Plugin;
use oxidhome_sdk::bindings::oxidhome::plugin::events::{Event, EventPayload};
use oxidhome_sdk::host;

#[derive(Default)]
struct EventRecorder;

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
            "event-recorder received event",
        );
    }
}

oxidhome_sdk::plugin!(EventRecorder);
