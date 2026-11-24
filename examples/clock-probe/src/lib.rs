//! OxidHome test fixture: a plugin that reports the time it sees.
//!
//! On every `tick` it publishes a bus-only `clock` custom event whose
//! payload is what the guest's WASI clocks read: wall-clock Unix
//! milliseconds (`wall_ms`) and monotonic milliseconds since `init`
//! (`mono_ms`). A host on a virtual clock (`oxidhome-test-host`) can
//! then check the guest sees virtual time, not real time.

use std::time::{Instant, SystemTime, UNIX_EPOCH};

use oxidhome_sdk::{Plugin, host};

#[derive(Default)]
struct ClockProbe {
    started: Option<Instant>,
}

impl Plugin for ClockProbe {
    fn init(&mut self) -> Result<(), String> {
        self.started = Some(Instant::now());
        Ok(())
    }

    fn shutdown(&mut self) {}

    fn tick(&mut self) {
        let wall_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_millis());
        let mono_ms = self.started.map_or(0, |s| s.elapsed().as_millis());
        let payload = format!("{{\"wall_ms\":{wall_ms},\"mono_ms\":{mono_ms}}}");
        let _ = host::publish_custom_event(None, "clock", payload);
    }
}

oxidhome_sdk::plugin!(ClockProbe);
