//! `tracing` ↔ host `logging` import bridge.
//!
//! Plugin authors write idiomatic `tracing::info!("...")` calls inside
//! their plugin; [`init`] installs a global subscriber that forwards
//! every event to the host's `logging::log(level, message)` import.
//!
//! Phase 2 forwards level + a formatted message only — `logging::log`
//! takes `(level, string)` in the 0.1 WIT. Structured fields land in
//! Phase 5 when the WIT grows a `fields` parameter; the bridge will
//! start forwarding fields then. Until then, fields are formatted into
//! the message string by `tracing-subscriber`'s default formatter, so
//! they aren't lost — they just aren't typed on the wire.

use core::fmt::Write as _;

use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};

use crate::bindings::oxidhome::plugin::logging::{self as host_logging, Level as WitLevel};

/// Install the bridge as the **global** `tracing` subscriber. Idempotent
/// in the sense that it returns an error on second call (matching
/// `tracing::subscriber::set_global_default`); plugins should call this
/// once at the top of [`Plugin::init`](crate::Plugin::init).
///
/// # Errors
///
/// Returns the original `SetGlobalDefaultError` if a global subscriber
/// is already installed for the current process. Callers that don't
/// care can `let _ = oxidhome_sdk::logging::init();`.
pub fn init() -> Result<(), tracing::subscriber::SetGlobalDefaultError> {
    tracing::subscriber::set_global_default(HostLogBridge)
}

/// Subscriber that turns every `tracing::Event` into a single
/// `host_logging::log(level, formatted_message)` call.
struct HostLogBridge;

impl Subscriber for HostLogBridge {
    fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        // Spans are no-ops in Phase 2 — Phase 5 wires per-event field
        // capture (and span field propagation). We still have to return a
        // valid Id; use a constant non-zero value.
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

    fn event(&self, event: &Event<'_>) {
        let level = wit_level(*event.metadata().level());
        let mut visitor = MessageVisitor::default();
        event.record(&mut visitor);
        host_logging::log(level, &visitor.finish());
    }

    fn enter(&self, _span: &tracing::span::Id) {}
    fn exit(&self, _span: &tracing::span::Id) {}
}

fn wit_level(level: Level) -> WitLevel {
    match level {
        Level::TRACE => WitLevel::Trace,
        Level::DEBUG => WitLevel::Debug,
        Level::INFO => WitLevel::Info,
        Level::WARN => WitLevel::Warn,
        Level::ERROR => WitLevel::Error,
    }
}

/// Pulls the `message` field out of an event and concatenates other
/// fields as `key=value` text. This is the same shape Phase 2 of the
/// host produces for plugin events, so the round-trip looks consistent.
#[derive(Default)]
struct MessageVisitor {
    message: String,
    extras: String,
}

impl MessageVisitor {
    /// Route a single (`field`, formatted-value) pair to either
    /// [`Self::message`] or [`Self::extras`]. Centralizing the
    /// dispatch ensures every `record_*` method handles
    /// `field.name() == "message"` identically — a primitive
    /// `tracing::info!(message = 42)` ends up in `message`, not
    /// `extras`.
    fn push(&mut self, field: &Field, value: core::fmt::Arguments<'_>) {
        if field.name() == "message" {
            let _ = write!(&mut self.message, "{value}");
        } else {
            if !self.extras.is_empty() {
                self.extras.push(' ');
            }
            let _ = write!(&mut self.extras, "{}={value}", field.name());
        }
    }
}

impl Visit for MessageVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn core::fmt::Debug) {
        // The default `tracing::info!(...)` macro formats the
        // format-string output through `Debug` and records it as the
        // `message` field. Other fields recorded as `Debug` get the
        // `key={value:?}` shape.
        if field.name() == "message" {
            let _ = write!(&mut self.message, "{value:?}");
            // tracing's Debug formatting for &str yields `"the str"` with
            // quotes; strip a single matching pair if present.
            if self.message.starts_with('"')
                && self.message.ends_with('"')
                && self.message.len() >= 2
            {
                self.message = self.message[1..self.message.len() - 1].to_string();
            }
        } else {
            if !self.extras.is_empty() {
                self.extras.push(' ');
            }
            let _ = write!(&mut self.extras, "{}={value:?}", field.name());
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.push(field, format_args!("{value}"));
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.push(field, format_args!("{value}"));
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.push(field, format_args!("{value}"));
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        self.push(field, format_args!("{value}"));
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.push(field, format_args!("{value}"));
    }
}

impl MessageVisitor {
    fn finish(mut self) -> String {
        if !self.extras.is_empty() {
            if !self.message.is_empty() {
                self.message.push(' ');
            }
            self.message.push_str(&self.extras);
        }
        self.message
    }
}

#[cfg(test)]
mod tests {
    //! Drives [`MessageVisitor`] through `tracing`'s real callsite
    //! plumbing by installing a tiny [`Subscriber`] that records the
    //! formatted output for each event. `tracing::Field` is opaque,
    //! so going through `tracing::info!(...)` is the only way to
    //! exercise every `record_*` arm with a real `Field` reference.
    //!
    //! These tests cover [`MessageVisitor`] and [`wit_level`].
    //! [`HostLogBridge::event`] and [`init`] both call into the
    //! wit-bindgen `host_logging::log` import which has no native
    //! implementation; that surface is exercised end-to-end by the
    //! `oxidhome-core` `hello_world` integration test instead.

    use std::sync::{Arc, Mutex};

    use tracing::Subscriber;

    use super::{MessageVisitor, WitLevel, wit_level};

    /// Recorder subscriber: captures every event's `(level, message)`
    /// after running it through [`MessageVisitor`]. The shared
    /// `events` `Arc<Mutex>` lets the test reach the captured data
    /// after `with_default` consumes the subscriber by value.
    struct Capture {
        events: Arc<Mutex<Vec<(tracing::Level, String)>>>,
    }

    impl Subscriber for Capture {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            let mut visitor = MessageVisitor::default();
            event.record(&mut visitor);
            self.events
                .lock()
                .unwrap()
                .push((*event.metadata().level(), visitor.finish()));
        }
    }

    fn capture(emit: impl FnOnce()) -> Vec<(tracing::Level, String)> {
        let events = Arc::new(Mutex::new(Vec::new()));
        let cap = Capture {
            events: Arc::clone(&events),
        };
        tracing::subscriber::with_default(cap, emit);
        std::mem::take(&mut *events.lock().unwrap())
    }

    #[test]
    fn captures_str_message_without_quotes() {
        let events = capture(|| tracing::info!("hello world"));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].0, tracing::Level::INFO);
        assert_eq!(events[0].1, "hello world");
    }

    #[test]
    fn captures_format_string_message() {
        let n = 7;
        let events = capture(|| tracing::warn!("count={n}"));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].0, tracing::Level::WARN);
        assert_eq!(events[0].1, "count=7");
    }

    #[test]
    fn primitive_message_field_routes_to_message_not_extras() {
        // Regression for the bug where `tracing::info!(message = 42)`
        // ended up in `extras` because the primitive recorders
        // didn't special-case the `message` field.
        let events = capture(|| {
            tracing::info!(message = 42);
        });
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].1, "42");
    }

    #[test]
    fn additional_fields_render_in_extras() {
        let events = capture(|| {
            tracing::info!(user_id = 42, ok = true, "auth check");
        });
        assert_eq!(events.len(), 1);
        let msg = &events[0].1;
        assert!(msg.starts_with("auth check"), "got {msg}");
        assert!(msg.contains("user_id=42"), "got {msg}");
        assert!(msg.contains("ok=true"), "got {msg}");
    }

    #[test]
    fn float_and_str_fields_route_to_extras() {
        let events = capture(|| {
            tracing::info!(ratio = 0.25_f64, label = "kitchen", "metrics");
        });
        assert_eq!(events.len(), 1);
        let msg = &events[0].1;
        assert!(msg.contains("ratio=0.25"));
        assert!(msg.contains("label=kitchen"));
    }

    #[test]
    fn each_level_maps_to_wit_level() {
        assert!(matches!(wit_level(tracing::Level::TRACE), WitLevel::Trace));
        assert!(matches!(wit_level(tracing::Level::DEBUG), WitLevel::Debug));
        assert!(matches!(wit_level(tracing::Level::INFO), WitLevel::Info));
        assert!(matches!(wit_level(tracing::Level::WARN), WitLevel::Warn));
        assert!(matches!(wit_level(tracing::Level::ERROR), WitLevel::Error));
    }
}
