//! `tracing` ↔ host `logging` import bridge.
//!
//! Plugin authors write idiomatic `tracing::info!("...")` calls inside
//! their plugin; [`init`] installs a global subscriber that forwards
//! every event to the host's `logging::log(level, message)` import.
//!
//! Phase 2 forwards level + a formatted message only — `logging::log`
//! takes `(level, string)` in the 0.1 WIT. Structured fields land in
//! Phase 5 when the WIT grows a `fields` parameter (see
//! `.claude/docs/01_wit.md` Phase 5 entry); the bridge will start
//! forwarding fields then. Until then, fields are formatted into the
//! message string by `tracing-subscriber`'s default formatter, so they
//! aren't lost — they just aren't typed on the wire.

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
