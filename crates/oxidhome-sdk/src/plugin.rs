//! The [`Plugin`] trait — what every standard-world plugin implements.

use crate::bindings::oxidhome::plugin::{
    devices::{Command, CommandResult},
    events::Event,
    types::{Error, KeyValue},
};

/// Lifecycle and event entry points for a standard-world plugin.
///
/// Implementors carry their own state behind `&mut self`; the
/// [`plugin!`](crate::plugin) macro stores the instance in a
/// thread-local cell, constructs it via [`Default`] on `init`, and
/// drops it on `shutdown`.
///
/// `on_event`, `execute_command`, and `tick` have sensible defaults
/// (no-op or "unavailable" reply) so simple plugins only override the
/// methods they care about.
pub trait Plugin: Default + 'static {
    /// Called once after the host instantiates the component, before
    /// any other callback. Return `Err` to abort instantiation.
    ///
    /// # Errors
    ///
    /// Plugins return an `Err(message)` to signal that initialization
    /// could not complete; the host treats this as a fatal load
    /// failure and the instance is dropped.
    fn init(&mut self) -> Result<(), String>;

    /// Called once before the host drops the component instance. The
    /// instance is dropped immediately after this call returns.
    fn shutdown(&mut self);

    /// Delivered by the host for every event matching one of this
    /// plugin's subscriptions. Default no-op.
    fn on_event(&mut self, _event: Event) {}

    /// Invoked when the host routes a command to a device this plugin
    /// owns. Default returns
    /// [`Error::Unavailable`] — override to handle real commands.
    fn execute_command(&mut self, _device: String, _cmd: Command) -> CommandResult {
        CommandResult::Err(Error::Unavailable(
            "execute-command not implemented by this plugin".into(),
        ))
    }

    /// Invoked when the host dispatches a `call-service` to a service
    /// this plugin registered (Phase 7). `service` is the host-assigned
    /// `service-id`, `command` the command name, `args` its arguments.
    /// Default returns [`Error::Unavailable`] — plugins that expose
    /// services override it.
    fn execute_service_command(
        &mut self,
        _service: String,
        _command: String,
        _args: Vec<KeyValue>,
    ) -> CommandResult {
        CommandResult::Err(Error::Unavailable(
            "execute-service-command not implemented by this plugin".into(),
        ))
    }

    /// Called on the cadence the manifest's `tick_interval_ms` requests.
    /// Default no-op for plugins that don't poll.
    fn tick(&mut self) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bindings::oxidhome::plugin::events::{Event, EventPayload, StateChange};

    #[derive(Default)]
    struct Stub {
        inits: u32,
        shutdowns: u32,
        on_events: u32,
        ticks: u32,
    }

    impl Plugin for Stub {
        fn init(&mut self) -> Result<(), String> {
            self.inits += 1;
            Ok(())
        }
        fn shutdown(&mut self) {
            self.shutdowns += 1;
        }
        fn on_event(&mut self, _event: Event) {
            self.on_events += 1;
        }
        fn tick(&mut self) {
            self.ticks += 1;
        }
    }

    fn state_change_event() -> Event {
        Event {
            device: None,
            timestamp: 0,
            payload: EventPayload::StateChanged(StateChange {
                capability: "switch".into(),
                fields: Vec::new(),
            }),
        }
    }

    /// `execute_command` has no override here: assert the trait
    /// default returns `Error::Unavailable` so plugins that don't
    /// own commands surface a clear error to the host instead of
    /// trapping.
    #[test]
    fn default_execute_command_returns_unavailable() {
        let mut p = Stub::default();
        let result = p.execute_command(
            "d-1".into(),
            Command {
                capability: "switch".into(),
                action: "toggle".into(),
                args: Vec::new(),
            },
        );
        match result {
            CommandResult::Err(Error::Unavailable(_)) => {}
            other => panic!("expected Err(Unavailable), got {other:?}"),
        }
    }

    /// Verify the stub forwards each callback exactly once, so the
    /// trait shape itself is exercised end-to-end (`init` → `on_event`
    /// → `tick` → `shutdown`).
    #[test]
    fn lifecycle_round_trip_increments_counters() {
        let mut p = Stub::default();
        p.init().expect("init");
        p.on_event(state_change_event());
        p.tick();
        p.shutdown();
        assert_eq!(p.inits, 1);
        assert_eq!(p.on_events, 1);
        assert_eq!(p.ticks, 1);
        assert_eq!(p.shutdowns, 1);
    }
}
