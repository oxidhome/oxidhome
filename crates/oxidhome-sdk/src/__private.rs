//! Internal scaffolding for the [`plugin!`](crate::plugin) macro. **Not
//! a stable API** — items here can change between SDK versions.

// Functions in this module are only ever called from inside the macro
// expansion, so the lints clippy raises about return values being
// "easy to forget" don't apply here — the macro always uses the
// return value or discards it on purpose.
#![allow(clippy::must_use_candidate, clippy::missing_errors_doc)]

pub use core::cell::RefCell;
pub use core::option::Option;
pub use core::result::Result;
pub use std::string::String;
pub use std::thread_local;
pub use std::vec::Vec;

pub use crate::bindings;

/// One-instance-per-component plugin cell.
///
/// `wasm32-wasip2` is single-threaded, so the [`thread_local!`] macro
/// gives us interior-mutability without a [`std::sync::Mutex`]. The
/// cell is `None` until [`Plugin::init`](crate::Plugin::init) runs and
/// is reset to `None` after [`Plugin::shutdown`](crate::Plugin::shutdown).
pub fn run_init<P: crate::Plugin>(
    cell: &'static std::thread::LocalKey<RefCell<Option<P>>>,
) -> Result<(), String> {
    cell.with(|cell| {
        let mut slot = cell.borrow_mut();
        // The lifecycle is `init -> ... -> shutdown` per the trait
        // contract. A second `init` without an intervening `shutdown`
        // would silently drop the previous plugin (skipping its
        // shutdown side effects), so we surface the contract
        // violation as an error instead of overwriting.
        if slot.is_some() {
            return Err(String::from(
                "Plugin::init called while a previous instance is still live; \
                 call Plugin::shutdown first",
            ));
        }
        let mut p = <P as Default>::default();
        let outcome = crate::Plugin::init(&mut p);
        if outcome.is_ok() {
            *slot = Option::Some(p);
        }
        outcome
    })
}

pub fn run_shutdown<P: crate::Plugin>(cell: &'static std::thread::LocalKey<RefCell<Option<P>>>) {
    cell.with(|cell| {
        let mut slot = cell.borrow_mut();
        if let Option::Some(mut p) = slot.take() {
            crate::Plugin::shutdown(&mut p);
        }
    });
}

pub fn run_on_event<P: crate::Plugin>(
    cell: &'static std::thread::LocalKey<RefCell<Option<P>>>,
    event: bindings::oxidhome::plugin::events::Event,
) {
    cell.with(|cell| {
        if let Option::Some(p) = cell.borrow_mut().as_mut() {
            crate::Plugin::on_event(p, event);
        }
    });
}

pub fn run_execute_command<P: crate::Plugin>(
    cell: &'static std::thread::LocalKey<RefCell<Option<P>>>,
    device: String,
    cmd: bindings::oxidhome::plugin::devices::Command,
) -> bindings::oxidhome::plugin::devices::CommandResult {
    cell.with(|cell| match cell.borrow_mut().as_mut() {
        Option::Some(p) => crate::Plugin::execute_command(p, device, cmd),
        Option::None => bindings::oxidhome::plugin::devices::CommandResult::Err(
            bindings::oxidhome::plugin::types::Error::Unavailable("plugin not initialized".into()),
        ),
    })
}

pub fn run_execute_service_command<P: crate::Plugin>(
    cell: &'static std::thread::LocalKey<RefCell<Option<P>>>,
    service: String,
    command: String,
    args: Vec<bindings::oxidhome::plugin::types::KeyValue>,
) -> bindings::oxidhome::plugin::devices::CommandResult {
    cell.with(|cell| match cell.borrow_mut().as_mut() {
        Option::Some(p) => crate::Plugin::execute_service_command(p, service, command, args),
        Option::None => bindings::oxidhome::plugin::devices::CommandResult::Err(
            bindings::oxidhome::plugin::types::Error::Unavailable("plugin not initialized".into()),
        ),
    })
}

pub fn run_tick<P: crate::Plugin>(cell: &'static std::thread::LocalKey<RefCell<Option<P>>>) {
    cell.with(|cell| {
        if let Option::Some(p) = cell.borrow_mut().as_mut() {
            crate::Plugin::tick(p);
        }
    });
}

/// Wires a plugin type into the wit-bindgen-generated `plugin` world
/// exports. Generated [`Plugin`](crate::Plugin)-trait dispatch lives
/// here so the macro body stays small.
///
/// The macro:
///
/// 1. declares a thread-local `RefCell<Option<$ty>>` holding the
///    instance,
/// 2. emits an `impl bindings::Guest for $ty` whose static methods
///    delegate to the dispatch helpers above, and
/// 3. invokes the wit-bindgen `export!` macro to emit the canonical-ABI
///    glue (the actual wasm component exports).
///
/// Used via [`plugin!`](crate::plugin); not a public API on its own.
#[macro_export]
#[doc(hidden)]
macro_rules! __plugin_impl {
    ($ty:ident) => {
        const _: () = {
            $crate::__private::thread_local! {
                static __OXIDHOME_PLUGIN: $crate::__private::RefCell<
                    $crate::__private::Option<$ty>,
                > = const {
                    $crate::__private::RefCell::new($crate::__private::Option::None)
                };
            }

            impl $crate::__private::bindings::Guest for $ty {
                fn init() -> $crate::__private::Result<(), $crate::__private::String> {
                    $crate::__private::run_init::<$ty>(&__OXIDHOME_PLUGIN)
                }

                fn shutdown() {
                    $crate::__private::run_shutdown::<$ty>(&__OXIDHOME_PLUGIN);
                }

                fn on_event(ev: $crate::__private::bindings::oxidhome::plugin::events::Event) {
                    $crate::__private::run_on_event::<$ty>(&__OXIDHOME_PLUGIN, ev);
                }

                fn execute_command(
                    device: $crate::__private::String,
                    cmd: $crate::__private::bindings::oxidhome::plugin::devices::Command,
                ) -> $crate::__private::bindings::oxidhome::plugin::devices::CommandResult {
                    $crate::__private::run_execute_command::<$ty>(&__OXIDHOME_PLUGIN, device, cmd)
                }

                fn execute_service_command(
                    service: $crate::__private::String,
                    command: $crate::__private::String,
                    args: $crate::__private::Vec<
                        $crate::__private::bindings::oxidhome::plugin::types::KeyValue,
                    >,
                ) -> $crate::__private::bindings::oxidhome::plugin::devices::CommandResult {
                    $crate::__private::run_execute_service_command::<$ty>(
                        &__OXIDHOME_PLUGIN,
                        service,
                        command,
                        args,
                    )
                }

                fn tick() {
                    $crate::__private::run_tick::<$ty>(&__OXIDHOME_PLUGIN);
                }
            }

            $crate::__private::bindings::export!(
                $ty with_types_in $crate::__private::bindings
            );
        };
    };
}

/// Public face of the [`__plugin_impl!`] machinery. Plugin authors use
/// this name; the macro itself is just a thin re-export so docs stay
/// readable.
#[macro_export]
macro_rules! plugin {
    ($ty:ident) => {
        $crate::__plugin_impl!($ty);
    };
}

#[cfg(test)]
mod tests {
    //! Drive every `run_*` helper directly. `cargo test` runs each
    //! `#[test]` on its own thread, so the `thread_local!` cells
    //! below start `None` for every case — no manual cleanup
    //! between tests.

    use super::*;
    use crate::bindings::oxidhome::plugin::devices::{Command, CommandResult};
    use crate::bindings::oxidhome::plugin::events::{Event, EventPayload, StateChange};
    use crate::bindings::oxidhome::plugin::types::{Error, Value};

    #[derive(Default)]
    struct Counter {
        init_count: u32,
        shutdown_count: u32,
        events: Vec<Event>,
        commands: Vec<(String, Command)>,
        ticks: u32,
        /// If true, `init` returns `Err`; the cell should stay `None`
        /// after the failed attempt.
        fail_init: bool,
    }

    impl crate::Plugin for Counter {
        fn init(&mut self) -> Result<(), String> {
            self.init_count += 1;
            if self.fail_init {
                Err("forced".into())
            } else {
                Ok(())
            }
        }
        fn shutdown(&mut self) {
            self.shutdown_count += 1;
        }
        fn on_event(&mut self, event: Event) {
            self.events.push(event);
        }
        fn execute_command(&mut self, device: String, cmd: Command) -> CommandResult {
            self.commands.push((device, cmd));
            CommandResult::Ok
        }
        fn tick(&mut self) {
            self.ticks += 1;
        }
    }

    fn state_changed() -> Event {
        Event {
            device: None,
            timestamp: 0,
            payload: EventPayload::StateChanged(StateChange {
                capability: "switch".into(),
                fields: Vec::new(),
            }),
        }
    }

    fn command() -> Command {
        Command {
            capability: "switch".into(),
            action: "toggle".into(),
            args: Vec::new(),
        }
    }

    #[test]
    fn run_init_creates_and_stores_instance() {
        thread_local! {
            static CELL: RefCell<Option<Counter>> = const { RefCell::new(None) };
        }
        run_init::<Counter>(&CELL).expect("init");
        CELL.with(|c| {
            let p = c.borrow();
            assert_eq!(p.as_ref().expect("present").init_count, 1);
        });
    }

    #[test]
    fn run_init_rejects_double_init() {
        thread_local! {
            static CELL: RefCell<Option<Counter>> = const { RefCell::new(None) };
        }
        run_init::<Counter>(&CELL).unwrap();
        let err = run_init::<Counter>(&CELL).unwrap_err();
        assert!(
            err.contains("Plugin::init called while a previous instance is still live"),
            "unexpected error: {err}"
        );
    }

    /// A plugin whose `init` always errors — used to exercise
    /// `run_init`'s "`outcome.is_err()` ⇒ leave slot empty" branch
    /// without polluting [`Counter`] (which the rest of these tests
    /// expect to construct via `Default`).
    #[derive(Default)]
    struct AlwaysFail;

    impl crate::Plugin for AlwaysFail {
        fn init(&mut self) -> Result<(), String> {
            Err("nope".into())
        }
        fn shutdown(&mut self) {}
    }

    #[test]
    fn run_init_failure_leaves_slot_empty() {
        thread_local! {
            static FAIL_CELL: RefCell<Option<AlwaysFail>> = const { RefCell::new(None) };
        }
        let err = run_init::<AlwaysFail>(&FAIL_CELL).unwrap_err();
        assert_eq!(err, "nope");
        // Cell stays empty so the host can retry without tripping
        // the double-init guard.
        FAIL_CELL.with(|c| assert!(c.borrow().is_none()));
    }

    #[test]
    fn run_shutdown_runs_and_clears_slot() {
        thread_local! {
            static CELL: RefCell<Option<Counter>> = const { RefCell::new(None) };
        }
        run_init::<Counter>(&CELL).unwrap();
        run_shutdown::<Counter>(&CELL);
        CELL.with(|c| assert!(c.borrow().is_none()));
    }

    #[test]
    fn run_shutdown_on_empty_slot_is_a_noop() {
        thread_local! {
            static CELL: RefCell<Option<Counter>> = const { RefCell::new(None) };
        }
        // No init beforehand — must not panic.
        run_shutdown::<Counter>(&CELL);
        CELL.with(|c| assert!(c.borrow().is_none()));
    }

    #[test]
    fn run_on_event_forwards_to_plugin() {
        thread_local! {
            static CELL: RefCell<Option<Counter>> = const { RefCell::new(None) };
        }
        run_init::<Counter>(&CELL).unwrap();
        run_on_event::<Counter>(&CELL, state_changed());
        CELL.with(|c| {
            let p = c.borrow();
            let p = p.as_ref().expect("instance");
            assert_eq!(p.events.len(), 1);
        });
    }

    #[test]
    fn run_on_event_before_init_is_a_noop() {
        thread_local! {
            static CELL: RefCell<Option<Counter>> = const { RefCell::new(None) };
        }
        // Skipping init, the cell is None — must not panic.
        run_on_event::<Counter>(&CELL, state_changed());
        CELL.with(|c| assert!(c.borrow().is_none()));
    }

    #[test]
    fn run_execute_command_uninitialized_returns_unavailable() {
        thread_local! {
            static CELL: RefCell<Option<Counter>> = const { RefCell::new(None) };
        }
        let result = run_execute_command::<Counter>(&CELL, "d-1".into(), command());
        match result {
            CommandResult::Err(Error::Unavailable(msg)) => {
                assert!(msg.contains("plugin not initialized"));
            }
            other => panic!("expected Err(Unavailable), got {other:?}"),
        }
    }

    #[test]
    fn run_execute_command_forwards_after_init() {
        thread_local! {
            static CELL: RefCell<Option<Counter>> = const { RefCell::new(None) };
        }
        run_init::<Counter>(&CELL).unwrap();
        let result = run_execute_command::<Counter>(&CELL, "d-1".into(), command());
        assert!(matches!(result, CommandResult::Ok));
        CELL.with(|c| {
            let p = c.borrow();
            assert_eq!(p.as_ref().unwrap().commands.len(), 1);
        });
    }

    #[test]
    fn run_tick_forwards_after_init() {
        thread_local! {
            static CELL: RefCell<Option<Counter>> = const { RefCell::new(None) };
        }
        run_init::<Counter>(&CELL).unwrap();
        run_tick::<Counter>(&CELL);
        run_tick::<Counter>(&CELL);
        CELL.with(|c| {
            let p = c.borrow();
            assert_eq!(p.as_ref().unwrap().ticks, 2);
        });
    }

    #[test]
    fn run_tick_before_init_is_a_noop() {
        thread_local! {
            static CELL: RefCell<Option<Counter>> = const { RefCell::new(None) };
        }
        run_tick::<Counter>(&CELL);
        CELL.with(|c| assert!(c.borrow().is_none()));
    }

    /// Reference an unused field to keep `Value` linked into the
    /// test binary so the import path doesn't get pruned by
    /// dead-code elimination — the `command()` helper above is what
    /// covers `Value::*` constructors in practice.
    #[test]
    fn value_variants_construct_cleanly() {
        let _ = Value::BoolVal(true);
        let _ = Value::IntVal(42);
        let _ = Value::FloatVal(1.5);
        let _ = Value::StringVal("s".into());
        let _ = Value::BytesVal(vec![1, 2, 3]);
        let _ = Value::JsonVal("{}".into());
    }
}
