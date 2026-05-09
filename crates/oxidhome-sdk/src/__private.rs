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
