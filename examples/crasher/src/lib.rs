//! OxidHome Phase 6c example: a plugin that crashes on demand.
//!
//! The `crash_on` config field picks the failure mode:
//!
//! - `"tick"` (default) — `init` succeeds, then the first lifecycle
//!   `tick()` panics, which the host catches as a Wasmtime trap;
//! - `"init"` — `init` returns `Err`, a clean deterministic startup
//!   failure;
//! - `"shutdown"` — `init` + `tick` succeed, but the guest's
//!   `shutdown` handler panics. Used by the round-3 F1 supervisor
//!   test to verify an operator-requested shutdown that traps is
//!   terminal (never restarted) regardless of the manifest's
//!   restart policy;
//! - `"command"` — `init` registers a switch device and `tick` is a
//!   no-op, but `execute_command` panics. The H5 test fixture for a
//!   trap after the plugin started a command (`outcome_unknown`).
//!
//! It exists purely as the fixture for the Phase-6 supervisor's
//! restart-policy and backoff tests — `on-trap` restarts the tick
//! trap but treats the `init` failure as terminal.

use oxidhome_sdk::bindings::oxidhome::plugin::capabilities::CapabilitySpec;
use oxidhome_sdk::bindings::oxidhome::plugin::devices::{Command, CommandResult};
use oxidhome_sdk::{Device, Plugin, host};

#[derive(Default)]
struct Crasher;

impl Plugin for Crasher {
    fn init(&mut self) -> Result<(), String> {
        let _ = oxidhome_sdk::logging::init();
        let mode = host::config::get_typed::<String>("crash_on")
            .map_err(|e| format!("reading crash_on config: {e}"))?
            .unwrap_or_else(|| "tick".to_string());
        if mode == "init" {
            return Err("crasher: deliberate init failure".to_string());
        }
        if mode == "command" {
            host::register_device(
                Device::new("switch-1", "Crashing Switch").capability(CapabilitySpec::Switch),
            )
            .map_err(|e| format!("register-device failed: {e:?}"))?;
        }
        oxidhome_sdk::tracing::info!("crasher ready — mode: {mode}");
        Ok(())
    }

    fn tick(&mut self) {
        let mode = host::config::get_typed::<String>("crash_on")
            .ok()
            .flatten()
            .unwrap_or_else(|| "tick".to_string());
        if mode == "tick" {
            // A guest panic unwinds to a Wasmtime trap, which
            // the host catches and classifies as
            // `TrapReason::Trap`.
            panic!("crasher: deliberate tick trap");
        }
    }

    fn execute_command(&mut self, _device: String, _cmd: Command) -> CommandResult {
        // Only reachable in `"command"` mode: no other mode registers
        // a device for the host to route a command to.
        panic!("crasher: deliberate execute-command trap");
    }

    fn shutdown(&mut self) {
        let mode = host::config::get_typed::<String>("crash_on")
            .ok()
            .flatten()
            .unwrap_or_else(|| "tick".to_string());
        if mode == "shutdown" {
            panic!("crasher: deliberate shutdown trap");
        }
    }
}

oxidhome_sdk::plugin!(Crasher);
