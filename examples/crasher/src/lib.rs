//! OxidHome Phase 6c example: a plugin that crashes on demand.
//!
//! The `crash_on` config field picks the failure mode:
//!
//! - `"tick"` (default) — `init` succeeds, then the first lifecycle
//!   `tick()` panics, which the host catches as a Wasmtime trap;
//! - `"init"` — `init` returns `Err`, a clean deterministic startup
//!   failure.
//!
//! It exists purely as the fixture for the Phase-6 supervisor's
//! restart-policy and backoff tests — `on-trap` restarts the tick
//! trap but treats the `init` failure as terminal.

use oxidhome_sdk::Plugin;
use oxidhome_sdk::host;

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
        oxidhome_sdk::tracing::info!("crasher ready — will trap on first tick");
        Ok(())
    }

    fn tick(&mut self) {
        // A guest panic unwinds to a Wasmtime trap, which the host
        // catches and classifies as `TrapReason::Trap`.
        panic!("crasher: deliberate tick trap");
    }

    fn shutdown(&mut self) {}
}

oxidhome_sdk::plugin!(Crasher);
