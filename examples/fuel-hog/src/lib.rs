//! OxidHome Phase 7a example: burns sandbox budgets on demand.
//!
//! Two config knobs:
//!
//! - `mode` (`"fuel"` | `"memory"`) — what to burn. `"fuel"` enters a
//!   tight loop the wasmtime `Store::set_fuel` budget cuts short.
//!   `"memory"` grows a `Vec` until the `ResourceLimiter` refuses
//!   memory growth past `memory_max_mb`. Pairing `"fuel"` mode with
//!   a manifest that sets `fuel_per_call` huge + `call_timeout_ms`
//!   tight exercises the epoch-interrupt path instead.
//! - `phase` (`"init"` | `"tick"`) — when to burn. `"init"` runs the
//!   chosen budget-burner inside `init`, `"tick"` runs it inside the
//!   lifecycle `tick()` hook.
//!
//! It exists purely as the fixture for the Phase-7a sandbox-limits
//! tests — `on-trap` should restart fuel / memory / timeout traps
//! the same way it restarts a regular trap.

use oxidhome_sdk::Plugin;
use oxidhome_sdk::host;

#[derive(Default)]
struct FuelHog;

fn cfg_mode() -> String {
    host::config::get_typed::<String>("mode")
        .ok()
        .flatten()
        .unwrap_or_else(|| "fuel".to_string())
}

fn cfg_phase() -> String {
    host::config::get_typed::<String>("phase")
        .ok()
        .flatten()
        .unwrap_or_else(|| "tick".to_string())
}

fn burn(mode: &str) {
    match mode {
        "memory" => {
            // Allocate aggressively until the limiter refuses
            // memory.grow. `wrapping_add` keeps the optimiser from
            // eliminating the loop body.
            let mut total: usize = 0;
            let mut keep: Vec<Vec<u8>> = Vec::new();
            loop {
                let chunk = vec![0u8; 1024 * 1024];
                total = total.wrapping_add(chunk.len());
                keep.push(chunk);
            }
        }
        _ => {
            // "fuel" (default) — a tight loop that just consumes
            // wasm instructions. `wrapping_add` defeats optimisation.
            let mut x: u64 = 0;
            loop {
                x = x.wrapping_add(1);
                // A side-effect read keeps LLVM from removing the loop.
                std::hint::black_box(x);
            }
        }
    }
}

impl Plugin for FuelHog {
    fn init(&mut self) -> Result<(), String> {
        let _ = oxidhome_sdk::logging::init();
        let mode = cfg_mode();
        let phase = cfg_phase();
        if phase == "init" {
            // Will not return; the supervisor traps via fuel /
            // memory / timeout depending on the manifest.
            burn(&mode);
        }
        oxidhome_sdk::tracing::info!(mode = %mode, phase = %phase, "fuel-hog ready");
        Ok(())
    }

    fn tick(&mut self) {
        if cfg_phase() == "tick" {
            burn(&cfg_mode());
        }
    }

    fn shutdown(&mut self) {}
}

oxidhome_sdk::plugin!(FuelHog);
