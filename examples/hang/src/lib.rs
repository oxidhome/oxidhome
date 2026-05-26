//! OxidHome Phase 7a example: a plugin that never returns.
//!
//! The `phase` config picks which hook hangs:
//!
//! - `"tick"` (default) — `init` succeeds, then the lifecycle
//!   `tick()` enters an infinite loop;
//! - `"init"` — `init` itself never returns.
//!
//! It's the fixture for the liveness-watchdog tests: the host must be
//! able to interrupt the wedged call (`Trap::Interrupt`) so the
//! supervisor can reclaim the instance instead of hanging forever.

use oxidhome_sdk::Plugin;
use oxidhome_sdk::host;

#[derive(Default)]
struct Hang;

fn cfg_phase() -> String {
    host::config::get_typed::<String>("phase")
        .ok()
        .flatten()
        .unwrap_or_else(|| "tick".to_string())
}

fn spin() -> ! {
    // A tight loop the watchdog (epoch interruption) cuts short.
    // `black_box` keeps the optimiser from removing the body.
    let mut x: u64 = 0;
    loop {
        x = x.wrapping_add(1);
        std::hint::black_box(x);
    }
}

impl Plugin for Hang {
    fn init(&mut self) -> Result<(), String> {
        let _ = oxidhome_sdk::logging::init();
        if cfg_phase() == "init" {
            spin();
        }
        oxidhome_sdk::tracing::info!("hang ready — will spin on first tick");
        Ok(())
    }

    fn tick(&mut self) {
        if cfg_phase() == "tick" {
            spin();
        }
    }

    fn shutdown(&mut self) {}
}

oxidhome_sdk::plugin!(Hang);
