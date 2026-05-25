//! Per-instance liveness watchdog — Phase 7a.
//!
//! `OxidHome` deliberately does **not** cap plugin resource usage
//! (fuel, memory): on an admin-curated home hub, catching a greedy
//! plugin is the operator's job, and the host's role is to surface
//! metrics, not to enforce quotas. The one thing the host *must*
//! guarantee is that
//! it can always reclaim a wedged instance — without it, a plugin that
//! enters an infinite loop would make its Phase-6 supervisor's
//! `instance.tick().await` never return, so the supervisor could never
//! process a `stop()` or restart, and a tokio worker would be pinned
//! until the whole host restarts.
//!
//! The watchdog is that guarantee, and nothing more:
//!
//! - `Config::epoch_interruption(true)` on the engine.
//! - A dedicated OS thread ([`EpochTicker`]) bumps the engine's epoch
//!   every [`EPOCH_TICK_MS`]. It's a std thread, not a tokio task: a
//!   wasm tight loop blocks the tokio worker driving it and never
//!   yields, so a `tokio::spawn`ed ticker on the same runtime could
//!   starve. The OS scheduler always runs this thread.
//! - Before every host-driven entry point the instance arms a
//!   per-call epoch deadline ([`WATCHDOG_DEFAULT`], a fixed generous
//!   timeout — not a per-plugin knob). A call that runs past it traps
//!   with [`wasmtime::Trap::Interrupt`], which the supervisor
//!   classifies as [`TrapReason::Unresponsive`] and restarts under the
//!   `on-trap` policy.
//!
//! [`TrapReason::Unresponsive`]: super::lifecycle::TrapReason::Unresponsive

use std::sync::{Arc, Weak};
use std::time::Duration;

use wasmtime::Engine as WasmtimeEngine;

/// How often [`EpochTicker`] increments the engine's epoch counter —
/// the watchdog's resolution. A 30 s deadline gets ~300 ticks of
/// headroom; the cost per tick is one atomic increment.
pub const EPOCH_TICK_MS: u64 = 100;

/// The fixed per-call liveness deadline. Generous on purpose: it only
/// trips a genuinely stuck call, never a heavy-but-progressing one.
/// Long-running work (streaming, media) is the `streaming-plugin`
/// world (Phase 8) with its own model, not a plugin-tunable knob here.
pub const WATCHDOG_DEFAULT: Duration = Duration::from_secs(30);

/// Dedicated OS thread that bumps the engine's epoch counter every
/// [`EPOCH_TICK_MS`]. Held by a [`Weak`] so it exits cleanly once the
/// engine drops — integration tests build many engines.
pub(crate) struct EpochTicker;

impl EpochTicker {
    pub(crate) fn spawn(engine: &Arc<WasmtimeEngine>) {
        let weak: Weak<WasmtimeEngine> = Arc::downgrade(engine);
        std::thread::Builder::new()
            .name("oxidhome-epoch-ticker".into())
            .spawn(move || {
                loop {
                    std::thread::sleep(Duration::from_millis(EPOCH_TICK_MS));
                    let Some(engine) = weak.upgrade() else {
                        return;
                    };
                    engine.increment_epoch();
                }
            })
            .expect("spawning epoch ticker thread");
    }
}

/// How many epoch ticks correspond to `timeout`, for
/// `Store::set_epoch_deadline`. One extra tick of headroom so a
/// deadline that's a clean multiple of [`EPOCH_TICK_MS`] doesn't trip
/// at the boundary; floored at 1 so a sub-tick timeout still arms.
#[must_use]
pub(crate) fn deadline_ticks(timeout: Duration) -> u64 {
    let ms = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX);
    (ms / EPOCH_TICK_MS).max(1) + 1
}

/// Whether an `anyhow::Error` from a wasm call is the watchdog firing
/// (`wasmtime::Trap::Interrupt`), as opposed to any other trap.
#[must_use]
pub(crate) fn is_watchdog_trap(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        cause
            .downcast_ref::<wasmtime::Trap>()
            .is_some_and(|trap| matches!(trap, wasmtime::Trap::Interrupt))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deadline_ticks_rounds_up_with_headroom() {
        // 30 s / 100 ms = 300, + 1 headroom.
        assert_eq!(deadline_ticks(Duration::from_secs(30)), 301);
        // Sub-tick timeout still arms at least 2 ticks.
        assert_eq!(deadline_ticks(Duration::from_millis(50)), 2);
        assert_eq!(deadline_ticks(Duration::from_millis(0)), 2);
    }

    #[test]
    fn is_watchdog_trap_matches_interrupt_only() {
        let interrupt: anyhow::Error =
            anyhow::Error::new(wasmtime::Trap::Interrupt).context("invoking plugin tick");
        assert!(is_watchdog_trap(&interrupt));

        let other: anyhow::Error = anyhow::Error::new(wasmtime::Trap::OutOfFuel);
        assert!(!is_watchdog_trap(&other));

        let plain = anyhow::anyhow!("not a trap");
        assert!(!is_watchdog_trap(&plain));
    }
}
