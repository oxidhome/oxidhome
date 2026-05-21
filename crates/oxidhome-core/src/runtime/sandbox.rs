//! Per-instance Wasmtime sandbox limits — Phase 7a.
//!
//! The host caps three resources per supervised plugin call:
//!
//! - **Fuel** — `Config::consume_fuel(true)` plus a per-call
//!   `Store::set_fuel(...)`. A wasm tight-loop exhausts the budget
//!   and the next yield-point traps with [`wasmtime::Trap::OutOfFuel`].
//!   The supervisor classifies that into [`TrapReason::OutOfFuel`]
//!   ([`super::lifecycle::TrapReason`]), which `on-trap` treats as a
//!   restartable resource-budget exhaustion.
//! - **Memory** — per-store [`wasmtime::ResourceLimiter`] gates
//!   `memory.grow` against the manifest's `memory_max_mb`. Refused
//!   growth returns an `Err` from the limiter that carries
//!   [`MemoryLimitExceeded`], which the classifier maps to
//!   [`TrapReason::OutOfMemory`].
//! - **Wall-clock per call** — `Config::epoch_interruption(true)`
//!   plus a dedicated OS thread ([`EpochTicker`]) that increments the
//!   engine's epoch counter every [`EPOCH_TICK_MS`]. A wasm tight
//!   loop yields no tokio polls, so `tokio::time::timeout` alone
//!   can't preempt it; the std-thread ticker is independent of the
//!   tokio runtime and lets wasmtime trap a runaway call at the next
//!   epoch check (`Trap::Interrupt`), classified as
//!   [`TrapReason::OutOfTimeBudget`].
//!
//! Manifest fields ([`oxidhome_manifest::RuntimeSection`]) supply the
//! per-call budgets; absent values fall back on [`DEFAULT_FUEL_PER_CALL`]
//! / [`DEFAULT_MEMORY_MAX_MB`] / [`DEFAULT_CALL_TIMEOUT_MS`].

use std::sync::{Arc, Weak};
use std::time::Duration;

use wasmtime::Engine as WasmtimeEngine;

/// Default per-call fuel budget when the manifest omits `fuel_per_call`.
/// Loose enough that the existing examples (kv-counter, simulated-switch,
/// event-recorder) don't trip without declaring a budget; tighter values
/// stay opt-in per plugin.
pub const DEFAULT_FUEL_PER_CALL: u64 = 10_000_000;

/// Default per-store memory cap when the manifest omits `memory_max_mb`.
pub const DEFAULT_MEMORY_MAX_MB: u64 = 64;

/// Default per-call wall-clock budget when the manifest omits
/// `call_timeout_ms`. 5 s is enough for any non-streaming entry
/// point; streaming work lands in Phase 8 with its own knobs.
pub const DEFAULT_CALL_TIMEOUT_MS: u64 = 5_000;

/// How often [`EpochTicker`] increments the engine's epoch counter.
/// Picks the timeout granularity: a 5 s budget gets ~50 ticks, a
/// 200 ms budget gets ~2.
pub const EPOCH_TICK_MS: u64 = 100;

/// Dedicated OS thread (not a tokio task) that bumps the engine's
/// epoch counter every [`EPOCH_TICK_MS`]. The std thread is the
/// load-bearing choice: a wasm tight loop blocks the tokio worker
/// that's driving it and never yields, so a `tokio::spawn`ed ticker
/// on the *same* runtime can starve if every worker is similarly
/// busy. The OS scheduler always runs this thread. The ticker
/// terminates when the engine drops (the `Weak` no longer upgrades).
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

/// Custom error the resource-limiter returns when a `memory.grow`
/// would push past the manifest's `memory_max_mb`. The classifier
/// downcasts to this to surface a [`TrapReason::OutOfMemory`].
///
/// [`TrapReason::OutOfMemory`]: super::lifecycle::TrapReason::OutOfMemory
#[derive(Debug)]
pub(crate) struct MemoryLimitExceeded {
    pub limit_bytes: usize,
    pub requested_bytes: usize,
}

impl std::fmt::Display for MemoryLimitExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "memory growth denied: requested {} bytes, limit is {} bytes",
            self.requested_bytes, self.limit_bytes,
        )
    }
}

impl std::error::Error for MemoryLimitExceeded {}

/// Per-store memory ceiling enforced via [`wasmtime::ResourceLimiter`].
/// One per [`super::state::PluginState`]; the limit is read from the
/// instance's manifest at instantiation time.
pub struct PluginResourceLimiter {
    /// Per-`Store` memory ceiling in bytes (`memory_max_mb * MiB`).
    memory_max_bytes: usize,
}

impl PluginResourceLimiter {
    /// Build a limiter from a memory cap in MiB.
    #[must_use]
    pub fn new(memory_max_mb: u64) -> Self {
        Self {
            // saturating_mul to defend against an absurd manifest
            // value overflowing usize on a 32-bit host.
            memory_max_bytes: usize::try_from(memory_max_mb)
                .unwrap_or(usize::MAX)
                .saturating_mul(1024 * 1024),
        }
    }
}

impl wasmtime::ResourceLimiter for PluginResourceLimiter {
    fn memory_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        if desired <= self.memory_max_bytes {
            Ok(true)
        } else {
            // Returning `Err` aborts the call; the error rides up
            // wasmtime as a trap whose chain `classify_trap` walks to
            // surface a typed `OutOfMemory`.
            Err(wasmtime::Error::new(MemoryLimitExceeded {
                limit_bytes: self.memory_max_bytes,
                requested_bytes: desired,
            }))
        }
    }

    fn table_growing(
        &mut self,
        _current: usize,
        _desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        // Table growth isn't capped in Phase 7. WIT-bindgen generated
        // tables are small and fixed-shape; revisit when a real plugin
        // needs the knob.
        Ok(true)
    }
}

/// Classified shape of a wasmtime trap, as the supervisor sees it.
#[derive(Debug, Clone)]
pub(crate) enum ClassifiedTrap {
    /// `Trap::OutOfFuel` — `Store::set_fuel` budget exhausted.
    OutOfFuel,
    /// `Trap::Interrupt` — `set_epoch_deadline` fired past the
    /// per-call wall-clock budget.
    OutOfTimeBudget,
    /// [`MemoryLimitExceeded`] from the resource limiter.
    OutOfMemory,
    /// Any other wasmtime trap (`unreachable`, OOB, stack overflow…)
    /// or a non-trap host-side error. Carries the rendered message.
    Other(String),
}

/// Walk an `anyhow::Error` chain to classify the trap. Checks for
/// the typed [`MemoryLimitExceeded`] marker first, then for
/// `wasmtime::Trap::OutOfFuel` / `Trap::Interrupt`. Anything else is
/// `Other` with the rendered chain.
pub(crate) fn classify_trap(err: &anyhow::Error) -> ClassifiedTrap {
    // Limiter-refused memory growth — the host's `Err` rides up the
    // anyhow chain wrapping the original `MemoryLimitExceeded`.
    if err
        .chain()
        .any(|cause| cause.downcast_ref::<MemoryLimitExceeded>().is_some())
    {
        return ClassifiedTrap::OutOfMemory;
    }
    // Typed wasmtime trap reasons (fuel / cooperative-interrupt
    // epoch). Both appear directly on the chain as a `wasmtime::Trap`.
    for cause in err.chain() {
        if let Some(trap) = cause.downcast_ref::<wasmtime::Trap>() {
            return match trap {
                wasmtime::Trap::OutOfFuel => ClassifiedTrap::OutOfFuel,
                wasmtime::Trap::Interrupt => ClassifiedTrap::OutOfTimeBudget,
                _ => ClassifiedTrap::Other(format!("{err:#}")),
            };
        }
    }
    ClassifiedTrap::Other(format!("{err:#}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifier_detects_memory_limit() {
        let err: anyhow::Error = anyhow::Error::new(MemoryLimitExceeded {
            limit_bytes: 1024,
            requested_bytes: 4096,
        })
        .context("growing instance memory");
        assert!(matches!(classify_trap(&err), ClassifiedTrap::OutOfMemory));
    }

    #[test]
    fn classifier_detects_out_of_fuel() {
        let err: anyhow::Error =
            anyhow::Error::new(wasmtime::Trap::OutOfFuel).context("invoking plugin tick");
        assert!(matches!(classify_trap(&err), ClassifiedTrap::OutOfFuel));
    }

    #[test]
    fn classifier_detects_interrupt_as_out_of_time_budget() {
        let err: anyhow::Error =
            anyhow::Error::new(wasmtime::Trap::Interrupt).context("invoking plugin tick");
        assert!(matches!(
            classify_trap(&err),
            ClassifiedTrap::OutOfTimeBudget
        ));
    }

    #[test]
    fn classifier_falls_back_to_other_for_unrelated_traps() {
        let err: anyhow::Error = anyhow::Error::new(wasmtime::Trap::StackOverflow);
        match classify_trap(&err) {
            ClassifiedTrap::Other(msg) => assert!(msg.contains("stack")),
            other => panic!("expected Other, got {other:?}"),
        }
    }

    #[test]
    fn resource_limiter_caps_memory_growth() {
        use wasmtime::ResourceLimiter as _;
        let mut limiter = PluginResourceLimiter::new(1);
        // 1 MiB is allowed.
        assert!(matches!(
            limiter.memory_growing(0, 1024 * 1024, None),
            Ok(true)
        ));
        // 2 MiB exceeds the cap → typed error.
        let err = limiter
            .memory_growing(0, 2 * 1024 * 1024, None)
            .expect_err("over cap");
        assert!(err.downcast_ref::<MemoryLimitExceeded>().is_some());
    }
}
