//! Per-instance lifecycle supervisor — Phase 6b.
//!
//! [`supervise`] spawns one tokio task per plugin instance. That task
//! *owns* the [`PluginInstance`] (hence its Wasmtime `Store`) and is
//! the only thing that ever drives it — preserving the single-threaded
//! per-`Store` WASM contract. The task `select!`s between three
//! sources and drains the event bus after each:
//!
//! - **control commands** — `execute-command` / `shutdown` arriving
//!   through the [`InstanceHandle`]'s mpsc channel;
//! - **ticks** — a `tokio::time::interval` whose cadence is the
//!   manifest's `runtime.tick_interval_ms` (absent ⇒ no ticks);
//! - **bus events** — a `broadcast` wakeup receiver; any publish wakes
//!   the loop, which then runs [`PluginInstance::drain_events`] to
//!   deliver matching events into the plugin's `on-event`. This is the
//!   subscriber-only-plugin path: such a plugin never ticks, so a
//!   `select!` arm on the bus is what makes its events arrive.
//!
//! The state machine is `Loading → Inited → Running`, with
//! `Stopping → Stopped` on a clean shutdown. A crash goes
//! `Running → Crashed`; the manifest's `restart` policy then decides
//! between `Restarting → Loading` (a fresh `Store`, after an
//! exponential-backoff wait) and the terminal `Failed`. A `load`
//! failure is always terminal — there's no manifest to read a policy
//! from. The consecutive-restart counter is capped at [`MAX_RESTARTS`]
//! and resets once an instance stays `Running` for [`HEALTHY_RESET`].

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use oxidhome_manifest::RestartPolicy;
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::{broadcast, mpsc, oneshot, watch};
use tokio::time::{Instant, Interval, MissedTickBehavior};

use crate::Engine;
use crate::host_impl::plugin::oxidhome::plugin::devices::{Command, CommandResult};
use crate::host_impl::plugin::oxidhome::plugin::events::Event;
use crate::host_impl::plugin::oxidhome::plugin::types::{DeviceId, KeyValue, ServiceId};
use crate::runtime::dispatcher::{CALL_STACK, CallFrame};
use crate::state::CallGuard;

use super::instance::{InitError, PluginInstance};

/// Tunable supervisor timing — restart backoff plus the consecutive-
/// restart cap and its healthy-reset window. Production code uses
/// [`SupervisorTuning::default`] (the values in the Phase-6 plan);
/// tests inject a fast variant through [`supervise_with_tuning`] so a
/// restart suite runs in milliseconds rather than minutes.
#[derive(Debug, Clone)]
pub struct SupervisorTuning {
    /// Backoff ceiling for the first restart (doubles each attempt).
    pub backoff_base: Duration,
    /// Upper bound the doubling backoff saturates against.
    pub backoff_max: Duration,
    /// Consecutive restarts attempted before the supervisor gives up
    /// and goes `Failed`.
    pub max_restarts: u32,
    /// How long an instance must stay `Running` before its
    /// consecutive-restart counter resets to zero — so a plugin that
    /// crashes rarely keeps being restarted, only a tight crash-loop
    /// is capped.
    pub healthy_reset: Duration,
    /// Per-call liveness watchdog deadline applied to every host entry
    /// point. Production uses [`watchdog::WATCHDOG_DEFAULT`]; tests
    /// lower it so a hung-plugin case trips in milliseconds.
    pub watchdog: Duration,
}

impl Default for SupervisorTuning {
    fn default() -> Self {
        Self {
            backoff_base: Duration::from_secs(1),
            backoff_max: Duration::from_mins(1),
            max_restarts: 10,
            healthy_reset: Duration::from_mins(5),
            watchdog: super::watchdog::WATCHDOG_DEFAULT,
        }
    }
}

/// Observable lifecycle state of a supervised instance. Published
/// through the [`InstanceHandle`]'s `watch` channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstanceState {
    /// The supervisor task is loading + instantiating the component.
    Loading,
    /// `init` returned `Ok`; the run loop hasn't started yet.
    Inited,
    /// Steady state — serving ticks, commands, and event drains.
    Running,
    /// The instance just crashed; the supervisor is applying the
    /// restart policy. `restarts` is the consecutive-restart count
    /// *so far* (0 on the first crash).
    Crashed { reason: String, restarts: u32 },
    /// Crashed and waiting out the backoff delay before restart
    /// attempt `attempt`.
    Restarting { attempt: u32 },
    /// A clean `shutdown` is in flight.
    Stopping,
    /// Clean terminal state — `shutdown` completed.
    Stopped,
    /// Unrecoverable terminal state — a `load` failure, a crash the
    /// `restart` policy doesn't cover, or the restart cap hit.
    Failed { error: String },
}

impl InstanceState {
    /// Whether the supervisor task has exited — no further transitions
    /// will happen.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(self, InstanceState::Stopped | InstanceState::Failed { .. })
    }
}

/// Why a supervised instance crashed. The supervisor's `on-trap`
/// restart policy keys off this: every variant *except*
/// [`TrapReason::InitFailed`] is restartable; the deterministic init
/// failure isn't, since retrying a bad config won't fix it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrapReason {
    /// A Wasmtime trap — guest panic, `unreachable`, an out-of-bounds
    /// access, or a host-call error surfacing from an entry point
    /// other than `init`.
    Trap(String),
    /// The plugin's `init` export returned `Err` — a clean,
    /// deterministic startup failure that retrying won't fix.
    InitFailed(String),
    /// The liveness watchdog interrupted a call that ran past the
    /// deadline (Phase 7a). Restartable — a stuck call may not recur.
    Unresponsive(String),
}

impl std::fmt::Display for TrapReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TrapReason::Trap(m) => write!(f, "trap: {m}"),
            TrapReason::InitFailed(m) => write!(f, "init failed: {m}"),
            TrapReason::Unresponsive(m) => write!(f, "unresponsive (watchdog): {m}"),
        }
    }
}

/// Classify an `anyhow::Error` from a post-init entry-point call
/// (`tick`, `execute_command`, `drain_events`, `shutdown`) into the
/// matching [`TrapReason`] — the watchdog interrupt vs a generic trap.
fn classify_post_init_trap(err: &anyhow::Error) -> TrapReason {
    let msg = format!("{err:#}");
    if super::watchdog::is_watchdog_trap(err) {
        TrapReason::Unresponsive(msg)
    } else {
        TrapReason::Trap(msg)
    }
}

/// A message the [`InstanceHandle`] sends to the supervisor task.
#[derive(Debug)]
enum ControlCommand {
    /// Run the plugin's `execute-command` for a device it owns.
    Execute {
        device: DeviceId,
        cmd: Command,
        reply: oneshot::Sender<anyhow::Result<CommandResult>>,
    },
    /// Run the plugin's `execute-service-command` on a service it owns
    /// — the dispatcher hops to this on the owner's supervisor task so
    /// the single-`Store` contract holds. `chain` is the full
    /// in-flight `call-service` chain (caller's parent chain + the
    /// frame for this call); the supervisor scopes it on its task
    /// before driving the wasm so nested `call-service`s from inside
    /// `execute-service-command` see the full chain for cycle checks.
    ///
    /// `guard` is the [`CallGuard`] the dispatcher acquired before
    /// sending the message. It rides with the work so the in-flight
    /// refcount tracks *real* execution: dropped when the supervisor
    /// finishes the wasm call (`handle_control` holds it across the
    /// scoped invocation), or dropped with the message if the
    /// channel closes before the supervisor consumes it. Nothing
    /// *reads* it — `Drop` does the decrement.
    ExecuteService {
        chain: Vec<CallFrame>,
        guard: CallGuard,
        service: ServiceId,
        command: String,
        args: Vec<KeyValue>,
        reply: oneshot::Sender<anyhow::Result<CommandResult>>,
    },
    /// Run `shutdown` and end the supervisor task.
    Shutdown { reply: oneshot::Sender<()> },
}

/// Host-side handle to one supervised instance. Cheap to clone and
/// `Send + Sync`, so the future registry / API layers can hold it.
/// Dropping every clone closes the control channel, which the
/// supervisor treats as a shutdown request.
#[derive(Debug, Clone)]
pub struct InstanceHandle {
    instance_id: Arc<str>,
    /// Manifest-resolved `plugin.id` (e.g. `example.simulated-switch`).
    /// Cached on the handle so API / CLI consumers can join instance
    /// listings on the plugin without reading the manifest again, and
    /// the registry / dispatcher can attribute work in audit logs by
    /// plugin without an extra lookup.
    plugin_id: Arc<str>,
    control: mpsc::Sender<ControlCommand>,
    state: watch::Receiver<InstanceState>,
}

impl InstanceHandle {
    /// The instance id this supervisor was started with.
    #[must_use]
    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }

    /// The manifest-resolved `plugin.id` this instance is a copy of.
    /// Stable across the instance's lifetime (the manifest is
    /// read-once at load and pinned to the supervisor).
    #[must_use]
    pub fn plugin_id(&self) -> &str {
        &self.plugin_id
    }

    /// A snapshot of the current [`InstanceState`].
    #[must_use]
    pub fn state(&self) -> InstanceState {
        self.state.borrow().clone()
    }

    /// Wait until the instance reaches [`InstanceState::Running`].
    ///
    /// # Errors
    ///
    /// Returns `Err` if the instance reaches a terminal state first —
    /// `Failed` (carrying the crash message) or `Stopped` — or if the
    /// supervisor task ends without ever publishing `Running`.
    pub async fn wait_for_running(&self) -> anyhow::Result<()> {
        let mut rx = self.state.clone();
        loop {
            match &*rx.borrow_and_update() {
                InstanceState::Running => return Ok(()),
                InstanceState::Failed { error } => {
                    return Err(anyhow!("instance `{}` failed: {error}", self.instance_id));
                }
                InstanceState::Stopped => {
                    // `watch` keeps only the latest value, so a fast
                    // Running→Stopped instance lands here too — don't
                    // claim it never reached Running, only that it's
                    // terminal now.
                    return Err(anyhow!("instance `{}` is Stopped", self.instance_id));
                }
                // A crash mid-restart isn't terminal — a later
                // attempt may still reach Running, so keep waiting.
                InstanceState::Loading
                | InstanceState::Inited
                | InstanceState::Crashed { .. }
                | InstanceState::Restarting { .. }
                | InstanceState::Stopping => {}
            }
            if rx.changed().await.is_err() {
                return Err(anyhow!(
                    "instance `{}` supervisor ended before reaching Running",
                    self.instance_id,
                ));
            }
        }
    }

    /// Wait until the supervisor task reaches a terminal state and
    /// return it ([`InstanceState::Stopped`] or
    /// [`InstanceState::Failed`]).
    pub async fn wait_terminal(&self) -> InstanceState {
        let mut rx = self.state.clone();
        loop {
            {
                let cur = rx.borrow_and_update();
                if cur.is_terminal() {
                    return cur.clone();
                }
            }
            if rx.changed().await.is_err() {
                // Sender dropped — the last value it left is terminal
                // (the task only drops its sender on the way out).
                return rx.borrow().clone();
            }
        }
    }

    /// Run the plugin's `execute-command` for `device`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the supervisor is gone, or if the call traps —
    /// a trap also crashes the instance (`Failed`). A plugin returning
    /// a normal error result surfaces as `Ok(CommandResult::Err(..))`.
    pub async fn execute_command(
        &self,
        device: DeviceId,
        cmd: Command,
    ) -> anyhow::Result<CommandResult> {
        let (reply, rx) = oneshot::channel();
        self.control
            .send(ControlCommand::Execute { device, cmd, reply })
            .await
            .map_err(|_| {
                anyhow!(
                    "instance `{}` supervisor is no longer running",
                    self.instance_id,
                )
            })?;
        rx.await.map_err(|_| {
            anyhow!(
                "instance `{}` supervisor dropped the command reply",
                self.instance_id,
            )
        })?
    }

    /// Run the plugin's `execute-service-command` on `service`. Used
    /// by [`crate::runtime::dispatcher`]'s cross-instance routing —
    /// always hops to the *owner*'s supervisor task so the
    /// single-`Store` contract holds.
    ///
    /// `chain` is the full in-flight `call-service` chain leading to
    /// this call; the callee's supervisor scopes it on its own task
    /// before invoking the wasm, so cycle detection works across the
    /// task hop.
    ///
    /// **Caller blocking note.** The caller's supervisor task is
    /// parked on the oneshot until this returns, so any other control
    /// message (including `stop`) queued on the caller's mpsc waits
    /// up to [`crate::runtime::dispatcher::DISPATCH_TIMEOUT`] for the
    /// service call to complete.
    ///
    /// # Errors
    ///
    /// `Err` if the supervisor is gone, the supervisor dropped the
    /// reply, or the call trapped (a trap also crashes the instance).
    /// A plugin returning a normal error result surfaces as
    /// `Ok(CommandResult::Err(..))`.
    pub(crate) async fn execute_service_command(
        &self,
        chain: Vec<CallFrame>,
        guard: CallGuard,
        service: ServiceId,
        command: String,
        args: Vec<KeyValue>,
    ) -> anyhow::Result<CommandResult> {
        let (reply, rx) = oneshot::channel();
        // If the send fails (control channel closed), the
        // `SendError` carries the message back; `map_err` discards
        // it, which drops the `ControlCommand::ExecuteService` and
        // with it the `CallGuard` → refcount decrements cleanly even
        // on the supervisor-gone path.
        self.control
            .send(ControlCommand::ExecuteService {
                chain,
                guard,
                service,
                command,
                args,
                reply,
            })
            .await
            .map_err(|_| {
                anyhow!(
                    "instance `{}` supervisor is no longer running",
                    self.instance_id,
                )
            })?;
        rx.await.map_err(|_| {
            anyhow!(
                "instance `{}` supervisor dropped the service-command reply",
                self.instance_id,
            )
        })?
    }

    /// Ask the supervisor to run `shutdown` and end the task. Awaits
    /// the shutdown completing. Idempotent — calling `stop` on an
    /// already-terminal instance returns `Ok(())`.
    ///
    /// # Errors
    ///
    /// This call itself does not fail; the `Result` is reserved for a
    /// future where `stop` can report a shutdown trap.
    pub async fn stop(&self) -> anyhow::Result<()> {
        let (reply, rx) = oneshot::channel();
        if self
            .control
            .send(ControlCommand::Shutdown { reply })
            .await
            .is_err()
        {
            // Supervisor already exited — already Stopped or Failed.
            return Ok(());
        }
        // A dropped reply means the task ended before acking; that's
        // still "stopped" from the caller's point of view.
        let _ = rx.await;
        Ok(())
    }
}

/// Spawn a supervisor task for the plugin in `plugin_dir` and return
/// its [`InstanceHandle`] immediately. The task loads, `init`s, and
/// then runs the instance until `shutdown` or a crash; the handle's
/// `watch` channel reports progress (starts at
/// [`InstanceState::Loading`]).
#[must_use]
pub fn supervise(
    engine: Engine,
    plugin_dir: PathBuf,
    instance_id: impl Into<String>,
    plugin_id: impl Into<String>,
    overrides: Option<toml::Value>,
) -> InstanceHandle {
    supervise_with_tuning(
        engine,
        plugin_dir,
        instance_id,
        plugin_id,
        overrides,
        SupervisorTuning::default(),
    )
}

/// Like [`supervise`], but with an explicit [`SupervisorTuning`].
/// Intended for tests that need a fast backoff / low restart cap; the
/// daemon always uses [`supervise`].
#[doc(hidden)]
#[must_use]
pub fn supervise_with_tuning(
    engine: Engine,
    plugin_dir: PathBuf,
    instance_id: impl Into<String>,
    plugin_id: impl Into<String>,
    overrides: Option<toml::Value>,
    tuning: SupervisorTuning,
) -> InstanceHandle {
    let instance_id: Arc<str> = Arc::from(instance_id.into());
    let plugin_id: Arc<str> = Arc::from(plugin_id.into());
    let (control_tx, control_rx) = mpsc::channel(16);
    let (state_tx, state_rx) = watch::channel(InstanceState::Loading);
    let handle = InstanceHandle {
        instance_id: Arc::clone(&instance_id),
        plugin_id: Arc::clone(&plugin_id),
        control: control_tx,
        state: state_rx,
    };
    tokio::spawn(run_supervisor(
        engine,
        plugin_dir,
        instance_id,
        overrides,
        tuning,
        control_rx,
        state_tx,
    ));
    handle
}

/// What the run loop should do after a `select!` arm completes.
enum LoopAction {
    /// Stay in the loop (after draining pending events).
    Continue,
    /// `shutdown` ran — leave the loop with a clean `Stopped`.
    Stop,
}

/// Publish a state transition: log it under `runtime.lifecycle` and
/// push it onto the `watch` channel.
fn transition(state_tx: &watch::Sender<InstanceState>, instance_id: &str, next: InstanceState) {
    tracing::info!(
        target: "runtime.lifecycle",
        instance_id,
        state = ?next,
        "instance lifecycle transition",
    );
    // A send error means every handle was dropped; the task keeps
    // going (a dropped handle still wants a clean shutdown) and the
    // value is simply unobserved.
    let _ = state_tx.send(next);
}

/// Exponential-backoff-with-full-jitter delay policy for restarts.
struct BackoffPolicy {
    base: Duration,
    max: Duration,
}

impl BackoffPolicy {
    fn new(base: Duration, max: Duration) -> Self {
        Self { base, max }
    }

    /// Pre-jitter delay ceiling for restart `attempt` (1-based):
    /// `min(base * 2^(attempt-1), max)`.
    fn ceiling(&self, attempt: u32) -> Duration {
        // Cap the shift so `1 << shift` can't overflow `u32`; any
        // shift past ~6 already saturates against `max` anyway.
        let shift = attempt.saturating_sub(1).min(31);
        self.base.saturating_mul(1u32 << shift).min(self.max)
    }

    /// Backoff delay for restart `attempt` — the [`Self::ceiling`]
    /// scaled by a full-jitter factor in `[0.5, 1.0)`, so a fleet of
    /// instances that crash together don't all restart in lockstep.
    fn next_delay(&self, attempt: u32) -> Duration {
        use std::time::{SystemTime, UNIX_EPOCH};
        let ceiling = self.ceiling(attempt);
        // Cheap entropy — avoids a `rand` dependency for jitter.
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        let frac = 0.5 + 0.5 * (f64::from(nanos) / 1_000_000_000.0);
        ceiling.mul_f64(frac)
    }
}

/// Outcome of the restart decision for one crash.
#[derive(Debug, PartialEq, Eq)]
enum RestartDecision {
    /// Restart the instance after a backoff wait.
    Restart,
    /// Stop trying — transition to `Failed`.
    GiveUp,
}

/// Decide whether to restart, given the manifest policy, the crash
/// reason, how many consecutive restarts have happened already, and
/// the restart cap.
fn restart_decision(
    policy: RestartPolicy,
    reason: &TrapReason,
    restarts_done: u32,
    max_restarts: u32,
) -> RestartDecision {
    let policy_allows = match policy {
        RestartPolicy::Never => false,
        RestartPolicy::Always => true,
        // `on-trap` restarts a real trap or a watchdog interrupt, but
        // not a clean `init` failure — retrying a deterministic config
        // error won't fix it.
        RestartPolicy::OnTrap => {
            matches!(reason, TrapReason::Trap(_) | TrapReason::Unresponsive(_))
        }
    };
    if policy_allows && restarts_done < max_restarts {
        RestartDecision::Restart
    } else {
        RestartDecision::GiveUp
    }
}

/// Outcome of one full load → init → run-loop attempt.
enum LifecycleOutcome {
    /// A clean `shutdown` ran — the supervisor should exit.
    Stopped,
    /// `load` itself failed; there's no manifest, so no policy — the
    /// supervisor must treat this as terminal.
    LoadFailed(String),
    /// The instance loaded then crashed. Carries everything the
    /// restart decision needs.
    Crashed {
        policy: RestartPolicy,
        reason: TrapReason,
        /// The instance stayed `Running` at least the tuning's
        /// `healthy_reset` window — long enough to reset the
        /// consecutive-restart counter.
        ran_healthy: bool,
    },
}

/// Outcome of the steady-state `select!` loop.
enum ServeOutcome {
    /// A clean `shutdown` ran.
    Stopped,
    /// The instance trapped.
    Crashed(TrapReason),
}

/// Outcome of waiting out a restart backoff delay.
enum BackoffOutcome {
    /// The delay elapsed — go ahead and restart.
    Elapsed,
    /// A shutdown was requested mid-backoff.
    Shutdown,
}

/// The supervisor task body: run the instance, and on a crash apply
/// the manifest's `restart` policy with exponential backoff until a
/// clean stop, an unrecoverable failure, or the restart cap.
async fn run_supervisor(
    engine: Engine,
    plugin_dir: PathBuf,
    instance_id: Arc<str>,
    overrides: Option<toml::Value>,
    tuning: SupervisorTuning,
    mut control_rx: mpsc::Receiver<ControlCommand>,
    state_tx: watch::Sender<InstanceState>,
) {
    // Subscribe the wakeup receiver *before* loading so no publish
    // between now and the run loop is missed: the broadcast channel
    // buffers wakeups until the loop's first `recv`. Reused across
    // restarts — a fresh instance re-subscribes its own receivers.
    let mut wakeup = engine.events().subscribe_all().receiver;
    let backoff = BackoffPolicy::new(tuning.backoff_base, tuning.backoff_max);
    // Consecutive restarts; reset once an instance runs healthily.
    let mut restarts: u32 = 0;

    loop {
        let outcome = run_one_lifecycle(
            &engine,
            &plugin_dir,
            &instance_id,
            overrides.as_ref(),
            tuning.healthy_reset,
            tuning.watchdog,
            &mut control_rx,
            &mut wakeup,
            &state_tx,
        )
        .await;

        match outcome {
            LifecycleOutcome::Stopped => return,
            LifecycleOutcome::LoadFailed(msg) => {
                transition(
                    &state_tx,
                    &instance_id,
                    InstanceState::Failed {
                        error: format!("load failed: {msg}"),
                    },
                );
                return;
            }
            LifecycleOutcome::Crashed {
                policy,
                reason,
                ran_healthy,
            } => {
                if ran_healthy {
                    restarts = 0;
                }
                if restart_decision(policy, &reason, restarts, tuning.max_restarts)
                    == RestartDecision::GiveUp
                {
                    let error = if restarts >= tuning.max_restarts {
                        format!(
                            "gave up after {} consecutive restarts; last crash: {reason}",
                            tuning.max_restarts,
                        )
                    } else {
                        format!(
                            "not restarting under `{}` policy: {reason}",
                            policy.as_str()
                        )
                    };
                    transition(&state_tx, &instance_id, InstanceState::Failed { error });
                    return;
                }
                transition(
                    &state_tx,
                    &instance_id,
                    InstanceState::Crashed {
                        reason: reason.to_string(),
                        restarts,
                    },
                );
                restarts += 1;
                let delay = backoff.next_delay(restarts);
                transition(
                    &state_tx,
                    &instance_id,
                    InstanceState::Restarting { attempt: restarts },
                );
                if let BackoffOutcome::Shutdown =
                    backoff_wait(delay, &mut control_rx, &instance_id).await
                {
                    transition(&state_tx, &instance_id, InstanceState::Stopped);
                    return;
                }
            }
        }
    }
}

/// Run one load → init → serve attempt. State transitions up to
/// `Running` (and the clean `Stopped`) are emitted here; the
/// supervisor owns `Crashed` / `Restarting` / `Failed`.
//
// The argument list is wide because the supervisor lends this helper
// every borrow it needs for one attempt; bundling them into a struct
// purely for the lint would only move the noise.
#[allow(clippy::too_many_arguments)]
async fn run_one_lifecycle(
    engine: &Engine,
    plugin_dir: &Path,
    instance_id: &str,
    overrides: Option<&toml::Value>,
    healthy_reset: Duration,
    watchdog: Duration,
    control_rx: &mut mpsc::Receiver<ControlCommand>,
    wakeup: &mut broadcast::Receiver<Event>,
    state_tx: &watch::Sender<InstanceState>,
) -> LifecycleOutcome {
    // Sweep any device/service registry entries this instance left
    // behind on a previous life. First load is a no-op; on a restart
    // it prevents stacking duplicates as `init` re-registers, and
    // keeps the registries from growing unboundedly across crash
    // loops. Idempotent + cheap (one HashMap retain each).
    engine.devices().remove_by_owner(instance_id);
    engine.services().remove_by_owner(instance_id);

    transition(state_tx, instance_id, InstanceState::Loading);

    let mut instance = match PluginInstance::load_with_overrides(
        engine,
        plugin_dir,
        instance_id.to_string(),
        overrides,
    )
    .await
    {
        Ok(instance) => instance,
        Err(e) => return LifecycleOutcome::LoadFailed(format!("{e:#}")),
    };
    instance.set_watchdog(watchdog);
    let policy = instance.manifest().runtime.restart;

    match instance.init().await {
        Ok(()) => {}
        Err(e) => {
            let reason = match e {
                InitError::Plugin(msg) => TrapReason::InitFailed(msg),
                InitError::Trap(msg) => TrapReason::Trap(msg),
                InitError::Unresponsive(msg) => TrapReason::Unresponsive(msg),
            };
            return LifecycleOutcome::Crashed {
                policy,
                reason,
                ran_healthy: false,
            };
        }
    }
    transition(state_tx, instance_id, InstanceState::Inited);

    // Deliver anything the plugin's subscriptions buffered during init.
    if let Err(e) = instance.drain_events().await {
        return LifecycleOutcome::Crashed {
            policy,
            reason: classify_post_init_trap(&e),
            ran_healthy: false,
        };
    }

    let tick = build_tick_interval(&instance);
    let running_since = Instant::now();
    transition(state_tx, instance_id, InstanceState::Running);

    match serve_loop(
        &mut instance,
        control_rx,
        wakeup,
        state_tx,
        instance_id,
        tick,
    )
    .await
    {
        ServeOutcome::Stopped => LifecycleOutcome::Stopped,
        ServeOutcome::Crashed(reason) => LifecycleOutcome::Crashed {
            policy,
            reason,
            ran_healthy: running_since.elapsed() >= healthy_reset,
        },
    }
}

/// Build the tick interval if the manifest declares a cadence. The
/// floor (`MIN_TICK_INTERVAL_MS`) is enforced at manifest validation.
fn build_tick_interval(instance: &PluginInstance) -> Option<Interval> {
    instance.manifest().runtime.tick_interval_ms.map(|ms| {
        let period = Duration::from_millis(ms);
        // `interval_at(now + period, ..)` so the *first* tick lands one
        // cadence after Running, not immediately — `tick_interval_ms`
        // is the gap between ticks, the first one included.
        let mut interval = tokio::time::interval_at(Instant::now() + period, period);
        // A slow tick body must not make the loop "catch up" with a
        // burst of back-to-back ticks; delay the schedule instead.
        interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        interval
    })
}

/// The steady-state `select!` loop — see the module docs.
async fn serve_loop(
    instance: &mut PluginInstance,
    control_rx: &mut mpsc::Receiver<ControlCommand>,
    wakeup: &mut broadcast::Receiver<Event>,
    state_tx: &watch::Sender<InstanceState>,
    instance_id: &str,
    mut tick: Option<Interval>,
) -> ServeOutcome {
    let mut bus_open = true;
    loop {
        let outcome: anyhow::Result<LoopAction> = tokio::select! {
            ctrl = control_rx.recv() => {
                handle_control(instance, state_tx, instance_id, ctrl).await
            }
            // `if tick.is_some()` gates the `unwrap` — the arm is only
            // polled when an interval exists.
            _ = async { tick.as_mut().unwrap().tick().await }, if tick.is_some() => {
                instance.tick().await.map(|()| LoopAction::Continue)
            }
            ev = wakeup.recv(), if bus_open => {
                match ev {
                    // A real event or a lag both mean "events happened,
                    // go drain". The drain below reads the plugin's own
                    // filtered receivers; this one is only a wakeup.
                    Ok(_) | Err(RecvError::Lagged(_)) => Ok(LoopAction::Continue),
                    // Bus sender gone (engine dropped): stop selecting
                    // on it so the arm can't busy-loop.
                    Err(RecvError::Closed) => {
                        bus_open = false;
                        Ok(LoopAction::Continue)
                    }
                }
            }
        };

        match outcome {
            Ok(LoopAction::Continue) => {
                if let Err(e) = instance.drain_events().await {
                    return ServeOutcome::Crashed(classify_post_init_trap(&e));
                }
            }
            Ok(LoopAction::Stop) => {
                transition(state_tx, instance_id, InstanceState::Stopped);
                return ServeOutcome::Stopped;
            }
            Err(e) => return ServeOutcome::Crashed(classify_post_init_trap(&e)),
        }
    }
}

/// Wait out a restart backoff delay. Returns early if a shutdown is
/// requested mid-backoff; an `execute-command` arriving during the
/// wait is answered with an error (the instance isn't running).
async fn backoff_wait(
    delay: Duration,
    control_rx: &mut mpsc::Receiver<ControlCommand>,
    instance_id: &str,
) -> BackoffOutcome {
    let sleep = tokio::time::sleep(delay);
    tokio::pin!(sleep);
    loop {
        tokio::select! {
            () = &mut sleep => return BackoffOutcome::Elapsed,
            ctrl = control_rx.recv() => match ctrl {
                // Every handle dropped, or an explicit shutdown.
                None => return BackoffOutcome::Shutdown,
                Some(ControlCommand::Shutdown { reply }) => {
                    let _ = reply.send(());
                    return BackoffOutcome::Shutdown;
                }
                // The two `Execute*` arms hand the caller the same
                // "instance is restarting" Err, but the typed reply
                // channels are distinct so the arms can't share a
                // single block. The arms may diverge later (e.g.
                // returning a typed `CommandResult::Err` for service
                // calls); keep them separate now rather than merging.
                #[allow(clippy::match_same_arms)]
                Some(ControlCommand::Execute { reply, .. }) => {
                    let _ = reply.send(Err(anyhow!(
                        "instance `{instance_id}` is restarting after a crash",
                    )));
                }
                #[allow(clippy::match_same_arms)]
                Some(ControlCommand::ExecuteService { reply, .. }) => {
                    let _ = reply.send(Err(anyhow!(
                        "instance `{instance_id}` is restarting after a crash",
                    )));
                }
            }
        }
    }
}

/// Handle one control message (or the channel closing). Returns the
/// loop action, or an `Err` if the plugin trapped (→ `Failed`).
async fn handle_control(
    instance: &mut PluginInstance,
    state_tx: &watch::Sender<InstanceState>,
    instance_id: &str,
    ctrl: Option<ControlCommand>,
) -> anyhow::Result<LoopAction> {
    match ctrl {
        // Every handle was dropped — nobody can observe or drive the
        // instance anymore. Shut it down cleanly.
        None => {
            transition(state_tx, instance_id, InstanceState::Stopping);
            instance.shutdown().await?;
            Ok(LoopAction::Stop)
        }
        Some(ControlCommand::Shutdown { reply }) => {
            transition(state_tx, instance_id, InstanceState::Stopping);
            let result = instance.shutdown().await;
            // Ack the caller whether or not `shutdown` trapped — the
            // `?` below still surfaces a trap as `Failed`.
            let _ = reply.send(());
            result?;
            Ok(LoopAction::Stop)
        }
        Some(ControlCommand::Execute { device, cmd, reply }) => {
            match instance.execute_command(device, cmd).await {
                Ok(result) => {
                    let _ = reply.send(Ok(result));
                    Ok(LoopAction::Continue)
                }
                Err(trap) => {
                    // Surface the trap to the caller, then crash the
                    // instance — an `execute-command` trap is a crash.
                    let _ = reply.send(Err(anyhow!(
                        "instance `{instance_id}` crashed during execute-command: {trap:#}",
                    )));
                    Err(trap)
                }
            }
        }
        Some(ControlCommand::ExecuteService {
            chain,
            guard,
            service,
            command,
            args,
            reply,
        }) => {
            // Scope `CALL_STACK` to the chain handed to us by the
            // caller's dispatcher *on this supervisor's task*. That's
            // how cycle detection survives the task hop: any nested
            // `host::call_service` from inside the wasm we're about
            // to drive runs on this task, reads `CALL_STACK`, and
            // sees the full chain leading to it.
            //
            // `guard` is bound only into this match arm — held across
            // the wasm call below, dropped *before* `reply.send` so
            // the caller can never observe `active_call_count > 0`
            // after its await resumes. (The codex/GPT-5 invariant —
            // refcount > 0 *while wasm is running* — still holds:
            // wasm finishes inside the `scope(...).await` above the
            // drop, so the drop happens strictly after the work is
            // done.)
            let outcome = CALL_STACK
                .scope(
                    chain,
                    instance.execute_service_command(service, command, args),
                )
                .await;
            drop(guard);
            match outcome {
                Ok(result) => {
                    let _ = reply.send(Ok(result));
                    Ok(LoopAction::Continue)
                }
                Err(trap) => {
                    let _ = reply.send(Err(anyhow!(
                        "instance `{instance_id}` crashed during execute-service-command: {trap:#}",
                    )));
                    Err(trap)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The restart cap used across the decision-matrix tests.
    const CAP: u32 = 10;

    #[test]
    fn default_tuning_matches_the_phase6_plan() {
        let t = SupervisorTuning::default();
        assert_eq!(t.backoff_base, Duration::from_secs(1));
        assert_eq!(t.backoff_max, Duration::from_mins(1));
        assert_eq!(t.max_restarts, 10);
        assert_eq!(t.healthy_reset, Duration::from_mins(5));
    }

    #[test]
    fn backoff_ceiling_doubles_then_caps_at_max() {
        let policy = BackoffPolicy::new(Duration::from_secs(1), Duration::from_mins(1));
        assert_eq!(policy.ceiling(1), Duration::from_secs(1));
        assert_eq!(policy.ceiling(2), Duration::from_secs(2));
        assert_eq!(policy.ceiling(4), Duration::from_secs(8));
        // 1 * 2^6 = 64s, capped to the 60s max.
        assert_eq!(policy.ceiling(7), Duration::from_mins(1));
        // A huge attempt must saturate, not overflow the shift.
        assert_eq!(policy.ceiling(100), Duration::from_mins(1));
        assert_eq!(policy.ceiling(u32::MAX), Duration::from_mins(1));
    }

    #[test]
    fn backoff_next_delay_stays_within_full_jitter_band() {
        let policy = BackoffPolicy::new(Duration::from_secs(1), Duration::from_mins(1));
        for attempt in 1..=10 {
            let ceiling = policy.ceiling(attempt);
            let delay = policy.next_delay(attempt);
            // Full jitter: delay ∈ [0.5 * ceiling, ceiling).
            assert!(delay >= ceiling / 2, "attempt {attempt}: {delay:?} < half");
            assert!(delay <= ceiling, "attempt {attempt}: {delay:?} > ceiling");
        }
    }

    #[test]
    fn never_policy_always_gives_up() {
        for reason in [
            TrapReason::Trap("x".into()),
            TrapReason::InitFailed("x".into()),
        ] {
            assert_eq!(
                restart_decision(RestartPolicy::Never, &reason, 0, CAP),
                RestartDecision::GiveUp,
            );
        }
    }

    #[test]
    fn always_policy_restarts_either_reason_under_the_cap() {
        for reason in [
            TrapReason::Trap("x".into()),
            TrapReason::InitFailed("x".into()),
        ] {
            assert_eq!(
                restart_decision(RestartPolicy::Always, &reason, 0, CAP),
                RestartDecision::Restart,
            );
            assert_eq!(
                restart_decision(RestartPolicy::Always, &reason, CAP - 1, CAP),
                RestartDecision::Restart,
            );
        }
    }

    #[test]
    fn on_trap_policy_restarts_traps_but_not_init_failures() {
        assert_eq!(
            restart_decision(RestartPolicy::OnTrap, &TrapReason::Trap("x".into()), 0, CAP),
            RestartDecision::Restart,
        );
        assert_eq!(
            restart_decision(
                RestartPolicy::OnTrap,
                &TrapReason::InitFailed("x".into()),
                0,
                CAP,
            ),
            RestartDecision::GiveUp,
        );
    }

    #[test]
    fn restart_cap_gives_up_even_for_an_always_policy() {
        let reason = TrapReason::Trap("x".into());
        assert_eq!(
            restart_decision(RestartPolicy::Always, &reason, CAP, CAP),
            RestartDecision::GiveUp,
        );
        assert_eq!(
            restart_decision(RestartPolicy::Always, &reason, CAP + 1, CAP),
            RestartDecision::GiveUp,
        );
    }
}
