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
use crate::host_impl::plugin::oxidhome::plugin::types::DeviceId;

use super::instance::{InitError, PluginInstance};

/// How many consecutive restarts the supervisor will attempt before
/// giving up and going `Failed`. The counter resets after an instance
/// stays `Running` for [`HEALTHY_RESET`], so a plugin that crashes
/// rarely keeps being restarted — only a tight crash-loop is capped.
const MAX_RESTARTS: u32 = 10;

/// How long an instance must stay `Running` before its consecutive-
/// restart counter resets to zero.
const HEALTHY_RESET: Duration = Duration::from_mins(5);

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
/// restart policy keys off this: a [`TrapReason::Trap`] is
/// restartable, a [`TrapReason::InitFailed`] is not. Phase 7 adds
/// fuel- / memory-exhaustion variants here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrapReason {
    /// A Wasmtime trap — guest panic, `unreachable`, an out-of-bounds
    /// access, or a host-call error surfacing from an entry point
    /// other than `init`.
    Trap(String),
    /// The plugin's `init` export returned `Err` — a clean,
    /// deterministic startup failure that retrying won't fix.
    InitFailed(String),
}

impl std::fmt::Display for TrapReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TrapReason::Trap(m) => write!(f, "trap: {m}"),
            TrapReason::InitFailed(m) => write!(f, "init failed: {m}"),
        }
    }
}

/// A message the [`InstanceHandle`] sends to the supervisor task.
enum ControlCommand {
    /// Run the plugin's `execute-command` for a device it owns.
    Execute {
        device: DeviceId,
        cmd: Command,
        reply: oneshot::Sender<anyhow::Result<CommandResult>>,
    },
    /// Run `shutdown` and end the supervisor task.
    Shutdown { reply: oneshot::Sender<()> },
}

/// Host-side handle to one supervised instance. Cheap to clone and
/// `Send + Sync`, so the future registry / API layers can hold it.
/// Dropping every clone closes the control channel, which the
/// supervisor treats as a shutdown request.
#[derive(Clone)]
pub struct InstanceHandle {
    instance_id: Arc<str>,
    control: mpsc::Sender<ControlCommand>,
    state: watch::Receiver<InstanceState>,
}

impl InstanceHandle {
    /// The instance id this supervisor was started with.
    #[must_use]
    pub fn instance_id(&self) -> &str {
        &self.instance_id
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
    overrides: Option<toml::Value>,
) -> InstanceHandle {
    let instance_id: Arc<str> = Arc::from(instance_id.into());
    let (control_tx, control_rx) = mpsc::channel(16);
    let (state_tx, state_rx) = watch::channel(InstanceState::Loading);
    let handle = InstanceHandle {
        instance_id: Arc::clone(&instance_id),
        control: control_tx,
        state: state_rx,
    };
    tokio::spawn(run_supervisor(
        engine,
        plugin_dir,
        instance_id,
        overrides,
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
/// Held as fixed host constants rather than manifest knobs — see the
/// Phase-6 plan; revisit if a real plugin needs per-plugin tuning.
struct BackoffPolicy {
    base: Duration,
    max: Duration,
}

impl BackoffPolicy {
    fn new() -> Self {
        Self {
            base: Duration::from_secs(1),
            max: Duration::from_mins(1),
        }
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
/// reason, and how many consecutive restarts have happened already.
fn restart_decision(
    policy: RestartPolicy,
    reason: &TrapReason,
    restarts_done: u32,
) -> RestartDecision {
    let policy_allows = match policy {
        RestartPolicy::Never => false,
        RestartPolicy::Always => true,
        // `on-trap` restarts real traps but not a clean `init` failure
        // — retrying a deterministic config error won't fix it.
        RestartPolicy::OnTrap => matches!(reason, TrapReason::Trap(_)),
    };
    if policy_allows && restarts_done < MAX_RESTARTS {
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
        /// The instance stayed `Running` at least [`HEALTHY_RESET`]
        /// — long enough to reset the consecutive-restart counter.
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
    mut control_rx: mpsc::Receiver<ControlCommand>,
    state_tx: watch::Sender<InstanceState>,
) {
    // Subscribe the wakeup receiver *before* loading so no publish
    // between now and the run loop is missed: the broadcast channel
    // buffers wakeups until the loop's first `recv`. Reused across
    // restarts — a fresh instance re-subscribes its own receivers.
    let mut wakeup = engine.events().subscribe_all().receiver;
    let backoff = BackoffPolicy::new();
    // Consecutive restarts; reset once an instance runs healthily.
    let mut restarts: u32 = 0;

    loop {
        let outcome = run_one_lifecycle(
            &engine,
            &plugin_dir,
            &instance_id,
            overrides.as_ref(),
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
                if restart_decision(policy, &reason, restarts) == RestartDecision::GiveUp {
                    let error = if restarts >= MAX_RESTARTS {
                        format!(
                            "gave up after {MAX_RESTARTS} consecutive restarts; last crash: {reason}",
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
async fn run_one_lifecycle(
    engine: &Engine,
    plugin_dir: &Path,
    instance_id: &str,
    overrides: Option<&toml::Value>,
    control_rx: &mut mpsc::Receiver<ControlCommand>,
    wakeup: &mut broadcast::Receiver<Event>,
    state_tx: &watch::Sender<InstanceState>,
) -> LifecycleOutcome {
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
    let policy = instance.manifest().runtime.restart;

    match instance.init().await {
        Ok(()) => {}
        Err(InitError::Plugin(msg)) => {
            return LifecycleOutcome::Crashed {
                policy,
                reason: TrapReason::InitFailed(msg),
                ran_healthy: false,
            };
        }
        Err(InitError::Trap(msg)) => {
            return LifecycleOutcome::Crashed {
                policy,
                reason: TrapReason::Trap(msg),
                ran_healthy: false,
            };
        }
    }
    transition(state_tx, instance_id, InstanceState::Inited);

    // Deliver anything the plugin's subscriptions buffered during init.
    if let Err(e) = instance.drain_events().await {
        return LifecycleOutcome::Crashed {
            policy,
            reason: TrapReason::Trap(format!("event drain failed: {e:#}")),
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
            ran_healthy: running_since.elapsed() >= HEALTHY_RESET,
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
                    return ServeOutcome::Crashed(TrapReason::Trap(format!(
                        "event drain failed: {e:#}"
                    )));
                }
            }
            Ok(LoopAction::Stop) => {
                transition(state_tx, instance_id, InstanceState::Stopped);
                return ServeOutcome::Stopped;
            }
            Err(e) => return ServeOutcome::Crashed(TrapReason::Trap(format!("{e:#}"))),
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
                Some(ControlCommand::Execute { reply, .. }) => {
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_ceiling_doubles_then_caps_at_max() {
        let policy = BackoffPolicy::new();
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
        let policy = BackoffPolicy::new();
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
                restart_decision(RestartPolicy::Never, &reason, 0),
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
                restart_decision(RestartPolicy::Always, &reason, 0),
                RestartDecision::Restart,
            );
            assert_eq!(
                restart_decision(RestartPolicy::Always, &reason, MAX_RESTARTS - 1),
                RestartDecision::Restart,
            );
        }
    }

    #[test]
    fn on_trap_policy_restarts_traps_but_not_init_failures() {
        assert_eq!(
            restart_decision(RestartPolicy::OnTrap, &TrapReason::Trap("x".into()), 0),
            RestartDecision::Restart,
        );
        assert_eq!(
            restart_decision(
                RestartPolicy::OnTrap,
                &TrapReason::InitFailed("x".into()),
                0,
            ),
            RestartDecision::GiveUp,
        );
    }

    #[test]
    fn restart_cap_gives_up_even_for_an_always_policy() {
        let reason = TrapReason::Trap("x".into());
        assert_eq!(
            restart_decision(RestartPolicy::Always, &reason, MAX_RESTARTS),
            RestartDecision::GiveUp,
        );
        assert_eq!(
            restart_decision(RestartPolicy::Always, &reason, MAX_RESTARTS + 1),
            RestartDecision::GiveUp,
        );
    }
}
