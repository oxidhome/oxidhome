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
//! `Stopping → Stopped` on a clean shutdown and `Failed` on any crash.
//! Crash *recovery* (restart policy + backoff) lands in Phase 6c — for
//! now a crash is terminal.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::{Interval, MissedTickBehavior};

use crate::Engine;
use crate::host_impl::plugin::oxidhome::plugin::devices::{Command, CommandResult};
use crate::host_impl::plugin::oxidhome::plugin::types::DeviceId;

use super::instance::PluginInstance;

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
    /// A clean `shutdown` is in flight.
    Stopping,
    /// Clean terminal state — `shutdown` completed.
    Stopped,
    /// Unrecoverable terminal state. Carries the failure message.
    /// Phase 6c turns the crash paths that land here into restarts
    /// where the manifest's `restart` policy permits.
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
                    return Err(anyhow!(
                        "instance `{}` stopped before reaching Running",
                        self.instance_id,
                    ));
                }
                InstanceState::Loading | InstanceState::Inited | InstanceState::Stopping => {}
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

/// The supervisor task body — see the module docs.
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
    // buffers wakeups until the loop's first `recv`.
    let mut wakeup = engine.events().subscribe_all().receiver;

    let mut instance = match PluginInstance::load_with_overrides(
        &engine,
        &plugin_dir,
        instance_id.to_string(),
        overrides.as_ref(),
    )
    .await
    {
        Ok(instance) => instance,
        Err(e) => {
            transition(
                &state_tx,
                &instance_id,
                InstanceState::Failed {
                    error: format!("load failed: {e:#}"),
                },
            );
            return;
        }
    };

    if let Err(e) = instance.init().await {
        transition(
            &state_tx,
            &instance_id,
            InstanceState::Failed {
                error: format!("init failed: {e:#}"),
            },
        );
        return;
    }
    transition(&state_tx, &instance_id, InstanceState::Inited);

    // Deliver anything the plugin's subscriptions buffered during init.
    if let Err(e) = instance.drain_events().await {
        transition(
            &state_tx,
            &instance_id,
            InstanceState::Failed {
                error: format!("event drain failed: {e:#}"),
            },
        );
        return;
    }

    // Build the tick interval if the manifest declares a cadence. The
    // floor (`MIN_TICK_INTERVAL_MS`) is enforced at manifest validation.
    let mut tick: Option<Interval> = instance.manifest().runtime.tick_interval_ms.map(|ms| {
        let mut interval = tokio::time::interval(Duration::from_millis(ms));
        // A slow tick body must not make the loop "catch up" with a
        // burst of back-to-back ticks; delay the schedule instead.
        interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        interval
    });

    transition(&state_tx, &instance_id, InstanceState::Running);

    let mut bus_open = true;
    loop {
        let outcome: anyhow::Result<LoopAction> = tokio::select! {
            ctrl = control_rx.recv() => {
                handle_control(&mut instance, &state_tx, &instance_id, ctrl).await
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
                    transition(
                        &state_tx,
                        &instance_id,
                        InstanceState::Failed {
                            error: format!("event drain failed: {e:#}"),
                        },
                    );
                    return;
                }
            }
            Ok(LoopAction::Stop) => {
                transition(&state_tx, &instance_id, InstanceState::Stopped);
                return;
            }
            Err(e) => {
                transition(
                    &state_tx,
                    &instance_id,
                    InstanceState::Failed {
                        error: format!("{e:#}"),
                    },
                );
                return;
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
