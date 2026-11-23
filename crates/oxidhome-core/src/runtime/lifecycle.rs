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
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::{Instant, Interval, MissedTickBehavior};

use crate::Engine;
use crate::auth::invocation::{self, InvocationContext};
use crate::host_impl::plugin::oxidhome::plugin::devices::{Command, CommandResult};
use crate::host_impl::plugin::oxidhome::plugin::types::{
    DeviceId, Error as WitError, KeyValue, ServiceId,
};
use crate::state::CallGuard;

use super::command::{
    AbandonOnDrop, CommandOutcome, CommandReport, DispatchTicket, PendingCommands, mint_command_id,
};
use super::instance::{ComponentCache, InitError, PluginInstance, SupervisedLoad};
use super::sandbox::{SandboxLauncher, SandboxRole, SandboxScript};

/// How long a plugin call that is running when a stop is requested
/// may take to finish before the supervisor cancels it. Covers a guest
/// blocked in a host import (a WASI `sleep`, a slow `call-service`),
/// which the epoch watchdog can't interrupt.
pub const STOP_GRACE: Duration = Duration::from_secs(2);

/// Upper bound the API stop handlers wait for a stopped instance to be
/// reaped. A parent's `on-shutdown` and then its sandboxes' (in
/// parallel) are each bounded by the watchdog, plus [`STOP_GRACE`] for
/// a call in flight; this leaves room for both and some scheduling.
pub const STOP_WAIT_LIMIT: Duration = Duration::from_secs(75);

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
    /// point. Production uses `watchdog::WATCHDOG_DEFAULT`; tests
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
    /// `ctx` is the invocation the command belongs to (H6); the
    /// supervisor scopes it on its task while the wasm runs and
    /// refuses the command if its deadline has passed by the time it
    /// is dequeued.
    ///
    /// H5: `ticket` is shared with the waiting caller; the supervisor
    /// runs the command only if it wins `queued → started` (see
    /// [`super::command`]). The reply is the explicit outcome.
    Execute {
        ctx: InvocationContext,
        device: DeviceId,
        cmd: Command,
        ticket: DispatchTicket,
        reply: oneshot::Sender<CommandOutcome>,
    },
    /// Run the plugin's `execute-service-command` on a service it owns
    /// — the dispatcher hops to this on the owner's supervisor task so
    /// the single-`Store` contract holds. `ctx` is the callee's
    /// invocation context, whose delegation chain is the full
    /// in-flight `call-service` chain (caller's parent chain + the
    /// hop for this call); the supervisor scopes it on its task
    /// before driving the wasm so nested `call-service`s from inside
    /// `execute-service-command` see the full chain for cycle checks
    /// and inherit the root principal and deadline (H6).
    ///
    /// `guard` holds the [`CallGuard`] the dispatcher acquired before
    /// sending the message. It rides with the work so the in-flight
    /// refcount tracks *real* execution: the supervisor takes it when
    /// it starts the call and drops it when the wasm call finishes
    /// (`handle_control` holds it across the scoped invocation). A
    /// caller that withdraws the still-queued call takes and drops it
    /// at once, so the queued message doesn't hold up
    /// `remove-service`; otherwise it drops with the message. Nothing
    /// *reads* it — `Drop` does the decrement.
    ///
    /// H5: `ticket` works as for `Execute`: the supervisor enters the
    /// callee only if it wins `queued → started`, so a caller that
    /// stopped waiting while the call was queued knows it never ran.
    /// An `Err` reply means the call did not run.
    ExecuteService {
        ctx: InvocationContext,
        guard: SharedCallGuard,
        service: ServiceId,
        command: String,
        args: Vec<KeyValue>,
        ticket: DispatchTicket,
        reply: oneshot::Sender<anyhow::Result<CommandResult>>,
    },
    /// Run `shutdown` and end the supervisor task.
    Shutdown { reply: oneshot::Sender<()> },
}

/// A [`CallGuard`] shared by a queued service call and its caller:
/// whoever decides the call's fate takes it — the supervisor when it
/// starts the call, the caller when it withdraws it.
#[derive(Clone, Debug)]
pub(crate) struct SharedCallGuard(Arc<std::sync::Mutex<Option<CallGuard>>>);

impl SharedCallGuard {
    fn new(guard: CallGuard) -> Self {
        Self(Arc::new(std::sync::Mutex::new(Some(guard))))
    }

    fn take(&self) -> Option<CallGuard> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
    }

    /// Drop the guard (if still held) under the lock, so whoever finds
    /// it gone knows the refcount was already decremented.
    fn release(&self) {
        let mut slot = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        drop(slot.take());
    }
}

/// Releases the [`SharedCallGuard`] of a service call that never
/// started once its caller stops waiting. Declared before the
/// call's [`AbandonOnDrop`] so it drops after the ticket is settled.
struct ReleaseUnlessStarted {
    ticket: DispatchTicket,
    guard: SharedCallGuard,
}

impl Drop for ReleaseUnlessStarted {
    fn drop(&mut self) {
        if !self.ticket.started() {
            self.guard.release();
        }
    }
}

/// How a service call dispatched to the owner's supervisor ended
/// (H5, the service-call side of [`super::command`]).
#[derive(Debug)]
pub(crate) enum ServiceCallOutcome {
    /// The callee ran and replied. A trap mid-call is
    /// `CommandResult::Unknown` here, since the callee was entered.
    Replied(CommandResult),
    /// The call did not run and never will (supervisor gone, instance
    /// restarting, refused at dequeue); safe to retry.
    NotRun(String),
    /// The caller's wait ended while the call was still queued; it did
    /// not run and never will. Safe to retry.
    TimedOut,
    /// The callee was entered but no reply arrived (the wait ended
    /// mid-call, or its supervisor went away): it may have acted.
    Unknown(String),
}

/// Facts the supervisor learns on the first successful load and
/// shares with its [`InstanceHandle`]. Each slot is set once; later
/// restarts of the same install produce the same values.
#[derive(Debug, Default)]
pub(crate) struct LoadedSlots {
    installation_uuid: std::sync::OnceLock<Arc<str>>,
    config_view: std::sync::OnceLock<Arc<serde_json::Value>>,
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
    /// Host-minted per-install UUID (`inst-<32 hex>`), pinned by the
    /// supervisor after the first successful load. `None` while the
    /// instance is still `Loading`. Shared with the supervisor task
    /// via `Arc<OnceLock<_>>` so the handle and the task see the
    /// same slot; the supervisor sets it exactly once (subsequent
    /// restarts of the same install re-set to the same value and
    /// `OnceLock::set` returns `Err`, which we swallow).
    loaded: Arc<LoadedSlots>,
    control: mpsc::Sender<ControlCommand>,
    state: watch::Receiver<InstanceState>,
    /// Set once a stop is requested. The supervisor stops on it even if
    /// no `Shutdown` message arrives, and cancels a plugin call still
    /// running [`STOP_GRACE`] after it is set.
    stop: Arc<watch::Sender<bool>>,
    /// Set by the reaper once the instance has left the registry (a
    /// registry-managed instance only).
    reaped: Arc<watch::Sender<bool>>,
    /// ADR-0001: for a script sandbox, the script it runs.
    sandbox: Option<Arc<SandboxScript>>,
}

impl InstanceHandle {
    /// A handle whose supervisor never runs: the instance is already
    /// `Failed` with `error`. The `supervise*` entry points return one
    /// for an instance id they refuse.
    fn refused(instance_id: String, plugin_id: String, error: String) -> Self {
        tracing::warn!(instance_id = %instance_id, error = %error, "supervise refused");
        let (control, _rx) = mpsc::channel(1);
        let (_tx, state) = watch::channel(InstanceState::Failed { error });
        Self {
            instance_id: Arc::from(instance_id),
            plugin_id: Arc::from(plugin_id),
            loaded: Arc::default(),
            control,
            state,
            stop: Arc::new(watch::Sender::new(false)),
            reaped: Arc::new(watch::Sender::new(false)),
            sandbox: None,
        }
    }

    /// Round-9 F2: test-only constructor for
    /// `runtime::registry::tests`, which needs a plausible
    /// `InstanceHandle` to feed into `InstanceRegistry::register`
    /// without actually spinning up a supervisor. The
    /// control channel has no attached receiver, so any
    /// `execute_command` call on the returned handle will
    /// fail (the send errors and the handler surfaces
    /// that). Round-11 F3 correction: `stop()` on this
    /// handle returns `Ok(())` — its implementation
    /// deliberately treats a closed control channel as
    /// "already Stopped or Failed" (idempotent), so it
    /// does NOT fail here; it just doesn't do anything.
    /// The registry test never exercises either path.
    ///
    /// Round-10 F3: the watch is seeded with `Stopped` (a
    /// terminal state) instead of `Loading`, so
    /// [`Self::wait_terminal`]'s contract holds — a
    /// caller who happens to await terminal on this
    /// handle sees `Stopped` immediately rather than
    /// getting back the non-terminal `Loading` value the
    /// receiver would otherwise borrow after the sender's
    /// drop wakes `changed()` with `Err`.
    #[cfg(test)]
    pub(crate) fn for_registry_test(instance_id: &str, plugin_id: &str) -> Self {
        let (control, _rx) = tokio::sync::mpsc::channel(1);
        let (_tx, state) = tokio::sync::watch::channel(InstanceState::Stopped);
        Self {
            instance_id: Arc::from(instance_id),
            plugin_id: Arc::from(plugin_id),
            // Registry-test handles never run a real load, so
            // the cell stays unset — mirrors the `Loading` state
            // that never advanced to a first successful load.
            loaded: Arc::default(),
            control,
            state,
            stop: Arc::new(watch::Sender::new(false)),
            reaped: Arc::new(watch::Sender::new(false)),
            sandbox: None,
        }
    }

    /// A handle that reports `Running` forever, for sandbox-registry
    /// unit tests that need a live child.
    #[cfg(test)]
    pub(crate) fn running_for_test(instance_id: &str, plugin_id: &str) -> Self {
        let (control, _rx) = tokio::sync::mpsc::channel(1);
        let (_tx, state) = tokio::sync::watch::channel(InstanceState::Running);
        Self {
            instance_id: Arc::from(instance_id),
            plugin_id: Arc::from(plugin_id),
            loaded: Arc::default(),
            control,
            state,
            stop: Arc::new(watch::Sender::new(false)),
            reaped: Arc::new(watch::Sender::new(false)),
            sandbox: None,
        }
    }

    /// The instance id this supervisor was started with.
    #[must_use]
    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }

    /// ADR-0001: for a script sandbox, the instance that started it.
    /// `None` for any other instance.
    #[must_use]
    pub fn parent_instance_id(&self) -> Option<&str> {
        self.sandbox.as_deref().map(SandboxScript::parent_instance)
    }

    /// ADR-0001: for a script sandbox, its `local-id` within the
    /// parent. `None` for any other instance.
    #[must_use]
    pub fn sandbox_local_id(&self) -> Option<&str> {
        self.sandbox.as_deref().map(SandboxScript::local_id)
    }

    /// The manifest-resolved `plugin.id` this instance is a copy of.
    /// Stable across the instance's lifetime (the manifest is
    /// read-once at load and pinned to the supervisor).
    #[must_use]
    pub fn plugin_id(&self) -> &str {
        &self.plugin_id
    }

    /// Host-minted per-install UUID (`inst-<32 hex>`) pinned to
    /// this instance's supervisor. `None` while the instance is
    /// still `Loading` (the supervisor sets the slot after the
    /// first successful component load). Callers keying store
    /// operations by `(installation_uuid, instance_id)` — MCP
    /// `oxidhome://blobs/<instance>/<name>` in particular —
    /// should treat `None` as "instance is not yet ready."
    #[must_use]
    pub fn installation_uuid(&self) -> Option<&str> {
        self.loaded.installation_uuid.get().map(Arc::as_ref)
    }

    /// M7: the instance's resolved config as the read APIs show it —
    /// [`crate::redact::masked_config_view`], so `type = "secret"`
    /// fields carry a `set` flag and `"***"`, never the plaintext.
    /// `None` until the first successful load (same lifecycle as
    /// [`Self::installation_uuid`]).
    #[must_use]
    pub fn config_view(&self) -> Option<serde_json::Value> {
        self.loaded.config_view.get().map(|v| (**v).clone())
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

    /// Run the plugin's `execute-command` for `device` as a
    /// host-origin invocation (no external principal, no deadline).
    /// External entry points use [`Self::execute_command_in`].
    pub async fn execute_command(&self, device: DeviceId, cmd: Command) -> CommandReport {
        let ctx = InvocationContext::host_origin(&self.instance_id);
        self.execute_command_in(ctx, device, cmd).await
    }

    /// Run the plugin's `execute-command` for `device` on behalf of
    /// `ctx` (H6). The supervisor installs `ctx` while the wasm runs,
    /// so a `call-service` the plugin makes is attributed to `ctx`'s
    /// root principal and bounded by its deadline.
    ///
    /// H5: mints the command id (overwriting `cmd.id`) and always
    /// returns an explicit outcome — this never fails. `timed_out` is
    /// reported only for a command the plugin will never see; once the
    /// supervisor has entered the plugin, a missed deadline, a trap or
    /// a lost supervisor is `outcome_unknown`. Dropping the returned
    /// future withdraws a still-queued command.
    pub async fn execute_command_in(
        &self,
        ctx: InvocationContext,
        device: DeviceId,
        mut cmd: Command,
    ) -> CommandReport {
        let command_id = mint_command_id();
        cmd.id.clone_from(&command_id);
        let outcome = self.dispatch_command(ctx, device, cmd).await;
        CommandReport {
            command_id,
            outcome,
        }
    }

    async fn dispatch_command(
        &self,
        ctx: InvocationContext,
        device: DeviceId,
        cmd: Command,
    ) -> CommandOutcome {
        let ticket = DispatchTicket::default();
        // Declared before `_withdraw` so a dropped caller withdraws the
        // ticket before its reply channel closes: the supervisor can't
        // claim the command for a receiver that is already gone.
        let (reply, mut rx) = oneshot::channel();
        let _withdraw = AbandonOnDrop(ticket.clone());
        let deadline = ctx.deadline();
        let call_id = ctx.call_id().to_owned();
        let timed_out = || CommandOutcome::TimedOut {
            message: format!(
                "invocation `{call_id}` deadline passed before instance `{}` started the \
                 command; it did not run",
                self.instance_id,
            ),
        };
        let enqueue = self.control.send(ControlCommand::Execute {
            ctx,
            device,
            cmd,
            ticket: ticket.clone(),
            reply,
        });
        let enqueued = match deadline {
            Some(d) => match tokio::time::timeout_at(d, enqueue).await {
                Ok(enqueued) => enqueued,
                // Never enqueued.
                Err(_) => return timed_out(),
            },
            None => enqueue.await,
        };
        if enqueued.is_err() {
            return CommandOutcome::Rejected {
                error: WitError::Unavailable(format!(
                    "instance `{}` is not running",
                    self.instance_id
                )),
            };
        }
        let received = if let Some(d) = deadline {
            let Ok(received) = tokio::time::timeout_at(d, &mut rx).await else {
                if ticket.try_withdraw() {
                    return timed_out();
                }
                // Entered before the deadline; the reply may have
                // landed in the same instant. Closing first makes the
                // race binary: a reply sent after this point fails, and
                // the supervisor audits it as a late result.
                rx.close();
                return rx.try_recv().unwrap_or_else(|_| CommandOutcome::Unknown {
                    message: format!(
                        "invocation `{call_id}` deadline passed while instance `{}` was \
                         executing the command; it may have taken effect",
                        self.instance_id,
                    ),
                });
            };
            received
        } else {
            (&mut rx).await
        };
        received.unwrap_or_else(|_| {
            if ticket.started() {
                CommandOutcome::Unknown {
                    message: format!(
                        "instance `{}` supervisor went away while executing the command",
                        self.instance_id,
                    ),
                }
            } else {
                CommandOutcome::Rejected {
                    error: WitError::Unavailable(format!(
                        "instance `{}` stopped before running the command",
                        self.instance_id,
                    )),
                }
            }
        })
    }

    /// Run the plugin's `execute-service-command` on `service`. Used
    /// by [`crate::runtime::dispatcher`]'s cross-instance routing —
    /// always hops to the *owner*'s supervisor task so the
    /// single-`Store` contract holds.
    ///
    /// `ctx` is the callee's invocation context (its chain is the full
    /// in-flight `call-service` chain leading to this call); the
    /// callee's supervisor scopes it on its own task before invoking
    /// the wasm, so cycle detection and root attribution survive the
    /// task hop.
    ///
    /// H5: the call carries the same dispatch ticket as a device
    /// command. The caller waits until `wait_until`; if that passes
    /// while the call is still queued it never runs
    /// ([`ServiceCallOutcome::TimedOut`]), and once the callee was
    /// entered a missed deadline or a lost supervisor is
    /// [`ServiceCallOutcome::Unknown`]. Dropping the returned future
    /// withdraws a still-queued call.
    ///
    /// **Caller blocking note.** The caller's supervisor task is
    /// parked on the oneshot until this returns, so any other control
    /// message (including `stop`) queued on the caller's mpsc waits
    /// up to [`crate::runtime::dispatcher::DISPATCH_TIMEOUT`] for the
    /// service call to complete.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn execute_service_command(
        &self,
        ctx: InvocationContext,
        guard: CallGuard,
        service: ServiceId,
        command: String,
        args: Vec<KeyValue>,
        ticket: DispatchTicket,
        wait_until: Instant,
    ) -> ServiceCallOutcome {
        let guard = SharedCallGuard::new(guard);
        // Drop order: `_withdraw` settles the ticket, then `_release`
        // frees the guard of a call that will never start, then the
        // reply channel closes (so the supervisor can't claim the call
        // for a receiver that is already gone).
        let (reply, mut rx) = oneshot::channel();
        let _release = ReleaseUnlessStarted {
            ticket: ticket.clone(),
            guard: guard.clone(),
        };
        let _withdraw = AbandonOnDrop(ticket.clone());
        // If the send fails (control channel closed), `_release` drops
        // the `CallGuard` → refcount decrements cleanly even on the
        // supervisor-gone path.
        let enqueue = self.control.send(ControlCommand::ExecuteService {
            ctx,
            guard,
            service,
            command,
            args,
            ticket: ticket.clone(),
            reply,
        });
        match tokio::time::timeout_at(wait_until, enqueue).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) => {
                return ServiceCallOutcome::NotRun(format!(
                    "instance `{}` supervisor is no longer running",
                    self.instance_id,
                ));
            }
            // Never enqueued.
            Err(_) => return ServiceCallOutcome::TimedOut,
        }
        let Ok(received) = tokio::time::timeout_at(wait_until, &mut rx).await else {
            if ticket.try_withdraw() {
                return ServiceCallOutcome::TimedOut;
            }
            // Entered before the deadline; as for device commands,
            // close first so a reply landing now is either taken here
            // or fails on the supervisor's side.
            rx.close();
            return match rx.try_recv() {
                Ok(Ok(result)) => ServiceCallOutcome::Replied(result),
                Ok(Err(err)) => ServiceCallOutcome::NotRun(format!("{err:#}")),
                Err(_) => ServiceCallOutcome::Unknown(format!(
                    "the deadline passed while instance `{}` was executing the call",
                    self.instance_id,
                )),
            };
        };
        match received {
            Ok(Ok(result)) => ServiceCallOutcome::Replied(result),
            Ok(Err(err)) => ServiceCallOutcome::NotRun(format!("{err:#}")),
            Err(_) if ticket.started() => ServiceCallOutcome::Unknown(format!(
                "instance `{}` supervisor went away while executing the call",
                self.instance_id,
            )),
            Err(_) => ServiceCallOutcome::NotRun(format!(
                "instance `{}` stopped before running the call",
                self.instance_id,
            )),
        }
    }

    /// Ask the supervisor to stop, without waiting. A plugin call in
    /// flight gets [`STOP_GRACE`] to finish and is then cancelled (so
    /// a guest blocked in a host import can't hold the stop up), then
    /// `on-shutdown` runs, bounded by the watchdog. Commands still
    /// queued are refused as `unavailable` without running.
    /// Idempotent.
    pub fn request_stop(&self) {
        self.stop.send_replace(true);
    }

    /// Whether a stop was requested.
    pub(crate) fn stop_requested(&self) -> bool {
        *self.stop.borrow()
    }

    /// Ask the supervisor to run `shutdown` and end the task, and wait
    /// until the instance is terminal: its `Store` is dropped by then.
    /// See [`Self::request_stop`]. Idempotent — calling `stop` on an
    /// already-terminal instance returns `Ok(())`.
    ///
    /// # Errors
    ///
    /// This call itself does not fail; the `Result` is reserved for a
    /// future where `stop` can report a shutdown trap.
    pub async fn stop(&self) -> anyhow::Result<()> {
        self.request_stop();
        let (reply, rx) = oneshot::channel();
        if self
            .control
            .send(ControlCommand::Shutdown { reply })
            .await
            .is_ok()
        {
            // A dropped reply means the task ended before acking;
            // that's still "stopped" from the caller's point of view.
            let _ = rx.await;
        }
        // Supervisor already exited, or acked: either way, wait for the
        // terminal state, which is published after the `Store` drop.
        self.wait_terminal().await;
        Ok(())
    }

    /// Wait until the reaper has released the instance: it is terminal,
    /// its sandboxes (for a parent) are gone, and it has left the
    /// instance registry. Only registry-managed instances
    /// ([`crate::Engine::start_instance`] and the sandboxes they start)
    /// are reaped; for any other this never returns.
    pub async fn wait_reaped(&self) {
        let mut rx = self.reaped.subscribe();
        // `Err` means every sender dropped, which can't happen while
        // `self` holds one.
        let _ = rx.wait_for(|reaped| *reaped).await;
    }

    /// Reaper hook: the instance has been released.
    pub(crate) fn mark_reaped(&self) {
        self.reaped.send_replace(true);
    }
}

/// What [`stop_and_wait_reaped`] saw.
#[derive(Debug, Default)]
pub struct StopWaitReport {
    /// Instances that stopped and were reaped in time.
    pub stopped: Vec<String>,
    /// Instances asked to stop that weren't reaped before the bound.
    /// They keep stopping in the background.
    pub still_stopping: Vec<String>,
}

/// Ask every instance in `handles` to stop at once, then wait for each
/// to be reaped (see [`InstanceHandle::wait_reaped`]), at most `bound`
/// in total. The API stop handlers use this with [`STOP_WAIT_LIMIT`]:
/// a parent is reaped only once its sandboxes are, so waiting for the
/// reap (not just the parent's terminal state) means a stopped plugin
/// leaves nothing running.
pub async fn stop_and_wait_reaped(handles: Vec<InstanceHandle>, bound: Duration) -> StopWaitReport {
    for handle in &handles {
        handle.request_stop();
    }
    let deadline = Instant::now() + bound;
    let mut report = StopWaitReport::default();
    for handle in handles {
        let id = handle.instance_id().to_owned();
        if tokio::time::timeout_at(deadline, handle.wait_reaped())
            .await
            .is_ok()
        {
            report.stopped.push(id);
        } else {
            tracing::warn!(
                instance_id = %id,
                bound_ms = u64::try_from(bound.as_millis()).unwrap_or(u64::MAX),
                "instance still stopping after the stop wait limit",
            );
            report.still_stopping.push(id);
        }
    }
    report
}

/// Spawn a supervisor task for the plugin in `plugin_dir` and return
/// its [`InstanceHandle`] immediately. The task loads, `init`s, and
/// then runs the instance until `shutdown` or a crash; the handle's
/// `watch` channel reports progress (starts at
/// [`InstanceState::Loading`]).
/// Spawn a supervisor task for a dev-time load. Test / harness
/// entrypoint; the daemon reaches this indirectly via
/// [`crate::Engine::start_instance`] (dev) or
/// [`crate::Engine::start_installed_instance`] (production).
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
    supervise_with_tuning_and_mode(
        engine,
        plugin_dir,
        instance_id,
        plugin_id,
        overrides,
        crate::runtime::LoadMode::Dev,
        tuning,
    )
}

/// H11 round-2 F1: full-fidelity supervisor spawn with explicit
/// `LoadMode` and tuning. Used by
/// [`crate::Engine::start_instance_with_tuning`] (which the API
/// paths and dev-load path both route through with their chosen
/// mode). `supervise` / `supervise_with_tuning` above are the
/// `LoadMode::Dev` sugar for tests.
///
/// Phase 6 leftover TOCTOU fix + round-2 F3:
/// `first_load_pinned_manifest` is the pre-parsed manifest
/// snapshot that pre-flight used to decide the singleton
/// slot / `plugin_id`. When present, the supervisor uses
/// those exact bytes on **every** load attempt (first load
/// and every restart) — the manifest is treated as
/// immutable for the supervisor's lifetime. An atomic
/// replace of `manifest.toml` during startup or restart
/// backoff can no longer sneak a mismatched identity or
/// capability set past the registry.
///
/// `None` is the test-suite entry (`supervise` /
/// `supervise_with_tuning`) that spawns without a
/// pre-flight step; those tests re-read the manifest on
/// every attempt (their pin is deliberately absent).
#[doc(hidden)]
#[must_use]
pub fn supervise_with_tuning_and_mode(
    engine: Engine,
    plugin_dir: PathBuf,
    instance_id: impl Into<String>,
    plugin_id: impl Into<String>,
    overrides: Option<toml::Value>,
    mode: crate::runtime::LoadMode,
    tuning: SupervisorTuning,
) -> InstanceHandle {
    supervise_with_tuning_mode_and_pin(
        engine,
        plugin_dir,
        instance_id,
        plugin_id,
        overrides,
        mode,
        tuning,
        None,
    )
}

#[doc(hidden)]
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn supervise_with_tuning_mode_and_pin(
    engine: Engine,
    plugin_dir: PathBuf,
    instance_id: impl Into<String>,
    plugin_id: impl Into<String>,
    overrides: Option<toml::Value>,
    mode: crate::runtime::LoadMode,
    tuning: SupervisorTuning,
    first_load_pinned_manifest: Option<(Vec<u8>, oxidhome_manifest::PluginManifest)>,
) -> InstanceHandle {
    let instance_id = instance_id.into();
    let plugin_id = plugin_id.into();
    // These helpers bypass the instance registry, so they can't claim
    // an id the registry or the sandbox namespace owns. The refusal is
    // an already-`Failed` handle, so callers see it where they'd see a
    // load failure.
    if let Err(err) = super::instance::check_embedder_instance_id(&engine, &instance_id) {
        return InstanceHandle::refused(instance_id, plugin_id, format!("{err:#}"));
    }
    spawn_supervisor(
        engine,
        plugin_dir,
        instance_id,
        plugin_id,
        overrides,
        mode,
        tuning,
        first_load_pinned_manifest,
        SandboxSpawn::Disabled,
    )
}

/// ADR-0001: spawn the supervisor for a script sandbox. It loads the
/// parent's component under the parent's manifest snapshot, load mode,
/// config overrides and tuning; only the instance id and the script
/// differ.
pub(crate) fn supervise_sandbox(
    engine: Engine,
    launcher: &SandboxLauncher,
    instance_id: String,
    plugin_id: String,
    script: Arc<SandboxScript>,
) -> InstanceHandle {
    spawn_supervisor(
        engine,
        launcher.plugin_dir.clone(),
        instance_id,
        plugin_id,
        launcher.overrides.clone(),
        launcher.mode.clone(),
        launcher.tuning.clone(),
        launcher.pinned_manifest.clone(),
        SandboxSpawn::Child {
            script,
            cache: Arc::clone(&launcher.component_cache),
        },
    )
}

/// ADR-0001: a new supervisor's place in the sandbox model.
pub(crate) enum SandboxSpawn {
    /// Can't start sandboxes: the supervisor isn't registry-managed
    /// (`supervise*` entry points), so nothing would reap its children.
    Disabled,
    /// A registry-managed instance; its reaper stops its sandboxes.
    Parent,
    /// A script sandbox. It shares its parent's compiled component.
    Child {
        script: Arc<SandboxScript>,
        cache: Arc<ComponentCache>,
    },
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn spawn_supervisor(
    engine: Engine,
    plugin_dir: PathBuf,
    instance_id: String,
    plugin_id: String,
    overrides: Option<toml::Value>,
    mode: crate::runtime::LoadMode,
    tuning: SupervisorTuning,
    first_load_pinned_manifest: Option<(Vec<u8>, oxidhome_manifest::PluginManifest)>,
    sandbox: SandboxSpawn,
) -> InstanceHandle {
    let instance_id: Arc<str> = Arc::from(instance_id);
    let plugin_id: Arc<str> = Arc::from(plugin_id);
    let (control_tx, control_rx) = mpsc::channel(16);
    let (state_tx, state_rx) = watch::channel(InstanceState::Loading);
    let (stop_tx, stop_rx) = watch::channel(false);
    let loaded: Arc<LoadedSlots> = Arc::default();
    // ADR-0001 follow-up: compile once per supervisor. A supervisor
    // whose manifest is pinned pins the component bytes with it, and
    // its sandboxes share that cache; the unpinned test entry points
    // re-read both on every attempt.
    let own_cache = || first_load_pinned_manifest.as_ref().map(|_| Arc::default());
    // ADR-0001: a sandbox serves its script to `current-sandbox`; any
    // other instance may start sandboxes of itself with the inputs
    // this supervisor was spawned with.
    let (sandbox_role, component_cache, child_script) = match sandbox {
        SandboxSpawn::Disabled => (None, own_cache(), None),
        SandboxSpawn::Parent => {
            let cache: Arc<ComponentCache> = own_cache().unwrap_or_default();
            let launcher = SandboxLauncher {
                engine: engine.clone(),
                plugin_dir: plugin_dir.clone(),
                overrides: overrides.clone(),
                mode: mode.clone(),
                tuning: tuning.clone(),
                pinned_manifest: first_load_pinned_manifest.clone(),
                component_cache: Arc::clone(&cache),
            };
            (
                Some(SandboxRole::Parent(Arc::new(launcher))),
                Some(cache),
                None,
            )
        }
        SandboxSpawn::Child { script, cache } => (
            Some(SandboxRole::Child(Arc::clone(&script))),
            Some(cache),
            Some(script),
        ),
    };
    let handle = InstanceHandle {
        instance_id: Arc::clone(&instance_id),
        plugin_id: Arc::clone(&plugin_id),
        loaded: Arc::clone(&loaded),
        control: control_tx,
        state: state_rx,
        stop: Arc::new(stop_tx),
        reaped: Arc::new(watch::Sender::new(false)),
        sandbox: child_script,
    };
    tokio::spawn(run_supervisor(
        engine,
        plugin_dir,
        instance_id,
        overrides,
        tuning,
        mode,
        Channels {
            control: control_rx,
            state: state_tx,
            stop: stop_rx,
        },
        loaded,
        first_load_pinned_manifest,
        sandbox_role,
        component_cache,
    ));
    handle
}

/// The supervisor's ends of its handle's channels.
struct Channels {
    control: mpsc::Receiver<ControlCommand>,
    state: watch::Sender<InstanceState>,
    stop: watch::Receiver<bool>,
}

/// Whether a stop was requested, or every handle is gone: the check
/// between plugin calls, matching [`stop_requested`].
fn stop_is_requested(stop: &watch::Receiver<bool>) -> bool {
    *stop.borrow() || stop.has_changed().is_err()
}

/// Resolves once a stop is requested, or every handle is gone (also a
/// stop request, and the only one a guest blocked in a host import
/// can hear).
async fn stop_requested(stop: &mut watch::Receiver<bool>) {
    let _ = stop.wait_for(|requested| *requested).await;
}

/// Drive one plugin call. If a stop is requested while it runs, it
/// gets [`STOP_GRACE`] to finish; past that it is cancelled (`None`):
/// the future is dropped, which also cancels a guest blocked in a host
/// import. A cancelled instance must not be entered again.
async fn guest_call<T>(
    stop: &mut watch::Receiver<bool>,
    call: impl std::future::Future<Output = T>,
) -> Option<T> {
    tokio::pin!(call);
    tokio::select! {
        biased;
        out = &mut call => return Some(out),
        () = stop_requested(stop) => {}
    }
    tokio::time::timeout(STOP_GRACE, call).await.ok()
}

/// The supervisor's control receiver. When the supervisor ends, the
/// commands still queued are refused through [`refuse_unserved`]
/// instead of dropped. `run_supervisor` drains it before publishing
/// the terminal state; `Drop` is the backstop for any other exit.
struct ControlQueue {
    rx: mpsc::Receiver<ControlCommand>,
    pending: Arc<PendingCommands>,
    instance_id: Arc<str>,
}

impl std::ops::Deref for ControlQueue {
    type Target = mpsc::Receiver<ControlCommand>;
    fn deref(&self) -> &Self::Target {
        &self.rx
    }
}

impl std::ops::DerefMut for ControlQueue {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.rx
    }
}

impl Drop for ControlQueue {
    fn drop(&mut self) {
        self.rx.close();
        while let Ok(command) = self.rx.try_recv() {
            refuse_unserved(
                command,
                &self.instance_id,
                "stopped before running it",
                &self.pending,
            );
        }
    }
}

/// What the run loop should do after a `select!` arm completes.
enum LoopAction {
    /// Stay in the loop (after draining pending events).
    Continue,
    /// `shutdown` ran — leave the loop with a clean `Stopped`.
    Stop,
    /// Round-3 F1: operator-requested shutdown that trapped
    /// mid-teardown. Terminal (never restarts, even under
    /// `on-trap`) — the operator asked to stop, and the
    /// stop request must be honoured regardless of guest
    /// shutdown failure. The reason string is logged and
    /// surfaces on the `Failed` transition so the audit
    /// row records the trap.
    StopFailed(String),
    /// A stop cancelled the plugin call in flight: the instance can't
    /// be entered again, so it stops without `on-shutdown`.
    Cancelled,
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
    /// Round-3 F1: operator-requested shutdown that trapped
    /// mid-teardown. Terminal — the supervisor MUST NOT
    /// restart, even under `on-trap` policy. Transitions
    /// to `Failed` with the trap reason.
    StoppedFailed(String),
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
    /// Round-3 F1: operator-requested shutdown that
    /// trapped mid-teardown. Terminal (never restarts) —
    /// carries the trap reason for the `Failed` transition
    /// in the outer supervisor.
    StoppedFailed(String),
    /// A stop cancelled the plugin call in flight.
    Cancelled,
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
#[allow(clippy::too_many_arguments)]
async fn run_supervisor(
    engine: Engine,
    plugin_dir: PathBuf,
    instance_id: Arc<str>,
    overrides: Option<toml::Value>,
    tuning: SupervisorTuning,
    mode: crate::runtime::LoadMode,
    channels: Channels,
    // Pinned by the FIRST successful load and shared with the
    // `InstanceHandle` this supervisor was spawned alongside.
    // `run_one_lifecycle` sets it via `OnceLock::set` — the
    // first successful attempt wins; every restart re-sets to
    // the same value (same install) and the `.set()` returns
    // `Err`, which is expected and ignored.
    loaded: Arc<LoadedSlots>,
    // Phase 6 leftover TOCTOU fix + review F3: when `Some`, every
    // load attempt (first load and every restart) uses this snapshot,
    // so the manifest is immutable for the supervisor's lifetime; a
    // reinstall needs a stop and start. `None` is the test-suite entry
    // (`supervise*`), which re-reads it on every attempt.
    pinned_manifest: Option<(Vec<u8>, oxidhome_manifest::PluginManifest)>,
    // ADR-0001: whether this instance is a script sandbox or may
    // start them; `None` for neither.
    sandbox_role: Option<SandboxRole>,
    // ADR-0001 follow-up: the compiled component, shared by every
    // attempt (and, for a parent, its sandboxes).
    component_cache: Option<Arc<ComponentCache>>,
) {
    let Channels {
        control,
        state: state_tx,
        stop: mut stop_rx,
    } = channels;
    let pending = engine.pending_commands();
    let mut control_rx = ControlQueue {
        rx: control,
        pending: Arc::clone(&pending),
        instance_id: Arc::clone(&instance_id),
    };
    // C2d — the pre-C2d supervisor eagerly subscribed to
    // `subscribe_all()` so every published event woke every
    // supervisor system-wide (F2 amplification). That subscription
    // is gone. The wake handle now lives on each freshly-loaded
    // `PluginInstance` (see `PluginInstance::wake`) and the bus
    // only signals it when a published event matches one of the
    // plugin's active subscription filters. Pre-init publishes
    // don't wake the supervisor for this instance — that's the
    // intended shape, since the plugin hasn't declared any
    // interest in the bus yet.
    let backoff = BackoffPolicy::new(tuning.backoff_base, tuning.backoff_max);
    // Consecutive restarts; reset once an instance runs healthily.
    let mut restarts: u32 = 0;

    // The terminal state is published only after the queue drain
    // below, so the reaper (and shutdown, which waits for it) sees
    // every refusal already queued on the journal.
    let terminal = loop {
        // Round-2 F3: clone the pinned snapshot for THIS
        // attempt, keeping the original held on the
        // supervisor stack so every subsequent restart
        // uses the same bytes. Cloning the manifest is
        // cheap — small TOML in memory. `None` means "no
        // pin was supplied at spawn"; the loader will
        // re-read on every attempt (test-suite path only).
        let pinned = pinned_manifest.clone();
        let outcome = run_one_lifecycle(
            &engine,
            &plugin_dir,
            &instance_id,
            overrides.as_ref(),
            tuning.healthy_reset,
            tuning.watchdog,
            &mode,
            &mut control_rx,
            &mut stop_rx,
            &state_tx,
            &loaded,
            pinned,
            SupervisedLoad {
                cache: component_cache.as_deref(),
                sandbox: sandbox_role.clone(),
            },
        )
        .await;

        match outcome {
            LifecycleOutcome::Stopped => break InstanceState::Stopped,
            LifecycleOutcome::StoppedFailed(reason) => {
                // Round-3 F1: operator asked to stop; the guest
                // shutdown trapped. Terminal — no restart, ever.
                break InstanceState::Failed { error: reason };
            }
            LifecycleOutcome::LoadFailed(msg) => {
                break InstanceState::Failed {
                    error: format!("load failed: {msg}"),
                };
            }
            LifecycleOutcome::Crashed {
                policy,
                reason,
                ran_healthy,
            } => {
                if ran_healthy {
                    restarts = 0;
                }
                // A stop requested while the instance was crashing
                // (say, the watchdog interrupting a call a stop was
                // waiting on) wins over the restart policy.
                if stop_is_requested(&stop_rx) {
                    break InstanceState::Stopped;
                }
                if restart_decision(policy, &reason, restarts, tuning.max_restarts)
                    == RestartDecision::GiveUp
                {
                    let error = give_up_reason(policy, &reason, restarts, tuning.max_restarts);
                    break InstanceState::Failed { error };
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
                    backoff_wait(delay, &mut control_rx, &mut stop_rx, &instance_id, &pending).await
                {
                    break InstanceState::Stopped;
                }
            }
        }
    };
    // H5: the instance is terminal. Refuse whatever is still queued
    // instead of dropping it, so a device command whose caller already
    // disconnected still gets its `COMMAND` row. `recv` (not
    // `try_recv`) after `close` also waits out a sender that reserved
    // its slot before the close, and ends once the queue is empty.
    control_rx.close();
    while let Some(ctrl) = control_rx.recv().await {
        refuse_unserved(ctrl, &instance_id, "stopped before running it", &pending);
    }
    // Its accepted commands can't complete any more. Queued before the
    // terminal state, so a journal closed right after `stop` (or a
    // `supervise` caller with no reaper) still records them as
    // stopped rather than leaving them to the next boot.
    pending.expire_owner(&instance_id, super::ExpiryReason::InstanceStopped);
    transition(&state_tx, &instance_id, terminal);
}

/// The `Failed` reason when the restart decision gives up.
fn give_up_reason(
    policy: RestartPolicy,
    reason: &TrapReason,
    restarts: u32,
    max_restarts: u32,
) -> String {
    if restarts >= max_restarts {
        format!("gave up after {max_restarts} consecutive restarts; last crash: {reason}")
    } else {
        format!(
            "not restarting under `{}` policy: {reason}",
            policy.as_str()
        )
    }
}

/// Run one load → init → serve attempt. State transitions up to
/// `Running` are emitted here; the supervisor owns `Crashed` /
/// `Restarting` and the terminal `Stopped` / `Failed`.
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
    mode: &crate::runtime::LoadMode,
    control_rx: &mut mpsc::Receiver<ControlCommand>,
    stop: &mut watch::Receiver<bool>,
    state_tx: &watch::Sender<InstanceState>,
    // Slot shared with the [`InstanceHandle`] this supervisor
    // was spawned alongside — populated after the first
    // successful load with the installation UUID pinned to the
    // instance. See [`run_supervisor`] for the once-vs-restart
    // note.
    loaded: &Arc<LoadedSlots>,
    // Phase 6 leftover TOCTOU fix + round-2 F3: the
    // supervisor's pinned manifest snapshot, cloned by
    // `run_supervisor` for every attempt (first load AND
    // every restart), so the manifest is treated as
    // immutable for the supervisor's lifetime. `None`
    // only reaches this helper via the un-pinned
    // test-suite paths; those re-read from disk on every
    // attempt.
    pinned_manifest: Option<(Vec<u8>, oxidhome_manifest::PluginManifest)>,
    supervised: SupervisedLoad<'_>,
) -> LifecycleOutcome {
    // Sweep any device/service registry entries this instance left
    // behind on a previous life. First load is a no-op; on a restart
    // it prevents stacking duplicates as `init` re-registers, and
    // keeps the registries from growing unboundedly across crash
    // loops. Idempotent + cheap (one HashMap retain each).
    engine.devices().remove_by_owner(instance_id);
    engine.services().remove_by_owner(instance_id);
    // H5: a fresh store can't complete commands the previous life
    // accepted.
    engine
        .pending_commands()
        .expire_owner(instance_id, super::ExpiryReason::InstanceRestarted);
    // H9: mark this instance's previous device-state entries `Stale`
    // and bump the supervisor generation, so entries applied under
    // this life are distinguishable. H9 round-5 finding 1: the composite
    // `restart_generation` holds the store's write lock across
    // both steps — the pre-fix two-call shape let a delayed
    // writer read the pre-bump generation and insert a fresh
    // entry stamped with the previous generation *after* the
    // stale sweep.
    engine.device_state().restart_generation(instance_id);

    transition(state_tx, instance_id, InstanceState::Loading);

    // `None` pin: the un-pinned test-suite path re-reads the manifest.
    // Instantiation runs component start functions, so a stop cancels
    // it like any other guest call.
    let load_result = guest_call(
        stop,
        PluginInstance::load_supervised(
            engine,
            plugin_dir,
            instance_id.to_string(),
            overrides,
            mode.clone(),
            pinned_manifest,
            supervised,
        ),
    )
    .await;
    let mut instance = match load_result {
        Some(Ok(instance)) => instance,
        Some(Err(e)) => return LifecycleOutcome::LoadFailed(format!("{e:#}")),
        None => return stopped_while_loading(instance_id),
    };
    // The installation UUID is now known and stable across
    // every subsequent restart of this supervisor (same
    // install ⇒ same UUID). Set once; ignore the `Err` on
    // subsequent restarts.
    let _ = loaded.installation_uuid.set(instance.installation_uuid());
    // M7: the overrides are pinned for the supervisor's lifetime, so
    // the masked view from the first load holds for every restart.
    let _ = loaded.config_view.get_or_init(|| {
        Arc::new(crate::redact::masked_config_view(
            &instance.manifest().config,
            instance.config(),
        ))
    });
    instance.set_watchdog(watchdog);
    let policy = instance.manifest().runtime.restart;

    // Stopped while loading: don't enter the plugin at all.
    if stop_is_requested(stop) {
        return stop_after_cancel(instance, instance_id);
    }
    match guest_call(stop, instance.init()).await {
        None => return stop_after_cancel(instance, instance_id),
        Some(Ok(())) => {}
        Some(Err(e)) => {
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
    if stop_is_requested(stop) {
        // Stopped while `init` ran: no event handlers.
        return shutdown_before_serving(instance, state_tx, instance_id).await;
    }
    // Deliver anything the plugin's subscriptions buffered during init.
    match guest_call(stop, instance.drain_events()).await {
        None => return stop_after_cancel(instance, instance_id),
        Some(Ok(_)) => {}
        Some(Err(e)) => {
            return LifecycleOutcome::Crashed {
                policy,
                reason: classify_post_init_trap(&e),
                ran_healthy: false,
            };
        }
    }

    let tick = build_tick_interval(&instance);
    let running_since = Instant::now();
    // C2d — grab the wake AFTER load, because it's constructed
    // inside `PluginState::new()`. Each restart gets a fresh
    // `Notify` (the freshly-loaded `PluginInstance` has its own
    // wake), and the bus's subscription wake registrations are
    // scoped to that instance's live subscriptions.
    let wake = instance.wake();
    transition(state_tx, instance_id, InstanceState::Running);

    match serve_loop(
        &mut instance,
        control_rx,
        stop,
        &wake,
        state_tx,
        instance_id,
        tick,
    )
    .await
    {
        ServeOutcome::Stopped => {
            // The supervisor publishes `Stopped` only once the `Store`
            // is gone (and the control queue drained), so a caller that
            // saw it (and the reaper) knows no guest code of this life
            // can still run.
            drop(instance);
            LifecycleOutcome::Stopped
        }
        ServeOutcome::Cancelled => stop_after_cancel(instance, instance_id),
        ServeOutcome::StoppedFailed(reason) => LifecycleOutcome::StoppedFailed(reason),
        ServeOutcome::Crashed(reason) => LifecycleOutcome::Crashed {
            policy,
            reason,
            ran_healthy: running_since.elapsed() >= healthy_reset,
        },
    }
}

/// A stop cancelled the load (instantiation runs start functions).
fn stopped_while_loading(instance_id: &str) -> LifecycleOutcome {
    tracing::warn!(instance_id, "stop requested while loading; load cancelled");
    LifecycleOutcome::Stopped
}

/// A stop requested while `init` ran: run `on-shutdown` without
/// delivering events first, then drop the `Store` (the supervisor
/// publishes `Stopped`).
async fn shutdown_before_serving(
    mut instance: PluginInstance,
    state_tx: &watch::Sender<InstanceState>,
    instance_id: &str,
) -> LifecycleOutcome {
    if let LoopAction::StopFailed(reason) =
        shutdown_on_request(&mut instance, state_tx, instance_id).await
    {
        return LifecycleOutcome::StoppedFailed(reason);
    }
    drop(instance);
    LifecycleOutcome::Stopped
}

/// A stop cancelled (or preempted) a plugin call: the instance can't
/// be entered again, so skip `on-shutdown`, drop the `Store`, then
/// publish `Stopped`.
fn stop_after_cancel(instance: PluginInstance, instance_id: &str) -> LifecycleOutcome {
    tracing::warn!(
        instance_id,
        "stop requested: a plugin call didn't finish within the grace period and was \
         cancelled; on-shutdown skipped",
    );
    drop(instance);
    LifecycleOutcome::Stopped
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

/// Which `select!` arm woke the serve loop.
enum Wakeup {
    Stop,
    Control(Option<ControlCommand>),
    Tick,
    Event,
}

/// The steady-state `select!` loop — see the module docs.
async fn serve_loop(
    instance: &mut PluginInstance,
    control_rx: &mut mpsc::Receiver<ControlCommand>,
    stop: &mut watch::Receiver<bool>,
    wake: &tokio::sync::Notify,
    state_tx: &watch::Sender<InstanceState>,
    instance_id: &str,
    mut tick: Option<Interval>,
) -> ServeOutcome {
    loop {
        let next = async {
            tokio::select! {
                ctrl = control_rx.recv() => Wakeup::Control(ctrl),
                // `if tick.is_some()` gates the `unwrap` — the arm is only
                // polled when an interval exists.
                _ = async { tick.as_mut().unwrap().tick().await }, if tick.is_some() => Wakeup::Tick,
                // C2d wake path — signaled by `EventBus::signal_wakes`
                // when a published event matches one of the plugin's
                // active subscription filters. `Notify` deduplicates
                // multiple `notify_one` calls that land between two
                // `notified().await`s to a single wake, so a burst of
                // matching publishes drains together in one pass —
                // exactly the behaviour we want.
                () = wake.notified() => Wakeup::Event,
            }
        };
        // A requested stop goes first: queued commands are then refused
        // without running (see `ControlQueue`). The others are polled
        // fairly, so a stream of commands can't starve the tick.
        let wakeup = tokio::select! {
            biased;
            () = stop_requested(stop) => Wakeup::Stop,
            wakeup = next => wakeup,
        };
        let outcome: anyhow::Result<LoopAction> = match wakeup {
            Wakeup::Stop => Ok(shutdown_on_request(instance, state_tx, instance_id).await),
            Wakeup::Control(ctrl) => {
                handle_control(instance, state_tx, stop, instance_id, ctrl).await
            }
            Wakeup::Tick => match guest_call(stop, instance.tick()).await {
                Some(result) => result.map(|()| LoopAction::Continue),
                None => Ok(LoopAction::Cancelled),
            },
            Wakeup::Event => Ok(LoopAction::Continue),
        };

        match outcome {
            // A stop requested meanwhile goes straight to shutdown,
            // without entering new event handlers.
            Ok(LoopAction::Continue) if stop_is_requested(stop) => {}
            Ok(LoopAction::Continue) => match guest_call(stop, instance.drain_events()).await {
                Some(Ok(_)) => {}
                Some(Err(e)) => return ServeOutcome::Crashed(classify_post_init_trap(&e)),
                None => return ServeOutcome::Cancelled,
            },
            // The supervisor publishes `Stopped` once the control
            // queue is drained.
            Ok(LoopAction::Stop) => return ServeOutcome::Stopped,
            Ok(LoopAction::Cancelled) => return ServeOutcome::Cancelled,
            Ok(LoopAction::StopFailed(reason)) => {
                tracing::warn!(
                    instance_id,
                    reason = %reason,
                    "operator-requested shutdown trapped — refusing to restart",
                );
                return ServeOutcome::StoppedFailed(reason);
            }
            Err(e) => return ServeOutcome::Crashed(classify_post_init_trap(&e)),
        }
    }
}

/// Run `on-shutdown` for a stop (a `Shutdown` message, the stop flag,
/// or every handle dropped). Round-3 F1: an operator-requested stop is
/// terminal whether or not the guest's teardown ran cleanly: a trap
/// (or a hook that didn't return in time) is `StopFailed`, which the
/// outer supervisor turns into `Failed` without a restart.
async fn shutdown_on_request(
    instance: &mut PluginInstance,
    state_tx: &watch::Sender<InstanceState>,
    instance_id: &str,
) -> LoopAction {
    transition(state_tx, instance_id, InstanceState::Stopping);
    match instance.shutdown().await {
        Ok(()) => LoopAction::Stop,
        Err(err) => LoopAction::StopFailed(format!("shutdown trapped: {err:#}")),
    }
}

/// Wait out a restart backoff delay. Returns early if a shutdown is
/// requested mid-backoff; an `execute-command` arriving during the
/// wait is answered with an error (the instance isn't running).
async fn backoff_wait(
    delay: Duration,
    control_rx: &mut mpsc::Receiver<ControlCommand>,
    stop: &mut watch::Receiver<bool>,
    instance_id: &str,
    pending: &PendingCommands,
) -> BackoffOutcome {
    let sleep = tokio::time::sleep(delay);
    tokio::pin!(sleep);
    loop {
        tokio::select! {
            biased;
            () = stop_requested(stop) => return BackoffOutcome::Shutdown,
            () = &mut sleep => return BackoffOutcome::Elapsed,
            ctrl = control_rx.recv() => match ctrl {
                // Every handle dropped, or an explicit shutdown.
                None => return BackoffOutcome::Shutdown,
                Some(ControlCommand::Shutdown { reply }) => {
                    let _ = reply.send(());
                    return BackoffOutcome::Shutdown;
                }
                Some(ctrl) => {
                    refuse_unserved(ctrl, instance_id, "is restarting after a crash", pending);
                }
            }
        }
    }
}

/// Refuse a control message the instance can't serve (restart backoff,
/// or a terminal supervisor draining its queue): `instance
/// `<id>` <why>`. The ticket's `try_refuse` settles the call, the same
/// decision a stop and the caller's own withdrawal take. A device
/// command is `rejected`, or `timed_out` when its caller had already
/// gone or its deadline passed (neither ran, so a retry is safe); when
/// its caller disconnected, the refusal is recorded as its `COMMAND`
/// row, since the request row has no outcome. A service call gets a
/// dispatch error; a shutdown is acknowledged.
fn refuse_unserved(ctrl: ControlCommand, instance_id: &str, why: &str, pending: &PendingCommands) {
    match ctrl {
        ControlCommand::Execute {
            ctx,
            device,
            cmd,
            ticket,
            reply,
        } => {
            // `None`: the plugin was entered, which a command still in
            // the queue never was.
            let Some(caller_gone) = ticket.try_refuse() else {
                return;
            };
            // A caller that went away or whose deadline passed while
            // queued gets `timed_out`; the rest `rejected`. Neither ran.
            let refused = if caller_gone || ctx.is_expired() {
                CommandOutcome::TimedOut {
                    message: format!("instance `{instance_id}` {why}; the command did not run"),
                }
            } else {
                CommandOutcome::Rejected {
                    error: WitError::Unavailable(format!("instance `{instance_id}` {why}")),
                }
            };
            // A caller that withdrew at its own deadline reported
            // `timed_out` itself.
            if let Err(outcome) = reply.send(refused)
                && !ticket.withdrawn_by_caller()
            {
                pending.record_resolution(&ctx, &cmd.id, &device, &outcome);
            }
        }
        ControlCommand::ExecuteService {
            guard,
            ticket,
            reply,
            ..
        } => {
            // Settles the ticket so the caller reads "did not run".
            let _ = ticket.try_refuse();
            // Released before the reply, as on the dequeue refusal, so
            // the caller never sees the refused call still active.
            guard.release();
            let _ = reply.send(Err(anyhow!("instance `{instance_id}` {why}")));
        }
        ControlCommand::Shutdown { reply } => {
            let _ = reply.send(());
        }
    }
}

/// `ControlCommand::Execute`: run one device command and reply with
/// its H5 outcome. A trap is still a crash (propagated after replying).
#[allow(clippy::too_many_arguments)]
async fn run_execute(
    instance: &mut PluginInstance,
    stop: &mut watch::Receiver<bool>,
    instance_id: &str,
    ctx: InvocationContext,
    device: DeviceId,
    cmd: Command,
    ticket: &DispatchTicket,
    reply: oneshot::Sender<CommandOutcome>,
) -> anyhow::Result<LoopAction> {
    // H6: the root gave up (or its budget ran out while the
    // command sat in this queue). Running it now would actuate
    // a device nobody is waiting on any more. H5: the ticket
    // makes "did not run" race-free against the caller's own
    // deadline (and its disconnect).
    // The deadline check and the claim are one ticket decision, so a
    // caller withdrawing at its deadline sees either "started" or
    // "never ran", never a refused command marked started.
    if !ticket.try_start_unless(|| ctx.is_expired()) {
        let _ = ticket.try_abandon();
        let refused = CommandOutcome::TimedOut {
            message: format!(
                "instance `{instance_id}` refused execute-command: invocation `{}` \
                 deadline exceeded before dispatch",
                ctx.call_id(),
            ),
        };
        if let Err(outcome) = reply.send(refused)
            && !ticket.withdrawn_by_caller()
        {
            // The caller went away (disconnect, not its deadline:
            // that path reports `timed_out` itself) while the command
            // was queued; its request row has no outcome, so record
            // that it never ran.
            if let Some(pending) = instance.pending_commands() {
                pending.record_resolution(&ctx, &cmd.id, &device, &outcome);
            }
        }
        return Ok(LoopAction::Continue);
    }
    let command_id = cmd.id.clone();
    let device_id = device.clone();
    let ctx = ctx.entering(instance_id);
    // For a late-result audit row: keeps the executing instance.
    let entered_ctx = ctx.clone();
    let result = guest_call(
        stop,
        invocation::CURRENT.scope(ctx, instance.execute_command(device, cmd)),
    )
    .await;
    let result_cancelled = result.is_none();
    let (outcome, trap) = match result {
        // A stop cancelled the call: the plugin was entered, so the
        // command may have taken effect.
        None => (
            CommandOutcome::Unknown {
                message: format!(
                    "instance `{instance_id}` was stopped while executing the command; it may \
                     have taken effect",
                ),
            },
            None,
        ),
        Some(Ok(result)) => (CommandOutcome::from_plugin(result), None),
        // An `execute-command` trap is a crash. The plugin was
        // entered, so whatever it did to the device may stand.
        // The caller gets a short message; the trap detail (wasm
        // backtrace) stays in the instance's failure reason and logs.
        Some(Err(trap)) => {
            tracing::warn!(
                instance_id = %instance_id,
                command_id = %command_id,
                error = %format!("{trap:#}"),
                "execute-command trapped; command outcome unknown",
            );
            (
                CommandOutcome::Unknown {
                    message: format!(
                        "instance `{instance_id}` crashed during execute-command; the \
                         command may have taken effect",
                    ),
                },
                Some(trap),
            )
        }
    };
    if let Err(outcome) = reply.send(outcome)
        && !matches!(outcome, CommandOutcome::Accepted)
    {
        // The caller stopped waiting (deadline or disconnect)
        // after the plugin was entered and reported
        // `outcome_unknown`; record how the command really
        // ended. A late `accepted` is skipped: the pending entry
        // records the terminal outcome.
        if let Some(pending) = instance.pending_commands() {
            pending.record_resolution(&entered_ctx, &command_id, &device_id, &outcome);
        }
    }
    match (result_cancelled, trap) {
        (true, _) => Ok(LoopAction::Cancelled),
        (false, None) => Ok(LoopAction::Continue),
        (false, Some(trap)) => Err(trap),
    }
}

/// Handle one control message (or the channel closing). Returns the
/// loop action, or an `Err` if the plugin trapped (→ `Failed`).
async fn handle_control(
    instance: &mut PluginInstance,
    state_tx: &watch::Sender<InstanceState>,
    stop: &mut watch::Receiver<bool>,
    instance_id: &str,
    ctrl: Option<ControlCommand>,
) -> anyhow::Result<LoopAction> {
    match ctrl {
        // Every handle was dropped — nobody can observe or drive the
        // instance anymore. Shut it down cleanly.
        None => Ok(shutdown_on_request(instance, state_tx, instance_id).await),
        Some(ControlCommand::Shutdown { reply }) => {
            let action = shutdown_on_request(instance, state_tx, instance_id).await;
            // Ack the caller whether or not `shutdown` trapped so
            // they aren't left waiting on the reply channel.
            let _ = reply.send(());
            Ok(action)
        }
        Some(ControlCommand::Execute {
            ctx,
            device,
            cmd,
            ticket,
            reply,
        }) => {
            run_execute(
                instance,
                stop,
                instance_id,
                ctx,
                device,
                cmd,
                &ticket,
                reply,
            )
            .await
        }
        Some(ControlCommand::ExecuteService {
            ctx,
            guard,
            service,
            command,
            args,
            ticket,
            reply,
        }) => {
            // Scope the invocation context handed to us by the
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
            //
            // H6: a hop whose deadline already passed is dropped
            // unexecuted — the caller's dispatcher has stopped
            // waiting for it. H5: one ticket decision with the
            // caller's withdrawal, so a caller that gave up while the
            // call was queued knows it never ran.
            if !ticket.try_start_unless(|| ctx.is_expired()) {
                let _ = ticket.try_abandon();
                guard.release();
                let _ = reply.send(Err(anyhow!(
                    "instance `{instance_id}` refused execute-service-command: invocation \
                     `{}` deadline exceeded before dispatch",
                    ctx.call_id(),
                )));
                return Ok(LoopAction::Continue);
            }
            // Started: the caller no longer releases it.
            let guard = guard.take();
            let outcome = guest_call(
                stop,
                invocation::CURRENT.scope(
                    ctx,
                    instance.execute_service_command(service, command, args),
                ),
            )
            .await;
            drop(guard);
            match outcome {
                // A stop cancelled the call after the callee was
                // entered (H5: it may have acted).
                None => {
                    let _ = reply.send(Ok(CommandResult::Unknown(format!(
                        "instance `{instance_id}` was stopped during execute-service-command; \
                         the call may have taken effect",
                    ))));
                    Ok(LoopAction::Cancelled)
                }
                Some(Ok(result)) => {
                    if reply.send(Ok(result)).is_err() {
                        // The caller's wait ended mid-call and it
                        // reported `unknown`; its hop row says so.
                        tracing::debug!(
                            instance_id = %instance_id,
                            "execute-service-command finished after the caller stopped waiting",
                        );
                    }
                    Ok(LoopAction::Continue)
                }
                // H5: the callee was entered, so whatever it did may
                // stand — the caller hears `unknown`, not a dispatch
                // failure it could safely retry. The trap detail stays
                // in the logs and the instance's failure reason. The
                // trap still crashes (and restarts) this instance only.
                Some(Err(trap)) => {
                    tracing::warn!(
                        instance_id = %instance_id,
                        error = %format!("{trap:#}"),
                        "execute-service-command trapped; call outcome unknown",
                    );
                    let _ = reply.send(Ok(CommandResult::Unknown(format!(
                        "instance `{instance_id}` crashed during execute-service-command; \
                         the call may have taken effect",
                    ))));
                    Err(trap)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stop_wait_reports_unreaped_instances_after_the_bound() {
        let slow = InstanceHandle::running_for_test("slow", "p");
        let done = InstanceHandle::running_for_test("done", "p");
        done.mark_reaped();
        let report =
            stop_and_wait_reaped(vec![slow.clone(), done.clone()], Duration::from_millis(50)).await;
        assert_eq!(report.stopped, ["done"]);
        assert_eq!(report.still_stopping, ["slow"]);
        assert!(slow.stop_requested() && done.stop_requested());
    }

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
