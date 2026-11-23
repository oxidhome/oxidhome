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
use tokio::time::Instant;

use crate::Engine;
use crate::auth::SensitiveSet;
use crate::auth::invocation::{self, InvocationContext};
use crate::clock::Interval;
use crate::host_impl::plugin::oxidhome::plugin::devices::{Command, CommandResult};
use crate::host_impl::plugin::oxidhome::plugin::types::{
    DeviceId, Error as WitError, KeyValue, ServiceId,
};
use crate::state::CallGuard;

use super::command::{
    CommandOutcome, CommandReport, DispatchTicket, PendingCommands, ReplyGuard, UnreadReply,
    mint_command_id,
};
use super::dispatcher::ResultCheck;
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
        /// H6 slice 2: the sensitive categories the caller's decision
        /// covered at admission. The supervisor re-authorizes at
        /// dispatch and refuses a command whose device has since
        /// gained a category outside this set.
        admitted: SensitiveSet,
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
        /// Checks a result nobody reads before it is recorded.
        check: ResultCheck,
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
/// call's [`ReplyGuard`] so it drops after the ticket is settled.
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
    /// H5: the engine's pending-command table, whose journal records a
    /// reply this handle's caller dropped without reading (see
    /// [`ReplyGuard`]). `None` for test handles. Weak, so a handle kept
    /// after its engine is gone doesn't keep the journal running; a
    /// reply guard holds it only while its reply is outstanding.
    pending: Option<std::sync::Weak<PendingCommands>>,
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
            pending: None,
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
            pending: None,
        }
    }

    /// A handle whose control messages land on `control`'s receiver,
    /// for tests that play the supervisor.
    #[cfg(test)]
    fn with_control_for_test(instance_id: &str, control: mpsc::Sender<ControlCommand>) -> Self {
        let (_tx, state) = tokio::sync::watch::channel(InstanceState::Running);
        Self {
            instance_id: Arc::from(instance_id),
            plugin_id: Arc::from("test.plugin"),
            loaded: Arc::default(),
            control,
            state,
            stop: Arc::new(watch::Sender::new(false)),
            reaped: Arc::new(watch::Sender::new(false)),
            sandbox: None,
            pending: None,
        }
    }

    /// [`Self::with_control_for_test`] whose dropped replies are
    /// recorded through `pending`'s journal.
    #[cfg(test)]
    fn with_pending_for_test(
        instance_id: &str,
        control: mpsc::Sender<ControlCommand>,
        pending: &Arc<PendingCommands>,
    ) -> Self {
        Self {
            pending: Some(Arc::downgrade(pending)),
            ..Self::with_control_for_test(instance_id, control)
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
            pending: None,
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
    ///
    /// H6 slice 2: this entry point admits no sensitive category, so
    /// an external caller's command to a lock, opener, alarm or
    /// camera device is `rejected` at dispatch. Sensitive commands
    /// go through the API surfaces, which discharge the obligations
    /// (rate limit, warn audit row) and then call
    /// [`Self::execute_command_admitted`].
    pub async fn execute_command_in(
        &self,
        ctx: InvocationContext,
        device: DeviceId,
        cmd: Command,
    ) -> CommandReport {
        self.execute_command_admitted(ctx, device, cmd, SensitiveSet::empty())
            .await
    }

    /// [`Self::execute_command_in`] for a caller whose authorization
    /// decision covered (and discharged) the sensitive categories
    /// `admitted` (H6 slice 2). An external command is re-authorized
    /// when the supervisor dequeues it: if the device's class now
    /// needs a category outside `admitted`, or the caller is no longer
    /// allowed at all, it is `rejected` without running.
    pub async fn execute_command_admitted(
        &self,
        ctx: InvocationContext,
        device: DeviceId,
        mut cmd: Command,
        admitted: SensitiveSet,
    ) -> CommandReport {
        let command_id = mint_command_id();
        cmd.id.clone_from(&command_id);
        let outcome = self.dispatch_command(ctx, device, cmd, admitted).await;
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
        admitted: SensitiveSet,
    ) -> CommandOutcome {
        let ticket = DispatchTicket::default();
        let (reply, rx) = oneshot::channel();
        // Dropping the caller withdraws a still-queued command and
        // records a reply it never read.
        let unread = self.unread_command_reply(&ctx, &cmd.id, &device);
        let mut rx = ReplyGuard::new(rx, ticket.clone(), unread);
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
            admitted,
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
            let Ok(received) = tokio::time::timeout_at(d, &mut *rx).await else {
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
            (&mut *rx).await
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

    /// What records a device-command reply the caller dropped without
    /// reading: its `COMMAND` row, as the supervisor writes one for a
    /// reply it couldn't send. A late `accepted` is skipped: the
    /// pending entry records the terminal outcome.
    fn unread_command_reply(
        &self,
        ctx: &InvocationContext,
        command_id: &str,
        device: &DeviceId,
    ) -> Option<UnreadReply<CommandOutcome>> {
        let pending = self.pending.as_ref()?.upgrade()?;
        if !ctx.root().is_external() {
            return None;
        }
        let ctx = ctx.clone();
        let command_id = command_id.to_owned();
        let device = device.clone();
        let instance_id = Arc::clone(&self.instance_id);
        Some(Box::new(move |outcome, ticket| {
            if matches!(outcome, CommandOutcome::Accepted) {
                return;
            }
            // As the supervisor records it: a result under the
            // executing instance, a refusal under the caller's context.
            let ctx = if ticket.started() {
                ctx.entering(&instance_id)
            } else {
                ctx
            };
            pending.record_resolution(&ctx, &command_id, &device, &outcome);
        }))
    }

    /// What records a service-call result the caller dropped without
    /// reading: a late-result row, as the supervisor writes one for a
    /// result it couldn't send. A refusal (the call never ran) needs
    /// none; the hop row says so.
    fn unread_service_reply(
        &self,
        ctx: &InvocationContext,
        command: &str,
        check: &ResultCheck,
    ) -> Option<UnreadReply<anyhow::Result<CommandResult>>> {
        let pending = self.pending.as_ref()?.upgrade()?;
        if !ctx.root().is_external() {
            return None;
        }
        let ctx = ctx.clone();
        let command = command.to_owned();
        let check = check.clone();
        Some(Box::new(move |reply, _| {
            if let Ok(result) = reply {
                record_late_service_result(&pending, &ctx, &command, &check, result);
            }
        }))
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
        check: ResultCheck,
        ticket: DispatchTicket,
        wait_until: Instant,
    ) -> ServiceCallOutcome {
        let guard = SharedCallGuard::new(guard);
        let unread = self.unread_service_reply(&ctx, &command, &check);
        // Drop order: `rx` settles the ticket (and records a result
        // nobody read), then `_release` frees the guard of a call that
        // will never start.
        let (reply, rx) = oneshot::channel();
        let _release = ReleaseUnlessStarted {
            ticket: ticket.clone(),
            guard: guard.clone(),
        };
        let mut rx = ReplyGuard::new(rx, ticket.clone(), unread);
        // If the send fails (control channel closed), `_release` drops
        // the `CallGuard` → refcount decrements cleanly even on the
        // supervisor-gone path.
        let enqueue = self.control.send(ControlCommand::ExecuteService {
            ctx,
            guard,
            service,
            command,
            args,
            check,
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
        let Ok(received) = tokio::time::timeout_at(wait_until, &mut *rx).await else {
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
        pending: Some(Arc::downgrade(&engine.pending_commands())),
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
    match drain_events(&mut instance, stop).await {
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
    // The healthy window is measured on the engine clock, as ticks
    // are (see `crate::clock`); the restart backoff stays real time.
    let clock = instance.clock().clone();
    let running_since = clock.instant();
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
            ran_healthy: clock.instant().saturating_duration_since(running_since) >= healthy_reset,
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
        let clock = instance.clock();
        // Starts at `now + period` so the *first* tick lands one
        // cadence after Running, not immediately — `tick_interval_ms`
        // is the gap between ticks, the first one included. A slow
        // tick body must not make the loop "catch up" with a burst of
        // back-to-back ticks: the clock's interval delays the schedule
        // instead (`MissedTickBehavior::Delay`).
        clock.tick_interval(clock.instant() + period, period)
    })
}

/// Which `select!` arm woke the serve loop.
enum Wakeup {
    Stop,
    Control(Option<ControlCommand>),
    Tick,
    Event,
}

/// Deliver the plugin's pending events as a [`guest_call`]. A stop
/// requested meanwhile ends the drain before the next delivery, not
/// only before the next drain.
async fn drain_events(
    instance: &mut PluginInstance,
    stop: &mut watch::Receiver<bool>,
) -> Option<anyhow::Result<usize>> {
    let stop_flag = stop.clone();
    guest_call(
        stop,
        instance.drain_events_until(|| stop_is_requested(&stop_flag)),
    )
    .await
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
            Ok(LoopAction::Continue) => match drain_events(instance, stop).await {
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
            ..
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
            record_refusal(&ticket, reply, refused, |outcome| {
                pending.record_resolution(&ctx, &cmd.id, &device, outcome);
            });
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

/// Reply with the refusal of a command that never ran, and record it
/// as its `COMMAND` row when the send fails: the caller is gone and
/// never reads it. A refusal the send delivered but the caller then
/// dropped unread is recorded by the caller's [`ReplyGuard`]; a caller
/// that withdrew at its own deadline reported `timed_out` itself.
fn record_refusal(
    ticket: &DispatchTicket,
    reply: oneshot::Sender<CommandOutcome>,
    refused: CommandOutcome,
    record: impl FnOnce(&CommandOutcome),
) {
    if let Err(outcome) = reply.send(refused)
        && !ticket.withdrawn_by_caller()
    {
        record(&outcome);
    }
}

/// Why an external command admitted for `admitted` may not run against
/// `resource` as it is classed now; `None` when it may (or when the
/// command is host-origin, which no grant governs).
fn dispatch_refusal(
    ctx: &InvocationContext,
    resource: &crate::auth::Resource,
    admitted: SensitiveSet,
) -> Option<String> {
    if !ctx.root().is_external() {
        return None;
    }
    let decision = crate::auth::authorize(ctx, crate::auth::Action::DeviceCommand, resource);
    if !decision.allow {
        return Some(
            "the caller may not command this device (its category may have changed \
                     while the command was queued)"
                .to_owned(),
        );
    }
    (!decision.obligations.sensitive.is_subset(admitted)).then(|| {
        format!(
            "the device is sensitive ({}) and this command was not admitted for that; \
             send it through an authorized API surface",
            decision.obligations.sensitive.to_csv()
        )
    })
}

/// Reply with the outcome of a command the plugin was entered for, and
/// record it as a late `COMMAND` row when the send fails: the caller
/// stopped waiting (deadline or disconnect) and reported
/// `outcome_unknown`, or nothing. A late `accepted` is skipped: the
/// pending entry records the terminal outcome.
fn reply_command_outcome(
    reply: oneshot::Sender<CommandOutcome>,
    outcome: CommandOutcome,
    record: impl FnOnce(&CommandOutcome),
) {
    if let Err(outcome) = reply.send(outcome)
        && !matches!(outcome, CommandOutcome::Accepted)
    {
        record(&outcome);
    }
}

/// Reply with the result of a service call the callee was entered
/// for, and record it as a late-result row when the send fails: the
/// caller stopped waiting and its hop row says `unknown`.
fn reply_service_result(
    reply: oneshot::Sender<anyhow::Result<CommandResult>>,
    result: CommandResult,
    record: impl FnOnce(CommandResult),
) {
    if let Err(Ok(result)) = reply.send(Ok(result)) {
        record(result);
    }
}

/// What records a service-call result the supervisor couldn't send.
fn late_service_recorder(
    pending: Option<Arc<PendingCommands>>,
    ctx: &InvocationContext,
    command: &str,
    check: ResultCheck,
) -> impl FnOnce(CommandResult) + use<> {
    let (ctx, command) = (ctx.clone(), command.to_owned());
    move |result| {
        if let Some(pending) = pending {
            record_late_service_result(&pending, &ctx, &command, &check, result);
        }
    }
}

/// Queue the late-result row of a service call whose caller never read
/// the result (externally-rooted invocations only).
fn record_late_service_result(
    pending: &PendingCommands,
    ctx: &InvocationContext,
    command: &str,
    check: &ResultCheck,
    result: CommandResult,
) {
    let checked = check.apply(result);
    if let Some(entry) = super::dispatcher::late_result_entry(ctx, command, checked.as_ref()) {
        pending.record_entry(entry);
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
    (device, cmd, admitted): (DeviceId, Command, SensitiveSet),
    ticket: &DispatchTicket,
    reply: oneshot::Sender<CommandOutcome>,
) -> anyhow::Result<LoopAction> {
    // H6 slice 2: the device's class may have changed while the
    // command was queued (a plugin's `update-device`, an operator's
    // category raise). Re-authorize against the class it has now; a
    // command admitted for a switch must not actuate a lock.
    let refusal = match instance.device_resource(&device) {
        Some(resource) => dispatch_refusal(&ctx, &resource, admitted),
        // Removed (or dropped by a refused re-registration) while the
        // command was queued: nothing classes it any more.
        None if ctx.root().is_external() => {
            Some("the device is no longer registered; the command did not run".to_owned())
        }
        None => None,
    };
    if let Some(why) = refusal
        && let Some(caller_gone) = ticket.try_refuse()
    {
        // As `refuse_unserved`: a caller gone or past its deadline
        // gets `timed_out` (it may already be reporting that itself).
        let refused = if caller_gone || ctx.is_expired() {
            CommandOutcome::TimedOut {
                message: format!("instance `{instance_id}`: {why}; the command did not run"),
            }
        } else {
            CommandOutcome::Rejected {
                error: WitError::PermissionDenied(why),
            }
        };
        if let Some(pending) = instance.pending_commands() {
            record_refusal(ticket, reply, refused, |outcome| {
                pending.record_resolution(&ctx, &cmd.id, &device, outcome);
            });
        } else {
            let _ = reply.send(refused);
        }
        return Ok(LoopAction::Continue);
    }
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
        // The caller went away (disconnect, not its deadline: that
        // path reports `timed_out` itself) while the command was
        // queued; its request row has no outcome, so record that it
        // never ran.
        if let Some(pending) = instance.pending_commands() {
            record_refusal(ticket, reply, refused, |outcome| {
                pending.record_resolution(&ctx, &cmd.id, &device, outcome);
            });
        } else {
            let _ = reply.send(refused);
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
    reply_command_outcome(reply, outcome, |outcome| {
        if let Some(pending) = instance.pending_commands() {
            pending.record_resolution(&entered_ctx, &command_id, &device_id, outcome);
        }
    });
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
            admitted,
            ticket,
            reply,
        }) => {
            run_execute(
                instance,
                stop,
                instance_id,
                ctx,
                (device, cmd, admitted),
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
            check,
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
            // For a late-result row, should the caller stop waiting.
            let record = late_service_recorder(instance.pending_commands(), &ctx, &command, check);
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
                    reply_service_result(
                        reply,
                        CommandResult::Unknown(format!(
                            "instance `{instance_id}` was stopped during \
                             execute-service-command; the call may have taken effect",
                        )),
                        record,
                    );
                    Ok(LoopAction::Cancelled)
                }
                // A result the caller no longer waits for (its wait
                // ended mid-call and its hop row says `unknown`) is
                // recorded as a late-result row.
                Some(Ok(result)) => {
                    reply_service_result(reply, result, record);
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
                    reply_service_result(
                        reply,
                        CommandResult::Unknown(format!(
                            "instance `{instance_id}` crashed during execute-service-command; \
                             the call may have taken effect",
                        )),
                        record,
                    );
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

    fn api_ctx() -> InvocationContext {
        use crate::auth::{Actor, ActorKind, Principal, Transport};
        let actor = Actor::api("tok-1", vec!["*".into()]);
        InvocationContext::external(Principal::token(ActorKind::Api, &actor, Transport::Rest))
    }

    /// H6 slice 2: a command admitted for a switch is refused at
    /// dispatch once the device reads as a lock, unless the admission
    /// already covered `lock`; host-origin commands are not checked.
    #[test]
    fn dispatch_rechecks_the_device_class() {
        use crate::auth::policy::SensitiveGrant;
        use crate::auth::{
            Actor, ActorKind, DeviceCategory, DeviceClass, Principal, Resource, SensitiveCategory,
            Transport,
        };
        let switch = Resource::device("dev-1", DeviceClass::of(DeviceCategory::Switch));
        let lock = Resource::device("dev-1", DeviceClass::of(DeviceCategory::Lock));
        let none = SensitiveSet::empty();
        let locks: SensitiveSet = [SensitiveCategory::Lock].into_iter().collect();

        assert_eq!(dispatch_refusal(&api_ctx(), &switch, none), None);
        assert!(
            dispatch_refusal(&api_ctx(), &lock, none).is_some(),
            "no grant"
        );

        let granted = Actor::api("tok-2", vec!["*".into()])
            .with_sensitive(vec![SensitiveGrant::all(SensitiveCategory::Lock)]);
        let ctx = InvocationContext::external(Principal::token(
            ActorKind::Api,
            &granted,
            Transport::Rest,
        ));
        let why = dispatch_refusal(&ctx, &lock, none).expect("grant, but not admitted");
        assert!(why.contains("lock"), "{why}");
        assert_eq!(dispatch_refusal(&ctx, &lock, locks), None);

        let host = InvocationContext::host_origin("inst");
        assert_eq!(dispatch_refusal(&host, &lock, none), None);
    }

    /// The journal-backed table and ledger the ordering tests read.
    fn journaled() -> (Arc<crate::state::AuditLog>, Arc<PendingCommands>) {
        use crate::state::{AuditLog, Db};
        let audit = Arc::new(AuditLog::new(Arc::new(Db::open_in_memory().expect("db"))));
        let pending = Arc::new(PendingCommands::new(Some(Arc::clone(&audit))).unwrap());
        (audit, pending)
    }

    /// The rows with `method`, once the journal drained.
    fn rows_of(
        audit: &crate::state::AuditLog,
        pending: &PendingCommands,
        method: &str,
    ) -> Vec<crate::state::AuditEntry> {
        assert!(pending.flush_journal(Duration::from_secs(5)));
        audit
            .query(&crate::state::AuditQuery::default(), 100)
            .expect("query")
            .into_iter()
            .filter(|r| r.method == method)
            .collect()
    }

    /// Poll `fut` once.
    fn no_check() -> ResultCheck {
        ResultCheck::new(Ok)
    }

    async fn poll_once<F: std::future::Future + Unpin>(fut: &mut F) -> std::task::Poll<F::Output> {
        std::future::poll_fn(|cx| std::task::Poll::Ready(std::pin::Pin::new(&mut *fut).poll(cx)))
            .await
    }

    /// One step of a supervisor or a caller, in the order a test plays
    /// them.
    #[derive(Clone, Copy, Debug)]
    enum Step {
        /// `refuse_unserved`: decide and send the refusal.
        Refuse,
        /// The refusal decision (`try_refuse`) alone.
        DecideRefusal,
        /// Send the refusal decided by `DecideRefusal`.
        SendRefusal,
        /// Enter the plugin (`try_start`).
        Start,
        /// Send the started command's result.
        SendResult,
        /// Drop the waiting caller without reading the reply.
        DropCaller,
        /// Let the caller read its reply.
        ReadReply,
    }

    /// Play `steps` for one device command and return its `COMMAND`
    /// rows and whatever the caller read.
    async fn play_command(
        steps: &[Step],
    ) -> (Vec<crate::state::AuditEntry>, Option<CommandReport>) {
        let (audit, pending) = journaled();
        let (control, mut rx) = mpsc::channel(4);
        let handle = InstanceHandle::with_pending_for_test("inst-a", control, &pending);
        let mut caller = Some(Box::pin(handle.execute_command_in(
            api_ctx(),
            "dev-1".into(),
            Command {
                id: String::new(),
                capability: "switch".into(),
                action: "toggle".into(),
                args: Vec::new(),
            },
        )));
        assert!(
            poll_once(caller.as_mut().unwrap()).await.is_pending(),
            "queued"
        );
        let mut ctrl = rx.try_recv().ok();
        let mut decided: Option<(ControlCommand, CommandOutcome)> = None;
        let mut read = None;
        for step in steps {
            match step {
                Step::Refuse => {
                    refuse_unserved(ctrl.take().unwrap(), "inst-a", "is stopping", &pending);
                }
                Step::DecideRefusal => {
                    let Some(ControlCommand::Execute { ticket, .. }) = &ctrl else {
                        panic!("no command")
                    };
                    let caller_gone = ticket.try_refuse().expect("never started");
                    let refused = if caller_gone {
                        CommandOutcome::TimedOut {
                            message: "gone".into(),
                        }
                    } else {
                        CommandOutcome::Rejected {
                            error: WitError::Unavailable("refused".into()),
                        }
                    };
                    decided = Some((ctrl.take().unwrap(), refused));
                }
                Step::SendRefusal => {
                    let (
                        ControlCommand::Execute {
                            ctx,
                            device,
                            cmd,
                            ticket,
                            reply,
                            ..
                        },
                        refused,
                    ) = decided.take().unwrap()
                    else {
                        panic!("no command")
                    };
                    record_refusal(&ticket, reply, refused, |outcome| {
                        pending.record_resolution(&ctx, &cmd.id, &device, outcome);
                    });
                }
                Step::Start => {
                    let Some(ControlCommand::Execute { ticket, .. }) = &ctrl else {
                        panic!("no command")
                    };
                    assert!(ticket.try_start());
                }
                Step::SendResult => {
                    let Some(ControlCommand::Execute {
                        ctx,
                        device,
                        cmd,
                        reply,
                        ..
                    }) = ctrl.take()
                    else {
                        panic!("no command")
                    };
                    let ctx = ctx.entering("inst-a");
                    reply_command_outcome(
                        reply,
                        CommandOutcome::Completed { state: None },
                        |outcome| pending.record_resolution(&ctx, &cmd.id, &device, outcome),
                    );
                }
                Step::DropCaller => drop(caller.take()),
                Step::ReadReply => read = Some(caller.take().unwrap().await),
            }
        }
        (rows_of(&audit, &pending, "COMMAND"), read)
    }

    /// H5 reply guard: a reply nobody reads is recorded exactly once,
    /// in every order of the supervisor's send and the caller's drop.
    #[tokio::test]
    async fn an_unread_command_reply_is_recorded_exactly_once_in_every_order() {
        use Step::{DecideRefusal, DropCaller, ReadReply, Refuse, SendRefusal, SendResult, Start};
        let cases: &[(&[Step], Option<&str>)] = &[
            // Refused while the caller waits; dropped before reading.
            (&[Refuse, DropCaller], Some("rejected")),
            // Dropped first; the refusal's send fails.
            (&[DropCaller, Refuse], Some("timed_out")),
            // Refusal decided, caller dropped, then the send fails.
            (&[DecideRefusal, DropCaller, SendRefusal], Some("rejected")),
            // Late result sent, then the caller dropped unread.
            (&[Start, SendResult, DropCaller], Some("completed")),
            // Caller dropped mid-call; the result's send fails.
            (&[Start, DropCaller, SendResult], Some("completed")),
            // A reply the caller read is its own row, not a `COMMAND`.
            (&[Refuse, ReadReply], None),
            (&[Start, SendResult, ReadReply], None),
        ];
        for (steps, want) in cases {
            let (rows, _) = play_command(steps).await;
            let got: Vec<_> = rows.iter().map(|r| r.command_outcome.as_deref()).collect();
            match want {
                Some(want) => assert_eq!(got, [Some(*want)], "{steps:?}"),
                None => assert!(got.is_empty(), "{steps:?}: {got:?}"),
            }
        }
        // A late result is recorded under the executing instance.
        let (rows, _) = play_command(&[Start, SendResult, DropCaller]).await;
        let inv: serde_json::Value =
            serde_json::from_str(rows[0].invocation.as_deref().unwrap()).unwrap();
        assert_eq!(inv["current"], "inst-a", "{inv}");
    }

    /// A caller that withdrew at its own deadline reported `timed_out`
    /// itself: the refusal that follows writes no `COMMAND` row.
    #[tokio::test]
    async fn a_refusal_after_the_callers_deadline_is_not_recorded_again() {
        let (audit, pending) = journaled();
        let (control, mut rx) = mpsc::channel(4);
        let handle = InstanceHandle::with_pending_for_test("inst-a", control, &pending);
        let ctx = api_ctx().with_deadline(Some(Instant::now() + Duration::from_millis(20)));
        let report = handle
            .execute_command_in(
                ctx,
                "dev-1".into(),
                Command {
                    id: String::new(),
                    capability: "switch".into(),
                    action: "toggle".into(),
                    args: Vec::new(),
                },
            )
            .await;
        assert_eq!(report.outcome.as_str(), "timed_out");
        refuse_unserved(rx.try_recv().unwrap(), "inst-a", "is stopping", &pending);
        assert_eq!(rows_of(&audit, &pending, "COMMAND"), []);
    }

    /// Play a service call to `inst-a`: the supervisor starts it, and
    /// the result is sent before or after the caller is dropped.
    async fn play_service(send_first: bool) -> Vec<crate::state::AuditEntry> {
        use crate::auth::invocation::DelegationHop;
        use crate::host_impl::plugin::oxidhome::plugin::services::ServiceInfo;
        let (audit, pending) = journaled();
        let services = Arc::new(crate::state::ServiceRegistry::new());
        let service = services
            .register(
                "inst-a".into(),
                "test.plugin".into(),
                ServiceInfo {
                    local_id: "svc".into(),
                    name: "svc".into(),
                    metadata: Vec::new(),
                    commands: Vec::new(),
                },
            )
            .expect("register");
        let (control, mut rx) = mpsc::channel(4);
        let handle = InstanceHandle::with_pending_for_test("inst-a", control, &pending);
        let ctx = api_ctx().delegate(DelegationHop {
            caller_instance: "caller".into(),
            target_plugin: "test.plugin".into(),
            target_instance: "inst-a".into(),
            target_service: "svc".into(),
        });
        let mut caller = Box::pin(handle.execute_service_command(
            ctx,
            services.acquire_call(&service).expect("acquire"),
            service.clone(),
            "go".into(),
            Vec::new(),
            no_check(),
            DispatchTicket::default(),
            Instant::now() + Duration::from_secs(5),
        ));
        assert!(poll_once(&mut caller).await.is_pending(), "queued");
        let Ok(ControlCommand::ExecuteService {
            ctx,
            command,
            ticket,
            reply,
            ..
        }) = rx.try_recv()
        else {
            panic!("no call")
        };
        assert!(ticket.try_start());
        let send = |reply| {
            reply_service_result(reply, CommandResult::Ok, |result| {
                record_late_service_result(&pending, &ctx, &command, &no_check(), result);
            });
        };
        if send_first {
            send(reply);
            drop(caller);
        } else {
            drop(caller);
            send(reply);
        }
        rows_of(
            &audit,
            &pending,
            super::super::dispatcher::SERVICE_CALL_RESULT_AUDIT_METHOD,
        )
    }

    /// A service-call result nobody reads gets one late-result row,
    /// whether it was sent before or after the caller was dropped.
    #[tokio::test]
    async fn an_unread_service_result_is_recorded_exactly_once_in_either_order() {
        for send_first in [true, false] {
            let rows = play_service(send_first).await;
            assert_eq!(rows.len(), 1, "send_first={send_first}: {rows:?}");
            let row = &rows[0];
            assert_eq!(row.path, "service.call/test.plugin/inst-a/svc/go");
            assert_eq!(row.execution_outcome.as_deref(), Some("success"));
            assert_eq!(row.command_outcome.as_deref(), Some("completed"));
            assert_eq!(row.token_id, "tok-1");
        }
    }

    /// A late result is checked against the command's `returns` as an
    /// on-time one is: one that breaks it is recorded as `internal`,
    /// and `outcome_unknown` (the callee ran), not `rejected`.
    #[test]
    fn a_late_result_is_recorded_after_its_schema_check() {
        let (audit, pending) = journaled();
        let ctx = api_ctx().delegate(crate::auth::invocation::DelegationHop {
            caller_instance: "caller".into(),
            target_plugin: "test.plugin".into(),
            target_instance: "inst-a".into(),
            target_service: "svc".into(),
        });
        let broken = ResultCheck::new(|_| Err(WitError::Internal("schema".into())));
        record_late_service_result(&pending, &ctx, "go", &broken, CommandResult::Ok);
        let rows = rows_of(
            &audit,
            &pending,
            super::super::dispatcher::SERVICE_CALL_RESULT_AUDIT_METHOD,
        );
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0].execution_outcome.as_deref(), Some("failed"));
        assert_eq!(rows[0].domain_error.as_deref(), Some("internal"));
        assert_eq!(rows[0].command_outcome.as_deref(), Some("outcome_unknown"));
    }

    /// A service call whose supervisor drops the reply: `NotRun` while
    /// still queued (safe to retry), `Unknown` once the callee started.
    #[tokio::test]
    async fn lost_service_reply_is_not_run_while_queued_and_unknown_once_started() {
        use crate::host_impl::plugin::oxidhome::plugin::services::ServiceInfo;
        let services = Arc::new(crate::state::ServiceRegistry::new());
        let service = services
            .register(
                "inst-a".into(),
                "test.plugin".into(),
                ServiceInfo {
                    local_id: "svc".into(),
                    name: "svc".into(),
                    metadata: Vec::new(),
                    commands: Vec::new(),
                },
            )
            .expect("register");
        let (control, mut rx) = mpsc::channel(4);
        let handle = InstanceHandle::with_control_for_test("inst-a", control);
        for start in [false, true] {
            let supervisor = tokio::spawn(async move {
                if let Some(ControlCommand::ExecuteService { ticket, reply, .. }) = rx.recv().await
                {
                    if start {
                        assert!(ticket.try_start());
                    }
                    drop(reply);
                }
                rx
            });
            let outcome = handle
                .execute_service_command(
                    InvocationContext::host_origin("caller"),
                    services.acquire_call(&service).expect("acquire"),
                    service.clone(),
                    "go".into(),
                    Vec::new(),
                    no_check(),
                    DispatchTicket::default(),
                    Instant::now() + Duration::from_secs(5),
                )
                .await;
            rx = supervisor.await.expect("join");
            match (start, outcome) {
                (false, ServiceCallOutcome::NotRun(_)) | (true, ServiceCallOutcome::Unknown(_)) => {
                }
                (_, other) => panic!("start={start}: {other:?}"),
            }
            assert_eq!(services.active_call_count(&service), 0);
        }
    }

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
