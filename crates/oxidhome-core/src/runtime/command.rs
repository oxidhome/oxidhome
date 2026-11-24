//! Explicit device-command outcomes (architecture review H5,
//! ADR-0003 in `docs/adr/0003-explicit-command-outcomes.md`).
//!
//! Every device command the host dispatches gets a host-minted
//! [command id](mint_command_id) (`cmd-<32 hex>`) and ends in exactly
//! one [`CommandOutcome`]. The id rides to the plugin in
//! `command.id`, back to the caller in the API response, and into the
//! audit ledger (`command_id` / `command_outcome` columns). One
//! invocation (`call_id`, H6) may carry several commands; each gets
//! its own id.
//!
//! The transition rules (see also ARCHITECTURE.md, "Command outcomes
//! (H5)"):
//!
//! | What happened | Outcome |
//! |---|---|
//! | plugin returned `ok` / `ok-with-state` | `completed` |
//! | plugin returned `err` | `rejected` |
//! | host refused before queueing (owner not running, restarting) | `rejected` |
//! | deadline passed while the command was still queued | `timed_out` |
//! | caller went away while the command was still queued | `timed_out` (never runs) |
//! | plugin returned `unknown` | `outcome_unknown` |
//! | trap / watchdog kill / supervisor lost after the plugin was entered | `outcome_unknown` |
//! | deadline passed after the plugin was entered | `outcome_unknown` |
//! | `ok-with-state` whose state violates the projection contract | `outcome_unknown` |
//! | plugin returned `accepted` | `accepted` (then pending) |
//! | pending → plugin called `complete-command` | its mapped outcome |
//! | pending → TTL elapsed, instance restarted or stopped | `outcome_unknown` |
//! | pending → the daemon stopped (resolved at the next boot) | `outcome_unknown` |
//!
//! The line between `timed_out` and `outcome_unknown` is a single
//! compare-and-swap on a `DispatchTicket` shared by the waiting
//! caller and the supervisor: the supervisor flips it `queued →
//! started` immediately before entering the wasm, the caller flips it
//! `queued → abandoned` when it stops waiting. Exactly one side wins,
//! so `timed_out` is only ever reported for a command the plugin will
//! never see.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use crate::auth::invocation::{InvocationContext, audit_cap, mint_prefixed_id};
use crate::host_impl::plugin::oxidhome::plugin::devices::CommandResult;
use crate::host_impl::plugin::oxidhome::plugin::types::{Error as WitError, KeyValue};
use crate::state::{AuditEntry, AuditLog};

use super::command_journal::{CommandJournal, PendingRow, REASON_EXPIRED};

/// Prefix of every host-minted command id.
pub const COMMAND_ID_PREFIX: &str = "cmd-";

/// Audit `method` of a resolution row: the final outcome of a command
/// whose dispatch row could not carry it (an `accepted` command that
/// later completed or expired, or a result that arrived after the
/// caller stopped waiting).
pub const COMMAND_RESOLUTION_AUDIT_METHOD: &str = "COMMAND";

/// Upper bound on accepted-but-unfinished commands across the host.
pub const MAX_PENDING_COMMANDS: usize = 1024;

/// Upper bound on accepted-but-unfinished commands per instance, so
/// one plugin can't fill the host-wide table.
pub const MAX_PENDING_COMMANDS_PER_INSTANCE: usize = 64;

/// How long an `accepted` command may stay pending before the host
/// records `outcome_unknown` for it.
pub const PENDING_COMMAND_TTL: Duration = Duration::from_mins(5);

/// Longest capability name a pending entry retains. Real capability
/// names are short; the bound keeps the table's footprint small even
/// for a plugin that accepts whatever capability a caller sends.
pub const MAX_PENDING_CAPABILITY_BYTES: usize = 256;

/// Length of a host-minted command id: `cmd-` plus 32 hex digits.
const COMMAND_ID_LEN: usize = COMMAND_ID_PREFIX.len() + 32;

/// Mint a fresh `cmd-<32 hex>` command id (128 random bits).
#[must_use]
pub fn mint_command_id() -> String {
    mint_prefixed_id(COMMAND_ID_PREFIX)
}

/// The explicit outcome of one device command (H5). See the module
/// docs for the transition rules.
#[derive(Debug, Clone)]
pub enum CommandOutcome {
    /// The plugin took the command and will finish it asynchronously
    /// (`command-result::accepted`). The final outcome goes to the
    /// audit ledger as a `COMMAND` resolution row.
    Accepted,
    /// The plugin reported success. `state` is the authoritative
    /// post-command state when the plugin returned `ok-with-state`.
    Completed {
        /// Post-command state, already projected into the device-state
        /// store.
        state: Option<Vec<KeyValue>>,
    },
    /// The plugin or the host refused the command before acting.
    /// Safe to retry once the cause is fixed.
    Rejected {
        /// Why — the plugin's error, or a host-built one.
        error: WitError,
    },
    /// The deadline passed before the plugin was entered. The command
    /// did not run and never will; safe to retry.
    TimedOut {
        /// Human-readable detail.
        message: String,
    },
    /// The command may or may not have taken effect. Read the device
    /// state before retrying.
    Unknown {
        /// Human-readable detail.
        message: String,
    },
}

impl CommandOutcome {
    /// Stable `snake_case` name used on every API surface and in the
    /// audit ledger's `command_outcome` column.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Completed { .. } => "completed",
            Self::Rejected { .. } => "rejected",
            Self::TimedOut { .. } => "timed_out",
            Self::Unknown { .. } => "outcome_unknown",
        }
    }

    /// Whether the host knows the command had no effect, so repeating
    /// it cannot duplicate a physical action.
    #[must_use]
    pub fn is_retry_safe(&self) -> bool {
        matches!(self, Self::Rejected { .. } | Self::TimedOut { .. })
    }

    /// Coarse value for the audit ledger's pre-H5 `execution_outcome`
    /// column: `success` for `completed`, `failed` for `rejected`,
    /// `None` otherwise (`command_outcome` carries the detail).
    #[must_use]
    pub fn execution_outcome(&self) -> Option<&'static str> {
        match self {
            Self::Completed { .. } => Some("success"),
            Self::Rejected { .. } => Some("failed"),
            _ => None,
        }
    }

    /// WIT error kind of a `rejected` outcome, for the audit ledger's
    /// `domain_error` column.
    #[must_use]
    pub fn domain_error(&self) -> Option<&'static str> {
        match self {
            Self::Rejected { error } => Some(crate::api::wit_error_kind(error)),
            _ => None,
        }
    }

    /// Map what a plugin returned onto the caller-visible outcome.
    #[must_use]
    pub fn from_plugin(result: CommandResult) -> Self {
        match result {
            CommandResult::Ok => Self::Completed { state: None },
            CommandResult::OkWithState(state) => Self::Completed { state: Some(state) },
            CommandResult::Err(error) => Self::Rejected {
                error: cap_wit_error(error),
            },
            CommandResult::Unknown(message) => Self::Unknown {
                message: cap_plugin_text(message),
            },
            CommandResult::Accepted => Self::Accepted,
        }
    }
}

/// A command id plus how the command ended — what every device-command
/// API returns.
#[derive(Debug, Clone)]
pub struct CommandReport {
    /// Host-minted `cmd-<32 hex>` id.
    pub command_id: String,
    /// The explicit outcome.
    pub outcome: CommandOutcome,
}

impl CommandReport {
    /// M7: withhold `bytes-val` fields of a `completed` state readout
    /// from a caller without `blobs:read`.
    pub(crate) fn withhold_bytes(&mut self) {
        if let CommandOutcome::Completed { state: Some(kvs) } = &mut self.outcome {
            crate::redact::withhold_bytes_in_kvs(kvs);
        }
    }
}

const QUEUED: u8 = 0;
const STARTED: u8 = 1;
const ABANDONED: u8 = 2;
/// Withdrawn by the caller's own deadline: the caller reports
/// `timed_out` itself, so the supervisor doesn't audit it again.
const WITHDRAWN: u8 = 3;
/// The supervisor holds the ticket while it reads the clock; it
/// resolves to `STARTED` or `ABANDONED` without any await in between.
const CLAIMING: u8 = 4;
/// Abandoned by a caller that was dropped (disconnect): nobody reads a
/// reply, so whoever refuses the command records its outcome, even if
/// the reply send happens to succeed before the receiver is gone.
const DISCONNECTED: u8 = 5;

/// Shared between the caller waiting on a command and the supervisor
/// that will run it; decides `timed_out` vs `outcome_unknown` (see the
/// module docs).
#[derive(Debug, Clone, Default)]
pub(crate) struct DispatchTicket(Arc<AtomicU8>);

impl DispatchTicket {
    /// Supervisor side: claim the command for execution. `false` means
    /// the caller already gave up and the command must not run.
    #[cfg(test)]
    pub(crate) fn try_start(&self) -> bool {
        self.try_start_unless(|| false)
    }

    /// Supervisor side: claim the command, then refuse it (abandoned,
    /// reported `timed_out`) if `expired()` says its deadline passed.
    /// The deadline check and the start are one decision: a caller
    /// withdrawing meanwhile waits for it, so an expired command that
    /// never ran can't be reported as started.
    pub(crate) fn try_start_unless(&self, expired: impl FnOnce() -> bool) -> bool {
        if self
            .0
            .compare_exchange(QUEUED, CLAIMING, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return false;
        }
        let start = !expired();
        self.0
            .store(if start { STARTED } else { ABANDONED }, Ordering::Release);
        start
    }

    /// Abandon a still-queued command nobody will report on (caller
    /// dropped, or the supervisor refusing an expired one). `true`
    /// means the command will never run; `false` means the supervisor
    /// already entered the plugin.
    pub(crate) fn try_abandon(&self) -> bool {
        self.withdraw(ABANDONED)
    }

    /// Caller side, dropped while waiting: like [`Self::try_abandon`],
    /// and marks the caller as gone for the refusal's audit write.
    pub(crate) fn try_disconnect(&self) -> bool {
        self.withdraw(DISCONNECTED)
    }

    /// Caller side, on its own deadline: like [`Self::try_abandon`],
    /// but the caller reports `timed_out` itself.
    pub(crate) fn try_withdraw(&self) -> bool {
        self.withdraw(WITHDRAWN)
    }

    fn withdraw(&self, to: u8) -> bool {
        let mut observed = self
            .0
            .compare_exchange(QUEUED, to, Ordering::AcqRel, Ordering::Acquire);
        // The supervisor is between claiming and deciding: a clock read,
        // no await. Wait for its decision.
        while observed == Err(CLAIMING) {
            std::thread::yield_now();
            observed = Err(self.0.load(Ordering::Acquire));
        }
        match observed {
            Ok(_) => true,
            // The supervisor refused it first; a caller about to
            // report `timed_out` itself takes over the audit write.
            Err(ABANDONED) => {
                if to == WITHDRAWN {
                    let _ = self.0.compare_exchange(
                        ABANDONED,
                        WITHDRAWN,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    );
                }
                true
            }
            Err(current) => current != STARTED,
        }
    }

    /// Whether the caller already reported this command as `timed_out`.
    pub(crate) fn withdrawn_by_caller(&self) -> bool {
        self.0.load(Ordering::Acquire) == WITHDRAWN
    }

    /// Whether a dropped caller withdrew the command: its refusal must
    /// be recorded, since no reply will be read.
    pub(crate) fn disconnected(&self) -> bool {
        self.0.load(Ordering::Acquire) == DISCONNECTED
    }

    /// Supervisor teardown: refuse a still-queued command. `None` if
    /// the plugin was entered; `Some(true)` if the caller had already
    /// gone (disconnect or deadline) before the refusal, `Some(false)`
    /// if this refusal won.
    pub(crate) fn try_refuse(&self) -> Option<bool> {
        let mut observed =
            self.0
                .compare_exchange(QUEUED, ABANDONED, Ordering::AcqRel, Ordering::Acquire);
        while observed == Err(CLAIMING) {
            std::thread::yield_now();
            observed = Err(self.0.load(Ordering::Acquire));
        }
        match observed {
            Ok(_) => Some(false),
            Err(STARTED) => None,
            Err(_) => Some(true),
        }
    }

    /// Whether the supervisor entered the plugin.
    pub(crate) fn started(&self) -> bool {
        self.0.load(Ordering::Acquire) == STARTED
    }
}

/// Withdraws a still-queued command when the waiting caller is dropped
/// (client disconnect): a command nobody waits for any more must not
/// actuate a device later.
pub(crate) struct AbandonOnDrop(pub(crate) DispatchTicket);

impl Drop for AbandonOnDrop {
    fn drop(&mut self) {
        let _ = self.0.try_disconnect();
    }
}

/// Why a pending command expired. Its code is the `domain_error` of
/// the `outcome_unknown` resolution row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpiryReason {
    /// No completion arrived within the TTL.
    Expired,
    /// The owning instance restarted; its new store can't complete it.
    InstanceRestarted,
    /// The owning instance stopped.
    InstanceStopped,
}

impl ExpiryReason {
    /// Stable code recorded in the resolution row's `domain_error`.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::Expired => REASON_EXPIRED,
            Self::InstanceRestarted => "instance_restarted",
            Self::InstanceStopped => "instance_stopped",
        }
    }

    fn message(self) -> &'static str {
        match self {
            Self::Expired => "no completion arrived before the pending command expired",
            Self::InstanceRestarted => "the plugin instance restarted",
            Self::InstanceStopped => "the plugin instance stopped",
        }
    }
}

/// One accepted command waiting for `complete-command`.
#[derive(Debug)]
struct Pending {
    owner_instance: String,
    device_id: String,
    capability: String,
    ctx: InvocationContext,
    /// Queued for the `pending_command` table; its resolution must
    /// delete the row.
    journaled: bool,
    /// The entry's TTL timer, aborted when the entry leaves the table
    /// any other way, so finished commands don't leave sleeping tasks.
    expiry: tokio::task::AbortHandle,
    /// When the entry expires; `take` refuses a completion after it
    /// even if the timer task hasn't run yet.
    expires_at: tokio::time::Instant,
}

/// What [`PendingCommands::take`] hands back for the completing
/// instance to project state against.
#[derive(Debug)]
pub(crate) struct PendingCommand {
    pub(crate) device_id: String,
    pub(crate) capability: String,
    ctx: InvocationContext,
    journaled: bool,
}

impl From<Pending> for PendingCommand {
    fn from(p: Pending) -> Self {
        Self {
            device_id: p.device_id,
            capability: p.capability,
            ctx: p.ctx,
            journaled: p.journaled,
        }
    }
}

/// Bounded table of `accepted` device commands (H5). An entry leaves
/// the table exactly once: through `complete-command`, through its TTL
/// expiring, or through its owning instance restarting / stopping —
/// the last two record `outcome_unknown`.
///
/// Externally-rooted entries are also written behind to the
/// `pending_command` table through the [command
/// journal](super::command_journal), which also writes every `COMMAND`
/// resolution row, so a daemon restart resolves them at the next boot
/// instead of dropping them.
pub struct PendingCommands {
    entries: Mutex<HashMap<String, Pending>>,
    ttl_ms: AtomicU64,
    journal: Option<CommandJournal>,
}

impl std::fmt::Debug for PendingCommands {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingCommands")
            .field("len", &self.len())
            .finish_non_exhaustive()
    }
}

impl PendingCommands {
    /// Empty table. With `audit`, a journal writer thread on the
    /// ledger's database persists externally-rooted entries and writes
    /// their `COMMAND` resolution rows; without it nothing is recorded.
    ///
    /// # Errors
    ///
    /// The journal's writer thread could not be started.
    pub fn new(audit: Option<Arc<AuditLog>>) -> std::io::Result<Self> {
        let journal = match audit {
            Some(log) => Some(CommandJournal::start(Arc::clone(log.db()))?),
            None => None,
        };
        Ok(Self {
            entries: Mutex::new(HashMap::new()),
            ttl_ms: AtomicU64::new(duration_ms(PENDING_COMMAND_TTL)),
            journal,
        })
    }

    /// Wait up to `timeout` for every queued persist and resolution row
    /// to reach the database. `true` when the journal drained (or there
    /// is none).
    pub fn flush_journal(&self, timeout: Duration) -> bool {
        self.journal.as_ref().is_none_or(|j| j.flush(timeout))
    }

    /// Shutdown: stop taking journal work and wait up to `timeout` for
    /// what is queued. Entries still pending stay in the
    /// `pending_command` table and are resolved at the next boot.
    /// `true` when the journal drained.
    pub fn close_journal(&self, timeout: Duration) -> bool {
        self.journal.as_ref().is_none_or(|j| j.close(timeout))
    }

    /// Change how long an accepted command may stay pending (default
    /// [`PENDING_COMMAND_TTL`]). Applies to commands accepted from now
    /// on. Mainly for tests.
    pub fn set_ttl(&self, ttl: Duration) {
        self.ttl_ms.store(duration_ms(ttl), Ordering::Relaxed);
    }

    /// Number of commands currently pending.
    #[must_use]
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// Whether no command is pending.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Pending>> {
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Track a command the plugin answered with `accepted`, and arm its
    /// expiry. Must run inside a tokio runtime.
    ///
    /// # Errors
    ///
    /// A message when the id isn't host-shaped, is already pending, or
    /// a table bound is hit — the caller then reports
    /// `outcome_unknown`, since the plugin believes it holds the
    /// command.
    pub(crate) fn register(
        self: &Arc<Self>,
        command_id: &str,
        owner_instance: &str,
        device_id: &str,
        capability: &str,
        ctx: InvocationContext,
    ) -> Result<(), String> {
        if capability.len() > MAX_PENDING_CAPABILITY_BYTES {
            return Err(format!(
                "capability name is longer than {MAX_PENDING_CAPABILITY_BYTES} bytes"
            ));
        }
        if !command_id.starts_with(COMMAND_ID_PREFIX) || command_id.len() != COMMAND_ID_LEN {
            return Err(format!(
                "command id `{}` was not minted by the host; it cannot be completed later",
                audit_cap(command_id),
            ));
        }
        {
            let mut entries = self.lock();
            if entries.contains_key(command_id) {
                return Err(format!("command `{command_id}` is already pending"));
            }
            if entries.len() >= MAX_PENDING_COMMANDS {
                return Err(format!(
                    "host pending-command table is full ({MAX_PENDING_COMMANDS})"
                ));
            }
            let per_instance = entries
                .values()
                .filter(|p| p.owner_instance == owner_instance)
                .count();
            if per_instance >= MAX_PENDING_COMMANDS_PER_INSTANCE {
                return Err(format!(
                    "instance `{owner_instance}` already has \
                     {MAX_PENDING_COMMANDS_PER_INSTANCE} pending commands"
                ));
            }
            // Spawned under the lock so the timer can't fire before its
            // entry exists; it only takes the lock after sleeping.
            let ttl = Duration::from_millis(self.ttl_ms.load(Ordering::Relaxed));
            let expires_at = tokio::time::Instant::now() + ttl;
            let weak: Weak<Self> = Arc::downgrade(self);
            let id = command_id.to_owned();
            let expiry = tokio::spawn(async move {
                tokio::time::sleep_until(expires_at).await;
                if let Some(table) = weak.upgrade() {
                    table.expire(&id, ExpiryReason::Expired);
                }
            })
            .abort_handle();
            // Queued under the table lock, so the persist is ahead of
            // any resolution of this entry in the journal and a
            // resolved command's row can't resurrect.
            let journaled = match &self.journal {
                Some(journal) if ctx.root().is_external() => journal.persist(pending_row(
                    command_id,
                    owner_instance,
                    device_id,
                    capability,
                    &ctx,
                    ttl,
                )),
                _ => false,
            };
            entries.insert(
                command_id.to_owned(),
                Pending {
                    owner_instance: owner_instance.to_owned(),
                    device_id: device_id.to_owned(),
                    capability: capability.to_owned(),
                    ctx,
                    journaled,
                    expiry,
                    expires_at,
                },
            );
        }
        Ok(())
    }

    /// Remove a pending command owned by `owner_instance` so the
    /// caller can record its final outcome with [`Self::resolve`].
    ///
    /// # Errors
    ///
    /// `not-found` if no such pending command belongs to the instance.
    pub(crate) fn take(
        &self,
        owner_instance: &str,
        command_id: &str,
    ) -> Result<PendingCommand, WitError> {
        // Host ids have a fixed length; don't hash an oversized
        // plugin-supplied string under the host-wide lock.
        if command_id.len() != COMMAND_ID_LEN {
            return Err(WitError::NotFound(format!(
                "command `{}` is not a host command id",
                audit_cap(command_id),
            )));
        }
        let mut entries = self.lock();
        match entries.get(command_id) {
            Some(p) if p.owner_instance == owner_instance => {}
            _ => {
                return Err(WitError::NotFound(format!(
                    "command `{}` is not pending for this instance (never accepted, \
                     already completed, or expired)",
                    audit_cap(command_id),
                )));
            }
        }
        let p = entries
            .remove(command_id)
            .expect("entry checked under the same lock");
        // Decided under the lock that claimed the entry.
        let expired = tokio::time::Instant::now() >= p.expires_at;
        p.expiry.abort();
        if expired {
            // The TTL passed; the timer just hasn't run yet. Expire it
            // here so a late completion can't count as `completed`.
            self.expired(command_id, p, ExpiryReason::Expired);
            drop(entries);
            return Err(WitError::NotFound(format!(
                "command `{}` expired before it was completed",
                audit_cap(command_id),
            )));
        }
        drop(entries);
        Ok(p.into())
    }

    /// Record the final outcome of a command taken with [`Self::take`].
    pub(crate) fn resolve(
        &self,
        command_id: &str,
        pending: &PendingCommand,
        outcome: &CommandOutcome,
    ) {
        self.resolve_with(command_id, pending, outcome, None);
    }

    fn resolve_with(
        &self,
        command_id: &str,
        pending: &PendingCommand,
        outcome: &CommandOutcome,
        reason: Option<ExpiryReason>,
    ) {
        tracing::info!(
            target: "host.command",
            command_id,
            call_id = pending.ctx.call_id(),
            device_id = %pending.device_id,
            outcome = outcome.as_str(),
            reason = reason.map(ExpiryReason::code),
            "accepted command resolved",
        );
        let Some(journal) = &self.journal else { return };
        let forget = pending.journaled.then(|| command_id.to_owned());
        match resolution_entry(
            &pending.ctx,
            command_id,
            &pending.device_id,
            outcome,
            reason.map(ExpiryReason::code),
        ) {
            Some(entry) => journal.resolve(entry, forget),
            // Only externally-rooted commands are journaled.
            None => debug_assert!(forget.is_none(), "host-origin command was persisted"),
        }
    }

    /// Record the final outcome of a command that never reached the
    /// pending table — a result that arrived after its caller stopped
    /// waiting, or a queued command whose caller disconnected — as a
    /// `COMMAND` row. Externally-rooted commands only (host-origin work
    /// stays out of the ledger, as for H6 hops); queued on the journal,
    /// so this never blocks.
    pub(crate) fn record_resolution(
        &self,
        ctx: &InvocationContext,
        command_id: &str,
        device_id: &str,
        outcome: &CommandOutcome,
    ) {
        if let (Some(journal), Some(entry)) = (
            &self.journal,
            resolution_entry(ctx, command_id, device_id, outcome, None),
        ) {
            journal.resolve(entry, None);
        }
    }

    /// Expire every pending command of `owner_instance` as
    /// `outcome_unknown` — its plugin instance restarted or stopped, so
    /// no completion can be matched any more.
    ///
    /// Like every expiry, the resolution is queued on the journal
    /// before the table lock is released, so a caller that sees the
    /// entry gone (the reaper, then shutdown closing the journal) knows
    /// its row is already queued.
    pub fn expire_owner(&self, owner_instance: &str, reason: ExpiryReason) {
        let mut entries = self.lock();
        let ids: Vec<String> = entries
            .iter()
            .filter(|(_, p)| p.owner_instance == owner_instance)
            .map(|(id, _)| id.clone())
            .collect();
        for id in ids {
            if let Some(p) = entries.remove(&id) {
                p.expiry.abort();
                // A TTL that already ran out is an expiry, whatever
                // ended the instance (as `take` judges a completion).
                let reason = if tokio::time::Instant::now() >= p.expires_at {
                    ExpiryReason::Expired
                } else {
                    reason
                };
                self.expired(&id, p, reason);
            }
        }
    }

    fn expire(&self, command_id: &str, reason: ExpiryReason) {
        let mut entries = self.lock();
        if let Some(p) = entries.remove(command_id) {
            self.expired(command_id, p, reason);
        }
    }

    /// Resolve a removed entry as `outcome_unknown`. Called with the
    /// table lock held.
    fn expired(&self, command_id: &str, p: Pending, reason: ExpiryReason) {
        let pending = PendingCommand::from(p);
        self.resolve_with(
            command_id,
            &pending,
            &CommandOutcome::Unknown {
                message: format!("accepted command did not complete: {}", reason.message()),
            },
            Some(reason),
        );
    }
}

/// `host-devices::complete-command` (H5): the plugin reports the final
/// result of a command it answered with `accepted`.
pub(crate) fn complete_command(
    state: &super::PluginState,
    command_id: &str,
    reply: CommandResult,
) -> Result<(), WitError> {
    if matches!(reply, CommandResult::Accepted) {
        return Err(WitError::InvalidArgument(
            "complete-command needs a final result; `accepted` is not one".into(),
        ));
    }
    let Some(table) = &state.pending_commands else {
        return Err(WitError::NotFound(format!(
            "command `{}` is not pending (this host does not track accepted commands)",
            audit_cap(command_id),
        )));
    };
    let pending = table.take(&state.instance_id, command_id)?;
    let reply = match reply {
        CommandResult::OkWithState(fields) => super::instance::project_command_state(
            &state.devices,
            &state.device_state,
            &state.instance_id,
            &pending.device_id,
            &pending.capability,
            fields,
        ),
        other => other,
    };
    table.resolve(command_id, &pending, &CommandOutcome::from_plugin(reply));
    Ok(())
}

/// Longest plugin-supplied message (an `err` or `unknown` reply) the
/// host passes on; longer text is cut at a char boundary.
pub const MAX_PLUGIN_MESSAGE_BYTES: usize = 4 * 1024;

/// Cap plugin-supplied text at [`MAX_PLUGIN_MESSAGE_BYTES`] before any
/// transport copies or encodes it.
pub(crate) fn cap_plugin_text(m: String) -> String {
    cap_text_at(m, MAX_PLUGIN_MESSAGE_BYTES)
}

/// M7 + H5: bound a plugin reply's `err` / `unknown` text, then scrub
/// the instance's secret values from it. Bounding first keeps the
/// scrubber from copying a guest-sized message. The cut is chosen on
/// the original text and moved past any secret occurrence that
/// straddles it, so every secret byte kept is part of a whole match the
/// scrubber then replaces; a later shorter cap can only trim scrubbed
/// text.
pub(crate) fn scrub_and_cap_reply(result: &mut CommandResult, secrets: &[&str]) {
    match result {
        CommandResult::Err(
            WitError::NotFound(m)
            | WitError::InvalidArgument(m)
            | WitError::PermissionDenied(m)
            | WitError::Unavailable(m)
            | WitError::Internal(m),
        )
        | CommandResult::Unknown(m)
            if m.len() > MAX_PLUGIN_MESSAGE_BYTES =>
        {
            *m = match secret_safe_cut(m, MAX_PLUGIN_MESSAGE_BYTES, secrets) {
                Some(cut) => cap_text_at(std::mem::take(m), cut),
                None => "[plugin message withheld by host]".to_owned(),
            };
        }
        _ => {}
    }
    crate::redact::scrub_command_error(result, secrets);
}

/// The largest char boundary `<= limit`, moved back before every
/// secret occurrence that would straddle it, so the kept prefix holds
/// only whole matches. Never exceeds `limit`, so the scrubber's input
/// stays bounded. Linear in `limit` plus the longest secret: one
/// overlapping Aho-Corasick pass over that window, then a sweep over
/// the merged match intervals. `None` when the matcher can't be built
/// (pathological secrets); the caller then withholds the text.
fn secret_safe_cut(text: &str, limit: usize, secrets: &[&str]) -> Option<usize> {
    let mut cut = limit.min(text.len());
    while !text.is_char_boundary(cut) {
        cut -= 1;
    }
    // Same eligibility as the scrubber: shorter secrets aren't masked.
    let longest = secrets
        .iter()
        .filter(|s| s.len() >= crate::redact::MIN_SCRUB_SECRET_LEN)
        .map(|s| s.len())
        .max()
        .unwrap_or(0);
    let mut window_end = text.len().min(cut.saturating_add(longest));
    while !text.is_char_boundary(window_end) {
        window_end += 1;
    }
    let window = &text[..window_end];
    let secrets: Vec<&str> = secrets
        .iter()
        .copied()
        .filter(|s| s.len() >= crate::redact::MIN_SCRUB_SECRET_LEN && window.contains(s))
        .collect();
    if secrets.is_empty() {
        return Some(cut);
    }
    // Contiguous NFA, as in the scrubber: a DFA's construction is
    // quadratic in a long repetitive secret.
    let matcher = aho_corasick::AhoCorasick::builder()
        .kind(Some(aho_corasick::AhoCorasickKind::ContiguousNFA))
        .build(&secrets)
        .ok()?;
    // Merge overlapping match intervals (sorted by start); a cut is
    // safe unless it falls strictly inside a merged interval, and a
    // merged interval's start is never inside another one.
    let mut spans: Vec<(usize, usize)> = matcher
        .find_overlapping_iter(window)
        .map(|m| (m.start(), m.end()))
        .collect();
    spans.sort_unstable();
    let mut merged: Option<(usize, usize)> = None;
    for (start, end) in spans {
        merged = match merged {
            Some((s, e)) if start < e => Some((s, e.max(end))),
            Some((s, e)) => {
                if s < cut && cut < e {
                    return Some(s);
                }
                Some((start, end))
            }
            None => Some((start, end)),
        };
    }
    Some(match merged {
        Some((s, e)) if s < cut && cut < e => s,
        _ => cut,
    })
}

fn cap_text_at(m: String, limit: usize) -> String {
    if m.len() <= limit {
        return m;
    }
    let mut cap = limit;
    while !m.is_char_boundary(cap) {
        cap -= 1;
    }
    // A fresh allocation, so the guest's oversized buffer is freed now.
    let mut out = String::with_capacity(cap + 32);
    out.push_str(&m[..cap]);
    out.push_str("… [truncated by host]");
    out
}

fn cap_wit_error(error: WitError) -> WitError {
    match error {
        WitError::NotFound(m) => WitError::NotFound(cap_plugin_text(m)),
        WitError::InvalidArgument(m) => WitError::InvalidArgument(cap_plugin_text(m)),
        WitError::PermissionDenied(m) => WitError::PermissionDenied(cap_plugin_text(m)),
        WitError::Unavailable(m) => WitError::Unavailable(cap_plugin_text(m)),
        WitError::Internal(m) => WitError::Internal(cap_plugin_text(m)),
    }
}

fn duration_ms(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// `path` of a `COMMAND` resolution row.
pub(crate) fn resolution_path(device_id: &str) -> String {
    format!("device.command/{}", audit_cap(device_id))
}

/// The persisted form of an accepted command (H5 restart
/// reconciliation): what the next boot needs to write its final row.
fn pending_row(
    command_id: &str,
    owner_instance: &str,
    device_id: &str,
    capability: &str,
    ctx: &InvocationContext,
    ttl: Duration,
) -> PendingRow {
    let root = ctx.root();
    let created_ms = crate::state::event_log::now_unix_ms();
    // M7: the row holds the same attribution an audit row would, so it
    // is redacted the same way before it reaches the database (and any
    // backup of it).
    let scrub = |text: &str| crate::redact::scrub_text(text).into_owned();
    PendingRow {
        command_id: command_id.to_owned(),
        call_id: ctx.call_id().to_owned(),
        owner_instance: scrub(audit_cap(owner_instance)),
        device_id: scrub(audit_cap(device_id)),
        // Caller-supplied, so redacted structurally too.
        capability: crate::redact::redact_text(capability).into_owned(),
        created_ms,
        expires_ms: created_ms.saturating_add(i64::try_from(ttl.as_millis()).unwrap_or(i64::MAX)),
        token_id: root.audit_token_id().to_owned(),
        actor_kind: root.kind().as_str().to_owned(),
        invocation_json: crate::redact::redact_text(&ctx.audit_json()).into_owned(),
    }
}

/// The `COMMAND` resolution row for an externally-rooted command;
/// `None` for host-origin work, which stays out of the ledger (as for
/// H6 hops). `reason` (an [`ExpiryReason`] code) overrides
/// `domain_error`.
fn resolution_entry(
    ctx: &InvocationContext,
    command_id: &str,
    device_id: &str,
    outcome: &CommandOutcome,
    reason: Option<&str>,
) -> Option<AuditEntry> {
    let root = ctx.root();
    if !root.is_external() {
        return None;
    }
    Some(AuditEntry {
        id: 0,
        intent_ms: 0,
        finalized_ms: None,
        token_id: root.audit_token_id().to_owned(),
        actor_kind: root.kind().as_str().to_owned(),
        method: COMMAND_RESOLUTION_AUDIT_METHOD.to_owned(),
        path: resolution_path(device_id),
        status: 200,
        decision: "allow".into(),
        required_scope: None,
        execution_outcome: outcome.execution_outcome().map(str::to_owned),
        domain_error: reason.or_else(|| outcome.domain_error()).map(str::to_owned),
        credential_fp: None,
        call_id: Some(ctx.call_id().to_owned()),
        invocation: Some(ctx.audit_json()),
        command_id: Some(audit_cap(command_id).to_owned()),
        command_outcome: Some(outcome.as_str().to_owned()),

        level: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_ids_are_prefixed_and_unique() {
        let a = mint_command_id();
        let b = mint_command_id();
        assert!(a.starts_with(COMMAND_ID_PREFIX));
        assert_eq!(a.len(), COMMAND_ID_PREFIX.len() + 32);
        assert_ne!(a, b);
    }

    #[test]
    fn plugin_results_map_onto_outcomes() {
        let cases = [
            (CommandResult::Ok, "completed"),
            (CommandResult::OkWithState(Vec::new()), "completed"),
            (
                CommandResult::Err(WitError::InvalidArgument("x".into())),
                "rejected",
            ),
            (CommandResult::Unknown("no ack".into()), "outcome_unknown"),
            (CommandResult::Accepted, "accepted"),
        ];
        for (result, want) in cases {
            assert_eq!(CommandOutcome::from_plugin(result).as_str(), want);
        }
    }

    #[test]
    fn only_rejected_and_timed_out_are_retry_safe() {
        assert!(
            CommandOutcome::Rejected {
                error: WitError::Unavailable(String::new())
            }
            .is_retry_safe()
        );
        assert!(
            CommandOutcome::TimedOut {
                message: String::new()
            }
            .is_retry_safe()
        );
        assert!(!CommandOutcome::Accepted.is_retry_safe());
        assert!(!CommandOutcome::Completed { state: None }.is_retry_safe());
        assert!(
            !CommandOutcome::Unknown {
                message: String::new()
            }
            .is_retry_safe()
        );
    }

    #[test]
    fn ticket_start_and_abandon_are_mutually_exclusive() {
        let t = DispatchTicket::default();
        assert!(t.try_start());
        assert!(!t.try_abandon());
        assert!(t.started());

        let t = DispatchTicket::default();
        assert!(t.try_abandon());
        assert!(!t.try_start());
        assert!(!t.started());
        // Abandoned by the supervisor first: the caller still learns
        // the command never ran.
        assert!(t.try_withdraw());
        assert!(
            t.withdrawn_by_caller(),
            "the caller owns the timeout report"
        );

        let t = DispatchTicket::default();
        assert!(t.try_withdraw());
        assert!(t.withdrawn_by_caller());
        assert!(!t.try_start());
    }

    #[test]
    fn expired_claim_is_never_started() {
        let t = DispatchTicket::default();
        assert!(!t.try_start_unless(|| true));
        assert!(!t.started());
        // The caller's withdrawal sees "never ran" and owns the report.
        assert!(t.try_withdraw());
        assert!(t.withdrawn_by_caller());
    }

    #[test]
    fn abandon_on_drop_withdraws_a_queued_command() {
        let t = DispatchTicket::default();
        drop(AbandonOnDrop(t.clone()));
        assert!(!t.try_start());
        assert!(t.disconnected());
        assert_eq!(t.try_refuse(), Some(true));
    }

    fn host_ctx() -> InvocationContext {
        InvocationContext::host_origin("inst-a")
    }

    #[tokio::test]
    async fn pending_command_completes_once_for_its_owner_only() {
        let table = Arc::new(PendingCommands::new(None).unwrap());
        let id = mint_command_id();
        table
            .register(&id, "inst-a", "dev-1", "switch", host_ctx())
            .expect("register");
        assert_eq!(table.len(), 1);
        assert!(
            table
                .register(&id, "inst-a", "dev-1", "switch", host_ctx())
                .is_err()
        );
        assert!(matches!(
            table.take("inst-b", &id),
            Err(WitError::NotFound(_))
        ));
        let taken = table.take("inst-a", &id).expect("owner takes it");
        assert_eq!(taken.device_id, "dev-1");
        assert!(table.is_empty());
        assert!(matches!(
            table.take("inst-a", &id),
            Err(WitError::NotFound(_))
        ));
    }

    #[tokio::test]
    async fn pending_command_refuses_foreign_ids_and_bounds_per_instance() {
        let table = Arc::new(PendingCommands::new(None).unwrap());
        assert!(
            table
                .register("plugin-made", "inst-a", "dev-1", "switch", host_ctx())
                .is_err()
        );
        for _ in 0..MAX_PENDING_COMMANDS_PER_INSTANCE {
            table
                .register(&mint_command_id(), "inst-a", "dev-1", "switch", host_ctx())
                .expect("under the bound");
        }
        let err = table
            .register(&mint_command_id(), "inst-a", "dev-1", "switch", host_ctx())
            .expect_err("per-instance bound");
        assert!(err.contains("pending commands"), "{err}");
        // Another instance still has room.
        table
            .register(&mint_command_id(), "inst-b", "dev-2", "switch", host_ctx())
            .expect("other instance");
    }

    #[tokio::test]
    async fn pending_command_bounds_capability_and_refuses_late_completion() {
        let table = Arc::new(PendingCommands::new(None).unwrap());
        let long = "x".repeat(MAX_PENDING_CAPABILITY_BYTES + 1);
        assert!(
            table
                .register(&mint_command_id(), "inst-a", "dev-1", &long, host_ctx())
                .is_err()
        );
        // The TTL has passed by the time the plugin completes; the
        // completion loses even though the timer hasn't fired yet.
        table.set_ttl(Duration::ZERO);
        let id = mint_command_id();
        table
            .register(&id, "inst-a", "dev-1", "switch", host_ctx())
            .expect("register");
        assert!(matches!(
            table.take("inst-a", &id),
            Err(WitError::NotFound(_))
        ));
        assert!(table.is_empty());
    }

    #[tokio::test]
    async fn pending_command_expires_after_ttl() {
        let table = Arc::new(PendingCommands::new(None).unwrap());
        table.set_ttl(Duration::from_millis(20));
        let id = mint_command_id();
        table
            .register(&id, "inst-a", "dev-1", "switch", host_ctx())
            .expect("register");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while !table.is_empty() {
            assert!(tokio::time::Instant::now() < deadline, "never expired");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(table.take("inst-a", &id).is_err());
    }

    #[tokio::test]
    async fn an_elapsed_ttl_expires_as_expired_whatever_ends_the_instance() {
        use crate::auth::{Actor, ActorKind, Principal, Transport};
        use crate::state::{AuditQuery, Db};
        let audit = Arc::new(AuditLog::new(Arc::new(Db::open_in_memory().expect("db"))));
        let table = Arc::new(PendingCommands::new(Some(Arc::clone(&audit))).unwrap());
        table.set_ttl(Duration::ZERO);
        let actor = Actor::api("tok-1", vec!["*".into()]);
        let ctx =
            InvocationContext::external(Principal::token(ActorKind::Api, &actor, Transport::Rest));
        let id = mint_command_id();
        table
            .register(&id, "inst-a", "dev-1", "switch", ctx)
            .expect("register");
        // No yield: the TTL timer hasn't run.
        table.expire_owner("inst-a", ExpiryReason::InstanceStopped);
        assert!(table.flush_journal(Duration::from_secs(5)));
        let rows = audit.query(&AuditQuery::default(), 10).expect("query");
        let row = rows
            .iter()
            .find(|r| r.command_id.as_deref() == Some(id.as_str()))
            .expect("resolution row");
        assert_eq!(row.domain_error.as_deref(), Some("expired"));
    }

    #[test]
    fn persisted_rows_are_redacted() {
        use crate::auth::{Actor, ActorKind, Principal, Transport};
        let actor = Actor::api("tok-1", vec!["*".into()]);
        let ctx =
            InvocationContext::external(Principal::token(ActorKind::Api, &actor, Transport::Rest));
        let row = pending_row(
            &mint_command_id(),
            "inst-a",
            "dev-1",
            r#"{"key":"password","value":"hunter2-secret"}"#,
            &ctx,
            PENDING_COMMAND_TTL,
        );
        assert!(!row.capability.contains("hunter2"), "{}", row.capability);
        assert_eq!(row.token_id, "tok-1");
        assert!(row.expires_ms > row.created_ms);
    }

    #[tokio::test]
    async fn expire_owner_drains_only_that_instance() {
        let table = Arc::new(PendingCommands::new(None).unwrap());
        let a = mint_command_id();
        let b = mint_command_id();
        table
            .register(&a, "inst-a", "dev-1", "switch", host_ctx())
            .expect("a");
        table
            .register(&b, "inst-b", "dev-2", "switch", host_ctx())
            .expect("b");
        table.expire_owner("inst-a", ExpiryReason::InstanceRestarted);
        assert_eq!(table.len(), 1);
        assert!(table.take("inst-b", &b).is_ok());
    }
}

#[cfg(test)]
mod message_cap_tests {
    use super::{CommandResult, MAX_PLUGIN_MESSAGE_BYTES, cap_plugin_text, scrub_and_cap_reply};

    #[test]
    fn secret_straddling_the_cap_is_scrubbed_and_text_bounded() {
        let secret = "hunter2-very-secret";
        // The secret starts 4 bytes before the cut.
        let mut text = "x".repeat(MAX_PLUGIN_MESSAGE_BYTES - 4);
        text.push_str(secret);
        text.push_str(&"y".repeat(1 << 20));
        let mut reply = CommandResult::Unknown(text);
        scrub_and_cap_reply(&mut reply, &[secret]);
        let CommandResult::Unknown(out) = reply else {
            panic!("variant kept")
        };
        assert!(!out.contains("hunter2"), "secret prefix leaked");
        assert!(out.len() < MAX_PLUGIN_MESSAGE_BYTES + 128, "{}", out.len());
        let out = cap_plugin_text(out);
        assert!(!out.contains("hunter2"));
    }

    #[test]
    fn earlier_secret_masking_cannot_pull_a_partial_secret_into_the_cap() {
        let secret = "s3cr3t-value-that-is-long";
        // One whole secret early (its mask is shorter), then one
        // straddling well past the cap.
        let mut text = String::from(secret);
        text.push_str(&"x".repeat(MAX_PLUGIN_MESSAGE_BYTES + 10 - secret.len()));
        text.push_str(secret);
        text.push_str(&"y".repeat(100));
        let mut reply = CommandResult::Unknown(text);
        scrub_and_cap_reply(&mut reply, &[secret]);
        let CommandResult::Unknown(out) = reply else {
            panic!("variant kept")
        };
        let out = cap_plugin_text(out);
        assert!(!out.contains("s3cr3t"), "partial secret leaked");
    }

    #[test]
    fn overlapping_secret_runs_keep_the_cut_bounded() {
        let secret = "aaaa";
        let mut reply = CommandResult::Unknown("a".repeat(1 << 20));
        scrub_and_cap_reply(&mut reply, &[secret]);
        let CommandResult::Unknown(out) = reply else {
            panic!("variant kept")
        };
        assert!(out.len() < MAX_PLUGIN_MESSAGE_BYTES + 128, "{}", out.len());
        assert!(!out.contains(secret), "{out}");
    }

    #[test]
    fn a_long_repetitive_secret_is_handled_in_linear_time() {
        // A secret longer than the cap, matched by the reply: the
        // whole prefix is covered, so nothing of it is kept.
        let secret = "b".repeat(64 * 1024);
        let mut reply = CommandResult::Unknown("b".repeat(1 << 20));
        let start = std::time::Instant::now();
        scrub_and_cap_reply(&mut reply, &[secret.as_str()]);
        assert!(start.elapsed() < std::time::Duration::from_secs(5));
        let CommandResult::Unknown(out) = reply else {
            panic!("variant kept")
        };
        assert!(!out.contains(&"b".repeat(16)), "{}", out.len());
    }

    #[test]
    fn passes_through_short_messages_unchanged() {
        let short = "brief plugin error".to_string();
        assert_eq!(cap_plugin_text(short.clone()), short);
    }

    #[test]
    fn truncates_over_cap_ascii_message() {
        let big = "x".repeat(MAX_PLUGIN_MESSAGE_BYTES + 100);
        let out = cap_plugin_text(big);
        assert!(
            out.len() <= MAX_PLUGIN_MESSAGE_BYTES + 32,
            "capped output {} B must fit within cap + suffix; got {}",
            MAX_PLUGIN_MESSAGE_BYTES,
            out.len(),
        );
        assert!(out.ends_with("[truncated by host]"));
    }

    #[test]
    fn truncation_respects_utf8_char_boundaries() {
        // Fill the message with 4-byte emojis so a naïve
        // byte truncation at exactly the cap would split a
        // scalar. `cap_plugin_text` walks back to the largest
        // safe boundary — the output is always valid UTF-8.
        let emoji = "😀";
        assert_eq!(emoji.len(), 4);
        let big: String = emoji.repeat((MAX_PLUGIN_MESSAGE_BYTES / 4) + 100);
        assert!(big.len() > MAX_PLUGIN_MESSAGE_BYTES);
        let out = cap_plugin_text(big);
        assert!(out.is_char_boundary(out.len() - "… [truncated by host]".len()));
        assert!(out.ends_with("[truncated by host]"));
    }
}
