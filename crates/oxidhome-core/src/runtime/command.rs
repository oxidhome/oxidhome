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

/// Shared between the caller waiting on a command and the supervisor
/// that will run it; decides `timed_out` vs `outcome_unknown` (see the
/// module docs).
#[derive(Debug, Clone, Default)]
pub(crate) struct DispatchTicket(Arc<AtomicU8>);

impl DispatchTicket {
    /// Supervisor side: claim the command for execution. `false` means
    /// the caller already gave up and the command must not run.
    pub(crate) fn try_start(&self) -> bool {
        self.0
            .compare_exchange(QUEUED, STARTED, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    /// Abandon a still-queued command nobody will report on (caller
    /// dropped, or the supervisor refusing an expired one). `true`
    /// means the command will never run; `false` means the supervisor
    /// already entered the plugin.
    pub(crate) fn try_abandon(&self) -> bool {
        self.withdraw(ABANDONED)
    }

    /// Caller side, on its own deadline: like [`Self::try_abandon`],
    /// but the caller reports `timed_out` itself.
    pub(crate) fn try_withdraw(&self) -> bool {
        self.withdraw(WITHDRAWN)
    }

    fn withdraw(&self, to: u8) -> bool {
        match self
            .0
            .compare_exchange(QUEUED, to, Ordering::AcqRel, Ordering::Acquire)
        {
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
        let _ = self.0.try_abandon();
    }
}

/// One accepted command waiting for `complete-command`.
#[derive(Debug)]
struct Pending {
    owner_instance: String,
    device_id: String,
    capability: String,
    ctx: InvocationContext,
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
}

/// Bounded table of `accepted` device commands (H5). An entry leaves
/// the table exactly once: through `complete-command`, through its TTL
/// expiring, or through its owning instance restarting / stopping —
/// the last two record `outcome_unknown`.
pub struct PendingCommands {
    entries: Mutex<HashMap<String, Pending>>,
    ttl_ms: AtomicU64,
    audit: Option<Arc<AuditLog>>,
}

impl std::fmt::Debug for PendingCommands {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingCommands")
            .field("len", &self.len())
            .finish_non_exhaustive()
    }
}

impl PendingCommands {
    /// Empty table. `audit` receives the `COMMAND` resolution rows of
    /// externally-rooted commands.
    #[must_use]
    pub fn new(audit: Option<Arc<AuditLog>>) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            ttl_ms: AtomicU64::new(duration_ms(PENDING_COMMAND_TTL)),
            audit,
        }
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
                    table.expire(
                        &id,
                        "no completion arrived before the pending command expired",
                    );
                }
            })
            .abort_handle();
            entries.insert(
                command_id.to_owned(),
                Pending {
                    owner_instance: owner_instance.to_owned(),
                    device_id: device_id.to_owned(),
                    capability: capability.to_owned(),
                    ctx,
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
        drop(entries);
        p.expiry.abort();
        if tokio::time::Instant::now() >= p.expires_at {
            // The TTL passed; the timer just hasn't run yet. Expire it
            // here so a late completion can't count as `completed`.
            let reason = "no completion arrived before the pending command expired";
            self.expired(command_id, p, reason);
            return Err(WitError::NotFound(format!(
                "command `{}` expired before it was completed",
                audit_cap(command_id),
            )));
        }
        Ok(PendingCommand {
            device_id: p.device_id,
            capability: p.capability,
            ctx: p.ctx,
        })
    }

    /// Record the final outcome of a command taken with [`Self::take`].
    pub(crate) fn resolve(
        &self,
        command_id: &str,
        pending: &PendingCommand,
        outcome: &CommandOutcome,
    ) {
        tracing::info!(
            target: "host.command",
            command_id,
            call_id = pending.ctx.call_id(),
            device_id = %pending.device_id,
            outcome = outcome.as_str(),
            "accepted command resolved",
        );
        record_resolution(
            self.audit.as_ref(),
            &pending.ctx,
            command_id,
            &pending.device_id,
            outcome,
        );
    }

    /// Expire every pending command of `owner_instance` as
    /// `outcome_unknown` — its plugin instance restarted or stopped, so
    /// no completion can be matched any more.
    pub fn expire_owner(&self, owner_instance: &str, reason: &str) {
        let drained: Vec<(String, Pending)> = {
            let mut entries = self.lock();
            let ids: Vec<String> = entries
                .iter()
                .filter(|(_, p)| p.owner_instance == owner_instance)
                .map(|(id, _)| id.clone())
                .collect();
            ids.into_iter()
                .filter_map(|id| entries.remove(&id).map(|p| (id, p)))
                .collect()
        };
        for (id, p) in drained {
            p.expiry.abort();
            self.expired(&id, p, reason);
        }
    }

    fn expire(&self, command_id: &str, reason: &str) {
        let removed = self.lock().remove(command_id);
        if let Some(p) = removed {
            self.expired(command_id, p, reason);
        }
    }

    fn expired(&self, command_id: &str, p: Pending, reason: &str) {
        let pending = PendingCommand {
            device_id: p.device_id,
            capability: p.capability,
            ctx: p.ctx,
        };
        self.resolve(
            command_id,
            &pending,
            &CommandOutcome::Unknown {
                message: format!("accepted command did not complete: {reason}"),
            },
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
    if m.len() <= MAX_PLUGIN_MESSAGE_BYTES {
        return m;
    }
    let mut cap = MAX_PLUGIN_MESSAGE_BYTES;
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

/// Write a `COMMAND` resolution row for an externally-rooted command
/// (host-origin work stays out of the ledger, as for H6 hops). Detached
/// and best-effort: the dispatch row is the durable evidence; this row
/// records how the command finally ended.
pub(crate) fn record_resolution(
    audit: Option<&Arc<AuditLog>>,
    ctx: &InvocationContext,
    command_id: &str,
    device_id: &str,
    outcome: &CommandOutcome,
) {
    let Some(log) = audit else { return };
    if !ctx.root().is_external() {
        return;
    }
    let root = ctx.root();
    let entry = AuditEntry {
        id: 0,
        intent_ms: 0,
        finalized_ms: None,
        token_id: root.audit_token_id().to_owned(),
        actor_kind: root.kind().as_str().to_owned(),
        method: COMMAND_RESOLUTION_AUDIT_METHOD.to_owned(),
        path: format!("device.command/{}", audit_cap(device_id)),
        status: 200,
        decision: "allow".into(),
        required_scope: None,
        execution_outcome: outcome.execution_outcome().map(str::to_owned),
        domain_error: outcome.domain_error().map(str::to_owned),
        credential_fp: None,
        call_id: Some(ctx.call_id().to_owned()),
        invocation: Some(ctx.audit_json()),
        command_id: Some(audit_cap(command_id).to_owned()),
        command_outcome: Some(outcome.as_str().to_owned()),
    };
    let log = Arc::clone(log);
    let Ok(rt) = tokio::runtime::Handle::try_current() else {
        tracing::warn!(target: "host.audit", command_id, "no runtime for command resolution row");
        return;
    };
    rt.spawn_blocking(move || {
        if let Err(err) = log.record_completed(&entry) {
            tracing::error!(target: "host.audit", error = %err, "command resolution row failed");
        }
    });
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
    fn abandon_on_drop_withdraws_a_queued_command() {
        let t = DispatchTicket::default();
        drop(AbandonOnDrop(t.clone()));
        assert!(!t.try_start());
    }

    fn host_ctx() -> InvocationContext {
        InvocationContext::host_origin("inst-a")
    }

    #[tokio::test]
    async fn pending_command_completes_once_for_its_owner_only() {
        let table = Arc::new(PendingCommands::new(None));
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
        let table = Arc::new(PendingCommands::new(None));
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
        let table = Arc::new(PendingCommands::new(None));
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
        let table = Arc::new(PendingCommands::new(None));
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
    async fn expire_owner_drains_only_that_instance() {
        let table = Arc::new(PendingCommands::new(None));
        let a = mint_command_id();
        let b = mint_command_id();
        table
            .register(&a, "inst-a", "dev-1", "switch", host_ctx())
            .expect("a");
        table
            .register(&b, "inst-b", "dev-2", "switch", host_ctx())
            .expect("b");
        table.expire_owner("inst-a", "instance restarted");
        assert_eq!(table.len(), 1);
        assert!(table.take("inst-b", &b).is_ok());
    }
}

#[cfg(test)]
mod message_cap_tests {
    use super::{MAX_PLUGIN_MESSAGE_BYTES, cap_plugin_text};

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
