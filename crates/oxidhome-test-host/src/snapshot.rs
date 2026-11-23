//! [`Snapshot`] — a compact, deterministic text rendering of what one
//! instance left in the host, for whole-state assertions.

use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::fmt::Write as _;
use std::path::Path;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, UNIX_EPOCH};

use oxidhome_core::state::{AuditEntry, AuditQuery, StateQuality};
use oxidhome_core::{Clock, CommandOutcome};

use crate::TestHostError;
use crate::view::InstanceRef;
use crate::wit::capabilities::{ButtonEvent, CapabilitySpec};
use crate::wit::events::EventPayload;
use crate::wit::services::{FieldSpec, ValueKind};
use crate::wit::types::{Error as WitError, KeyValue, Value};

/// Environment variable that makes [`Snapshot::assert_matches_file`]
/// (re)write the expected file instead of comparing against it.
pub const UPDATE_SNAPSHOTS_ENV: &str = "OXIDHOME_UPDATE_SNAPSHOTS";

/// What one instance has in the host — devices, services, events,
/// storage, blobs, and on request its device-state projection, the
/// commands the test sent it, and its audit rows — rendered one line
/// per item.
///
/// Built by `snapshot()` / `snapshot_with()` on
/// [`crate::TestPluginInstance`] or [`crate::SupervisedInstance`].
///
/// # Stable and redacted
///
/// Two runs of the same test render the same text, and the text is
/// safe to commit:
///
/// - Values stamped from a process-wide counter or a random source
///   are left out (event-log row ids, `svc-N` service ids, blob ids,
///   audit row ids) or replaced: a host-minted `cmd-<32 hex>` command
///   id or `call-<32 hex>` invocation id becomes `<cmd-1>`,
///   `<call-1>`, … numbered in order of first appearance.
/// - Times are left out unless [`SnapshotOptions::times`] asks for
///   them; then they render relative to the host's
///   [`crate::VirtualClock`] start (`@+1.500s`), or as `@?` on a
///   real-clock host.
/// - The instance's secret config values (manifest `type = "secret"`)
///   are masked as `***` wherever they appear — exact string values
///   of any length, and inside free text from four characters on —
///   as are values under credential-like keys (`password=…`,
///   `api_key: …`), `Bearer` credentials, and `oxh_` API tokens, by
///   the host's own redaction rules ([`oxidhome_core::redact`]).
///   [`SnapshotOptions::redact`] adds test-specific replacements.
///
/// Device ids stay in: they are a hash of the installation, instance
/// id, and local id, so they are stable as long as the test picks its
/// instance ids (or loads in the same order).
///
/// The text form ([`fmt::Display`]) is what [`Self::assert_matches`]
/// compares, e.g.
///
/// ```text
/// devices:
///   dev-0123456789abcdef "Simulated Switch" [switch]
/// services:
/// events:
///   dev-0123456789abcdef state-changed switch {state=true}
/// storage:
///   count = 3
/// blobs:
/// ```
///
/// The optional sections follow, in the order `device-state`,
/// `commands`, `audit`, each only when requested. Any text-snapshot
/// tool works too: compare `snapshot.to_string()`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Snapshot {
    /// `<device-id> "<name>" [<capability>, …]`, sorted by device id.
    pub devices: Vec<String>,
    /// `<local-id> "<name>" <command>(<param>: <kind>, …), …`, sorted
    /// by local id. An optional param renders as `name?`.
    pub services: Vec<String>,
    /// `<device-id or -> <payload>`, oldest first.
    pub events: Vec<String>,
    /// `<key> = <value>`, sorted by key.
    pub storage: Vec<String>,
    /// `<name> <size>B <mime or ->`, sorted by name.
    pub blobs: Vec<String>,
    /// With [`SnapshotOptions::device_state`]: the host's device-state
    /// projection for this instance's devices, one line per
    /// capability, `<device-id> <capability> {<field>=<value>, …}`,
    /// plus ` stale` once the instance stopped (or before its first
    /// report after a restart). Sorted by device id, then capability.
    pub device_state: Option<Vec<String>>,
    /// With [`SnapshotOptions::commands`]: every command the test sent
    /// this instance through the harness, oldest first,
    /// `<device-id> <capability>.<action> -> <outcome> <detail>`. The
    /// outcome is the H5 name (`completed`, `rejected`, `accepted`,
    /// `timed_out`, `outcome_unknown`); an `accepted` command shows
    /// `(pending)` while the host still waits for its
    /// `complete-command`, `(resolved)` after.
    pub commands: Option<Vec<String>>,
    /// With [`SnapshotOptions::audit`]: the audit-ledger rows rooted
    /// at this instance (a refused `get-state` / `read-events`, …),
    /// oldest first, `<decision> <status> <method> <path>` plus
    /// `scope=`, `outcome=`, `command=` and `error=` when set.
    pub audit: Option<Vec<String>>,
}

/// What [`Snapshot`] captures beyond the default sections, and how.
/// `SnapshotOptions::default()` is the plain `snapshot()`.
// Independent on/off switches set through the builder methods.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Default)]
pub struct SnapshotOptions {
    device_state: bool,
    commands: bool,
    audit: bool,
    times: bool,
    redactions: Vec<(String, String)>,
}

impl SnapshotOptions {
    /// Same as [`SnapshotOptions::default`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Every optional section, without times.
    #[must_use]
    pub fn all() -> Self {
        Self::new().device_state().commands().audit()
    }

    /// Add the `device-state` section.
    #[must_use]
    pub fn device_state(mut self) -> Self {
        self.device_state = true;
        self
    }

    /// Add the `commands` section.
    #[must_use]
    pub fn commands(mut self) -> Self {
        self.commands = true;
        self
    }

    /// Add the `audit` section. Waits (up to 10 s of real time) for
    /// audit rows the host writes in the background to land first.
    #[must_use]
    pub fn audit(mut self) -> Self {
        self.audit = true;
        self
    }

    /// Stamp events and device-state lines with the host time they
    /// were recorded at, relative to the virtual clock's start:
    /// `@+1.500s`. On a real-clock host every stamp is `@?`. Audit rows
    /// stay unstamped: the host writes some in the background.
    #[must_use]
    pub fn times(mut self) -> Self {
        self.times = true;
        self
    }

    /// Replace every occurrence of `text` with `placeholder` in the
    /// rendered snapshot, before the built-in redaction runs — for
    /// values the test knows are unstable or sensitive. Strings print
    /// escaped, so match a value with quotes or newlines as it prints.
    #[must_use]
    pub fn redact(mut self, text: impl Into<String>, placeholder: impl Into<String>) -> Self {
        let text = text.into();
        if !text.is_empty() {
            self.redactions.push((text, placeholder.into()));
        }
        self
    }
}

/// One command a test sent through the harness, for the `commands`
/// section.
#[derive(Debug, Clone)]
pub(crate) struct CommandRecord {
    pub(crate) device: String,
    pub(crate) capability: String,
    pub(crate) action: String,
    /// Empty until the reply.
    pub(crate) command_id: String,
    /// `None` while the command is in flight, or if the caller
    /// dropped the request before the reply.
    pub(crate) outcome: Option<CommandOutcome>,
    /// The caller dropped the request before the reply.
    pub(crate) dropped: bool,
}

/// How long a snapshot waits for background audit writers.
const AUDIT_FLUSH: Duration = Duration::from_secs(10);

/// Upper bound on the audit rows one snapshot reads.
const AUDIT_ROWS: usize = 100_000;

/// What one host's snapshots redact with, across every instance it
/// loaded: an instance id's stored data and events outlive a reload
/// (with a rotated secret, or a fresh command history).
#[derive(Debug, Default)]
pub(crate) struct HostRecords {
    /// Every instance's secret config values.
    secrets: Mutex<BTreeSet<String>>,
    /// Every command id the harness sent, in send order.
    command_ids: Mutex<Vec<String>>,
}

impl HostRecords {
    pub(crate) fn add<'s>(&self, values: impl IntoIterator<Item = &'s str>) {
        let mut set = self.secrets.lock().unwrap_or_else(PoisonError::into_inner);
        set.extend(values.into_iter().map(str::to_owned));
    }

    fn secret_values(&self) -> Vec<String> {
        let set = self.secrets.lock().unwrap_or_else(PoisonError::into_inner);
        set.iter().cloned().collect()
    }

    fn command_ids(&self) -> Vec<String> {
        self.command_ids
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

/// A command's place in the histories — the instance's and the
/// host's — taken before it is sent, so both keep send order. Filled
/// by [`Self::reply`]; dropped without one (the caller gave up on the
/// request), it records that instead of staying in flight.
pub(crate) struct CommandSlot<'a> {
    commands: &'a Mutex<Vec<CommandRecord>>,
    host: &'a HostRecords,
    slot: usize,
    host_slot: usize,
    replied: bool,
}

impl<'a> CommandSlot<'a> {
    pub(crate) fn reserve(
        commands: &'a Mutex<Vec<CommandRecord>>,
        host: &'a HostRecords,
        device: String,
        capability: String,
        action: String,
    ) -> Self {
        // Both slots under the instance's lock (taken first, then the
        // host's), so the two histories agree on send order.
        let mut list = commands.lock().unwrap_or_else(PoisonError::into_inner);
        list.push(CommandRecord {
            device,
            capability,
            action,
            command_id: String::new(),
            outcome: None,
            dropped: false,
        });
        let slot = list.len() - 1;
        let host_slot = {
            let mut ids = host
                .command_ids
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            ids.push(String::new());
            ids.len() - 1
        };
        drop(list);
        Self {
            commands,
            host,
            slot,
            host_slot,
            replied: false,
        }
    }

    /// Record the reply.
    pub(crate) fn reply(mut self, command_id: &str, outcome: CommandOutcome) {
        self.replied = true;
        self.fill(command_id, Some(outcome));
    }

    fn fill(&self, command_id: &str, outcome: Option<CommandOutcome>) {
        if let Some(record) = self
            .commands
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get_mut(self.slot)
        {
            command_id.clone_into(&mut record.command_id);
            record.outcome = outcome;
            record.dropped = !self.replied;
        }
        if let Some(id) = self
            .host
            .command_ids
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get_mut(self.host_slot)
        {
            command_id.clone_into(id);
        }
    }
}

impl Drop for CommandSlot<'_> {
    fn drop(&mut self) {
        if !self.replied {
            self.fill("", None);
        }
    }
}

impl Snapshot {
    pub(crate) fn capture(
        instance: &InstanceRef<'_>,
        options: &SnapshotOptions,
    ) -> Result<Self, TestHostError> {
        let stamp = Stamp::new(instance.engine.clock(), options.times);
        let secrets = instance.secrets.secret_values();
        let mut redactor = Redactor::new(&options.redactions, &secrets);
        // Number the commands' ids in the order they were sent — this
        // instance's first, then earlier loads' — not in the order the
        // snapshot happens to print them.
        let own: Vec<String> = instance
            .commands
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|r| r.command_id.clone())
            .collect();
        for id in own.iter().chain(&instance.secrets.command_ids()) {
            let _ = redactor.minted_ids(id);
        }
        let _secrets_in_scope = SecretsInScope::new(&secrets, redactor.ids.clone());
        let devices = instance
            .devices()
            .iter()
            .map(|d| {
                let caps: Vec<String> = d.info.capabilities.iter().map(render_spec).collect();
                format!("{} {:?} [{}]", d.id, d.info.name, caps.join(", "))
            })
            .collect();
        let services = instance
            .services()
            .iter()
            .map(|s| {
                let commands: Vec<String> = s
                    .info
                    .commands
                    .iter()
                    .map(|c| {
                        let params: Vec<String> = c.params.iter().map(render_field).collect();
                        format!("{}({})", tok(&c.name), params.join(", "))
                    })
                    .collect();
                format!(
                    "{} {:?} {}",
                    tok(&s.info.local_id),
                    s.info.name,
                    commands.join(", ")
                )
            })
            .collect();
        let events = instance
            .events()?
            .iter()
            .map(|e| {
                format!(
                    "{} {}{}",
                    e.device_id.as_deref().map_or_else(|| "-".to_owned(), tok),
                    render_payload(&e.payload),
                    stamp.at(e.received_ms),
                )
            })
            .collect();
        let view = instance.storage();
        let mut storage = Vec::new();
        for key in view.keys("")? {
            let value = view
                .get(&key)?
                .map_or_else(|| "<removed>".to_owned(), |v| render_value(&v));
            storage.push(format!("{} = {}", tok(&key), masked(&key, value)));
        }
        let blobs = instance
            .blobs()?
            .iter()
            .map(|b| {
                format!(
                    "{} {}B {}",
                    tok(&b.name),
                    b.size_bytes,
                    b.mime.as_deref().map_or_else(|| "-".to_owned(), esc)
                )
            })
            .collect();
        let device_state = options
            .device_state
            .then(|| render_device_state(instance, &stamp));
        let commands = options.commands.then(|| render_commands(instance));
        let audit = if options.audit {
            Some(render_audit(instance)?)
        } else {
            None
        };
        let mut snapshot = Self {
            devices,
            services,
            events,
            storage,
            blobs,
            device_state,
            commands,
            audit,
        };
        redactor.apply(&mut snapshot);
        Ok(snapshot)
    }

    fn sections(&self) -> Vec<(&'static str, &Vec<String>)> {
        let mut sections = vec![
            ("devices", &self.devices),
            ("services", &self.services),
            ("events", &self.events),
            ("storage", &self.storage),
            ("blobs", &self.blobs),
        ];
        for (name, lines) in [
            ("device-state", &self.device_state),
            ("commands", &self.commands),
            ("audit", &self.audit),
        ] {
            if let Some(lines) = lines {
                sections.push((name, lines));
            }
        }
        sections
    }

    fn lines_mut(&mut self) -> impl Iterator<Item = &mut String> {
        [
            &mut self.devices,
            &mut self.services,
            &mut self.events,
            &mut self.storage,
            &mut self.blobs,
        ]
        .into_iter()
        .chain(
            [&mut self.device_state, &mut self.commands, &mut self.audit]
                .into_iter()
                .flatten(),
        )
        .flat_map(|lines| lines.iter_mut())
    }

    /// Panic unless this snapshot renders as `expected`.
    ///
    /// `expected` is compared line by line after normalizing both
    /// sides: leading and trailing blank lines, trailing whitespace,
    /// and indentation common to every non-blank line are ignored, so
    /// it can be an indented raw string literal. The panic message
    /// carries a line diff (`-` expected, `+` actual) and the full
    /// actual text, ready to paste back into the test.
    ///
    /// # Panics
    ///
    /// When the normalized texts differ.
    #[track_caller]
    pub fn assert_matches(&self, expected: &str) {
        let actual = self.to_string();
        let (want, got) = (normalize(expected), normalize(&actual));
        assert!(
            want == got,
            "snapshot mismatch:\n{}\nactual snapshot:\n{}",
            diff(&want, &got),
            got.join("\n"),
        );
    }

    /// Like [`Self::assert_matches`], against the contents of `path`.
    ///
    /// With [`UPDATE_SNAPSHOTS_ENV`] set to anything other than `""`
    /// or `0`, writes the snapshot to `path` instead (creating parent
    /// directories) and passes — review the diff before committing.
    ///
    /// # Panics
    ///
    /// When the file's snapshot differs, or the file can't be read
    /// (including when it doesn't exist yet and the update variable
    /// isn't set) or written.
    #[track_caller]
    pub fn assert_matches_file(&self, path: impl AsRef<Path>) {
        let path = path.as_ref();
        if update_requested() {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).unwrap_or_else(|e| {
                    panic!("creating snapshot directory {}: {e}", parent.display())
                });
            }
            std::fs::write(path, self.to_string())
                .unwrap_or_else(|e| panic!("writing snapshot {}: {e}", path.display()));
            return;
        }
        let expected = std::fs::read_to_string(path).unwrap_or_else(|e| {
            panic!(
                "reading snapshot {}: {e} (set {UPDATE_SNAPSHOTS_ENV}=1 to create it)",
                path.display()
            )
        });
        self.assert_matches(&expected);
    }
}

impl fmt::Display for Snapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (name, lines) in self.sections() {
            writeln!(f, "{name}:")?;
            for line in lines {
                writeln!(f, "  {line}")?;
            }
        }
        Ok(())
    }
}

/// `t` in Unix milliseconds, negative before the epoch.
fn signed_unix_ms(t: std::time::SystemTime) -> i64 {
    let ms = |d: Duration| i64::try_from(d.as_millis()).unwrap_or(i64::MAX);
    match t.duration_since(UNIX_EPOCH) {
        Ok(after) => ms(after),
        Err(before) => -ms(before.duration()),
    }
}

/// Renders host timestamps for [`SnapshotOptions::times`].
enum Stamp {
    Off,
    RealClock,
    /// The virtual clock's start, in Unix ms.
    Since(i64),
}

impl Stamp {
    fn new(clock: &Clock, on: bool) -> Self {
        match (on, clock.as_virtual()) {
            (false, _) => Self::Off,
            (true, None) => Self::RealClock,
            (true, Some(v)) => Self::Since(signed_unix_ms(v.start())),
        }
    }

    /// ` @+S.mmms` for a stamp `ms` (Unix ms), or `""` when times are
    /// off.
    fn at(&self, ms: i64) -> String {
        match *self {
            Self::Off => String::new(),
            Self::RealClock => " @?".to_owned(),
            // Stamps clamp at the epoch: one there can't be placed.
            Self::Since(start) if start < 0 && ms == 0 => " @?".to_owned(),
            Self::Since(start) => {
                let rel = ms.saturating_sub(start);
                let sign = if rel < 0 { '-' } else { '+' };
                let abs = rel.unsigned_abs();
                format!(" @{sign}{}.{:03}s", abs / 1000, abs % 1000)
            }
        }
    }
}

fn render_device_state(instance: &InstanceRef<'_>, stamp: &Stamp) -> Vec<String> {
    // The whole projection: unlike a delta read, it doesn't come back
    // empty once eviction moved the store's watermark.
    let (_, _, all) = instance
        .engine
        .device_state()
        .snapshot_page_with_revision(None, usize::MAX);
    let mut entries: Vec<_> = all
        .into_iter()
        // Both owner fields, as the core state read checks them: a
        // stale row a dropped instance left under the same id belongs
        // to another installation.
        .filter(|e| {
            e.owner_instance == instance.instance_id
                && *e.owner_install == *instance.installation_uuid
        })
        .collect();
    entries.sort_by(|a, b| {
        (a.device_id.as_str(), a.capability.as_str())
            .cmp(&(b.device_id.as_str(), b.capability.as_str()))
    });
    entries
        .iter()
        .map(|e| {
            let stale = if e.quality == StateQuality::Stale {
                " stale"
            } else {
                ""
            };
            format!(
                "{} {} {}{stale}{}",
                tok(&e.device_id),
                tok(&e.capability),
                render_fields(&e.fields),
                stamp.at(e.received_ms),
            )
        })
        .collect()
}

fn render_commands(instance: &InstanceRef<'_>) -> Vec<String> {
    let pending = instance.engine.pending_commands();
    let records = instance
        .commands
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    // A reused id is pending at most for its latest acceptance.
    let latest: HashMap<&str, usize> = records
        .iter()
        .enumerate()
        .filter(|(_, r)| matches!(r.outcome, Some(CommandOutcome::Accepted)))
        .map(|(i, r)| (r.command_id.as_str(), i))
        .collect();
    records
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let head = format!(
                "{} {}.{} ->",
                tok(&r.device),
                tok(&r.capability),
                tok(&r.action),
            );
            let Some(outcome) = &r.outcome else {
                let status = if r.dropped {
                    "(dropped before the reply)"
                } else {
                    "(in flight)"
                };
                return format!("{head} {status}");
            };
            let detail = match outcome {
                CommandOutcome::Accepted
                    if latest.get(r.command_id.as_str()) == Some(&i)
                        && pending.is_pending(&r.command_id) =>
                {
                    " (pending)".to_owned()
                }
                CommandOutcome::Accepted => " (resolved)".to_owned(),
                CommandOutcome::Completed { state: None } => String::new(),
                CommandOutcome::Completed { state: Some(state) } => {
                    format!(" {}", render_fields(state))
                }
                CommandOutcome::Rejected { error } => format!(" {}", render_error(error)),
                CommandOutcome::TimedOut { message } | CommandOutcome::Unknown { message } => {
                    format!(" {}", esc(&mask_text(message)))
                }
            };
            format!("{head} {}{detail}", outcome.as_str())
        })
        .collect()
}

fn render_audit(instance: &InstanceRef<'_>) -> Result<Vec<String>, TestHostError> {
    // Rows the host writes off the call path: refused reads (H2) and
    // command resolutions (H5). A writer that doesn't drain fails the
    // capture rather than return a partial ledger.
    if !instance.engine.drain_state_read_audit(AUDIT_FLUSH) {
        return Err(TestHostError::AuditBacklog {
            writer: "refused-read audit",
        });
    }
    if !instance
        .engine
        .pending_commands()
        .flush_journal(AUDIT_FLUSH)
    {
        return Err(TestHostError::AuditBacklog {
            writer: "command journal",
        });
    }
    let query = AuditQuery {
        token_id: Some(instance.instance_id.to_owned()),
        ..AuditQuery::default()
    };
    // `token_id` also holds API credential ids; keep the plugin's.
    let mut rows = instance
        .engine
        .audit_log()
        .query(&query, AUDIT_ROWS.saturating_add(1))?;
    rows.retain(|r| r.actor_kind == "plugin");
    if rows.len() > AUDIT_ROWS {
        return Err(TestHostError::AuditTooLarge { limit: AUDIT_ROWS });
    }
    rows.sort_by_key(|r| r.id);
    Ok(rows.iter().map(render_audit_row).collect())
}

/// One audit row. Never stamped: a row the host writes in the
/// background takes its time when written, not when the call ran.
fn render_audit_row(row: &AuditEntry) -> String {
    let mut line = format!(
        "{} {} {} {}",
        tok(&row.decision),
        row.status,
        tok(&row.method),
        path_tok(&row.path)
    );
    for (key, value) in [
        ("scope", &row.required_scope),
        ("outcome", &row.execution_outcome),
        ("command", &row.command_outcome),
    ] {
        if let Some(value) = value {
            let _ = write!(line, " {key}={}", tok(value));
        }
    }
    if let Some(error) = &row.domain_error {
        let _ = write!(line, " error={error:?}");
    }
    line
}

fn render_error(error: &WitError) -> String {
    let (kind, message) = match error {
        WitError::NotFound(m) => ("not-found", m),
        WitError::InvalidArgument(m) => ("invalid-argument", m),
        WitError::PermissionDenied(m) => ("permission-denied", m),
        WitError::Unavailable(m) => ("unavailable", m),
        WitError::Internal(m) => ("internal", m),
    };
    format!("{kind}({:?})", mask_text(message).as_ref())
}

/// The redaction pass over a rendered snapshot (see [`Snapshot`],
/// "Stable and redacted").
struct Redactor<'a> {
    replacements: &'a [(String, String)],
    /// Every secret, and its escaped form where escaping changes it
    /// (a snapshot prints strings escaped), longest first.
    secrets: Vec<String>,
    /// Quoted renderings (`"…"`, as [`render_value`] prints a string)
    /// of every secret, longest first.
    quoted: Vec<String>,
    ids: HashMap<String, String>,
    counts: HashMap<&'static str, usize>,
}

/// Host-minted id prefixes replaced by numbered placeholders.
const MINTED_PREFIXES: [&str; 2] = ["cmd-", "call-"];

/// Hex digits after a minted id's prefix.
const MINTED_HEX_LEN: usize = 32;

impl<'a> Redactor<'a> {
    fn new(replacements: &'a [(String, String)], secrets: &[String]) -> Self {
        let raw: Vec<&String> = secrets.iter().filter(|s| !s.is_empty()).collect();
        // `"secret"`, and the same inside an escaped JSON string
        // (`\"secret\"`, as a `json:` value prints it).
        let mut quoted: Vec<String> = raw
            .iter()
            .flat_map(|s| {
                let in_json = format!("\"{}\"", json_escape(s)).escape_debug().to_string();
                [format!("{s:?}"), in_json]
            })
            .collect();
        quoted.sort_by_key(|s| std::cmp::Reverse(s.len()));
        // As printed: raw, escaped, inside an escaped JSON string, and
        // as hex bytes.
        let mut secrets: Vec<String> = raw
            .iter()
            .flat_map(|s| {
                let json = json_escape(s);
                [
                    (*s).clone(),
                    s.escape_debug().to_string(),
                    json.escape_debug().to_string(),
                    json,
                    hex(s.as_bytes()),
                ]
            })
            .chain(raw.iter().flat_map(|s| {
                // A bytes value cut off mid-secret: its shown prefix.
                // Only the bytes a value shows can be cut off.
                let bytes = s.as_bytes();
                (MIN_CUT_SECRET..=bytes.len().saturating_sub(1).min(SHOWN_BYTES))
                    .map(move |n| format!("{}{TRUNCATED}", hex(&bytes[..n])))
            }))
            .collect();
        secrets.sort_by_key(|s| std::cmp::Reverse(s.len()));
        secrets.dedup();
        Self {
            replacements,
            secrets,
            quoted,
            ids: HashMap::new(),
            counts: HashMap::new(),
        }
    }

    fn apply(mut self, snapshot: &mut Snapshot) {
        for line in snapshot.lines_mut() {
            *line = self.line(line);
        }
        // Keys and names can be minted ids: order by what the snapshot
        // prints.
        snapshot.services.sort();
        snapshot.storage.sort();
        snapshot.blobs.sort();
    }

    fn line(&mut self, line: &str) -> String {
        let mut text = line.to_owned();
        for (from, to) in self.replacements {
            text = text.replace(from.as_str(), to);
        }
        // Ids first: a secret that overlaps one must not break it up
        // and leave its random part behind.
        let mut text = self.minted_ids(&text);
        // A string value equal to a secret, however short.
        for quoted in &self.quoted {
            let masked = if quoted.starts_with('\\') {
                "\\\"***\\\""
            } else {
                "\"***\""
            };
            text = text.replace(quoted.as_str(), masked);
        }
        let secrets: Vec<&str> = self.secrets.iter().map(String::as_str).collect();
        let text = oxidhome_core::redact::scrub_secret_values(&text, &secrets).into_owned();
        oxidhome_core::redact::scrub_text(&text).into_owned()
    }

    /// Replace host-minted ids with `<cmd-1>`-style placeholders.
    fn minted_ids(&mut self, text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        let mut rest = text;
        'scan: while !rest.is_empty() {
            for prefix in MINTED_PREFIXES {
                if let Some(id) = minted_id_at(rest, prefix) {
                    let next = self.counts.entry(prefix).or_default();
                    let placeholder = self.ids.entry(id.to_owned()).or_insert_with(|| {
                        *next += 1;
                        format!("<{prefix}{next}>")
                    });
                    out.push_str(placeholder);
                    rest = &rest[id.len()..];
                    continue 'scan;
                }
            }
            let ch = rest.chars().next().expect("non-empty");
            out.push(ch);
            rest = &rest[ch.len_utf8()..];
        }
        out
    }
}

/// How many bytes of a bytes value a snapshot shows.
const SHOWN_BYTES: usize = 32;

/// `text` with structured credentials masked if it is a JSON document
/// that has some, else as is. Plain text is left to the redaction
/// pass, which matches declared secrets first, then credential-like
/// text: masking part of a secret here would stop it matching whole.
fn mask_json_doc(text: &str) -> std::borrow::Cow<'_, str> {
    let changed = match serde_json::from_str::<serde_json::Value>(text) {
        // A JSON string scalar: its decoded text, masked as plain text.
        Ok(serde_json::Value::String(inner)) => {
            mask_plain(&inner).map(|m| serde_json::Value::String(m).to_string())
        }
        Ok(mut doc) if doc.is_object() || doc.is_array() => {
            // Credential-keyed values first (a declared secret may
            // match a key's name), then declared secrets, whole, before
            // the credential text rules could mask part of one. Object
            // keys that are ids the harness sent get their placeholders
            // before the object is re-encoded (and so re-sorted).
            let paired = mask_sensitive_pairs(&mut doc);
            let masked = CAPTURE_SCOPE.with(|s| {
                let scope = s.borrow();
                mask_secret_leaves(&mut doc, &scope.secrets) | rename_id_keys(&mut doc, &scope.ids)
            }) | paired;
            let redacted = oxidhome_core::redact::redact_json(&mut doc);
            (masked || redacted).then(|| doc.to_string())
        }
        _ => None,
    };
    changed.map_or(std::borrow::Cow::Borrowed(text), std::borrow::Cow::Owned)
}

/// Rename object keys that are ids in `ids` to their placeholders.
/// `true` if any was renamed.
fn rename_id_keys(doc: &mut serde_json::Value, ids: &HashMap<String, String>) -> bool {
    match doc {
        serde_json::Value::Object(map) => {
            let mut changed = false;
            for value in map.values_mut() {
                changed |= rename_id_keys(value, ids);
            }
            let known: Vec<String> = map
                .keys()
                .filter(|k| ids.contains_key(*k))
                .cloned()
                .collect();
            for key in known {
                if let Some(value) = map.remove(&key) {
                    map.insert(ids[&key].clone(), value);
                    changed = true;
                }
            }
            changed
        }
        serde_json::Value::Array(items) => items
            .iter_mut()
            .fold(false, |acc, v| rename_id_keys(v, ids) | acc),
        _ => false,
    }
}

/// What the rendering helpers mask with while a snapshot is captured
/// on this thread (see [`SecretsInScope`]).
#[derive(Default)]
struct CaptureScope {
    /// Declared secrets.
    secrets: Vec<String>,
    /// Ids the harness sent, and their placeholders.
    ids: HashMap<String, String>,
}

thread_local! {
    static CAPTURE_SCOPE: std::cell::RefCell<CaptureScope> =
        std::cell::RefCell::new(CaptureScope::default());
}

/// Makes a capture's secrets and seeded ids visible to
/// [`mask_json_doc`] and [`mask_text`] while it lives.
struct SecretsInScope;

impl SecretsInScope {
    fn new(secrets: &[String], ids: HashMap<String, String>) -> Self {
        CAPTURE_SCOPE.with(|s| {
            *s.borrow_mut() = CaptureScope {
                secrets: secrets.to_vec(),
                ids,
            };
        });
        Self
    }
}

impl Drop for SecretsInScope {
    fn drop(&mut self) {
        CAPTURE_SCOPE.with(|s| *s.borrow_mut() = CaptureScope::default());
    }
}

/// Free text as a snapshot prints it, masked before escaping (escaping
/// changes separators the credential rules look for): a JSON document
/// as [`mask_json_doc`]; other text with the declared secrets of the
/// capture replaced, then credential-like text scrubbed.
fn mask_text(text: &str) -> std::borrow::Cow<'_, str> {
    let json = mask_json_doc(text);
    if matches!(json, std::borrow::Cow::Owned(_)) {
        return json;
    }
    mask_plain(text).map_or(std::borrow::Cow::Borrowed(text), std::borrow::Cow::Owned)
}

/// Plain `text` with the capture's declared secrets replaced, then
/// credential-like text scrubbed; `None` if nothing changed.
fn mask_plain(text: &str) -> Option<String> {
    let mut out = text.to_owned();
    CAPTURE_SCOPE.with(|s| {
        for secret in s.borrow().secrets.iter().filter(|s| !s.is_empty()) {
            out = out.replace(secret.as_str(), "***");
        }
    });
    let scrubbed = oxidhome_core::redact::scrub_text(&out).into_owned();
    (scrubbed != text).then_some(scrubbed)
}

/// Mask the values the core JSON redactor would, by key, before
/// anything rewrites the keys: an object entry under a credential-like
/// key, and a `{"key": <credential-like>, "value": …}` pair. `true` if
/// anything changed.
fn mask_sensitive_pairs(doc: &mut serde_json::Value) -> bool {
    use oxidhome_core::redact::is_sensitive_key;
    let masked = serde_json::Value::String(oxidhome_core::redact::REDACTED.to_owned());
    match doc {
        serde_json::Value::Object(map) => {
            let mut changed = false;
            let pair_key = map
                .get("key")
                .and_then(serde_json::Value::as_str)
                .is_some_and(is_sensitive_key);
            for (key, value) in map.iter_mut() {
                let sensitive = is_sensitive_key(key) || (pair_key && key == "value");
                if sensitive && (value.is_string() || value.is_number()) {
                    *value = masked.clone();
                    changed = true;
                } else {
                    changed |= mask_sensitive_pairs(value);
                }
            }
            changed
        }
        serde_json::Value::Array(items) => items
            .iter_mut()
            .fold(false, |acc, v| mask_sensitive_pairs(v) | acc),
        _ => false,
    }
}

/// Replace every string leaf of `doc` containing a declared secret
/// with `"***"`. `true` if anything changed.
fn mask_secret_leaves(doc: &mut serde_json::Value, secrets: &[String]) -> bool {
    match doc {
        serde_json::Value::String(s)
            if secrets
                .iter()
                .any(|secret| !secret.is_empty() && s.contains(secret.as_str())) =>
        {
            "***".clone_into(s);
            true
        }
        serde_json::Value::Array(items) => items
            .iter_mut()
            .fold(false, |acc, v| mask_secret_leaves(v, secrets) | acc),
        serde_json::Value::Object(map) => map
            .values_mut()
            .fold(false, |acc, v| mask_secret_leaves(v, secrets) | acc),
        _ => false,
    }
}

/// Marks a bytes value cut off after its first bytes.
const TRUNCATED: char = '…';

/// Shortest secret prefix masked where a bytes value is cut off.
const MIN_CUT_SECRET: usize = 4;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

/// `text` escaped as inside a JSON string.
fn json_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if u32::from(c) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out
}

/// The minted id `prefix` + 32 lowercase hex digits at the start of
/// `text`, unless more hex digits follow.
fn minted_id_at<'t>(text: &'t str, prefix: &str) -> Option<&'t str> {
    let hex = text.strip_prefix(prefix)?;
    let is_hex = |b: &u8| b.is_ascii_digit() || (b'a'..=b'f').contains(b);
    let bytes = hex.as_bytes();
    if bytes.len() < MINTED_HEX_LEN || !bytes[..MINTED_HEX_LEN].iter().all(is_hex) {
        return None;
    }
    if bytes.get(MINTED_HEX_LEN).is_some_and(is_hex) {
        return None;
    }
    Some(&text[..prefix.len() + MINTED_HEX_LEN])
}

/// Whether [`UPDATE_SNAPSHOTS_ENV`] asks for snapshot files to be
/// rewritten.
fn update_requested() -> bool {
    std::env::var_os(UPDATE_SNAPSHOTS_ENV).is_some_and(|v| !v.is_empty() && v != "0")
}

/// A WIT value as compact text: bare bools and numbers, quoted
/// strings, hex bytes (abbreviated past 32), `json:` + the JSON text
/// quoted.
#[must_use]
pub fn render_value(value: &Value) -> String {
    match value {
        Value::BoolVal(b) => b.to_string(),
        Value::IntVal(n) => n.to_string(),
        Value::FloatVal(x) => format!("{x:?}"),
        // A string may hold a JSON document: its structured
        // credentials are masked as the API masks them.
        Value::StringVal(s) => format!("{:?}", mask_text(s)),
        Value::BytesVal(bytes) => {
            let mut out = String::from("0x");
            for b in bytes.iter().take(SHOWN_BYTES) {
                let _ = write!(out, "{b:02x}");
            }
            if bytes.len() > SHOWN_BYTES {
                let _ = write!(out, "{TRUNCATED}({} bytes)", bytes.len());
            }
            out
        }
        // Structured credentials (`{"password": …}`, a `key-value`
        // whose key is credential-like) are masked as the API masks
        // them; other JSON prints as stored.
        Value::JsonVal(json) => format!("json:{:?}", mask_json_doc(json)),
    }
}

/// A name in a delimited position (key, id, topic, …): bare when it
/// is a plain word (letters, digits, `_-.:`), otherwise quoted and
/// escaped like a Rust string, so no name can imitate the separators
/// around it and every item stays on one line.
fn tok(text: &str) -> String {
    tok_allowing(text, "")
}

/// [`tok`] for a `/`-separated path (an audit row's).
fn path_tok(text: &str) -> String {
    tok_allowing(text, "/")
}

fn tok_allowing(text: &str, extra: &str) -> String {
    let plain = !text.is_empty()
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_-.:".contains(c) || extra.contains(c));
    if plain {
        text.to_owned()
    } else {
        format!("{text:?}")
    }
}

/// `value` (rendered), or `"***"` under a credential-like `key`
/// whatever its type — the text scrubber can't tell a JSON or bytes
/// rendering's value apart from its type tag.
fn masked(key: &str, value: String) -> String {
    if oxidhome_core::redact::is_sensitive_key(key) {
        "\"***\"".to_owned()
    } else {
        value
    }
}

/// Trailing free text (an event payload, a blob mime type): escaped
/// onto one line.
fn esc(text: &str) -> String {
    text.escape_debug().to_string()
}

fn render_fields(fields: &[KeyValue]) -> String {
    let parts: Vec<String> = fields
        .iter()
        .map(|kv| {
            format!(
                "{}={}",
                tok(&kv.key),
                masked(&kv.key, render_value(&kv.value))
            )
        })
        .collect();
    format!("{{{}}}", parts.join(", "))
}

fn render_payload(payload: &EventPayload) -> String {
    match payload {
        EventPayload::StateChanged(sc) => {
            format!(
                "state-changed {} {}",
                tok(&sc.capability),
                render_fields(&sc.fields)
            )
        }
        EventPayload::Button(b) => format!("button {}", render_button(b)),
        // Structured credentials masked as the API masks them.
        EventPayload::Inference(r) => format!(
            "inference {} {}",
            tok(&r.model),
            esc(&mask_text(&r.payload))
        ),
        EventPayload::Custom(c) => {
            format!("custom {} {}", tok(&c.topic), esc(&mask_text(&c.payload)))
        }
    }
}

fn render_button(event: &ButtonEvent) -> String {
    match event {
        ButtonEvent::Pressed => "pressed".to_owned(),
        ButtonEvent::Released => "released".to_owned(),
        ButtonEvent::SinglePress => "single-press".to_owned(),
        ButtonEvent::DoublePress => "double-press".to_owned(),
        ButtonEvent::LongPress => "long-press".to_owned(),
        ButtonEvent::Rotated(by) => format!("rotated({by:?})"),
    }
}

fn render_spec(spec: &CapabilitySpec) -> String {
    match spec {
        CapabilitySpec::Switch => "switch".to_owned(),
        CapabilitySpec::Dimmer => "dimmer".to_owned(),
        CapabilitySpec::ColorLight(_) => "color-light".to_owned(),
        CapabilitySpec::Sensor(_) => "sensor".to_owned(),
        CapabilitySpec::Button => "button".to_owned(),
        CapabilitySpec::VideoStream => "video-stream".to_owned(),
        CapabilitySpec::AudioStream => "audio-stream".to_owned(),
        CapabilitySpec::Lock => "lock".to_owned(),
        CapabilitySpec::Opener(_) => "opener".to_owned(),
        CapabilitySpec::AlarmPanel(_) => "alarm-panel".to_owned(),
        CapabilitySpec::Siren => "siren".to_owned(),
        CapabilitySpec::Extension(ext) => {
            format!(
                "extension({}/{}@{})",
                tok(&ext.namespace),
                tok(&ext.name),
                ext.version
            )
        }
    }
}

fn render_field(field: &FieldSpec) -> String {
    let kind = match field.kind {
        ValueKind::BoolVal => "bool",
        ValueKind::IntVal => "int",
        ValueKind::FloatVal => "float",
        ValueKind::StringVal => "string",
        ValueKind::BytesVal => "bytes",
        ValueKind::JsonVal => "json",
    };
    let optional = if field.required { "" } else { "?" };
    format!("{}{optional}: {kind}", tok(&field.name))
}

/// Lines of `text` with trailing whitespace, surrounding blank lines,
/// and common indentation removed.
fn normalize(text: &str) -> Vec<String> {
    let lines: Vec<&str> = text.lines().map(str::trim_end).collect();
    let start = lines
        .iter()
        .position(|l| !l.is_empty())
        .unwrap_or(lines.len());
    let end = lines
        .iter()
        .rposition(|l| !l.is_empty())
        .map_or(start, |i| i + 1);
    let lines = &lines[start..end];
    let indent = lines
        .iter()
        .filter(|l| !l.is_empty())
        .map(|l| l.len() - l.trim_start().len())
        .min()
        .unwrap_or(0);
    lines
        .iter()
        .map(|l| l.get(indent..).unwrap_or_default().to_owned())
        .collect()
}

/// Largest LCS table (cells) [`diff`] builds; past it the differing
/// middle is shown as a plain remove-all / add-all.
const MAX_DIFF_CELLS: usize = 1 << 20;

/// A minimal line diff: unchanged lines prefixed with two spaces,
/// removed with `- `, added with `+ `. The common prefix and suffix
/// are matched directly; the middle by longest common subsequence
/// while that stays under [`MAX_DIFF_CELLS`].
fn diff(want: &[String], got: &[String]) -> String {
    let prefix = want.iter().zip(got).take_while(|(a, b)| a == b).count();
    let suffix = want[prefix..]
        .iter()
        .rev()
        .zip(got[prefix..].iter().rev())
        .take_while(|(a, b)| a == b)
        .count();
    let (want_mid, got_mid) = (
        &want[prefix..want.len() - suffix],
        &got[prefix..got.len() - suffix],
    );
    let mut out = String::new();
    for line in &want[..prefix] {
        let _ = writeln!(out, "  {line}");
    }
    let (n, m) = (want_mid.len(), got_mid.len());
    if (n + 1).saturating_mul(m + 1) > MAX_DIFF_CELLS {
        for line in want_mid {
            let _ = writeln!(out, "- {line}");
        }
        for line in got_mid {
            let _ = writeln!(out, "+ {line}");
        }
    } else {
        lcs_diff(want_mid, got_mid, &mut out);
    }
    for line in &want[want.len() - suffix..] {
        let _ = writeln!(out, "  {line}");
    }
    out
}

fn lcs_diff(want: &[String], got: &[String], out: &mut String) {
    let (n, m) = (want.len(), got.len());
    // lcs[i][j] = LCS length of want[i..] and got[j..].
    let mut lcs = vec![vec![0_usize; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            lcs[i][j] = if want[i] == got[j] {
                lcs[i + 1][j + 1] + 1
            } else {
                lcs[i + 1][j].max(lcs[i][j + 1])
            };
        }
    }
    let (mut i, mut j) = (0, 0);
    while i < n || j < m {
        if i < n && j < m && want[i] == got[j] {
            let _ = writeln!(out, "  {}", want[i]);
            i += 1;
            j += 1;
        } else if j < m && (i == n || lcs[i][j + 1] >= lcs[i + 1][j]) {
            let _ = writeln!(out, "+ {}", got[j]);
            j += 1;
        } else {
            let _ = writeln!(out, "- {}", want[i]);
            i += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Snapshot {
        Snapshot {
            devices: vec!["dev-1 \"Lamp\" [switch]".into()],
            services: Vec::new(),
            events: vec!["dev-1 state-changed switch {state=true}".into()],
            storage: vec!["count = 3".into()],
            blobs: Vec::new(),
            device_state: None,
            commands: None,
            audit: None,
        }
    }

    #[test]
    fn optional_sections_render_after_the_default_ones() {
        let mut snap = sample();
        snap.commands = Some(vec!["dev-1 switch.toggle -> completed".into()]);
        snap.audit = Some(Vec::new());
        assert_eq!(
            snap.to_string(),
            "devices:\n  dev-1 \"Lamp\" [switch]\nservices:\nevents:\n  \
             dev-1 state-changed switch {state=true}\nstorage:\n  count = 3\nblobs:\n\
             commands:\n  dev-1 switch.toggle -> completed\naudit:\n"
        );
    }

    #[test]
    fn redaction_masks_secrets_and_numbers_minted_ids() {
        let secrets = vec![
            "hunter2-long".to_owned(),
            "pw".to_owned(),
            "quo\"te-secret".to_owned(),
        ];
        let extra = vec![("instance-7".to_owned(), "<inst>".to_owned())];
        let mut snap = sample();
        let cmd_a = format!("cmd-{}", "ab".repeat(16));
        let cmd_b = format!("cmd-{}", "01".repeat(16));
        let call = format!("call-{}", "9f".repeat(16));
        snap.storage = vec![
            "short = \"pw\"".into(),
            "note = \"the key is hunter2-long!\"".into(),
            "creds = \"password=abc\"".into(),
            "who = \"instance-7\"".into(),
            "esc = \"a quo\\\"te-secret inside\"".into(),
        ];
        snap.audit = Some(vec![
            format!("allow 200 COMMAND {cmd_a} {call}"),
            format!("allow 200 COMMAND {cmd_b} {cmd_a}"),
            // Not a minted id: too short, or followed by more hex.
            format!("cmd-test cmd-{}0", "ab".repeat(16)),
        ]);
        Redactor::new(&extra, &secrets).apply(&mut snap);
        assert_eq!(
            snap.storage,
            // Sorted as printed.
            [
                "creds = \"password=***\"",
                "esc = \"a *** inside\"",
                "note = \"the key is ***!\"",
                "short = \"***\"",
                "who = \"<inst>\"",
            ]
        );
        assert_eq!(masked("password", "json:\"x\"".into()), "\"***\"");
        assert_eq!(masked("count", "3".into()), "3");
        assert_eq!(
            snap.audit.unwrap(),
            [
                "allow 200 COMMAND <cmd-1> <call-1>",
                "allow 200 COMMAND <cmd-2> <cmd-1>",
                &format!("cmd-test cmd-{}0", "ab".repeat(16)),
            ]
        );
        // A seeded id keeps its number wherever it shows up first.
        let mut snap = sample();
        snap.storage = vec![format!("{cmd_a} = 1"), format!("{cmd_b} = 2")];
        let mut redactor = Redactor::new(&[], &[]);
        let _ = redactor.minted_ids(&cmd_b);
        redactor.apply(&mut snap);
        assert_eq!(snap.storage, ["<cmd-1> = 2", "<cmd-2> = 1"]);
        assert_eq!(minted_id_at("cmd-", "cmd-"), None);
        assert_eq!(
            minted_id_at(&format!("cmd-{}", "AB".repeat(16)), "cmd-"),
            None
        );
    }

    #[test]
    fn encoded_secrets_are_masked() {
        // Under neutral keys: a secret inside a JSON value, and as bytes.
        let mut snap = sample();
        snap.storage = vec![
            format!(
                "doc = {}",
                render_value(&Value::JsonVal("{\"k\": \"p\\\"ass-word\"}".into()))
            ),
            format!(
                "raw = {}",
                render_value(&Value::BytesVal(b"hunter2-long".to_vec()))
            ),
        ];
        Redactor::new(&[], &["p\"ass-word".to_owned(), "hunter2-long".to_owned()]).apply(&mut snap);
        assert_eq!(
            snap.storage,
            ["doc = json:\"{\\\"k\\\": \\\"***\\\"}\"", "raw = 0x***"]
        );
        assert_eq!(json_escape("a\"b\\c\n\u{1}"), "a\\\"b\\\\c\\n\\u0001");
        // A bytes value cut off mid-secret.
        let long = "s".repeat(30) + "ecret!";
        let mut snap = sample();
        snap.storage = vec![format!(
            "raw = {}",
            render_value(&Value::BytesVal([b"ab", long.as_bytes()].concat()))
        )];
        Redactor::new(&[], &[long]).apply(&mut snap);
        assert_eq!(snap.storage, ["raw = 0x6162***(38 bytes)"]);
        // A long secret at offset zero, cut at exactly the shown bytes.
        let long = "k".repeat(40);
        let mut snap = sample();
        snap.storage = vec![format!(
            "raw = {}",
            render_value(&Value::BytesVal(long.as_bytes().to_vec()))
        )];
        Redactor::new(&[], &[long]).apply(&mut snap);
        assert_eq!(snap.storage, ["raw = 0x***(40 bytes)"]);
        // A short secret as a whole JSON string; JSON in a string value.
        let mut snap = sample();
        snap.storage = vec![
            format!(
                "doc = {}",
                render_value(&Value::JsonVal(r#"{"note":"pw"}"#.into()))
            ),
            format!(
                "text = {}",
                render_value(&Value::StringVal(
                    r#"{"key":"password","value":"fixture-value"}"#.into()
                ))
            ),
        ];
        Redactor::new(&[], &["pw".to_owned()]).apply(&mut snap);
        assert_eq!(snap.storage[0], r#"doc = json:"{\"note\":\"***\"}""#);
        assert!(
            !snap.storage[1].contains("fixture-value"),
            "{:?}",
            snap.storage
        );
        // Structured credentials in JSON, as the API masks them.
        assert_eq!(
            render_value(&Value::JsonVal(
                "{\"key\":\"password\",\"value\":\"hunter2\"}".into()
            )),
            format!(
                "json:{:?}",
                format!(
                    "{{\"key\":\"password\",\"value\":\"{}\"}}",
                    oxidhome_core::redact::REDACTED
                )
            )
        );
    }

    #[test]
    fn declared_secrets_match_before_credential_scrubbing() {
        let url = "https://alice:letmein@hub.example/?api_key=abc123";
        let secrets = [url.to_owned()];
        let _scope = SecretsInScope::new(&secrets, HashMap::new());
        let mut snap = sample();
        snap.storage = vec![
            format!("conn = {}", render_value(&Value::StringVal(url.into()))),
            format!(
                "doc = {}",
                render_value(&Value::JsonVal(format!(r#"{{"url":"{url}"}}"#)))
            ),
        ];
        Redactor::new(&[], &secrets).apply(&mut snap);
        assert_eq!(
            snap.storage,
            ["conn = \"***\"", r#"doc = json:"{\"url\":\"***\"}""#]
        );
    }

    #[test]
    fn secrets_named_like_keys_and_tab_separated_tokens() {
        let secrets = ["pass".to_owned()];
        let _scope = SecretsInScope::new(&secrets, HashMap::new());
        let doc = render_value(&Value::JsonVal(
            r#"{"key":"password","value":"hunter2"}"#.into(),
        ));
        assert!(!doc.contains("hunter2"), "{doc}");
        let note = render_value(&Value::StringVal("Bearer\tabcdef123456".into()));
        assert!(!note.contains("abcdef123456"), "{note}");
        // As a typed (JSON string) value too.
        let typed = render_value(&Value::JsonVal(r#""Bearer\tabcdef123456""#.into()));
        assert!(!typed.contains("abcdef123456"), "{typed}");
    }

    #[test]
    fn json_keys_take_seeded_placeholders() {
        let (a, b) = (
            format!("cmd-{}", "f".repeat(32)),
            format!("cmd-{}", "0".repeat(32)),
        );
        let ids = HashMap::from([
            (a.clone(), "<cmd-1>".to_owned()),
            (b.clone(), "<cmd-2>".to_owned()),
        ]);
        let _scope = SecretsInScope::new(&[], ids);
        let doc = render_value(&Value::JsonVal(format!(r#"{{"{b}":2,"{a}":1}}"#)));
        assert_eq!(doc, r#"json:"{\"<cmd-1>\":1,\"<cmd-2>\":2}""#);
    }

    #[test]
    fn ids_and_errors_survive_secret_overlap() {
        // A secret overlapping a minted id leaves no part of the id.
        let mut snap = sample();
        let call = format!("call-{}", "9f".repeat(16));
        snap.storage = vec![format!("k = {call:?}")];
        Redactor::new(&[], &["call".to_owned()]).apply(&mut snap);
        // (The placeholder's name may be masked; the random part is gone.)
        assert_eq!(snap.storage, ["k = \"<***-1>\""]);
        // Structured credentials in a refusal's message are masked.
        let text = render_error(&WitError::InvalidArgument(
            r#"{"key":"password","value":"fixture-password"}"#.into(),
        ));
        assert!(!text.contains("fixture-password"), "{text}");
    }

    #[test]
    fn options_and_stamps() {
        let opts = SnapshotOptions::all()
            .times()
            .redact("", "x")
            .redact("a", "b");
        assert!(opts.device_state && opts.commands && opts.audit && opts.times);
        assert_eq!(opts.redactions, [("a".to_owned(), "b".to_owned())]);
        assert!(!SnapshotOptions::new().device_state);

        assert_eq!(Stamp::new(&Clock::system(), false).at(5), "");
        assert_eq!(Stamp::new(&Clock::system(), true).at(5), " @?");
        let clock = Clock::from(oxidhome_core::VirtualClock::starting_at(
            UNIX_EPOCH + Duration::from_secs(10),
        ));
        let stamp = Stamp::new(&clock, true);
        assert_eq!(stamp.at(11_500), " @+1.500s");
        assert_eq!(stamp.at(10_000), " @+0.000s");
        assert_eq!(stamp.at(9_000), " @-1.000s");
        // Before the epoch, stamps clamped to it can't be placed.
        let early = Clock::from(oxidhome_core::VirtualClock::starting_at(
            UNIX_EPOCH - Duration::from_secs(1),
        ));
        let stamp = Stamp::new(&early, true);
        assert_eq!(stamp.at(1_000), " @+2.000s");
        assert_eq!(stamp.at(0), " @?");
    }

    #[test]
    fn audit_rows_and_errors_render() {
        let row = AuditEntry {
            id: 4,
            intent_ms: 0,
            finalized_ms: None,
            token_id: "inst".into(),
            actor_kind: "plugin".into(),
            method: "STATE".into(),
            path: "device.state/inst/dev-1".into(),
            status: 403,
            decision: "deny".into(),
            required_scope: Some("reads_state".into()),
            execution_outcome: Some("failed".into()),
            domain_error: Some("not found".into()),
            credential_fp: None,
            call_id: None,
            invocation: None,
            command_id: None,
            command_outcome: Some("rejected".into()),
        };
        assert_eq!(
            render_audit_row(&row),
            "deny 403 STATE device.state/inst/dev-1 scope=reads_state outcome=failed \
             command=rejected error=\"not found\""
        );
        for (error, text) in [
            (WitError::NotFound("a".into()), "not-found(\"a\")"),
            (
                WitError::InvalidArgument("b".into()),
                "invalid-argument(\"b\")",
            ),
            (
                WitError::PermissionDenied("c".into()),
                "permission-denied(\"c\")",
            ),
            (WitError::Unavailable("d".into()), "unavailable(\"d\")"),
            (WitError::Internal("e".into()), "internal(\"e\")"),
        ] {
            assert_eq!(render_error(&error), text);
        }
    }

    #[test]
    fn renders_every_section_in_order() {
        assert_eq!(
            sample().to_string(),
            "devices:\n  dev-1 \"Lamp\" [switch]\nservices:\nevents:\n  \
             dev-1 state-changed switch {state=true}\nstorage:\n  count = 3\nblobs:\n"
        );
    }

    #[test]
    fn matches_ignore_indentation_and_blank_edges() {
        sample().assert_matches(
            "
            devices:
              dev-1 \"Lamp\" [switch]
            services:
            events:
              dev-1 state-changed switch {state=true}
            storage:
              count = 3
            blobs:
            ",
        );
    }

    #[test]
    fn mismatch_reports_a_line_diff() {
        let err = std::panic::catch_unwind(|| {
            sample().assert_matches("devices:\nservices:\nevents:\nstorage:\n  count = 4\nblobs:");
        })
        .expect_err("must not match");
        let msg = err.downcast_ref::<String>().expect("string panic");
        assert!(msg.contains("+   dev-1 \"Lamp\" [switch]"), "{msg}");
        assert!(msg.contains("-   count = 4"), "{msg}");
        assert!(msg.contains("+   count = 3"), "{msg}");
        assert!(msg.contains("  events:"), "{msg}");
    }

    #[test]
    fn names_cannot_imitate_separators() {
        assert_eq!(tok("count"), "count");
        assert_eq!(tok("automation.morning"), "automation.morning");
        assert_eq!(tok("a/b@1"), "\"a/b@1\"");
        assert_eq!(tok(""), "\"\"");
        assert_eq!(tok("a = 1\n  b"), "\"a = 1\\n  b\"");
        let kv = |k: &str, v: bool| KeyValue {
            key: k.into(),
            value: Value::BoolVal(v),
        };
        assert_ne!(
            render_fields(&[kv("a", true), kv("b", false)]),
            render_fields(&[kv("a=true, b", false)])
        );
        assert_eq!(
            render_fields(&[kv("a=true, b", false)]),
            "{\"a=true, b\"=false}"
        );
        assert_eq!(
            render_value(&Value::JsonVal("{\"a\": 1}, b=2".into())),
            "json:\"{\\\"a\\\": 1}, b=2\""
        );
        assert_eq!(
            render_payload(&EventPayload::Custom(crate::wit::events::CustomEvent {
                topic: "t x".into(),
                payload: "{\"k\":\n1}".into(),
            })),
            "custom \"t x\" {\\\"k\\\":\\n1}"
        );
    }

    #[test]
    fn values_render_compactly() {
        assert_eq!(render_value(&Value::BoolVal(true)), "true");
        assert_eq!(render_value(&Value::IntVal(-2)), "-2");
        assert_eq!(render_value(&Value::FloatVal(1.0)), "1.0");
        assert_eq!(render_value(&Value::StringVal("a\"b".into())), "\"a\\\"b\"");
        assert_eq!(render_value(&Value::BytesVal(vec![0, 255])), "0x00ff");
        assert_eq!(
            render_value(&Value::BytesVal(vec![1; 33])),
            format!("0x{}…(33 bytes)", "01".repeat(32))
        );
        assert_eq!(render_value(&Value::JsonVal("{}".into())), "json:\"{}\"");
    }

    #[test]
    fn command_slots_keep_send_order() {
        let commands = Mutex::default();
        let host = HostRecords::default();
        let first = CommandSlot::reserve(&commands, &host, "d".into(), "c".into(), "a".into());
        let second = CommandSlot::reserve(&commands, &host, "d".into(), "c".into(), "b".into());
        second.reply("cmd-2", CommandOutcome::Accepted);
        drop(first);
        let list = commands.lock().unwrap();
        assert_eq!(list[0].action, "a");
        assert!(list[0].dropped && list[0].outcome.is_none());
        assert_eq!(list[1].command_id, "cmd-2");
        assert!(!list[1].dropped);
        assert_eq!(host.command_ids(), ["", "cmd-2"]);
    }

    #[test]
    fn payloads_and_specs_render() {
        use crate::wit::capabilities::{ExtensionSpec, SensorSpec, Unit};
        use crate::wit::events::{CustomEvent, InferenceResult};
        assert_eq!(
            render_payload(&EventPayload::Button(ButtonEvent::Rotated(0.5))),
            "button rotated(0.5)"
        );
        for (b, s) in [
            (ButtonEvent::Pressed, "pressed"),
            (ButtonEvent::Released, "released"),
            (ButtonEvent::SinglePress, "single-press"),
            (ButtonEvent::DoublePress, "double-press"),
            (ButtonEvent::LongPress, "long-press"),
        ] {
            assert_eq!(render_button(&b), s);
        }
        assert_eq!(
            render_payload(&EventPayload::Custom(CustomEvent {
                topic: "t".into(),
                payload: "{}".into()
            })),
            "custom t {}"
        );
        assert_eq!(
            render_payload(&EventPayload::Inference(InferenceResult {
                model: "m".into(),
                payload: "[]".into(),
                frame_timestamp: Some(1),
            })),
            "inference m []"
        );
        // Structured credentials in a payload are masked.
        let masked = render_payload(&EventPayload::Custom(CustomEvent {
            topic: "t".into(),
            payload: r#"{"key":"password","value":"fixture-value"}"#.into(),
        }));
        assert!(!masked.contains("fixture-value"), "{masked}");
        let masked = render_payload(&EventPayload::Inference(InferenceResult {
            model: "m".into(),
            payload: r#"{"token":"fixture-value"}"#.into(),
            frame_timestamp: None,
        }));
        assert!(!masked.contains("fixture-value"), "{masked}");
        assert_eq!(
            render_spec(&CapabilitySpec::Extension(ExtensionSpec {
                namespace: "acme".into(),
                name: "fan".into(),
                version: 2,
            })),
            "extension(acme/fan@2)"
        );
        assert_eq!(
            render_spec(&CapabilitySpec::Sensor(SensorSpec {
                unit: Unit::Celsius,
                min: None,
                max: None,
            })),
            "sensor"
        );
    }

    #[test]
    fn large_diffs_fall_back_to_remove_and_add() {
        let lines = |tag: &str| -> Vec<String> { (0..2000).map(|i| format!("{tag}{i}")).collect() };
        let mut want = vec!["head".to_owned()];
        want.extend(lines("a"));
        want.push("tail".to_owned());
        let mut got = vec!["head".to_owned()];
        got.extend(lines("b"));
        got.push("tail".to_owned());
        let out = diff(&want, &got);
        assert!(out.starts_with("  head\n- a0\n"), "{}", &out[..40]);
        assert!(out.ends_with("+ b1999\n  tail\n"));
        assert_eq!(out.lines().count(), 4002);
        // Small middles still get a real LCS diff.
        let small = diff(
            &["x".into(), "a".into(), "y".into()],
            &["x".into(), "b".into(), "a".into(), "y".into()],
        );
        assert_eq!(small, "  x\n+ b\n  a\n  y\n");
    }

    #[test]
    fn update_env_writes_then_compares() {
        // Only the read path here: setting the variable would race
        // other tests in this binary.
        let dir = crate::tempdir::TempDir::new().expect("tempdir");
        let path = dir.path().join("snap.txt");
        std::fs::write(&path, sample().to_string()).expect("write");
        sample().assert_matches_file(&path);
        // In update mode a missing file is created instead.
        if !update_requested() {
            let missing =
                std::panic::catch_unwind(|| sample().assert_matches_file(dir.path().join("none")));
            assert!(missing.is_err());
        }
    }
}
