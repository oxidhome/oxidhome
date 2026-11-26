//! H2: the `host-state` import — plugin read access to the host-owned
//! device-state projection.
//!
//! A plugin always sees the entries its own instance wrote, as written.
//! Any other entry is a [`crate::auth::Resource::State`] the engine
//! decides on ([`crate::auth::authorize_plugin`], H6 slice 5):
//! `state.read` needs a `[[capabilities.reads_state]]` grant matching
//! its owner plugin, capability and device ([`StateGrant::matches`];
//! the effective grant is requested ∩ granted, see
//! `state::effective_capabilities`), no deny list on the chain may
//! refuse it, and when the read is part of an invocation rooted at a
//! token, the token needs `device.read` on the device. `bytes-val`
//! fields are replaced by a withheld marker unless `blob.read` is
//! allowed the same way (a matching grant with `bytes = true`, for
//! camera bytes one with `sensitive = ["camera"]` too, and the
//! root's `blob.read`; an allow that carries a sensitive obligation,
//! camera bytes, withholds them too: a plugin read can't meet it).
//! `get-state` answers `not-found` both for an unknown device and for
//! one with no entry this plugin may see, so a plugin can't probe which
//! device ids exist; the second case also writes an audit `deny` row
//! (`method = STATE`, `required_scope` the refusal's label, e.g.
//! `reads_state`) in the background, for the operator. Allowed reads
//! are traced, not audited: reads change nothing and would dominate
//! the ledger.

use std::sync::Arc;

use oxidhome_manifest::StateGrant;

use super::state::PluginState;
use crate::auth::invocation::{self, InvocationContext};
use crate::auth::{Action, DeviceClass, PluginPrincipal, Resource, authorize_plugin};
use crate::host_impl::plugin::oxidhome::plugin::host_state::{
    self, DeviceState as WitDeviceState, StateFilter, StatePage, StateQuality as WitQuality,
};
use crate::host_impl::plugin::oxidhome::plugin::types::{DeviceId, Error as WitError, Value};
use crate::state::{AuditEntry, DeviceState, StateQuality};

/// Default and maximum devices per `list-state` page.
const DEFAULT_LIST_LIMIT: usize = 64;
const MAX_LIST_LIMIT: usize = 256;
/// Byte budget per `list-state` page (same as the REST snapshot).
const MAX_LIST_PAGE_BYTES: usize = 1024 * 1024;
/// Entries one `list-state` call looks at before it returns a partial
/// page, bounding how long it holds the store lock under a sparse
/// filter or grant.
const LIST_SCAN_BUDGET: usize = 4096;
/// Scans read again when devices change during one, before giving up.
const SNAPSHOT_TRIES: usize = 3;
/// Deny rows queued for the audit worker, process-wide. Past the
/// limit a refusal is dropped (the worker traces how many).
const DENY_AUDIT_QUEUE: usize = 64;
/// Longest device id `get-state` / a `list-state` filter accepts.
/// Host-minted ids are 20 bytes; this only stops a guest from making
/// the host copy a huge string under the store lock.
const MAX_DEVICE_ID_LEN: usize = 256;
/// Audit `method` for state reads.
pub(crate) const STATE_READ_AUDIT_METHOD: &str = "STATE";
/// Audit `method` for event-history reads (`host-events::read-events`).
pub(crate) const EVENT_READ_AUDIT_METHOD: &str = "EVENTS";
/// Audit `method` for refused network access of a `streaming-plugin`
/// instance (Phase 8): connects, sends, binds, lookups, HTTP requests.
pub(crate) const NETWORK_AUDIT_METHOD: &str = "NET";

/// What a plugin may see of one entry.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Visibility {
    /// Visible, `bytes-val` withheld.
    Withheld,
    Full,
}

/// Own entries are the ones this instance wrote *as this
/// installation*: an instance id reused by another plugin, or by a
/// reinstall of the same plugin, doesn't inherit the stale entries its
/// predecessor left behind. Script sandboxes (ADR-0001,
/// `<parent>~<local-id>`) are distinct instances: a sandbox and its
/// parent don't see each other's entries as their own. They share the
/// installation's `reads_state` grants, so a grant naming the plugin's
/// own id lets them read each other.
fn is_own(instance_id: &str, installation_uuid: &str, entry: &DeviceState) -> bool {
    entry.owner_instance == instance_id && entry.owner_install == installation_uuid
}

/// The cheap first pass of a `list-state` scan, run under the store
/// lock: own entries, and entries some `reads_state` grant covers. A
/// superset of what [`visibility`] lets through.
fn maybe_visible(
    instance_id: &str,
    installation_uuid: &str,
    grants: &[StateGrant],
    entry: &DeviceState,
) -> bool {
    is_own(instance_id, installation_uuid, entry)
        || grants
            .iter()
            .any(|g| g.matches(&entry.owner_plugin, &entry.device_id, &entry.capability))
}

/// A `list-state` entry's [`Visibility`] for `plugin`, or `None` when
/// it is left out; decided from `classes` (no registry lock), so it
/// runs under the store's lock. Without `bytes`, only whether it is
/// left out is decided (`Withheld` stands for any visibility).
fn decide(
    ctx: &InvocationContext,
    plugin: &PluginPrincipal<'_>,
    installation_uuid: &str,
    grants: &oxidhome_manifest::CapabilitiesSection,
    classes: &crate::state::devices::ClassSnapshot,
    entry: &DeviceState,
    bytes: bool,
) -> Option<Visibility> {
    if !maybe_visible(
        plugin.instance_id,
        installation_uuid,
        &grants.reads_state,
        entry,
    ) {
        return None;
    }
    visibility(
        ctx,
        plugin,
        installation_uuid,
        classes.class_of(&entry.device_id),
        classes.instance_is_camera(&entry.owner_instance),
        entry,
        bytes,
    )
    .ok()
}

/// What `plugin`, reading within `ctx`, may see of `entry` (of a
/// device of `class`), or the label of the refusal. `camera_source`:
/// the entry's owner instance has registered a camera, so its bytes
/// count as camera bytes whatever the device (as for a token's direct
/// read, `api::bytes`). Without `bytes`, the bytes aren't decided
/// (`Withheld`).
///
/// The two decisions read one policy: a deny list changed between
/// them (one refusing the entry replacing one refusing its bytes, say)
/// could let each pass, so they are made again, and the entry refused
/// when the lists keep changing.
fn visibility(
    ctx: &InvocationContext,
    plugin: &PluginPrincipal<'_>,
    installation_uuid: &str,
    class: DeviceClass,
    camera_source: bool,
    entry: &DeviceState,
    bytes: bool,
) -> Result<Visibility, &'static str> {
    if is_own(plugin.instance_id, installation_uuid, entry) {
        return Ok(Visibility::Full);
    }
    for _ in 0..SNAPSHOT_TRIES {
        let policy = plugin.denies.generation();
        let vis = visibility_once(ctx, plugin, class, camera_source, entry, bytes);
        if plugin.denies.generation() == policy {
            return vis;
        }
    }
    Err("plugin-deny")
}

/// [`visibility`] of a foreign entry, its policy read once or twice.
fn visibility_once(
    ctx: &InvocationContext,
    plugin: &PluginPrincipal<'_>,
    class: DeviceClass,
    camera_source: bool,
    entry: &DeviceState,
    bytes: bool,
) -> Result<Visibility, &'static str> {
    let resource = Resource::state(
        entry.device_id.as_str(),
        class,
        entry.owner_plugin.as_str(),
        entry.capability.as_str(),
    );
    let read = authorize_plugin(ctx, plugin, Action::StateRead, &resource);
    if !read.allow {
        return Err(read.reason.audit_label().unwrap_or("reads_state"));
    }
    // Only an entry with bytes needs the second decision.
    if !bytes
        || !entry
            .fields
            .iter()
            .any(|kv| matches!(kv.value, Value::BytesVal(_)))
    {
        return Ok(Visibility::Withheld);
    }
    let bytes_resource = if camera_source {
        Resource::state(
            entry.device_id.as_str(),
            class.with_camera_bytes(),
            entry.owner_plugin.as_str(),
            entry.capability.as_str(),
        )
    } else {
        resource
    };
    let bytes = authorize_plugin(ctx, plugin, Action::BlobRead, &bytes_resource);
    // A sensitive obligation (camera bytes for the root) is one a
    // plugin read can't meet: withhold.
    Ok(if bytes.allow && bytes.obligations.sensitive.is_empty() {
        Visibility::Full
    } else {
        Visibility::Withheld
    })
}

fn to_wit(entry: &DeviceState, vis: Visibility) -> WitDeviceState {
    let mut fields = entry.fields.clone();
    if vis != Visibility::Full {
        for kv in &mut fields {
            if let Value::BytesVal(b) = &kv.value {
                kv.value = Value::JsonVal(format!(
                    "{{\"withheld\":\"bytes\",\"size_bytes\":{},\"required_scope\":\"reads_state.bytes\"}}",
                    b.len()
                ));
            }
        }
    }
    WitDeviceState {
        device: entry.device_id.clone(),
        capability: entry.capability.clone(),
        fields,
        revision: entry.global_revision,
        received_ms: u64::try_from(entry.received_ms).unwrap_or(0),
        observed_ms: entry.observed_ms,
        quality: match entry.quality {
            StateQuality::Fresh => WitQuality::Fresh,
            StateQuality::Stale => WitQuality::Stale,
        },
    }
}

/// One refused plugin read or network access, recorded by
/// [`deny_audit_worker`].
pub(crate) struct DenyAudit {
    log: Arc<crate::state::AuditLog>,
    /// The caller's context; `None` (host-origin) is minted by the
    /// worker, off the guest's path.
    ctx: Option<invocation::InvocationContext>,
    instance_id: String,
    read: DeniedRead,
}

/// What a [`DenyAudit`] row refused.
pub(crate) enum DeniedRead {
    /// `host-state::get-state` of a device with no visible entry;
    /// `scope` is the refusal's label.
    State { device: String, scope: &'static str },
    /// `host-events::read-events` refused; `scope` is the refusal's
    /// label (`subscribes_events` without the grant).
    Events { scope: &'static str },
    /// `host-events::subscribe` refused (H6 slice 5); `scope` is the
    /// refusal's label.
    Subscribe { scope: &'static str },
    /// Network access the instance's `[capabilities] network` rules
    /// don't allow (Phase 8). `op` is `connect` / `send` / `bind` /
    /// `listen` / `lookup` / `http`; `target` the address, name or
    /// authority; `reason` the policy's explanation.
    Network {
        op: &'static str,
        target: String,
        reason: String,
    },
    /// Not a refusal: an `https://` request trusted a LAN device's
    /// certificate on first use (Phase 8.2), recorded as an `allow` row
    /// so the operator sees every new pin.
    TlsPinned { target: String, sha256: String },
}

/// Queue the audit `deny` row for a `get-state` that found state the
/// plugin may not see (H2). The guest's return path only clones a few
/// values and does a non-blocking `try_send`: tracing, building the
/// row and the write all happen on one long-lived worker thread, so
/// neither the error nor its latency tells the plugin the device
/// exists. The operator still sees the row.
fn audit_state_denied(
    log: Option<Arc<crate::state::AuditLog>>,
    instance_id: &str,
    device: &str,
    scope: &'static str,
) {
    queue_deny_audit(
        log,
        instance_id,
        DeniedRead::State {
            device: device.to_owned(),
            scope,
        },
    );
}

/// Queue an audit `deny` row for a refused plugin read. Never blocks:
/// past the queue limit the row is dropped and counted.
pub(crate) fn queue_deny_audit(
    log: Option<Arc<crate::state::AuditLog>>,
    instance_id: &str,
    read: DeniedRead,
) {
    let Some(log) = log else {
        return;
    };
    let job = DenyAudit {
        log,
        ctx: invocation::current(),
        instance_id: instance_id.to_owned(),
        read,
    };
    // Counted before the send, so a drain never sees a queued job as
    // already written.
    deny_audit_adjust(1);
    if deny_audit_queue().is_none_or(|q| q.try_send(job).is_err()) {
        deny_audit_adjust(-1);
        DENY_AUDIT_DROPPED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

static DENY_AUDIT_DROPPED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Deny rows queued or being written, and the condvar a drain waits
/// on for it to reach zero.
static DENY_AUDIT_PENDING: std::sync::Mutex<usize> = std::sync::Mutex::new(0);
static DENY_AUDIT_IDLE: std::sync::Condvar = std::sync::Condvar::new();

fn deny_audit_adjust(delta: isize) {
    let mut pending = DENY_AUDIT_PENDING
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *pending = pending.saturating_add_signed(delta);
    if *pending == 0 {
        DENY_AUDIT_IDLE.notify_all();
    }
}

/// Wait up to `timeout` for every queued `get-state` deny row to be
/// written (H2 follow-up). Called at shutdown after the supervisors
/// stop, so the refusals they made reach the ledger. Returns whether
/// the queue drained; on `false` the remaining rows may be lost (a
/// hung disk must not hold shutdown). Process-wide: the worker is.
#[must_use]
pub fn drain_state_read_audit(timeout: std::time::Duration) -> bool {
    let pending = DENY_AUDIT_PENDING
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (pending, _) = DENY_AUDIT_IDLE
        .wait_timeout_while(pending, timeout, |n| *n > 0)
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *pending == 0
}

/// The audit worker's queue, starting the worker on first use. Called
/// from `PluginState::new` so the first refused read doesn't pay for
/// the thread start.
pub(crate) fn deny_audit_queue() -> Option<&'static std::sync::mpsc::SyncSender<DenyAudit>> {
    use std::sync::OnceLock;
    use std::sync::mpsc::{SyncSender, sync_channel};
    static QUEUE: OnceLock<Option<SyncSender<DenyAudit>>> = OnceLock::new();
    QUEUE.get_or_init(|| {
        let (tx, rx) = sync_channel::<DenyAudit>(DENY_AUDIT_QUEUE);
        // A detached std thread: Tokio waits for blocking tasks at
        // runtime teardown, so a write stuck on the disk must not be
        // one. It exits when the process does.
        std::thread::Builder::new()
            .name("state-deny-audit".into())
            .spawn(move || deny_audit_worker(&rx, &DENY_AUDIT_DROPPED))
            .map_err(|err| {
                tracing::error!(target: "host.audit", error = %err, "plugin-read audit worker not started");
            })
            .ok()
            .map(|_| tx)
    })
    .as_ref()
}

fn deny_audit_worker(
    rx: &std::sync::mpsc::Receiver<DenyAudit>,
    dropped: &std::sync::atomic::AtomicU64,
) {
    while let Ok(job) = rx.recv() {
        let lost = dropped.swap(0, std::sync::atomic::Ordering::Relaxed);
        if lost > 0 {
            tracing::warn!(target: "host.audit", lost, "plugin-read deny rows dropped: queue full");
        }
        let (method, path, scope) = match &job.read {
            DeniedRead::State { device, scope } => {
                tracing::warn!(
                    target: "host.state",
                    instance_id = %job.instance_id,
                    device = %device,
                    required = scope,
                    "get-state denied",
                );
                (
                    STATE_READ_AUDIT_METHOD,
                    format!(
                        "device.state/{}/{}",
                        invocation::audit_cap(&job.instance_id),
                        invocation::audit_cap(device)
                    ),
                    *scope,
                )
            }
            DeniedRead::Events { scope } => {
                tracing::warn!(
                    target: "host.events",
                    instance_id = %job.instance_id,
                    required = scope,
                    "read-events denied",
                );
                (
                    EVENT_READ_AUDIT_METHOD,
                    format!("event.history/{}", invocation::audit_cap(&job.instance_id)),
                    *scope,
                )
            }
            // `subscribe` traced it when it refused.
            DeniedRead::Subscribe { scope } => (
                EVENT_READ_AUDIT_METHOD,
                format!(
                    "event.subscribe/{}",
                    invocation::audit_cap(&job.instance_id)
                ),
                *scope,
            ),
            // The policy already traced it (rate-limited with the row).
            DeniedRead::Network { op, target, .. } => (
                NETWORK_AUDIT_METHOD,
                format!(
                    "net.{op}/{}/{}",
                    invocation::audit_cap(&job.instance_id),
                    invocation::audit_cap(target)
                ),
                "network",
            ),
            DeniedRead::TlsPinned { target, sha256 } => (
                NETWORK_AUDIT_METHOD,
                format!(
                    "net.tls_pin/{}/{}/sha256:{sha256}",
                    invocation::audit_cap(&job.instance_id),
                    invocation::audit_cap(target)
                ),
                "network",
            ),
        };
        let domain_error = match &job.read {
            DeniedRead::Network { reason, .. } => Some(reason.clone()),
            _ => None,
        };
        let allowed = matches!(job.read, DeniedRead::TlsPinned { .. });
        let ctx = job
            .ctx
            .unwrap_or_else(|| invocation::InvocationContext::host_origin(&job.instance_id));
        let root = ctx.root();
        let entry = AuditEntry {
            caused_by: ctx.caused_by().map(str::to_owned),
            id: 0,
            intent_ms: 0,
            finalized_ms: None,
            token_id: root.audit_token_id().to_owned(),
            actor_kind: root.kind().as_str().to_owned(),
            method: method.to_owned(),
            path,
            status: if allowed { 200 } else { 403 },
            decision: if allowed { "allow" } else { "deny" }.into(),
            required_scope: Some(scope.into()),
            execution_outcome: None,
            domain_error,
            credential_fp: None,
            call_id: Some(ctx.call_id().to_owned()),
            invocation: Some(ctx.audit_json()),
            command_id: None,
            command_outcome: None,

            // A new pin is trust the operator should see.
            level: allowed.then(|| "warn".to_owned()),
        };
        if let Err(err) = job.log.record_completed(&entry) {
            tracing::error!(target: "host.audit", method, error = %err, "plugin-read deny row failed");
        }
        deny_audit_adjust(-1);
    }
}

/// The one answer for "nothing to show": an unknown device and a
/// device the plugin may not see are indistinguishable.
fn no_visible_state(device: &str) -> WitError {
    WitError::NotFound(format!(
        "no visible state for device {device} (unknown, or needs a matching \
         `[[capabilities.reads_state]]` grant)"
    ))
}

impl host_state::Host for PluginState {
    async fn get_state(&mut self, device: DeviceId) -> Result<Vec<WitDeviceState>, WitError> {
        if device.len() > MAX_DEVICE_ID_LEN {
            return Err(WitError::InvalidArgument(format!(
                "device id longer than {MAX_DEVICE_ID_LEN} bytes"
            )));
        }
        let entries = self.device_state.snapshot_device(&device);
        if entries.is_empty() {
            return Err(no_visible_state(&device));
        }
        let ctx = invocation::current_or_host(&self.instance_id);
        let plugin = self.principal();
        // Every decision under one classification: a device
        // reclassified meanwhile means deciding again.
        let decide_all = || {
            let mut refused = None;
            let class = self.devices.class_of(&device);
            let out: Vec<WitDeviceState> = entries
                .iter()
                .filter_map(|e| {
                    match visibility(
                        &ctx,
                        &plugin,
                        &self.installation_uuid,
                        class,
                        self.devices.instance_is_camera(&e.owner_instance),
                        e,
                        true,
                    ) {
                        Ok(vis) => Some(to_wit(e, vis)),
                        Err(label) => {
                            refused.get_or_insert(label);
                            None
                        }
                    }
                })
                .collect();
            (out, refused)
        };
        let mut decided = None;
        for _ in 0..SNAPSHOT_TRIES {
            let classes = self.devices.generation();
            let result = decide_all();
            if self.devices.generation() == classes {
                decided = Some(result);
                break;
            }
        }
        // Undecided reads as nothing visible: a distinct error would
        // tell a hidden device from an unknown one.
        let Some((mut out, refused)) = decided else {
            return Err(no_visible_state(&device));
        };
        if out.is_empty() {
            audit_state_denied(
                self.audit_log.clone(),
                &self.instance_id,
                &device,
                refused.unwrap_or(crate::auth::READS_STATE_GRANT),
            );
            return Err(no_visible_state(&device));
        }
        out.sort_by(|a, b| a.capability.cmp(&b.capability));
        tracing::debug!(
            target: "host.state",
            instance_id = %self.instance_id,
            device = %device,
            entries = out.len(),
            "get-state",
        );
        Ok(out)
    }

    async fn list_state(
        &mut self,
        filter: StateFilter,
        cursor: Option<String>,
        limit: u32,
    ) -> Result<StatePage, WitError> {
        if filter
            .device
            .as_ref()
            .is_some_and(|d| d.len() > MAX_DEVICE_ID_LEN)
        {
            return Err(WitError::InvalidArgument(format!(
                "filter device id longer than {MAX_DEVICE_ID_LEN} bytes"
            )));
        }
        // The cursor is sealed: the scan may stop on a device this
        // plugin can't see, and its id must not leak.
        let after = match cursor.as_deref() {
            None => None,
            Some(token) => Some(self.device_state.open_scan_position(token).ok_or_else(|| {
                WitError::InvalidArgument(
                    "invalid or expired list-state cursor; start over without one".into(),
                )
            })?),
        };
        let limit = match usize::try_from(limit).unwrap_or(usize::MAX) {
            0 => DEFAULT_LIST_LIMIT,
            n => n.min(MAX_LIST_LIMIT),
        };
        let grants = Arc::clone(&self.granted_capabilities);
        let install = self.installation_uuid.to_string();
        let ctx = &invocation::current_or_host(&self.instance_id);
        let plugin = &self.principal();
        // Every entry is decided in full inside the scan, so one this
        // plugin may not see never counts toward the page. The device
        // classes are read before (the registry's locks aren't taken
        // under the store's) and must still hold after: a camera
        // registered meanwhile may have state in the page. Otherwise
        // the page is read again.
        let mut tries = 0;
        let (page, entries) = loop {
            let policy = plugin.denies.generation();
            let classes = self.devices.class_snapshot();
            let visible =
                |e: &DeviceState| decide(ctx, plugin, &install, &grants, &classes, e, false);
            let page = self.device_state.snapshot_page_capped(
                after.as_deref(),
                limit,
                MAX_LIST_PAGE_BYTES,
                crate::state::PageSizing::Estimate,
                LIST_SCAN_BUDGET,
                |e| {
                    filter.device.as_ref().is_none_or(|d| *d == e.device_id)
                        && filter
                            .capability
                            .as_ref()
                            .is_none_or(|c| *c == e.capability)
                        && visible(e).is_some()
                },
            );
            // The byte decisions too, under the same classification.
            let entries: Vec<WitDeviceState> = page
                .devices
                .iter()
                .flatten()
                .filter_map(|e| {
                    decide(ctx, plugin, &install, &grants, &classes, e, true)
                        .map(|vis| to_wit(e, vis))
                })
                .collect();
            // The scan's and the second pass's decisions under one
            // policy, or an entry the scan let through and the second
            // pass dropped could end the listing early.
            if self.devices.is_current(&classes) && plugin.denies.generation() == policy {
                break (page, entries);
            }
            tries += 1;
            if tries == SNAPSHOT_TRIES {
                return Err(WitError::Unavailable(
                    "devices or deny lists changed throughout list-state; try again".into(),
                ));
            }
        };
        let next_cursor = page
            .resume_after
            .map(|after| self.device_state.seal_scan_position(&after));
        Ok(StatePage {
            revision: page.revision,
            entries,
            next_cursor,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_impl::plugin::oxidhome::plugin::types::KeyValue;

    fn entry(owner_instance: &str, owner_plugin: &str, device: &str, cap: &str) -> DeviceState {
        DeviceState {
            device_id: device.into(),
            capability: cap.into(),
            fields: vec![KeyValue {
                key: "frame".into(),
                value: Value::BytesVal(vec![1, 2, 3]),
            }],
            global_revision: 7,
            received_ms: 5,
            observed_ms: 4,
            source_generation: 1,
            owner_instance: owner_instance.into(),
            owner_plugin: owner_plugin.into(),
            owner_install: format!("inst-{owner_plugin}"),
            quality: StateQuality::Fresh,
        }
    }

    fn grant(plugin: &str, caps: &[&str], devices: &[&str], bytes: bool) -> StateGrant {
        StateGrant {
            plugin: plugin.into(),
            capabilities: caps.iter().map(|c| (*c).into()).collect(),
            devices: devices.iter().map(|d| (*d).into()).collect(),
            bytes,
            sensitive: Vec::new(),
        }
    }

    /// What instance `me` of `p.me` (installation `install`) with
    /// `grants` sees of `e`, in host-rooted work.
    fn vis(me: &str, install: &str, grants: &[StateGrant], e: &DeviceState) -> Option<Visibility> {
        let denies = crate::state::PluginDenyStore::detached();
        let plugin = PluginPrincipal {
            plugin_id: "p.me",
            instance_id: me,
            requested_services: &[],
            granted_services: &[],
            reads_state: grants,
            subscribes_events: false,
            reads_event_bytes: false,
            camera_event_bytes: false,
            denies: &denies,
        };
        let ctx = InvocationContext::host_origin(me);
        let v = visibility(&ctx, &plugin, install, DeviceClass::other(), false, e, true).ok();
        // The scan's first pass never hides what the decision shows.
        assert!(v.is_none() || maybe_visible(me, install, grants, e));
        v
    }

    #[test]
    fn own_entries_are_always_fully_visible() {
        let e = entry("me", "p.me", "dev-1", "camera");
        assert_eq!(vis("me", "inst-p.me", &[], &e), Some(Visibility::Full));
        // Same instance id, another installation (reinstall or another
        // plugin): not its own.
        assert_eq!(vis("me", "inst-p.new", &[], &e), None);
    }

    /// H1 × H2: a sandbox child and its parent share the installation
    /// but not own-entry visibility; a grant on their own plugin id
    /// opens it.
    #[test]
    fn sandbox_children_do_not_inherit_own_entries() {
        let parent = entry("me", "p.me", "dev-1", "switch");
        assert_eq!(vis("me~s1", "inst-p.me", &[], &parent), None);
        let child = entry("me~s1", "p.me", "dev-2", "switch");
        assert_eq!(vis("me", "inst-p.me", &[], &child), None);
        let own_plugin = grant("p.me", &["*"], &["*"], false);
        assert_eq!(
            vis("me~s1", "inst-p.me", &[own_plugin], &parent),
            Some(Visibility::Withheld)
        );
    }

    #[test]
    fn foreign_entries_need_a_matching_grant() {
        let e = entry("other", "p.other", "dev-1", "camera");
        assert_eq!(vis("me", "inst-p.me", &[], &e), None);
        let wrong_plugin = grant("p.else", &["*"], &["*"], true);
        let wrong_cap = grant("p.other", &["switch"], &["*"], true);
        let wrong_dev = grant("*", &["*"], &["dev-2"], true);
        let empty_caps = grant("*", &[], &["*"], true);
        for g in [wrong_plugin, wrong_cap, wrong_dev, empty_caps] {
            assert_eq!(vis("me", "inst-p.me", &[g], &e), None);
        }
        let no_bytes = grant("p.other", &["camera"], &["dev-1"], false);
        assert_eq!(
            vis("me", "inst-p.me", std::slice::from_ref(&no_bytes), &e),
            Some(Visibility::Withheld)
        );
        let bytes = grant("*", &["*"], &["*"], true);
        assert_eq!(
            vis("me", "inst-p.me", &[no_bytes, bytes], &e),
            Some(Visibility::Full)
        );
    }

    /// H6 slice 5: inside a token's invocation, bytes from an instance
    /// that registered a camera are camera bytes, whatever the device:
    /// a token without the camera grant can't have a plugin read them
    /// on its behalf, as it can't read them directly.
    #[test]
    fn camera_source_bytes_need_the_roots_camera_grant() {
        use crate::auth::{Actor, ActorKind, Principal, Transport};
        let denies = crate::state::PluginDenyStore::detached();
        let grants = [grant("*", &["*"], &["*"], true)];
        let plugin = PluginPrincipal {
            plugin_id: "p.me",
            instance_id: "me",
            requested_services: &[],
            granted_services: &[],
            reads_state: &grants,
            subscribes_events: false,
            reads_event_bytes: false,
            camera_event_bytes: false,
            denies: &denies,
        };
        let e = entry("other", "p.other", "dev-1", "switch");
        let actor = Actor::api("tok", vec!["devices:read".into(), "blobs:read".into()]);
        let ctx =
            InvocationContext::external(Principal::token(ActorKind::Api, &actor, Transport::Rest));
        let class = DeviceClass::other();
        assert_eq!(
            visibility(&ctx, &plugin, "inst-p.me", class, false, &e, true),
            Ok(Visibility::Full)
        );
        assert_eq!(
            visibility(&ctx, &plugin, "inst-p.me", class, true, &e, true),
            Ok(Visibility::Withheld)
        );
        // H6 slice 5b: a camera-approved plugin under a token holding
        // the camera grant still gets them withheld: the token's allow
        // carries an obligation a plugin read can't meet (Q6).
        let approved = [StateGrant {
            sensitive: vec!["camera".into()],
            ..grant("*", &["*"], &["*"], true)
        }];
        let plugin = PluginPrincipal {
            reads_state: &approved,
            ..plugin
        };
        let host = InvocationContext::host_origin("me");
        assert_eq!(
            visibility(&host, &plugin, "inst-p.me", class, true, &e, true),
            Ok(Visibility::Full),
            "the plugin's own grant"
        );
        let camera = actor.with_sensitive(vec![crate::auth::SensitiveGrant::all(
            crate::auth::SensitiveCategory::Camera,
        )]);
        let ctx =
            InvocationContext::external(Principal::token(ActorKind::Api, &camera, Transport::Rest));
        assert_eq!(
            visibility(&ctx, &plugin, "inst-p.me", class, true, &e, true),
            Ok(Visibility::Withheld)
        );
    }

    #[test]
    fn withheld_bytes_become_a_marker() {
        let e = entry("other", "p.other", "dev-1", "camera");
        let w = to_wit(&e, Visibility::Withheld);
        let Value::JsonVal(marker) = &w.fields[0].value else {
            panic!("bytes not withheld: {:?}", w.fields[0].value);
        };
        assert!(marker.contains("\"size_bytes\":3"));
        assert!(marker.contains("reads_state.bytes"));
        let f = to_wit(&e, Visibility::Full);
        assert!(matches!(f.fields[0].value, Value::BytesVal(_)));
    }

    /// H2 follow-up: a shutdown drain waits for queued deny rows to be
    /// written, and reports a queue that can't drain in time.
    #[test]
    fn drain_waits_for_queued_deny_rows() {
        let db = Arc::new(crate::state::Db::open_in_memory().expect("db"));
        let log = Arc::new(crate::state::AuditLog::new(Arc::clone(&db)));
        assert!(drain_state_read_audit(std::time::Duration::ZERO));
        // Hold the writer so the worker can't finish the rows yet.
        let (held_tx, held_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let holder = {
            let db = Arc::clone(&db);
            std::thread::spawn(move || {
                db.write(|_| {
                    held_tx.send(()).expect("held");
                    release_rx.recv().expect("release");
                    Ok::<_, rusqlite::Error>(())
                })
                .expect("hold");
            })
        };
        held_rx.recv().expect("writer held");
        for device in ["dev-a", "dev-b"] {
            audit_state_denied(Some(Arc::clone(&log)), "inst", device, "reads_state");
        }
        assert!(
            !drain_state_read_audit(std::time::Duration::from_millis(50)),
            "rows are still waiting on the writer"
        );
        release_tx.send(()).expect("release");
        holder.join().expect("holder");
        assert!(drain_state_read_audit(std::time::Duration::from_secs(10)));
        assert_eq!(log.count().expect("count"), 2);
    }
}
