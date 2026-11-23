//! H2: the `host-state` import — plugin read access to the host-owned
//! device-state projection.
//!
//! A plugin always sees the entries its own instance wrote. Any other
//! entry needs a `[[capabilities.reads_state]]` grant matching its
//! owner plugin, capability and device ([`StateGrant::matches`]); the
//! effective grant is requested ∩ granted (see
//! `state::effective_capabilities`). `bytes-val` fields are replaced
//! by a withheld marker unless a matching grant sets `bytes = true`
//! (own entries are returned as written). A `get-state` refused for
//! lack of a grant writes an audit `deny` row (`method = STATE`,
//! `required_scope = reads_state`), awaited for a bounded time so a
//! plugin looping on refused reads is throttled by the ledger rather
//! than queueing writes. Allowed reads are traced, not audited:
//! reads change nothing and would dominate the ledger.

use std::sync::Arc;
use std::time::Duration;

use oxidhome_manifest::StateGrant;

use super::state::PluginState;
use crate::auth::invocation;
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
/// How long a refused read waits for its audit row.
const DENY_AUDIT_WAIT: Duration = Duration::from_secs(2);
/// Deny-row writes in flight at once, process-wide. A write that
/// outlives [`DENY_AUDIT_WAIT`] keeps its permit until it completes,
/// so a stalled writer can't pile up blocking tasks; past the limit a
/// refusal is traced but not audited.
const MAX_PENDING_DENY_AUDITS: usize = 32;
static DENY_AUDIT_PERMITS: tokio::sync::Semaphore =
    tokio::sync::Semaphore::const_new(MAX_PENDING_DENY_AUDITS);
/// Audit `method` for state reads.
pub(crate) const STATE_READ_AUDIT_METHOD: &str = "STATE";

/// What a plugin may see of one entry.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Visibility {
    Hidden,
    /// Visible, `bytes-val` withheld.
    Withheld,
    Full,
}

/// Own entries are the ones this instance wrote *as this
/// installation*: an instance id reused by another plugin, or by a
/// reinstall of the same plugin, doesn't inherit the stale entries its
/// predecessor left behind.
fn visibility(
    instance_id: &str,
    installation_uuid: &str,
    grants: &[StateGrant],
    entry: &DeviceState,
) -> Visibility {
    if entry.owner_instance == instance_id && entry.owner_install == installation_uuid {
        return Visibility::Full;
    }
    let mut seen = Visibility::Hidden;
    for grant in grants {
        if grant.matches(&entry.owner_plugin, &entry.device_id, &entry.capability) {
            if grant.bytes {
                return Visibility::Full;
            }
            seen = Visibility::Withheld;
        }
    }
    seen
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

/// Audit `deny` row for a refused `get-state` (H2). Takes owned
/// values: the host-import future must be `Send`, and `PluginState`
/// is not `Sync`.
async fn audit_state_denied(
    log: Option<Arc<crate::state::AuditLog>>,
    instance_id: String,
    device: String,
) {
    {
        let Some(log) = log else {
            return;
        };
        let ctx = invocation::current_or_host(&instance_id);
        let root = ctx.root();
        let entry = AuditEntry {
            id: 0,
            intent_ms: 0,
            finalized_ms: None,
            token_id: root.audit_token_id().to_owned(),
            actor_kind: root.kind().as_str().to_owned(),
            method: STATE_READ_AUDIT_METHOD.to_owned(),
            path: format!(
                "device.state/{}/{}",
                invocation::audit_cap(&instance_id),
                invocation::audit_cap(&device)
            ),
            status: 403,
            decision: "deny".into(),
            required_scope: Some("reads_state".into()),
            execution_outcome: None,
            domain_error: None,
            credential_fp: None,
            call_id: Some(ctx.call_id().to_owned()),
            invocation: Some(ctx.audit_json()),
            command_id: None,
            command_outcome: None,
        };
        let Ok(permit) = DENY_AUDIT_PERMITS.try_acquire() else {
            tracing::warn!(
                target: "host.audit",
                "state-read deny row dropped: too many audit writes pending",
            );
            return;
        };
        let write = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            log.record_completed(&entry)
        });
        match tokio::time::timeout(DENY_AUDIT_WAIT, write).await {
            Ok(Ok(Ok(_))) => {}
            Ok(Ok(Err(err))) => {
                tracing::error!(target: "host.audit", error = %err, "state-read deny row failed");
            }
            Ok(Err(err)) => {
                tracing::error!(target: "host.audit", error = %err, "state-read deny row panicked");
            }
            Err(_) => {
                tracing::warn!(target: "host.audit", "state-read deny row still pending");
            }
        }
    }
}

impl host_state::Host for PluginState {
    async fn get_state(&mut self, device: DeviceId) -> Result<Vec<WitDeviceState>, WitError> {
        let entries = self.device_state.snapshot_device(&device);
        if entries.is_empty() {
            return Err(WitError::NotFound(format!("no state for device {device}")));
        }
        let grants = Arc::clone(&self.granted_capabilities);
        let install = self.installation_uuid.to_string();
        let mut out: Vec<WitDeviceState> = entries
            .iter()
            .filter_map(|e| {
                let vis = visibility(&self.instance_id, &install, &grants.reads_state, e);
                (vis != Visibility::Hidden).then(|| to_wit(e, vis))
            })
            .collect();
        if out.is_empty() {
            tracing::warn!(
                target: "host.state",
                instance_id = %self.instance_id,
                device = %device,
                "get-state denied — no matching capabilities.reads_state grant",
            );
            audit_state_denied(self.audit_log.clone(), self.instance_id.clone(), device).await;
            return Err(WitError::PermissionDenied(
                "get-state requires a matching `[[capabilities.reads_state]]` grant".into(),
            ));
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
        let instance_id = self.instance_id.clone();
        let install = self.installation_uuid.to_string();
        let page = self.device_state.snapshot_page_capped(
            after.as_deref(),
            limit,
            MAX_LIST_PAGE_BYTES,
            LIST_SCAN_BUDGET,
            |e| {
                filter.device.as_ref().is_none_or(|d| *d == e.device_id)
                    && filter
                        .capability
                        .as_ref()
                        .is_none_or(|c| *c == e.capability)
                    && visibility(&instance_id, &install, &grants.reads_state, e)
                        != Visibility::Hidden
            },
        );
        let next_cursor = page
            .resume_after
            .map(|after| self.device_state.seal_scan_position(&after));
        let entries = page
            .devices
            .iter()
            .flatten()
            .map(|e| {
                to_wit(
                    e,
                    visibility(&instance_id, &install, &grants.reads_state, e),
                )
            })
            .collect();
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
        }
    }

    #[test]
    fn own_entries_are_always_fully_visible() {
        let e = entry("me", "p.me", "dev-1", "camera");
        assert_eq!(visibility("me", "inst-p.me", &[], &e), Visibility::Full);
        // Same instance id, another installation (reinstall or another
        // plugin): not its own.
        assert_eq!(visibility("me", "inst-p.new", &[], &e), Visibility::Hidden);
    }

    #[test]
    fn foreign_entries_need_a_matching_grant() {
        let e = entry("other", "p.other", "dev-1", "camera");
        assert_eq!(visibility("me", "inst-p.me", &[], &e), Visibility::Hidden);
        let wrong_plugin = grant("p.else", &["*"], &["*"], true);
        let wrong_cap = grant("p.other", &["switch"], &["*"], true);
        let wrong_dev = grant("*", &["*"], &["dev-2"], true);
        let empty_caps = grant("*", &[], &["*"], true);
        for g in [wrong_plugin, wrong_cap, wrong_dev, empty_caps] {
            assert_eq!(visibility("me", "inst-p.me", &[g], &e), Visibility::Hidden);
        }
        let no_bytes = grant("p.other", &["camera"], &["dev-1"], false);
        assert_eq!(
            visibility("me", "inst-p.me", std::slice::from_ref(&no_bytes), &e),
            Visibility::Withheld
        );
        let bytes = grant("*", &["*"], &["*"], true);
        assert_eq!(
            visibility("me", "inst-p.me", &[no_bytes, bytes], &e),
            Visibility::Full
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
}
