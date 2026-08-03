//! H9: host-owned canonical device-state projection.
//!
//! The `DeviceRegistry` tracks *what* devices exist. The
//! [`DeviceStateStore`] tracks *what state they're in* — the review
//! report's H2 finding was that the host stored only registration-time
//! `initial_state` and never observed subsequent `state-changed`
//! events, so API/UI reads could show the initial state forever while
//! live events reported something else, and a late-starting automation
//! had no authorized way to read another device's current state.
//!
//! Design notes:
//!
//! - **Keyed on `(device_id, capability)`.** Devices have multiple
//!   capabilities (a light might be `switchable + dimmable + color`);
//!   each carries its own field set. Storing per-capability instead
//!   of a flat state-bag matches the WIT `state-change` shape.
//!
//! - **Per-entry revision + store-wide revision.** The store-wide
//!   `global_revision` is a monotonic counter bumped on every apply;
//!   entries record their `global_revision` at write time so a
//!   caller can pass `since_revision=N` and receive every entry
//!   with `global_revision > N`. The per-`(device, capability)`
//!   `revision` field is a local counter that survives quality
//!   transitions and lets consumers detect "same entry, updated".
//!
//! - **Trust-separated timestamps.** `received_ms` is the host's
//!   wall-clock; `observed_ms` is the plugin's self-reported
//!   `event.timestamp`. Callers that need to reason about ordering
//!   use `received_ms` (and `revision`); `observed_ms` is
//!   informational only, matching the [`super::event_log`] pattern.
//!
//! - **Quality + source generation.** Each entry carries a
//!   [`StateQuality`] (`Fresh` or `Stale`) and the supervisor
//!   generation of the owning instance at write time. When the
//!   owning instance stops (or a new supervisor life begins),
//!   [`Self::mark_instance_stale`] flips every entry owned by that
//!   instance to `Stale`. Consumers filter on `quality` rather than
//!   assuming any value they see is current — the review's
//!   "silently retain old values across restart" failure mode.
//!
//! - **In-memory only for the H9 first cut.** Matches
//!   [`super::DeviceRegistry`]. Persistence to `SQLite` is a
//!   follow-up if a use case surfaces (post-restart state
//!   reconciliation without re-observing).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};

use crate::host_impl::plugin::oxidhome::plugin::types::{DeviceId, KeyValue};

/// Freshness marker for a stored state entry. `Stale` isn't a value
/// consumers can't read — it means "the plugin instance that
/// published this value is no longer live". Callers that treat
/// device state as safety-critical filter `Stale` out; callers that
/// only need best-effort telemetry can still read it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StateQuality {
    Fresh,
    Stale,
}

/// One state entry — the current value of one capability on one
/// device, plus the trust and freshness metadata a consumer needs to
/// reason about it.
#[derive(Debug, Clone)]
pub struct DeviceState {
    pub device_id: DeviceId,
    /// Capability name (`"switch"`, `"dimmer"`, `"sensor"`, ...).
    pub capability: String,
    /// Partial state fields most recently observed for this
    /// capability. Same shape as `wit::state-change.fields`.
    pub fields: Vec<KeyValue>,
    /// Per-`(device, capability)` monotonic counter — bumps on
    /// every applied change to *this* slot.
    pub revision: u64,
    /// Store-wide monotonic revision at which this update was
    /// applied. Callers of the delta API pass a `since_revision`;
    /// entries with `global_revision > since_revision` are what
    /// they haven't seen.
    pub global_revision: u64,
    /// Host wall-clock (ms since epoch) when the update was applied.
    /// Trusted — set from the host clock, not the plugin's.
    pub received_ms: i64,
    /// Plugin-supplied observed-at timestamp (ms) from the
    /// `event.timestamp` field. Best-effort — the plugin's clock,
    /// not the host's, so unsuitable for ordering. Mirrors the
    /// `event_log` payload/received timestamp separation.
    pub observed_ms: u64,
    /// Supervisor generation of the owning instance at write time.
    /// See [`DeviceStateStore::bump_generation`] and
    /// [`DeviceStateStore::mark_instance_stale`].
    pub source_generation: u64,
    /// Owning `instance_id`. Used by `mark_instance_stale` to find
    /// entries to flip. Not part of the identity of the state slot
    /// (an instance restart under the same `instance_id` reuses
    /// the slot — the same operator-facing name maps to the same
    /// entry, just with a new generation).
    pub owner_instance: String,
    pub quality: StateQuality,
}

/// H9 host-owned device-state projection. One per
/// [`Engine`](crate::Engine); cheap to clone via `Arc`.
#[derive(Debug, Default)]
pub struct DeviceStateStore {
    /// `(device_id, capability)` → current entry.
    entries: RwLock<HashMap<(DeviceId, String), Arc<DeviceState>>>,
    /// Monotonic counter — every apply bumps this and stamps the
    /// new value on the entry. Callers use it to catch up via
    /// [`Self::deltas_since`].
    global_revision: AtomicU64,
    /// Current supervisor generation per `owner_instance`, bumped
    /// by [`Self::bump_generation`] on each start. Reads here at
    /// apply time so a state event published just before the
    /// stale-marker fires still lands as `Fresh` under the
    /// *previous* generation and is transitioned to `Stale` on
    /// the next `mark_instance_stale` sweep.
    generations: RwLock<HashMap<String, u64>>,
}

impl DeviceStateStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn entries_read(&self) -> RwLockReadGuard<'_, HashMap<(DeviceId, String), Arc<DeviceState>>> {
        self.entries.read().unwrap_or_else(PoisonError::into_inner)
    }
    fn entries_write(&self) -> RwLockWriteGuard<'_, HashMap<(DeviceId, String), Arc<DeviceState>>> {
        self.entries.write().unwrap_or_else(PoisonError::into_inner)
    }
    fn generations_read(&self) -> RwLockReadGuard<'_, HashMap<String, u64>> {
        self.generations
            .read()
            .unwrap_or_else(PoisonError::into_inner)
    }
    fn generations_write(&self) -> RwLockWriteGuard<'_, HashMap<String, u64>> {
        self.generations
            .write()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Current store-wide monotonic revision. A snapshot taken at
    /// this value can be reconciled against `deltas_since(rev)` to
    /// catch up on every subsequent change.
    #[must_use]
    pub fn current_revision(&self) -> u64 {
        self.global_revision.load(Ordering::Acquire)
    }

    /// Bump the supervisor generation for `owner_instance`. Called
    /// from the supervisor at the top of every life (fresh start
    /// or restart). Subsequent [`Self::apply`] calls from this
    /// instance land under the bumped generation; a subsequent
    /// [`Self::mark_instance_stale`] sweeps everything carrying
    /// an earlier generation.
    pub fn bump_generation(&self, owner_instance: &str) -> u64 {
        let mut gens = self.generations_write();
        let next = gens.get(owner_instance).copied().unwrap_or(0) + 1;
        gens.insert(owner_instance.to_string(), next);
        next
    }

    /// Read the current generation for `owner_instance`, or `0` if
    /// no `bump_generation` has fired yet (test harnesses).
    fn current_generation(&self, owner_instance: &str) -> u64 {
        self.generations_read()
            .get(owner_instance)
            .copied()
            .unwrap_or(0)
    }

    /// Seed an initial state for a `(device_id, capability)` pair —
    /// called from `register_device` for each entry in
    /// `DeviceInfo.initial_state`. Applies with the same
    /// `Fresh`/`revision` machinery as [`Self::apply`], so a
    /// consumer that reads immediately after `init` sees the
    /// initial values, and a `state-changed` event minutes later
    /// bumps the same slot.
    pub fn seed(
        &self,
        device_id: DeviceId,
        owner_instance: String,
        capability: String,
        fields: Vec<KeyValue>,
        observed_ms: u64,
        received_ms: i64,
    ) {
        self.apply(
            device_id,
            owner_instance,
            capability,
            fields,
            observed_ms,
            received_ms,
        );
    }

    /// Apply a state change. Bumps the store-wide `global_revision`
    /// and the per-slot `revision`, records the trust-separated
    /// timestamps, and stamps the current generation for the owner.
    /// Overwrites any prior entry for the same
    /// `(device_id, capability)`. If a stale entry lands under an
    /// older generation than what's now current for the instance,
    /// the new entry is stamped with the current generation and
    /// marked `Fresh` — the freshness marker follows the *most
    /// recent* write, not the entry's history.
    pub fn apply(
        &self,
        device_id: DeviceId,
        owner_instance: String,
        capability: String,
        fields: Vec<KeyValue>,
        observed_ms: u64,
        received_ms: i64,
    ) {
        let generation = self.current_generation(&owner_instance);
        let global_revision = self.global_revision.fetch_add(1, Ordering::AcqRel) + 1;
        let mut entries = self.entries_write();
        let key = (device_id.clone(), capability.clone());
        let revision = entries.get(&key).map_or(1, |prev| prev.revision + 1);
        let entry = Arc::new(DeviceState {
            device_id,
            capability,
            fields,
            revision,
            global_revision,
            received_ms,
            observed_ms,
            source_generation: generation,
            owner_instance,
            quality: StateQuality::Fresh,
        });
        entries.insert(key, entry);
    }

    /// Snapshot every capability entry currently known for
    /// `device_id`. Empty when the device has no observed state
    /// (never registered, or registered without `initial_state`
    /// and no subsequent `state-changed` publishes).
    #[must_use]
    pub fn snapshot_device(&self, device_id: &str) -> Vec<Arc<DeviceState>> {
        self.entries_read()
            .iter()
            .filter(|((did, _), _)| did == device_id)
            .map(|(_, meta)| Arc::clone(meta))
            .collect()
    }

    /// Snapshot a single `(device, capability)` slot.
    #[must_use]
    pub fn snapshot_capability(
        &self,
        device_id: &str,
        capability: &str,
    ) -> Option<Arc<DeviceState>> {
        self.entries_read()
            .get(&(device_id.to_string(), capability.to_string()))
            .map(Arc::clone)
    }

    /// Return every entry with `global_revision > since_revision`,
    /// sorted ascending on `global_revision`, capped at `limit`.
    /// Callers pair a snapshot at revision N with
    /// `deltas_since(N, limit)` to reconcile without gaps.
    #[must_use]
    pub fn deltas_since(&self, since_revision: u64, limit: usize) -> Vec<Arc<DeviceState>> {
        let mut out: Vec<Arc<DeviceState>> = self
            .entries_read()
            .values()
            .filter(|m| m.global_revision > since_revision)
            .map(Arc::clone)
            .collect();
        out.sort_by_key(|m| m.global_revision);
        out.truncate(limit);
        out
    }

    /// Mark every entry owned by `owner_instance` as `Stale`. Bumps
    /// the store-wide revision for each modified entry so a caller
    /// polling `deltas_since` observes the quality transition.
    /// Called by the supervisor when an instance reaches a terminal
    /// state, and by [`Self::bump_generation`]-adjacent code paths
    /// that want to eagerly sweep pre-restart state.
    ///
    /// Returns the number of entries flipped (test / observability).
    pub fn mark_instance_stale(&self, owner_instance: &str) -> usize {
        let mut entries = self.entries_write();
        let keys_to_stale: Vec<(DeviceId, String)> = entries
            .iter()
            .filter(|(_, m)| m.owner_instance == owner_instance && m.quality == StateQuality::Fresh)
            .map(|(k, _)| k.clone())
            .collect();
        let n = keys_to_stale.len();
        for key in keys_to_stale {
            let global_revision = self.global_revision.fetch_add(1, Ordering::AcqRel) + 1;
            // Rebuild the Arc — outstanding snapshots keep the old
            // value; the map slot points at the new `Stale` entry.
            let prev = entries
                .get(&key)
                .expect("just filtered on presence")
                .clone();
            let updated = Arc::new(DeviceState {
                global_revision,
                quality: StateQuality::Stale,
                ..(*prev).clone()
            });
            entries.insert(key, updated);
        }
        n
    }
}

/// Shared `Arc` alias, parallel to `SharedDeviceRegistry`.
pub type SharedDeviceStateStore = Arc<DeviceStateStore>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_impl::plugin::oxidhome::plugin::types::{KeyValue, Value};

    fn kv(k: &str, v: Value) -> KeyValue {
        KeyValue {
            key: k.into(),
            value: v,
        }
    }

    #[test]
    fn apply_creates_entry_with_starting_revision_and_fresh_quality() {
        let store = DeviceStateStore::new();
        store.apply(
            "dev-1".into(),
            "alpha".into(),
            "switch".into(),
            vec![kv("state", Value::BoolVal(true))],
            10,
            100,
        );
        let entry = store.snapshot_capability("dev-1", "switch").expect("entry");
        assert_eq!(entry.revision, 1);
        assert_eq!(entry.global_revision, 1);
        assert_eq!(entry.received_ms, 100);
        assert_eq!(entry.observed_ms, 10);
        assert_eq!(entry.quality, StateQuality::Fresh);
        assert_eq!(entry.source_generation, 0); // no bump_generation yet
        assert!(matches!(entry.fields[0].value, Value::BoolVal(true)));
    }

    #[test]
    fn apply_overwrites_and_bumps_both_revisions() {
        let store = DeviceStateStore::new();
        store.apply(
            "dev-1".into(),
            "alpha".into(),
            "switch".into(),
            vec![kv("state", Value::BoolVal(true))],
            10,
            100,
        );
        store.apply(
            "dev-1".into(),
            "alpha".into(),
            "switch".into(),
            vec![kv("state", Value::BoolVal(false))],
            20,
            200,
        );
        let entry = store.snapshot_capability("dev-1", "switch").unwrap();
        // Per-slot revision counts local changes.
        assert_eq!(entry.revision, 2);
        // Store-wide revision bumps on every apply.
        assert_eq!(entry.global_revision, 2);
        assert_eq!(store.current_revision(), 2);
        assert!(matches!(entry.fields[0].value, Value::BoolVal(false)));
    }

    #[test]
    fn snapshot_device_returns_every_capability_entry() {
        let store = DeviceStateStore::new();
        store.apply(
            "dev-1".into(),
            "alpha".into(),
            "switch".into(),
            vec![],
            0,
            0,
        );
        store.apply(
            "dev-1".into(),
            "alpha".into(),
            "dimmer".into(),
            vec![],
            0,
            0,
        );
        store.apply(
            "dev-2".into(),
            "alpha".into(),
            "sensor".into(),
            vec![],
            0,
            0,
        );
        let mut caps: Vec<String> = store
            .snapshot_device("dev-1")
            .into_iter()
            .map(|m| m.capability.clone())
            .collect();
        caps.sort();
        assert_eq!(caps, vec!["dimmer".to_string(), "switch".to_string()]);
    }

    #[test]
    fn deltas_since_returns_only_newer_entries_sorted_and_capped() {
        let store = DeviceStateStore::new();
        for i in 0..5 {
            store.apply(
                format!("dev-{i}"),
                "alpha".into(),
                "switch".into(),
                vec![],
                0,
                0,
            );
        }
        // Snapshot cursor at revision 2 → deltas returns entries
        // with global_revision 3, 4, 5.
        let deltas = store.deltas_since(2, 10);
        assert_eq!(deltas.len(), 3);
        let revs: Vec<u64> = deltas.iter().map(|m| m.global_revision).collect();
        assert_eq!(revs, vec![3, 4, 5]);
        // Limit truncates ascending — you get the *earliest*
        // deltas so you can drive the cursor forward one page at a
        // time without missing anything.
        let capped = store.deltas_since(0, 2);
        let capped_revs: Vec<u64> = capped.iter().map(|m| m.global_revision).collect();
        assert_eq!(capped_revs, vec![1, 2]);
    }

    #[test]
    fn mark_instance_stale_flips_owned_entries_and_bumps_revision() {
        let store = DeviceStateStore::new();
        store.apply(
            "dev-alpha".into(),
            "alpha".into(),
            "switch".into(),
            vec![],
            0,
            0,
        );
        store.apply(
            "dev-beta".into(),
            "beta".into(),
            "switch".into(),
            vec![],
            0,
            0,
        );
        assert_eq!(store.current_revision(), 2);

        let flipped = store.mark_instance_stale("alpha");
        assert_eq!(flipped, 1);
        let alpha_entry = store.snapshot_capability("dev-alpha", "switch").unwrap();
        assert_eq!(alpha_entry.quality, StateQuality::Stale);
        // Revision bumped so a delta poller catches the transition.
        assert_eq!(alpha_entry.global_revision, 3);
        let beta_entry = store.snapshot_capability("dev-beta", "switch").unwrap();
        assert_eq!(beta_entry.quality, StateQuality::Fresh);
        // Second sweep is idempotent — alpha's entry is already
        // Stale, so nothing to flip.
        assert_eq!(store.mark_instance_stale("alpha"), 0);
    }

    #[test]
    fn bump_generation_stamps_the_next_apply() {
        let store = DeviceStateStore::new();
        assert_eq!(store.bump_generation("alpha"), 1);
        store.apply(
            "dev-1".into(),
            "alpha".into(),
            "switch".into(),
            vec![],
            0,
            0,
        );
        assert_eq!(
            store
                .snapshot_capability("dev-1", "switch")
                .unwrap()
                .source_generation,
            1,
        );
        assert_eq!(store.bump_generation("alpha"), 2);
        store.apply(
            "dev-1".into(),
            "alpha".into(),
            "switch".into(),
            vec![],
            0,
            0,
        );
        assert_eq!(
            store
                .snapshot_capability("dev-1", "switch")
                .unwrap()
                .source_generation,
            2,
        );
    }

    /// A snapshot handed out by `snapshot_capability` is an `Arc`
    /// — subsequent `apply` calls rebuild the Arc, and the old
    /// snapshot keeps observing what it read.
    #[test]
    fn snapshot_is_immutable_after_read() {
        let store = DeviceStateStore::new();
        store.apply(
            "dev-1".into(),
            "alpha".into(),
            "switch".into(),
            vec![kv("state", Value::BoolVal(true))],
            0,
            0,
        );
        let before = store.snapshot_capability("dev-1", "switch").unwrap();
        assert!(matches!(before.fields[0].value, Value::BoolVal(true)));

        store.apply(
            "dev-1".into(),
            "alpha".into(),
            "switch".into(),
            vec![kv("state", Value::BoolVal(false))],
            0,
            0,
        );
        // Old snapshot unchanged.
        assert!(matches!(before.fields[0].value, Value::BoolVal(true)));
        let after = store.snapshot_capability("dev-1", "switch").unwrap();
        assert!(matches!(after.fields[0].value, Value::BoolVal(false)));
    }
}
