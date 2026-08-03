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
//! - **Single lock serializes revisions with insertions (round-2
//!   review fix).** The store's `global_revision` counter lives
//!   *inside* the same `RwLock` that guards the entries map, so
//!   revision allocation and insertion are one atomic operation.
//!   Snapshot / delta reads also take that lock, so a reader
//!   observing `current_revision() = N` sees every entry with
//!   `global_revision ≤ N` in the entries map. The previous shape
//!   allocated the revision with a separate `AtomicU64::fetch_add`
//!   before taking the write lock, which let writer A allocate rev
//!   1 and pause while writer B committed rev 2 — a poller could
//!   then advance to 2 and A's rev-1 entry became invisible to
//!   every future `since_revision ≥ 2` request.
//!
//! - **Fields merge on `key`, not replace (round-2 review fix).**
//!   `state-change.fields` is documented as the *changed* fields
//!   only, not the full snapshot. Applying a color-light update
//!   with only `{hue: 0.5}` used to blow away the previously
//!   observed `saturation` / `value` / `color-temp-kelvin`. The
//!   current [`Self::apply`] merges by key: unchanged keys survive,
//!   changed keys take the new value. Explicit removal isn't
//!   supported in this cut (WIT `state-change` has no delete
//!   marker); a plugin that needs a field to go away
//!   `remove-device` + `register-device` again, which also triggers
//!   capability reconciliation.
//!
//! - **Lifecycle reconciliation (round-2 review fix).** Removing
//!   a device — or shipping an `update-device` with a narrower
//!   `capabilities` list — used to leave stale projection entries
//!   `Fresh` indefinitely. [`Self::mark_device_stale`] and
//!   [`Self::reconcile_capabilities`] now flip the affected
//!   entries and bump the global revision so a delta poller
//!   catches the transition. The host runtime wires these into
//!   `register-device` / `update-device` / `remove-device`.
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
use std::sync::{Arc, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};

use crate::host_impl::plugin::oxidhome::plugin::types::{DeviceId, KeyValue};

/// Freshness marker for a stored state entry. `Stale` isn't a value
/// consumers can't read — it means "the plugin instance that
/// published this value is no longer live, or the device / capability
/// has been unregistered". Callers that treat device state as
/// safety-critical filter `Stale` out; callers that only need
/// best-effort telemetry can still read it.
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
    /// Merged partial-state fields observed to date for this
    /// capability. Same shape as `wit::state-change.fields`, but
    /// accumulates across updates — `state-change.fields` is
    /// documented as *changes*, so merging by key preserves fields
    /// the plugin isn't currently reporting.
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

/// The map + the monotonic revision counter, jointly under one
/// `RwLock` so allocation and insertion linearize with reads.
#[derive(Debug, Default)]
struct StoreInner {
    entries: HashMap<(DeviceId, String), Arc<DeviceState>>,
    /// Store-wide monotonic revision. Every mutating operation
    /// increments this and stamps the value onto the entry being
    /// written. Held under the same lock as `entries` so an
    /// observer that reads `global_revision = N` from
    /// `current_revision()` sees every entry with
    /// `global_revision ≤ N` already in the map.
    global_revision: u64,
}

impl StoreInner {
    /// Allocate the next store-wide revision. **MUST** be called
    /// under a write lock on `self`.
    fn next_revision(&mut self) -> u64 {
        self.global_revision += 1;
        self.global_revision
    }
}

/// H9 host-owned device-state projection. One per
/// [`Engine`](crate::Engine); cheap to clone via `Arc`.
#[derive(Debug, Default)]
pub struct DeviceStateStore {
    inner: RwLock<StoreInner>,
    /// Current supervisor generation per `owner_instance`, bumped
    /// by [`Self::bump_generation`] on each start. Read at apply
    /// time so a state event published just before the
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

    fn inner_read(&self) -> RwLockReadGuard<'_, StoreInner> {
        self.inner.read().unwrap_or_else(PoisonError::into_inner)
    }
    fn inner_write(&self) -> RwLockWriteGuard<'_, StoreInner> {
        self.inner.write().unwrap_or_else(PoisonError::into_inner)
    }
    fn generations_write(&self) -> RwLockWriteGuard<'_, HashMap<String, u64>> {
        self.generations
            .write()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Current store-wide monotonic revision. A snapshot taken at
    /// this value can be reconciled against `deltas_since(rev)` to
    /// catch up on every subsequent change. Reads under the entries
    /// lock so the value is guaranteed to reflect every committed
    /// entry (round-2 review fix — the pre-fix shape allowed the
    /// counter to advance ahead of the map).
    #[must_use]
    pub fn current_revision(&self) -> u64 {
        self.inner_read().global_revision
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
        self.generations
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(owner_instance)
            .copied()
            .unwrap_or(0)
    }

    /// Seed an initial state for a `(device_id, capability)` pair —
    /// called from `register_device` for each entry in
    /// `DeviceInfo.initial_state`. Merges into any existing slot,
    /// same as [`Self::apply`], so the initial values compose
    /// correctly with any state that had accumulated before a
    /// re-registration.
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

    /// Apply a partial state change. Merges the new `fields` into
    /// the existing entry by key — unchanged keys survive, changed
    /// keys take the new value, new keys are added. Bumps the
    /// store-wide `global_revision` and the per-slot `revision`,
    /// stamps the trust-separated timestamps + current generation,
    /// and marks the entry `Fresh`.
    ///
    /// **Serialized (round-2 review fix)** — revision allocation
    /// and insertion happen under one write lock, so a poller that
    /// observes `current_revision() = N` sees every entry with
    /// `global_revision ≤ N`. The pre-fix shape allocated with
    /// `AtomicU64::fetch_add` before taking the lock, opening a
    /// race where allocated-but-uncommitted revisions could be
    /// permanently skipped by delta pollers.
    ///
    /// **Merge, not replace (round-2 review fix).** WIT
    /// `state-change.fields` is documented as *changes only*. The
    /// pre-fix shape blew away every prior field on each apply, so
    /// a color-light update reporting only `hue` erased the last
    /// known `saturation` / `value` / `color-temp-kelvin`.
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
        let mut inner = self.inner_write();
        let global_revision = inner.next_revision();
        let key = (device_id.clone(), capability.clone());
        let (merged_fields, revision) = match inner.entries.get(&key) {
            Some(prev) => (merge_fields(&prev.fields, &fields), prev.revision + 1),
            None => (fields, 1),
        };
        let entry = Arc::new(DeviceState {
            device_id,
            capability,
            fields: merged_fields,
            revision,
            global_revision,
            received_ms,
            observed_ms,
            source_generation: generation,
            owner_instance,
            quality: StateQuality::Fresh,
        });
        inner.entries.insert(key, entry);
    }

    /// Snapshot every capability entry currently known for
    /// `device_id`. Empty when the device has no observed state
    /// (never registered, or registered without `initial_state`
    /// and no subsequent `state-changed` publishes).
    #[must_use]
    pub fn snapshot_device(&self, device_id: &str) -> Vec<Arc<DeviceState>> {
        self.inner_read()
            .entries
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
        self.inner_read()
            .entries
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
            .inner_read()
            .entries
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
        let mut inner = self.inner_write();
        let keys_to_stale: Vec<(DeviceId, String)> = inner
            .entries
            .iter()
            .filter(|(_, m)| m.owner_instance == owner_instance && m.quality == StateQuality::Fresh)
            .map(|(k, _)| k.clone())
            .collect();
        for key in &keys_to_stale {
            let global_revision = inner.next_revision();
            let prev = inner
                .entries
                .get(key)
                .expect("just filtered on presence")
                .clone();
            let updated = Arc::new(DeviceState {
                global_revision,
                quality: StateQuality::Stale,
                ..(*prev).clone()
            });
            inner.entries.insert(key.clone(), updated);
        }
        keys_to_stale.len()
    }

    /// H9 round-2 finding 3: mark every entry for `device_id` as
    /// `Stale`. Called from `remove-device` — the device is gone,
    /// so its projection entries must not continue to advertise
    /// as `Fresh`. Also called from `register-device` before
    /// seeding, so any pre-existing entries from a prior life of
    /// the same stable id start `Stale` and are re-initialized
    /// only for the capabilities the current registration declares.
    ///
    /// Returns the number of entries flipped.
    pub fn mark_device_stale(&self, device_id: &str) -> usize {
        let mut inner = self.inner_write();
        let keys_to_stale: Vec<(DeviceId, String)> = inner
            .entries
            .iter()
            .filter(|((did, _), m)| did == device_id && m.quality == StateQuality::Fresh)
            .map(|(k, _)| k.clone())
            .collect();
        for key in &keys_to_stale {
            let global_revision = inner.next_revision();
            let prev = inner
                .entries
                .get(key)
                .expect("just filtered on presence")
                .clone();
            let updated = Arc::new(DeviceState {
                global_revision,
                quality: StateQuality::Stale,
                ..(*prev).clone()
            });
            inner.entries.insert(key.clone(), updated);
        }
        keys_to_stale.len()
    }

    /// H9 round-2 finding 3: reconcile the projection with a
    /// `DeviceInfo.capabilities` list — flip any entry whose
    /// `capability` isn't in `live_capabilities` to `Stale`.
    /// Called from `register-device` and `update-device` so a
    /// device that dropped a capability (or re-registered with a
    /// narrower spec list) doesn't leave the old entries
    /// advertising as `Fresh` under the same stable id.
    ///
    /// Returns the number of entries flipped.
    pub fn reconcile_capabilities(&self, device_id: &str, live_capabilities: &[String]) -> usize {
        let mut inner = self.inner_write();
        let keys_to_stale: Vec<(DeviceId, String)> = inner
            .entries
            .iter()
            .filter(|((did, cap), m)| {
                did == device_id
                    && m.quality == StateQuality::Fresh
                    && !live_capabilities.iter().any(|live| live == cap)
            })
            .map(|(k, _)| k.clone())
            .collect();
        for key in &keys_to_stale {
            let global_revision = inner.next_revision();
            let prev = inner
                .entries
                .get(key)
                .expect("just filtered on presence")
                .clone();
            let updated = Arc::new(DeviceState {
                global_revision,
                quality: StateQuality::Stale,
                ..(*prev).clone()
            });
            inner.entries.insert(key.clone(), updated);
        }
        keys_to_stale.len()
    }
}

/// Merge `updates` into `prev` by `key` — new keys are appended,
/// duplicated keys have their value replaced by the update. Preserves
/// `prev`'s ordering for stable keys so a snapshot-diffing consumer
/// sees minimal churn.
fn merge_fields(prev: &[KeyValue], updates: &[KeyValue]) -> Vec<KeyValue> {
    let mut out: Vec<KeyValue> = prev.to_vec();
    for update in updates {
        if let Some(existing) = out.iter_mut().find(|kv| kv.key == update.key) {
            existing.value = update.value.clone();
        } else {
            out.push(update.clone());
        }
    }
    out
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
        assert_eq!(entry.source_generation, 0);
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
        assert_eq!(entry.revision, 2);
        assert_eq!(entry.global_revision, 2);
        assert_eq!(store.current_revision(), 2);
        assert!(matches!(entry.fields[0].value, Value::BoolVal(false)));
    }

    /// Round-2 finding 2: `state-change.fields` is *changes only*.
    /// Applying `{hue: 0.5}` onto a color-light entry with prior
    /// `{hue, saturation, value, color_temp_kelvin}` must
    /// preserve the untouched keys.
    #[test]
    fn apply_merges_by_key_preserving_untouched_fields() {
        let store = DeviceStateStore::new();
        store.apply(
            "dev-1".into(),
            "alpha".into(),
            "color-light".into(),
            vec![
                kv("hue", Value::FloatVal(0.1)),
                kv("saturation", Value::FloatVal(0.9)),
                kv("value", Value::FloatVal(0.8)),
                kv("color_temp_kelvin", Value::IntVal(4000)),
            ],
            0,
            0,
        );
        // Second apply reports only `hue`. Saturation / value /
        // color_temp_kelvin must survive.
        store.apply(
            "dev-1".into(),
            "alpha".into(),
            "color-light".into(),
            vec![kv("hue", Value::FloatVal(0.5))],
            0,
            0,
        );
        let entry = store.snapshot_capability("dev-1", "color-light").unwrap();
        let field = |k: &str| entry.fields.iter().find(|f| f.key == k).cloned();
        assert!(matches!(
            field("hue").unwrap().value,
            Value::FloatVal(v) if (v - 0.5).abs() < f64::EPSILON
        ));
        assert!(matches!(
            field("saturation").unwrap().value,
            Value::FloatVal(v) if (v - 0.9).abs() < f64::EPSILON
        ));
        assert!(matches!(
            field("value").unwrap().value,
            Value::FloatVal(v) if (v - 0.8).abs() < f64::EPSILON
        ));
        assert!(matches!(
            field("color_temp_kelvin").unwrap().value,
            Value::IntVal(4000)
        ));
    }

    /// Round-2 finding 1: revision allocation + insertion must be
    /// under one lock. Drive many threads through `apply` in
    /// parallel and verify every revision from 1..=N is committed
    /// and observable. Under the pre-fix shape (atomic allocate
    /// then separate write-lock) some revisions could commit out
    /// of order or be permanently skipped by delta pollers.
    #[test]
    fn concurrent_applies_commit_every_revision_contiguously() {
        use std::sync::Arc as StdArc;
        use std::thread;

        let store = StdArc::new(DeviceStateStore::new());
        let threads = 8;
        let per_thread = 25;
        let mut handles = Vec::new();
        for t in 0..threads {
            let s = StdArc::clone(&store);
            handles.push(thread::spawn(move || {
                for i in 0..per_thread {
                    s.apply(
                        format!("dev-{t}-{i}"),
                        format!("owner-{t}"),
                        "switch".into(),
                        vec![],
                        0,
                        0,
                    );
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        // Every allocated revision must have committed an entry —
        // deltas_since(0, large) must return exactly `threads *
        // per_thread` entries and the global revisions must cover
        // 1..=threads*per_thread exactly.
        let total = threads * per_thread;
        assert_eq!(store.current_revision(), total as u64);
        let deltas = store.deltas_since(0, total * 2);
        assert_eq!(deltas.len(), total);
        let mut revs: Vec<u64> = deltas.iter().map(|m| m.global_revision).collect();
        revs.sort_unstable();
        let expected: Vec<u64> = (1..=total as u64).collect();
        assert_eq!(revs, expected);
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
        let deltas = store.deltas_since(2, 10);
        assert_eq!(deltas.len(), 3);
        let revs: Vec<u64> = deltas.iter().map(|m| m.global_revision).collect();
        assert_eq!(revs, vec![3, 4, 5]);
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
        assert_eq!(alpha_entry.global_revision, 3);
        let beta_entry = store.snapshot_capability("dev-beta", "switch").unwrap();
        assert_eq!(beta_entry.quality, StateQuality::Fresh);
        assert_eq!(store.mark_instance_stale("alpha"), 0);
    }

    /// Round-2 finding 3: `remove-device` (via `mark_device_stale`)
    /// flips every entry for `device_id` to `Stale`, bumps
    /// revisions so a poller catches the transition.
    #[test]
    fn mark_device_stale_flips_all_capabilities_for_device() {
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
            "dev-other".into(),
            "alpha".into(),
            "switch".into(),
            vec![],
            0,
            0,
        );
        assert_eq!(store.mark_device_stale("dev-1"), 2);
        assert_eq!(
            store
                .snapshot_capability("dev-1", "switch")
                .unwrap()
                .quality,
            StateQuality::Stale
        );
        assert_eq!(
            store
                .snapshot_capability("dev-1", "dimmer")
                .unwrap()
                .quality,
            StateQuality::Stale
        );
        // Other device unaffected.
        assert_eq!(
            store
                .snapshot_capability("dev-other", "switch")
                .unwrap()
                .quality,
            StateQuality::Fresh
        );
    }

    /// Round-2 finding 3: `update-device` with a narrower
    /// capability list should flip the dropped capabilities'
    /// entries. `reconcile_capabilities` keeps entries whose
    /// capability is in the live list and stales the rest.
    #[test]
    fn reconcile_capabilities_flips_dropped_capabilities_only() {
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
            "dev-1".into(),
            "alpha".into(),
            "color-light".into(),
            vec![],
            0,
            0,
        );
        // Live capability list drops `dimmer`.
        let dropped = store
            .reconcile_capabilities("dev-1", &["switch".to_string(), "color-light".to_string()]);
        assert_eq!(dropped, 1);
        assert_eq!(
            store
                .snapshot_capability("dev-1", "dimmer")
                .unwrap()
                .quality,
            StateQuality::Stale
        );
        assert_eq!(
            store
                .snapshot_capability("dev-1", "switch")
                .unwrap()
                .quality,
            StateQuality::Fresh
        );
        assert_eq!(
            store
                .snapshot_capability("dev-1", "color-light")
                .unwrap()
                .quality,
            StateQuality::Fresh
        );
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
        assert!(matches!(before.fields[0].value, Value::BoolVal(true)));
        let after = store.snapshot_capability("dev-1", "switch").unwrap();
        assert!(matches!(after.fields[0].value, Value::BoolVal(false)));
    }
}
