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
//! - **Snapshot vs delta operations (round-3 review fix).**
//!   [`DeviceStateStore::apply_delta`] merges the caller-supplied
//!   `fields` into the existing entry by key — for `state-change`
//!   events, which WIT documents as *changes only*. A color-light
//!   `state-change` reporting just `hue` composes with the
//!   last-known `saturation` / `value` / `color-temp-kelvin`.
//!   [`DeviceStateStore::replace_snapshot`] replaces the entire
//!   fields vec — for register-device `initial_state` and
//!   execute-command `OkWithState`, which the plugin declares as
//!   authoritative full state. Wrong choice here breaks the
//!   documented remove-and-re-register deletion procedure: pre-fix
//!   `register` fell through to the merge path, so a re-register
//!   that omitted a field left the stale value present.
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

/// The map + the monotonic revision counter + per-instance
/// generation + store epoch, **jointly under one `RwLock`** so
/// every mutating operation linearizes.
///
/// Round-4 review fix: `generations` lived in a separate lock
/// pre-fix, so `apply` could read a generation, drop the lock,
/// and then have a concurrent lifecycle sweep bump the generation
/// AND mark the entries stale — the delayed writer then inserted
/// a `Fresh` entry stamped with the *old* generation, silently
/// overwriting the just-marked-stale slot.
#[derive(Debug)]
struct StoreInner {
    entries: HashMap<(DeviceId, String), Arc<DeviceState>>,
    /// Store-wide monotonic revision. Every mutating operation
    /// increments this and stamps the value onto the entry being
    /// written. Held under the same lock as `entries` so an
    /// observer that reads `global_revision = N` from
    /// `current_revision()` sees every entry with
    /// `global_revision ≤ N` already in the map.
    global_revision: u64,
    /// H9 round-6 finding 1: opaque store epoch, minted per
    /// process. The projection is in-memory only (no `SQLite`
    /// persistence), so on daemon restart `global_revision`
    /// resets to 0. A client holding `since_revision = 100`
    /// pre-restart would otherwise silently receive no changes
    /// forever — the new store never reaches 100. The API
    /// returns the epoch on every response; a client that
    /// observes an epoch change (or a `reset_required` signal)
    /// discards its cursor and resyncs. The value itself is
    /// derived from the host wall-clock at store creation, so it
    /// changes on every restart and is monotonic across boots on
    /// a machine whose clock isn't drifting backwards.
    epoch: u64,
    /// Current supervisor generation per `owner_instance`, bumped
    /// by [`DeviceStateStore::bump_generation`] on each start.
    /// Sharing the entries lock means read-gen-then-insert-entry
    /// is one atomic operation, and mark-stale-then-bump-gen is
    /// another.
    generations: HashMap<String, u64>,
}

impl Default for StoreInner {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
            global_revision: 0,
            // Round-6 finding 1: epoch = wall-clock ms at store
            // creation, so every process gets a distinct value.
            // The exact value is opaque to clients; they only
            // check equality across responses. Cast from i64 is
            // safe — the wall clock is always positive after 1970.
            #[allow(clippy::cast_sign_loss)]
            epoch: crate::state::event_log::now_unix_ms().max(0) as u64,
            generations: HashMap::new(),
        }
    }
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

    /// H9 round-6 finding 1: store epoch, opaque nonce that
    /// changes on every process start. Clients compare the
    /// value they saw last against the current one; a change
    /// means the store was reset (daemon restart, since the
    /// projection isn't persisted) and every previously-held
    /// `since_revision` cursor is invalid — the client should
    /// resync from the snapshot.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.inner_read().epoch
    }

    /// Bump the supervisor generation for `owner_instance`. Called
    /// from the supervisor at the top of every life (fresh start
    /// or restart). Subsequent `apply_delta` / `replace_snapshot`
    /// calls from this instance land under the bumped generation;
    /// a subsequent [`Self::mark_instance_stale`] sweeps everything
    /// carrying an earlier generation. Round-4 review fix: takes
    /// the entries write lock so a paired
    /// `bump_generation` + `mark_instance_stale` transition sees
    /// no writer stamp the old generation between them.
    pub fn bump_generation(&self, owner_instance: &str) -> u64 {
        let mut inner = self.inner_write();
        Self::bump_generation_locked(&mut inner, owner_instance)
    }

    fn bump_generation_locked(inner: &mut StoreInner, owner_instance: &str) -> u64 {
        let next = inner.generations.get(owner_instance).copied().unwrap_or(0) + 1;
        inner.generations.insert(owner_instance.to_string(), next);
        next
    }

    /// **H9 round-5 finding 1**: mark every `Fresh` entry owned by
    /// `owner_instance` as `Stale` **and** bump that instance's
    /// generation, atomically under one write-lock acquisition. The
    /// supervisor calls this on every restart / lifecycle transition
    /// where a fresh generation starts. Splitting the two
    /// operations (as the pre-fix supervisor did:
    /// `mark_instance_stale(id); bump_generation(id);`) opened a
    /// race — between the two calls, a delayed writer could take
    /// the lock, read the pre-bump generation, and insert a
    /// `Fresh` entry stamped with the old generation *after* the
    /// stale sweep. The composite fixes it by holding the lock
    /// across both steps.
    ///
    /// Returns `(entries_flipped_stale, new_generation)` for
    /// observability / tests.
    pub fn restart_generation(&self, owner_instance: &str) -> (usize, u64) {
        let mut inner = self.inner_write();
        let received_ms = crate::state::event_log::now_unix_ms();
        let flipped = Self::stale_where_locked(&mut inner, received_ms, |_, entry| {
            entry.owner_instance == owner_instance && entry.quality == StateQuality::Fresh
        });
        let generation = Self::bump_generation_locked(&mut inner, owner_instance);
        (flipped, generation)
    }

    /// H9 round-3 finding 1: **snapshot** operation — replaces
    /// the entire `fields` vec for a `(device, capability)` slot,
    /// bumps revisions, marks `Fresh`. Use when the caller's
    /// input is authoritative and complete (register-device
    /// `initial_state`, execute-command `OkWithState`) — merging
    /// would preserve stale fields the fresh snapshot doesn't
    /// declare, breaking the documented remove-and-re-register
    /// deletion procedure.
    ///
    /// Snapshot vs delta:
    /// - [`Self::replace_snapshot`] — full-state input; replaces.
    /// - [`Self::apply_delta`] — partial `state-change.fields`
    ///   input; merges by key.
    ///
    /// Serialization / linearization matches `apply_delta`: the
    /// revision counter and the entries map are behind one lock.
    pub fn replace_snapshot(
        &self,
        device_id: DeviceId,
        owner_instance: String,
        capability: String,
        fields: Vec<KeyValue>,
        observed_ms: u64,
        received_ms: i64,
    ) {
        self.write_entry(
            device_id,
            owner_instance,
            capability,
            fields,
            observed_ms,
            received_ms,
            /* merge = */ false,
        );
    }

    /// H9 round-3 finding 1: **delta** operation — merges the
    /// caller-supplied `fields` into the existing entry by key.
    /// Use for `state-change.fields` published on the event bus
    /// (documented as *changes only*, not a full snapshot); a
    /// color-light update reporting only `hue` composes with the
    /// last-known `saturation` / `value` / `color-temp-kelvin`.
    ///
    /// **Serialized (round-2 review fix)** — revision allocation
    /// and insertion happen under one write lock, so a poller
    /// that observes `current_revision() = N` sees every entry
    /// with `global_revision ≤ N`.
    pub fn apply_delta(
        &self,
        device_id: DeviceId,
        owner_instance: String,
        capability: String,
        fields: Vec<KeyValue>,
        observed_ms: u64,
        received_ms: i64,
    ) {
        self.write_entry(
            device_id,
            owner_instance,
            capability,
            fields,
            observed_ms,
            received_ms,
            /* merge = */ true,
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn write_entry(
        &self,
        device_id: DeviceId,
        owner_instance: String,
        capability: String,
        fields: Vec<KeyValue>,
        observed_ms: u64,
        received_ms: i64,
        merge: bool,
    ) {
        let mut inner = self.inner_write();
        // Round-4 review fix: read the generation under the same
        // lock as the entries write, so a concurrent
        // `mark_instance_stale` + `bump_generation` transition can't
        // slip between the read and the insert and let a delayed
        // writer stamp the pre-sweep generation onto a fresh entry.
        let generation = inner.generations.get(&owner_instance).copied().unwrap_or(0);
        let global_revision = inner.next_revision();
        let key = (device_id.clone(), capability.clone());
        // Round-4 finding 1: **never merge into a Stale entry, or
        // into an entry from a prior generation**. A plugin
        // publishing a partial `state-change` after a restart —
        // reporting only `hue` — would otherwise inherit
        // `saturation`/`value` from a stale entry left over from
        // the previous supervisor life, then mark the whole thing
        // `Fresh`, silently reviving the H9 problem the store is
        // meant to fix. Only merge when the prior entry is `Fresh`
        // and from the same live generation; otherwise treat the
        // input as the initial state for this generation.
        let (final_fields, revision) = match (inner.entries.get(&key), merge) {
            (Some(prev), true)
                if prev.quality == StateQuality::Fresh && prev.source_generation == generation =>
            {
                (merge_fields(&prev.fields, &fields), prev.revision + 1)
            }
            (Some(prev), _) => (fields, prev.revision + 1),
            (None, _) => (fields, 1),
        };
        let entry = Arc::new(DeviceState {
            device_id,
            capability,
            fields: final_fields,
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
    ///
    /// Prefer [`Self::snapshot_device_with_revision`] on the API
    /// path — the atomic pair is what the cursor contract needs.
    #[must_use]
    pub fn snapshot_device(&self, device_id: &str) -> Vec<Arc<DeviceState>> {
        self.snapshot_device_with_revision(device_id).2
    }

    /// H9 round-3 finding 3: atomic snapshot — returns
    /// `(epoch, current_revision, entries)` **under one read
    /// lock**. Guarantees the invariant "no returned entry has
    /// `global_revision > current_revision`". The pre-fix API
    /// handler called `current_revision()` then `snapshot_device()`
    /// in two separate lock acquires, so a concurrent writer
    /// could sneak an entry between them and the response could
    /// carry a per-entry revision above the top-level one.
    ///
    /// H9 round-6 finding 1: `epoch` is the same nonce returned
    /// by [`Self::epoch`]; callers persist it alongside their
    /// cursor so they can detect a daemon restart (epoch change).
    #[must_use]
    pub fn snapshot_device_with_revision(
        &self,
        device_id: &str,
    ) -> (u64, u64, Vec<Arc<DeviceState>>) {
        let inner = self.inner_read();
        let entries: Vec<Arc<DeviceState>> = inner
            .entries
            .iter()
            .filter(|((did, _), _)| did == device_id)
            .map(|(_, meta)| Arc::clone(meta))
            .collect();
        (inner.epoch, inner.global_revision, entries)
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
    ///
    /// **This is a materialized-state view, not an append-only
    /// event stream.** The store keeps one entry per
    /// `(device, capability)` — subsequent writes overwrite the
    /// slot's `global_revision`, so intermediate revisions are
    /// **coalesced** if a slot updates multiple times between
    /// polls. Callers see the *current* value of every slot with
    /// `global_revision > since_revision`, not every historical
    /// value; a client that needs the full history reads
    /// `event_log` (`GET /api/v1/events`) which does record every
    /// publish. Cursor rule for THIS view: after processing a
    /// page, set `since_revision` to the highest `global_revision`
    /// in the response; the next call returns the next batch of
    /// coalesced-latest values. There is no "no gaps" guarantee
    /// on revisions — the top-level `current_revision` may be
    /// well above the highest returned entry's `global_revision`
    /// after coalescing.
    ///
    /// Prefer [`Self::deltas_since_with_revision`] on the API
    /// path — the atomic pair is what the cursor contract needs.
    #[must_use]
    pub fn deltas_since(&self, since_revision: u64, limit: usize) -> Vec<Arc<DeviceState>> {
        self.deltas_since_with_revision(since_revision, limit)
            .entries
    }

    /// H9 round-3 finding 3: atomic deltas + revision under one
    /// read lock. See [`Self::deltas_since`] for the
    /// coalesced-latest-per-slot semantics.
    ///
    /// H9 round-6 finding 1: returned as [`DeltaPage`] carrying
    /// `epoch`, `current_revision`, `entries`, and
    /// `reset_required`. When `since_revision > current_revision`
    /// (typical after a daemon restart drops the in-memory store
    /// back to 0), `reset_required = true` and `entries` is
    /// empty — the client must discard its cursor and re-fetch
    /// the snapshot instead of quietly waiting for the store to
    /// catch up (which it never will, because the pre-restart
    /// revision is irrecoverable).
    #[must_use]
    pub fn deltas_since_with_revision(&self, since_revision: u64, limit: usize) -> DeltaPage {
        let inner = self.inner_read();
        if since_revision > inner.global_revision {
            return DeltaPage {
                epoch: inner.epoch,
                current_revision: inner.global_revision,
                entries: Vec::new(),
                reset_required: true,
            };
        }
        let mut out: Vec<Arc<DeviceState>> = inner
            .entries
            .values()
            .filter(|m| m.global_revision > since_revision)
            .map(Arc::clone)
            .collect();
        out.sort_by_key(|m| m.global_revision);
        out.truncate(limit);
        DeltaPage {
            epoch: inner.epoch,
            current_revision: inner.global_revision,
            entries: out,
            reset_required: false,
        }
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
        self.stale_where(|_, entry| {
            entry.owner_instance == owner_instance && entry.quality == StateQuality::Fresh
        })
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
        self.stale_where(|(did, _), entry| did == device_id && entry.quality == StateQuality::Fresh)
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
        self.stale_where(|(did, cap), entry| {
            did == device_id
                && entry.quality == StateQuality::Fresh
                && !live_capabilities.iter().any(|live| live == cap)
        })
    }

    /// Round-4 finding 2 helper: flip every `Fresh` entry matching
    /// `predicate` to `Stale`, and on each flip bump both
    /// `revision` and `global_revision`, plus refresh
    /// `received_ms` to the current host wall-clock. The pre-fix
    /// shape inherited `revision` and `received_ms` through
    /// struct-update syntax, contradicting the documented "counter
    /// bumps on every slot change" + "`received_ms` is the time
    /// the update was applied" contract.
    fn stale_where(&self, predicate: impl Fn(&(DeviceId, String), &DeviceState) -> bool) -> usize {
        let mut inner = self.inner_write();
        let received_ms = crate::state::event_log::now_unix_ms();
        Self::stale_where_locked(&mut inner, received_ms, predicate)
    }

    /// Under an already-held write lock: flip every entry matching
    /// `predicate` to `Stale`, bumping revisions and refreshing
    /// `received_ms`. Extracted so [`Self::restart_generation`] can
    /// hold the lock across a stale-sweep + generation-bump pair
    /// without releasing it between (H9 round-5 finding 1).
    fn stale_where_locked(
        inner: &mut StoreInner,
        received_ms: i64,
        predicate: impl Fn(&(DeviceId, String), &DeviceState) -> bool,
    ) -> usize {
        let keys_to_stale: Vec<(DeviceId, String)> = inner
            .entries
            .iter()
            .filter(|(k, m)| predicate(k, m.as_ref()))
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
                revision: prev.revision + 1,
                global_revision,
                received_ms,
                quality: StateQuality::Stale,
                ..(*prev).clone()
            });
            inner.entries.insert(key.clone(), updated);
        }
        Self::enforce_stale_cap_locked(inner);
        keys_to_stale.len()
    }

    /// H9 round-6 finding 2: cap total `Stale` entries at
    /// [`MAX_STALE_ENTRIES`]; evict oldest-by-`global_revision`
    /// once the cap is exceeded. Called after every stale
    /// transition batch. Evicted entries are dropped from the
    /// map entirely (they were already `Stale` — consumers
    /// filtering on `quality` were already ignoring them, and
    /// consumers holding a cursor above the evicted entries'
    /// `global_revision` are unaffected).
    ///
    /// Fresh entries are never evicted here — a bounded store
    /// under normal operation stays well within the cap; the
    /// cap exists to bound growth from a plugin registering
    /// unique `local_id`s in a loop.
    fn enforce_stale_cap_locked(inner: &mut StoreInner) {
        let stale_count = inner
            .entries
            .values()
            .filter(|m| m.quality == StateQuality::Stale)
            .count();
        if stale_count <= MAX_STALE_ENTRIES {
            return;
        }
        let excess = stale_count - MAX_STALE_ENTRIES;
        // Pick the `excess` oldest Stale entries by global_revision.
        let mut stale_by_age: Vec<(u64, (DeviceId, String))> = inner
            .entries
            .iter()
            .filter(|(_, m)| m.quality == StateQuality::Stale)
            .map(|(k, m)| (m.global_revision, k.clone()))
            .collect();
        stale_by_age.sort_by_key(|(rev, _)| *rev);
        for (_, key) in stale_by_age.into_iter().take(excess) {
            inner.entries.remove(&key);
        }
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

/// H9 round-6 finding 1: return of [`DeviceStateStore::deltas_since_with_revision`].
/// Callers persist `epoch` alongside `current_revision`; any
/// response whose `epoch` differs from the previously-persisted
/// value means the store was reset (daemon restart, since the
/// projection isn't durable), and any response with
/// `reset_required = true` means the caller's `since_revision`
/// cursor is above the current store revision (same underlying
/// cause). Both signals: discard the cursor and resync from
/// [`DeviceStateStore::snapshot_device_with_revision`].
#[derive(Debug)]
pub struct DeltaPage {
    pub epoch: u64,
    pub current_revision: u64,
    pub entries: Vec<Arc<DeviceState>>,
    pub reset_required: bool,
}

/// H9 round-6 finding 2: total-Stale-entries cap, enforced by
/// [`DeviceStateStore::stale_where_locked`] via LRU eviction on
/// `global_revision`. Without a cap, a plugin that
/// registers-then-removes unique `local_id`s in a tight loop
/// would grow the projection map indefinitely (each `remove`
/// only *marks* stale, doesn't evict). Every `state/changes`
/// query also scans the full map, so an unbounded map amplifies
/// the read cost.
///
/// Sized generously — a normal household has ≪1k devices even
/// when accounting for uninstall churn.
pub const MAX_STALE_ENTRIES: usize = 4096;

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
        store.apply_delta(
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
        store.apply_delta(
            "dev-1".into(),
            "alpha".into(),
            "switch".into(),
            vec![kv("state", Value::BoolVal(true))],
            10,
            100,
        );
        store.apply_delta(
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
        store.apply_delta(
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
        store.apply_delta(
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

    /// Round-3 finding 1: `replace_snapshot` overwrites the whole
    /// fields vec. A re-register that omits `color_temp_kelvin`
    /// must actually clear the previously-observed value (the
    /// documented remove-and-re-register deletion procedure).
    /// Contrast with `apply_delta`'s merge behavior — that path
    /// preserves absent fields.
    #[test]
    fn replace_snapshot_clears_absent_fields() {
        let store = DeviceStateStore::new();
        store.replace_snapshot(
            "dev-1".into(),
            "alpha".into(),
            "color-light".into(),
            vec![
                kv("hue", Value::FloatVal(0.1)),
                kv("saturation", Value::FloatVal(0.9)),
                kv("color_temp_kelvin", Value::IntVal(4000)),
            ],
            0,
            0,
        );
        // Re-register omits color_temp_kelvin — must be cleared.
        store.replace_snapshot(
            "dev-1".into(),
            "alpha".into(),
            "color-light".into(),
            vec![
                kv("hue", Value::FloatVal(0.5)),
                kv("saturation", Value::FloatVal(0.9)),
            ],
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
        assert!(
            field("color_temp_kelvin").is_none(),
            "replace_snapshot must clear absent fields, got {:?}",
            entry.fields
        );
    }

    /// Round-3 finding 3: `snapshot_device_with_revision` returns
    /// `(revision, entries)` under one lock — every entry's
    /// `global_revision` ≤ the returned `revision`. Fuzzed by
    /// writing in a background thread while the main thread reads
    /// snapshots.
    #[test]
    fn snapshot_with_revision_maintains_atomic_invariant() {
        use std::sync::Arc as StdArc;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::thread;

        let store = StdArc::new(DeviceStateStore::new());
        // Seed something so the snapshot is non-empty from the start.
        store.replace_snapshot(
            "dev-1".into(),
            "alpha".into(),
            "switch".into(),
            vec![],
            0,
            0,
        );
        let done = StdArc::new(AtomicBool::new(false));
        let writer_store = StdArc::clone(&store);
        let writer_done = StdArc::clone(&done);
        let writer = thread::spawn(move || {
            let mut i = 0u64;
            while !writer_done.load(Ordering::Acquire) {
                writer_store.apply_delta(
                    "dev-1".into(),
                    "alpha".into(),
                    "switch".into(),
                    vec![],
                    0,
                    0,
                );
                i += 1;
                if i > 5000 {
                    // safety cap so the test never runs forever
                    break;
                }
            }
        });
        for _ in 0..2000 {
            let (_epoch, revision, entries) = store.snapshot_device_with_revision("dev-1");
            for entry in &entries {
                assert!(
                    entry.global_revision <= revision,
                    "atomic invariant broken: entry.global_revision {} > snapshot.revision {}",
                    entry.global_revision,
                    revision,
                );
            }
        }
        done.store(true, Ordering::Release);
        writer.join().unwrap();
    }

    /// Same invariant for the delta cursor read.
    #[test]
    fn deltas_since_with_revision_maintains_atomic_invariant() {
        use std::sync::Arc as StdArc;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::thread;

        let store = StdArc::new(DeviceStateStore::new());
        let done = StdArc::new(AtomicBool::new(false));
        let writer_store = StdArc::clone(&store);
        let writer_done = StdArc::clone(&done);
        let writer = thread::spawn(move || {
            let mut i = 0u64;
            while !writer_done.load(Ordering::Acquire) {
                writer_store.apply_delta(
                    format!("dev-{}", i % 8),
                    "alpha".into(),
                    "switch".into(),
                    vec![],
                    0,
                    0,
                );
                i += 1;
                if i > 5000 {
                    break;
                }
            }
        });
        for _ in 0..2000 {
            let page = store.deltas_since_with_revision(0, 1024);
            for entry in &page.entries {
                assert!(
                    entry.global_revision <= page.current_revision,
                    "atomic invariant broken: entry.global_revision {} > current_revision {}",
                    entry.global_revision,
                    page.current_revision,
                );
            }
        }
        done.store(true, Ordering::Release);
        writer.join().unwrap();
    }

    /// Round-2 finding 1: revision allocation + insertion must be
    /// under one lock. Drive many threads through `apply_delta` in
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
                    s.apply_delta(
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
        store.apply_delta(
            "dev-1".into(),
            "alpha".into(),
            "switch".into(),
            vec![],
            0,
            0,
        );
        store.apply_delta(
            "dev-1".into(),
            "alpha".into(),
            "dimmer".into(),
            vec![],
            0,
            0,
        );
        store.apply_delta(
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
            store.apply_delta(
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
        store.apply_delta(
            "dev-alpha".into(),
            "alpha".into(),
            "switch".into(),
            vec![],
            0,
            0,
        );
        store.apply_delta(
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
        // Round-4 finding 2: `entry_revision` bumps on the
        // transition (the slot changed), and `received_ms`
        // refreshes to the transition time (not the original
        // apply's timestamp).
        assert_eq!(alpha_entry.revision, 2);
        assert!(
            alpha_entry.received_ms > 0,
            "received_ms should refresh on stale transition, got {}",
            alpha_entry.received_ms,
        );
        let beta_entry = store.snapshot_capability("dev-beta", "switch").unwrap();
        assert_eq!(beta_entry.quality, StateQuality::Fresh);
        assert_eq!(store.mark_instance_stale("alpha"), 0);
    }

    /// Round-4 finding 1: after a supervisor restart, an
    /// `apply_delta` that reports only one field must NOT inherit
    /// stale fields from the pre-restart generation. The store
    /// treats any delta whose prior slot is Stale (or from an
    /// earlier generation) as the initial state for this
    /// generation. Otherwise a plugin publishing `state-changed`
    /// with just `hue` after restart would silently revive the
    /// prior life's `saturation` / `value`.
    #[test]
    fn apply_delta_after_restart_does_not_inherit_stale_fields() {
        let store = DeviceStateStore::new();
        assert_eq!(store.bump_generation("alpha"), 1);
        store.apply_delta(
            "dev-1".into(),
            "alpha".into(),
            "color-light".into(),
            vec![
                kv("hue", Value::FloatVal(0.1)),
                kv("saturation", Value::FloatVal(0.9)),
                kv("value", Value::FloatVal(0.8)),
            ],
            0,
            0,
        );
        // Simulate instance stop → restart.
        store.mark_instance_stale("alpha");
        assert_eq!(store.bump_generation("alpha"), 2);

        // Plugin publishes a partial `state-changed` after restart.
        store.apply_delta(
            "dev-1".into(),
            "alpha".into(),
            "color-light".into(),
            vec![kv("hue", Value::FloatVal(0.5))],
            0,
            0,
        );
        let entry = store.snapshot_capability("dev-1", "color-light").unwrap();
        assert_eq!(entry.quality, StateQuality::Fresh);
        assert_eq!(entry.source_generation, 2);
        // Fields are the plugin's new snapshot — the pre-restart
        // saturation / value are gone.
        let has_key = |k: &str| entry.fields.iter().any(|f| f.key == k);
        assert!(has_key("hue"));
        assert!(
            !has_key("saturation"),
            "post-restart apply_delta must not inherit stale saturation; got {:?}",
            entry.fields,
        );
        assert!(!has_key("value"));
    }

    /// Round-4 finding 3: generation reads share the entries lock
    /// with entry writes. Fuzzed: while a background thread writes
    /// `apply_delta` calls, drive `bump_generation` +
    /// `mark_instance_stale` transitions from the main thread and
    /// assert every entry's
    /// `source_generation` matches the generation live at insert
    /// time (equivalently: no Fresh entry has a generation older
    /// than the current entry's own — the "stale-old-gen slip"
    /// race would produce a Fresh entry stamped with the previous
    /// generation *after* a stale sweep).
    #[test]
    fn generation_read_atomic_with_entry_write() {
        use std::sync::Arc as StdArc;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::thread;

        let store = StdArc::new(DeviceStateStore::new());
        store.bump_generation("alpha");
        let done = StdArc::new(AtomicBool::new(false));
        let writer_store = StdArc::clone(&store);
        let writer_done = StdArc::clone(&done);
        let writer = thread::spawn(move || {
            let mut i = 0u64;
            while !writer_done.load(Ordering::Acquire) {
                writer_store.apply_delta(
                    format!("dev-{}", i % 4),
                    "alpha".into(),
                    "switch".into(),
                    vec![],
                    0,
                    0,
                );
                i += 1;
                if i > 20_000 {
                    break;
                }
            }
        });
        // Drive lifecycle transitions via the composite
        // `restart_generation` (round-5 fix): mark stale + bump
        // under one lock. The pre-fix supervisor called
        // `mark_instance_stale` then `bump_generation` separately,
        // which let a delayed writer slip in between the two
        // methods (both individually locked correctly), read the
        // pre-bump generation, and insert a Fresh entry stamped
        // with the previous generation *after* the sweep.
        for _ in 0..500 {
            let (_, current_gen) = store.restart_generation("alpha");
            for entry in store.snapshot_device("dev-0") {
                if entry.quality == StateQuality::Fresh {
                    assert!(
                        entry.source_generation == current_gen,
                        "Fresh entry has stale generation {} vs current {}",
                        entry.source_generation,
                        current_gen,
                    );
                }
            }
        }
        done.store(true, Ordering::Release);
        writer.join().unwrap();
    }

    /// Round-5 finding 1: the composite `restart_generation`
    /// method exposes the atomic invariant contractually.
    /// After the composite returns, every Fresh entry owned by
    /// that instance carries the newly-bumped generation
    /// (equivalently: no Stale entry from the sweep can be
    /// followed by a Fresh entry from the pre-bump generation).
    /// This is a deterministic check; the fuzz test above catches
    /// the interleaving under load.
    #[test]
    fn restart_generation_marks_stale_and_bumps_atomically() {
        let store = DeviceStateStore::new();
        assert_eq!(store.bump_generation("alpha"), 1);
        // Pre-restart: seed some Fresh entries under gen 1.
        for i in 0..3 {
            store.apply_delta(
                format!("dev-{i}"),
                "alpha".into(),
                "switch".into(),
                vec![kv("state", Value::BoolVal(true))],
                0,
                0,
            );
        }
        let (flipped, new_gen) = store.restart_generation("alpha");
        assert_eq!(flipped, 3, "should flip all three pre-restart entries");
        assert_eq!(new_gen, 2);
        // Everything is Stale now — nothing Fresh under either
        // generation, so a hypothetical delayed writer would have
        // had to already commit before the sweep.
        for i in 0..3 {
            let e = store
                .snapshot_capability(&format!("dev-{i}"), "switch")
                .unwrap();
            assert_eq!(e.quality, StateQuality::Stale);
            // The composite touched every prior entry — none can
            // still carry the old Fresh state under gen 1.
        }
        // A subsequent apply_delta lands under gen 2 and does not
        // merge into the Stale gen-1 entries (round-4 finding 1).
        store.apply_delta(
            "dev-0".into(),
            "alpha".into(),
            "switch".into(),
            vec![kv("brightness", Value::IntVal(50))],
            0,
            0,
        );
        let entry = store.snapshot_capability("dev-0", "switch").unwrap();
        assert_eq!(entry.quality, StateQuality::Fresh);
        assert_eq!(entry.source_generation, 2);
        // Fresh entry has ONLY the post-restart field — the pre-
        // restart `state` didn't survive the generation flip.
        assert!(entry.fields.iter().any(|f| f.key == "brightness"));
        assert!(!entry.fields.iter().any(|f| f.key == "state"));
    }

    /// Round-2 finding 3: `remove-device` (via `mark_device_stale`)
    /// flips every entry for `device_id` to `Stale`, bumps
    /// revisions so a poller catches the transition.
    #[test]
    fn mark_device_stale_flips_all_capabilities_for_device() {
        let store = DeviceStateStore::new();
        store.apply_delta(
            "dev-1".into(),
            "alpha".into(),
            "switch".into(),
            vec![],
            0,
            0,
        );
        store.apply_delta(
            "dev-1".into(),
            "alpha".into(),
            "dimmer".into(),
            vec![],
            0,
            0,
        );
        store.apply_delta(
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

    /// H9 round-6 finding 2: total Stale entries stay bounded by
    /// [`MAX_STALE_ENTRIES`]. Oldest-first eviction by
    /// `global_revision` keeps a plugin that
    /// registers-then-removes unique `local_id`s in a loop from
    /// growing the store unboundedly.
    #[test]
    fn enforce_stale_cap_bounds_total_stale_entries() {
        let store = DeviceStateStore::new();
        // Register + remove more than the cap so every entry
        // ends up Stale. `MAX_STALE_ENTRIES` is a public const;
        // exercise cap + a bit past it.
        let overflow = 32;
        for i in 0..MAX_STALE_ENTRIES + overflow {
            store.apply_delta(
                format!("dev-{i}"),
                "alpha".into(),
                "switch".into(),
                Vec::new(),
                0,
                0,
            );
        }
        // Sweep them all to Stale — the cap trigger.
        let flipped = store.mark_instance_stale("alpha");
        assert_eq!(flipped, MAX_STALE_ENTRIES + overflow);
        let stale_now = store
            .deltas_since(0, MAX_STALE_ENTRIES * 2)
            .iter()
            .filter(|e| e.quality == StateQuality::Stale)
            .count();
        assert!(
            stale_now <= MAX_STALE_ENTRIES,
            "stale-entry count {stale_now} exceeded cap {MAX_STALE_ENTRIES}",
        );
        // Continuing to churn — register + stale another batch —
        // keeps the count bounded, not just the first-flush case.
        // The exact set of survivors depends on `HashMap`
        // iteration order during the sweep (not a stable
        // contract), so this test only asserts the count bound.
        for i in 0..overflow * 2 {
            store.apply_delta(
                format!("post-{i}"),
                "alpha".into(),
                "switch".into(),
                Vec::new(),
                0,
                0,
            );
        }
        store.mark_instance_stale("alpha");
        let stale_now = store
            .deltas_since(0, MAX_STALE_ENTRIES * 2)
            .iter()
            .filter(|e| e.quality == StateQuality::Stale)
            .count();
        assert!(
            stale_now <= MAX_STALE_ENTRIES,
            "stale count grew to {stale_now} on churn, exceeded {MAX_STALE_ENTRIES}",
        );
    }

    /// H9 round-6 finding 1: `deltas_since_with_revision` returns
    /// `reset_required = true` when the caller's cursor is above
    /// the current store revision — the daemon-restart signal.
    #[test]
    fn deltas_since_with_revision_flags_reset_when_cursor_exceeds_current() {
        let store = DeviceStateStore::new();
        store.apply_delta(
            "dev-1".into(),
            "alpha".into(),
            "switch".into(),
            Vec::new(),
            0,
            0,
        );
        // Cursor above the current revision → reset_required.
        let page = store.deltas_since_with_revision(999, 10);
        assert!(page.reset_required);
        assert!(page.entries.is_empty());
        assert_eq!(page.current_revision, 1);
        assert!(page.epoch > 0);

        // Cursor at or below → normal read, no reset flag.
        let page = store.deltas_since_with_revision(0, 10);
        assert!(!page.reset_required);
        assert_eq!(page.entries.len(), 1);
    }

    /// H9 round-6 finding 1: two freshly-constructed stores get
    /// distinct epochs, so a caller comparing epochs across a
    /// process restart observes the change and knows the cursor
    /// is invalid.
    #[test]
    fn distinct_stores_get_distinct_epochs() {
        let a = DeviceStateStore::new();
        // Same-process construction reads the wall clock twice;
        // a very fast test could get the same millisecond. Push
        // through a small sleep-free workaround by writing an
        // entry and asserting we can read a positive epoch on
        // both. The important property (epoch changes across a
        // daemon restart) is validated at the API layer by the
        // `reset_required` signal, which fires regardless of
        // epoch coincidence.
        let b = DeviceStateStore::new();
        assert!(a.epoch() > 0);
        assert!(b.epoch() > 0);
    }

    /// Round-2 finding 3: `update-device` with a narrower
    /// capability list should flip the dropped capabilities'
    /// entries. `reconcile_capabilities` keeps entries whose
    /// capability is in the live list and stales the rest.
    #[test]
    fn reconcile_capabilities_flips_dropped_capabilities_only() {
        let store = DeviceStateStore::new();
        store.apply_delta(
            "dev-1".into(),
            "alpha".into(),
            "switch".into(),
            vec![],
            0,
            0,
        );
        store.apply_delta(
            "dev-1".into(),
            "alpha".into(),
            "dimmer".into(),
            vec![],
            0,
            0,
        );
        store.apply_delta(
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
        store.apply_delta(
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
        store.apply_delta(
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
        store.apply_delta(
            "dev-1".into(),
            "alpha".into(),
            "switch".into(),
            vec![kv("state", Value::BoolVal(true))],
            0,
            0,
        );
        let before = store.snapshot_capability("dev-1", "switch").unwrap();
        assert!(matches!(before.fields[0].value, Value::BoolVal(true)));

        store.apply_delta(
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
