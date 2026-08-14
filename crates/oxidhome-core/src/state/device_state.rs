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

use std::collections::{BTreeMap, HashMap};
use std::ops::Bound;
use std::sync::{Arc, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};

use rand::TryRng;

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
    /// Store-wide monotonic revision at which this update was
    /// applied. Callers of the delta API pass a `since_revision`;
    /// entries with `global_revision > since_revision` are what
    /// they haven't seen. **The only ordering axis** — there is
    /// no per-key counter (H9 round-9 finding 1: a per-key
    /// counter would have to survive stale-cap eviction, which
    /// either grows the store unboundedly with tombstones or
    /// forces global epoch rotation on every eviction — an
    /// attack vector where one plugin churning unique
    /// `local_id`s past the 4096 cap would trigger a
    /// process-wide resync for every API client).
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
    /// H9 round-12 finding 2: keyed on `(device_id, capability)`
    /// in a `BTreeMap` so pagination can `range` from the cursor
    /// in `O(log N + k)` without scanning + sorting the entire
    /// store on every request. Point lookups (`write_entry`,
    /// `snapshot_capability`) become `O(log N)` rather than
    /// `O(1)`, but at the store's expected size (≤ a few
    /// thousand entries per host) that's a handful of
    /// comparisons — well below the noise of a wasm host call.
    entries: BTreeMap<(DeviceId, String), Arc<DeviceState>>,
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
    /// discards its cursor and resyncs.
    ///
    /// Round-7 finding 2: the value is a 128-bit OS-random nonce
    /// hex-encoded as a String (not a wall-clock ms), so
    /// distinct stores collide with negligible probability
    /// (2⁻¹²⁸ per rebuild), regardless of clock resolution or
    /// timing. String-encoded so JavaScript clients (which lose
    /// precision above 2⁵³ on the Number type) can compare it
    /// as an ordinary string identifier.
    epoch: String,
    /// H9 round-7 finding 1: highest `global_revision` of any
    /// stale entry ever evicted by [`Self::enforce_stale_cap_locked`].
    /// A client with `since_revision < evicted_through_revision`
    /// may have missed the stale-transition-and-eviction path
    /// of a slot they cached as `Fresh`, so
    /// [`Self::deltas_since_with_revision`] returns
    /// `reset_required: true` on that condition. Pre-fix, only
    /// `since_revision > current_revision` triggered a reset —
    /// so a cursor *below* the current revision but above what
    /// eviction had swept could silently miss removals.
    evicted_through_revision: u64,
    /// Current supervisor generation per `owner_instance`, bumped
    /// by [`DeviceStateStore::bump_generation`] on each start.
    /// Sharing the entries lock means read-gen-then-insert-entry
    /// is one atomic operation, and mark-stale-then-bump-gen is
    /// another.
    generations: HashMap<String, u64>,
    /// H9 round-14 finding 3: per-process 256-bit random secret
    /// used to HMAC-sign the resync pagination cursor exposed
    /// by `GET /api/v1/devices/state`. The cursor payload
    /// (`epoch.revision.device_id`) travels in plain-text so
    /// the server can decode it, but the trailing MAC ties
    /// each cursor to *this* store's secret — a client can't
    /// forge a cursor with a modified revision or device id
    /// even though the epoch is publicly visible.
    ///
    /// Stays constant for the lifetime of the store (i.e., the
    /// daemon process): a restart mints a new secret, but
    /// also mints a new `epoch`, so any cursor from the prior
    /// life fails epoch verification long before the MAC
    /// check ever fires.
    cursor_secret: [u8; 32],
}

impl Default for StoreInner {
    fn default() -> Self {
        Self {
            entries: BTreeMap::new(),
            global_revision: 0,
            epoch: mint_epoch(),
            evicted_through_revision: 0,
            generations: HashMap::new(),
            cursor_secret: mint_cursor_secret(),
        }
    }
}

/// H9 round-14 finding 3: 256-bit OS-random secret used to
/// HMAC-sign the resync-pagination cursor. See
/// [`StoreInner::cursor_secret`].
fn mint_cursor_secret() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    rand::rngs::SysRng
        .try_fill_bytes(&mut bytes)
        .expect("system RNG must be available");
    bytes
}

/// H9 round-7 finding 2: 128-bit OS-random nonce, hex-encoded.
/// Called from [`StoreInner::default`] — every fresh store gets
/// a distinct opaque identifier that clients compare as a
/// string. String encoding sidesteps JavaScript's 2⁵³ integer
/// precision limit; hex is the same shape as
/// `installed_plugins::mint_installation_uuid`.
fn mint_epoch() -> String {
    let mut bytes = [0u8; 16];
    // `SysRng::try_fill_bytes` returns `Result<(), Infallible>` on
    // supported platforms; `.expect` documents the "must be
    // available" operational contract (same shape as
    // `mint_installation_uuid`).
    rand::rngs::SysRng
        .try_fill_bytes(&mut bytes)
        .expect("system RNG must be available");
    let mut hex = String::with_capacity(6 + 32);
    hex.push_str("epoch-");
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(hex, "{b:02x}");
    }
    hex
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
    ///
    /// Round-7 finding 2: string, not integer — a 128-bit
    /// OS-random nonce so distinct stores collide with
    /// negligible probability, and JavaScript clients can
    /// compare it losslessly.
    #[must_use]
    pub fn epoch(&self) -> String {
        self.inner_read().epoch.clone()
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

    #[allow(clippy::too_many_arguments, clippy::needless_pass_by_value)]
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
        // H9 round-13 finding 2: cap the slot's field count so
        // `apply_delta` with unique keys can't grow one slot
        // without bound. `replace_snapshot` also gets capped
        // (truncate to first MAX_FIELDS_PER_SLOT) — the input
        // can carry arbitrary field count, and letting a
        // register-device install a slot already at 10 000
        // fields defeats the point.
        let final_fields = match (inner.entries.get(&key), merge) {
            (Some(prev), true)
                if prev.quality == StateQuality::Fresh && prev.source_generation == generation =>
            {
                let (merged, dropped) = merge_fields(&prev.fields, &fields);
                if dropped > 0 {
                    tracing::warn!(
                        target: "device_state.slot_field_cap",
                        device_id = %device_id,
                        capability = %capability,
                        dropped,
                        cap = MAX_FIELDS_PER_SLOT,
                        "apply_delta dropped {dropped} new field(s): per-slot cap reached",
                    );
                }
                merged
            }
            _ => {
                // H9 round-16 finding 1: canonicalize the
                // snapshot input by folding duplicate keys
                // last-wins BEFORE storing. Pre-fix, an
                // `OkWithState([state=true, state=false])`
                // (or a register-device `initial_state`
                // with duplicate keys) went into the
                // projection unchanged — the wire response
                // and REST HashMap conversion disagreed
                // about which value was authoritative, and
                // a later `apply_delta` updated only the
                // first match, leaving contradictory
                // values in the same slot forever.
                let mut f = merge_fields_unbounded(&[], &fields);
                if f.len() > MAX_FIELDS_PER_SLOT {
                    let dropped = f.len() - MAX_FIELDS_PER_SLOT;
                    tracing::warn!(
                        target: "device_state.slot_field_cap",
                        device_id = %device_id,
                        capability = %capability,
                        dropped,
                        cap = MAX_FIELDS_PER_SLOT,
                        "replace_snapshot truncated {dropped} field(s): per-slot cap exceeded",
                    );
                    f.truncate(MAX_FIELDS_PER_SLOT);
                }
                f
            }
        };
        // H9 round-15 finding 2: byte-cap backstop. Admission
        // at the WIT boundary catches the common case
        // correctly (round-15 fixed the last-wins-with-
        // duplicates math), but the store's write path is
        // reachable from direct-callers (tests, in-process
        // helpers) and rare cross-instance races. Drop
        // trailing fields until the total serialized size
        // fits `MAX_BYTES_PER_SLOT`, matching the
        // field-count backstop pattern above.
        let final_fields = truncate_to_byte_cap(final_fields, &device_id, &capability);
        let entry = Arc::new(DeviceState {
            device_id,
            capability,
            fields: final_fields,
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
    ) -> (String, u64, Vec<Arc<DeviceState>>) {
        let inner = self.inner_read();
        let entries: Vec<Arc<DeviceState>> = inner
            .entries
            .iter()
            .filter(|((did, _), _)| did == device_id)
            .map(|(_, meta)| Arc::clone(meta))
            .collect();
        (inner.epoch.clone(), inner.global_revision, entries)
    }

    /// H9 round-10 finding 2 / round-11 finding 1 / round-12
    /// findings 1+2: full-store snapshot **page** for
    /// `reset_required` recovery.
    ///
    /// Returns entries strictly after `after_device_id`
    /// (or from the start if `None`), grouped so all
    /// capabilities of one device land on the same page,
    /// capped at `device_limit` distinct devices. Reads
    /// `epoch` + `global_revision` under the same read lock
    /// as the range scan, so a single page is internally
    /// consistent.
    ///
    /// Round-12 finding 2: uses `BTreeMap::range` from
    /// `(cursor, MAX)` exclusive, iterates lazily, and stops
    /// after `device_limit` distinct device ids. Cost:
    /// `O(log N + k · caps-per-device)` — no full-store
    /// clone-then-sort, and the lock is released the moment
    /// the page fills.
    ///
    /// Round-12 finding 1: cross-page consistency is the
    /// **caller's** responsibility. The caller pins the
    /// resync anchor to the revision returned on the *first*
    /// page and, after paging through the full set, uses
    /// that pinned value as the `since_revision` for
    /// subsequent `/state/changes` polls — so any write that
    /// happened during pagination (including to devices
    /// sorting behind the current cursor, or to devices
    /// registered mid-pagination) is picked up on the next
    /// cursor poll. The API handler enforces this by
    /// echoing the pinned revision through subsequent pages.
    #[must_use]
    pub fn snapshot_page_with_revision(
        &self,
        after_device_id: Option<&str>,
        device_limit: usize,
    ) -> (String, u64, Vec<Arc<DeviceState>>) {
        let inner = self.inner_read();
        let start = match after_device_id {
            Some(cursor) => Bound::Excluded((cursor.to_string(), MAX_CAP_SENTINEL.to_string())),
            None => Bound::Unbounded,
        };
        let mut entries: Vec<Arc<DeviceState>> = Vec::new();
        let mut distinct_devices: usize = 0;
        let mut current_device: Option<&DeviceId> = None;
        for ((did, _cap), entry) in inner.entries.range((start, Bound::Unbounded)) {
            if current_device != Some(did) {
                if distinct_devices >= device_limit {
                    break;
                }
                distinct_devices += 1;
                current_device = Some(did);
            }
            entries.push(Arc::clone(entry));
        }
        (inner.epoch.clone(), inner.global_revision, entries)
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

    /// H9 round-14 finding 1: pre-check whether an
    /// `apply_delta` would push the slot past
    /// [`MAX_FIELDS_PER_SLOT`] or [`MAX_BYTES_PER_SLOT`].
    /// Callers invoke this at the WIT boundary before
    /// persisting the event log record and before updating
    /// the projection, so an oversized `state-change` is
    /// rejected outright instead of the projection silently
    /// desyncing from the durable log and the bus fanout
    /// (round-13's silent truncation).
    ///
    /// H9 round-15 finding 1: the admission math mirrors
    /// [`Self::write_entry`]'s merge-vs-replace rule.
    /// `apply_delta` only *merges* into a Fresh entry from
    /// the caller's current generation; otherwise it treats
    /// the incoming vec as a replace. Round-14 baselined
    /// against the existing slot unconditionally, so a
    /// post-restart 64-field Stale slot + a one-field
    /// delta got counted as 65 fields and rejected —
    /// even though the write would have replaced the slot
    /// with just that one field.
    ///
    /// H9 round-15 finding 2: the incoming vec is
    /// **normalized to last-wins per key** before
    /// measuring. Round-14 subtracted the existing value's
    /// bytes for every duplicate occurrence of a key,
    /// under-counting the merged result. E.g. an existing
    /// `{a=40 KiB, b=20 KiB}` + incoming `[a="", a=<50 KiB>]`
    /// used to project to 50 KiB but actually writes 70 KiB.
    /// Normalizing first captures the last value only —
    /// which is what `merge_fields` observes after applying
    /// updates sequentially.
    ///
    /// # Errors
    /// [`SlotCapExceeded`] with the offending measurement.
    pub fn check_delta_admission(
        &self,
        device_id: &str,
        owner_instance: &str,
        capability: &str,
        incoming: &[KeyValue],
    ) -> Result<(), SlotCapExceeded> {
        let inner = self.inner_read();
        let key = (device_id.to_string(), capability.to_string());
        // Round-15 finding 1: only take the existing slot as
        // the merge baseline if the write path would too.
        // See `write_entry`.
        let caller_generation = inner.generations.get(owner_instance).copied().unwrap_or(0);
        let existing_slot = inner.entries.get(&key);
        let baseline: &[KeyValue] = existing_slot
            .filter(|prev| {
                prev.quality == StateQuality::Fresh && prev.source_generation == caller_generation
            })
            .map_or(&[][..], |prev| prev.fields.as_slice());
        // Round-15 finding 2: last-wins normalization of
        // duplicates in the incoming vec, matching
        // `merge_fields`'s sequential-apply semantics.
        // Uses an *unbounded* merge (unlike `merge_fields`,
        // which silently truncates at the field cap): the
        // whole point of admission is to see the true
        // merged size and reject at the WIT boundary.
        let projected = merge_fields_unbounded(baseline, incoming);
        check_slot_caps(projected.len(), fields_byte_estimate(&projected))?;
        // Round-16 finding 2: per-instance aggregate bytes
        // cap. Compute (existing owner total − old slot
        // bytes for this write's key + projected slot
        // bytes) and reject if the sum exceeds the cap.
        // A write that replaces an existing slot doesn't
        // double-count the old bytes.
        let projected_bytes = fields_byte_estimate(&projected);
        // Round-17 finding 3: only subtract the old slot's
        // bytes if it was Fresh (Stale bytes are excluded
        // from the owner's aggregate total, so subtracting
        // them would under-count).
        let old_slot_bytes = existing_slot
            .filter(|e| e.quality == StateQuality::Fresh)
            .map_or(0, |e| fields_byte_estimate(&e.fields));
        check_instance_caps_locked(&inner, owner_instance, old_slot_bytes, projected_bytes)
    }

    /// H9 round-14 finding 1: pre-check whether a
    /// `replace_snapshot` (register-device `initial_state`
    /// or execute-command `OkWithState`) exceeds the per-
    /// slot caps. Unlike `apply_delta`, replace ignores the
    /// existing slot, so the check is purely on the
    /// incoming vec.
    ///
    /// H9 round-16 finding 1: measures the vec *after*
    /// deduplicating duplicate keys last-wins, matching
    /// what the write path stores. Without this, a
    /// snapshot like `[state=<big1>, state=<big2>]` would
    /// count both values toward the byte cap even though
    /// only `<big2>` reaches the projection.
    ///
    /// # Errors
    /// [`SlotCapExceeded`] with the offending measurement.
    pub fn check_snapshot_admission(fields: &[KeyValue]) -> Result<(), SlotCapExceeded> {
        let deduped = merge_fields_unbounded(&[], fields);
        check_slot_caps(deduped.len(), fields_byte_estimate(&deduped))
    }

    /// H9 round-17 finding 2: fold duplicate keys in
    /// `fields` last-wins, returning the canonical vec
    /// the projection would store for a `replace_snapshot`
    /// or `OkWithState`. Callers wrap this around any
    /// snapshot vec that also feeds a wire response (the
    /// `execute-command` result) so the projection, the
    /// REST `HashMap` conversion, and the Connect RPC
    /// duplicate-preserving encoding all agree on which
    /// values are authoritative.
    #[must_use]
    pub fn canonicalize_snapshot_fields(fields: &[KeyValue]) -> Vec<KeyValue> {
        merge_fields_unbounded(&[], fields)
    }

    /// H9 round-16 finding 2: pre-check whether accepting a
    /// single-slot snapshot-shape write (`OkWithState`) for
    /// `owner_instance` on `(device_id, capability)` would
    /// push that instance's aggregate projected bytes past
    /// [`MAX_PROJECTED_BYTES_PER_INSTANCE`]. Called from
    /// `execute_command` alongside
    /// [`Self::check_snapshot_admission`] (which handles
    /// the per-slot cap). Separated because the per-slot
    /// check doesn't need to know the owner, while the
    /// aggregate check does.
    ///
    /// # Errors
    /// [`SlotCapExceeded::Instance`] with the offending
    /// aggregate.
    pub fn check_instance_snapshot_admission(
        &self,
        device_id: &str,
        owner_instance: &str,
        capability: &str,
        incoming: &[KeyValue],
    ) -> Result<(), SlotCapExceeded> {
        let inner = self.inner_read();
        let key = (device_id.to_string(), capability.to_string());
        // Round-17 finding 3: Stale slot bytes are excluded
        // from the owner's aggregate — subtract only Fresh
        // ones to stay symmetric.
        let old_slot_bytes = inner
            .entries
            .get(&key)
            .filter(|e| e.quality == StateQuality::Fresh)
            .map_or(0, |e| fields_byte_estimate(&e.fields));
        let deduped = merge_fields_unbounded(&[], incoming);
        let projected_bytes = fields_byte_estimate(&deduped);
        check_instance_caps_locked(&inner, owner_instance, old_slot_bytes, projected_bytes)
    }

    /// H9 round-16 finding 2: batch pre-check for
    /// `register-device` — verifies that the whole
    /// `initial_state` seed, taken together with all
    /// existing entries owned by `owner_instance` (minus the
    /// bytes the register will replace for this device),
    /// stays within
    /// [`MAX_PROJECTED_BYTES_PER_INSTANCE`]. Necessary
    /// because a register call installs multiple slots for
    /// one device in one atomic step; a per-slot check
    /// couldn't see the cumulative effect until it was too
    /// late to reject.
    ///
    /// # Errors
    /// [`SlotCapExceeded::Instance`] with the offending
    /// aggregate.
    pub fn check_instance_register_admission(
        &self,
        device_id: &str,
        owner_instance: &str,
        seed_state: &[(String, Vec<KeyValue>)],
    ) -> Result<(), SlotCapExceeded> {
        let inner = self.inner_read();
        // Sum Fresh bytes of the existing slots for this
        // device (regardless of capability) — the register
        // will replace them wholesale. Round-17 finding 3:
        // Stale bytes are excluded from the owner's
        // aggregate, so they must be excluded from the
        // subtract-baseline too.
        let old_device_bytes: usize = inner
            .entries
            .iter()
            .filter(|((did, _), e)| did == device_id && e.quality == StateQuality::Fresh)
            .map(|(_, e)| fields_byte_estimate(&e.fields))
            .sum();
        // Sum of the new (deduped) slot bytes across the
        // whole seed.
        let new_device_bytes: usize = seed_state
            .iter()
            .map(|(_, fields)| {
                let deduped = merge_fields_unbounded(&[], fields);
                fields_byte_estimate(&deduped)
            })
            .sum();
        check_instance_caps_locked(&inner, owner_instance, old_device_bytes, new_device_bytes)
    }

    /// H9 round-14 finding 3: sign an all-devices-snapshot
    /// pagination cursor. Returns
    /// `"<epoch>.<pinned_revision>.<after_device_id>.<hmac>"`
    /// where `hmac` is a 128-bit prefix of HMAC-SHA256 keyed
    /// on this store's per-process
    /// [`StoreInner::cursor_secret`]. Because the secret is
    /// server-side only, a client can neither forge a valid
    /// cursor from scratch nor mutate the pinned revision /
    /// device id in an existing one without the MAC failing
    /// verification.
    #[must_use]
    pub fn issue_cursor(&self, pinned_revision: u64, after_device_id: &str) -> String {
        let inner = self.inner_read();
        let payload = format!("{}.{pinned_revision}.{after_device_id}", inner.epoch);
        let mac = hmac_sha256(&inner.cursor_secret, payload.as_bytes());
        let mut hex = String::with_capacity(32);
        for b in &mac[..16] {
            use std::fmt::Write as _;
            let _ = write!(hex, "{b:02x}");
        }
        format!("{payload}.{hex}")
    }

    /// H9 round-14 finding 3: verify + decode a paginated
    /// cursor issued by [`Self::issue_cursor`]. Returns
    /// `(epoch, pinned_revision, after_device_id)` on
    /// success. Malformed shape, bad revision, or MAC
    /// mismatch → `Err(CursorError::Bad)`. Well-formed
    /// cursor whose epoch no longer matches the store's
    /// current epoch → `Err(CursorError::EpochChanged)`.
    ///
    /// H9 round-15 finding 3: **epoch comparison happens
    /// before MAC verification**. A cursor issued by a
    /// prior life of the daemon has both a stale epoch AND
    /// a stale MAC (because a restart rotates
    /// [`StoreInner::cursor_secret`] alongside
    /// [`StoreInner::epoch`]); round-14 checked the MAC
    /// first, so every legitimate pre-restart cursor
    /// failed as `Bad` (→ 400) instead of `EpochChanged`
    /// (→ 409). Reordering is safe: the epoch is public
    /// information (every response emits it), so
    /// short-circuiting on epoch mismatch doesn't leak
    /// anything a fabricated cursor couldn't already
    /// discover, and it lets the handler tell the
    /// documented "daemon restarted, restart the resync"
    /// story instead of a 400 that reads as a client bug.
    ///
    /// # Errors
    /// See [`CursorError`].
    pub fn verify_cursor(&self, raw: &str) -> Result<(String, u64, String), CursorError> {
        let (payload, mac_hex) = raw.rsplit_once('.').ok_or(CursorError::Bad)?;
        let mut parts = payload.splitn(3, '.');
        let epoch = parts.next().ok_or(CursorError::Bad)?;
        let rev = parts.next().ok_or(CursorError::Bad)?;
        let device = parts.next().ok_or(CursorError::Bad)?;
        if epoch.is_empty() || device.is_empty() || mac_hex.len() != 32 {
            return Err(CursorError::Bad);
        }
        let pinned_revision = rev.parse::<u64>().map_err(|_| CursorError::Bad)?;
        let inner = self.inner_read();
        // Round-15 finding 3: epoch check first — a
        // pre-restart cursor cleanly surfaces as
        // `EpochChanged` even though its MAC is signed
        // with the previous life's secret.
        if epoch != inner.epoch {
            return Err(CursorError::EpochChanged);
        }
        let expected = hmac_sha256(&inner.cursor_secret, payload.as_bytes());
        let mut supplied = [0u8; 16];
        for (i, chunk) in mac_hex.as_bytes().chunks(2).enumerate() {
            supplied[i] = u8::from_str_radix(
                std::str::from_utf8(chunk).map_err(|_| CursorError::Bad)?,
                16,
            )
            .map_err(|_| CursorError::Bad)?;
        }
        if !constant_time_eq(&expected[..16], &supplied) {
            return Err(CursorError::Bad);
        }
        Ok((epoch.to_string(), pinned_revision, device.to_string()))
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
    ///
    /// H9 round-7 finding 1: also sets `reset_required = true`
    /// when `since_revision < evicted_through_revision` — the
    /// stale-cap sweep may have evicted transitions the client
    /// hadn't yet observed (e.g. a `Fresh → Stale` flip that
    /// dropped from the map because too many other stale slots
    /// accumulated). Pre-fix, only the above-current case
    /// triggered a reset, so a cursor *below* the current
    /// revision but *below* the eviction watermark silently
    /// missed those transitions.
    #[must_use]
    pub fn deltas_since_with_revision(&self, since_revision: u64, limit: usize) -> DeltaPage {
        let inner = self.inner_read();
        if since_revision > inner.global_revision || since_revision < inner.evicted_through_revision
        {
            return DeltaPage {
                epoch: inner.epoch.clone(),
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
            epoch: inner.epoch.clone(),
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
    /// as `Fresh`. `register-device` uses
    /// [`Self::reset_and_seed_device`] instead: it needs the
    /// same stale-sweep, but atomically paired with the initial
    /// seed so a reader can't observe a "gone-then-back with
    /// old values" transient (H9 round-10 finding 1).
    ///
    /// Returns the number of entries flipped.
    pub fn mark_device_stale(&self, device_id: &str) -> usize {
        self.stale_where(|(did, _), entry| did == device_id && entry.quality == StateQuality::Fresh)
    }

    /// H9 round-2 finding 3: reconcile the projection with a
    /// `DeviceInfo.capabilities` list — flip any entry whose
    /// `capability` isn't in `live_capabilities` to `Stale`.
    /// Called from `update-device` — an update narrows the
    /// declared capabilities but doesn't necessarily reset the
    /// retained ones. See [`Self::reset_and_seed_device`] for
    /// the register-device path (which flips *everything* and
    /// re-seeds atomically).
    ///
    /// Returns the number of entries flipped.
    pub fn reconcile_capabilities(&self, device_id: &str, live_capabilities: &[String]) -> usize {
        self.stale_where(|(did, cap), entry| {
            did == device_id
                && entry.quality == StateQuality::Fresh
                && !live_capabilities.iter().any(|live| live == cap)
        })
    }

    /// H9 round-10 finding 1: atomic register-device reset +
    /// seed. Under a single write lock: (1) flip every `Fresh`
    /// entry for `device_id` to `Stale` (bumping revisions and
    /// `received_ms` on each flip), then (2) write each
    /// `(capability, fields)` from `initial_state` back as a
    /// fresh snapshot. Concurrent readers observe either the
    /// pre-reset state or the fully-reset+seeded state — never
    /// a mix. Any capability the caller declares but doesn't
    /// seed stays `Stale` until a subsequent `state-change`
    /// arrives — the desired behavior for a re-registration
    /// with empty `initial_state`.
    ///
    /// Pre-fix, register-device called `reconcile_capabilities`
    /// (which only flips *removed* capabilities) then looped
    /// `replace_snapshot` per seed entry. A re-register of the
    /// same stable id with the same capability list but empty
    /// `initial_state` left every previous entry untouched and
    /// `Fresh`, silently retaining pre-restart values as
    /// authoritative — the exact H9 problem the store exists
    /// to solve.
    pub fn reset_and_seed_device(
        &self,
        device_id: &DeviceId,
        owner_instance: &str,
        initial_state: Vec<(String, Vec<KeyValue>)>,
        observed_ms: u64,
        received_ms: i64,
    ) {
        let mut inner = self.inner_write();
        // (1) Flip every Fresh entry for device_id to Stale.
        Self::stale_where_locked(&mut inner, received_ms, |(did, _), entry| {
            did == device_id && entry.quality == StateQuality::Fresh
        });
        // (2) Seed each capability. Same generation lookup shape
        // as `write_entry` so post-restart writes stamp the right
        // generation onto the reseeded slots.
        let generation = inner.generations.get(owner_instance).copied().unwrap_or(0);
        for (capability, fields) in initial_state {
            // H9 round-16 finding 1: canonicalize the input
            // by folding duplicate keys last-wins BEFORE
            // storing, same as `write_entry`'s replace path.
            let mut fields = merge_fields_unbounded(&[], &fields);
            // H9 round-13 finding 2: same per-slot field cap
            // as `write_entry`.
            if fields.len() > MAX_FIELDS_PER_SLOT {
                let dropped = fields.len() - MAX_FIELDS_PER_SLOT;
                tracing::warn!(
                    target: "device_state.slot_field_cap",
                    device_id = %device_id,
                    capability = %capability,
                    dropped,
                    cap = MAX_FIELDS_PER_SLOT,
                    "reset_and_seed_device truncated {dropped} field(s): per-slot cap exceeded",
                );
                fields.truncate(MAX_FIELDS_PER_SLOT);
            }
            let global_revision = inner.next_revision();
            let key = (device_id.clone(), capability.clone());
            let entry = Arc::new(DeviceState {
                device_id: device_id.clone(),
                capability,
                fields,
                global_revision,
                received_ms,
                observed_ms,
                source_generation: generation,
                owner_instance: owner_instance.to_string(),
                quality: StateQuality::Fresh,
            });
            inner.entries.insert(key, entry);
        }
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
    /// transition batch.
    ///
    /// H9 round-7 finding 1: also updates
    /// `evicted_through_revision` to the highest evicted
    /// `global_revision`, so [`Self::deltas_since_with_revision`]
    /// can force `reset_required` on any client whose cursor is
    /// at or below that watermark — they might have missed the
    /// stale-transition of a slot they'd cached as `Fresh`.
    /// Pre-fix, evictions were silent and such a client would
    /// keep serving pre-eviction values forever.
    ///
    /// Fresh entries are never evicted here — a bounded store
    /// under normal operation stays well within the cap; the
    /// cap exists to bound growth from a plugin registering
    /// unique `local_id`s in a loop.
    ///
    /// H9 round-9 finding 1: the round-8 epoch-rotation-on-
    /// eviction was reverted. It defended per-key `revision`
    /// monotonicity — but with `revision` now removed as a
    /// wire field (only `global_revision` orders), there's no
    /// per-key counter to protect. Rotating on eviction would
    /// also have been a `DoS` vector: one plugin churning
    /// unique `local_id`s past the cap would force every API
    /// client to resnapshot on every removal.
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
        let mut stale_by_age: Vec<(u64, (DeviceId, String))> = inner
            .entries
            .iter()
            .filter(|(_, m)| m.quality == StateQuality::Stale)
            .map(|(k, m)| (m.global_revision, k.clone()))
            .collect();
        stale_by_age.sort_by_key(|(rev, _)| *rev);
        for (rev, key) in stale_by_age.into_iter().take(excess) {
            inner.entries.remove(&key);
            // Round-7 finding 1: advance the watermark to the
            // highest evicted revision. Cursors at or below
            // this value need a reset (they may have missed
            // this slot's flip to Stale, which was already the
            // client's final chance to observe the transition).
            if rev > inner.evicted_through_revision {
                inner.evicted_through_revision = rev;
            }
        }
    }
}

/// H9 round-13 finding 2: per-slot cap on distinct field
/// keys. `apply_delta` merges partial updates key-by-key,
/// growing the `fields` vec by one per unseen key — so a
/// plugin repeatedly publishing `state-change` events with
/// unique keys could grow a single `Fresh` slot without
/// bound, bypassing the device count quota (only one slot)
/// and the stale-entry cap (never flipped stale). It would
/// also make merge cost quadratic and inflate every
/// snapshot page carrying the oversized device.
///
/// Chosen generously: real capabilities carry a handful of
/// fields (a color-light: 5–8; a sensor: 2), so the cap
/// only bites malicious / buggy plugins. Paired with
/// [`MAX_BYTES_PER_SLOT`] so field count alone can't get
/// you to the count cap with 64 KiB values (a 4 MiB slot),
/// and pre-checked at the WIT boundary
/// (`publish_event` / `execute_command` / `register-device`)
/// so an overflow is rejected before the event log records
/// it — see [`Self::check_delta_admission`] and
/// [`Self::check_snapshot_admission`].
pub const MAX_FIELDS_PER_SLOT: usize = 64;

/// H9 round-14 finding 2 / round-16 finding 2: per-slot cap
/// on the *serialized* byte size of a slot's fields
/// (approximated as the sum of key bytes + value byte
/// estimates). Bounds one slot's share of every snapshot
/// response body — one slot at 4 MiB (the pre-fix worst
/// case: 64 fields × 64 KiB each) would dominate a page
/// and any subscriber's copy on the bus.
///
/// Round-16 tightened this from 64 KiB → 16 KiB. Real
/// capabilities carry a handful of fields — a color-light
/// with `hue` / `saturation` / `value` / `color-temp-kelvin`
/// sits at tens of bytes, not thousands; even a JSON blob
/// state comfortably fits in 16 KiB. The old 64 KiB
/// aggregated (with `MAX_DEVICES_PER_INSTANCE = 1024`
/// and `MAX_CAPABILITIES_PER_DEVICE = 32`) to 2 GiB per
/// instance worst-case; the new bound plus the
/// per-instance quota below caps that at
/// `MAX_PROJECTED_BYTES_PER_INSTANCE` regardless.
pub const MAX_BYTES_PER_SLOT: usize = 16 * 1024;

/// H9 round-16 finding 2: per-instance aggregate cap on the
/// projected byte size of all this instance's slots. Paired
/// with the per-slot cap, this is the actual memory bound
/// a plugin can push into the projection: pre-fix,
/// `MAX_DEVICES_PER_INSTANCE × MAX_CAPABILITIES_PER_DEVICE
/// × MAX_BYTES_PER_SLOT` multiplied to 2 GiB per instance —
/// well over the host's budget. Checked at admission
/// against an on-demand scan (only fires on the WIT-boundary
/// admission path, not on every internal write).
pub const MAX_PROJECTED_BYTES_PER_INSTANCE: usize = 16 * 1024 * 1024;

/// Merge `updates` into `prev` by `key` — new keys are appended,
/// duplicated keys have their value replaced by the update. Preserves
/// `prev`'s ordering for stable keys so a snapshot-diffing consumer
/// sees minimal churn. H9 round-13 finding 2: rejects new keys
/// once the merged vec would exceed [`MAX_FIELDS_PER_SLOT`];
/// updates to existing keys are always accepted (they don't
/// grow the slot). Returns `(merged, dropped_new_keys)` so
/// the caller can `tracing::warn` on drops.
fn merge_fields(prev: &[KeyValue], updates: &[KeyValue]) -> (Vec<KeyValue>, usize) {
    let mut out: Vec<KeyValue> = prev.to_vec();
    let mut dropped = 0;
    for update in updates {
        if let Some(existing) = out.iter_mut().find(|kv| kv.key == update.key) {
            existing.value = update.value.clone();
        } else if out.len() < MAX_FIELDS_PER_SLOT {
            out.push(update.clone());
        } else {
            dropped += 1;
        }
    }
    (out, dropped)
}

/// H9 round-14 finding 3: outcome of
/// [`DeviceStateStore::verify_cursor`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CursorError {
    /// Malformed shape, unparseable revision, missing/short
    /// MAC, or MAC mismatch — a client-side error.
    Bad,
    /// Cursor's MAC verified but its epoch no longer matches
    /// the store's current epoch — the daemon restarted (or
    /// the store was re-initialized) between page fetches.
    /// Client should restart the resync from an unpinned
    /// request.
    EpochChanged,
}

/// HMAC-SHA256 keyed on `key`, over `msg`. Standard
/// construction: `H((K' ⊕ opad) || H((K' ⊕ ipad) || msg))`
/// where `K'` is `key` padded / re-hashed to the block size
/// (64 bytes for SHA-256). Only ~15 lines — not worth
/// pulling in the `hmac` crate just for the cursor MAC.
fn hmac_sha256(key: &[u8; 32], msg: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    const BLOCK: usize = 64;
    let mut k_padded = [0u8; BLOCK];
    k_padded[..key.len()].copy_from_slice(key);
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= k_padded[i];
        opad[i] ^= k_padded[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(msg);
    let inner_digest = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_digest);
    outer.finalize().into()
}

/// Constant-time byte comparison for the cursor MAC check —
/// early-exit `==` would leak timing info about how much of
/// the MAC matched, so use `subtle`-style OR-accumulation.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// H9 round-14 finding 1 / round-16 finding 2: cap
/// violation from
/// [`DeviceStateStore::check_delta_admission`] /
/// [`DeviceStateStore::check_snapshot_admission`]. The
/// runtime maps this to `WitError::InvalidArgument` so the
/// plugin sees a rejection instead of the projection
/// silently truncating while the durable event log records
/// the full state. Carries either a per-slot violation or
/// a per-instance aggregate-bytes violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotCapExceeded {
    /// A single slot would exceed the per-slot field or
    /// byte cap.
    Slot {
        projected_fields: usize,
        projected_bytes: usize,
        cap_fields: usize,
        cap_bytes: usize,
    },
    /// Accepting the write would push this instance's
    /// total projected bytes past
    /// [`MAX_PROJECTED_BYTES_PER_INSTANCE`].
    Instance {
        projected_instance_bytes: usize,
        cap_instance_bytes: usize,
    },
}

impl std::fmt::Display for SlotCapExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Slot {
                projected_fields,
                projected_bytes,
                cap_fields,
                cap_bytes,
            } => write!(
                f,
                "device-state slot cap exceeded: fields={projected_fields}/{cap_fields} \
                 bytes={projected_bytes}/{cap_bytes}",
            ),
            Self::Instance {
                projected_instance_bytes,
                cap_instance_bytes,
            } => write!(
                f,
                "device-state per-instance aggregate cap exceeded: \
                 bytes={projected_instance_bytes}/{cap_instance_bytes}",
            ),
        }
    }
}

/// H9 round-16 finding 2 / round-17 finding 3: aggregate-
/// bytes check for one instance. Runs under an already-
/// held read lock so the scan sees a consistent set of
/// entries. On-demand rather than incremental — admission
/// is only invoked at the WIT boundary, not on every
/// internal write, so the scan cost (O(N) over the store,
/// bounded by
/// `MAX_DEVICES_PER_INSTANCE × MAX_CAPABILITIES_PER_DEVICE`)
/// is acceptable next to a wasm host-call.
///
/// Round-17 finding 3: **counts Fresh entries only**. Stale
/// entries are eligible for reclamation by the stale-cap
/// evictor and by remove/re-register flows; charging them
/// against a plugin's live quota would let an instance fill
/// its quota, remove those devices, and then be locked
/// out of publishing any new state until the total-store
/// stale cap fires. The caller must symmetrically pass
/// `old_slot_bytes = 0` when replacing a Stale slot (see
/// callers).
fn check_instance_caps_locked(
    inner: &StoreInner,
    owner_instance: &str,
    old_slot_bytes: usize,
    projected_slot_bytes: usize,
) -> Result<(), SlotCapExceeded> {
    let owner_total: usize = inner
        .entries
        .values()
        .filter(|e| e.owner_instance == owner_instance && e.quality == StateQuality::Fresh)
        .map(|e| fields_byte_estimate(&e.fields))
        .sum();
    let projected_instance_bytes = owner_total
        .saturating_sub(old_slot_bytes)
        .saturating_add(projected_slot_bytes);
    if projected_instance_bytes > MAX_PROJECTED_BYTES_PER_INSTANCE {
        return Err(SlotCapExceeded::Instance {
            projected_instance_bytes,
            cap_instance_bytes: MAX_PROJECTED_BYTES_PER_INSTANCE,
        });
    }
    Ok(())
}

fn check_slot_caps(projected_fields: usize, projected_bytes: usize) -> Result<(), SlotCapExceeded> {
    if projected_fields > MAX_FIELDS_PER_SLOT || projected_bytes > MAX_BYTES_PER_SLOT {
        return Err(SlotCapExceeded::Slot {
            projected_fields,
            projected_bytes,
            cap_fields: MAX_FIELDS_PER_SLOT,
            cap_bytes: MAX_BYTES_PER_SLOT,
        });
    }
    Ok(())
}

fn key_value_byte_estimate(kv: &KeyValue) -> usize {
    kv.key.len() + value_byte_estimate(&kv.value)
}

fn value_byte_estimate(v: &crate::host_impl::plugin::oxidhome::plugin::types::Value) -> usize {
    use crate::host_impl::plugin::oxidhome::plugin::types::Value;
    match v {
        Value::BoolVal(_) => 1,
        Value::IntVal(_) | Value::FloatVal(_) => 8,
        Value::StringVal(s) | Value::JsonVal(s) => s.len(),
        Value::BytesVal(b) => b.len(),
    }
}

fn fields_byte_estimate(fields: &[KeyValue]) -> usize {
    fields.iter().map(key_value_byte_estimate).sum()
}

/// H9 round-15 finding 2: byte-cap backstop for the write
/// path — drop trailing fields until the total serialized
/// size fits `MAX_BYTES_PER_SLOT`. Belt-and-suspenders
/// counterpart to the field-count truncation already in
/// `write_entry`; admission at the WIT boundary is the
/// primary check.
fn truncate_to_byte_cap(fields: Vec<KeyValue>, device_id: &str, capability: &str) -> Vec<KeyValue> {
    let total = fields_byte_estimate(&fields);
    if total <= MAX_BYTES_PER_SLOT {
        return fields;
    }
    let mut running = 0usize;
    let mut out = Vec::with_capacity(fields.len());
    for kv in fields {
        let n = key_value_byte_estimate(&kv);
        if running.saturating_add(n) > MAX_BYTES_PER_SLOT {
            break;
        }
        running += n;
        out.push(kv);
    }
    let dropped = total - running;
    tracing::warn!(
        target: "device_state.slot_field_cap",
        device_id = %device_id,
        capability = %capability,
        dropped_bytes = dropped,
        cap = MAX_BYTES_PER_SLOT,
        "write_entry byte-cap backstop truncated {dropped} bytes: per-slot byte cap exceeded",
    );
    out
}

/// H9 round-15 finding 2: unbounded variant of
/// [`merge_fields`] used by
/// [`DeviceStateStore::check_delta_admission`]. Matches
/// merge semantics — new keys appended, existing keys
/// replaced in place, duplicate keys in `updates` collapse
/// to last-wins — but never truncates, so the caller sees
/// the true projected size and can reject at the WIT
/// boundary before persistence. The write path still uses
/// the truncating [`merge_fields`] as a backstop.
fn merge_fields_unbounded(prev: &[KeyValue], updates: &[KeyValue]) -> Vec<KeyValue> {
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
    /// H9 round-7 finding 2: string (128-bit OS-random nonce)
    /// so distinct stores collide with negligible probability
    /// and JavaScript clients compare it losslessly.
    pub epoch: String,
    pub current_revision: u64,
    pub entries: Vec<Arc<DeviceState>>,
    pub reset_required: bool,
}

/// H9 round-12 finding 2: sentinel string that sorts strictly
/// after every real capability name. Bytes are `F4 8F BF BF`
/// (`\u{10FFFF}` in UTF-8), higher than any lowercase-ASCII
/// capability name (`switch`, `dimmer`, `sensor`, …), so
/// `Bound::Excluded((cursor, MAX_CAP_SENTINEL.to_string()))`
/// skips every entry whose `device_id == cursor` — exactly
/// what "`device_id` > cursor" pagination needs.
const MAX_CAP_SENTINEL: &str = "\u{10FFFF}";

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
        assert_eq!(entry.global_revision, 1);
        assert_eq!(entry.received_ms, 100);
        assert_eq!(entry.observed_ms, 10);
        assert_eq!(entry.quality, StateQuality::Fresh);
        assert_eq!(entry.source_generation, 0);
        assert!(matches!(entry.fields[0].value, Value::BoolVal(true)));
    }

    #[test]
    fn apply_overwrites_and_bumps_global_revision() {
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
        // Round-4 finding 2: `global_revision` bumps on the
        // transition (the slot changed), and `received_ms`
        // refreshes to the transition time (not the original
        // apply's timestamp).
        assert_eq!(alpha_entry.global_revision, 3);
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

    /// H9 round-7 finding 1: `deltas_since_with_revision` also
    /// returns `reset_required = true` when the caller's cursor
    /// is below the store's `evicted_through_revision` watermark
    /// — the stale-cap sweep may have evicted a `Fresh → Stale`
    /// transition the client hadn't yet observed. Pre-fix, only
    /// the cursor-above-current case triggered a reset, so an
    /// entry evicted at revision E left every cursor with
    /// `since_revision < E` silently missing the transition.
    #[test]
    fn deltas_since_with_revision_flags_reset_when_cursor_below_evicted() {
        let store = DeviceStateStore::new();
        // Register + stale-sweep enough entries to overflow the
        // stale cap and trigger eviction.
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
        store.mark_instance_stale("alpha");
        // Store has evicted at least `overflow` entries. Any
        // cursor at or below any evicted revision must reset.
        let current = store.current_revision();
        let page = store.deltas_since_with_revision(0, 1024);
        assert!(
            page.reset_required,
            "cursor 0 below eviction watermark should reset, current={} page={:?}",
            current,
            (
                &page.epoch,
                page.current_revision,
                page.reset_required,
                page.entries.len()
            ),
        );

        // A cursor at or above the current revision is either
        // fine (== current, no deltas) or a restart-cursor
        // (> current, also resets — covered by round-6 test).
        let page = store.deltas_since_with_revision(current, 1024);
        assert!(!page.reset_required);
        assert!(page.entries.is_empty());
    }

    /// H9 round-9 finding 1: churn-driven eviction must NOT
    /// rotate the store epoch. The round-8 defence tied
    /// eviction to global cursor invalidation, which one
    /// misbehaving plugin could weaponize by cycling unique
    /// `local_id`s past the 4096 cap — every removal beyond
    /// the warmup would then force every API client to
    /// re-snapshot every device. With `revision` removed as a
    /// per-key counter (only `global_revision` orders), the
    /// invariant the rotation defended no longer exists.
    #[test]
    fn stale_cap_eviction_does_not_rotate_epoch() {
        let store = DeviceStateStore::new();
        let epoch_before = store.epoch();
        for i in 0..MAX_STALE_ENTRIES + 32 {
            store.apply_delta(
                format!("dev-{i}"),
                "alpha".into(),
                "switch".into(),
                Vec::new(),
                0,
                0,
            );
        }
        store.mark_instance_stale("alpha");
        assert_eq!(
            store.epoch(),
            epoch_before,
            "eviction must not rotate the epoch (would be a global-resync DoS via one plugin churning unique local_ids)",
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
        assert!(page.epoch.starts_with("epoch-"));

        // Cursor at or below → normal read, no reset flag.
        let page = store.deltas_since_with_revision(0, 10);
        assert!(!page.reset_required);
        assert_eq!(page.entries.len(), 1);
    }

    /// H9 round-7 finding 2: two freshly-constructed stores get
    /// **distinct** epochs, with 2⁻¹²⁸ collision probability.
    /// Pre-fix, the epoch was `now_unix_ms()`, so two stores
    /// created in the same millisecond collided — a client that
    /// polled the pre-restart store at revision 100, saw a
    /// restart, and re-polled quickly enough could observe the
    /// same epoch and continue advancing its cursor into
    /// nonsense. String encoding also sidesteps JavaScript's
    /// 2⁵³ integer precision limit.
    #[test]
    fn distinct_stores_get_distinct_random_epochs() {
        let a = DeviceStateStore::new();
        let b = DeviceStateStore::new();
        assert!(a.epoch().starts_with("epoch-"));
        assert!(b.epoch().starts_with("epoch-"));
        assert_ne!(
            a.epoch(),
            b.epoch(),
            "distinct stores must mint distinct random epochs"
        );
    }

    /// H9 round-14 finding 1: `check_delta_admission` returns
    /// `Err(SlotCapExceeded)` when a `state-change` would
    /// push the slot past field count OR byte budget. The
    /// runtime calls this at the WIT boundary before
    /// persisting the event log record, so an overflow is
    /// rejected outright — pre-fix, the store silently
    /// truncated and the durable log / bus fanout kept the
    /// full state, desyncing the projection from every
    /// downstream authoritative view.
    #[test]
    fn check_delta_admission_flags_field_and_byte_overflow() {
        let store = DeviceStateStore::new();
        // Fill the slot to just under the field cap with tiny
        // string values (1 byte each) so the byte cap isn't
        // the trigger.
        for i in 0..MAX_FIELDS_PER_SLOT - 1 {
            store.apply_delta(
                "dev-1".into(),
                "alpha".into(),
                "switch".into(),
                vec![kv(&format!("k{i}"), Value::StringVal("x".into()))],
                0,
                0,
            );
        }
        // Adding one existing key is OK (no growth).
        store
            .check_delta_admission(
                "dev-1",
                "alpha",
                "switch",
                &[kv("k0", Value::StringVal("y".into()))],
            )
            .expect("existing-key update fits");
        // Adding one new key fits.
        store
            .check_delta_admission(
                "dev-1",
                "alpha",
                "switch",
                &[kv("new-key", Value::StringVal("z".into()))],
            )
            .expect("one new key stays under the field cap");
        // Adding two new keys overflows the field cap.
        let err = store
            .check_delta_admission(
                "dev-1",
                "alpha",
                "switch",
                &[
                    kv("more1", Value::StringVal("z".into())),
                    kv("more2", Value::StringVal("z".into())),
                ],
            )
            .expect_err("two new keys must overflow the field cap");
        match err {
            SlotCapExceeded::Slot {
                cap_fields,
                projected_fields,
                ..
            } => {
                assert_eq!(cap_fields, MAX_FIELDS_PER_SLOT);
                assert!(projected_fields > MAX_FIELDS_PER_SLOT);
            }
            other @ SlotCapExceeded::Instance { .. } => panic!("expected Slot, got {other:?}"),
        }

        // Byte cap: a single oversized value overflows even
        // when the field count is fine.
        let big = "a".repeat(MAX_BYTES_PER_SLOT + 1);
        let err = store
            .check_delta_admission(
                "dev-2",
                "alpha",
                "switch",
                &[kv("giant", Value::StringVal(big))],
            )
            .expect_err("one oversized value must overflow the byte cap");
        match err {
            SlotCapExceeded::Slot {
                cap_bytes,
                projected_bytes,
                ..
            } => {
                assert_eq!(cap_bytes, MAX_BYTES_PER_SLOT);
                assert!(projected_bytes > MAX_BYTES_PER_SLOT);
            }
            other @ SlotCapExceeded::Instance { .. } => panic!("expected Slot, got {other:?}"),
        }
    }

    /// H9 round-17 finding 3: Stale entries don't count
    /// against the per-instance aggregate quota — an
    /// instance can fill 16 MiB with Fresh, mark it Stale,
    /// and then publish new Fresh state up to the quota
    /// again without waiting for the total-store stale-cap
    /// evictor.
    #[test]
    fn stale_entries_do_not_charge_against_per_instance_quota() {
        let store = DeviceStateStore::new();
        // Fill the instance close to the aggregate cap with
        // Fresh entries near the per-slot cap.
        let per_slot_bytes = MAX_BYTES_PER_SLOT - 32;
        let slots = MAX_PROJECTED_BYTES_PER_INSTANCE / per_slot_bytes;
        for i in 0..slots {
            store.apply_delta(
                format!("dev-{i}"),
                "alpha".into(),
                "switch".into(),
                vec![kv(
                    "state",
                    Value::StringVal("s".repeat(per_slot_bytes - "state".len())),
                )],
                0,
                0,
            );
        }
        // Adding another slot would overflow.
        store
            .check_delta_admission(
                "dev-post",
                "alpha",
                "switch",
                &[kv(
                    "state",
                    Value::StringVal("s".repeat(per_slot_bytes - "state".len())),
                )],
            )
            .expect_err("Fresh baseline: aggregate cap must fire");

        // Flip everything Stale. Aggregate accounting
        // excludes Stale now — the same write goes through.
        assert!(store.mark_instance_stale("alpha") >= slots);
        store
            .check_delta_admission(
                "dev-post",
                "alpha",
                "switch",
                &[kv(
                    "state",
                    Value::StringVal("s".repeat(per_slot_bytes - "state".len())),
                )],
            )
            .expect("Stale entries must not consume the live quota");
    }

    /// H9 round-16 finding 1: `replace_snapshot` inputs are
    /// canonicalized last-wins before storing — a snapshot
    /// with duplicate keys ends up as a single entry per
    /// key in the projection.
    #[test]
    fn replace_snapshot_canonicalizes_duplicate_keys_last_wins() {
        let store = DeviceStateStore::new();
        store.replace_snapshot(
            "dev-1".into(),
            "alpha".into(),
            "switch".into(),
            vec![
                kv("state", Value::BoolVal(true)),
                kv("state", Value::BoolVal(false)),
            ],
            0,
            0,
        );
        let entry = store.snapshot_capability("dev-1", "switch").unwrap();
        assert_eq!(entry.fields.len(), 1);
        assert_eq!(entry.fields[0].key, "state");
        assert!(matches!(entry.fields[0].value, Value::BoolVal(false)));
    }

    /// H9 round-16 finding 2: per-instance aggregate cap
    /// rejects writes that would push one plugin's total
    /// projected bytes past
    /// [`MAX_PROJECTED_BYTES_PER_INSTANCE`], even when
    /// each individual write stays under the per-slot cap.
    #[test]
    fn check_delta_admission_enforces_per_instance_aggregate_cap() {
        let store = DeviceStateStore::new();
        // Fill the instance to just under the aggregate
        // cap with slots each near the per-slot cap.
        let per_slot_bytes = MAX_BYTES_PER_SLOT - 32;
        let slots = MAX_PROJECTED_BYTES_PER_INSTANCE / per_slot_bytes;
        for i in 0..slots {
            store.apply_delta(
                format!("dev-{i}"),
                "alpha".into(),
                "switch".into(),
                vec![kv(
                    "state",
                    Value::StringVal("s".repeat(per_slot_bytes - "state".len())),
                )],
                0,
                0,
            );
        }
        // One more slot's-worth of bytes overflows the
        // aggregate cap.
        let err = store
            .check_delta_admission(
                "dev-tip",
                "alpha",
                "switch",
                &[kv(
                    "state",
                    Value::StringVal("s".repeat(per_slot_bytes - "state".len())),
                )],
            )
            .expect_err("aggregate cap must fire");
        match err {
            SlotCapExceeded::Instance {
                cap_instance_bytes,
                projected_instance_bytes,
            } => {
                assert_eq!(cap_instance_bytes, MAX_PROJECTED_BYTES_PER_INSTANCE);
                assert!(projected_instance_bytes > MAX_PROJECTED_BYTES_PER_INSTANCE);
            }
            other @ SlotCapExceeded::Slot { .. } => panic!("expected Instance, got {other:?}"),
        }
        // A different owner_instance has its own quota
        // bucket — same-shape write goes through.
        store
            .check_delta_admission(
                "dev-tip",
                "beta",
                "switch",
                &[kv(
                    "state",
                    Value::StringVal("s".repeat(per_slot_bytes - "state".len())),
                )],
            )
            .expect("other instance has its own aggregate bucket");
    }

    /// H9 round-15 finding 1: admission mirrors
    /// `write_entry`'s merge-vs-replace rule. When the
    /// existing slot is Stale (or from a prior
    /// generation), the write would replace — so admission
    /// treats the incoming vec as the whole slot, not as
    /// an addition to the old baseline.
    #[test]
    fn check_delta_admission_uses_write_semantics_for_stale_baseline() {
        let store = DeviceStateStore::new();
        // Fill the slot near the field cap while it's Fresh.
        for i in 0..MAX_FIELDS_PER_SLOT {
            store.apply_delta(
                "dev-1".into(),
                "alpha".into(),
                "switch".into(),
                vec![kv(&format!("k{i}"), Value::StringVal("x".into()))],
                0,
                0,
            );
        }
        // A single-new-key delta on the Fresh slot correctly
        // overflows (baseline is the existing 64 fields).
        store
            .check_delta_admission(
                "dev-1",
                "alpha",
                "switch",
                &[kv("new", Value::StringVal("y".into()))],
            )
            .expect_err("Fresh + 1 new key overflows the field cap");
        // Flip the slot Stale (mimicking `mark_instance_stale`
        // after the owning instance terminates). Same delta
        // now must succeed — the write path would treat the
        // Stale slot as absent and replace it with `[new]`.
        assert!(store.mark_instance_stale("alpha") >= 1);
        store
            .check_delta_admission(
                "dev-1",
                "alpha",
                "switch",
                &[kv("new", Value::StringVal("y".into()))],
            )
            .expect(
                "Stale baseline: write would replace with 1 field, admission must not \
                 double-count the pre-restart slot",
            );
        // Same story for a delta from a *newer* generation
        // against a still-Fresh but same-generation-mismatched
        // baseline (register the same instance's next life).
        store.bump_generation("alpha");
        store
            .check_delta_admission(
                "dev-1",
                "alpha",
                "switch",
                &[kv("new", Value::StringVal("y".into()))],
            )
            .expect("generation-mismatched baseline: write would replace");
    }

    /// H9 round-15 finding 2: duplicates in the incoming
    /// vec normalize to last-wins before measurement.
    /// Pre-fix the admission math subtracted the existing
    /// value's bytes for every duplicate occurrence,
    /// under-counting the real merged size and letting the
    /// slot overflow past the byte cap.
    #[test]
    fn check_delta_admission_normalizes_duplicate_keys_before_measuring() {
        let store = DeviceStateStore::new();
        // Seed the slot near the per-slot byte cap: two
        // ~7 KiB values (14 KiB total, under the 16 KiB cap).
        let seven = "a".repeat(7 * 1024);
        store.apply_delta(
            "dev-1".into(),
            "alpha".into(),
            "switch".into(),
            vec![
                kv("a", Value::StringVal(seven.clone())),
                kv("b", Value::StringVal(seven.clone())),
            ],
            0,
            0,
        );
        // Incoming that folds last-wins to `a=<12 KiB>`
        // (7 replaced) alongside the untouched `b=7 KiB`,
        // projecting to ~19 KiB — over the 16 KiB slot cap.
        // Pre-fix (round-15) math subtracted `a`'s bytes
        // twice and undercounted.
        let twelve = "z".repeat(12 * 1024);
        let err = store
            .check_delta_admission(
                "dev-1",
                "alpha",
                "switch",
                &[
                    kv("a", Value::StringVal(String::new())),
                    kv("a", Value::StringVal(twelve)),
                ],
            )
            .expect_err("duplicates must fold last-wins before the byte cap check");
        match err {
            SlotCapExceeded::Slot {
                projected_bytes, ..
            } => assert!(projected_bytes > MAX_BYTES_PER_SLOT),
            other @ SlotCapExceeded::Instance { .. } => panic!("expected Slot, got {other:?}"),
        }
    }

    /// H9 round-15 finding 3: `verify_cursor` compares the
    /// epoch before validating the MAC, so a legitimate
    /// cursor from a prior daemon life (rotated
    /// `cursor_secret` AND rotated `epoch`) surfaces as
    /// `EpochChanged` — mapped to 409 by the API handler —
    /// rather than `Bad` (400). Pre-fix, the MAC check
    /// ran first and failed against the new secret, so
    /// every pre-restart cursor looked like a fabricated
    /// one.
    #[test]
    fn verify_cursor_flags_epoch_mismatch_before_mac_mismatch() {
        let old_life = DeviceStateStore::new();
        let cursor = old_life.issue_cursor(7, "dev-1");
        // Simulate a daemon restart — fresh store, fresh
        // secret, fresh epoch.
        let new_life = DeviceStateStore::new();
        assert_ne!(old_life.epoch(), new_life.epoch());
        assert_eq!(
            new_life.verify_cursor(&cursor),
            Err(CursorError::EpochChanged),
            "pre-restart cursor must surface as EpochChanged (409), not Bad (400)",
        );
    }

    /// H9 round-14 finding 3: `verify_cursor` accepts a
    /// cursor issued by the same store, rejects a mutated
    /// one, rejects a fabricated one (no MAC), and returns
    /// `EpochChanged` for a MAC-valid cursor whose epoch
    /// belongs to a different store instance.
    #[test]
    fn verify_cursor_authenticates_hmac_and_epoch() {
        let store = DeviceStateStore::new();
        let cursor = store.issue_cursor(42, "dev-1");
        let (epoch, rev, device) = store
            .verify_cursor(&cursor)
            .expect("issuing store must verify its own cursor");
        assert_eq!(epoch, store.epoch());
        assert_eq!(rev, 42);
        assert_eq!(device, "dev-1");

        // Mutate the pinned revision — MAC fails.
        let (payload, mac) = cursor.rsplit_once('.').unwrap();
        let mut parts = payload.splitn(3, '.');
        let stored_epoch = parts.next().unwrap();
        let _rev = parts.next().unwrap();
        let stored_device = parts.next().unwrap();
        let mutated = format!("{stored_epoch}.999.{stored_device}.{mac}");
        assert_eq!(store.verify_cursor(&mutated), Err(CursorError::Bad));

        // Mutate the device id — MAC fails.
        let mutated = format!("{stored_epoch}.42.dev-forged.{mac}");
        assert_eq!(store.verify_cursor(&mutated), Err(CursorError::Bad));

        // A cursor issued by a *different* store fails.
        // Round-15 finding 3: epoch check runs before the
        // MAC check, so this surfaces as `EpochChanged`
        // (409) — a legitimate cursor from a prior daemon
        // life, not a forged one.
        let other = DeviceStateStore::new();
        let alien = other.issue_cursor(42, "dev-1");
        assert_eq!(store.verify_cursor(&alien), Err(CursorError::EpochChanged));

        // Malformed shape.
        assert_eq!(store.verify_cursor("garbage"), Err(CursorError::Bad));
        assert_eq!(store.verify_cursor("a.b.c"), Err(CursorError::Bad));
    }

    /// H9 round-13 finding 2: `apply_delta` with unique keys
    /// cannot grow one slot past [`MAX_FIELDS_PER_SLOT`].
    /// Updates to existing keys are still accepted at the cap
    /// (they don't grow the slot). A `replace_snapshot`
    /// carrying an oversized fields vec is truncated to the
    /// same cap.
    #[test]
    fn apply_delta_caps_slot_fields_at_max_fields_per_slot() {
        let store = DeviceStateStore::new();
        // Push MAX + 32 unique keys through apply_delta, one at
        // a time, mimicking the "state-change per unique key"
        // growth vector.
        for i in 0..MAX_FIELDS_PER_SLOT + 32 {
            store.apply_delta(
                "dev-1".into(),
                "alpha".into(),
                "switch".into(),
                vec![kv(&format!("k{i}"), Value::StringVal("v".into()))],
                0,
                0,
            );
        }
        let entry = store.snapshot_capability("dev-1", "switch").unwrap();
        assert_eq!(
            entry.fields.len(),
            MAX_FIELDS_PER_SLOT,
            "apply_delta must cap the slot's distinct-key growth",
        );

        // Updating an EXISTING key still applies at the cap.
        let old_v = entry.fields[0].value.clone();
        let existing_key = entry.fields[0].key.clone();
        store.apply_delta(
            "dev-1".into(),
            "alpha".into(),
            "switch".into(),
            vec![kv(&existing_key, Value::StringVal("updated".into()))],
            0,
            0,
        );
        let updated = store.snapshot_capability("dev-1", "switch").unwrap();
        assert_eq!(updated.fields.len(), MAX_FIELDS_PER_SLOT);
        let after = &updated
            .fields
            .iter()
            .find(|kv| kv.key == existing_key)
            .unwrap()
            .value;
        assert!(
            !matches!(after, v if std::mem::discriminant(v) == std::mem::discriminant(&old_v)
                                 && matches!(v, Value::StringVal(s) if s == "v")),
            "existing key must have picked up the new value",
        );

        // replace_snapshot with an oversized fields vec is
        // truncated (not rejected).
        let oversized: Vec<KeyValue> = (0..MAX_FIELDS_PER_SLOT + 8)
            .map(|i| kv(&format!("r{i}"), Value::StringVal("x".into())))
            .collect();
        store.replace_snapshot(
            "dev-2".into(),
            "alpha".into(),
            "switch".into(),
            oversized,
            0,
            0,
        );
        let entry = store.snapshot_capability("dev-2", "switch").unwrap();
        assert_eq!(entry.fields.len(), MAX_FIELDS_PER_SLOT);
    }

    /// H9 round-12 finding 2: `snapshot_page_with_revision`
    /// ranges from the cursor via `BTreeMap::range` — the
    /// returned entries are in `(device_id, capability)`
    /// order, and pages after the cursor start strictly past
    /// the cursor's `device_id`. Also proves `device_limit`
    /// caps distinct devices (not entries) so per-device
    /// atomicity holds.
    #[test]
    fn snapshot_page_with_revision_pages_in_device_order_from_cursor() {
        let store = DeviceStateStore::new();
        // Five devices × two capabilities each, inserted in a
        // deliberately-out-of-order sequence so the BTreeMap's
        // sort — not insertion order — is what pagination
        // observes.
        for i in [3, 1, 4, 0, 2] {
            for cap in ["switch", "dimmer"] {
                store.apply_delta(
                    format!("dev-{i}"),
                    "alpha".into(),
                    (*cap).into(),
                    Vec::new(),
                    0,
                    0,
                );
            }
        }
        // Page 1: limit=2 distinct devices → dev-0, dev-1,
        // each with both capabilities (dimmer sorts before
        // switch).
        let (_, _, page) = store.snapshot_page_with_revision(None, 2);
        assert_eq!(
            page.iter()
                .map(|e| format!("{}/{}", e.device_id, e.capability))
                .collect::<Vec<_>>(),
            vec![
                "dev-0/dimmer",
                "dev-0/switch",
                "dev-1/dimmer",
                "dev-1/switch",
            ],
        );

        // Page 2: cursor at dev-1 → strictly past dev-1's
        // entries.
        let (_, _, page) = store.snapshot_page_with_revision(Some("dev-1"), 2);
        let ids: Vec<String> = page.iter().map(|e| e.device_id.clone()).collect();
        assert!(
            ids.iter().all(|d| d.as_str() > "dev-1"),
            "range must skip cursor's own entries, got {ids:?}",
        );
        assert_eq!(
            page.iter()
                .map(|e| e.device_id.as_str())
                .collect::<std::collections::BTreeSet<_>>(),
            ["dev-2", "dev-3"].into_iter().collect(),
        );
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
