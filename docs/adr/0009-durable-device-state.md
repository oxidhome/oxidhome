# ADR-0009: Durable device-state projection and plugin state reads (H2)

- **Status:** accepted
- **Date:** 2026-11-22
- **Deciders:** OxidHome maintainers
- **Supersedes:** none
- **Superseded by:** none
- **References:** architecture review 2026-07-28, H2; H3 (event-log durability classes); H4 (`cursor_expired`);
  M6 ([ADR-0008](0008-sqlite-connection-model.md)); M7 (data classification)

## Context

The host owns a canonical current-state projection (`DeviceStateStore`, H9), but it lived only in memory. A restart
lost every value until each plugin republished, the store epoch changed on every boot, so every API client had to
resync, and plugins had no way to read state at all, neither other devices' nor their own. The fix has to keep H3's
rule that a disk problem never stops live control, and it must not add disk work to the event publish gate.

## Decision

- The projection is persisted in a `device_state` table (migration 19), one row per `(device, capability)` slot, plus
  a one-row `device_state_meta` (epoch, flushed revision, eviction watermark, skipped revision ranges). The store is
  restored at boot, before any plugin runs.
- Writes are write-behind. A mutation only marks its key dirty in memory. A flusher thread writes the dirty slots in
  one normal-priority transaction, at most every 250 ms, as a consistent snapshot of the store at one revision. A
  failed flush is retried with backoff and never affects publishing.
- Restored values are `stale` until the owner republishes them. The host does not claim a value it has not seen in
  the owner's current life.
- The epoch is persisted. A restored store continues from the flushed revision `R` plus 2^32 and records `(R, R + 2^32]`
  as a skipped range before serving anything. Cursors at or below `R` stay valid, and cursors inside a skipped range get
  `reset_required`.
- Plugins read state through a new `host-state` WIT import (`get-state`, `list-state`). An instance always reads what
  it wrote. Other entries need a `[[capabilities.reads_state]]` grant selecting owner plugin, capability and device,
  with `bytes = true` required to see `bytes-val` fields. Requested and granted lists are intersected by equality, and
  refused `get-state` calls are audited.
- Connect gains `GetDeviceState`, `ListDeviceState` and `ListDeviceStateChanges`, with parity to the REST endpoints.

## Rejected options

- **Write-through on every state change.** This would put a disk write under the H3 publish gate, which is exactly
  the coupling H3 removed. It would also cost a transaction per publish.
- **Derive state from `event_log` at boot.** The event log does not hold every state change: `ok-with-state` and
  registration change state without an event, rows written in degraded mode are missing, and retention trims history.
  Replaying it would also make boot cost grow with history.
- **Rotate the epoch on every unclean restart.** Clients would have to resync after any crash, even when their cursor
  was below everything that was lost. The skipped-range rule is precise and keeps those cursors valid.
- **Keep restored values `fresh`.** Automations would act on values no live plugin vouches for.
- **Let every plugin read all state.** This conflicts with C2c's rule that what a plugin can observe is declared in
  the manifest and reviewed at install time.

## Consequences

- Up to 250 ms of state changes (longer while the disk fails) can be lost on a crash. Clients whose cursors fall in
  that window resync.
- Each boot uses 2^32 revisions, which keeps revisions below 2^53 for about two million restarts.
- Installs that predate `reads_state` have no grant until an operator grants one.
- Follow-ups: expose flush health (pending keys, last error) in `readyz` and `oxidhome://status`, and add an operator
  API to narrow `reads_state` grants.
