# ADR-0008: One SQLite writer with pooled readers and writer priority

- **Status:** accepted
- **Date:** 2026-11-22
- **Deciders:** the maintainer
- **Supersedes:** none
- **Superseded by:** none
- **References:** architecture review finding M6

## Context

Every persistent store (KV, blob index, event history, diagnostic logs, audit ledger, tokens, plugin registry,
dashboards) shares one `SQLite` file, and until M6 it also shared one mutexed connection. A history query, a burst of
diagnostic log inserts (one transaction per row) or a token's `last_used_ms` bump on every request all queued in
front of event publication and audit writes. WAL mode already allows concurrent readers; the single connection threw
that away.

## Decision

`Db` keeps exactly one writer connection, so commit order stays mutex order and cross-store transactions stay
possible. Around it:

- **Readers.** A file-backed `Db` opens up to four `query_only` reader connections on demand. `Db::read` runs each
  closure in one deferred read transaction on a pooled reader, so it sees one snapshot and doesn't wait on the
  writer. In-memory databases keep a single connection.
- **Writer priority.** `Db::write` is normal priority; `Db::write_low_priority` is for work nobody waits on. An
  admission gate hands the writer to queued normal-priority callers first; a low-priority caller defers at most
  250 ms, then gets the next turn after a normal-priority transaction. Diagnostic logs are committed in batches of
  up to 256 rows and trimmed in chunks, both at low priority. Token `last_used_ms` is coalesced to a 60 s resolution.
- **Busy and checkpoint policy.** Every connection uses a 5 s `busy_timeout`. A background thread runs a passive
  WAL checkpoint every 10 s; the writer's `wal_autocheckpoint` is raised to 16384 pages as a backstop, and
  `journal_size_limit` is 64 MiB.

Durability rules don't change: audit writes stay two-phase, unbatched and fail-closed, and the M4 / durable-intent
paths still raise the writer to `synchronous = FULL` for their transaction.

## Rejected options

- **A pool crate (`r2d2`, `deadpool-sqlite`).** The pool is a mutex, a condvar and a vector; a dependency would add
  supply-chain surface and still need the read-transaction wrapper and the writer gate written by hand.
- **Several writer connections.** `SQLite` allows one writer at a time anyway; more writer connections only move
  the queue into `SQLITE_BUSY` retries and lose the in-process ordering the H3 mirror and the KV quota checks rely on.
- **A separate database file for diagnostic logs.** It would remove log writes from the writer entirely, but it
  splits backups, restore checks and migrations across two files. Batching plus low priority bounds the cost to one
  batch per normal-priority write.

## Consequences

While normal-priority callers are queued, consecutive low-priority transactions always have a normal-priority one
between them. That is a per-class guarantee: admission within the normal class is not FIFO, so an individual
normal-priority write has no fixed bound on the transactions that run ahead of it. A slow disk still slows every writer, and the H3 bus gate still serializes
publishers behind one mirror write. Reads that need to be atomic with a later filesystem effect (the blob open) must
stay on the writer. Each file-backed `Db` holds up to six connections and one extra thread.
