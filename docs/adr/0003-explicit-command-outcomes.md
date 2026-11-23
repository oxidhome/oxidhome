# ADR-0003: Explicit command outcome states

- **Status:** accepted
- **Date:** 2026-11-22
- **Deciders:** the maintainer
- **Supersedes:** none
- **Superseded by:** none
- **References:** architecture review finding H5

## Context

A device command returns `command-result` (`ok`, `ok-with-state`, or `err`) and nothing else. A caller whose request
times out, or whose plugin traps after the device already acted, cannot tell whether the action happened. Retrying a
`toggle`, an unlock or a garage-door command can then repeat a physical effect.

## Decision

Every command gets a host-minted command id and ends in one of these explicit outcome states:

- `accepted`: the host queued the command for the owning plugin; no result yet.
- `completed`: the plugin reported success.
- `rejected`: the host or the plugin refused the command before acting.
- `timed_out`: the deadline passed before the command started executing.
- `outcome_unknown`: the command may have run, but no result arrived (for example a trap or a timeout mid-call).

The command id and outcome are returned to the caller and recorded in the audit trail. The descriptions above are the
intent; the exact transition rules are settled in the implementation PR.

## Rejected options

Not adopted for now; each can be added later on top of the command id:

- **Client idempotency keys** with replay of the stored result for a duplicate key.
- **Result lookup** of a past command by its id.
- **Expected-revision checks** that refuse a command when the device state changed since the caller read it.

## Consequences

- The WIT `command-result` changes, so the contract version and baseline change with it (see
  [ADR-0007](0007-0x-publication-policy.md)).
- The REST, Connect and MCP command APIs change to return the command id and outcome state.
- A caller still cannot safely retry after `outcome_unknown`; it has to read the device state first.

## Implementation notes

Shipped in the H5 implementation PR. The command id is `cmd-<32 hex>`, minted by the host at dispatch; WIT
`command-result` gained `unknown(string)` and `accepted`, and `host-devices` gained `complete-command` (contract stays at
`oxidhome:plugin@0.1.0`, baseline re-blessed). `accepted` means "the plugin took the command and will finish it later",
not "queued by the host": a host-side queue that answers before the plugin runs would leave every command
`outcome_unknown`-prone.

| What happened | Outcome |
|---|---|
| plugin replied `ok` / `ok-with-state` | `completed` |
| plugin replied `err` | `rejected` |
| host refused before queueing (instance not running, restarting, stopped before the command ran) | `rejected` |
| deadline passed, or the caller went away, while the command was still queued | `timed_out` (it never runs) |
| plugin replied `unknown` | `outcome_unknown` |
| trap, watchdog kill or deadline after the plugin started the command | `outcome_unknown` |
| `ok-with-state` the projection refuses (size caps, sensor units) | `outcome_unknown` |
| plugin replied `accepted` | `accepted`, then pending |
| pending, plugin calls `complete-command` | the reply's outcome, as above |
| pending, 5 min pass or the instance restarts or stops | `outcome_unknown` |
| pending when the daemon stopped (resolved at the next boot) | `outcome_unknown` |
| queued, refused in restart backoff or by a terminal supervisor | `rejected` (`timed_out` if the caller had gone) |

`rejected` and `timed_out` are safe to retry. REST maps the outcomes to 200 / 202 / 422 / 504 / 502; Connect keeps an
OK status and carries `command_outcome`; MCP sets `isError` for the three failure outcomes. Pending and late results
are recorded as `COMMAND` audit rows sharing the request's `call_id`; there is still no lookup API.

### Restart reconciliation and service calls

Shipped in the H5 follow-up PR. Externally-rooted `accepted` commands are persisted to a `pending_command` table
(migration 20): command and call ids, owner instance, device, capability, created and expiry wall-clock times, and the
request's audit linkage (`token_id`, `actor_kind`, invocation JSON). Host-origin commands are not persisted, as they
have no audit row to complete.

- **Write-behind, one writer.** The command path only queues work. A single "command journal" thread writes persists
  and every `COMMAND` resolution row in queue order, up to 256 jobs per normal-priority transaction through the M6
  writer. It replaces the per-row blocking tasks. A resolution row and the delete of its persisted entry commit in one
  transaction, so a command is either still pending on disk or has its final row. A command the plugin completes
  before its persist is flushed doesn't resurrect: the persist was queued under the table lock, ahead of any
  resolution, and a persist followed by its resolution in one batch is skipped.
- **Bounds.** The table limits are unchanged (64 per instance, 1024 total). The journal holds 4096 jobs; past that a
  persist is skipped (the command is tracked in memory only) and the resolution of a never-persisted command is dropped
  and counted. A persisted command's resolution is always queued, which keeps the queue below about twice the bound.
  A failed batch is retried every second; shutdown drains the journal for up to 5 s after the supervisors stop.
- **What is lost.** As with the H2 projection, the write-behind trades the command path's latency for a small window:
  a crash after the caller heard `accepted` but before the persist was flushed (normally milliseconds) leaves the
  request row `accepted` with no final row. Making `accepted` wait for a committed row would put a disk write on every
  accepted command.
- **Boot.** Before any plugin runs, every surviving row is resolved to `outcome_unknown` with a `COMMAND` row whose
  `domain_error` is `daemon_restart`, or `expired` if its expiry had already passed, and deleted in the same
  transaction. Other expiry rows carry `expired`, `instance_restarted` or `instance_stopped` in the same column. A
  supervisor expires its pending commands as `instance_stopped` before it publishes its terminal state, so only a
  crash or a supervisor that misses the shutdown deadline leaves rows for the next boot. A failed reconciliation stops the boot, as a failed
  device-state restore does. A resolution whose persisted row is already gone (another boot reconciled it) writes no
  second row. Persisted rows are redacted like audit rows (M7).
- **Queued commands that are dropped.** A command refused during a restart backoff, or still queued when its
  supervisor goes terminal (the supervisor drains and refuses its queue before it publishes the terminal state), is
  `rejected` when the refusal wins while its caller still waits within its deadline, and `timed_out` when the caller
  had already gone or its deadline had passed. Neither ran. If its caller disconnected, that outcome is recorded as a
  `COMMAND` row.
- **Service calls.** `ExecuteService` carries the same dispatch ticket. When the caller's wait ends while the call is
  queued, it never runs, and `call-service` answers `unavailable` with "it did not run" (safe to retry). Once the
  callee started, a missed deadline or a lost supervisor answers `ok(unknown(..))`, as a trap already did. The WIT
  contract is unchanged; the H6 hop row is finalized `allow` with no execution outcome for `unknown`, and `error` /
  503 for a call that did not run. A caller cancelled mid-call (its future dropped) gets the same split from the
  ticket, so its hop row doesn't stay `pending` (short of a runtime torn down before the finalize is written), and a withdrawn queued call releases its in-flight refcount at once.

