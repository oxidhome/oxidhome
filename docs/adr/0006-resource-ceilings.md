# ADR-0006: Host resource ceilings replace "no compute limits"

- **Status:** accepted
- **Date:** 2026-07-31
- **Deciders:** the maintainer
- **Supersedes:** the Phase 7 "no compute limits" policy (2026-05-22, PR #30), which predates these ADRs
- **Superseded by:** none
- **References:** architecture review finding C4, PR #102

## Context

Phase 7 dropped the planned fuel and memory limits: on an admin-run hub, spotting a greedy plugin was left to the
operator, and the host kept only a per-call liveness watchdog. The architecture review (C4) showed that one plugin
could then exhaust host memory, disk or the event bus before the watchdog fired, taking every other plugin and the
daemon down with it.

## Decision

The host enforces fixed resource ceilings on every plugin instance. They are platform safety limits, not
per-plugin tuning, and there are no manifest knobs for them:

- **Per `Store`** (aggregated over all memories and tables of the instance): 128 MiB linear memory, 100,000 table
  elements, at most 8 memories, 16 tables and 128 instances. Going over is a trap, which the supervisor
  handles as a crash under the instance's restart policy.
- **Per host call:** 64 KiB per KV value, 16 MiB per blob write, 64 KiB per event payload, 64 live subscriptions per
  instance, and 4 KiB per log message (longer messages are truncated), plus per-instance rate limits on event
  publishing and logging.
- **CPU:** no fuel or instruction budget. The per-call liveness watchdog (Wasmtime epoch interruption, 30 s) still
  reclaims a wedged instance, and CPU use is left to metrics.

Refusals of host calls surface to the plugin as `permission-denied`.

## Rejected options

- **No limits** (the Phase 7 policy). One plugin can take the whole host down.
- **Fuel metering.** Costs throughput on every instruction; the watchdog already covers the runaway-loop case.
- **Per-manifest limit knobs.** A plugin would set its own limits. Operators may get grant-based overrides later.

## Consequences

- A legitimate plugin that needs more than a ceiling fails until the ceiling is raised in code.
- Under the [ADR-0001](0001-one-sandbox-per-script.md) model the ceilings apply per script, not per scripting plugin.
