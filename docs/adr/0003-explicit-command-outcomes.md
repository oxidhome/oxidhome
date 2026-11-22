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
