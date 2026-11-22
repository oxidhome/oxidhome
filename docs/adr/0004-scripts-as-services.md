# ADR-0004: Scripts are services

- **Status:** accepted
- **Date:** 2026-06-01
- **Deciders:** the maintainer
- **Supersedes:** none
- **Superseded by:** [ADR-0001](0001-one-sandbox-per-script.md), in part (one `Store` for all scripts of a plugin)
- **References:** Phase 7, PRs #30, #32, #33, #34

## Context

Embedded scripting plugins (Rhai, Lua) host user-written automation scripts that need to expose commands and call
each other, like peers. Devices do not fit: a script has no hardware and no capability state. Phase 6's lifecycle
had one plugin instance per manifest entry and no way to create instances dynamically.

## Decision

A script is a **service**. A plugin instance registers services with `host-services::register-service`, gated by
`[capabilities] declares_services`, and handles their commands in its `execute-service-command` export. Any plugin
calls a service through `host-services::call-service`; the host dispatcher routes the call to the owning instance's
supervisor task, checks the caller's `consumes_services` grants, detects cycles and bounds the call with a timeout.
For Phase 7 all scripts of one scripting plugin live in that plugin's single instance and Wasmtime `Store`.

## Rejected options

- **One plugin instance per script, in Phase 7.** It costs a `Store` per script and needed dynamic child instances
  that the Phase 6 lifecycle did not have. [ADR-0001](0001-one-sandbox-per-script.md) later adopts this model.
- **Modelling scripts as devices.** Scripts have commands but no capability state, and device ids, grants and the
  state projection would carry meaningless entries.

## Consequences

- Services are a second kind of peer next to devices, with their own registry, grants and audit rows.
- A call between two services of the same instance is rejected, because that instance's supervisor is already busy
  with the caller. This is what [ADR-0001](0001-one-sandbox-per-script.md) resolves.
