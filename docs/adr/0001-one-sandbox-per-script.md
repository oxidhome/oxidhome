# ADR-0001: One sandbox per script for same-instance script calls

- **Status:** accepted
- **Date:** 2026-11-22
- **Deciders:** the maintainer
- **Supersedes:** [ADR-0004](0004-scripts-as-services.md), in part (all scripts sharing one Wasmtime `Store`)
- **Superseded by:** none
- **References:** architecture review finding H1

## Context

[ADR-0004](0004-scripts-as-services.md) makes every user script a service, but runs all scripts of a scripting plugin
inside one plugin instance, so one Wasmtime `Store`. The service dispatcher rejects a call whose caller and target are
the same instance (`same-instance dispatch is not supported`): the target's supervisor is already busy waiting for the
caller, so the call would deadlock. The main scripting use case, one script calling another (`evening-routine` →
`house-mode`), therefore cannot use `host-services::call-service`. Routing it inside the plugin instead would skip the
host's grants, audit, deadlines and tracing.

## Decision

Each script runs in its own sandbox: a child instance with its own Wasmtime `Store`, created and supervised by the
host on behalf of the scripting plugin. A script-to-script call is then a normal cross-instance call through the host
dispatcher, with the same grant checks, audit rows, deadlines and cycle detection as any other service call.

## Rejected options

- **An internal broker in the scripting plugin.** Calls between scripts would never reach the host, so grants, audit
  and deadlines would have to be duplicated in every scripting plugin, and the host could not see or enforce them.
- **Plugin-local-only calls.** Scripts could call each other only through plugin code, not through the service API.
  That breaks the "every script is a peer" model and leaves those calls invisible to the host.

## Consequences

- The plugin lifecycle gains dynamic child instances: a scripting plugin asks the host to start and stop one sandbox
  per script, and the supervisor, restart policy and state keying have to cover them.
- Each script pays the memory and start-up cost of its own `Store`. The C4 ceilings
  ([ADR-0006](0006-resource-ceilings.md)) then apply per script instead of per scripting plugin.
- The dispatcher keeps rejecting same-instance calls; a script never calls a service in its own sandbox.
- Implementation starts with a design PR that settles the child-instance lifecycle, identity and grant model before
  any code lands.
