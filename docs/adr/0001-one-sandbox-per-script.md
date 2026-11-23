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

## Implementation notes

Added with the first implementation slice. They settle the open points in *Consequences* above; they don't change
the decision.

### Sandbox model

- A **script sandbox** is a child instance of a scripting-plugin instance (the *parent*): the same component and the
  same pinned manifest, loaded into its own Wasmtime `Store` under its own supervisor task. The parent's supervisor
  compiles the component once, on its first load, and keeps the bytes and the compiled form for its lifetime; its
  restarts, its sandboxes and their restarts instantiate that, so a sandbox runs exactly the parent's code (a rebuilt
  dev `.wasm` is picked up only by a fresh start). A reinstall or upgrade needs a stop and start, so a new supervisor
  and a new compile; a load that resolves a different installation than the cached one is refused. The parent starts one with
  `host-sandboxes::start-sandbox(local-id, source)` and stops it with `stop-sandbox(local-id)`; `list-sandboxes`
  shows the live ones. Inside a sandbox, `current-sandbox()` returns the script's `local-id`, its instance id, the
  parent's instance id and the source, so the component's `init` knows which script to run. In a parent it returns
  `none`.
- `start-sandbox` returns as soon as the child supervisor is spawned; it doesn't wait for the child's `init`. Calling it again with the same `local-id` and the same source is a no-op that returns the
  same instance id, so a restarted parent can re-adopt its scripts. A different source for a live `local-id` is
  refused (`invalid-argument`): stop the old one first.
- `stop-sandbox` removes the sandbox from the parent's list at once and stops the child in the background. Until the
  child's supervisor is gone it still counts against the parent's limit, and starting the same `local-id` again
  answers `unavailable`; the parent retries.
- **Supervision.** Each sandbox has its own supervisor, restart policy (the manifest's `restart`), backoff, restart
  cap and liveness watchdog. A trap or a wedged loop in one script crashes and restarts only that sandbox. Sandboxes
  outlive a crash of their parent: they are still listed when the parent's next life runs `init`. They stop when the
  parent reaches a terminal state (stopped by the operator, or `Failed`), when the parent stops them, or on daemon
  shutdown. A terminal parent leaves the instance registry only after all its sandboxes have, so stopping it and
  then uninstalling never races a child that is still running. The API stop handlers wait for that release (bounded
  by `STOP_WAIT_LIMIT`, 75 s; past it they answer with the instances still stopping).
- **Stopping.** A stop gives a plugin call in flight a 2 s grace, then cancels it, so a script blocked in a host
  import (a WASI `sleep`, a slow `call-service`) can't hold its stop up; the epoch watchdog only interrupts guest
  code. A cancelled call's caller hears `unknown` (it may have acted), and `on-shutdown` is skipped. `on-shutdown`
  itself is bounded by the watchdog deadline in wall-clock time. `Stopped` is published only after the `Store` is
  dropped.
- Sandboxes don't nest: `start-sandbox` from inside a sandbox is `permission-denied`. Only instances the engine
  starts and reaps can start sandboxes; one driven without that (the test host's unsupervised `load`, the
  `supervise*` helpers) gets `unavailable`. An instance's sandbox role is set before its component is
  instantiated.
- A singleton plugin can't run sandboxes: every sandbox is another copy of the component, which would break the
  exclusivity `singleton` promises. Manifest validation refuses `singleton = true` with `script_sandboxes > 0`.
- A sandbox's KV, blob and device-state rows key on its own instance id, so each script has its own storage that
  survives its restarts, its parent's restarts and its parent stopping (the parent re-creates it later).
  `stop-sandbox` means the script is removed: once the sandbox is gone, the host purges its KV and blob storage and
  drops its device-state generation and publish rate limiter, before the `local-id` can be started again. A plugin
  that changes a script's source (stop, then start) starts the new version with empty storage; state that must
  outlive the script belongs in the parent's storage. Purging on removal was chosen over a per-plugin budget across
  sandbox namespaces: it needs no new accounting, and with it the live-sandbox limit bounds a plugin's stored data
  (at most `script_sandboxes` live namespaces, plus those its parent stopped without removing). Its device-state
  entries stay, `stale`, under the projection's stale cap.
- The purge waits for any KV or blob operation still running for the sandbox (a stop cancels a guest call blocked
  past its grace period, but the blocking storage write it started runs on), for up to 5 s. It is announced by a
  `sandbox_removal` row (migration 21) that `stop-sandbox` writes before it returns and the purge deletes once it
  succeeds; while the row exists the `local-id` can't be started again (`unavailable`) and the removed sandbox still
  counts against `script_sandboxes`. A purge that fails, or that a shutdown or crash cuts off, keeps its row and runs
  again at the next boot, before any plugin (a boot that can't read the rows fails); uninstalling the plugin clears
  the rows with the rest of its storage.

### Identity

- A sandbox's instance id is `<parent-instance>~<local-id>`. `local-id` is 1–64 bytes of `[a-z0-9_-]`, starting with
  a letter or digit, and the whole id must still be a safe instance id (at most 128 bytes). `~` is reserved:
  `Engine::start_instance` refuses an operator-chosen instance id containing it, so a sandbox id can't collide with
  an ordinary instance. An existing instance whose id already contains `~` can't be started under that id any more; 0.x
  accepts the break ([ADR-0007](0007-0x-publication-policy.md)).
- The sandbox runs under the parent's installation identity (`plugin_id`, `installation_uuid`, load mode) and the
  same effective capabilities. The instance id is what distinguishes it everywhere else: service ownership, the
  `caller_instance` and `instance` axes of `consumes_services` grants, the delegation chain, audit rows, logs and
  the instance list in the API, which shows a sandbox's `parent_instance_id` and `sandbox_local_id` (REST, Connect,
  MCP).
- The embedder entry points that bypass the instance registry (`PluginInstance::load*`, `supervise*`) refuse an id
  containing `~` and the id of a registered instance.

### Resource ceilings

The [ADR-0006](0006-resource-ceilings.md) ceilings are per `Store`, so each sandbox gets its own 128 MiB of linear
memory and its own table and instance caps, and the per-instance limits (KV and blob quotas, subscriptions, publish
and log rates) apply per script. A plugin's total is bounded by the number of sandboxes it may run, which the
manifest caps (below). There is still no CPU budget; the watchdog is per call, per sandbox.

### Dispatch between scripts

A script exposes its commands by registering a service in its own sandbox. Because every script has its own
instance, scripts of one plugin can all use the same service `local-id` (the example uses `script`), and a script
addresses another as `(plugin-id, <parent>~<other-local-id>, local-id)` through `resolve-service`. Script A calling
script B is then an ordinary cross-instance `call-service`: the dispatcher checks the caller's `consumes_services`
grants (requested ∧ granted) against B's sandbox instance id and A's as `caller_instance`, refuses cycles
(A → B → A) and expired deadlines, clamps the hop to the root's remaining deadline, and writes the H6 hop rows with
the full delegation chain for externally-rooted invocations. The same-instance refusal stays: a script calling a
service in its own sandbox is still refused.

If B traps after the call reached it, A gets `command-result::unknown` (H5: B may have acted) and B restarts under
its own policy. A call that never reached B (B restarting, not running, deadline passed before dequeue) is
`unavailable`.

### Manifest and grants

- `[capabilities] script_sandboxes = N` lets each instance of the plugin run up to `N` sandboxes at once (`0`, the
  default, refuses `start-sandbox` with `permission-denied`). Manifest validation caps `N` at 64. The effective
  value is the minimum of the requested and the granted value, like the storage quotas.
- Scripts are not listed in the manifest: users write them at run time. Their grants are ordinary
  `consumes_services` entries. A scripting plugin requests `{plugin = <self>, instance = "*", service = "script",
  commands = ["*"]}` to let scripts call each other, and an operator narrows the granted copy per script with exact
  `instance` / `caller_instance` values such as `main~house-mode`. Every sandbox otherwise inherits the plugin's
  capabilities. Grants that differ per script beyond these two axes are deferred.

### Deferred

- Per-script tuning of the ceilings, and a per-plugin aggregate memory budget across sandboxes.
- Persisting sandboxes across daemon restarts on the host side: the parent re-creates them from its own storage in
  `init`.
- Saying in the WIT's `stop-sandbox` docs that the sandbox's storage goes with it.
