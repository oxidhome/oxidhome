# ADR-0010: Authorization model for sensitive actions and per-resource permissions (H6 slice 2)

- **Status:** proposed
- **Date:** 2026-11-22
- **Deciders:** the maintainer (decision pending)
- **Supersedes:** none
- **Superseded by:** none
- **References:** architecture review 2026-07-28, H6 (with C5, H10, M7); H6 slice 1 (`auth::InvocationContext`);
  [ADR-0001](0001-one-sandbox-per-script.md) (sandbox children); [ADR-0009](0009-durable-device-state.md)
  (`reads_state` grants); `crates/oxidhome-core/src/api/scopes.rs`, `crates/oxidhome-core/src/auth/`

This record proposes a design and asks for a decision. Nothing in it is implemented. It is long because it compares
three options on the same ten scenarios. Read **Summary**, **Context**, **Options compared**, **Recommendation** and
**Questions for the maintainer** (about 20 minutes); the scenario listings are in Appendix A.

## Summary

- **Recommendation:** one host function, `authorize(ctx, action, resource) -> Decision`, called at every boundary
  (REST, Connect, MCP, WIT host calls, the service dispatcher). Behind it, the **Cedar** policy engine
  (`cedar-policy` crate) with a host-owned schema, a fixed set of **role presets** and **templates**, and a small set
  of built-in `forbid` rules for sensitive categories. Users pick presets and fill in slots (area, devices, plugin);
  they never have to write a policy.
- **What is needed whatever the engine:** a host-owned resource model (device category, area, tags), host-derived
  sensitive categories that wildcards do not match, the root's limits applied on every delegated hop, and root
  attribution on events. That is most of the work and most of the value. The engine choice is the smaller decision.
- **Why Cedar over a hand-rolled A+B:** OxidHome needs deny rules that beat any allow ("never the alarm, even with a
  wildcard"), conditions on context (daytime, someone home), and policies the host can validate before accepting.
  A+B can cover the ten scenarios here with a `deny` list and fixed equality conditions, at moderate cost. The
  margin for Cedar is the next rule nobody planned for: with A+B every new shape is a code change and a new piece of
  unspecified semantics; with Cedar it is validated policy text. The margin is real but not large, and Cedar still
  needs a fair amount of host code around it (Interface).
- **Cost of Cedar (measured, see Costs):** about 6–7 MB of stripped binary, 60 packages new to the lockfile, about
  300 s of extra CPU time for a cold release build, and 25–35 µs per decision with 50 policies on an Apple M1 core
  (roughly linear in the number of policies evaluated). The latency is fine for commands; list endpoints need
  per-principal policy slicing to stay cheap on a Raspberry Pi.
- **Fallback:** the `authorize()` interface does not expose Cedar types. If Cedar proves too heavy, options A+B
  (scopes with resource selectors, plus roles) can sit behind the same interface, and the presets keep their names.

## Context

### What exists today

- **Tokens carry flat scopes.** `auth_token.scope_json` is a list of strings such as `devices:command`, or `["*"]`
  for the bootstrap admin token (`api/scopes.rs`). A scope is matched literally; `*` matches everything.
- **One per-resource check exists.** The 14.4 token policy adds per-tool constraints. Only two keys are enforced: a
  `device.send_command` device-id allowlist (literal ids or `dev-…*` globs, `auth::authorize_device_command`, on REST,
  Connect and MCP) and a `plugins` allowlist on the MCP `plugins.*` tools. A token that names any other constraint key
  is refused at verify time so it can't be silently unrestricted.
- **Checks are per route.** About 60 `require_scope` uses across `api/server.rs` (REST), `api/connect_rpc.rs`
  and `api/mcp/*`, each choosing its own scope constant and, where it has one, its own resource check.
- **Plugins are authorized by manifest grants, not scopes.** `[capabilities]` in the manifest is a request; the
  operator-approved copy in `plugin_installation.granted_capabilities_json` is the grant; the effective permission is
  their intersection (C5). Each grant kind has its own matcher at its own call site: `consumes_services` in the
  dispatcher (H10), `reads_state` in `runtime::state_read` (H2), `subscribes_events`, `script_sandboxes`, `network`,
  `declares_devices` / `declares_services`, storage and blob quotas.
- **H6 slice 1 carries the root, not its authority.** Every external request mints an `InvocationContext` (call id,
  root `Principal` with subject, credential and transport, executing instance, deadline, delegation chain). It rides
  `ControlCommand::Execute` / `ExecuteService` and is a `task_local` while the plugin runs. Hop audit rows carry the
  root. But `Principal` holds only ids, not the root's scopes or constraints, and the dispatcher authorizes a hop on
  the calling plugin's `consumes_services` alone.
- **No sensitive data model.** The WIT capability set is `switch`, `dimmer`, `color-light`, `sensor`, `button`,
  `video-stream`, `audio-stream` and `extension(...)`. There is no lock, opener or alarm capability, so a door lock
  today registers as a `switch` or as a plugin extension and nothing in the host knows it is a lock. There are no
  areas, no tags, no users and no roles. Device names can be overridden, but nothing else about a device is
  operator-owned.

### Failure modes

1. **`devices:command` covers every device, including locks.** The 14.4 allowlist narrows by opaque device id only.
   An operator who wants "lights but not locks" must enumerate every light id and update the token when a light is
   added. The planned "sensitive-action policy" (`.claude/docs/00_OVERVIEW.md`, `03_core.md`, `10_mcp.md`) has no
   data to key on.
2. **Per-route checks drift.** Each of the ~60 sites picks its scope and resource check by hand, per transport.
   14.4 had to add a per-transport allowlist of enforced constraint keys, because a constraint enforced on one
   transport but not another would be silently unrestricted there. A new route that forgets the resource check is
   broader than its siblings, and nothing notices.
3. **The root's limits stop at the first hop (confused deputy).** A token allowed to command one device of a
   scripting plugin triggers a script; the script's `call-service` is checked against the script plugin's
   `consumes_services` only. If the plugin may call the lock plugin's `unlock` service, the narrow token has
   effectively unlocked the door. The audit row names the token, but nothing refused it.
4. **Events lose root attribution.** A WIT `event` carries host-stamped `origin-plugin-id` / `origin-instance-id` but
   no call id. Subscribers' `on-event` runs under a host-origin context rooted at the subscriber. "Which request made
   the alarm go off" can't be answered from `GET /api/v1/audit?call_id=…` once an event is in the path.
5. **Wildcards grant everything forever.** `*` tokens and the `mcp-stdio` session (which runs as an ambient
   `mcp-stdio-parent-process` actor with `*`) automatically gain every future capability, including future sensitive
   ones. Plugin grants can also use `*` (`reads_state.plugin`, `consumes_services.instance`), with the same effect.

## Resource model

Authorization keys on **host-owned** attributes. A plugin can describe its devices, but it never sets an attribute a
policy decides on, except where the table says so and the host validates it.

| Kind | Attributes | Who sets them |
|------|------------|---------------|
| Device | `id` (`dev-<16 hex>`) | Host, from installation UUID + local id (C1). |
| | `capabilities` (set of capability keys) | Plugin at `register-device`, checked against `declares_devices`. |
| | `category` (`light`, `lock`, `opener`, `alarm`, `camera`, `climate`, `sensor`, `other`, …) | **Host-derived** from capabilities (table below). Operator may **raise** it (mark a `switch` that drives a garage door as `opener`), never lower it. Plugin cannot set it. |
| | `sensitive` (bool) | Host: true when the category is sensitive. Operator may set true, not false. |
| | `plugin`, `installation`, `instance` | Host (owner of the registration). |
| | `area` | Operator. **Missing:** no area model exists. Needs an `area` table (id, name, parent) and a device → area assignment. |
| | `tags` | Operator. **Missing:** no tag model. Plugin-supplied `metadata` is not used for authorization. |
| Service | `plugin`, `instance`, `local_id`, `commands` | Host from `register-service` (immutable `local-id`, H10). |
| | `sensitive` (per service or per command) | Operator. A script service "open garage" is sensitive even though it is not a device. |
| Plugin / instance | `plugin_id`, `installation`, `instance_id`, `parent` (sandbox child `p~s` → parent `p`) | Host. Publisher identity is future work (C5). |
| Event | `topic`, `device` (and that device's attributes), `origin_plugin`, `origin_instance`, `call_id` | Host stamps origin and (new) call id; topic and device come from the publisher, checked by C2. |
| State entry | device attributes + `capability`, `has_bytes` | Host projection (H2). |
| Blob | `instance`, `name`, `class` (`snapshot`, `audio`, `inference`, `other`) | Host (instance). **Missing:** `blob-store` writes carry only a name, bytes and an optional MIME type, so the host has no provenance to derive `class`; a plugin that registers `video-stream` devices would have to be treated as producing camera blobs, or blobs stay unclassified. |
| Config | `instance`, `key`, `secret` (M7) | Manifest schema (`type = "secret"`); values by operator. |
| Host (admin) | singleton; actions below | Host. |

**Category derivation.** This is the part that must not be plugin-controlled.

| Category | Sensitive | Derived from |
|----------|-----------|--------------|
| `lock` | yes | new standard capability `lock` |
| `opener` (garage door, gate) | yes | new standard capability `opener` (or `cover` with `kind = garage`) |
| `alarm` (panel, siren) | yes | new standard capabilities `alarm-panel`, `siren` |
| `camera` | yes for `blob.read` / bytes, no for control (open question 4) | `video-stream` |
| `light` | no | `color-light`, or `dimmer` with `switch` |
| `switch` | no | `switch` alone (a plug or relay); the operator raises it when it drives a door or siren |
| `climate`, `sensor`, `media`, `other` | no | as named |

Rules: a device's category is the most sensitive category any of its capabilities implies. An `extension(...)`
capability maps through a host-maintained table of known extension ids; an unknown extension is `other`, which is
**not** sensitive (open question 3). This needs new WIT capabilities, a contract change under
[ADR-0007](0007-0x-publication-policy.md).

**The category is a durable floor.** `update-device` and re-registration can replace a device's capability list, so
the host persists the highest category it has seen per device id (with the operator's raises) and never lowers it
on its own; only the operator can. This stops a plugin from turning a known lock into a switch. It does not stop a
plugin from registering hardware as a plain `switch` under a fresh local id from the start, or from exposing a lock
through an unmarked service: classification cannot be stronger than the trust placed in the plugin at install. New
devices and services from plugins that hold sensitive grants should be surfaced to the operator for classification.

## Action taxonomy

Actions are `kind.verb`. Each existing scope maps onto one or more actions. Sensitive actions are marked; a wildcard
never matches them.

| Today's scope | Action(s) | Resource | Notes |
|---------------|-----------|----------|-------|
| `devices:list` | `device.list` | Device | Lists become filtered per device, not all-or-nothing. |
| `devices:read` | `device.read` | Device | |
| `devices:command` | `device.command` | Device (+ `context.command.capability`, `.verb`) | **Sensitive** when the device is. Verb-level rules are possible ("lock but not unlock"). |
| `events:tail` / `events:read` | `event.subscribe` / `event.read` | Event | Filtered by the event's device attributes. |
| `blobs:read` | `blob.read`, and the bytes in state/events/results | Blob / Device | **Sensitive** for camera class (open question 4). |
| `instances:list`, `plugins:list` | `instance.read`, `plugin.read` | Instance / Plugin | `plugin.read` covers `/schema` too. |
| `plugins:start` / `plugins:stop` | `instance.start` / `instance.stop` | Instance | |
| `plugins:install` / `plugins:uninstall` | `plugin.install` / `plugin.uninstall` | Host / Plugin | **Sensitive.** |
| `plugins:ui` | `plugin.ui` | Plugin | |
| `dashboards:read` / `:write` | `dashboard.read` / `dashboard.write` | Dashboard | |
| `status:read`, `logs:read` | `host.status`, `host.logs` | Host | |
| `audit:read` | `host.audit` | Host | **Sensitive** (reveals who did what). |
| (none; CLI only today) | `token.manage`, `policy.manage` | Host | **Sensitive.** Needed once tokens and policies are managed over the API. |
| (none) | `service.call` | Service | For tokens: a future direct service-call API, and the strict delegation variant. |
| `consumes_services` | `service.call` | Service | Plugin principal. |
| `reads_state` | `state.read` | State entry | Plugin principal. |
| `subscribes_events` | `event.subscribe` | Event | Plugin principal. |

Kept **outside** the engine, as manifest-only checks: `network` (host/port patterns, not a host entity; per-socket
enforcement is itself future work), `declares_devices` / `declares_services` (what a plugin may register, not what
it may touch), quotas and `script_sandboxes` (counts, not permissions). They still show in the install-time review.

## Options compared

All three put the same `authorize()` in front and use the same resource model; they differ in how a grant is written
and evaluated. Appendix A writes ten scenarios in each form.

- **A: scopes plus resource selectors.** Extend today's token policy: each grant is
  `{actions, resources: {category, area, plugin, devices, tags}}`, plus a `deny` list that wins over grants. Plugin
  manifest grants keep their own shapes. Hand-rolled in Rust.
- **B: roles on top of A.** Named bundles of A-grants (`owner`, `admin`, `resident`, `guest`, `dashboard`,
  `monitor`, `assistant`); a token holds roles plus optional extra grants or narrowing.
- **C: a policy language (Cedar).** Grants are Cedar `permit` / `forbid` policies over a host schema. Roles are
  Cedar entities (`Token in Role::"guest"`); scoped presets are Cedar templates with slots
  (`resource in ?resource` for an area). Manifest grants are compiled into generated policies.

| Criterion | A | A+B | C (Cedar) |
|-----------|---|-----|-----------|
| "Lights in the living room" without listing ids | yes (selectors) | yes | yes |
| Deny that beats any allow ("never the alarm") | a `deny` list checked once in `authorize()` | same | built in (`forbid` always wins) |
| Context conditions (daytime, someone home, confirmed) | fixed equality on host context keys | same | built in, any boolean expression |
| Verb-level rules (lock yes, unlock no) | another selector axis | same | `context.command.verb == "lock"` |
| Validation before a policy is accepted | we write it | we write it | schema validator in the crate |
| Semantics documented and tested elsewhere | no | no | yes (formal spec, differential testing) |
| Explaining a decision | we write it | we write it | determining policy ids returned with every decision |
| Users must learn a syntax | no | no | no for presets; yes for custom rules |
| Dependency cost | none | none | see Costs |
| Conditions on live device state | host must put it in the request | same | same |
| Host code still needed | evaluator, selectors, deny, conditions, explanations | + roles | entity building, obligations, chain evaluation, slicing, diagnostics checks |
| Effort to first useful slice | low | medium | medium |
| Effort to reach scenarios 4, 6, 7 | medium | medium | low |
| Custom rules beyond the presets | each new shape is a code change | same | text, validated |

### Alternatives to Cedar

- **OPA / Rego.** OPA is a Go service; running it as a sidecar on a Raspberry Pi is out. `regorus` (Microsoft) is a
  Rust Rego interpreter and is embeddable, so "not embeddable" is no longer true. It loses anyway: Rego is a general
  query language, deny-overrides must be written by hand, there is no typed schema validation of the Cedar kind, and
  presets would be Rego modules users could not safely edit.
- **Oso / Polar.** The open-source library is deprecated (Oso moved to a hosted service). Not a candidate.
- **casbin-rs.** Active, supports RBAC and ABAC with a configurable deny-overrides effect. Its matchers are untyped
  expression strings and its policies are CSV-like rows; there is no schema validation, and attribute access needs
  custom functions. It is a reasonable engine for B, not a better C.
- **Biscuit tokens.** Datalog checks inside the token, with offline attenuation. Attractive for delegation, but it
  replaces the token format and moves policy into credentials. Out of scope.
- **Hand-rolled** is options A and B.

## Sensitive categories

**Sensitive:** `lock`, `opener`, `alarm` (device commands); `camera` bytes and blobs (privacy, open question 4);
`plugin.install`, `plugin.uninstall`; `token.manage`, `policy.manage`; `host.audit`. A sensitive service or service
command is whatever the operator marks.

Rules, identical in every option:

1. **Wildcards don't match.** `*`, `action` with no constraint, a role that grants "all devices", or a plugin
   `reads_state` / `consumes_services` wildcard never covers a sensitive resource. Only a grant that names the
   category does. In Cedar this is one built-in `forbid ... unless { principal.sensitive_grants.contains(...) }`,
   where `sensitive_grants` is a principal attribute set only by an explicit grant (Appendix B).
2. **Explicit grant.** The token or plugin holds the category by name (`sensitive: ["lock"]`). The UI shows it as a
   separate checkbox with a warning, never inside a preset by default except `owner`. The appendix keeps this as one
   principal-wide set for brevity, which has a gap: a principal with `lock` for one door and a broad permit elsewhere
   reaches every lock. The implementation should bind the sensitive grant to its scope, for example by mapping a
   command on a sensitive device to a separate action (`device.command.sensitive`) that only an explicit, scoped
   permit names, and by refusing stored policies with an unconstrained `action` other than the host's own
   `owner` / `admin` presets.
3. **Obligations on allow.** An allowed sensitive action always writes its audit row at `warn` with the determining
   policy ids. It may also carry a **rate limit** (per principal per category, e.g. 5 per 10 min) and a
   **confirmation** requirement (the request must carry a fresh confirmation: a second factor, an MCP elicitation
   answer or a UI prompt; the host sets `context.confirmed`). In Cedar these ride as annotations on the permitting
   policy (`@rate("5/10m")`, `@confirm("true")`); `authorize()` turns them into `obligations`, taking the union
   over all determining permits. A condition that must always hold is written as a `forbid`, not on a permit (see
   scenario 6). A confirmation is bound to the specific command and call id, so it cannot be replayed. The rate
   limiter can reuse the MCP per-token token bucket (14.7b).
4. **Bytes follow one decision.** If camera bytes become sensitive, the same decision gates `blob.read` and the
   `bytes-val` fields in state, events and command results (today's M7 withholding), and the `admin` preset does
   not include it.
5. **Denies are quiet to the caller.** The response stays a bare 403 / `permission-denied`, as today; the reason goes
   to the audit row only.

## Delegation

The chain from H6 slice 1 already exists. The proposal adds authority to it.

- **Carry the root's authority.** `InvocationContext` gains the root's resolved principal (token id, roles,
  sensitive grants, constraints), not just its id. It stays host-only.
- **Rule for every hop:** `allow = permit(root) ∧ permit(executing plugin) ∧ no forbid matches for any principal
  on the chain`.
  - The **root** must be permitted the action on the resource. This keeps a narrow token's allowlist intact: a
    guest-room token or a one-button token cannot have a script use the script's broader grants on its behalf. For
    plugin-only actions the host asks the token-facing equivalent (`state.read` → `device.read`,
    `event.subscribe` → `event.read`).
  - The **executing plugin** must be permitted by its own compiled grants. This is today's H10 / H2 check.
  - **Every principal on the chain contributes its forbids**: the root and each plugin that made a hop. A plugin that
    may not touch the alarm cannot launder the call through a second plugin, and an assistant's "never locks" rule
    travels with the work. Intermediate plugins' permits were checked on their own hop.
  - **Delegation grants.** A token that should run a scene whose script calls other services gets explicit
    `service.call` permits for those services (a template: "this token may trigger these services"). Presets that
    command devices (`resident`, `admin`) include `service.call` on non-sensitive services; `guest`, `dashboard` and
    `monitor` do not. A looser variant drops the root-permit term and keeps only the root's forbids; it is simpler for
    users, but a narrow token's allowlist then stops at the first hop (open question 5).
  - In Cedar this is one authorizer call per chain principal. For the root and the executing plugin the decision
    must be `Allow`; for intermediate plugins only a deny with determining policies (a forbid) counts.
- **Host-rooted work** (`tick`, `init`, `on-event`) keeps the plugin as its root, as today, so only the plugin's own
  grants and forbids apply.
- **Events carry attribution, not authority.** The host stamps the publishing invocation's `call_id` (and root
  principal id) on the event and on `event_log`. A subscriber's `on-event` records it as `caused_by` in its own
  context and audit rows, so `?call_id=` follows the reaction. It does **not** inherit the root's authority: an event
  is a fact delivered to many subscribers, and making every automation run under whichever token caused the event
  would break automations unpredictably. (Open question 6.)
- **What the chain does not cover.** The guarantee holds for synchronous chains only. Work started by an event, a
  `tick` or a sandbox `init` runs with the plugin's own authority, so a plugin that holds a sensitive grant and
  subscribes to events is an independently privileged automation: whoever can cause a matching event can trigger
  it. Such grants are therefore explicit, shown at install time, and audited at `warn` with `caused_by`. The audit
  query also needs a `caused_by` filter, since `?call_id=` is an exact match today.
- **Sandbox children.** A child `p~s` is its own principal whose parent is `p`; grants written for the installation
  apply to both (they already share `reads_state` / `consumes_services`, ADR-0001). Per-script narrowing names the
  child (`principal == Instance::"p~s"`) or uses `caller_instance` as today.
- **Cost.** One evaluation per principal on the chain: two for a first hop (root, plugin), one more per further
  hop. Chains are short (cycle detection, deadline).

## Unifying plugin grants

**Recommendation:** manifest grants stay manifest fields and stay the source of truth. At load, the host compiles the
effective grant (requested ∩ granted, C5) into generated Cedar policies owned by the installation, and loads them
into the same policy set as the user's rules.

- The install-time review keeps its current shape: the user sees what the plugin requests, in plain language. Today
  a fresh install copies the requested capabilities into the grant; operator narrowing at install is future work
  either way. Content binding (C5) and quarantine do not change.
- What changes: a user `forbid` ("no plugin may command alarms") now overrides a plugin grant, and plugin grants get
  the same sensitive-category rule and the same audit and explanation path as tokens.
- Sensitive plugin grants are a new explicit manifest request (`sensitive = ["lock"]` on a grant), shown separately
  at install time and never implied by `*`.
- The generated policies are derived data, rebuilt from the grant on every load; they are not edited by hand. They
  keep every selector of today's matchers (all five `consumes_services` axes; `reads_state` owner, capability,
  device and bytes; own entries by instance **and** installation, ADR-0009).
- **The manifest stays a ceiling.** User rules about plugin principals may only be `forbid`s; the host refuses a
  stored custom `permit` whose principal scope can match a plugin. A plugin is therefore allowed only by its own
  compiled grant, never by a user permit that reaches past what it requested.
- Not converted: `network`, `declares_*`, quotas, `script_sandboxes` (see Action taxonomy).

The alternative, plugins writing Cedar policies in the manifest, is rejected: it puts a policy language in the
plugin author's hands and makes install-time review harder to explain.

## Interface

```rust
pub fn authorize(ctx: &InvocationContext, action: Action, resource: &Resource) -> Decision;

pub struct Decision {
    pub allow: bool,
    pub reason: Reason,              // determining policy ids, or "no permit matched", or an evaluation error
    pub obligations: Obligations,    // audit_level (info/warn), rate_limit, require_confirmation
}
```

- `Action` is a closed Rust enum (the taxonomy above); `Resource` is a host struct built from the host's own
  registries, never from caller input. Neither exposes Cedar types, so A+B can replace the engine.
- **Call sites:** REST and Connect handlers, MCP tools and resources (replacing `require_scope` and
  `authorize_device_command`), the device-command path in `InstanceHandle`, the service dispatcher (replacing the
  `consumes_services` matcher), `host-state` reads, `host-events::subscribe` and event delivery, blob reads. Route
  scopes stay as a coarse pre-check during migration only.
- **List endpoints** call `authorize` per item (devices, state, events) and drop denied items silently, like
  `list-state` does today: a hidden item and an unknown one look the same, and filtering writes no per-item deny
  rows.
- **Streams** (`/events/tail`, Connect tails, MCP subscriptions) re-check each event at delivery against the current
  policy set; a revoked token or a policy change that removes access ends or filters the stream. Today's REST tail
  captures the byte permission once at upgrade; that changes.
- **Fail closed:** an evaluation error, a missing entity or an invalid policy set is a deny with reason `error`.
  Cedar skips a policy whose evaluation errors and decides on the rest, so the wrapper must check the diagnostics on
  every decision, including an `Allow`.
- **Audit:** every refused request or hop writes a row with the reason (policy id or `no-permit`) in
  `required_scope`; sensitive allows write a `warn` row; ordinary allows keep today's per-request row.
  Plugin-internal calls (`state.read`, `event.subscribe`) are audited on deny only, through H2's bounded queue.
- **Slicing** must keep every global and ancestor-scoped `forbid` (roles, plugins, areas) in each slice; only
  permits are sliced.
- **Performance:** the policy set is parsed and validated once, held in an `Arc`, and swapped atomically on reload.
  Entities for a request (principal with roles, resource with area ancestors, chain principals) are built from
  in-memory registries; no SQL on the hot path. No decision cache at first: measured latency (Costs) makes one
  unnecessary, and a cache would need invalidation on every area, tag, role and grant change. Policies are sliced
  by principal scope so a request evaluates the built-ins plus its own principal's and roles' policies.
- **Reload:** a policy change (preset assignment, area change, plugin grant) rebuilds the entity store or the policy
  set, validates it against the schema and swaps it in; a set that fails validation is refused and the old one stays.

## Costs

### Cedar dependency (measured)

Measured on 2026-11-22 with a scratch crate outside the repo: `cedar-policy = "=4.15.0"`, Rust 1.100.0, release
profile defaults, `aarch64-apple-darwin` on an Apple M1 (8 cores). Five other builds were running on the machine
(load average 40–97), so wall-clock times are inflated; CPU times are the steadier figure. The baseline is the same
binary with only `serde` and `serde_json`.

| Measure | Baseline | With Cedar | Delta |
|---------|----------|------------|-------|
| Cold release build, wall | 19 s | 121–299 s | +100–280 s (load-dependent) |
| Cold release build, CPU (user) | 13 s | 307–318 s | about +300 s |
| Critical path | – | `cedar-policy-core` 87 s → `cedar-policy` 65 s, serial | |
| Binary, unstripped | 0.51 MB | 9.54 MB | +9.0 MB |
| Binary, stripped | – | 7.2 MB | about +6.7 MB |
| Crates (normal deps / with build deps) | 12 | 69 / 108 | |
| Packages not already in OxidHome's `Cargo.lock` | – | 60 (lockfile to lockfile) | `lalrpop`, `logos`, `miette`, `petgraph`, `serde_with`, `stacker` / `psm`, `smol_str`, … |

- Turning off the default features (`datetime`, `decimal`, `ipaddr`) made no measurable size difference.
- The binary delta inside OxidHome would be somewhat lower, since `regex`, `aho-corasick` and `serde` are already
  linked; about 6 MB stripped is a fair estimate, not a measurement.
- Licences of all new crates are MIT, Apache-2.0 or dual, which `deny.toml` already allows.
- `stacker` / `psm` build a little assembly through `cc`; it supports `aarch64-unknown-linux-gnu`.
- Raspberry Pi: not measured. A Pi 4 core is several times slower than an M1 core, so a cold native build on a Pi
  would gain on the order of ten minutes, dominated by the two serial Cedar crates. Cross-compiling, or building
  only release artifacts in CI, avoids paying it on the device. Incremental builds are unaffected once the crate is
  compiled.

**Evaluation latency** (thread CPU time per `is_authorized` call, 50 policies, 250 entities, mixed allow/deny):

| Measure | Result |
|---------|--------|
| 1 / 13 / 50 policies | 0.7–0.9 / 8–11 / 25–37 µs per decision |
| Building the `Request` and `Context` with schema checks | +12–15 µs per decision |
| Parse schema / parse 50 policies / validate them | 1–3 ms / 1–1.4 ms / 1.2–1.4 ms, once per reload |
| Load 250 entities (devices, areas, roles, tokens, instances) | 5.5–6 ms, once per change |

Limits of the benchmark: entities are prebuilt, the 1/13-policy figures take the first policies rather than a real
slice, and there is no end-to-end list or chain measurement and no Pi run. Cedar evaluates every policy in the set
for each request, so cost grows linearly. With 50 policies a device command
pays about 40–50 µs including request building, which is noise next to a plugin call. A list of 200 devices would cost
about 10 ms on the M1 and, by estimate, a few tens of milliseconds on a Pi 4. The fix is **per-principal policy
slicing**: index policies by their principal scope (Cedar exposes it) and evaluate only the built-ins plus the slice
for the request's principal and roles, which keeps the evaluated set near the 13-policy figure.

### Policy authoring

- **Presets first.** `owner`, `admin`, `resident`, `guest`, `dashboard`, `monitor`, `assistant`. A token gets one
  role plus optional slots (area, plugin, device list) and optional sensitive categories. The CLI and UI never show
  Cedar for these.
- **Templates** cover the scoped presets (`guest` in an area, `dashboard` for an area, "plugin X only"). Cedar
  templates allow `?principal` and `?resource` slots in the policy scope; that is enough for areas and plugins.
- **Custom rules** are an advanced path: Cedar text, validated against the schema before it is stored, and shown with
  a dry run ("this rule would change N decisions for these tokens").
- **Schema** is host-owned and versioned with the binary; a schema change that invalidates stored custom rules
  refuses to load them and reports which ones.

## Migration

| Today | After |
|-------|-------|
| `["*"]` bootstrap or recovered admin token | role `owner`: everything, including all sensitive categories. The label is not proof (any token can be labelled `admin`); the owner is the token recorded by the bootstrap or `recover-admin-token` audit rows, or the one the operator names |
| other `["*"]` tokens | role `admin`: everything **except** sensitive categories (**breaking**) |
| `devices:command` | `device.command` on non-sensitive devices (**breaking** for locks, openers, alarms) |
| any 14.4 constraint (`device.send_command` devices; `plugins.show` / `start` / `stop` / `uninstall` / `install` plugins) | carried over as a per-token `forbid ... unless` on that action, so the token is never broader than today; `plugins.install` keeps its manifest-derived check before side effects |
| any other scope | the matching action(s) on all resources |
| `plugins:install` / `plugins:uninstall` | `plugin.install` / `plugin.uninstall`; already explicit, so they count as the explicit sensitive grant |
| `audit:read` | `host.audit`; already explicit |
| `mcp-stdio` ambient `*` | a `local-process` principal (no credential id) with role `admin` and no sensitive grants unless the operator passes a flag (open question 7). The launching process can already read the state directory, so this limits an AI client, not a local attacker |
| plugin grants | compiled policies; same effect, plus the sensitive rule |

**Breaking change.** Existing wildcard and `devices:command` tokens lose access to sensitive categories. In practice
the break is small today: no device is classified sensitive until the new capabilities land and plugins adopt them,
or an operator marks a device. Recommended handling: migrate in one release, log every token that lost access at
`warn` on startup, and document `oxidhome token grant-sensitive <id> lock` (or the UI equivalent). The legacy
`scope_json` array stays readable; tokens are not rewritten in place.

## Recommendation

Adopt option C with Cedar behind a single `authorize()` interface, role presets and templates so users never write
policies, host-derived sensitive categories that wildcards never match, and the root's limits applied on every
delegated hop. Build the interface and the resource model first (every option needs them), so the engine decision
can still be reversed at low cost until the third PR.

The margin over A+B is moderate, not decisive. A+B handles every scenario here with a `deny` list and fixed
conditions. Cedar wins on what comes after: custom rules as validated text instead of code changes, specified
semantics, and decision explanations for free. If the binary and build cost above is unacceptable, or the
maintainer wants presets only and never user-written rules, A+B behind the same interface is the better choice.

## Questions for the maintainer

1. **Engine:** Cedar (C), or A+B behind the same interface? The first two PRs are the same either way.
2. **WIT:** add `lock`, `opener`, `alarm-panel`, `siren` as standard capabilities in the next contract bump? Without
   them the host cannot derive categories and sensitive protection depends on operators marking devices.
3. **Unknown extensions:** should a device with only unknown `extension(...)` capabilities be `other` (usable, not
   protected) or sensitive until classified (safe, but breaks wildcard tokens for those devices)?
4. **Cameras:** is camera bytes/blob access a sensitive category (privacy), or does today's `blobs:read` scope
   suffice? Is camera *control* (pan, privacy shutter) sensitive?
5. **Delegation strictness:** on a delegated hop, require the root's permit as well as its forbids (recommended;
   scene and button tokens then need explicit `service.call` delegation grants), or apply only the root's forbids
   (simpler, but a narrow token's allowlist stops at the first hop)?
6. **Events:** attribution only (recommended), or should an `on-event` reaction inherit the causing root's forbids?
7. **mcp-stdio:** keep it as a trusted ambient admin, and if so with or without sensitive categories?
8. **Breaking change:** accept that `*` tokens other than the bootstrap owner lose sensitive access, with a startup
   warning, in a 0.x release?
9. **Areas and tags:** add the area/tag model as part of this work (needed by guest and dashboard presets), or ship
   presets keyed only on category and plugin first?
10. **Confirmation:** which second step counts for `require_confirmation` (UI re-prompt, MCP elicitation, TOTP), and
    is it needed in the first release or only the rate limit and `warn` audit?
11. **Multi-user:** should `User` principals (people with roles, tokens belonging to a user) land with this, or stay
    deferred with tokens as the only principal?

## Implementation slicing

For the recommended option. Slices 1 and 2 are engine-independent.

1. **`authorize()` facade and action enum.** Introduce `Action`, `Resource`, `Decision`; route every REST, Connect
   and MCP check and `authorize_device_command` through it with an evaluator that reproduces today's scope semantics
   exactly. No behavior change; removes per-route drift. Carry the root's resolved authority in `InvocationContext`.
2. **Resource model and sensitive categories.** WIT capabilities (`lock`, `opener`, `alarm-panel`, `siren`),
   host-derived category, `device_meta` table (area, tags, operator category raise), sensitive rule with `warn` audit
   and per-category rate limit, startup report of affected tokens. The breaking change lands here.
3. **Cedar engine.** Add `cedar-policy`, the schema, built-in forbids, role presets and templates, token → role
   assignment, policy storage with validation and atomic reload, CLI for presets. The legacy evaluator becomes a
   generated policy set.
4. **Delegation and events.** Root and plugin permits plus chain forbids on dispatcher hops (and on host-mediated device
   commands once they exist), `call_id` on events and `event_log`, `caused_by` in subscriber contexts.
5. **Plugin grants in the engine.** Compile `consumes_services`, `reads_state`, `subscribes_events` into generated
   policies; explicit sensitive plugin grants in the manifest and install review; user forbids over plugins.

## Rejected options

Pending the decision. If C is accepted, A and A+B are rejected because deny-overrides, context conditions and
validation would have to be built and specified by hand; Rego, Polar and casbin for the reasons under
*Alternatives to Cedar*.

## Consequences

If accepted as recommended:

- A new dependency of the size measured above, maintained by AWS under Apache-2.0, on the authorization hot path.
- One place decides every authorization; route scopes become a compatibility layer and then go away.
- Two new host-owned models (areas/tags, device category) and a WIT contract change for sensitive capabilities.
- A breaking change for wildcard and `devices:command` tokens on sensitive devices.
- Policies become data the host must validate, store, migrate across schema changes and explain in the audit log.

## Appendix A: Scenarios

Each scenario shows the A+B form (JSON token or role policy, with a `deny` list and a `when` mini-language where
needed) and the Cedar form. Cedar uses the schema in Appendix B.

The A+B form uses this shape, an extension of today's `{scopes, constraints}` token policy:

```json
{
  "roles":     [{"role": "guest", "area": "guest-room"}],
  "grants":    [{"actions": ["device.command"], "category": ["light"], "area": ["hall"], "plugin": ["…"],
                 "devices": ["dev-…"], "tags": ["…"], "when": {"occupied": true}}],
  "deny":      [{"actions": ["*"], "category": ["alarm"]}],
  "sensitive": ["lock"]
}
```

Roles are host-shipped bundles of grants with optional slots (`area`, `plugin`). `deny` wins over any grant.
`sensitive` is the explicit sensitive-category list. `when` is a fixed set of host context keys compared for
equality. Plugins keep their manifest grants and gain an operator `deny` list on the installation.

The Cedar form is the policy text the host stores. All of it was checked with the `cedar-policy` 4.15 validator
against the schema in Appendix B (strict mode), and each scenario's allow and deny cases were run through the
authorizer with the expected result. Policies marked *preset*, *template*, *built-in* or *compiled* ship with the
host or are generated; the user only links templates and picks options. The built-ins that apply everywhere are:

```cedar
@id("builtin.sensitive-device")
forbid (principal, action == OxidHome::Action::"device.command", resource)
when { resource.sensitive }
unless { principal.sensitive_grants.contains(resource.category) };

@id("builtin.sensitive-service")
forbid (principal, action == OxidHome::Action::"service.call", resource)
when { resource.sensitive }
unless { principal.sensitive_grants.contains(resource.category) };

@id("builtin.sensitive-plugins")
forbid (principal, action in [OxidHome::Action::"plugin.install", OxidHome::Action::"plugin.uninstall"], resource)
unless { principal.sensitive_grants.contains("plugins") };

// builtin.sensitive-tokens (token.manage, policy.manage) and builtin.sensitive-audit (host.audit) have the same shape.

@id("builtin.own-devices")
permit (
  principal is OxidHome::Instance,
  action in [OxidHome::Action::"device.read", OxidHome::Action::"state.read", OxidHome::Action::"device.command"],
  resource is OxidHome::Device
)
when { resource.installation == principal.installation && resource.instance == principal.instance };
```

### 1. Guest token

A visitor may use lights, media and climate in the guest room for the weekend. Nothing else.

A+B:

```json
{"roles": [{"role": "guest", "area": "guest-room"}]}
```

with the host role `guest = [{"actions": ["device.read", "device.command"], "category": ["light", "media",
"climate"], "area": "$area"}]`. "For the weekend" needs token expiry, which does not exist today (tokens have
revocation only); it belongs on the token, not in the policy.

Cedar (*template*, linked with `?principal = Token::"tok-guest"`, `?resource = Area::"guest-room"`):

```cedar
@id("template.guest")
permit (
  principal == ?principal,
  action in [OxidHome::Action::"device.read", OxidHome::Action::"device.command"],
  resource in ?resource
)
when { ["light", "media", "climate"].contains(resource.category) };
```

Guest-room lamp: allowed. Hall lamp: denied (no permit). Front door lock: denied by `builtin.sensitive-device`.

### 2. Lights-only wall dashboard

A tablet on the wall lists, reads and switches lights anywhere in the home, and shows their events.

A+B:

```json
{"roles": [{"role": "dashboard", "area": "home"}]}
```

with `dashboard = [{"actions": ["device.list", "device.read", "device.command", "event.read"], "category":
["light"], "area": "$area"}]`.

Cedar (*template*, linked with the token and `Area::"home"`):

```cedar
@id("template.dashboard")
permit (
  principal == ?principal,
  action in [OxidHome::Action::"device.list", OxidHome::Action::"device.read",
             OxidHome::Action::"device.command", OxidHome::Action::"event.read"],
  resource in ?resource
)
when { resource is OxidHome::Device && resource.category == "light" };
```

Hall lamp: allowed. Temperature sensor: not even listed.

### 3. Read-only monitoring token

Prometheus-style scraping: read every device and event and the host status; no commands, no camera bytes, no audit.

A+B: `{"roles": ["monitor"]}`, `monitor = [{"actions": ["read"]}]`, where the `read` group excludes `blob.read`
and `host.audit`.

Cedar (*preset*): `blob.read` is outside the `read` group and `host.audit` is in `sensitive_admin`.

```cedar
@id("preset.monitor")
permit (principal in OxidHome::Role::"monitor", action in OxidHome::Action::"read", resource);
```

Reading the lock's state: allowed. Switching a lamp: denied. Audit: denied by `builtin.sensitive-audit`.

### 4. MCP AI assistant

An LLM over MCP may read everything, command lights only, and must never touch locks, even if someone later adds
`lock` to its sensitive grants by mistake.

A+B:

```json
{"roles": ["assistant"], "deny": [{"actions": ["device.command", "service.call"], "category": ["lock"]}]}
```

with `assistant = [{"actions": ["read"]}, {"actions": ["device.command"], "category": ["light"]}]`. The `deny` must
be part of the role, or every assistant token has to repeat it.

Cedar (*preset*):

```cedar
@id("preset.assistant.read")
permit (principal in OxidHome::Role::"assistant", action in OxidHome::Action::"read", resource);

@id("preset.assistant.lights")
permit (principal in OxidHome::Role::"assistant", action == OxidHome::Action::"device.command", resource)
when { resource.category == "light" };

@id("preset.assistant.never-locks")
forbid (
  principal in OxidHome::Role::"assistant",
  action in [OxidHome::Action::"device.command", OxidHome::Action::"service.call"],
  resource
)
when { resource has category && resource.category == "lock" };
```

Tested with a token whose `sensitive_grants` contains `lock`: unlocking is still denied, by
`preset.assistant.never-locks`. The rule also covers `service.call` on lock-category services, so it holds on a
delegated hop through a script (scenario 10).

### 5. The Kasa plugin

Kasa controls its own plugs and bulbs, talks to the LAN, and must never operate an alarm.

- Own devices: in A+B, an implicit rule; in Cedar, `builtin.own-devices`. Today a plugin talks to its own hardware
  over the network and never asks the host, so this only matters for host-mediated paths (state reads, and a future
  `send-command` import).
- Network: stays the manifest rule `network = ["udp://192.168.1.0/24:9999", "tcp://192.168.1.0/24:9999"]`, outside
  the engine.
- No alarms:

A+B (operator deny list on the installation):

```json
{"plugin": "com.example.kasa", "deny": [{"actions": ["*"], "category": ["alarm"]}]}
```

Cedar (*user rule*, created from a "never allow this plugin to…" form):

```cedar
@id("user.kasa-no-alarm")
forbid (principal in OxidHome::Plugin::"com.example.kasa", action, resource)
when { resource has category && resource.category == "alarm" };
```

Kasa switching its own lamp: allowed. Kasa reading another plugin's sensor without a `reads_state` grant: denied.
Kasa and a siren: denied by both the built-in and the user rule.

### 6. Door unlock only when someone is home and it is daytime

An automation script `automation~arrival` may unlock the front door, and only when the home is occupied and it is
daylight.

Prerequisites in both options: a host-mediated device command from a plugin (a future `host-devices::send-command`
import; today a plugin cannot command another plugin's device at all), and host "home variables" (`occupied`,
`daylight`) computed from sources the operator chooses. Neither exists yet. Policies cannot read device state
directly; the host must put it into the request context.

A+B (on the script's installation; `when` is the mini-language):

```json
{"grants": [{"actions": ["device.command"], "devices": ["dev-9c1e04d2a7b3f610"], "verbs": ["unlock"],
             "when": {"occupied": true, "daylight": true}, "caller_instance": "automation~arrival"}],
 "sensitive": ["lock"]}
```

Here A+B has had to grow `verbs`, `when` and `caller_instance` axes.

Cedar (*user rule*; the instance holds `lock` in `sensitive_grants` through its explicit grant):

```cedar
@id("user.front-door-arrival.permit")
@audit("warn")
@rate("4/1h")
permit (
  principal == OxidHome::Instance::"automation~arrival",
  action == OxidHome::Action::"device.command",
  resource == OxidHome::Device::"dev-9c1e04d2a7b3f610"
)
when { context has command && context.command.capability == "lock" && context.command.verb == "unlock" };

// The condition is a forbid, so no other plugin permit can unlock this door at night or with nobody home.
// People (tokens) are not covered: the owner can still open the door at night.
@id("user.front-door-unlock-only-when-home-by-day")
forbid (principal is OxidHome::Instance, action == OxidHome::Action::"device.command", resource == OxidHome::Device::"dev-9c1e04d2a7b3f610")
when { context has command && context.command.verb == "unlock" }
unless { context.occupied && context.daylight };
```

Occupied and daylight: allowed, with a `warn` audit row and a rate-limit obligation. At night, or with nobody home:
denied by the forbid, for every plugin. A mandatory condition must be a `forbid`: had it been written only on the
permit, any other plugin permit would unlock the door at night and carry no obligation. Obligations are
the union over all determining permits plus the host's own (every sensitive allow is audited at `warn`).

### 7. A plugin that must never trigger the alarm, even with a wildcard

A lighting plugin was granted `consumes_services` with `instance = "*"` and `commands = ["*"]` on the alarm plugin,
and someone even granted it the `alarm` sensitive category. It still must not trigger the siren.

A+B: the same `deny` list as scenario 5, checked once in `authorize()` before the grant matchers.

Cedar (*user rule*):

```cedar
@id("user.lights-plugin-never-alarm")
forbid (principal in OxidHome::Plugin::"com.example.lights", action, resource)
when { resource has category && resource.category == "alarm" };
```

`service.call` on the siren service (operator category `alarm`): denied by this rule even though a permit and the
sensitive grant exist. Because the rule names the plugin, it covers every instance and every sandbox child.

### 8. Plugin install and remove restricted to admin

A+B: `plugins:install` / `plugins:uninstall` stay explicit grants that no role except `owner` includes and `*` never
matches.

Cedar: `builtin.sensitive-plugins` (above). An `admin` token without `plugins` in `sensitive_grants` is denied; the
owner token is allowed by `preset.admin`; a `resident` token is denied.

```cedar
@id("preset.admin")
permit (principal in OxidHome::Role::"admin", action, resource);
```

### 9. H1 sandbox children share the parent's grants

The scripting plugin's grant lets it call `increment` and `get` on the counter service. The operator wants only the
`evening` script to use it.

A+B: today's H10 shape already does this, with the operator narrowing `caller_instance`:

```toml
[[capabilities.consumes_services]]   # granted copy
plugin = "com.example.counter"
instance = "counter"
service = "counter"
commands = ["increment", "get"]
caller_instance = "scripting~evening"
```

Cedar (*compiled* from the plugin's requested ∩ granted list, plus a *user rule* for the narrowing):

```cedar
@id("grant.inst-5f2a.consumes_services.0")
permit (principal in OxidHome::Plugin::"com.example.scripting", action == OxidHome::Action::"service.call", resource)
when {
  resource.plugin == "com.example.counter" && resource.instance == "counter" &&
  resource.local_id == "counter" &&
  context has command && ["increment", "get"].contains(context.command.verb)
};

@id("user.only-evening-script-calls-counter")
forbid (principal in OxidHome::Plugin::"com.example.scripting", action == OxidHome::Action::"service.call", resource)
when { resource.plugin == "com.example.counter" }
unless { principal == OxidHome::Instance::"scripting~evening" };
```

`scripting~evening` → `increment`: allowed. `scripting~other` → `increment`: denied. `scripting~evening` → `reset`:
denied (not in the grant). Children are `Instance` entities whose parents are the plugin and the parent instance, so
plugin-level grants and forbids reach them without copying.

### 10. Delegated hops: token → plugin → another plugin

A token `tok-btn` may command one device: a virtual "goodnight" button the scripting plugin owns (today's 14.4
allowlist, or in Cedar `permit (principal == OxidHome::Token::"tok-btn", action ==
OxidHome::Action::"device.command", resource == OxidHome::Device::"dev-scriptbtn");`). Pressing it runs
`scripting~doors`, which calls a notification service (`notify.send`, not sensitive) and then the Z-Wave plugin's
`door` service command `unlock` (operator category `lock`, so sensitive). The script's installation holds
`consumes_services` grants for both and the `lock` sensitive grant.

Today: the press passes `devices:command` and the allowlist; both hops pass the script's H10 grants; the door
unlocks. The audit rows name `tok-btn` as root, after the fact.

With the recommended rule (root permit, executing-plugin permit, no forbid on the chain), in either option:

| Hop | Root `tok-btn` | Executing `scripting~doors` | Result |
|-----|----------------|-----------------------------|--------|
| `notify.send` | no permit | allowed (compiled grant) | **denied**, unless the token gets a delegation grant for `notify` |
| `door.unlock` | forbidden (`builtin.sensitive-service`, no `lock`) | allowed (grant + `lock`) | **denied** |

A `resident` token pressing the same button: `notify.send` allowed (the preset includes non-sensitive
`service.call`), `door.unlock` denied (no `lock`). An owner token: both allowed, the unlock audited at `warn`. An
assistant token holding `lock` by mistake: denied by `preset.assistant.never-locks`, which covers `service.call`.
Refused hops are `deny` audit rows with the root's call id and the deciding policy id.

With the looser variant (open question 5), `tok-btn`'s `notify.send` hop would be allowed and only the unlock denied.

Each cell above is a separate per-principal decision run through the Cedar authorizer in the scratch harness; the
combination across the chain is host code in `authorize()` and was worked out by hand.

## Appendix B: Cedar schema sketch

The schema the scenarios were validated against. It is a sketch for the decision, not the final schema: the real
one adds events, dashboards and config as entity types, and the actions for them.

```cedar
namespace OxidHome {
  // Principals. A token's roles are its parents; sensitive_grants is set only by an explicit grant.
  entity Role;
  entity Token in [Role] { label: String, sensitive_grants: Set<String> };
  entity Plugin;
  // A plugin instance; a sandbox child `p~s` has its parent instance as a parent too.
  entity Instance in [Plugin, Instance] {
    plugin: String,
    installation: String,
    instance: String,
    sensitive_grants: Set<String>,
  };

  // Resources. Every attribute is host-owned; see "Resource model".
  entity Area in [Area];
  entity Device in [Area] {
    plugin: String,
    installation: String,
    instance: String,
    capabilities: Set<String>,
    category: String,
    sensitive: Bool,
    tags: Set<String>,
  };
  entity Service {
    plugin: String,
    instance: String,
    local_id: String,
    category: String,
    sensitive: Bool,
  };
  entity Blob { instance: String, class: String };
  entity Host;

  type Command = { capability: String, verb: String };
  type Ctx = {
    transport: String,   // rest | connect | mcp-http | mcp-stdio | host
    hops: Long,          // length of the delegation chain
    confirmed: Bool,     // a fresh confirmation came with the request
    daylight: Bool,      // host "home" variables, computed from operator-chosen sources
    occupied: Bool,
    command?: Command,   // device.command and service.call only
  };

  // Action groups used by presets.
  action read;
  action control;
  action manage;
  action sensitive_admin;

  action "device.list", "device.read" in [read]
    appliesTo { principal: [Token, Instance], resource: [Device], context: Ctx };
  action "event.read", "event.subscribe" in [read]
    appliesTo { principal: [Token, Instance], resource: [Device, Host], context: Ctx };
  action "state.read" in [read]
    appliesTo { principal: [Instance], resource: [Device], context: Ctx };
  action "plugin.read", "instance.read", "host.status", "dashboard.read" in [read]
    appliesTo { principal: [Token], resource: [Host, Plugin, Instance], context: Ctx };
  action "blob.read"
    appliesTo { principal: [Token, Instance], resource: [Blob, Device], context: Ctx };
  action "device.command" in [control]
    appliesTo { principal: [Token, Instance], resource: [Device], context: Ctx };
  action "service.call" in [control]
    appliesTo { principal: [Token, Instance], resource: [Service], context: Ctx };
  action "instance.start", "instance.stop", "plugin.ui", "dashboard.write", "host.logs" in [manage]
    appliesTo { principal: [Token], resource: [Host, Plugin, Instance], context: Ctx };
  action "plugin.install", "plugin.uninstall", "token.manage", "policy.manage", "host.audit" in [sensitive_admin]
    appliesTo { principal: [Token], resource: [Host, Plugin], context: Ctx };
}
```

The `@audit` and `@rate` annotations used in scenario 6 are host conventions: Cedar ignores annotations during
evaluation, and `authorize()` reads them from the determining policies to build the decision's obligations.
