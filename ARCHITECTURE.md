# OxidHome Architecture

> **Status:** Initial architectural design document — captures the design decisions that shape the codebase. The implementation is in active development; sections explicitly settled, re-scoped, or superseded as the code progresses are flagged inline.

## Mission

OxidHome is an open home-automation platform that combines a Rust core with WebAssembly plugins. The goal is a hub that is:

- **Safe to expose** to a home network (memory-safe core, sandboxed plugins, capability-scoped permissions)
- **Fast enough** to react in real time on modest hardware
- **Flexible enough** to support the long tail of devices, protocols, and integrations
- **Honest about its limits** — when WASM isn't the right answer, the architecture provides a well-marked escape hatch rather than pretending

The design is informed by what works (and doesn't) in Home Assistant, Scrypted, Frigate, Matter, and similar systems.

## Core technical choices

### Rust for the core

The hub sits in a privileged spot on the network. Memory safety without a GC, predictable performance, and a runtime small enough to live alongside devices on the same hardware are non-negotiable. Rust delivers all three.

### WebAssembly (Component Model) for plugins

Plugins are `.wasm` components — not raw `.wasm` modules. The Component Model is the foundation, not an optimization:

- Rich types across the host/plugin boundary (no manual serialization boilerplate)
- Language-agnostic plugin authoring (Rust first, but Go, JS, Python, C# all viable)
- Capability-based imports — plugins can only do what the host imports give them
- Standard interfaces (WASI 0.2) for HTTP, sockets, clocks, etc.

### Wasmtime as the runtime

Best Component Model support, async host functions, mature embedding API, well-maintained by the same group that chairs the WASM spec work.

### WIT as the API contract

The `oxidhome.wit` file is the *real product* in a sense. Once plugins exist in the wild against version 0.1 of the WIT, breaking changes get expensive. The WIT deserves real care on the first cut.

## The plugin model

### Plugin vs. plugin instance

- A **plugin** is a `.wasm` component package — the code (e.g. "onvif-camera", "zigbee2mqtt-bridge")
- A **plugin instadsance** is a configured, running copy of that plugin (one per camera, one per Zigbee bridge, etc.)

A user installs the "ONVIF camera" plugin once. They configure three cameras through the UI. The host spins up three component instances of that plugin, each with its own config, capabilities, and lifecycle. Crash isolation, per-instance supervision, and independent updates fall out naturally.

Plugin manifests declare whether the plugin is **singleton** (Zigbee coordinator owns the radio — only one instance makes sense) or **multi-instance** (cameras, MQTT brokers).

### The three plugin worlds

The WIT defines multiple worlds, each adding capabilities on top of the previous:

| World                               | Purpose                                                       | Examples                                                             |
|-------------------------------------|---------------------------------------------------------------|----------------------------------------------------------------------|
| `plugin`                            | Standard device integrations, automations, logic. No raw I/O. | Switch drivers, sensor adapters, scene controllers, automation rules |
| `streaming-plugin`                  | Adds WASI sockets and HTTP for long-lived I/O.                | Cameras, MQTT bridges, voice assistants, network discovery           |
| `ai-plugin` / `streaming-ai-plugin` | Adds the `inference` import for using host-managed ML models. | Person detection, audio classification, anomaly detection            |

Importing a WASI interface does **not** grant access to it. Capabilities are gated by the plugin manifest the user approves at install time. The host enforces network allowlists, filesystem scopes, model access, etc. per instance.

## The device model

### Capabilities, not device types

Device archetypes are not enumerated as types. Instead, devices declare a list of **capabilities** — small, reusable units of functionality:

- A bulb = `[switch, dimmer, color-light]`
- A doorbell = `[button, video-stream, audio-stream, motion-detector]`
- A thermostat = `[temperature-sensor, target-temperature, mode-selector]`
- A robot vacuum = `[command, battery-sensor, status-reporter]`

This matches what Home Assistant, Matter, HomeKit, and SmartThings all converged on. Consumers (UIs, automations, voice integrations) ask "does this device support brightness?" not "is this device a SmartBulb_v3?"

The capability variant includes an `extension(string)` arm so plugin authors can add new capability types without waiting for the core spec to catch up. Consumers that don't recognize an extension capability simply ignore it (forward compatibility).

### Standard capabilities

The 0.1 WIT defines:

- `switchable` — discrete on/off
- `dimmable` — continuous 0.0–1.0 level (brightness, fan speed, blind position)
- `color` — HSV + optional color temperature
- `measurement` — numeric reading with a unit string
- `button-event` — stateless press/release/rotation events
- `video-stream` / `audio-stream` — references to media streams
- `extension(string)` — open-ended for plugin-defined capabilities

This is intentionally a small starting set. Expect it to grow as real devices are integrated.

## The host responsibilities

The host (Rust core) owns:

1. **Plugin lifecycle** — loading components, spawning instances, enforcing capabilities, restarting on crash. Each install of a plugin is stamped with a per-install `installation_uuid` persisted in the `plugin_installation` SQL table; the UUID feeds device-id derivation so that uninstalling and reinstalling the same plugin id produces distinct device ids. Uninstalled rows are tombstoned rather than deleted so operators can audit when identity rotated for a given `plugin_id`; **the tombstone table does not carry a device-id back-reference** — audit rows written against a retired install's device ids cannot be resolved back through this table (adding a `plugin_device` mapping is a C1c follow-up if that lookup becomes load-bearing). The manifest's `[capabilities]` block is the plugin's **request**; the host stores an independent **granted** copy in `plugin_installation.granted_capabilities_json` and every runtime gate (device-capability check, `subscribes-events`, storage/blob quotas) consults the grant rather than the manifest, so a future operator API can narrow the grant without editing the plugin's manifest (v1 defaults grant = request at install time)
2. **Device registry** — canonical list of devices, IDs, names, current state. Host-minted device ids are deterministic: `dev-<hex(SHA-256(installation_uuid, instance_id, local_id))>`. A plugin's re-registration on restart resurrects the same id; a reinstall (fresh `installation_uuid`) mints a new one
3. **Event bus** — pub/sub for state changes, button events, plugin-defined custom events. Delivery is per-subscriber (private `mpsc` queue per `subscribe*` call, filter applied before enqueue): a slow subscriber whose queue fills drops events for itself only, with a `tracing::warn` and per-subscriber drop counter — the pre-C2e shared broadcast ring would have evicted events for every subscriber on overflow. Publish is per-instance rate-limited (C2d) so a rogue plugin can't spend the delivery loop's per-second budget monopolistically
4. **Storage** — small KV per plugin instance (with quotas), plus a separate blob-store interface for larger data (out of 0.1 scope)
5. **Configuration** — plugin instance configs, user preferences
6. **Media pipelines** — when streaming plugins describe pipelines, the host runs them natively
7. **Model registry** (0.x+) — when AI plugins request inference, the host loads/runs models natively
8. **UI / API surface** — HTTP endpoints for clients to consume, currently split across a JSON/REST + WebSocket surface and a Connect RPC surface (which speaks Connect, gRPC, and gRPC-Web off the same handlers) on one shared listener

## Streaming and media (the camera problem)

### The principle: control in WASM, data in native code

WASM is excellent for parsing, state machines, crypto, and small per-packet work. WASM is **bad** for video codec work — it can't see the GPU, software-decoding 4K H.265 in WASM will drop frames on commodity hardware.

Therefore: **WASM plugins describe media pipelines; the host runs them natively** (using GStreamer, FFmpeg-as-a-library, or a Rust media stack).

### The pipeline model

A streaming plugin's `setup-pipeline` returns a `media-pipeline` describing:

- A **source** — either a URL the host opens directly (RTSP/HTTP), or a `plugin-pipe` where the plugin produces re-framed bytes
- A list of **steps** — demux, decode, re-encode, transcode, filter, inference-tap
- A list of **sinks** — RTSP path, WebRTC track, HLS path, recording profile
- An **activation policy** — on-demand, always-on, motion-triggered

### How it handles real-world cameras

| Camera type                                                | What the plugin does                                                                     | Where bytes go                                                                          |
|------------------------------------------------------------|------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------|
| Standard ONVIF                                             | Discovers RTSP URL via WS-Discovery                                                      | Host opens URL directly; bytes never enter WASM                                         |
| Tapo / Reolink / proprietary auth + standard codec         | Runs vendor handshake, strips proprietary framing, re-frames as RTP, writes to host pipe | Bytes pass through WASM as RTP packets (cheap), host pipeline takes over                |
| Cloud-only camera                                          | Authenticates against vendor cloud, requests stream URL                                  | If standard URL: easy case. If requires vendor SDK: error, user needs the native bridge |
| Encrypted vendor stream                                    | Runs key derivation; either decrypts in WASM or hands key to host                        | Per-frame work native if decryption is heavy                                            |
| Codec mismatch (H.265 from camera, H.264 needed by WebRTC) | Pipeline includes `decode-video` + `encode-video` steps                                  | Host does both natively, with hardware acceleration                                     |
| MJPEG-only ancient camera                                  | Pulls JPEGs over HTTP, writes to host pipe with format hint                              | Host decodes/re-encodes natively                                                        |

### The native bridge escape hatch

Some cameras genuinely cannot be supported from WASM:

- Vendor SDK shipped only as closed-source `.so` / `.dll`
- Hardware decoder access requiring direct V4L2 / VAAPI / NVENC ioctls
- Protocols using kernel features WASI doesn't expose (raw sockets, multicast on specific interfaces)

For these, OxidHome supports a **native bridge plugin** type — a separate subprocess running under OS-level sandboxing (separate user, seccomp profile, network namespace), talking to the core over a defined IPC protocol (gRPC or Cap'n Proto over Unix socket).

This is **explicitly marked in the UI** as native code requiring user trust. WASM is the default and covers >90% of integrations; native is for the irreducible exceptions.

## AI / ML plugins

### The same pattern as cameras: control in WASM, computation in native

WASM cannot effectively run real-time ML inference on video. wasi-nn lets WASM plugins request inference from a host-managed runtime, which is the right model.

### The three AI patterns OxidHome supports

| Pattern                                 | Where it runs                                                                                                    | When to use                                     |
|-----------------------------------------|------------------------------------------------------------------------------------------------------------------|-------------------------------------------------|
| External AI service                     | Plugin is a thin HTTP client to Frigate/Ollama/CodeProject.AI/cloud APIs                                         | Day one. User runs the AI service themselves.   |
| Host-managed model + WASM orchestration | Plugin requests model, host runs it natively (ONNX Runtime / TensorRT / Core ML / OpenVINO), plugin gets results | Polished real-time inference. Some 0.x version. |
| Native AI bridge                        | Closed vendor SDKs, exotic accelerators                                                                          | Last resort, same shape as native camera bridge |

### The `inference-tap` pipeline step

For real-time video AI, plugins don't pull frames into WASM. Instead, the pipeline includes an `inference-tap` step:

```
Camera → Decode (native) → Inference Tap (native, GPU) → ...
                                ↓
                          Plugin gets results
                          as events (small payload)
```

The plugin sees only structured inference results (bounding boxes, labels, confidences) — a few hundred bytes per frame, not a megabyte of RGB. The plugin's job is the *interesting* part: filtering, debouncing, deciding what counts as an "event," ignoring zones, weighting by motion.

### Models as platform resources

Models are **first-class platform resources**, not application code shipped inside plugins:

- Host has a **model registry** with versioned, signed model files
- Plugins declare model dependencies in their manifest
- Multiple plugins can share a model (one copy in GPU memory)
- The host abstracts hardware backends (CUDA, ROCm, Metal, OpenVINO, CPU)
- Plugins are not coupled to specific accelerator SDKs

This avoids both the "every plugin ships its own copy of YOLO" problem and the "plugins are a side-channel for arbitrary GPU code" problem.

### Trust and safety for models

Loading a model is asking the host to execute computation on the GPU using arbitrary weights. Defenses:

- Models in the official registry are signed and reviewed
- Plugin manifests declare which models they need; user approves at install
- ONNX-only as the model format (well-defined operator set; no arbitrary code paths)
- Resource limits on inference (max memory per model, max time per call)
- User-provided models always supported as an escape hatch (drop ONNX in `/var/lib/oxidhome/models/`)

### Hardware backend strategy

- **Day one**: ONNX Runtime with CPU execution provider, plus optional CUDA and Core ML where toolchain permits
- **Later**: pluggable execution backends (TensorRT, OpenVINO, Hailo, Coral) that users opt into
- **Never**: silent fallback. If a model can't run on the user's hardware, fail clearly. Don't have someone's NVR cooking on CPU because their CUDA install was broken and we didn't tell them.

## Communication patterns

### Host → Plugin

- **Lifecycle** — `init()`, `shutdown()`
- **Event delivery** — the host buffers matching events on the subscriber's per-instance queue. A host-side helper (`PluginInstance::drain_events()`) walks that queue and invokes the plugin's `on-event` export once per buffered event. There is no separate `drain-events` export on the plugin world. Phase 3 ships the helper; *when* to call it is the caller's choice today — integration tests invoke it explicitly after each host-driven step. The intended future driver is a per-instance tokio task that owns the `Store` and `select!`s between control commands and bus events, draining automatically after each entry point (`init`, `execute-command`, `tick`); that scheduler lands with Phase 6's per-instance lifecycle. The polling-drain shape preserves the single-threaded per-`Store` WASM contract — no host call ever re-enters the plugin from a separate task — and avoids needing a streaming export on the plugin world.
- **Commands** — `execute-command(device, cmd)` for actions targeting plugin's devices; `execute-service-command(service, command, args)` for actions targeting the plugin's services (Phase 7), routed from the host dispatcher
- **Periodic** — `tick()` for plugins that genuinely need a heartbeat (most should be event-driven)

### Plugin → Host (imports)

- **Device lifecycle** — `register-device`, `update-device`, `remove-device`, `get-device`
- **Service lifecycle** (Phase 7) — `register-service`, `update-service`, `remove-service`, `get-service`; gated by `[capabilities] declares_services`
- **Event bus** — `publish-event`, `subscribe`, `unsubscribe`
- **Storage** — `get`, `set`, `delete`, `list-keys` (small KV, per instance); blob bytes via the `blob-store` interface
- **Configuration** — `get-config`, `list-config`
- **Inference** (AI plugins only) — `load-model`, model handles with `infer()`
- **Logging** — at standard levels

### Plugin → Plugin (Phase 7)

- **Service dispatch** — `host-services::call-service(target, command, args)` is a synchronous host-mediated call. The host resolves `target` (a `service-id` minted by `register-service`) to its owning instance, looks the instance up in the engine's registry, and hops to that instance's Phase-6 supervisor task to invoke its `execute-service-command` export. The single-`Store` contract holds: a callee's wasm only ever runs on its own supervisor task.
- **Recursion / cycles** — the dispatcher carries the in-flight call chain across the task hop (in `ControlCommand::ExecuteService`); the callee's supervisor re-scopes a `tokio::task_local` on its task before driving the wasm so any nested `call-service` sees the full chain. Cycle detection is at instance granularity — a same-instance peer service must use the plugin's internal dispatch — and rejects with `Error::InvalidArgument` rather than deadlocking.
- **Back-pressure** — a registry refcount makes `remove-service` refuse with `Error::Unavailable` while a call is in flight; the refcount travels with the work (in the control-channel message), not with the caller's wait future, so a dispatch-side timeout can't release it mid-handler.

### Long-running work

- Most plugins are event-driven (subscribe + react)
- Streaming plugins use Wasmtime's async host function support — calls suspend without burning CPU
- Plugins that genuinely need polling implement `tick()`; the host calls it on a schedule from the manifest

## What's deliberately not in 0.1

> **Re-scoped since the initial draft.** The items below have moved
> out of the deferred list — either pulled into 0.1 scope or
> settled with a concrete plan as the design firmed up:
>
> - **Host-side blob storage** — *now in scope*, planned for Phase 5b (filesystem bytes + SQLite index).
> - **Authentication / actor identity in commands** — *pulled forward*; an actor model lands by Phase 4 and is required before Phase 12's external API.
> - **Storage backend** — *settled* (SQLite via `rusqlite` + `bundled`, WAL mode).
> - **Inter-plugin communication beyond the event bus** — *shipped in Phase 7*. A plugin instance can register **services** (non-device peers — automation scripts, virtual integrations) gated by `[capabilities] declares_services`; another plugin (or the same plugin) can drive them through `host-services::call-service`, a synchronous host import. The host's dispatcher routes the call to the owner instance's supervisor task (preserving the single-`Store` contract), rejects A→…→A cycles at instance granularity, and bounds the round-trip with a dispatch timeout *and* the per-call liveness watchdog.
> - **Plugin resource usage** — *not limited by design*. OxidHome does not cap a plugin's CPU/memory; on an admin-curated home hub, catching a greedy or buggy plugin is the operator's job, and the host's role is to surface metrics rather than enforce compute quotas. The host keeps exactly one guarantee — a per-call **liveness watchdog** (Wasmtime epoch interruption) so the supervisor can always reclaim a wedged/infinite-loop instance. (Storage and blob *byte* quotas remain — they guard finite disk, not compute.)

The remaining items below are still deferred:

- **Resource handles for devices** (Component Model supports them; useful for capability-scoped device access)
- **Versioned migration policy** for SDK evolution
- **Model registry implementation** (start with external AI services + user-provided ONNX)
- **Native bridge plugin protocol** (defer until first real need)

## Open questions

> **Resolved since the initial draft.** Items below are no longer
> open — capturing the decisions inline so this section stays useful
> as a delta against the original questions:
>
> - **Plugin manifest schema** — *settled* TOML.
> - **WIT versioning policy** — *settled* semver, not enforced until first external SDK release.
> - **Storage backend** — *settled* SQLite.
> - **UI / API surface** — the daemon serves two RPC surfaces off the same axum listener: the JSON/REST + WebSocket surface (Phase 12) and a Connect RPC surface (Phase 15) whose `connectrpc` router speaks Connect JSON, gRPC, and gRPC-Web off the same handler set. Every 0.1 cluster (`health`, `instances`, `devices`, `plugins`, `logs`, `events` — including `events.tail` as server-streaming) exists on both surfaces; the JSON side stays for browser/curl debuggability and the Connect side is the SDK-facing contract. Auth, scope, and audit are enforced by shared code paths — both surfaces route into a dedicated **audit ledger** (`AuditLog`, backed by its own `audit_event` SQLite table separate from the drop-tolerant `LogStore`) with a synchronous two-phase intent/finalize write contract for cancellation-safe forensic guarantees. External query surface: `GET /api/v1/audit` (scoped on `audit:read`, cursor-paginated via `next_cursor`). Web UI as the primary consumer surface (Phase 13; the SvelteKit shell lives in the separate `oxidhome/ui` repo and the JS plugin-author package in `oxidhome/ui-sdk`), MCP server first-class (Phase 14). GraphQL remains out of scope.

Still open:

- **Model registry hosting** — official curated registry vs. HuggingFace pull-through vs. self-host only
- **Discovery / mDNS** — should the core handle this, or each protocol plugin?
- **Trust model for plugins themselves** — signing? official registry? ad-hoc install with warnings?

## Implementation decisions

Settled engineering choices that shape the codebase, captured here so they survive when transient planning docs do not.

### Bindgen and publication

- **`oxidhome-wit`** — the single bindgen crate, with **per-world Cargo features**: `plugin`, `streaming-plugin`, `ai-plugin`, `streaming-ai-plugin`. Each world's module tree is `#[cfg(feature = "...")]`-gated so a plugin that only uses one world doesn't trip `wasm-component-ld`'s "multiple component-type metadata sections" linker error. Host and SDK both depend on it.
- **Publication policy.** All three crates (`oxidhome-wit`, `oxidhome-sdk`, `oxidhome-core`) carry `publish = false` through 0.x. Path dependencies and a workspace-root `wit/` directory make publishing impossible without packaging changes anyway, and pre-1.0 we want zero friction iterating on the WIT. The three flip publishable together at the first SDK release intended for external plugin authors. Re-evaluate sooner only if a second-language SDK (Go, JS) needs a versioned `oxidhome-wit` artifact to bindgen against.
- **Exact-pinning policy.** `wit-bindgen` (in `oxidhome-wit`) and `wasmtime` (in `oxidhome-core`) are pinned because silent minor bumps can change generated bindings or runtime embedding behavior.

### Observability

- **`tracing` for logging — never `log`.** Spans cross every host-call boundary from Phase 2 onward; retrofitting is painful. From Phase 5c, a SQLite-backed `tracing::Subscriber` layer also persists structured events so they're queryable through the CLI/API.

### Async + Wasmtime embedding

- **Wasmtime async + tokio.** Single tokio multi-thread runtime in `oxidhome-core`, entered via `#[tokio::main]` in the host binary; host imports rely on the ambient runtime that installs. Plumbing a `tokio::runtime::Handle` through the Wasmtime store data so host imports can cleanly spawn background work without leaning on the ambient runtime is an open Phase-2 follow-up (see the open question in the `oxidhome-core` per-crate plan).
- **Single-threaded contract per `Store`.** One `wasmtime::Store` per `PluginInstance`. Concurrent invocations of the same instance are serialized; cross-instance work runs in parallel.
- **`bindgen!` async syntax** is `imports: { default: async }` (modern wasmtime), not the deprecated `async: true`.
- **Resource-path syntax** in `with:` mappings uses `interface.type` (dot), not `interface/type` (slash): e.g. `oxidhome:plugin/media.pipeline-handle`.

## Current safety invariants

Load-bearing invariants the codebase depends on today. Each corresponds to a shipped review fix or Phase decision — they are what the runtime, API, and storage layers assume when routing untrusted plugin work.

### Identity and grants

- **`installation_uuid` is the source of identity.** Every `install` mints an opaque `inst-<32 hex>` UUID and persists it on the `plugin_installation` SQL row. Uninstall tombstones the row; a subsequent reinstall mints a fresh UUID. Device IDs derive from the UUID (not from `plugin_id`), so an uninstall + reinstall cannot inherit device identity or audit lineage from the previous installation. **C1 / C1b.**
- **Granted capabilities are authoritative; requested capabilities are not.** `plugin_installation.granted_capabilities_json` is what the runtime consults at every capability gate. The manifest's `[capabilities]` block is a *request* — the loader computes `effective = requested ∩ granted` so a stale grant that is broader than the current manifest cannot authorize newly-requested permissions. **C5.**
- **Grants are content-bound.** `plugin_installation.content_digest` is a domain-tagged SHA-256 over `(manifest bytes, wasm bytes)`. The loader recomputes; on any mismatch it **rejects the load** with a "content digest mismatch — reinstall to re-issue the grant" error rather than degrading to a synthetic identity. **C5 review F3.**
- **Quarantine is fail-closed.** A live `plugin_installation` row with a NULL / malformed `granted_capabilities_json` or NULL `content_digest` is quarantined at scan: absent from `entries` so `start_instance` cannot launch it, but still `is_quarantined()` so raw-path CLI loads whose manifest declares the same `plugin_id` refuse rather than shadow the persisted grant. An operator's `uninstall` + `install` cycle re-issues both fields together. **C5 review F1.**

### Lifecycle serialization

- **`plugin_id` load provenance is explicit.** `Engine::start_installed_instance` (API path) carries the observed `installation_uuid` into the loader as `LoadMode::Installed`; `Engine::start_instance` (dev / argv) uses `LoadMode::Dev`. The loader fails closed under `Installed` if the registry row named by the expected UUID is missing, its path changed, or the UUID rotated — no silent fallback to a synthetic identity. **H11 review F1.**
- **Start and uninstall of the same `plugin_id` serialize.** `Engine::plugin_lifecycle_lock(plugin_id)` returns an `Arc<tokio::sync::Mutex<()>>`; both JSON and Connect handlers hold it across the running-instances check + the compose work. `uninstall` moves an owned guard into its `spawn_blocking` closure so a cancelled handler cannot release the reservation while the detached FS + SQL work is still running. Map entries are `Weak` so nonexistent-id requests don't grow the map without bound. **H3 + H3 review F1/F2.**
- **Uninstall is retryable and cannot orphan state.** `Engine::uninstall_plugin` resolves the `installation_uuid` from either the live-entries map OR the quarantined map (`installed_plugins.installation_uuid_for(plugin_id)`), then purges per-install KV rows + blob dirs *before* tombstoning the registry row. Quarantined installs get the same purge path as live installs. On any purge error the row stays live and the API returns the error, so the operator can retry — no silent stranding of blob bytes. **H2 review F2 + H12 review F1.**

### Per-instance state

- **KV, blob-index, and blob directories key on `(installation_uuid, instance_id)`.** Migration 14 rekeyed the four state tables (`kv`, `kv_usage`, `blob`, `blob_usage`) with a composite PK; the FS layout is `<state_dir>/blobs/<installation_uuid>/<instance_id>/`. An uninstall + reinstall of the same `plugin_id` mints a fresh UUID and therefore an empty per-instance keyspace. `purge_installation` on both stores handles the wipe. **H2.**
- **Instance IDs are FS-segment safe.** `is_safe_instance_id` — 1..=128 bytes, no `/`, `\`, `..`, leading `.`, or `\0` — is enforced at the API edge (`start_plugin_instance` returns 400) and again in the blob store as belt-and-suspenders. Every `BlobStore` entry point refuses an unsafe id before any path construction. The KV store trusts the id (it never touches the filesystem), so its check lives at the API edge only. **H1 + H1 review F1.**
- **Duplicate manifest IDs quarantine every path.** A scan that sees two directories declaring the same `plugin_id` stores ALL paths on the `QuarantineEntry`; a single `uninstall` removes every path in one call so no leftover directory survives to be backfilled on the next scan. **H8 + H8 review F1.**
- **Legacy blob directories are reclaimed once.** `Engine::with_state_dir` runs a one-shot sweep of `<state_dir>/blobs/` when `Db::pre_open_user_version() < 14`, so the pre-migration-14 flat layout doesn't leak bytes forever. Post-14 boots skip the sweep so dev-load blob dirs survive. **H2 review F3.**

### Event delivery

- **Per-subscriber `mpsc` queues.** Each subscriber owns a 256-slot `tokio::sync::mpsc` channel; back-pressure on one subscriber drops events **for itself only** (per-subscriber `dropped` counter + rate-limited warn). No shared broadcast ring where a slow tail client can evict events from the plugin supervisor. **C2e.**
- **Wake registration is filter-scoped.** `EventBus::subscribe_with_wake` pairs a `Notify` with the subscription filter; publishes signal only wakes whose filter matches, so a supervisor whose plugin has no subscriptions is quiet under any flood. **C2d.**
- **Per-instance publish rate limit.** `admit_publish(instance_id)` throttles at a bounded arrival rate (`DEFAULT_PUBLISH_RATE_PER_SEC` / `DEFAULT_PUBLISH_BURST`) *before* the durable log write, so a flooder can't spend disk + threads freely. **C2d.**
- **Lag is folded into the event slot.** `SubscriberMessage::Event { event, skipped_before }` — one slot per publish. A freed slot always delivers a real event; a separate `Lagged` marker slot could steal that free slot and starve fresh events indefinitely under a chronic tight-capacity workload. Wire receivers translate `skipped_before > 0` into the Connect `Lagged` body / JSON `{"lagged": N}` frame ahead of the event. **H4 + H4 review F1.**
- **`pending_lag` accounting is race-free vs the next successful delivery.** Each `Subscriber` holds a `send_gate: std::sync::Mutex<()>` that serializes the `claim (swap 0) + try_send + reinject` triple in `EventBus::publish_with_id`. Concurrent publishers can't interleave — either A completes first (its event carries the accumulated N) or B completes first (fresh event, `skipped_before = 0`) — so the "next successful send surfaces the complete gap" invariant holds. The critical section is O(1): one atomic swap + one non-blocking `try_send` + at most one `fetch_add` on the error path. The pre-fix load-then-`fetch_sub` shape let two publishers each load the same count and each subtract it, wrapping the counter near `u64::MAX`; the atomic swap closed that, and the gate closes the interleave that let a stale `pending_lag` batch surface *after* a fresh event. **H4 + H4 review F1 + H12 review P2.**

### Audit and access

- **API requests hit a dedicated audit ledger.** `audit_event` is separate from the diagnostic `log_event` stream so a burst of debug logs can't evict audit rows. Writes are two-phase: `record_intent` before the handler runs, `finalize` after — a client disconnect mid-handler leaves the pending row behind as evidence of the attempted action. **C3.**
- **Authorization outcome and execution outcome are separate audit fields.** `decision` carries the auth outcome (`allow` / `deny` / `error` / `pending`), `status` carries the wire HTTP status, `execution_outcome` + `domain_error` carry the plugin's `CommandResult::Err` kind. A plugin returning an error on an authorized request no longer shows up in `WHERE decision = 'deny'` searches. **C3 review F4.**
- **Tokens are hashed at rest.** 256-bit CSPRNG bearer tokens, SHA-256 at rest — plain SHA is correct for a uniformly-random 256-bit secret; a slow KDF only pays off against low-entropy passwords. `revoked_ms` is a tombstone; rows aren't deleted so audit lineage stays intact. **12-API tokens.**

### Path safety

- **Uninstall works on the recorded path, not a recomputed one.** `install` validates `plugin_id` shape before it enters the registry; `uninstall` deletes only the path the registry observed, with a `starts_with(plugins_root)` containment re-check before any `remove_dir_all`. A registry-corruption divergence refuses rather than escapes the plugins root.
- **Blob paths never escape `blobs_root`.** `check_instance_id` + `check_installation_uuid` refuse unsafe segments; `ensure_contained` re-verifies the resolved path lives under the root. Both checks fire at every blob-store entry point. **H1.**
- **Installed reads apply `O_NOFOLLOW` on the final component + hash the same buffers the loader compiles.** `read_installed_bytes` opens the target file with `O_NOFOLLOW` so a symlink swap of the leaf is refused, and the C5 digest verification hashes the same in-memory buffers the loader will compile from, closing the TOCTOU window a file-path re-read would reopen. **The stronger claim — full fd-relative traversal with beneath-resolution on every intermediate path component — is NOT yet in force**: intermediate directory components go through ordinary path resolution, and the runtime loader (`PluginInstance::load_with_overrides`) uses `tokio::fs::read` directly. Closing that gap on Linux via `openat2(RESOLVE_BENEATH)` is tracked as a follow-up (H12 review P1 F2). **C5 review round-4 (leaf O_NOFOLLOW) + open work.**

Design notes that don't yet correspond to a shipped invariant (Phase 6+ items in flight: `Engine::start_installed_instance` grant-scope refresh on manifest edit, `Engine::start_dev_instance` audit-log attribution, service dispatcher call-stack chain guarantees) live in the per-phase task-list rather than here — they promote up as they ship.

## North-star principles

These are the architectural tiebreakers:

1. **Security over convenience.** A capability-gated, sandboxed plugin model is the whole point. Don't add escape hatches that defeat the model. When you need an escape hatch (native bridges), make it explicit and visible.

2. **Honest about WASM's limits.** WASM is great for control-plane work and bad for codec-rate data. Design with that grain, not against it.

3. **Capabilities, not types.** Don't enumerate device archetypes. Compose capabilities. Make extension a first-class concept.

4. **The WIT is the product.** Other things change; the WIT is the contract plugin authors depend on. Iterate hard before 1.0; iterate carefully after.

5. **Fail clearly, not silently.** A misconfigured AI model running on CPU when the user expected GPU is a worse outcome than an upfront error. Visibility beats false positives.

6. **Native code is the exception.** The default story is "install a `.wasm` component and trust the sandbox." When that's not enough (vendor SDKs, hardware acceleration), it's a marked exception, not a parallel architecture.
