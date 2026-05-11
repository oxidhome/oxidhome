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
- A **plugin instance** is a configured, running copy of that plugin (one per camera, one per Zigbee bridge, etc.)

A user installs the "ONVIF camera" plugin once. They configure three cameras through the UI. The host spins up three component instances of that plugin, each with its own config, capabilities, and lifecycle. Crash isolation, per-instance resource limits, and independent updates fall out naturally.

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

1. **Plugin lifecycle** — loading components, spawning instances, enforcing capabilities, restarting on crash
2. **Device registry** — canonical list of devices, IDs, names, current state
3. **Event bus** — pub/sub for state changes, button events, plugin-defined custom events
4. **Storage** — small KV per plugin instance (with quotas), plus a separate blob-store interface for larger data (out of 0.1 scope)
5. **Configuration** — plugin instance configs, user preferences
6. **Media pipelines** — when streaming plugins describe pipelines, the host runs them natively
7. **Model registry** (0.x+) — when AI plugins request inference, the host loads/runs models natively
8. **UI / API surface** — REST/WebSocket/whatever for clients to consume

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
- **Event delivery** — `on-event(event)` for subscribed events
- **Commands** — `execute-command(device, cmd)` for actions targeting plugin's devices
- **Periodic** — `tick()` for plugins that genuinely need a heartbeat (most should be event-driven)

### Plugin → Host (imports)

- **Device lifecycle** — `register-device`, `update-device`, `remove-device`
- **Event bus** — `publish-event`, `subscribe`, `unsubscribe`
- **Storage** — `get`, `set`, `delete`, `list-keys` (small KV, per instance)
- **Configuration** — `get-config`, `list-config`
- **Inference** (AI plugins only) — `load-model`, model handles with `infer()`
- **Logging** — at standard levels

### Long-running work

- Most plugins are event-driven (subscribe + react)
- Streaming plugins use Wasmtime's async host function support — calls suspend without burning CPU
- Plugins that genuinely need polling implement `tick()`; the host calls it on a schedule from the manifest

## What's deliberately not in 0.1

> **Re-scoped since the initial draft.** The items below changed
> status from "deferred" as the design firmed up:
>
> - **Host-side blob storage** — *now in scope*, planned for Phase 5b (filesystem bytes + SQLite index).
> - **Authentication / actor identity in commands** — *pulled forward*; an actor model lands by Phase 4 and is required before Phase 12's external API.
> - **Storage backend** — *settled* (SQLite via `rusqlite` + `bundled`, WAL mode).

The remaining items below are still deferred:

- **Inter-plugin communication** beyond the event bus (large design space; ship without first)
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
> - **UI / API surface** — REST/WebSocket on the existing listener (Phase 12), web UI as the primary surface (Phase 13; the SvelteKit shell lives in the separate `oxidhome/ui` repo and the JS plugin-author package in `oxidhome/ui-sdk`), MCP server first-class (Phase 14). GraphQL/gRPC remain out of scope.

Still open:

- **Model registry hosting** — official curated registry vs. HuggingFace pull-through vs. self-host only
- **Discovery / mDNS** — should the core handle this, or each protocol plugin?
- **Trust model for plugins themselves** — signing? official registry? ad-hoc install with warnings?

## Licensing

- **Code**: dual MIT / Apache-2.0 (Rust ecosystem standard)
- **Articles, documentation, written content**: CC BY 4.0
- Each repository declares its own license; these are the org defaults.

## North-star principles

When in doubt during implementation, these are the tiebreakers:

1. **Security over convenience.** A capability-gated, sandboxed plugin model is the whole point. Don't add escape hatches that defeat the model. When you need an escape hatch (native bridges), make it explicit and visible.

2. **Honest about WASM's limits.** WASM is great for control-plane work and bad for codec-rate data. Design with that grain, not against it.

3. **Capabilities, not types.** Don't enumerate device archetypes. Compose capabilities. Make extension a first-class concept.

4. **The WIT is the product.** Other things change; the WIT is the contract plugin authors depend on. Iterate hard before 1.0; iterate carefully after.

5. **Fail clearly, not silently.** A misconfigured AI model running on CPU when the user expected GPU is a worse outcome than an upfront error. Visibility beats false positives.

6. **Native code is the exception.** The default story is "install a `.wasm` component and trust the sandbox." When that's not enough (vendor SDKs, hardware acceleration), it's a marked exception, not a parallel architecture.
