# hello-world

The smallest possible OxidHome plugin: logs `hello` on `init` and `bye`
on `shutdown`. Used as the Phase 2 integration-test fixture proving the
host can load a `.wasm` component, instantiate it, and round-trip
through the WIT `logging` import.

The example lives in its own Cargo workspace so the host build doesn't
drag `wasm32-wasip2` targets through its graph.

## Build

From this directory:

```shell
cargo build --target wasm32-wasip2
```

The resulting component is at
`target/wasm32-wasip2/debug/hello_world.wasm`.

## Run via the host

From Phase 4 on, the host loader takes the plugin's **install
directory**, not a bare `.wasm` path: it reads `manifest.toml`,
validates it, and resolves `[runtime].wasm` relative to that
directory. This example ships its `manifest.toml` alongside its
`Cargo.toml`, and the manifest's `wasm` key points at
`target/wasm32-wasip2/debug/hello_world.wasm`. So a `cargo build` is
all you need before launching:

From the **OxidHome workspace root**:

```shell
cargo run -p oxidhome-core -- examples/hello-world
```

The host reads `examples/hello-world/manifest.toml`, loads the
`.wasm` the manifest points at, calls its exported `init` then
`shutdown`, and exits.

## Verify

You should see two `tracing` log lines on stdout, in order:

    INFO plugin.init{instance_id=hello_world}: oxidhome_core::runtime::state: hello instance_id="hello_world"
    INFO plugin.shutdown{instance_id=hello_world}: oxidhome_core::runtime::state: bye instance_id="hello_world"

What each piece tells you:

- `plugin.init{...}` / `plugin.shutdown{...}` — the `tracing::Span`
  the host opens around each lifecycle call.
- `hello` / `bye` — the message the plugin emitted via
  `oxidhome_sdk::tracing::info!(...)`. The plugin's subscriber
  forwarded it through the WIT `logging::log` import; the host's
  `logging::Host` impl re-emitted it as a host-side `tracing::info!`,
  which is what stdout receives.
- `instance_id="hello_world"` — added by the host's logging impl,
  derived from the plugin's filename stem (Phase 6 swaps in the
  manifest-declared id).

If you only see one line, or `bye` arrives before `hello`, something in
the lifecycle bridge is broken — the integration test
(`crates/oxidhome-core/tests/hello_world.rs`) asserts the same shape.

## Inspect the component (optional)

`wasm-tools` decodes which world the component implements:

    wasm-tools component wit target/wasm32-wasip2/debug/hello_world.wasm

Look for `world root` exporting `init`, `shutdown`, `on-event`,
`execute-command`, `tick` — the standard `oxidhome:plugin/plugin` world.
