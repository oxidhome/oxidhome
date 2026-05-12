# simulated-switch

A software-only switch — no real hardware, no ambient state. Used as
the Phase 3 integration-test fixture for the device registry +
event bus.

What it does:

- On `init`: registers one device (`switch-1`) with the `switch`
  capability and reports an initial `state = false`.
- On `execute_command`:
  - `switch::set { state: bool }` — sets the switch to the requested
    state.
  - `switch::toggle` — flips the current state.
  - Any other capability/action returns an `Error::InvalidArgument`.
- On every successful state change: publishes a `state-changed` event
  with the new `state` field on the host's event bus.
- On `shutdown`: best-effort `remove_device` to clear the registry.

The example lives in its own Cargo workspace so the host build doesn't
drag `wasm32-wasip2` targets through its graph.

## Build

From this directory:

```shell
cargo build --target wasm32-wasip2
```

The component is at
`target/wasm32-wasip2/debug/simulated_switch.wasm`.

## Run via the host

The Phase 2 host binary loads the plugin, calls `init`, then
`shutdown` — it has no command-line surface for sending commands or
subscribing to events yet (Phase 12 lands the CLI). Useful as a smoke
check that the plugin loads and registers cleanly:

```shell
# from the OxidHome workspace root
cargo run -p oxidhome-core -- \
    examples/simulated-switch/target/wasm32-wasip2/debug/simulated_switch.wasm
```

## Verify

The interesting end-to-end path runs through the integration test
`crates/oxidhome-core/tests/simulated_switch.rs`, which:

1. Loads the plugin.
2. Subscribes to the bus *before* `init`.
3. Asserts the registry holds exactly one device after `init`.
4. Calls `execute_command(device_id, switch::toggle)` and asserts
   `OkWithState { state = true }` comes back.
5. Reads the bus subscription and asserts a matching `state-changed`
   event arrived.
6. Calls `shutdown` and asserts the registry is empty afterward.

To run it:

```shell
# from the OxidHome workspace root
cargo nextest run -p oxidhome-core --test simulated_switch
```

## Inspect the component (optional)

```shell
wasm-tools component wit target/wasm32-wasip2/debug/simulated_switch.wasm
```

The world this implements should match `oxidhome:plugin/plugin` —
exports `init`, `shutdown`, `on-event`, `execute-command`, `tick`;
imports `host-devices`, `host-events`, `host-config`, `storage`,
`logging` plus the WASI imports libstd pulls in.
