# event-recorder

A passive plugin that subscribes to every event on the bus and logs
each one through its `on_event` callback. Companion to
`examples/simulated-switch` — together they exercise the Phase 3
plugin-side `on-event` dispatch path that
`PluginInstance::drain_events()` drives.

This example exists for the integration test in
`crates/oxidhome-core/tests/event_dispatch.rs`. It registers no
devices, handles no commands, and keeps no state — the only
observable behaviour is the log line emitted from `on_event`.

## Build

```shell
cargo build --target wasm32-wasip2
```

## Run via the host

The Phase 2 host binary doesn't yet have a way to drive `drain_events`
from the command line (Phase 6 lands the per-instance scheduler), so
this plugin is most useful inside the integration test:

```shell
# from the OxidHome workspace root
cargo nextest run -p oxidhome-core --test event_dispatch
```

The test loads `simulated-switch` and `event-recorder`, drives a
`switch::toggle` on the switch, calls `drain_events()` on the
recorder, and asserts the recorder's `on_event` logged the matching
`state-changed` event.

## Inspect the component (optional)

```shell
wasm-tools component wit target/wasm32-wasip2/debug/event_recorder.wasm
```

Same `oxidhome:plugin/plugin` world as the other examples; the
plugin's `on-event` export is the interesting one here.
