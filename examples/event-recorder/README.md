# event-recorder

A passive plugin that subscribes to every event on the bus and logs
each one through its `on_event` callback. Companion to
`examples/simulated-switch` — together they exercise the Phase 3
plugin-side `on-event` dispatch path that
`PluginInstance::drain_events()` drives.

This example exists for the integration test in
`crates/oxidhome-core/tests/event_dispatch.rs`. It registers no
devices and keeps no state beyond a count of received events. It
answers three `recorder` commands: `count` (events seen so far),
`read-state device=<id>` and `list-state`. The last two read the
host's device-state projection through the `host-state` import (H2).
Reading another plugin's devices needs a
`[[capabilities.reads_state]]` grant, which this manifest leaves out
on purpose; `crates/oxidhome-test-host/tests/test_host.rs` stages one.

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

Needs `cargo-nextest` (covered by the workspace's `cargo install-tools` alias — see `CONTRIBUTING.md`). If you'd rather not install it, `cargo test -p oxidhome-core --test event_dispatch` works on a default Rust setup.

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
