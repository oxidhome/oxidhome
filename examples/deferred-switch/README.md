# deferred-switch

A simulated switch whose commands finish asynchronously, showing the `accepted` command outcome from
[ADR-0003](../../docs/adr/0003-explicit-command-outcomes.md).

- On `init`: registers one device (`switch-1`) with the `switch` capability.
- On `execute_command`:
  - `switch::set { state: bool }` and `switch::toggle` return `CommandResult::Accepted` and remember the
    host-minted `cmd.id`. The caller sees outcome `accepted` (REST `202`).
  - The same with `lost: true` is accepted but never completed, so the host expires it as `outcome_unknown`.
  - Any other capability or action returns `err`, which the host reports as `rejected`.
- On each `tick` (every 50 ms): applies every accepted command, publishes `state-changed`, and calls
  `host::complete_command(id, OkWithState)`. The host projects the state and records the final outcome in the
  audit trail.

## Build

```shell
cargo build --target wasm32-wasip2
```

The component is at `target/wasm32-wasip2/debug/deferred_switch.wasm`.
