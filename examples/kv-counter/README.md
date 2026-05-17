# kv-counter

A persistent counter — reads its value from the host's KV store on
`init`, increments on each `counter::tick` command, persists the new
value back through `host::storage::set`. Used as the Phase 5a
integration-test fixture proving the SQLite-backed KV survives a host
restart.

What it does:

- On `init`: calls `host::storage::get("count")`. `Ok(None)` is
  treated as the first-boot path (counter starts at 0); any other
  error (storage gated off, type mismatch, sqlite failure) propagates
  from `init` so misconfigurations surface loudly.
- On `execute_command`:
  - `counter::tick` — increments and writes back, returns the new
    value in `OkWithState { count: int-val }`.
  - `counter::read` — returns the current in-memory value without
    touching storage.
  - Any other capability/action returns `Error::InvalidArgument`.
- On `shutdown`: logs the final count. The value is already persisted
  by the last successful `tick` — no flush step required.

The example deliberately doesn't register a device; Phase 3's device
gate and Phase 5a's storage gate are independent.

## Build

From this directory:

```shell
cargo build --target wasm32-wasip2
```

The component is at `target/wasm32-wasip2/debug/kv_counter.wasm`.

## Run via the host

```shell
# from the OxidHome workspace root
cargo run -p oxidhome-core -- examples/kv-counter
```

The Phase 2 binary loads the plugin, calls `init` and `shutdown` —
there's no CLI surface for sending commands yet (Phase 12). On a fresh
state directory `init` reads `Ok(None)` from storage and the counter
starts at 0; subsequent runs against the same `<state_dir>` would
report whatever the previous run left in `count`.

## Manifest

Storage is gated behind `capabilities.storage_quota_kb`. The example
declares 4 KiB, which is plenty for a single integer counter:

```toml
[capabilities]
storage_quota_kb = 4
```

A quota of 0 (or absent) keeps storage off — every `host::storage::*`
call returns `permission-denied` before it reaches the KV.

## Verify

The integration test
`crates/oxidhome-core/tests/storage_persistence.rs` drives the full
restart cycle: load the plugin against a tempdir, send three `tick`
commands, drop the instance + engine, reopen the engine against the
same tempdir, load the plugin again, send `counter::read`, assert the
value is 3.
