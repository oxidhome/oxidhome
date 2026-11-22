# oxidhome-test-host

Run an OxidHome plugin inside a `#[test]`: load its component, drive its
lifecycle, and assert on what it did — devices registered, events
published, storage and blobs written, services served — without starting
the `oxidhome-core` daemon.

The harness isn't a mock. A `TestHost` wraps a real `oxidhome-core`
engine on a throwaway state directory, and plugins go through the
production loader, capability gates, quotas, and host-import
implementations. A grant a test injects goes through the same validation
an operator's grant does, so a test can't run a plugin under a boundary
production would never allow.

## Writing a test for your plugin

Build the plugin for `wasm32-wasip2` first. The harness loads a plugin
directory: `manifest.toml` plus the component its `[runtime] wasm` entry
points at.

Say the plugin registers a switch and flips it on `toggle`:

```rust,no_run
use std::time::Duration;

use oxidhome_test_host::wit::devices::{Command, CommandResult};
use oxidhome_test_host::{LoadOptions, TestHost, TestHostError};

// Run it from `#[tokio::test(flavor = "multi_thread")]`, or see
// "Synchronous tests" below.
async fn toggle_flips_the_switch() -> Result<(), TestHostError> {
    // A fresh engine on a temp state dir, removed on drop.
    let host = TestHost::new()?;

    // Load without starting anything; then call `init` yourself. A
    // fixed instance id keeps device ids (and snapshots) stable.
    let mut plugin = host
        .load_with("path/to/my-switch", LoadOptions::new().instance_id("switch"))
        .await?;
    plugin.init().await?;

    // `init` registered one device.
    let device = plugin.devices()[0].id.clone();

    // Send it a command, exactly as the daemon routes one.
    let toggle = Command {
        capability: "switch".into(),
        action: "toggle".into(),
        args: Vec::new(),
    };
    let reply = plugin.send_command(device.clone(), toggle).await?;
    assert!(matches!(reply, CommandResult::OkWithState(_)));

    // Assert on everything at once. Timestamps and other clock- or
    // counter-derived values are left out, so this is stable; the
    // device id is a hash of the plugin, instance, and local id.
    plugin.snapshot()?.assert_matches(&format!(
        r#"
        devices:
          {device} "My Switch" [switch]
        services:
        events:
          {device} state-changed switch {{state=true}}
        storage:
        blobs:
        "#
    ));

    // `tick` runs on a virtual clock: with `tick_interval_ms = 1000`,
    // advancing 3.5 s runs exactly three ticks.
    assert_eq!(plugin.advance(Duration::from_millis(3500)).await?, 3);

    plugin.shutdown().await
}
```

On a mismatch, `assert_matches` panics with a line diff and the full
actual snapshot, ready to paste back. To keep a snapshot in a file
instead, use `assert_matches_file(path)` and run the test once with
`OXIDHOME_UPDATE_SNAPSHOTS=1` to (re)write it.

## Denying a capability

Run the plugin under a narrower grant than its manifest requests, to
test how it copes:

```rust,no_run
use oxidhome_test_host::{CapabilitiesSection, InitError, LoadOptions, TestHost, TestHostError};

# async fn demo() -> Result<(), TestHostError> {
let host = TestHost::new()?;
let mut plugin = host
    .load_with(
        "path/to/kv-counter",
        // No storage quota: every storage call is refused.
        LoadOptions::new().grant(CapabilitiesSection::default()),
    )
    .await?;
assert!(matches!(
    plugin.init().await,
    Err(TestHostError::Init(InitError::Plugin(_)))
));
# Ok(())
# }
```

A grant asking for *more* than the manifest requests is refused with
`TestHostError::GrantExceedsRequest`.

## Services, crashes, and hangs

`TestHost::start` runs a plugin under the daemon's own supervisor
instead. Use it for a plugin that *serves* `call-service` requests, and
to test the restart policy and the liveness watchdog:

```rust,no_run
use std::time::Duration;

use oxidhome_test_host::wit::devices::CommandResult;
use oxidhome_test_host::wit::types::{KeyValue, Value};
use oxidhome_test_host::{InstanceState, LoadOptions, TestHost, test_supervision};

# async fn demo() -> Result<(), Box<dyn std::error::Error>> {
let host = TestHost::new()?;
let counter = host.start("path/to/service-counter").await?;
counter.wait_for_running().await?;

// Call the service through the production dispatcher: routing, the
// typed argument schema, and cycle detection all apply.
let svc = counter.service_id("counter").expect("registered");
let by = vec![KeyValue { key: "by".into(), value: Value::IntVal(5) }];
let reply = host.call_service(svc, "increment", by).await;
assert!(matches!(reply, Ok(CommandResult::OkWithState(_))));
counter.stop().await?;

// A plugin whose tick never returns is interrupted by the watchdog.
let hang = host
    .start_with(
        "path/to/hang",
        LoadOptions::new().supervision(oxidhome_test_host::SupervisorTuning {
            watchdog: Duration::from_millis(300),
            ..test_supervision()
        }),
    )
    .await?;
assert!(matches!(hang.wait_terminal().await, InstanceState::Failed { .. }));
# Ok(())
# }
```

## Synchronous tests

Every driver method is `async`. In a plain `#[test]`, wrap each call in
`block_on`, which runs it on a shared runtime that keeps supervised
instances alive between calls:

```rust,no_run
use oxidhome_test_host::{TestHost, block_on};

let host = TestHost::new().unwrap();
let mut counter = block_on(host.load("path/to/kv-counter")).unwrap();
block_on(counter.init()).unwrap();
block_on(counter.tick()).unwrap();
```

## Limits

- Time: `advance` controls when `tick` runs. Everything else that reads a
  clock — the guest's WASI clocks, event receive times, blob timestamps,
  the watchdog, a supervised instance's tick interval — uses real time,
  because `oxidhome-core` has no clock injection.
- A directly loaded plugin can call services but can't serve them; start
  the provider with `TestHost::start`.
- The direct path uses the production 30 s watchdog; lower it through
  `LoadOptions::supervision` on a supervised instance.
- No streaming or AI mocks yet: the `streaming-plugin` and AI worlds
  aren't built.

The crate's own tests (`tests/examples.rs`) exercise every plugin under
`examples/` and are a good source of patterns.
