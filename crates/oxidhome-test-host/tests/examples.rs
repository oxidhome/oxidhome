//! One test (or a few) per plugin under `examples/`, exercising its
//! main path through the harness — and, along the way, the harness
//! features each one needs: supervised instances and host-side
//! service calls, blobs, crash and watchdog handling, the virtual
//! clock, snapshots, and `block_on`. `hello-world`, `simulated-switch`,
//! `kv-counter`, and `event-recorder` also run through the
//! conformance suite (`tests/conformance.rs`).

#[path = "support.rs"]
mod support;

use std::time::Duration;

use oxidhome_test_host::wit::devices::{Command, CommandResult};
use oxidhome_test_host::wit::types::{Error as WitError, KeyValue, Value};
use oxidhome_test_host::{
    CapabilitiesSection, InitError, InstanceState, LoadOptions, ServiceGrant, SupervisorTuning,
    TestHost, TestHostError, block_on, test_supervision,
};
use support::{
    CRASHER, HANG, HELLO_WORLD, KV_COUNTER, SERVICE_BOUNCER, SERVICE_CALLER, SERVICE_COUNTER,
    SIMULATED_SWITCH, SNAPSHOT_SAVER, stage_unchanged,
};

fn config(text: &str) -> toml::Value {
    toml::from_str(text).expect("config overrides parse")
}

fn arg(key: &str, value: Value) -> KeyValue {
    KeyValue {
        key: key.into(),
        value,
    }
}

/// The single `value` int a counter reply carries.
fn counter_value(reply: Result<CommandResult, WitError>) -> i64 {
    match reply {
        Ok(CommandResult::OkWithState(fields)) => match fields.as_slice() {
            [
                KeyValue {
                    key,
                    value: Value::IntVal(n),
                },
            ] if key == "value" => *n,
            other => panic!("unexpected counter reply fields {other:?}"),
        },
        other => panic!("expected a counter value, got {other:?}"),
    }
}

fn invalid_argument(reply: Result<CommandResult, WitError>) -> String {
    match reply {
        Err(WitError::InvalidArgument(msg)) => msg,
        other => panic!("expected invalid-argument, got {other:?}"),
    }
}

fn failed_error(state: InstanceState) -> String {
    match state {
        InstanceState::Failed { error } => error,
        other => panic!("expected Failed, got {other:?}"),
    }
}

/// Supervisor settings for the watchdog tests: a short deadline and no
/// restarts, so a hang ends the instance quickly.
fn fast_watchdog() -> SupervisorTuning {
    SupervisorTuning {
        watchdog: Duration::from_millis(300),
        max_restarts: 0,
        ..test_supervision()
    }
}

// ── service-counter ────────────────────────────────────────────────

/// The counter's service, called through the production dispatcher:
/// the M2 typed schema (`increment(by?: int in 1..=1000)`) is enforced
/// before the plugin runs, and the service leaves with the instance.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn service_counter_serves_typed_commands() {
    let staged = stage_unchanged(SERVICE_COUNTER);
    let host = TestHost::new().unwrap();
    let counter = host
        .start_with(staged.path(), LoadOptions::new().instance_id("counter"))
        .await
        .unwrap();
    counter.wait_for_running().await.unwrap();
    assert_eq!(counter.state(), InstanceState::Running);
    assert_eq!(counter.plugin_id(), "example.service-counter");
    let svc = counter.service_id("counter").expect("counter registered");
    assert_eq!(counter.services().len(), 1);
    assert_eq!(
        counter.snapshot().unwrap().services,
        ["counter \"counter\" increment(by?: int), get()"]
    );

    let by = |n| vec![arg("by", Value::IntVal(n))];
    assert_eq!(
        counter_value(host.call_service(&svc, "increment", by(5)).await),
        5
    );
    assert_eq!(
        counter_value(host.call_service(&svc, "increment", Vec::new()).await),
        6
    );
    assert_eq!(
        counter_value(host.call_service(&svc, "get", Vec::new()).await),
        6
    );

    // Refused by the host's schema check; the counter never sees them.
    let msg = invalid_argument(host.call_service(&svc, "increment", by(0)).await);
    assert!(msg.contains("expected 1..=1000"), "{msg}");
    let msg = invalid_argument(
        host.call_service(
            &svc,
            "increment",
            vec![arg("by", Value::StringVal("2".into()))],
        )
        .await,
    );
    assert!(msg.contains("`int-val`"), "{msg}");
    let msg = invalid_argument(host.call_service(&svc, "reset", Vec::new()).await);
    assert!(msg.contains("declares no command \"reset\""), "{msg}");
    assert_eq!(
        counter_value(host.call_service(&svc, "get", Vec::new()).await),
        6
    );

    assert_eq!(counter.stop().await.unwrap(), InstanceState::Stopped);
    assert!(host.engine().services().list().is_empty());
    assert!(matches!(
        host.call_service(&svc, "get", Vec::new()).await,
        Err(WitError::NotFound(_))
    ));
    // The id is free again once `stop` returns.
    let again = host
        .start_with(staged.path(), LoadOptions::new().instance_id("counter"))
        .await
        .unwrap();
    again.wait_for_running().await.unwrap();
    again.stop().await.unwrap();
}

// ── service-caller ─────────────────────────────────────────────────

/// A directly driven caller drives a supervised counter through
/// `call-service` during its `init`, under its manifest's
/// `consumes_services` grant.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn service_caller_drives_the_counter() {
    let counter_dir = stage_unchanged(SERVICE_COUNTER);
    let caller_dir = stage_unchanged(SERVICE_CALLER);
    let host = TestHost::new().unwrap();
    let counter = host.start(counter_dir.path()).await.unwrap();
    counter.wait_for_running().await.unwrap();
    let svc = counter.service_id("counter").unwrap();

    let mut caller = host
        .load_with(
            caller_dir.path(),
            LoadOptions::new().config(config(&format!("target_service_id = \"{svc}\""))),
        )
        .await
        .unwrap();
    caller.init().await.unwrap();
    assert!(matches!(
        caller.storage().get("final_value").unwrap(),
        Some(Value::IntVal(3))
    ));
    assert_eq!(
        counter_value(host.call_service(&svc, "get", Vec::new()).await),
        3
    );
    caller.shutdown().await.unwrap();
    counter.stop().await.unwrap();
}

/// The caller's grant is enforced by the dispatcher: narrowed to `get`,
/// its first `increment` is refused. A counter that is only driven
/// directly can't serve the call at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn service_caller_grant_and_routing_are_enforced() {
    let counter_dir = stage_unchanged(SERVICE_COUNTER);
    let caller_dir = stage_unchanged(SERVICE_CALLER);
    let host = TestHost::new().unwrap();
    let counter = host.start(counter_dir.path()).await.unwrap();
    counter.wait_for_running().await.unwrap();
    let svc = counter.service_id("counter").unwrap();
    let target = config(&format!("target_service_id = \"{svc}\""));

    let requested = host
        .load_with(caller_dir.path(), LoadOptions::new().config(target.clone()))
        .await
        .unwrap()
        .manifest()
        .capabilities
        .clone();
    let get_only = CapabilitiesSection {
        consumes_services: vec![ServiceGrant {
            commands: vec!["get".into()],
            ..requested.consumes_services[0].clone()
        }],
        ..requested.clone()
    };
    let mut narrowed = host
        .load_with(
            caller_dir.path(),
            LoadOptions::new().config(target.clone()).grant(get_only),
        )
        .await
        .unwrap();
    match narrowed.init().await {
        Err(TestHostError::Init(InitError::Plugin(msg))) => {
            assert!(msg.contains("PermissionDenied"), "{msg}");
            assert!(msg.contains("command `increment`"), "{msg}");
        }
        other => panic!("expected the increment to be refused, got {other:?}"),
    }
    assert_eq!(
        counter_value(host.call_service(&svc, "get", Vec::new()).await),
        0,
        "a refused call must not reach the counter"
    );

    // A grant the manifest doesn't request never gets that far.
    let wider = CapabilitiesSection {
        consumes_services: vec![ServiceGrant {
            commands: vec!["reset".into()],
            ..requested.consumes_services[0].clone()
        }],
        ..requested
    };
    let err = host
        .load_with(caller_dir.path(), LoadOptions::new().grant(wider))
        .await
        .err()
        .expect("wider grant must be refused");
    assert!(
        matches!(err, TestHostError::GrantExceedsRequest { .. }),
        "{err:?}"
    );
    counter.stop().await.unwrap();

    // The counter's service registered by a directly driven instance:
    // the dispatcher has no supervisor to route the call to.
    let mut direct_counter = host.load(counter_dir.path()).await.unwrap();
    direct_counter.init().await.unwrap();
    let svc = direct_counter.service_id("counter").unwrap();
    let mut caller = host
        .load_with(
            caller_dir.path(),
            LoadOptions::new().config(config(&format!("target_service_id = \"{svc}\""))),
        )
        .await
        .unwrap();
    match caller.init().await {
        Err(TestHostError::Init(InitError::Plugin(msg))) => {
            assert!(msg.contains("Unavailable"), "{msg}");
            assert!(msg.contains("is not running"), "{msg}");
        }
        other => panic!("expected the call to be unavailable, got {other:?}"),
    }
}

// ── service-bouncer ────────────────────────────────────────────────

/// Two bouncers forwarding `kick` to each other: one hop lands, a loop
/// back into a parked supervisor is refused as a cycle, and a bouncer
/// aimed at itself is refused as same-instance dispatch — promptly,
/// not after the 30 s dispatch timeout.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn service_bouncer_cycles_are_rejected() {
    let staged = stage_unchanged(SERVICE_BOUNCER);
    let host = TestHost::new().unwrap();
    let alpha = host
        .start_with(staged.path(), LoadOptions::new().instance_id("alpha"))
        .await
        .unwrap();
    let beta = host
        .start_with(staged.path(), LoadOptions::new().instance_id("beta"))
        .await
        .unwrap();
    alpha.wait_for_running().await.unwrap();
    beta.wait_for_running().await.unwrap();
    let svc_a = alpha.service_id("bouncer").unwrap();
    let svc_b = beta.service_id("bouncer").unwrap();
    let started = std::time::Instant::now();

    // alpha → beta, and beta has no target: the leaf hop answers.
    alpha
        .storage()
        .set("bounce_to", Value::StringVal(svc_b.clone()))
        .unwrap();
    assert!(matches!(
        host.call_service(&svc_a, "kick", Vec::new()).await,
        Ok(CommandResult::Ok)
    ));

    // alpha → beta → alpha: beta's call back into alpha is refused,
    // and alpha passes beta's error through.
    beta.storage()
        .set("bounce_to", Value::StringVal(svc_a.clone()))
        .unwrap();
    match host.call_service(&svc_a, "kick", Vec::new()).await {
        Ok(CommandResult::Err(WitError::InvalidArgument(msg))) => {
            assert!(msg.contains("cycle detected"), "{msg}");
        }
        other => panic!("expected a cycle error, got {other:?}"),
    }

    // alpha → alpha.
    alpha
        .storage()
        .set("bounce_to", Value::StringVal(svc_a.clone()))
        .unwrap();
    match host.call_service(&svc_a, "kick", Vec::new()).await {
        Ok(CommandResult::Err(WitError::InvalidArgument(msg))) => {
            assert!(msg.contains("same-instance dispatch"), "{msg}");
        }
        other => panic!("expected a same-instance error, got {other:?}"),
    }
    assert!(started.elapsed() < Duration::from_secs(10));
    assert_eq!(host.engine().services().active_call_count(&svc_a), 0);
    assert_eq!(host.engine().services().active_call_count(&svc_b), 0);

    alpha.stop().await.unwrap();
    beta.stop().await.unwrap();
}

// ── snapshot-saver ─────────────────────────────────────────────────

fn write_snapshot(name: &str, payload: Vec<u8>) -> Command {
    Command {
        capability: "snapshot".into(),
        action: "write".into(),
        args: vec![
            arg("name", Value::StringVal(name.into())),
            arg("payload", Value::BytesVal(payload)),
        ],
    }
}

/// `init` writes one blob; the `snapshot::write` command adds more,
/// readable back byte for byte.
#[tokio::test(flavor = "current_thread")]
async fn snapshot_saver_writes_blobs() {
    let staged = stage_unchanged(SNAPSHOT_SAVER);
    let host = TestHost::new().unwrap();
    let mut saver = host.load(staged.path()).await.unwrap();
    saver.init().await.unwrap();
    assert_eq!(saver.read_blob("snapshot-init").unwrap(), b"snapshot:init");

    // The saver registers no device; it handles any device id.
    let reply = saver
        .send_command("camera", write_snapshot("frame-1", b"pixels".to_vec()))
        .await
        .unwrap();
    assert!(matches!(reply, CommandResult::OkWithState(_)), "{reply:?}");
    assert_eq!(saver.read_blob("frame-1").unwrap(), b"pixels");

    let list = Command {
        capability: "snapshot".into(),
        action: "list".into(),
        args: Vec::new(),
    };
    match saver.send_command("camera", list).await.unwrap() {
        CommandResult::OkWithState(fields) => assert!(
            matches!(fields.as_slice(), [KeyValue { value: Value::StringVal(names), .. }]
                if names == "frame-1,snapshot-init"),
            "{fields:?}"
        ),
        other => panic!("unexpected list reply {other:?}"),
    }
    assert_eq!(
        saver.snapshot().unwrap().blobs,
        ["frame-1 6B -", "snapshot-init 13B application/octet-stream"]
    );
    assert!(matches!(
        saver.read_blob("missing"),
        Err(TestHostError::Blobs(_))
    ));
}

/// The blob quota is a hard per-instance ceiling: a write past the
/// granted quota is refused and leaves nothing behind, and with no
/// quota at all the blob store is off.
#[tokio::test(flavor = "current_thread")]
async fn snapshot_saver_blob_quota_is_enforced() {
    let staged = stage_unchanged(SNAPSHOT_SAVER);
    let host = TestHost::new().unwrap();
    let one_mib = CapabilitiesSection {
        blob_quota_mb: 1,
        ..CapabilitiesSection::default()
    };
    let mut saver = host
        .load_with(staged.path(), LoadOptions::new().grant(one_mib))
        .await
        .unwrap();
    saver.init().await.unwrap();
    let reply = saver
        .send_command("camera", write_snapshot("big", vec![7; 2 * 1024 * 1024]))
        .await
        .unwrap();
    match reply {
        CommandResult::Err(WitError::InvalidArgument(msg)) => {
            assert!(msg.to_lowercase().contains("quota"), "{msg}");
        }
        other => panic!("expected the over-quota write to fail, got {other:?}"),
    }
    let names: Vec<String> = saver.blobs().unwrap().into_iter().map(|b| b.name).collect();
    assert_eq!(names, ["snapshot-init"]);

    let mut no_blobs = host
        .load_with(
            staged.path(),
            LoadOptions::new().grant(CapabilitiesSection::default()),
        )
        .await
        .unwrap();
    match no_blobs.init().await {
        Err(TestHostError::Init(InitError::Plugin(msg))) => {
            assert!(msg.contains("PermissionDenied"), "{msg}");
        }
        other => panic!("expected the blob write to be denied, got {other:?}"),
    }
}

// ── crasher ────────────────────────────────────────────────────────

/// Each failure mode, driven directly: the failing export's error comes
/// back to the test, and the plugin can be reloaded under the same id
/// the way a restart would.
#[tokio::test(flavor = "current_thread")]
async fn crasher_failure_modes_surface_as_errors() {
    let staged = stage_unchanged(CRASHER);
    let host = TestHost::new().unwrap();
    let crasher = |mode: &str| {
        LoadOptions::new()
            .instance_id("crasher")
            .config(config(&format!("crash_on = \"{mode}\"")))
    };

    let mut tick = host
        .load_with(staged.path(), crasher("tick"))
        .await
        .unwrap();
    tick.init().await.unwrap();
    let err = tick.tick().await.expect_err("tick traps");
    assert!(
        matches!(err, TestHostError::Call { export: "tick", .. }),
        "{err:?}"
    );
    drop(tick);

    let mut init = host
        .load_with(staged.path(), crasher("init"))
        .await
        .unwrap();
    match init.init().await {
        Err(TestHostError::Init(InitError::Plugin(msg))) => {
            assert_eq!(msg, "crasher: deliberate init failure");
        }
        other => panic!("expected the init failure, got {other:?}"),
    }
    drop(init);

    let mut shutdown = host
        .load_with(staged.path(), crasher("shutdown"))
        .await
        .unwrap();
    shutdown.init().await.unwrap();
    shutdown.tick().await.unwrap();
    let err = shutdown.shutdown().await.expect_err("shutdown traps");
    assert!(
        matches!(
            err,
            TestHostError::Call {
                export: "on-shutdown",
                ..
            }
        ),
        "{err:?}"
    );
}

/// Under the supervisor, `restart = "on-trap"` restarts the tick trap
/// until the restart cap, then gives up; a failing `init` is terminal
/// at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn crasher_restarts_until_the_cap() {
    let staged = stage_unchanged(CRASHER);
    let host = TestHost::new().unwrap();
    let crasher = host
        .start_with(
            staged.path(),
            LoadOptions::new().supervision(SupervisorTuning {
                max_restarts: 2,
                ..test_supervision()
            }),
        )
        .await
        .unwrap();
    let error = failed_error(crasher.wait_terminal().await);
    assert!(error.contains("gave up after 2"), "{error}");
    assert_eq!(
        failed_error(crasher.stop().await.unwrap()),
        error,
        "stop on a failed instance reports the failure"
    );

    let crasher = host
        .start_with(
            staged.path(),
            LoadOptions::new().config(config("crash_on = \"init\"")),
        )
        .await
        .unwrap();
    match crasher.wait_for_running().await {
        Err(TestHostError::NotRunning { state, .. }) => {
            let error = failed_error(state);
            assert!(error.contains("init failed"), "{error}");
        }
        other => panic!("expected the init failure, got {other:?}"),
    }
}

// ── hang ───────────────────────────────────────────────────────────

/// A tick that never returns is interrupted by the liveness watchdog
/// and the instance fails as unresponsive instead of wedging its
/// supervisor.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hang_tick_is_interrupted_by_the_watchdog() {
    let staged = stage_unchanged(HANG);
    let host = TestHost::new().unwrap();
    let hang = host
        .start_with(
            staged.path(),
            LoadOptions::new().supervision(fast_watchdog()),
        )
        .await
        .unwrap();
    let error = failed_error(hang.wait_terminal().await);
    assert!(error.contains("unresponsive"), "{error}");
}

/// Same for an `init` that never returns: the instance never gets to
/// `Running`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hang_init_is_interrupted_by_the_watchdog() {
    let staged = stage_unchanged(HANG);
    let host = TestHost::new().unwrap();
    let hang = host
        .start_with(
            staged.path(),
            LoadOptions::new()
                .config(config("phase = \"init\""))
                .supervision(fast_watchdog()),
        )
        .await
        .unwrap();
    match hang.wait_for_running().await {
        Err(TestHostError::NotRunning { instance_id, state }) => {
            assert_eq!(instance_id, hang.instance_id());
            let error = failed_error(state);
            assert!(error.contains("unresponsive"), "{error}");
        }
        other => panic!("expected the hung init to fail, got {other:?}"),
    }
}

// ── virtual clock ──────────────────────────────────────────────────

/// `advance` runs exactly the ticks `tick_interval_ms` schedules in
/// the span: kv-counter ticks once a second.
#[tokio::test(flavor = "current_thread")]
async fn advance_runs_the_scheduled_ticks() {
    let staged = stage_unchanged(KV_COUNTER);
    let host = TestHost::new().unwrap();
    let mut counter = host.load(staged.path()).await.unwrap();
    counter.init().await.unwrap();
    let count = |c: &oxidhome_test_host::TestPluginInstance| match c.storage().get("count").unwrap()
    {
        Some(Value::IntVal(n)) => n,
        None => 0,
        other => panic!("unexpected count {other:?}"),
    };

    assert_eq!(counter.elapsed(), Duration::ZERO);
    assert_eq!(
        counter.advance(Duration::from_millis(999)).await.unwrap(),
        0
    );
    assert_eq!(count(&counter), 0);
    assert_eq!(counter.advance(Duration::from_millis(1)).await.unwrap(), 1);
    assert_eq!(count(&counter), 1);
    assert_eq!(
        counter.advance(Duration::from_millis(3500)).await.unwrap(),
        3
    );
    assert_eq!(count(&counter), 4);
    assert_eq!(counter.elapsed(), Duration::from_millis(4500));
    assert_eq!(
        counter.advance(Duration::from_millis(500)).await.unwrap(),
        1
    );
    assert_eq!(count(&counter), 5);
    // A direct `tick` runs now and leaves the clock alone.
    counter.tick().await.unwrap();
    assert_eq!(count(&counter), 6);
    assert_eq!(counter.elapsed(), Duration::from_secs(5));

    // No `tick_interval_ms`: never ticked, but the clock still moves.
    let staged = stage_unchanged(HELLO_WORLD);
    let mut hello = host.load(staged.path()).await.unwrap();
    hello.init().await.unwrap();
    assert_eq!(hello.advance(Duration::from_secs(60)).await.unwrap(), 0);
    assert_eq!(hello.elapsed(), Duration::from_mins(1));
}

/// A tick that traps stops the advance at that tick's boundary.
#[tokio::test(flavor = "current_thread")]
async fn advance_stops_at_a_trapping_tick() {
    let staged = stage_unchanged(CRASHER);
    let host = TestHost::new().unwrap();
    let mut crasher = host.load(staged.path()).await.unwrap();
    crasher.init().await.unwrap();
    let err = crasher
        .advance(Duration::from_millis(200))
        .await
        .expect_err("first tick traps");
    assert!(
        matches!(err, TestHostError::Call { export: "tick", .. }),
        "{err:?}"
    );
    // crasher ticks every 50 ms.
    assert_eq!(crasher.elapsed(), Duration::from_millis(50));
}

// ── snapshots ──────────────────────────────────────────────────────

fn toggle() -> Command {
    Command {
        capability: "switch".into(),
        action: "toggle".into(),
        args: Vec::new(),
    }
}

/// A whole-state snapshot of the switch after two toggles. Stable
/// across runs: no timestamps, and the device id derives from the
/// fixed instance id.
#[tokio::test(flavor = "current_thread")]
async fn simulated_switch_snapshot() {
    let staged = stage_unchanged(SIMULATED_SWITCH);
    let host = TestHost::new().unwrap();
    let mut switch = host
        .load_with(staged.path(), LoadOptions::new().instance_id("switch"))
        .await
        .unwrap();
    switch.init().await.unwrap();
    let device = switch.devices()[0].id.clone();
    for _ in 0..2 {
        switch.send_command(device.clone(), toggle()).await.unwrap();
    }
    let snapshot = switch.snapshot().unwrap();
    snapshot.assert_matches(&format!(
        r#"
        devices:
          {device} "Simulated Switch" [switch]
        services:
        events:
          {device} state-changed switch {{state=true}}
          {device} state-changed switch {{state=false}}
        storage:
        blobs:
        "#
    ));

    // The same snapshot through a file.
    let dir = support::TempDir::new("snapshot-file");
    let path = dir.path().join("switch.snap");
    std::fs::write(&path, snapshot.to_string()).unwrap();
    snapshot.assert_matches_file(&path);

    // A fresh host replays to the same text.
    let host = TestHost::new().unwrap();
    let mut again = host
        .load_with(staged.path(), LoadOptions::new().instance_id("switch"))
        .await
        .unwrap();
    again.init().await.unwrap();
    for _ in 0..2 {
        again.send_command(device.clone(), toggle()).await.unwrap();
    }
    again.snapshot().unwrap().assert_matches_file(&path);
}

// ── block_on ───────────────────────────────────────────────────────

/// A plain `#[test]`: direct and supervised instances driven through
/// `block_on`. The supervisor keeps running between calls because
/// every call shares one runtime.
#[test]
fn block_on_drives_a_synchronous_test() {
    let counter_dir = stage_unchanged(KV_COUNTER);
    let service_dir = stage_unchanged(SERVICE_COUNTER);
    let host = TestHost::new().unwrap();

    let mut counter = block_on(host.load(counter_dir.path())).unwrap();
    block_on(counter.init()).unwrap();
    assert_eq!(
        block_on(counter.advance(Duration::from_secs(2))).unwrap(),
        2
    );
    assert!(matches!(
        counter.storage().get("count").unwrap(),
        Some(Value::IntVal(2))
    ));

    let service = block_on(host.start(service_dir.path())).unwrap();
    block_on(service.wait_for_running()).unwrap();
    let svc = service.service_id("counter").unwrap();
    for expected in 1..=3 {
        let reply = block_on(host.call_service(&svc, "increment", Vec::new()));
        assert_eq!(counter_value(reply), expected);
    }
    assert_eq!(block_on(service.stop()).unwrap(), InstanceState::Stopped);
}
