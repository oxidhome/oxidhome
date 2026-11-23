//! One test (or a few) per plugin under `examples/`, exercising its
//! main path through the harness — and, along the way, the harness
//! features each one needs: supervised instances and host-side
//! service calls, blobs, crash and watchdog handling, the virtual
//! clock, snapshots, and `block_on`. `clock-probe` is the fixture for
//! the guest's view of the virtual clock. `hello-world`, `simulated-switch`,
//! `kv-counter`, and `event-recorder` also run through the
//! conformance suite (`tests/conformance.rs`).

#[path = "support.rs"]
mod support;

use std::time::Duration;

use oxidhome_test_host::wit::devices::{Command, CommandResult};
use oxidhome_test_host::wit::types::{Error as WitError, KeyValue, Value};
use oxidhome_test_host::{
    CapabilitiesSection, CommandOutcome, InitError, InstanceState, LoadOptions, ServiceGrant,
    SnapshotOptions, SupervisedInstance, SupervisorTuning, TestHost, TestHostError, VirtualClock,
    block_on, test_supervision,
};
use support::{
    CLOCK_PROBE, CRASHER, DEFERRED_SWITCH, HANG, HELLO_WORLD, KV_COUNTER, SCRIPT_HOST,
    SERVICE_BOUNCER, SERVICE_CALLER, SERVICE_COUNTER, SIMULATED_SWITCH, SNAPSHOT_SAVER,
    stage_unchanged,
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
    assert_eq!(host.engine().services().list().len(), 0);
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

// ── script-host ────────────────────────────────────────────────────

/// ADR-0001 under the harness: a supervised script-host runs each
/// script in its own sandbox instance, and one script calls another
/// through the host dispatcher. An unsupervised load can't start
/// sandboxes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn script_host_runs_scripts_in_sandboxes() {
    let staged = stage_unchanged(SCRIPT_HOST);
    let host = TestHost::new().unwrap();
    let manager = host
        .start_with(staged.path(), LoadOptions::new().instance_id("main"))
        .await
        .unwrap();
    manager.wait_for_running().await.unwrap();
    let scripts = manager.service_id("scripts").unwrap();
    let load = |id: &str, source: &str| {
        vec![
            arg("id", Value::StringVal(id.into())),
            arg("source", Value::StringVal(source.into())),
        ]
    };
    for (id, source) in [("b", "pong ok\n"), ("a", "ping call b pong\n")] {
        let reply = host.call_service(&scripts, "load", load(id, source)).await;
        assert!(
            matches!(reply, Ok(CommandResult::OkWithState(_))),
            "load {id}: {reply:?}"
        );
    }
    let services = host.engine().services();
    // Every sandbox compiles the component on load, which is slow in
    // debug builds on a loaded machine.
    let deadline = std::time::Instant::now() + Duration::from_mins(1);
    let svc_a = loop {
        let a = services.resolve_by_local_id("example.script-host", "main~a", "script");
        let b = services.resolve_by_local_id("example.script-host", "main~b", "script");
        if let (Some(a), Some(_)) = (a, b) {
            break a;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "scripts not running: {:?}",
            host.engine().instance("main~a").map(|h| h.state())
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    assert!(matches!(
        host.call_service(&svc_a, "ping", Vec::new()).await,
        Ok(CommandResult::Ok)
    ));
    manager.stop().await.unwrap();

    // Unsupervised, the same component can't start a sandbox.
    let mut direct = host
        .load_with(staged.path(), LoadOptions::new().instance_id("direct"))
        .await
        .unwrap();
    direct.init().await.unwrap();
    let scripts = direct.service_id("scripts").unwrap();
    let reply = direct
        .inner_mut()
        .execute_service_command(scripts, "load".into(), load("a", "pong ok\n"))
        .await
        .unwrap();
    assert!(
        matches!(reply, CommandResult::Err(WitError::Unavailable(_))),
        "{reply:?}"
    );
    direct.shutdown().await.unwrap();
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
        id: "cmd-test".into(),
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
        id: "cmd-test".into(),
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
/// supervisor. On the virtual clock this runs the production 30 s
/// watchdog in no real time, and shows it doesn't fire early: only
/// moving time past the deadline trips it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hang_tick_is_interrupted_by_the_watchdog() {
    let staged = stage_unchanged(HANG);
    let host = TestHost::with_virtual_clock().unwrap();
    let clock = host.virtual_clock().unwrap().clone();
    let hang = host
        .start_with(
            staged.path(),
            LoadOptions::new().supervision(SupervisorTuning {
                max_restarts: 0,
                ..test_supervision()
            }),
        )
        .await
        .unwrap();
    hang.wait_for_running().await.unwrap();

    // The first tick is due 10 ms after `Running`; once it fires, the
    // supervisor reschedules the next one while the tick spins. The
    // jump doesn't wait for the tick (it never returns).
    clock.advance(Duration::from_millis(10));
    eventually("the first tick to start", || {
        clock.next_deadline() > Some(clock.elapsed())
    })
    .await;
    // Short of the deadline, however long in real time, it runs on.
    clock.advance(Duration::from_secs(29));
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(hang.state(), InstanceState::Running);

    // Past it, the watchdog interrupts the call.
    clock.advance(Duration::from_secs(2));
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

/// A supervised instance ticks on the host's virtual clock: never on
/// its own, and exactly once per `tick_interval_ms` the clock passes,
/// however big the step.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn supervised_ticks_follow_the_virtual_clock() {
    let staged = stage_unchanged(KV_COUNTER);
    let host = TestHost::with_virtual_clock().unwrap();
    let counter = host.start(staged.path()).await.unwrap();
    counter.wait_for_running().await.unwrap();
    let count = || match counter.storage().get("count").unwrap() {
        Some(Value::IntVal(n)) => n,
        None => 0,
        other => panic!("unexpected count {other:?}"),
    };

    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert_eq!(count(), 0, "real time doesn't tick a virtual host");
    host.advance(Duration::from_millis(999)).await.unwrap();
    assert_eq!(count(), 0);
    host.advance(Duration::from_millis(1)).await.unwrap();
    assert_eq!(count(), 1);
    host.advance(Duration::from_millis(3500)).await.unwrap();
    assert_eq!(
        count(),
        4,
        "one tick per interval crossed, not one per step"
    );
    host.run_until_idle().await.unwrap();
    assert_eq!(count(), 4);
    assert_eq!(
        host.virtual_clock().unwrap().elapsed(),
        Duration::from_millis(4500)
    );
    counter.stop().await.unwrap();

    // A real-clock host has nothing to advance.
    let real = TestHost::new().unwrap();
    assert!(real.virtual_clock().is_none());
    assert!(matches!(
        real.advance(Duration::from_secs(1)).await,
        Err(TestHostError::RealClock)
    ));
    assert!(matches!(
        real.run_until_idle().await,
        Err(TestHostError::RealClock)
    ));
}

/// The guest's WASI clocks read the virtual clock: wall time from its
/// start, monotonic time from zero, both moving only with it. The
/// host's event receive times follow the same clock.
#[tokio::test(flavor = "current_thread")]
async fn guest_clocks_read_virtual_time() {
    let staged = stage_unchanged(CLOCK_PROBE);
    let start = std::time::UNIX_EPOCH + Duration::from_secs(1_000_000);
    let host = TestHost::with_clock(VirtualClock::starting_at(start)).unwrap();
    let mut probe = host.load(staged.path()).await.unwrap();
    probe.init().await.unwrap();
    // A direct tick runs at the current virtual time.
    probe.tick().await.unwrap();
    assert_eq!(probe.advance(Duration::from_millis(2500)).await.unwrap(), 2);
    assert_eq!(probe.elapsed(), Duration::from_millis(2500));
    probe
        .snapshot_with(&SnapshotOptions::new().times())
        .unwrap()
        .assert_matches(
            r#"
            devices:
            services:
            events:
              - custom clock {\"wall_ms\":1000000000,\"mono_ms\":0} @+0.000s
              - custom clock {\"wall_ms\":1000001000,\"mono_ms\":1000} @+1.000s
              - custom clock {\"wall_ms\":1000002000,\"mono_ms\":2000} @+2.000s
            storage:
            blobs:
            "#,
        );

    // Loaded later, an instance counts its ticks from its own load.
    let mut late = host.load(staged.path()).await.unwrap();
    late.init().await.unwrap();
    assert_eq!(late.elapsed(), Duration::ZERO);
    assert_eq!(late.advance(Duration::from_millis(500)).await.unwrap(), 0);
    assert_eq!(late.advance(Duration::from_millis(500)).await.unwrap(), 1);
    assert_eq!(probe.elapsed(), Duration::from_millis(3500));
}

/// Every snapshot masks the instance's secret config values, wherever
/// the plugin put them, and the optional sections render the
/// commands' H5 outcomes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn snapshots_mask_secrets() {
    let staged = stage_unchanged(KV_COUNTER);
    let manifest = staged.path().join("manifest.toml");
    let mut text = std::fs::read_to_string(&manifest).unwrap();
    text.push_str("\n[config.api_key]\ntype = \"secret\"\ndescription = \"Cloud key.\"\n");
    std::fs::write(&manifest, text).unwrap();
    let options = || {
        LoadOptions::new()
            .instance_id("counter")
            .config(config("api_key = \"k3y-secret\""))
    };
    let expected = r#"
        devices:
        services:
        events:
        storage:
          note = "***"
          other = "a *** inside"
          password = "***"
        blobs:
        commands:
          "" counter.bogus -> rejected invalid-argument("unsupported action counter::bogus")
        "#;
    let bogus = Command {
        id: "cmd-1".into(),
        capability: "counter".into(),
        action: "bogus".into(),
        args: Vec::new(),
    };
    let seed = |storage: oxidhome_test_host::StorageView| {
        storage
            .set("note", Value::StringVal("k3y-secret".into()))
            .unwrap();
        storage
            .set("other", Value::StringVal("a k3y-secret inside".into()))
            .unwrap();
        storage
            .set("password", Value::StringVal("hunter2".into()))
            .unwrap();
    };

    // Virtual, so the supervised counter doesn't tick into `storage`.
    let host = TestHost::with_virtual_clock().unwrap();
    let mut direct = host.load_with(staged.path(), options()).await.unwrap();
    direct.init().await.unwrap();
    seed(direct.storage());
    direct.send_command("", bogus.clone()).await.unwrap();
    let snapshot = direct
        .snapshot_with(&SnapshotOptions::new().commands())
        .unwrap();
    snapshot.assert_matches(expected);
    direct.shutdown().await.unwrap();

    // The supervised path resolves the same secrets.
    let supervised = host.start_with(staged.path(), options()).await.unwrap();
    supervised.wait_for_running().await.unwrap();
    supervised.send_command("", bogus).await;
    supervised
        .snapshot_with(&SnapshotOptions::new().commands())
        .unwrap()
        .assert_matches(expected);
    supervised.stop().await.unwrap();
}

// ── command outcomes (H5) ──────────────────────────────────────────

fn switch_command(action: &str, args: Vec<KeyValue>) -> Command {
    Command {
        id: String::new(),
        capability: "switch".into(),
        action: action.into(),
        args,
    }
}

fn only_device(instance: &SupervisedInstance) -> String {
    instance.devices()[0].id.clone()
}

/// Poll `done` every 10 ms for up to 5 s.
async fn eventually(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !done() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for {what}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Success is `completed` with the plugin's state; a plugin refusal is
/// `rejected` and retry-safe. Each dispatch gets its own host-minted id,
/// whatever id the caller put on the command.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn command_outcomes_completed_and_rejected() {
    let staged = stage_unchanged(SIMULATED_SWITCH);
    let host = TestHost::new().unwrap();
    let switch = host.start(staged.path()).await.unwrap();
    switch.wait_for_running().await.unwrap();
    let device = only_device(&switch);

    let first = switch
        .send_command(device.clone(), switch_command("toggle", Vec::new()))
        .await;
    match &first.outcome {
        CommandOutcome::Completed { state: Some(state) } => {
            assert_eq!(state[0].key, "state");
        }
        other => panic!("expected completed with state, got {other:?}"),
    }
    assert!(first.command_id.starts_with("cmd-"), "{first:?}");
    assert!(!first.outcome.is_retry_safe());

    let refused = switch
        .send_command(device, switch_command("self-destruct", Vec::new()))
        .await;
    match &refused.outcome {
        CommandOutcome::Rejected {
            error: WitError::InvalidArgument(_),
        } => {}
        other => panic!("expected rejected, got {other:?}"),
    }
    assert!(refused.outcome.is_retry_safe());
    assert_ne!(first.command_id, refused.command_id);
    switch.stop().await.unwrap();
}

/// A trap after the plugin started the command is `outcome_unknown`:
/// whatever it did to the device may stand. The trap still crashes the
/// instance.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn command_trap_after_start_is_outcome_unknown() {
    let staged = stage_unchanged(CRASHER);
    let host = TestHost::new().unwrap();
    let crasher = host
        .start_with(
            staged.path(),
            LoadOptions::new()
                .config(config("crash_on = \"command\""))
                .supervision(SupervisorTuning {
                    max_restarts: 0,
                    ..test_supervision()
                }),
        )
        .await
        .unwrap();
    crasher.wait_for_running().await.unwrap();
    let device = only_device(&crasher);

    let report = crasher
        .send_command(device, switch_command("toggle", Vec::new()))
        .await;
    match &report.outcome {
        CommandOutcome::Unknown { message } => {
            assert!(
                message.contains("crashed during execute-command"),
                "{message}"
            );
        }
        other => panic!("expected outcome_unknown, got {other:?}"),
    }
    assert!(!report.outcome.is_retry_safe());
    let error = failed_error(crasher.wait_terminal().await);
    assert!(error.contains("invoking plugin execute-command"), "{error}");
}

/// The deadline rules. The first command wedges the plugin; its
/// deadline passes while it runs, so it is `outcome_unknown`. The
/// second command's deadline passes while it waits in the queue behind
/// the first, so it is `timed_out` — and it never runs, even after the
/// watchdog frees the supervisor.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn command_deadline_before_and_after_start() {
    let staged = stage_unchanged(HANG);
    let host = TestHost::new().unwrap();
    let hang = host
        .start_with(
            staged.path(),
            LoadOptions::new()
                .config(config("phase = \"command\""))
                .supervision(SupervisorTuning {
                    watchdog: Duration::from_secs(1),
                    max_restarts: 0,
                    ..test_supervision()
                }),
        )
        .await
        .unwrap();
    hang.wait_for_running().await.unwrap();
    let device = only_device(&hang);

    let (running, queued) = tokio::join!(
        hang.send_command_with_deadline(
            device.clone(),
            switch_command("toggle", Vec::new()),
            Duration::from_millis(300),
        ),
        async {
            tokio::time::sleep(Duration::from_millis(50)).await;
            hang.send_command_with_deadline(
                device.clone(),
                switch_command("toggle", Vec::new()),
                Duration::from_millis(100),
            )
            .await
        },
    );
    match &running.outcome {
        CommandOutcome::Unknown { message } => {
            assert!(message.contains("while instance"), "{message}");
        }
        other => panic!("expected outcome_unknown, got {other:?}"),
    }
    match &queued.outcome {
        CommandOutcome::TimedOut { message } => {
            assert!(message.contains("did not run"), "{message}");
        }
        other => panic!("expected timed_out, got {other:?}"),
    }
    assert!(queued.outcome.is_retry_safe());
    // The watchdog ends the wedged call; the instance fails as
    // unresponsive.
    let error = failed_error(hang.wait_terminal().await);
    assert!(error.contains("unresponsive"), "{error}");
}

/// A stop while a command runs and another waits behind it: the
/// running one ends `outcome_unknown` (the watchdog interrupts the
/// spinning guest), the queued one is refused without running
/// (`rejected`), and the instance ends `Stopped`: the stop wins over
/// the crash.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stop_refuses_queued_commands() {
    let staged = stage_unchanged(HANG);
    let host = TestHost::new().unwrap();
    let hang = host
        .start_with(
            staged.path(),
            LoadOptions::new()
                .config(config("phase = \"command\""))
                .supervision(SupervisorTuning {
                    watchdog: Duration::from_secs(1),
                    ..test_supervision()
                }),
        )
        .await
        .unwrap();
    hang.wait_for_running().await.unwrap();
    let device = only_device(&hang);

    let (running, queued, ()) = tokio::join!(
        hang.send_command(device.clone(), switch_command("toggle", Vec::new())),
        async {
            tokio::time::sleep(Duration::from_millis(50)).await;
            hang.send_command(device.clone(), switch_command("toggle", Vec::new()))
                .await
        },
        async {
            tokio::time::sleep(Duration::from_millis(150)).await;
            hang.handle().request_stop();
        },
    );
    assert!(
        matches!(running.outcome, CommandOutcome::Unknown { .. }),
        "{running:?}"
    );
    match &queued.outcome {
        CommandOutcome::Rejected { error } => {
            assert!(error.to_string().contains("stopped before"), "{error}");
        }
        other => panic!("expected rejected, got {other:?}"),
    }
    assert_eq!(hang.wait_terminal().await, InstanceState::Stopped);
}

/// `accepted`: the caller hears it at once, the plugin completes the
/// command on its next tick with `complete-command`, and the pending
/// entry goes away with the state projected and published. On the
/// virtual clock nothing happens until the tick is due, and then
/// exactly once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn command_accepted_then_completed() {
    let staged = stage_unchanged(DEFERRED_SWITCH);
    let host = TestHost::with_virtual_clock().unwrap();
    let switch = host
        .start_with(staged.path(), LoadOptions::new().instance_id("switch"))
        .await
        .unwrap();
    switch.wait_for_running().await.unwrap();
    let device = only_device(&switch);

    let report = switch
        .send_command(device.clone(), switch_command("toggle", Vec::new()))
        .await;
    assert!(
        matches!(report.outcome, CommandOutcome::Accepted),
        "{report:?}"
    );
    let pending = switch.pending_commands();
    // Real time passing changes nothing.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(pending.len(), 1);
    host.advance(Duration::from_millis(49)).await.unwrap();
    assert_eq!(pending.len(), 1);
    // The fixture publishes no event: the projection changes because
    // the host projects the completion's `ok-with-state`.
    host.advance(Duration::from_millis(1)).await.unwrap();
    assert!(pending.is_empty());
    assert_eq!(projected_switch(&host, &device), Some(true));
    switch
        .snapshot_with(&SnapshotOptions::new().device_state().commands().times())
        .unwrap()
        .assert_matches(&format!(
            r#"
            devices:
              {device} "Deferred Switch" [switch]
            services:
            events:
            storage:
            blobs:
            device-state:
              {device} switch {{state=true}} @+0.050s
            commands:
              {device} switch.toggle -> accepted (resolved)
            "#
        ));
    switch.stop().await.unwrap();
}

/// An accepted command that never completes expires as
/// `outcome_unknown` when its TTL runs out — on the virtual clock, at
/// exactly that point; stopping the instance expires what it still
/// held.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn command_accepted_then_expired() {
    let staged = stage_unchanged(DEFERRED_SWITCH);
    let host = TestHost::with_virtual_clock().unwrap();
    let switch = host.start(staged.path()).await.unwrap();
    switch.wait_for_running().await.unwrap();
    let device = only_device(&switch);
    let lost = || switch_command("toggle", vec![arg("lost", Value::BoolVal(true))]);
    let pending = switch.pending_commands();

    // A short TTL keeps the 50 ms tick count down; the default works
    // the same, in more steps.
    pending.set_ttl(Duration::from_secs(1));
    let report = switch.send_command(device.clone(), lost()).await;
    assert!(
        matches!(report.outcome, CommandOutcome::Accepted),
        "{report:?}"
    );
    assert!(pending.is_pending(&report.command_id));
    host.advance(Duration::from_millis(999)).await.unwrap();
    assert_eq!(pending.len(), 1, "one virtual millisecond to go");
    host.advance(Duration::from_millis(1)).await.unwrap();
    assert!(pending.is_empty(), "the TTL ran out");

    pending.set_ttl(Duration::from_mins(5));
    let report = switch.send_command(device, lost()).await;
    assert!(matches!(report.outcome, CommandOutcome::Accepted));
    assert_eq!(pending.len(), 1);
    switch.stop().await.unwrap();
    assert!(
        pending.is_empty(),
        "stop expires the instance's pending commands"
    );
}

/// The direct harness registers `accepted` commands too, so a plugin's
/// asynchronous path is testable tick by tick on the virtual clock.
#[tokio::test(flavor = "current_thread")]
async fn command_accepted_completes_on_a_direct_tick() {
    let staged = stage_unchanged(DEFERRED_SWITCH);
    let host = TestHost::new().unwrap();
    let mut switch = host.load(staged.path()).await.unwrap();
    switch.init().await.unwrap();
    let device = switch.devices()[0].id.clone();
    let pending = host.engine().pending_commands();

    let mut command = switch_command("set", vec![arg("state", Value::BoolVal(true))]);
    command.id = "cmd-00000000000000000000000000000001".into();
    let reply = switch.send_command(device.clone(), command).await.unwrap();
    assert!(matches!(reply, CommandResult::Accepted), "{reply:?}");
    assert_eq!(pending.len(), 1);
    assert_eq!(switch.advance(Duration::from_millis(50)).await.unwrap(), 1);
    assert!(pending.is_empty(), "the tick completed the command");
    assert_eq!(projected_switch(&host, &device), Some(true));
}

/// The projected `switch.state` of `device`.
fn projected_switch(host: &TestHost, device: &str) -> Option<bool> {
    host.engine()
        .device_state()
        .snapshot_device(device)
        .iter()
        .filter(|s| s.capability == "switch")
        .flat_map(|s| s.fields.iter())
        .find_map(|kv| match (kv.key.as_str(), &kv.value) {
            ("state", Value::BoolVal(b)) => Some(*b),
            _ => None,
        })
}

// ── snapshots ──────────────────────────────────────────────────────

fn toggle() -> Command {
    Command {
        id: "cmd-test".into(),
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
