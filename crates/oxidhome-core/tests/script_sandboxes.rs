//! ADR-0001 — one sandbox per script.
//!
//! Drives the `script-host` example: a manager instance starts one
//! sandbox (child instance, own `Store`) per script, and scripts call
//! each other through `host-services::call-service`. Covers the
//! review's central H1 use case end to end: a same-plugin script →
//! script call goes through the host dispatcher (grants, cycle check,
//! deadline, H6 audit chain), a crash in the callee is `unknown` to the
//! caller (H5) and restarts only the callee, and the manager's
//! lifecycle bounds its sandboxes'.

#[path = "support.rs"]
mod support;

use std::path::PathBuf;
use std::time::{Duration, Instant};

use oxidhome_core::auth::{ActorKind, InvocationContext, Principal, Transport};
use oxidhome_core::host_impl::plugin::oxidhome::plugin::devices::CommandResult;
use oxidhome_core::host_impl::plugin::oxidhome::plugin::types::{Error, KeyValue, Value};
use oxidhome_core::runtime::{LoadMode, dispatcher};
use oxidhome_core::state::AuditQuery;
use oxidhome_core::{Actor, Engine, InstanceHandle, InstanceState, SupervisorTuning};
use oxidhome_manifest::{CapabilitiesSection, ServiceGrant};

const PLUGIN: &str = "example.script-host";
const MANAGER: &str = "main";

fn plugin_dir() -> PathBuf {
    let _wasm = support::build_example("script-host", "script_host.wasm");
    support::workspace_root()
        .join("examples")
        .join("script-host")
}

fn fast_tuning() -> SupervisorTuning {
    SupervisorTuning {
        backoff_base: Duration::from_millis(10),
        backoff_max: Duration::from_millis(40),
        ..SupervisorTuning::default()
    }
}

/// The test driver's own grant: any command on any service of the
/// example plugin (the manager's `scripts`, the scripts' `script`).
fn driver_grants() -> Vec<ServiceGrant> {
    ["scripts", "script"]
        .into_iter()
        .map(|service| ServiceGrant {
            plugin: PLUGIN.into(),
            instance: "*".into(),
            service: service.into(),
            commands: vec!["*".into()],
            caller_instance: "*".into(),
        })
        .collect()
}

async fn start_manager(engine: &Engine, mode: LoadMode) -> InstanceHandle {
    let handle = engine
        .start_instance_with_tuning(plugin_dir(), MANAGER, None, mode, fast_tuning())
        .await
        .expect("start manager");
    handle.wait_for_running().await.expect("manager Running");
    handle
}

/// Wait until `instance` has registered `local_id` and return its id.
async fn service_of(engine: &Engine, instance: &str, local_id: &str) -> String {
    let deadline = Instant::now() + Duration::from_mins(1);
    loop {
        if let Some(id) = engine
            .services()
            .resolve_by_local_id(PLUGIN, instance, local_id)
        {
            return id;
        }
        assert!(
            Instant::now() < deadline,
            "`{instance}` didn't register `{local_id}`"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn call(
    engine: &Engine,
    target: String,
    command: &str,
    args: Vec<KeyValue>,
) -> Result<CommandResult, Error> {
    let grants = driver_grants();
    dispatcher::call_service_from_host(
        engine,
        "test-driver",
        &grants,
        &grants,
        target,
        command,
        args,
    )
    .await
}

async fn call_in(
    engine: &Engine,
    ctx: InvocationContext,
    target: String,
    command: &str,
) -> Result<CommandResult, Error> {
    let grants = driver_grants();
    dispatcher::call_service_from_host_in(
        engine,
        ctx,
        "test-driver",
        &grants,
        &grants,
        target,
        command,
        Vec::new(),
    )
    .await
}

fn string(key: &str, value: &str) -> KeyValue {
    KeyValue {
        key: key.into(),
        value: Value::StringVal(value.into()),
    }
}

/// Load `id` through the manager's `scripts.load` and return the
/// sandbox's `script` service id once it is registered.
async fn load(engine: &Engine, id: &str, source: &str) -> String {
    let manager = service_of(engine, MANAGER, "scripts").await;
    let reply = call(
        engine,
        manager,
        "load",
        vec![string("id", id), string("source", source)],
    )
    .await;
    let instance = format!("{MANAGER}~{id}");
    match reply {
        Ok(CommandResult::OkWithState(fields)) => assert!(
            matches!(&fields[..], [KeyValue { key, value: Value::StringVal(v) }]
                if key == "instance_id" && *v == instance),
            "load reply {fields:?}"
        ),
        other => panic!("load `{id}` failed: {other:?}"),
    }
    service_of(engine, &instance, "script").await
}

fn api_root() -> InvocationContext {
    let actor = Actor::api("tok-h1", vec!["*".into()]);
    InvocationContext::external(Principal::token(ActorKind::Api, &actor, Transport::Rest))
}

/// Finalized audit rows of one invocation, oldest first.
async fn hop_rows(
    engine: &Engine,
    call_id: &str,
    want: usize,
) -> Vec<oxidhome_core::state::AuditEntry> {
    let audit = engine.audit_log();
    let started = Instant::now();
    loop {
        let mut rows = audit
            .query(
                &AuditQuery {
                    call_id: Some(call_id.to_owned()),
                    ..AuditQuery::default()
                },
                50,
            )
            .expect("query");
        if rows.len() >= want && rows.iter().all(|r| r.finalized_ms.is_some()) {
            rows.sort_by_key(|r| r.id);
            return rows;
        }
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "hop rows not finalized: {rows:?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// The central H1 use case: script `a` calls script `b` of the same
/// plugin through the host dispatcher. Each script is its own
/// supervised instance, the call is audited under the external root,
/// and the delegation chain records the script-to-script hop.
#[tokio::test(flavor = "multi_thread")]
async fn script_calls_sibling_through_host_dispatch_with_audited_chain() {
    let state = support::tempdir("sandbox-chain");
    let engine = Engine::with_state_dir(state.path()).expect("engine");
    let manager = start_manager(&engine, LoadMode::Dev).await;

    let svc_b = load(&engine, "b", "pong ok\n").await;
    let svc_a = load(&engine, "a", "ping call b pong\n").await;

    // Each script is its own instance of the plugin, child of `main`.
    for id in ["main~a", "main~b"] {
        let handle = engine.instance(id).expect("sandbox registered");
        assert_eq!(handle.plugin_id(), PLUGIN);
        // The service registers inside `init`, just before `Running`.
        handle.wait_for_running().await.expect("sandbox Running");
    }
    assert_eq!(
        engine.sandboxes().list(MANAGER),
        vec![
            ("a".to_owned(), "main~a".to_owned()),
            ("b".to_owned(), "main~b".to_owned())
        ]
    );
    // Loading the same source again re-adopts the live sandbox.
    assert_eq!(load(&engine, "b", "pong ok\n").await, svc_b);

    let root = api_root();
    let call_id = root.call_id().to_owned();
    let outcome = call_in(&engine, root, svc_a, "ping").await;
    assert!(matches!(outcome, Ok(CommandResult::Ok)), "got {outcome:?}");

    let rows = hop_rows(&engine, &call_id, 2).await;
    assert_eq!(rows.len(), 2, "one row per hop: {rows:?}");
    assert_eq!(
        rows[0].path,
        "service.call/example.script-host/main~a/script/ping"
    );
    assert_eq!(
        rows[1].path,
        "service.call/example.script-host/main~b/script/pong"
    );
    for row in &rows {
        assert_eq!(row.token_id, "tok-h1");
        assert_eq!(row.decision, "allow");
        assert_eq!(row.execution_outcome.as_deref(), Some("success"));
    }
    let inner: serde_json::Value =
        serde_json::from_str(rows[1].invocation.as_deref().expect("invocation")).expect("json");
    assert_eq!(inner["root"]["subject"], "tok-h1");
    assert_eq!(inner["chain"][0]["caller"], "test-driver");
    assert_eq!(inner["chain"][0]["instance"], "main~a");
    assert_eq!(inner["chain"][1]["caller"], "main~a");
    assert_eq!(inner["chain"][1]["instance"], "main~b");
    assert_eq!(inner["current"], "main~b");

    // A script the sandbox couldn't run is refused before it's saved.
    let scripts = service_of(&engine, MANAGER, "scripts").await;
    let outcome = call(
        &engine,
        scripts,
        "load",
        vec![string("id", "bad"), string("source", "bad.name ok\n")],
    )
    .await;
    assert!(
        matches!(outcome, Ok(CommandResult::Err(Error::InvalidArgument(_)))),
        "got {outcome:?}"
    );
    assert!(engine.instance("main~bad").is_none());

    // `~` is reserved for sandboxes: an operator can't take that id.
    let err = engine
        .start_instance(plugin_dir(), "main~c", None)
        .await
        .expect_err("`~` is reserved");
    assert!(err.to_string().contains("reserved"), "{err:#}");

    manager.stop().await.expect("stop manager");
}

/// The script-to-script call is authorized like any other: an
/// operator-narrowed grant lets `a` call `b` but not `c`.
#[tokio::test(flavor = "multi_thread")]
async fn sibling_call_needs_a_grant() {
    let state = support::tempdir("sandbox-grant");
    let engine = Engine::with_state_dir(state.path()).expect("engine");
    let granted = CapabilitiesSection {
        declares_services: vec!["scripts".into(), "script".into()],
        script_sandboxes: 8,
        storage_quota_kb: 256,
        consumes_services: vec![ServiceGrant {
            plugin: PLUGIN.into(),
            instance: "main~b".into(),
            service: "script".into(),
            commands: vec!["*".into()],
            caller_instance: "main~a".into(),
        }],
        ..CapabilitiesSection::default()
    };
    let manager = start_manager(
        &engine,
        LoadMode::Granted {
            granted: granted.into(),
        },
    )
    .await;

    load(&engine, "b", "pong ok\n").await;
    load(&engine, "c", "pong ok\n").await;
    let svc_a = load(&engine, "a", "to-b call b pong\nto-c call c pong\n").await;

    let outcome = call(&engine, svc_a.clone(), "to-b", Vec::new()).await;
    assert!(matches!(outcome, Ok(CommandResult::Ok)), "got {outcome:?}");
    let outcome = call(&engine, svc_a, "to-c", Vec::new()).await;
    match outcome {
        Ok(CommandResult::Err(Error::PermissionDenied(msg))) => {
            assert!(msg.contains("main~c"), "{msg}");
        }
        other => panic!("expected permission-denied, got {other:?}"),
    }

    manager.stop().await.expect("stop manager");
}

/// a → b → a is a cycle: refused promptly instead of deadlocking `a`'s
/// supervisor.
#[tokio::test(flavor = "multi_thread")]
async fn cycle_between_scripts_is_refused() {
    let state = support::tempdir("sandbox-cycle");
    let engine = Engine::with_state_dir(state.path()).expect("engine");
    let manager = start_manager(&engine, LoadMode::Dev).await;

    let svc_a = load(&engine, "a", "ping call b ping\n").await;
    load(&engine, "b", "ping call a ping\n").await;

    let started = Instant::now();
    let outcome = call(&engine, svc_a, "ping", Vec::new()).await;
    match outcome {
        Ok(CommandResult::Err(Error::InvalidArgument(msg))) => {
            assert!(msg.contains("cycle detected"), "{msg}");
        }
        other => panic!("expected cycle refusal, got {other:?}"),
    }
    assert!(started.elapsed() < Duration::from_secs(5));

    manager.stop().await.expect("stop manager");
}

/// The root's deadline bounds the script-to-script hop: with 500 ms
/// left, `a`'s call into a `b` that sleeps 3 s gives up at the root's
/// deadline, not after the 30 s dispatch timeout or the sleep. `b` had
/// started, so the answer is `unknown` (H5), not a retry-safe
/// `unavailable`.
#[tokio::test(flavor = "multi_thread")]
async fn deadline_propagates_to_the_sibling_hop() {
    let state = support::tempdir("sandbox-deadline");
    let engine = Engine::with_state_dir(state.path()).expect("engine");
    let manager = start_manager(&engine, LoadMode::Dev).await;

    load(&engine, "b", "slow sleep 3000\n").await;
    let svc_a = load(&engine, "a", "relay call b slow\n").await;

    let root = api_root();
    let root = root.with_deadline(Some(
        tokio::time::Instant::now() + Duration::from_millis(500),
    ));
    let call_id = root.call_id().to_owned();
    let started = Instant::now();
    let outcome = call_in(&engine, root, svc_a, "relay").await;
    let elapsed = started.elapsed();
    assert!(elapsed < Duration::from_millis(2500), "took {elapsed:?}");
    let msg = match outcome {
        Ok(CommandResult::Unknown(msg)) => msg,
        other => panic!("expected the started hop to be unknown, got {other:?}"),
    };
    assert!(msg.contains("deadline"), "{msg}");

    // The inner hop was dispatched under the same root and chain.
    let rows = hop_rows(&engine, &call_id, 2).await;
    assert_eq!(
        rows[1].path,
        "service.call/example.script-host/main~b/script/slow"
    );
    let inner: serde_json::Value =
        serde_json::from_str(rows[1].invocation.as_deref().expect("invocation")).expect("json");
    assert_eq!(inner["chain"][1]["caller"], "main~a");
    // ...and ended without an outcome: `b` was running, so it may
    // have acted, rather than running its sleep to success.
    assert_eq!(rows[1].status, 200, "{:?}", rows[1]);
    assert_eq!(rows[1].decision, "allow", "{:?}", rows[1]);
    assert_eq!(rows[1].execution_outcome, None, "{:?}", rows[1]);

    manager.stop().await.expect("stop manager");
}

/// A trap in `b` after the call reached it: the caller hears `unknown`
/// (b may have acted), `b` restarts on its own, and neither `a` nor the
/// manager restarts.
#[tokio::test(flavor = "multi_thread")]
async fn crash_in_sibling_is_unknown_and_restarts_only_that_script() {
    let state = support::tempdir("sandbox-crash");
    let engine = Engine::with_state_dir(state.path()).expect("engine");
    let manager = start_manager(&engine, LoadMode::Dev).await;

    let svc_b = load(&engine, "b", "boom trap\npong ok\n").await;
    let svc_a = load(&engine, "a", "relay call b boom\nping call b pong\n").await;
    let svc_manager = service_of(&engine, MANAGER, "scripts").await;

    let outcome = call(&engine, svc_a.clone(), "relay", Vec::new()).await;
    match outcome {
        Ok(CommandResult::Unknown(msg)) => assert!(msg.contains("main~b"), "{msg}"),
        other => panic!("expected unknown, got {other:?}"),
    }

    // `b` comes back under a fresh service id.
    let deadline = Instant::now() + Duration::from_mins(1);
    let new_b = loop {
        let id = service_of(&engine, "main~b", "script").await;
        if id != svc_b {
            break id;
        }
        assert!(Instant::now() < deadline, "b did not restart");
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    assert_ne!(new_b, svc_b);
    // `a` and the manager kept their registrations: they never restarted.
    assert_eq!(service_of(&engine, "main~a", "script").await, svc_a);
    assert_eq!(service_of(&engine, MANAGER, "scripts").await, svc_manager);
    assert_eq!(manager.state(), InstanceState::Running);

    let outcome = call(&engine, svc_a, "ping", Vec::new()).await;
    assert!(matches!(outcome, Ok(CommandResult::Ok)), "got {outcome:?}");

    manager.stop().await.expect("stop manager");
}

/// Stopping the manager stops its sandboxes; `unload` stops one.
#[tokio::test(flavor = "multi_thread")]
async fn sandboxes_end_with_their_manager() {
    let state = support::tempdir("sandbox-stop");
    let engine = Engine::with_state_dir(state.path()).expect("engine");
    let manager = start_manager(&engine, LoadMode::Dev).await;

    load(&engine, "a", "pong ok\n").await;
    load(&engine, "b", "pong ok\n").await;
    let scripts = service_of(&engine, MANAGER, "scripts").await;
    let outcome = call(&engine, scripts, "unload", vec![string("id", "a")]).await;
    assert!(matches!(outcome, Ok(CommandResult::Ok)), "got {outcome:?}");
    assert_eq!(
        engine.sandboxes().list(MANAGER),
        vec![("b".to_owned(), "main~b".to_owned())]
    );

    manager.stop().await.expect("stop manager");
    let deadline = Instant::now() + Duration::from_mins(1);
    // The manager leaves the registry only after its sandboxes have.
    while engine.instance(MANAGER).is_some() {
        assert!(Instant::now() < deadline, "manager never left the registry");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(engine.instance("main~a").is_none());
    assert!(engine.instance("main~b").is_none());
    assert!(!engine.sandboxes().has_children(MANAGER));
}

/// `script_sandboxes` caps the sandboxes one instance runs, and a
/// sandbox that is still stopping counts until its supervisor is gone.
#[tokio::test(flavor = "multi_thread")]
async fn sandbox_limit_counts_stopping_sandboxes() {
    let state = support::tempdir("sandbox-limit");
    let engine = Engine::with_state_dir(state.path()).expect("engine");
    let granted = CapabilitiesSection {
        declares_services: vec!["scripts".into(), "script".into()],
        script_sandboxes: 1,
        storage_quota_kb: 256,
        ..CapabilitiesSection::default()
    };
    let manager = start_manager(
        &engine,
        LoadMode::Granted {
            granted: granted.into(),
        },
    )
    .await;
    let scripts = service_of(&engine, MANAGER, "scripts").await;
    let load_b = || {
        call(
            &engine,
            scripts.clone(),
            "load",
            vec![string("id", "b"), string("source", "pong ok\n")],
        )
    };

    // The longest sleep the example allows, so `a` is still busy well
    // after the assertions below.
    let svc_a = load(&engine, "a", "hold sleep 10000\n").await;
    match load_b().await {
        Ok(CommandResult::Err(Error::Unavailable(msg))) => assert!(msg.contains("limit"), "{msg}"),
        other => panic!("expected the limit, got {other:?}"),
    }

    // Keep `a` busy, so it is still stopping after `unload`: hidden
    // from the list, still registered, and still counted.
    let held = tokio::spawn({
        let engine = engine.clone();
        let svc_a = svc_a.clone();
        async move { call(&engine, svc_a, "hold", Vec::new()).await }
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    while engine.services().active_call_count(&svc_a) == 0 {
        assert!(
            !held.is_finished() && Instant::now() < deadline,
            "the hold call never started"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    // Let the call reach `a`'s supervisor ahead of the stop.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let outcome = call(&engine, scripts.clone(), "unload", vec![string("id", "a")]).await;
    assert!(matches!(outcome, Ok(CommandResult::Ok)), "got {outcome:?}");
    assert_eq!(
        engine.sandboxes().list(MANAGER),
        Vec::<(String, String)>::new()
    );
    assert!(engine.instance("main~a").is_some());
    match load_b().await {
        Ok(CommandResult::Err(Error::Unavailable(msg))) => assert!(msg.contains("limit"), "{msg}"),
        other => panic!("a stopping sandbox must still count, got {other:?}"),
    }
    let _ = held.await;
    // Once `a` is gone, `b` fits.
    let deadline = Instant::now() + Duration::from_mins(1);
    loop {
        match load_b().await {
            Ok(CommandResult::OkWithState(_)) => break,
            Ok(CommandResult::Err(Error::Unavailable(_))) => {}
            other => panic!("unexpected {other:?}"),
        }
        assert!(Instant::now() < deadline, "a never finished stopping");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // `a`'s slot goes only after its instance-registry entry.
    assert!(engine.instance("main~a").is_none());

    manager.stop().await.expect("stop manager");
}

/// Scripts outlive a manager crash: the manager's next life re-adopts
/// the same sandbox (same instance, same service) instead of starting
/// a new one.
#[tokio::test(flavor = "multi_thread")]
async fn manager_crash_keeps_and_readopts_its_scripts() {
    let state = support::tempdir("sandbox-readopt");
    let engine = Engine::with_state_dir(state.path()).expect("engine");
    let manager = start_manager(&engine, LoadMode::Dev).await;
    let svc_a = load(&engine, "a", "pong ok\n").await;
    let scripts = service_of(&engine, MANAGER, "scripts").await;

    let outcome = call(&engine, scripts.clone(), "crash", Vec::new()).await;
    assert!(
        matches!(outcome, Ok(CommandResult::Unknown(_))),
        "a trap mid-call is unknown: {outcome:?}"
    );
    // The manager's next life registers `scripts` afresh.
    let deadline = Instant::now() + Duration::from_mins(1);
    let fresh = loop {
        match engine
            .services()
            .resolve_by_local_id(PLUGIN, MANAGER, "scripts")
        {
            Some(id) if id != scripts && manager.state() == InstanceState::Running => break id,
            _ => {}
        }
        assert!(Instant::now() < deadline, "manager never came back");
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    assert_ne!(fresh, scripts);

    // `a` kept running through it and is still the same sandbox.
    assert_eq!(
        engine.sandboxes().list(MANAGER),
        vec![("a".to_owned(), "main~a".to_owned())]
    );
    assert_eq!(service_of(&engine, "main~a", "script").await, svc_a);
    let outcome = call(&engine, svc_a.clone(), "pong", Vec::new()).await;
    assert!(matches!(outcome, Ok(CommandResult::Ok)), "got {outcome:?}");
    assert_eq!(load(&engine, "a", "pong ok\n").await, svc_a);

    manager.stop().await.expect("stop manager");
}

/// Wait until `instance` has left the instance registry.
async fn wait_gone(engine: &Engine, instance: &str) {
    let deadline = Instant::now() + Duration::from_mins(1);
    while engine.instance(instance).is_some() {
        assert!(
            Instant::now() < deadline,
            "`{instance}` never left the registry"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// ADR-0001 follow-up: a supervisor compiles its component once. Its
/// restarts, the sandboxes it starts and their restarts all reuse it.
#[tokio::test(flavor = "multi_thread")]
async fn restarts_and_sandboxes_reuse_the_compiled_component() {
    let state = support::tempdir("sandbox-compile-once");
    let engine = Engine::with_state_dir(state.path()).expect("engine");
    let manager = start_manager(&engine, LoadMode::Dev).await;
    assert_eq!(engine.component_compile_count(), 1);

    let svc_a = load(&engine, "a", "boom trap\npong ok\n").await;
    load(&engine, "b", "pong ok\n").await;
    assert_eq!(
        engine.component_compile_count(),
        1,
        "sandboxes compiled again"
    );

    // A sandbox restart reuses it.
    let outcome = call(&engine, svc_a.clone(), "boom", Vec::new()).await;
    assert!(
        matches!(outcome, Ok(CommandResult::Unknown(_))),
        "got {outcome:?}"
    );
    let deadline = Instant::now() + Duration::from_mins(1);
    while service_of(&engine, "main~a", "script").await == svc_a {
        assert!(Instant::now() < deadline, "a did not restart");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // So does a restart of the manager itself.
    let scripts = service_of(&engine, MANAGER, "scripts").await;
    let outcome = call(&engine, scripts.clone(), "crash", Vec::new()).await;
    assert!(
        matches!(outcome, Ok(CommandResult::Unknown(_))),
        "got {outcome:?}"
    );
    while service_of(&engine, MANAGER, "scripts").await == scripts {
        assert!(Instant::now() < deadline, "manager did not restart");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    manager.wait_for_running().await.expect("manager Running");
    assert_eq!(
        engine.component_compile_count(),
        1,
        "a restart compiled again"
    );

    manager.stop().await.expect("stop manager");
}

/// The parent/child relation is on every sandbox's handle, and the
/// API stop wait covers a parent's sandboxes: once it returns, none of
/// them is left, even one stuck in a slow call (cancelled, so its
/// caller hears `unknown`).
#[tokio::test(flavor = "multi_thread")]
async fn stop_waits_for_slow_sandboxes_and_reports_the_relation() {
    let state = support::tempdir("sandbox-stop-wait");
    let engine = Engine::with_state_dir(state.path()).expect("engine");
    let manager = start_manager(&engine, LoadMode::Dev).await;
    let svc_a = load(&engine, "a", "slow sleep 10000\n").await;

    let child = engine.instance("main~a").expect("sandbox registered");
    assert_eq!(child.parent_instance_id(), Some(MANAGER));
    assert_eq!(child.sandbox_local_id(), Some("a"));
    assert_eq!(manager.parent_instance_id(), None);
    assert_eq!(manager.sandbox_local_id(), None);

    let slow = tokio::spawn({
        let engine = engine.clone();
        async move { call(&engine, svc_a, "slow", Vec::new()).await }
    });
    // Let the call reach the sandbox's `sleep` (an idle sandbox enters
    // it within milliseconds; the margin is for loaded CI runners).
    tokio::time::sleep(Duration::from_secs(1)).await;

    let started = Instant::now();
    let report = oxidhome_core::stop_and_wait_reaped(vec![manager], Duration::from_mins(1)).await;
    assert_eq!(report.stopped, vec![MANAGER.to_owned()]);
    assert_eq!(report.still_stopping, Vec::<String>::new());
    assert!(
        started.elapsed() < Duration::from_secs(8),
        "the sandbox's 10 s sleep held the stop up: {:?}",
        started.elapsed()
    );
    assert!(engine.instance(MANAGER).is_none());
    assert!(engine.instance("main~a").is_none());
    assert!(matches!(child.state(), InstanceState::Stopped));

    match slow.await.expect("join") {
        Ok(CommandResult::Unknown(msg)) => assert!(msg.contains("stopped"), "{msg}"),
        other => panic!("expected unknown, got {other:?}"),
    }
}

/// A sandbox's storage goes with its script: `stop-sandbox` (the
/// manager's `unload`) purges it once the sandbox is gone, while a
/// sandbox that stops with its parent keeps it for the next life.
#[tokio::test(flavor = "multi_thread")]
async fn removed_script_storage_is_purged() {
    let state = support::tempdir("sandbox-purge");
    let engine = Engine::with_state_dir(state.path()).expect("engine");
    let manager = start_manager(&engine, LoadMode::Dev).await;
    let svc_a = load(&engine, "a", "save store\n").await;
    let svc_b = load(&engine, "b", "save store\n").await;
    for svc in [svc_a, svc_b] {
        let outcome = call(&engine, svc, "save", Vec::new()).await;
        assert!(matches!(outcome, Ok(CommandResult::Ok)), "got {outcome:?}");
    }
    let uuid = manager.installation_uuid().expect("loaded").to_owned();
    let kv = engine.kv();
    for id in ["main~a", "main~b"] {
        let (used, _) = kv.usage(&uuid, id).expect("usage").expect("row");
        assert!(used > 0, "{id} stored nothing");
    }

    let scripts = service_of(&engine, MANAGER, "scripts").await;
    let outcome = call(&engine, scripts, "unload", vec![string("id", "a")]).await;
    assert!(matches!(outcome, Ok(CommandResult::Ok)), "got {outcome:?}");
    wait_gone(&engine, "main~a").await;
    assert_eq!(kv.usage(&uuid, "main~a").expect("usage"), None);
    assert_eq!(
        kv.list_keys(&uuid, "main~a", "").expect("keys"),
        Vec::<String>::new()
    );

    // Stopping the manager isn't a removal: `b` keeps its storage.
    manager.stop().await.expect("stop manager");
    wait_gone(&engine, MANAGER).await;
    assert!(kv.usage(&uuid, "main~b").expect("usage").is_some());
    assert_eq!(
        kv.list_keys(&uuid, "main~b", "").expect("keys"),
        vec!["note".to_owned()]
    );
}

/// Sandboxes don't nest: `start-sandbox` from inside one is
/// `permission-denied`.
#[tokio::test(flavor = "multi_thread")]
async fn sandbox_cannot_start_a_sandbox() {
    let state = support::tempdir("sandbox-nest");
    let engine = Engine::with_state_dir(state.path()).expect("engine");
    let manager = start_manager(&engine, LoadMode::Dev).await;
    let svc_a = load(&engine, "a", "deeper nest\n").await;
    let outcome = call(&engine, svc_a, "deeper", Vec::new()).await;
    assert!(
        matches!(outcome, Ok(CommandResult::Err(Error::PermissionDenied(_)))),
        "got {outcome:?}"
    );
    assert!(engine.instance("main~a~nested").is_none());
    assert_eq!(
        engine.sandboxes().list(MANAGER),
        vec![("a".to_owned(), "main~a".to_owned())]
    );
    manager.stop().await.expect("stop manager");
}

/// The embedder entry points that bypass the instance registry refuse
/// a sandbox-shaped id and the id of a registered instance.
#[tokio::test(flavor = "multi_thread")]
async fn embedder_helpers_refuse_reserved_and_registered_ids() {
    let state = support::tempdir("sandbox-embedder-ids");
    let engine = Engine::with_state_dir(state.path()).expect("engine");
    let manager = start_manager(&engine, LoadMode::Dev).await;
    load(&engine, "a", "pong ok\n").await;

    for id in ["main~b", MANAGER, "main~a"] {
        let err = match oxidhome_core::PluginInstance::load(&engine, &plugin_dir(), id).await {
            Ok(_) => panic!("load accepted `{id}`"),
            Err(err) => format!("{err:#}"),
        };
        assert!(
            err.contains("reserved") || err.contains("running supervised instance"),
            "{id}: {err}"
        );
        let handle = oxidhome_core::supervise(engine.clone(), plugin_dir(), id, PLUGIN, None);
        let err = handle
            .wait_for_running()
            .await
            .expect_err("supervise accepted the id")
            .to_string();
        assert!(
            err.contains("reserved") || err.contains("running supervised instance"),
            "{id}: {err}"
        );
    }
    // The refusals touched nothing.
    assert_eq!(manager.state(), InstanceState::Running);
    assert!(engine.instance("main~b").is_none());
    manager.stop().await.expect("stop manager");
}
