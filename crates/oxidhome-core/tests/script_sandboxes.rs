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
/// deadline, not after the 30 s dispatch timeout or the sleep.
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
        Err(Error::Unavailable(msg)) | Ok(CommandResult::Err(Error::Unavailable(msg))) => msg,
        other => panic!("expected the hop to time out, got {other:?}"),
    };
    assert!(
        msg.contains("timed out") || msg.contains("deadline"),
        "{msg}"
    );

    // The inner hop was dispatched under the same root and chain.
    let rows = hop_rows(&engine, &call_id, 2).await;
    assert_eq!(
        rows[1].path,
        "service.call/example.script-host/main~b/script/slow"
    );
    let inner: serde_json::Value =
        serde_json::from_str(rows[1].invocation.as_deref().expect("invocation")).expect("json");
    assert_eq!(inner["chain"][1]["caller"], "main~a");

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
    while engine.instance("main~a").is_some() || engine.instance("main~b").is_some() {
        assert!(Instant::now() < deadline, "sandboxes outlived the manager");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        engine.sandboxes().list(MANAGER),
        Vec::<(String, String)>::new()
    );
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

    load(&engine, "a", "pong ok\n").await;
    match load_b().await {
        Ok(CommandResult::Err(Error::Unavailable(msg))) => assert!(msg.contains("limit"), "{msg}"),
        other => panic!("expected the limit, got {other:?}"),
    }

    let outcome = call(&engine, scripts.clone(), "unload", vec![string("id", "a")]).await;
    assert!(matches!(outcome, Ok(CommandResult::Ok)), "got {outcome:?}");
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
    // `a`'s slot goes just before its instance-registry entry.
    while engine.instance("main~a").is_some() {
        assert!(Instant::now() < deadline, "a never left the registry");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    manager.stop().await.expect("stop manager");
}
