//! Phase 7c — cross-plugin service dispatch.
//!
//! Drives two supervised instances (`service-counter` + `service-caller`)
//! against the dispatcher: the caller drives `counter.increment` × 3
//! → `counter.get` and stores the final value in KV; the test reads
//! it back to confirm the round-trip routed correctly.
//!
//! Also covers the dispatcher's defenses: instance-granularity
//! recursion detection (a counter that calls itself rejects with
//! `InvalidArgument`) and target-not-found (`call-service` against an
//! unknown `svc-N` returns `NotFound`).

#[path = "support.rs"]
mod support;

use std::time::{Duration, Instant};

use oxidhome_core::auth::role::builtin;

use oxidhome_core::host_impl::plugin::oxidhome::plugin::types::Value;
use oxidhome_core::{Engine, InstanceState};

/// State directory + builds for the two examples. Returns the engine
/// and the plugin dirs.
fn setup() -> (
    Engine,
    std::path::PathBuf,
    std::path::PathBuf,
    support::TempDir,
) {
    let _counter_wasm = support::build_example("service-counter", "service_counter.wasm");
    let _caller_wasm = support::build_example("service-caller", "service_caller.wasm");
    let counter_dir = support::workspace_root()
        .join("examples")
        .join("service-counter");
    let caller_dir = support::workspace_root()
        .join("examples")
        .join("service-caller");
    let state_dir = support::tempdir("dispatch-state");
    let engine = Engine::with_state_dir(state_dir.path()).expect("engine");
    (engine, counter_dir, caller_dir, state_dir)
}

/// Wait for the registry to surface the counter's `svc-N` id; mirror
/// of the Phase-6 `wait_until_unregistered` polling helper.
async fn await_service_id(engine: &Engine) -> String {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let services = engine.services().list();
        if let Some(meta) = services.first() {
            return meta.id.clone();
        }
        assert!(
            Instant::now() < deadline,
            "service not registered within 5s",
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Happy path: caller's `init` drives `counter.increment` × 3 →
/// `counter.get` via the dispatcher, and the final value lands in KV.
#[tokio::test(flavor = "multi_thread")]
async fn cross_plugin_call_service_round_trips() {
    let (engine, counter_dir, caller_dir, _state) = setup();

    // 1. Start the counter; it registers `counter` in `init`.
    let counter = engine
        .start_instance(counter_dir, "counter", None)
        .await
        .expect("start counter");
    counter.wait_for_running().await.expect("counter Running");
    let target_id = await_service_id(&engine).await;

    // 2. Start the caller with the canonical `svc-N` plugged into its
    //    config. The caller's `init` makes the four host calls and
    //    persists the final value.
    let overrides: toml::Value =
        toml::from_str(&format!("target_service_id = \"{target_id}\"\n")).expect("overrides parse");
    let caller = engine
        .start_instance(caller_dir, "caller", Some(overrides))
        .await
        .expect("start caller");
    caller.wait_for_running().await.expect("caller Running");

    // 3. The caller's KV has the final value the counter returned.
    // `PluginInstance::load` uses `manifest.plugin.id` as the
    // installation_uuid fallback for engine-loaded (non-installed)
    // plugins — see `runtime/instance.rs`.
    let stored = engine
        .kv()
        .get("example.service-caller", "caller", "final_value")
        .expect("read final_value");
    assert!(
        matches!(stored, Some(Value::IntVal(3))),
        "expected counter to be 3 after 3 increments, got {stored:?}",
    );

    // Active-call refcount should be 0 after the round-trip — the
    // dispatcher's `CallGuard::release` ran on each hop.
    assert_eq!(engine.services().active_call_count(&target_id), 0);

    caller.stop().await.expect("stop caller");
    counter.stop().await.expect("stop counter");
}

/// A `target_service_id` that doesn't exist surfaces `not-found`
/// through the dispatcher and back into the guest's `init` Result.
#[tokio::test(flavor = "multi_thread")]
async fn call_service_to_unknown_target_is_not_found() {
    let (engine, _counter_dir, caller_dir, _state) = setup();

    let overrides: toml::Value =
        toml::from_str("target_service_id = \"svc-999\"\n").expect("overrides parse");
    let caller = engine
        .start_instance(caller_dir, "caller", Some(overrides))
        .await
        .expect("start caller");

    match caller.wait_terminal().await {
        InstanceState::Failed { error } => {
            let lower = error.to_ascii_lowercase();
            assert!(
                lower.contains("not") && lower.contains("found") && lower.contains("svc-999"),
                "expected a not-found mentioning svc-999, got: {error}",
            );
        }
        other => panic!("expected Failed (caller's init returns Err), got {other:?}"),
    }
}

/// Cross-task A→B→A cycle, end-to-end through wasm. Two `service-bouncer`
/// instances are configured to bounce to each other; calling A.kick
/// runs A's wasm, which calls B.kick (A's supervisor parks),
/// which runs B's wasm, which calls A.kick — the dispatcher must
/// reject *that* with `InvalidArgument` rather than letting it
/// deadlock A's supervisor for the full 30s `DISPATCH_TIMEOUT`. The
/// error rides back through B's wasm into A's wasm, surfaces as a
/// `CommandResult::Err`, and the test asserts it landed promptly.
#[tokio::test(flavor = "multi_thread")]
async fn cross_task_cycle_is_rejected_promptly() {
    use oxidhome_core::host_impl::plugin::oxidhome::plugin::devices::CommandResult;
    use oxidhome_core::host_impl::plugin::oxidhome::plugin::types::{Error as WitError, Value};
    use oxidhome_core::runtime::dispatcher;

    let _wasm = support::build_example("service-bouncer", "service_bouncer.wasm");
    let bouncer_dir = support::workspace_root()
        .join("examples")
        .join("service-bouncer");
    let state_dir = support::tempdir("dispatch-cycle-state");
    let engine = Engine::with_state_dir(state_dir.path()).expect("engine");

    // Two bouncer instances, alpha and beta.
    let alpha = engine
        .start_instance(bouncer_dir.clone(), "alpha", None)
        .await
        .expect("start alpha");
    alpha.wait_for_running().await.expect("alpha Running");
    let beta = engine
        .start_instance(bouncer_dir, "beta", None)
        .await
        .expect("start beta");
    beta.wait_for_running().await.expect("beta Running");

    // Find the svc-N each instance registered.
    let services = engine.services().list();
    let svc_a = services
        .iter()
        .find(|m| m.owner_instance == "alpha")
        .expect("alpha registered a service")
        .id
        .clone();
    let svc_b = services
        .iter()
        .find(|m| m.owner_instance == "beta")
        .expect("beta registered a service")
        .id
        .clone();

    // Wire the cycle through each plugin's per-instance KV. The
    // bouncer reads `bounce_to` on every kick. Both bouncer
    // instances share the same plugin_id, which is the fallback
    // installation_uuid used by `PluginInstance::load`.
    let kv = engine.kv();
    kv.set(
        "example.service-bouncer",
        "alpha",
        "bounce_to",
        Value::StringVal(svc_b.clone()),
    )
    .expect("set alpha.bounce_to");
    kv.set(
        "example.service-bouncer",
        "beta",
        "bounce_to",
        Value::StringVal(svc_a.clone()),
    )
    .expect("set beta.bounce_to");

    // Drive A.kick from the host. Should round-trip *quickly* —
    // before the 30s DISPATCH_TIMEOUT — with the cycle error
    // surfaced via B's wasm to A's CommandResult::Err.
    let started = std::time::Instant::now();
    // H10: host-driven test grant — the wasm-to-wasm hops below
    // use the bouncer's own manifest grant. This one only
    // authorizes the outermost driver→A kick.
    let driver_grants = [oxidhome_manifest::ServiceGrant {
        plugin: "example.service-bouncer".into(),
        instance: "*".into(),
        service: "bouncer".into(),
        commands: vec!["kick".into()],
        caller_instance: "*".into(),
    }];
    let outcome = tokio::time::timeout(
        Duration::from_secs(10),
        dispatcher::call_service_from_host(
            &engine,
            "test-driver",
            // Same list for requested + granted — the test driver
            // isn't a real installed plugin, so there's no operator
            // narrowing shape to model.
            &driver_grants,
            &driver_grants,
            svc_a.clone(),
            "kick",
            Vec::new(),
        ),
    )
    .await
    .expect("call must not exceed the test timeout");
    let elapsed = started.elapsed();

    // The dispatcher returned (didn't deadlock).
    assert!(
        elapsed < Duration::from_secs(5),
        "cycle rejection should be near-instant; took {elapsed:?}",
    );

    // The shape: A's wasm propagated B's result, which propagated the
    // dispatcher's `InvalidArgument` from the cycle check. So the
    // outermost call returns `Ok(CommandResult::Err(InvalidArgument))`
    // — the dispatcher itself sees A's wasm finishing normally.
    // H10: the multi-hop case surfaces as "cycle detected".
    match outcome {
        Ok(CommandResult::Err(WitError::InvalidArgument(msg))) => {
            assert!(
                msg.to_ascii_lowercase().contains("cycle detected"),
                "expected `cycle detected` in: {msg}",
            );
        }
        other => panic!(
            "expected the cycle to surface as Ok(CommandResult::Err(InvalidArgument(\"cycle detected ...\"))), got {other:?}",
        ),
    }

    // Refcounts back to 0 — both guards released.
    assert_eq!(engine.services().active_call_count(&svc_a), 0);
    assert_eq!(engine.services().active_call_count(&svc_b), 0);

    alpha.stop().await.expect("stop alpha");
    beta.stop().await.expect("stop beta");
}

/// H10: caller-side authorization. Runs the same round-trip as
/// `cross_plugin_call_service_round_trips` but with the caller
/// staged against a manifest that omits `consumes_services`. The
/// dispatcher must refuse with `PermissionDenied` before the callee
/// runs, and `active_call_count` must remain 0.
#[tokio::test(flavor = "multi_thread")]
async fn call_service_without_consumes_services_grant_is_denied() {
    let _counter_wasm = support::build_example("service-counter", "service_counter.wasm");
    let caller_wasm = support::build_example("service-caller", "service_caller.wasm");
    let state_dir = support::tempdir("dispatch-grant-state");
    let engine = oxidhome_core::Engine::with_state_dir(state_dir.path()).expect("engine");

    let counter_dir = support::workspace_root()
        .join("examples")
        .join("service-counter");
    let counter = engine
        .start_instance(counter_dir, "counter", None)
        .await
        .expect("start counter");
    counter.wait_for_running().await.expect("counter Running");
    let target_id = await_service_id(&engine).await;

    // Stage the caller with NO consumes_services grant.
    let staged = support::stage_plugin(
        "svc-caller-no-grant",
        &caller_wasm,
        "service_caller.wasm",
        r#"manifest_version = 1
[plugin]
id = "example.service-caller-no-grant"
name = "Bare Service Caller"
version = "0.1.0"
world = "plugin"
sdk_version = "0.1.0"
[runtime]
wasm = "service_caller.wasm"
[capabilities]
storage_quota_kb = 4
[config.target_service_id]
type = "string"
description = "Target"
"#,
    );

    let overrides: toml::Value =
        toml::from_str(&format!("target_service_id = \"{target_id}\"\n")).expect("overrides parse");
    let caller = engine
        .start_instance(staged.path().to_path_buf(), "caller", Some(overrides))
        .await
        .expect("start caller");

    match caller.wait_terminal().await {
        oxidhome_core::InstanceState::Failed { error } => {
            let lower = error.to_ascii_lowercase();
            assert!(
                lower.contains("consumes_services") && lower.contains("counter"),
                "expected permission-denied naming consumes_services + target, got: {error}",
            );
        }
        other => panic!("expected Failed (grant denies the call), got {other:?}"),
    }

    // Grant check runs before `acquire_call` — refcount never bumped.
    assert_eq!(engine.services().active_call_count(&target_id), 0);

    counter.stop().await.expect("stop counter");
}

/// H10: a caller whose grant lists the target plugin but the wrong
/// *command* is still refused. Uses a staged manifest with
/// `commands = ["get"]` — the caller drives `increment` first, so
/// the first call fails permission-denied.
#[tokio::test(flavor = "multi_thread")]
async fn call_service_with_wrong_command_in_grant_is_denied() {
    let _counter_wasm = support::build_example("service-counter", "service_counter.wasm");
    let caller_wasm = support::build_example("service-caller", "service_caller.wasm");
    let state_dir = support::tempdir("dispatch-wrong-cmd-state");
    let engine = oxidhome_core::Engine::with_state_dir(state_dir.path()).expect("engine");

    let counter_dir = support::workspace_root()
        .join("examples")
        .join("service-counter");
    let counter = engine
        .start_instance(counter_dir, "counter", None)
        .await
        .expect("start counter");
    counter.wait_for_running().await.expect("counter Running");
    let target_id = await_service_id(&engine).await;

    let staged = support::stage_plugin(
        "svc-caller-wrong-cmd",
        &caller_wasm,
        "service_caller.wasm",
        r#"manifest_version = 1
[plugin]
id = "example.service-caller-wrong-cmd"
name = "Wrong-Command Service Caller"
version = "0.1.0"
world = "plugin"
sdk_version = "0.1.0"
[runtime]
wasm = "service_caller.wasm"
[capabilities]
storage_quota_kb = 4
# Grant covers `get` but not `increment` — the caller drives
# `increment` first, so the first hop is refused.
[[capabilities.consumes_services]]
plugin   = "example.service-counter"
instance = "*"
service  = "counter"
commands = ["get"]
[config.target_service_id]
type = "string"
description = "Target"
"#,
    );

    let overrides: toml::Value =
        toml::from_str(&format!("target_service_id = \"{target_id}\"\n")).expect("overrides parse");
    let caller = engine
        .start_instance(staged.path().to_path_buf(), "caller", Some(overrides))
        .await
        .expect("start caller");

    match caller.wait_terminal().await {
        oxidhome_core::InstanceState::Failed { error } => {
            let lower = error.to_ascii_lowercase();
            assert!(
                lower.contains("increment") && lower.contains("consumes_services"),
                "expected permission-denied naming `increment` + grant, got: {error}",
            );
        }
        other => panic!("expected Failed (wrong-command grant), got {other:?}"),
    }

    assert_eq!(engine.services().active_call_count(&target_id), 0);
    counter.stop().await.expect("stop counter");
}

/// H6: an externally-rooted invocation keeps its root principal across
/// the wasm boundary and the supervisor task hop. The test drives
/// driver → alpha (bouncer wasm) → beta (bouncer wasm) under an API
/// root; both hops must land in the audit ledger attributed to the root
/// token, sharing its call id, with the delegation chain growing by one
/// hop each time. The same chain driven host-origin writes no rows.
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::too_many_lines)] // one linear end-to-end narrative
async fn delegated_chain_is_audited_against_external_root() {
    use oxidhome_core::auth::{ActorKind, InvocationContext, Principal, Transport};
    use oxidhome_core::host_impl::plugin::oxidhome::plugin::devices::CommandResult;
    use oxidhome_core::runtime::dispatcher;
    use oxidhome_core::state::AuditQuery;
    use oxidhome_core::{Actor, host_impl::plugin::oxidhome::plugin::types::Value};

    let _wasm = support::build_example("service-bouncer", "service_bouncer.wasm");
    let bouncer_dir = support::workspace_root()
        .join("examples")
        .join("service-bouncer");
    let state_dir = support::tempdir("dispatch-h6-state");
    let engine = Engine::with_state_dir(state_dir.path()).expect("engine");

    let alpha = engine
        .start_instance(bouncer_dir.clone(), "alpha", None)
        .await
        .expect("start alpha");
    alpha.wait_for_running().await.expect("alpha Running");
    let beta = engine
        .start_instance(bouncer_dir, "beta", None)
        .await
        .expect("start beta");
    beta.wait_for_running().await.expect("beta Running");

    let services = engine.services().list();
    let svc_of = |owner: &str| {
        services
            .iter()
            .find(|m| m.owner_instance == owner)
            .expect("service registered")
            .id
            .clone()
    };
    let (svc_a, svc_b) = (svc_of("alpha"), svc_of("beta"));
    // alpha forwards to beta; beta has no `bounce_to` and returns Ok.
    engine
        .kv()
        .set(
            "example.service-bouncer",
            "alpha",
            "bounce_to",
            Value::StringVal(svc_b),
        )
        .expect("set alpha.bounce_to");

    let driver_grants = [oxidhome_manifest::ServiceGrant {
        plugin: "example.service-bouncer".into(),
        instance: "*".into(),
        service: "bouncer".into(),
        commands: vec!["kick".into()],
        caller_instance: "*".into(),
    }];
    let audit = engine.audit_log();

    // Host-origin: same chain, no ledger rows.
    let outcome = dispatcher::call_service_from_host(
        &engine,
        "test-driver",
        &driver_grants,
        &driver_grants,
        svc_a.clone(),
        "kick",
        Vec::new(),
    )
    .await;
    assert!(matches!(outcome, Ok(CommandResult::Ok)), "got {outcome:?}");
    let host_rows: Vec<_> = audit
        .query(&AuditQuery::default(), 50)
        .expect("query")
        .into_iter()
        .filter(|r| r.method == dispatcher::SERVICE_CALL_AUDIT_METHOD)
        .collect();
    assert!(
        host_rows.is_empty(),
        "host-origin hops audited: {host_rows:?}"
    );

    // API-rooted.
    let actor = Actor::api("tok-h6", vec![builtin("admin").unwrap()]);
    let root =
        InvocationContext::external(Principal::token(ActorKind::Api, &actor, Transport::Rest));
    let call_id = root.call_id().to_owned();
    let outcome = dispatcher::call_service_from_host_in(
        &engine,
        root,
        "test-driver",
        &driver_grants,
        &driver_grants,
        svc_a,
        "kick",
        Vec::new(),
    )
    .await;
    assert!(matches!(outcome, Ok(CommandResult::Ok)), "got {outcome:?}");

    // Finalize writes are detached from the caller; wait for both rows
    // to be finalized.
    let started = Instant::now();
    let mut rows = loop {
        let rows = audit
            .query(
                &AuditQuery {
                    call_id: Some(call_id.clone()),
                    ..AuditQuery::default()
                },
                50,
            )
            .expect("query");
        if rows.len() == 2 && rows.iter().all(|r| r.finalized_ms.is_some()) {
            break rows;
        }
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "hop rows not finalized: {rows:?}",
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    rows.sort_by_key(|r| r.id);
    assert_eq!(rows.len(), 2, "one row per hop: {rows:?}");
    for (depth, row) in rows.iter().enumerate() {
        assert_eq!(row.token_id, "tok-h6");
        assert_eq!(row.actor_kind, "api");
        assert_eq!(row.method, dispatcher::SERVICE_CALL_AUDIT_METHOD);
        assert_eq!(row.decision, "allow");
        assert_eq!(row.status, 200);
        assert_eq!(row.execution_outcome.as_deref(), Some("success"));
        assert!(row.finalized_ms.is_some());
        let inv: serde_json::Value =
            serde_json::from_str(row.invocation.as_deref().expect("invocation json"))
                .expect("json");
        assert_eq!(inv["root"]["subject"], "tok-h6");
        assert_eq!(inv["root"]["transport"], "rest");
        assert_eq!(inv["chain"].as_array().unwrap().len(), depth + 1);
    }
    // Outer hop: driver → alpha. Inner hop: alpha's wasm → beta, which
    // only carries the root because the context crossed into alpha's
    // supervisor task and back out through its `call-service` import.
    assert_eq!(
        rows[0].path,
        "service.call/example.service-bouncer/alpha/bouncer/kick"
    );
    assert_eq!(
        rows[1].path,
        "service.call/example.service-bouncer/beta/bouncer/kick"
    );
    let inner: serde_json::Value =
        serde_json::from_str(rows[1].invocation.as_deref().unwrap()).unwrap();
    assert_eq!(inner["chain"][0]["caller"], "test-driver");
    assert_eq!(inner["chain"][1]["caller"], "alpha");
    assert_eq!(inner["current"], "beta");

    alpha.stop().await.expect("stop alpha");
    beta.stop().await.expect("stop beta");
}

/// M2: the dispatcher enforces the counter's declared command
/// schemas before the callee runs. An undeclared command, an
/// undeclared / mistyped / out-of-range argument are all
/// `invalid-argument` and never reach the wasm (the counter's value
/// stays untouched); a well-typed `by` lands and the reply passes the
/// `returns` check.
#[tokio::test(flavor = "multi_thread")]
async fn call_service_args_are_checked_against_the_declared_schema() {
    use oxidhome_core::host_impl::plugin::oxidhome::plugin::devices::CommandResult;
    use oxidhome_core::host_impl::plugin::oxidhome::plugin::types::{
        Error as WitError, KeyValue, Value,
    };
    use oxidhome_core::runtime::dispatcher;
    use oxidhome_core::{
        Actor,
        auth::{ActorKind, InvocationContext, Principal, Transport},
        state::AuditQuery,
    };

    let (engine, counter_dir, _caller_dir, _state) = setup();
    let counter = engine
        .start_instance(counter_dir, "counter", None)
        .await
        .expect("start counter");
    counter.wait_for_running().await.expect("counter Running");
    let target = await_service_id(&engine).await;

    let grants = [oxidhome_manifest::ServiceGrant {
        plugin: "example.service-counter".into(),
        instance: "*".into(),
        service: "counter".into(),
        commands: vec!["*".into()],
        caller_instance: "*".into(),
    }];
    let call = |command: &'static str, args: Vec<KeyValue>| {
        dispatcher::call_service_from_host(
            &engine,
            "test-driver",
            &grants,
            &grants,
            target.clone(),
            command,
            args,
        )
    };
    let by = |value: Value| {
        vec![KeyValue {
            key: "by".into(),
            value,
        }]
    };

    for (command, args, needle) in [
        ("reset", Vec::new(), "declares no command \"reset\""),
        ("increment", by(Value::StringVal("2".into())), "`int-val`"),
        ("increment", by(Value::IntVal(0)), "expected 1..=1000"),
        (
            "get",
            vec![KeyValue {
                key: "extra".into(),
                value: Value::BoolVal(true),
            }],
            "not declared",
        ),
    ] {
        match call(command, args).await {
            Err(WitError::InvalidArgument(msg)) => {
                assert!(msg.contains(needle), "`{command}`: {msg}");
            }
            other => panic!("`{command}` should be invalid-argument, got {other:?}"),
        }
    }

    // H6 × M2: under an external root, a schema refusal is not an
    // authorization decision and the callee never runs, so it writes
    // no hop row (only grant refusals become `deny` rows).
    let actor = Actor::api("tok-m2", vec![builtin("admin").unwrap()]);
    let root =
        InvocationContext::external(Principal::token(ActorKind::Api, &actor, Transport::Rest));
    let call_id = root.call_id().to_owned();
    let outcome = dispatcher::call_service_from_host_in(
        &engine,
        root,
        "test-driver",
        &grants,
        &grants,
        target.clone(),
        "increment",
        by(Value::IntVal(0)),
    )
    .await;
    assert!(
        matches!(outcome, Err(WitError::InvalidArgument(_))),
        "got {outcome:?}"
    );
    let rows = engine
        .audit_log()
        .query(
            &AuditQuery {
                call_id: Some(call_id),
                ..AuditQuery::default()
            },
            50,
        )
        .expect("query");
    assert_eq!(rows.len(), 0, "schema refusal audited: {rows:?}");

    match call("increment", by(Value::IntVal(5))).await {
        Ok(CommandResult::OkWithState(fields)) => assert!(
            matches!(fields.as_slice(), [KeyValue { key, value: Value::IntVal(5) }] if key == "value"),
            "refused calls must not have reached the counter: {fields:?}",
        ),
        other => panic!("well-typed increment should succeed, got {other:?}"),
    }

    counter.stop().await.expect("stop counter");
}
