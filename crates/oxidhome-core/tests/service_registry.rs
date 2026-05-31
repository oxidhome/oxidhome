//! Phase 7b — service registry + lifecycle (no dispatch yet).
//!
//! Drives the `service-counter` example through `init` and asserts the
//! host's `ServiceRegistry` sees the registered service with the right
//! owner + commands. Also checks the capability gate: a plugin whose
//! manifest doesn't declare the service name is refused at
//! `register-service`. Cross-plugin `call-service` dispatch is Phase 7c.

#[path = "support.rs"]
mod support;

use oxidhome_core::{Engine, InstanceState, PluginInstance};

/// A loaded `service-counter` registers its `counter` service, and the
/// engine's `ServiceRegistry` reflects it (owner + declared commands).
#[tokio::test(flavor = "multi_thread")]
async fn registered_service_is_visible_in_registry() {
    let _wasm = support::build_example("service-counter", "service_counter.wasm");
    let plugin_dir = support::workspace_root()
        .join("examples")
        .join("service-counter");
    let engine = Engine::new().expect("engine");

    let mut instance = PluginInstance::load(&engine, &plugin_dir, "service_counter")
        .await
        .expect("load");
    instance.init().await.expect("init registers the service");

    let services = engine.services().list().await;
    assert_eq!(services.len(), 1, "expected one service, got {services:?}");
    let svc = &services[0];
    assert_eq!(svc.owner_instance, "service_counter");
    assert_eq!(svc.info.name, "counter");
    let commands: Vec<&str> = svc.info.commands.iter().map(|c| c.name.as_str()).collect();
    assert!(commands.contains(&"increment"), "got {commands:?}");
    assert!(commands.contains(&"get"), "got {commands:?}");

    instance.shutdown().await.expect("shutdown");
}

/// `register-service` is gated by `[capabilities] declares_services`:
/// the same wasm loaded against a manifest that doesn't declare
/// `counter` is refused with `permission-denied`, surfacing through the
/// guest's `init` Result.
#[tokio::test(flavor = "multi_thread")]
async fn undeclared_service_register_is_denied() {
    let wasm = support::build_example("service-counter", "service_counter.wasm");
    // Stage the same wasm with an empty `[capabilities]` (no
    // declares_services) so the host's gate refuses the registration.
    let plugin = support::stage_plugin(
        "svc-undeclared",
        &wasm,
        "service_counter.wasm",
        r#"manifest_version = 1
[plugin]
id = "example.service-counter-bare"
name = "Bare Service Counter"
version = "0.1.0"
world = "plugin"
sdk_version = "0.1.0"
[runtime]
wasm = "service_counter.wasm"
[capabilities]
"#,
    );
    let engine = Engine::new().expect("engine");

    let mut instance = PluginInstance::load(&engine, plugin.path(), "svc_bare")
        .await
        .expect("load (instantiation must succeed)");
    let err = match instance.init().await {
        Ok(()) => panic!("init should fail when the service isn't declared"),
        Err(e) => e,
    };
    let msg = format!("{err:#}").to_ascii_lowercase();
    assert!(
        msg.contains("permission") && msg.contains("counter"),
        "expected a permission-denied mentioning the service, got: {msg}",
    );
    // Nothing landed in the registry.
    assert!(engine.services().list().await.is_empty());
}

/// A supervised instance's services are reaped when it reaches a
/// terminal state — without this the registry leaks across stop /
/// crash-restart cycles, and Phase-7c routing would dispatch to stale
/// `svc-N` entries from a previous life.
#[tokio::test(flavor = "multi_thread")]
async fn services_are_reaped_on_terminal_state() {
    let _wasm = support::build_example("service-counter", "service_counter.wasm");
    let plugin_dir = support::workspace_root()
        .join("examples")
        .join("service-counter");
    let engine = Engine::new().expect("engine");

    let handle = engine
        .start_instance(plugin_dir, "service_counter", None)
        .await
        .expect("start_instance");
    handle.wait_for_running().await.expect("reach Running");
    assert_eq!(
        engine.services().list().await.len(),
        1,
        "service is registered while the instance is Running",
    );

    handle.stop().await.expect("stop");
    assert_eq!(handle.wait_terminal().await, InstanceState::Stopped);

    // The reaper runs in a separate spawned task — poll until the
    // sweep completes rather than racing it. (Same shape as the
    // Phase-6 `wait_until_unregistered` helper.)
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        if engine.services().list().await.is_empty() {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "services not reaped within 5s of terminal",
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

/// `remove_by_owner` is the building block — verify it directly so a
/// future refactor can't silently regress the scope (e.g. wipe the
/// whole map). Owner-other entries must survive.
#[tokio::test(flavor = "current_thread")]
async fn remove_by_owner_scopes_to_one_instance() {
    use oxidhome_core::host_impl::plugin::oxidhome::plugin::services::ServiceInfo;
    use oxidhome_core::state::ServiceRegistry;

    let reg = ServiceRegistry::new();
    let info = |n: &str| ServiceInfo {
        local_id: n.into(),
        name: n.into(),
        metadata: Vec::new(),
        commands: Vec::new(),
    };
    let _a1 = reg.register("alpha".into(), info("counter-a1")).await;
    let _a2 = reg.register("alpha".into(), info("counter-a2")).await;
    let _b1 = reg.register("beta".into(), info("counter-b1")).await;
    assert_eq!(reg.list().await.len(), 3);

    let removed = reg.remove_by_owner("alpha").await;
    assert_eq!(removed, 2, "expected two alpha services dropped");

    let remaining: Vec<String> = reg
        .list()
        .await
        .into_iter()
        .map(|m| m.owner_instance)
        .collect();
    assert_eq!(remaining, vec!["beta".to_string()]);

    // Idempotent — a second sweep finds nothing.
    assert_eq!(reg.remove_by_owner("alpha").await, 0);
}
