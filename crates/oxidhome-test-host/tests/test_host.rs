//! Harness-specific behavior the conformance suite doesn't cover:
//! grant injection, instance-id bookkeeping, teardown on drop, and the
//! assertion helpers' edge cases.

#[path = "support.rs"]
mod support;

use oxidhome_core::state::StateQuality;
use oxidhome_manifest::ServiceGrant;
use oxidhome_test_host::wit::devices::{Command, CommandResult};
use oxidhome_test_host::wit::events::EventPayload;
use oxidhome_test_host::wit::types::Value;
use oxidhome_test_host::{CapabilitiesSection, InitError, LoadOptions, TestHost, TestHostError};
use support::{HELLO_WORLD, KV_COUNTER, SIMULATED_SWITCH, stage, stage_unchanged};

fn toggle() -> Command {
    Command {
        capability: "switch".into(),
        action: "toggle".into(),
        args: Vec::new(),
    }
}

/// An injected grant that withholds the storage quota denies storage
/// exactly as a manifest without the quota does (see the conformance
/// suite's `storage_needs_quota`), and the full request still works.
#[tokio::test(flavor = "current_thread")]
async fn injected_grant_narrows_capabilities() {
    let staged = stage_unchanged(KV_COUNTER);
    let host = TestHost::new().unwrap();

    let mut denied = host
        .load_with(
            staged.path(),
            LoadOptions::new().grant(CapabilitiesSection::default()),
        )
        .await
        .unwrap();
    match denied.init().await {
        Err(TestHostError::Init(InitError::Plugin(msg))) => {
            assert!(msg.contains("PermissionDenied"), "{msg}");
        }
        other => panic!("expected a permission-denied init failure, got {other:?}"),
    }

    let full = denied.manifest().capabilities.clone();
    let mut allowed = host
        .load_with(staged.path(), LoadOptions::new().grant(full))
        .await
        .unwrap();
    allowed.init().await.unwrap();
    allowed.tick().await.unwrap();
    assert!(matches!(
        allowed.storage().get("count").unwrap(),
        Some(Value::IntVal(1))
    ));
}

/// A grant asking for more than the manifest requests is refused
/// before anything loads.
#[tokio::test(flavor = "current_thread")]
async fn grant_wider_than_request_is_refused() {
    let staged = stage_unchanged(HELLO_WORLD);
    let host = TestHost::new().unwrap();
    let grant = CapabilitiesSection {
        storage_quota_kb: 4,
        subscribes_events: true,
        ..CapabilitiesSection::default()
    };
    let err = host
        .load_with(staged.path(), LoadOptions::new().grant(grant))
        .await
        .err()
        .expect("wider grant must be refused");
    let TestHostError::GrantExceedsRequest { plugin_id, excess } = &err else {
        panic!("expected GrantExceedsRequest, got {err:?}");
    };
    assert_eq!(plugin_id, "example.hello-world");
    assert_eq!(excess.len(), 2, "{excess:?}");
    assert!(err.to_string().contains("storage_quota_kb"), "{err}");
}

/// A grant within the request but over the capability-count caps is
/// rejected by the production grant validator in the core loader.
#[tokio::test(flavor = "current_thread")]
async fn grant_over_capability_limits_is_refused_by_core() {
    let entry = ServiceGrant {
        plugin: "example.service-counter".into(),
        instance: "*".into(),
        service: "counter".into(),
        commands: vec!["get".into()],
        caller_instance: "*".into(),
    };
    let staged = stage(HELLO_WORLD, |caps| {
        let entry = toml::Value::try_from(&entry).unwrap();
        caps.insert("consumes_services".into(), toml::Value::Array(vec![entry]));
    });
    let host = TestHost::new().unwrap();
    let grant = CapabilitiesSection {
        consumes_services: vec![
            entry;
            oxidhome_manifest::validate::MAX_CONSUMES_SERVICES_GRANTS + 1
        ],
        ..CapabilitiesSection::default()
    };
    let err = host
        .load_with(staged.path(), LoadOptions::new().grant(grant))
        .await
        .err()
        .expect("grant over the caps must be refused");
    let TestHostError::Load { source, .. } = &err else {
        panic!("expected Load, got {err:?}");
    };
    assert!(source.to_string().contains("consumes_services"), "{source}");
}

/// Neither a granted nor a plain dev load may shadow an installed
/// package with the same plugin id.
#[tokio::test(flavor = "current_thread")]
async fn loads_never_shadow_an_installed_plugin() {
    let staged = stage_unchanged(HELLO_WORLD);
    let host = TestHost::new().unwrap();
    host.engine()
        .installed_plugins()
        .install(staged.path())
        .unwrap();

    for options in [
        LoadOptions::new().grant(CapabilitiesSection::default()),
        LoadOptions::new(),
    ] {
        let err = host
            .load_with(staged.path(), options)
            .await
            .err()
            .expect("shadowing load must be refused");
        let TestHostError::Load { source, .. } = &err else {
            panic!("expected Load, got {err:?}");
        };
        assert!(source.to_string().contains("installed"), "{source}");
    }
}

#[tokio::test(flavor = "current_thread")]
async fn instance_ids_are_validated_and_unique() {
    let staged = stage_unchanged(HELLO_WORLD);
    let host = TestHost::new().unwrap();

    for bad in ["*", "", "a/b", "..x"] {
        let err = host
            .load_with(staged.path(), LoadOptions::new().instance_id(bad))
            .await
            .err()
            .expect("bad id must be refused");
        assert!(
            matches!(&err, TestHostError::InvalidInstanceId(id) if id == bad),
            "{err:?}"
        );
    }

    let first = host
        .load_with(staged.path(), LoadOptions::new().instance_id("hello"))
        .await
        .unwrap();
    let err = host
        .load_with(staged.path(), LoadOptions::new().instance_id("hello"))
        .await
        .err()
        .expect("duplicate id must be refused");
    assert!(
        matches!(err, TestHostError::DuplicateInstanceId(_)),
        "{err:?}"
    );
    drop(first);
    host.load_with(staged.path(), LoadOptions::new().instance_id("hello"))
        .await
        .expect("id is free again after drop");

    // Generated ids are distinct and skip ids a caller chose.
    let taken = host
        .load_with(staged.path(), LoadOptions::new().instance_id("test-1"))
        .await
        .unwrap();
    let a = host.load(staged.path()).await.unwrap();
    let b = host.load(staged.path()).await.unwrap();
    assert_ne!(a.instance_id(), taken.instance_id());
    assert_ne!(a.instance_id(), b.instance_id());

    // A failed load releases its id.
    let empty = support::TempDir::new("no-manifest");
    let err = host
        .load_with(empty.path(), LoadOptions::new().instance_id("x"))
        .await
        .err()
        .expect("missing manifest");
    assert!(matches!(err, TestHostError::Manifest { .. }), "{err:?}");
    let bad_config: toml::Value = toml::from_str("nope = 1").unwrap();
    let err = host
        .load_with(
            staged.path(),
            LoadOptions::new().instance_id("x").config(bad_config),
        )
        .await
        .err()
        .expect("unknown config key");
    assert!(matches!(err, TestHostError::Load { .. }), "{err:?}");
    host.load_with(staged.path(), LoadOptions::new().instance_id("x"))
        .await
        .expect("failed loads don't leak the id");
}

/// Dropping an instance without `shutdown` still runs the host-side
/// teardown, as the supervisor does for a crashed instance.
#[tokio::test(flavor = "current_thread")]
async fn drop_runs_host_teardown() {
    let staged = stage_unchanged(SIMULATED_SWITCH);
    let host = TestHost::new().unwrap();
    let mut switch = host.load(staged.path()).await.unwrap();
    switch.init().await.unwrap();
    let device = switch.devices()[0].id.clone();
    drop(switch);

    assert!(host.engine().devices().list().is_empty());
    let state = host
        .engine()
        .device_state()
        .snapshot_capability(&device, "switch")
        .unwrap();
    assert_eq!(state.quality, StateQuality::Stale);
}

#[tokio::test(flavor = "current_thread")]
async fn events_are_oldest_first_and_storage_lists_keys() {
    let staged = stage_unchanged(SIMULATED_SWITCH);
    let host = TestHost::new().unwrap();
    let mut switch = host.load(staged.path()).await.unwrap();
    switch.init().await.unwrap();
    assert!(switch.events().unwrap().is_empty());
    let device = switch.devices()[0].id.clone();
    for _ in 0..3 {
        let reply = switch.send_command(device.clone(), toggle()).await.unwrap();
        assert!(matches!(reply, CommandResult::OkWithState(_)), "{reply:?}");
    }
    let states: Vec<bool> = switch
        .events()
        .unwrap()
        .into_iter()
        .map(|e| match e.payload {
            EventPayload::StateChanged(sc) => matches!(sc.fields[0].value, Value::BoolVal(true)),
            other => panic!("unexpected payload {other:?}"),
        })
        .collect();
    assert_eq!(states, [true, false, true]);
    assert_eq!(switch.deliver_pending_events().await.unwrap(), 0);
    switch.shutdown().await.unwrap();

    let staged = stage_unchanged(KV_COUNTER);
    let mut counter = host.load(staged.path()).await.unwrap();
    counter.init().await.unwrap();
    assert!(counter.storage().keys("").unwrap().is_empty());
    counter.tick().await.unwrap();
    assert_eq!(counter.storage().keys("").unwrap(), ["count"]);
    assert!(counter.storage().keys("x").unwrap().is_empty());
    assert!(host.state_dir().join("oxidhome.db").is_file());
}

/// An instance keeps the host's state directory alive after the host
/// itself is gone; the directory goes with the last handle.
#[tokio::test(flavor = "current_thread")]
async fn instance_outlives_its_host() {
    let staged = stage_unchanged(KV_COUNTER);
    let (mut counter, state_dir) = {
        let host = TestHost::new().unwrap();
        let counter = host.load(staged.path()).await.unwrap();
        (counter, host.state_dir().to_path_buf())
    };
    assert!(state_dir.is_dir());
    counter.init().await.unwrap();
    counter.tick().await.unwrap();
    let storage = counter.storage();
    drop(counter);
    assert!(matches!(
        storage.get("count").unwrap(),
        Some(Value::IntVal(1))
    ));
    drop(storage);
    assert!(!state_dir.exists());
}
