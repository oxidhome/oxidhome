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
use support::{EVENT_RECORDER, HELLO_WORLD, KV_COUNTER, SIMULATED_SWITCH, stage, stage_unchanged};

fn toggle() -> Command {
    Command {
        id: "cmd-test".into(),
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
    assert_eq!(counter.storage().keys("").unwrap(), Vec::<String>::new());
    counter.tick().await.unwrap();
    assert_eq!(counter.storage().keys("").unwrap(), ["count"]);
    assert_eq!(counter.storage().keys("x").unwrap(), Vec::<String>::new());
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

/// Dropping a `load_with` future mid-load frees its instance id (and
/// tears down anything filed under it) just like a failed load.
#[tokio::test(flavor = "current_thread")]
async fn cancelled_load_releases_its_id() {
    let staged = stage_unchanged(SIMULATED_SWITCH);
    let host = TestHost::new().unwrap();
    let load = host.load_with(staged.path(), LoadOptions::new().instance_id("switch"));
    // A zero timeout polls the load once and then drops it.
    if let Ok(result) = tokio::time::timeout(std::time::Duration::ZERO, load).await {
        // The load finished on its first poll; nothing was cancelled.
        drop(result.unwrap());
    }
    let mut switch = host
        .load_with(staged.path(), LoadOptions::new().instance_id("switch"))
        .await
        .expect("id is free after the cancelled load");
    switch.init().await.unwrap();
    assert_eq!(switch.devices().len(), 1);
}

fn read_state(device: &str) -> Command {
    Command {
        id: "cmd-read".into(),
        capability: "recorder".into(),
        action: "read-state".into(),
        args: vec![oxidhome_test_host::wit::types::KeyValue {
            key: "device".into(),
            value: Value::StringVal(device.into()),
        }],
    }
}

/// H2: a plugin reads another plugin's device state through
/// `host-state` only with a matching `reads_state` grant; a refused
/// read is the same `not-found` as for an unknown device (plus an
/// operator-side audit `deny` row), and `list-state` leaves the
/// device out.
#[tokio::test(flavor = "current_thread")]
#[allow(clippy::too_many_lines)]
async fn plugin_reads_device_state_only_with_a_grant() {
    use oxidhome_test_host::SnapshotOptions;
    use oxidhome_test_host::wit::types::Error as WitError;

    let host = TestHost::new().unwrap();
    let switch_dir = stage_unchanged(SIMULATED_SWITCH);
    let mut switch = host.load(switch_dir.path()).await.unwrap();
    switch.init().await.unwrap();
    let device = switch.devices()[0].id.clone();
    let list = || Command {
        id: "cmd-list".into(),
        capability: "recorder".into(),
        action: "list-state".into(),
        args: Vec::new(),
    };
    let int_field = |result: CommandResult, key: &str| match result {
        CommandResult::OkWithState(fields) => fields
            .into_iter()
            .find(|kv| kv.key == key)
            .map(|kv| kv.value),
        other => panic!("expected ok-with-state, got {other:?}"),
    };

    let plain = stage_unchanged(EVENT_RECORDER);
    let mut denied = host
        .load_with(plain.path(), LoadOptions::new().instance_id("denied"))
        .await
        .unwrap();
    denied.init().await.unwrap();
    // An invisible device and an unknown one get the same answer, so
    // the plugin can't probe which ids exist.
    let hidden = match denied.send_command("", read_state(&device)).await.unwrap() {
        CommandResult::Err(WitError::NotFound(msg)) => msg,
        other => panic!("expected not-found, got {other:?}"),
    };
    let unknown_id = "dev-00000000000000000000";
    let unknown = match denied
        .send_command("", read_state(unknown_id))
        .await
        .unwrap()
    {
        CommandResult::Err(WitError::NotFound(msg)) => msg,
        other => panic!("expected not-found, got {other:?}"),
    };
    assert_eq!(
        hidden.replace(device.as_str(), "<id>"),
        unknown.replace(unknown_id, "<id>"),
        "the two refusals must be indistinguishable",
    );
    assert!(hidden.contains("reads_state"), "{hidden}");
    assert!(matches!(
        int_field(denied.send_command("", list()).await.unwrap(), "entries"),
        Some(Value::IntVal(0))
    ));
    // The operator still gets a deny row for the hidden device, and
    // none for the unknown one. The row is written in the background;
    // the audit snapshot waits for it.
    denied
        .snapshot_with(&SnapshotOptions::new().audit())
        .unwrap()
        .assert_matches(&format!(
            "
            devices:
            services:
            events:
            storage:
              cursor = json:\"0\"
            blobs:
            audit:
              deny 403 STATE device.state/denied/{device} scope=reads_state
            "
        ));

    let granted = stage(EVENT_RECORDER, |caps| {
        let grant: toml::Table =
            toml::from_str("plugin = \"example.simulated-switch\"\ncapabilities = [\"switch\"]")
                .unwrap();
        caps.insert(
            "reads_state".into(),
            toml::Value::Array(vec![toml::Value::Table(grant)]),
        );
    });
    let mut reader = host
        .load_with(granted.path(), LoadOptions::new().instance_id("reader"))
        .await
        .unwrap();
    reader.init().await.unwrap();
    let fields = match reader.send_command("", read_state(&device)).await.unwrap() {
        CommandResult::OkWithState(fields) => fields,
        other => panic!("expected the switch state, got {other:?}"),
    };
    assert!(
        fields.iter().any(|kv| kv.key == "switch.quality"
            && matches!(&kv.value, Value::StringVal(q) if q == "fresh")),
        "{fields:?}"
    );
    assert!(
        fields
            .iter()
            .any(|kv| kv.key.starts_with("switch.") && kv.key != "switch.quality")
    );
    assert!(matches!(
        int_field(reader.send_command("", list()).await.unwrap(), "entries"),
        Some(Value::IntVal(1))
    ));

    // Once the owner is gone the value is still readable, as stale.
    drop(switch);
    let fields = match reader.send_command("", read_state(&device)).await.unwrap() {
        CommandResult::OkWithState(fields) => fields,
        other => panic!("expected the stale switch state, got {other:?}"),
    };
    assert!(
        fields.iter().any(|kv| kv.key == "switch.quality"
            && matches!(&kv.value, Value::StringVal(q) if q == "stale"))
    );
}

fn recorder(action: &str, args: Vec<(&str, Value)>) -> Command {
    Command {
        id: "cmd-recorder".into(),
        capability: "recorder".into(),
        action: action.into(),
        args: args
            .into_iter()
            .map(|(key, value)| oxidhome_test_host::wit::types::KeyValue {
                key: key.into(),
                value,
            })
            .collect(),
    }
}

/// Run a `recorder` command and return its fields by key.
async fn recorder_fields(
    instance: &mut oxidhome_test_host::TestPluginInstance,
    action: &str,
    args: Vec<(&str, Value)>,
) -> std::collections::HashMap<String, Value> {
    match instance
        .send_command("", recorder(action, args))
        .await
        .unwrap()
    {
        CommandResult::OkWithState(fields) => {
            fields.into_iter().map(|kv| (kv.key, kv.value)).collect()
        }
        other => panic!("recorder::{action} failed: {other:?}"),
    }
}

fn int_of(fields: &std::collections::HashMap<String, Value>, key: &str) -> i64 {
    match fields.get(key) {
        Some(Value::IntVal(n)) => *n,
        other => panic!("{key}: {other:?}"),
    }
}

fn ids_of(fields: &std::collections::HashMap<String, Value>) -> String {
    match fields.get("ids") {
        Some(Value::StringVal(ids)) => ids.clone(),
        other => panic!("ids: {other:?}"),
    }
}

/// `host-events::read-events`: the recorder catches up on events
/// recorded while it was stopped (resuming from the cursor it keeps in
/// KV), skips live duplicates, sees only rows its subscriptions match,
/// gets bytes withheld without `reads_event_bytes`, and starts over
/// from the head when its cursor expired.
#[tokio::test(flavor = "current_thread")]
#[allow(clippy::too_many_lines)]
async fn plugin_reads_event_history_from_its_cursor() {
    use oxidhome_test_host::wit::events::{CustomEvent, Event, StateChange};
    use oxidhome_test_host::wit::types::KeyValue;

    let host = TestHost::new().unwrap();
    let log = host.engine().event_log();
    let custom = |topic: &str| Event {
        device: None,
        timestamp: 0,
        origin_plugin_id: "test.publisher".into(),
        origin_instance_id: "publisher".into(),
        row_id: None,
        call_id: None,
        payload: EventPayload::Custom(CustomEvent {
            topic: topic.into(),
            payload: "{}".into(),
        }),
    };
    let record = |ev: Event| {
        log.record(1, &ev, &ev.origin_instance_id, &ev.origin_plugin_id)
            .unwrap()
    };
    record(custom("a.one"));
    record(custom("b.one"));
    record(custom("a.two"));
    record(Event {
        device: Some("dev-cam".into()),
        payload: EventPayload::StateChanged(StateChange {
            capability: "camera".into(),
            fields: vec![KeyValue {
                key: "frame".into(),
                value: Value::BytesVal(vec![1, 2, 3]),
            }],
        }),
        ..custom("")
    });

    let staged = stage_unchanged(EVENT_RECORDER);
    let load = || async {
        let mut rec = host
            .load_with(staged.path(), LoadOptions::new().instance_id("rec"))
            .await
            .unwrap();
        rec.init().await.unwrap();
        rec
    };

    // First start: the whole history.
    let mut rec = load().await;
    let history = recorder_fields(&mut rec, "history", Vec::new()).await;
    assert_eq!(int_of(&history, "caught_up"), 4);
    assert_eq!(int_of(&history, "cursor"), 4);
    let page = recorder_fields(&mut rec, "read-events", Vec::new()).await;
    assert_eq!(ids_of(&page), "1,2,3,4");
    assert_eq!((int_of(&page, "bytes"), int_of(&page, "withheld")), (0, 1));
    assert_eq!(int_of(&page, "next_after_id"), int_of(&page, "head_id"));
    let page = recorder_fields(
        &mut rec,
        "read-events",
        vec![("after", Value::IntVal(1)), ("limit", Value::IntVal(2))],
    )
    .await;
    assert_eq!(ids_of(&page), "2,3");
    assert_eq!(int_of(&page, "next_after_id"), 3);

    // Narrower subscription, narrower history; the cursor still moves
    // past the rows it skipped.
    recorder_fields(
        &mut rec,
        "resubscribe",
        vec![("topic", Value::StringVal("a.".into()))],
    )
    .await;
    let page = recorder_fields(&mut rec, "read-events", Vec::new()).await;
    assert_eq!(ids_of(&page), "1,3");
    assert_eq!(int_of(&page, "next_after_id"), 4);
    drop(rec);

    // Events recorded while stopped are caught up after a restart.
    record(custom("a.three"));
    record(custom("c.one"));
    let mut rec = load().await;
    let history = recorder_fields(&mut rec, "history", Vec::new()).await;
    assert_eq!(int_of(&history, "caught_up"), 2);
    assert_eq!(int_of(&history, "cursor"), 6);
    // A live event at or below the cursor is a duplicate.
    host.engine()
        .events()
        .publish_with_id(custom("a.three"), Some(5));
    assert_eq!(rec.deliver_pending_events().await.unwrap(), 1);
    let history = recorder_fields(&mut rec, "history", Vec::new()).await;
    assert_eq!(int_of(&history, "duplicates"), 1);
    // Events reaching two subscriptions' queues arrive in row-id
    // order, so the cursor doesn't drop the older one.
    recorder_fields(
        &mut rec,
        "resubscribe",
        vec![("topic", Value::StringVal("x.".into()))],
    )
    .await;
    recorder_fields(
        &mut rec,
        "subscribe",
        vec![("topic", Value::StringVal("y.".into()))],
    )
    .await;
    let y = record(custom("y.1"));
    let x = record(custom("x.1"));
    host.engine()
        .events()
        .publish_with_id(custom("y.1"), Some(y));
    host.engine()
        .events()
        .publish_with_id(custom("x.1"), Some(x));
    assert_eq!(rec.deliver_pending_events().await.unwrap(), 2);
    let history = recorder_fields(&mut rec, "history", Vec::new()).await;
    assert_eq!(int_of(&history, "duplicates"), 1);
    assert_eq!(int_of(&history, "cursor"), 8);
    drop(rec);

    // Retention pruned the rows after the saved cursor: the recorder
    // reports the expiry and resumes from the head.
    record(custom("d.one"));
    log.trim_older_than(i64::MAX).unwrap();
    let mut rec = load().await;
    let history = recorder_fields(&mut rec, "history", Vec::new()).await;
    assert!(matches!(history.get("expired"), Some(Value::BoolVal(true))));
    assert_eq!(int_of(&history, "caught_up"), 0);
    assert_eq!(int_of(&history, "cursor"), 9);
    let expired = recorder_fields(&mut rec, "read-events", vec![("after", Value::IntVal(2))]).await;
    assert_eq!(int_of(&expired, "expired_head_id"), 9);
    drop(rec);

    // With `reads_event_bytes` the frame comes back as written.
    let bytes = stage(EVENT_RECORDER, |caps| {
        caps.insert("reads_event_bytes".into(), toml::Value::Boolean(true));
    });
    record(Event {
        device: Some("dev-cam".into()),
        payload: EventPayload::StateChanged(StateChange {
            capability: "camera".into(),
            fields: vec![KeyValue {
                key: "frame".into(),
                value: Value::BytesVal(vec![4, 5]),
            }],
        }),
        ..custom("")
    });
    let mut reader = host
        .load_with(bytes.path(), LoadOptions::new().instance_id("bytes"))
        .await
        .unwrap();
    reader.init().await.unwrap();
    let page = recorder_fields(
        &mut reader,
        "read-events",
        vec![("after", Value::IntVal(9))],
    )
    .await;
    assert_eq!(ids_of(&page), "10");
    assert_eq!((int_of(&page, "bytes"), int_of(&page, "withheld")), (1, 0));
    let mut grant = reader.manifest().capabilities.clone();
    drop(reader);

    // Requested but not granted: still withheld.
    grant.reads_event_bytes = false;
    let mut narrowed = host
        .load_with(
            bytes.path(),
            LoadOptions::new().instance_id("narrowed").grant(grant),
        )
        .await
        .unwrap();
    narrowed.init().await.unwrap();
    let page = recorder_fields(
        &mut narrowed,
        "read-events",
        vec![("after", Value::IntVal(9))],
    )
    .await;
    assert_eq!((int_of(&page, "bytes"), int_of(&page, "withheld")), (0, 1));
}
