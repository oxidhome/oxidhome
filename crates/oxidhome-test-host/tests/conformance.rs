//! Host-interface conformance suite (architecture review M5).
//!
//! Every scenario below runs twice, against two backends:
//!
//! - [`Production`] — the daemon's path for an installed plugin:
//!   `Engine::with_state_dir`, `InstalledPluginRegistry::install`
//!   (which persists the grant and content digest), and
//!   `PluginInstance::load_with_mode(LoadMode::Installed)`, observed
//!   through the engine's own stores.
//! - [`Harness`] — `oxidhome_test_host::TestHost`, driven and observed
//!   only through the harness's public API.
//!
//! Both backends receive the same staged plugin directory, so any
//! observable difference between "what a test sees" and "what the
//! daemon does" fails here. New host interfaces get a scenario here
//! when the harness starts covering them.
//!
//! Each scenario is a generic `async fn` over [`Backend`]; the
//! `conformance!` macro at the bottom instantiates it once per backend.

#[path = "support.rs"]
mod support;

use std::path::Path;

use oxidhome_core::runtime::LoadMode;
use oxidhome_core::state::{EventQuery, StateQuality};
use oxidhome_core::{Engine, InitError, PluginInstance};
use oxidhome_test_host::wit::devices::{Command, CommandResult};
use oxidhome_test_host::wit::events::{CustomEvent, Event, EventPayload};
use oxidhome_test_host::wit::types::{KeyValue, Value};
use oxidhome_test_host::{LoadOptions, TestHost, TestHostError, TestPluginInstance};
use support::{EVENT_RECORDER, KV_COUNTER, SIMULATED_SWITCH, TempDir, stage, stage_unchanged};

// ---------------------------------------------------------------------
// Backend abstraction
// ---------------------------------------------------------------------

/// How a plugin's `init` ended, normalized across backends.
#[derive(Debug, PartialEq)]
enum InitOutcome {
    Ok,
    /// The plugin returned `Err(message)`.
    Plugin(String),
    Trap,
    Unresponsive,
}

impl From<Result<(), InitError>> for InitOutcome {
    fn from(r: Result<(), InitError>) -> Self {
        match r {
            Ok(()) => Self::Ok,
            Err(InitError::Plugin(msg)) => Self::Plugin(msg),
            Err(InitError::Trap(_)) => Self::Trap,
            Err(InitError::Unresponsive(_)) => Self::Unresponsive,
        }
    }
}

/// A device as observed from outside the plugin.
#[derive(Debug, PartialEq)]
struct ObservedDevice {
    id: String,
    local_id: String,
    capabilities: usize,
}

/// A published event as observed in the host's history.
#[derive(Debug)]
struct ObservedEvent {
    topic: String,
    device: Option<String>,
    plugin_id: String,
    instance_id: String,
    payload: EventPayload,
}

/// One way of hosting a plugin.
trait Backend {
    type Instance: Driver;

    fn new() -> Self;

    /// Load the plugin staged in `dir` under `instance_id`.
    async fn load(
        &mut self,
        dir: &Path,
        instance_id: &str,
        config: Option<toml::Value>,
    ) -> Result<Self::Instance, String>;

    /// The engine whose stores back this backend, for observations
    /// that aren't per-instance (device-state projection).
    fn engine(&self) -> &Engine;
}

/// Driving and observing one loaded instance.
trait Driver {
    async fn init(&mut self) -> InitOutcome;
    async fn tick(&mut self);
    async fn command(&mut self, device: &str, capability: &str, action: &str) -> CommandResult;
    /// Publish `event` on the bus and deliver pending events to the
    /// plugin; returns how many it received.
    async fn deliver(&mut self, event: Event) -> usize;
    async fn shutdown(self);
    fn devices(&self) -> Vec<ObservedDevice>;
    fn events(&self) -> Vec<ObservedEvent>;
    fn storage(&self, key: &str) -> Option<Value>;
}

fn command(capability: &str, action: &str) -> Command {
    Command {
        id: "cmd-test".into(),
        capability: capability.into(),
        action: action.into(),
        args: Vec::new(),
    }
}

// --- production -------------------------------------------------------

/// The daemon's install-then-load path, observed via the engine.
struct Production {
    // Drop order: engine before its state dir.
    engine: Engine,
    _state: TempDir,
}

struct ProductionInstance {
    engine: Engine,
    inner: PluginInstance,
}

impl Backend for Production {
    type Instance = ProductionInstance;

    fn new() -> Self {
        let state = TempDir::new("prod-state");
        let engine = Engine::with_state_dir(state.path()).expect("engine");
        Self {
            engine,
            _state: state,
        }
    }

    async fn load(
        &mut self,
        dir: &Path,
        instance_id: &str,
        config: Option<toml::Value>,
    ) -> Result<ProductionInstance, String> {
        let manifest: toml::Table =
            toml::from_str(&std::fs::read_to_string(dir.join("manifest.toml")).unwrap()).unwrap();
        let plugin_id = manifest["plugin"]["id"].as_str().unwrap().to_owned();
        let registry = self.engine.installed_plugins();
        let installed = match registry.get(&plugin_id) {
            Some(row) => row,
            None => registry.install(dir).map_err(|e| e.to_string())?,
        };
        let inner = PluginInstance::load_with_mode(
            &self.engine,
            &installed.path,
            instance_id,
            config.as_ref(),
            LoadMode::Installed {
                expected: installed.installation_uuid,
            },
        )
        .await
        .map_err(|e| format!("{e:#}"))?;
        Ok(ProductionInstance {
            engine: self.engine.clone(),
            inner,
        })
    }

    fn engine(&self) -> &Engine {
        &self.engine
    }
}

impl Driver for ProductionInstance {
    async fn init(&mut self) -> InitOutcome {
        self.inner.init().await.into()
    }

    async fn tick(&mut self) {
        self.inner.tick().await.expect("tick");
    }

    async fn command(&mut self, device: &str, capability: &str, action: &str) -> CommandResult {
        self.inner
            .execute_command(device.to_owned(), command(capability, action))
            .await
            .expect("execute-command")
    }

    async fn deliver(&mut self, event: Event) -> usize {
        self.engine.events().publish(event);
        self.inner.drain_events().await.expect("on-event")
    }

    async fn shutdown(mut self) {
        self.inner.shutdown().await.expect("shutdown");
        // What the supervisor's reaper does once the instance stops.
        self.engine.release_instance_state(self.inner.instance_id());
    }

    fn devices(&self) -> Vec<ObservedDevice> {
        let mut devices: Vec<_> = self
            .engine
            .devices()
            .list()
            .into_iter()
            .filter(|d| d.owner_instance == self.inner.instance_id())
            .map(|d| ObservedDevice {
                id: d.id.clone(),
                local_id: d.info.local_id.clone(),
                capabilities: d.info.capabilities.len(),
            })
            .collect();
        devices.sort_by(|a, b| a.id.cmp(&b.id));
        devices
    }

    fn events(&self) -> Vec<ObservedEvent> {
        let query = EventQuery {
            instance_id: Some(self.inner.instance_id().to_owned()),
            ..EventQuery::default()
        };
        let mut rows = self.engine.event_log().query(&query, 1000).expect("query");
        rows.reverse();
        rows.into_iter()
            .map(|e| ObservedEvent {
                topic: e.topic,
                device: e.device_id,
                plugin_id: e.plugin_id,
                instance_id: e.instance_id,
                payload: e.payload,
            })
            .collect()
    }

    fn storage(&self, key: &str) -> Option<Value> {
        self.engine
            .kv()
            .get(
                &self.inner.installation_uuid(),
                self.inner.instance_id(),
                key,
            )
            .expect("kv get")
    }
}

// --- harness ----------------------------------------------------------

/// `oxidhome-test-host`, used only through its public API.
struct Harness {
    host: TestHost,
}

impl Backend for Harness {
    type Instance = TestPluginInstance;

    fn new() -> Self {
        Self {
            host: TestHost::new().expect("test host"),
        }
    }

    async fn load(
        &mut self,
        dir: &Path,
        instance_id: &str,
        config: Option<toml::Value>,
    ) -> Result<TestPluginInstance, String> {
        let mut options = LoadOptions::new().instance_id(instance_id);
        if let Some(config) = config {
            options = options.config(config);
        }
        self.host
            .load_with(dir, options)
            .await
            .map_err(|e| format!("{:#}", ErrorChain(&e)))
    }

    fn engine(&self) -> &Engine {
        self.host.engine()
    }
}

impl Driver for TestPluginInstance {
    async fn init(&mut self) -> InitOutcome {
        match TestPluginInstance::init(self).await {
            Ok(()) => InitOutcome::Ok,
            Err(TestHostError::Init(e)) => InitOutcome::from(Err::<(), _>(e)),
            Err(other) => panic!("unexpected init error: {other}"),
        }
    }

    async fn tick(&mut self) {
        TestPluginInstance::tick(self).await.expect("tick");
    }

    async fn command(&mut self, device: &str, capability: &str, action: &str) -> CommandResult {
        self.send_command(device, command(capability, action))
            .await
            .expect("execute-command")
    }

    async fn deliver(&mut self, event: Event) -> usize {
        self.deliver_event(event).await.expect("on-event")
    }

    async fn shutdown(self) {
        TestPluginInstance::shutdown(self).await.expect("shutdown");
    }

    fn devices(&self) -> Vec<ObservedDevice> {
        TestPluginInstance::devices(self)
            .into_iter()
            .map(|d| ObservedDevice {
                id: d.id.clone(),
                local_id: d.info.local_id.clone(),
                capabilities: d.info.capabilities.len(),
            })
            .collect()
    }

    fn events(&self) -> Vec<ObservedEvent> {
        TestPluginInstance::events(self)
            .expect("events")
            .into_iter()
            .map(|e| ObservedEvent {
                topic: e.topic,
                device: e.device_id,
                plugin_id: e.plugin_id,
                instance_id: e.instance_id,
                payload: e.payload,
            })
            .collect()
    }

    fn storage(&self, key: &str) -> Option<Value> {
        self.storage().get(key).expect("storage get")
    }
}

/// Render an error with its whole source chain, so load-failure
/// assertions can match on the root cause the same way for both
/// backends (`anyhow`'s `{:#}` does this for the production side).
struct ErrorChain<'a>(&'a dyn std::error::Error);

impl std::fmt::Display for ErrorChain<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)?;
        let mut source = self.0.source();
        while let Some(err) = source {
            write!(f, ": {err}")?;
            source = err.source();
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

fn field(fields: &[KeyValue], key: &str) -> Option<Value> {
    fields
        .iter()
        .find(|kv| kv.key == key)
        .map(|kv| kv.value.clone())
}

/// WIT `value` has no `PartialEq`; compare the variants the examples
/// use through these.
fn as_bool(value: Option<Value>) -> Option<bool> {
    match value {
        Some(Value::BoolVal(b)) => Some(b),
        None => None,
        other => panic!("expected a bool, got {other:?}"),
    }
}

fn as_int(value: Option<Value>) -> Option<i64> {
    match value {
        Some(Value::IntVal(n)) => Some(n),
        None => None,
        other => panic!("expected an int, got {other:?}"),
    }
}

fn ok_state(result: CommandResult) -> Vec<KeyValue> {
    match result {
        CommandResult::OkWithState(fields) => fields,
        other => panic!("expected ok-with-state, got {other:?}"),
    }
}

fn projected_switch_state(engine: &Engine, device: &str) -> (Option<bool>, StateQuality) {
    let state = engine
        .device_state()
        .snapshot_capability(device, "switch")
        .expect("switch projection");
    (as_bool(field(&state.fields, "state")), state.quality)
}

fn plugin_error_mentions(outcome: &InitOutcome, needle: &str) -> bool {
    matches!(outcome, InitOutcome::Plugin(msg) if msg.contains(needle))
}

// ---------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------

/// host-devices: `register-device` in `init` lands in the registry
/// with a host-assigned id; teardown removes it.
async fn devices_register_and_release<B: Backend>() {
    let staged = stage_unchanged(SIMULATED_SWITCH);
    let mut backend = B::new();
    let mut switch = backend.load(staged.path(), "switch", None).await.unwrap();
    assert_eq!(switch.init().await, InitOutcome::Ok);

    let devices = switch.devices();
    assert_eq!(devices.len(), 1, "{devices:?}");
    assert_eq!(devices[0].local_id, "switch-1");
    assert_eq!(devices[0].capabilities, 1);
    assert!(devices[0].id.starts_with("dev-"), "{}", devices[0].id);

    switch.shutdown().await;
    assert!(backend.engine().devices().list().is_empty());
}

/// host-devices + host-events: a command reply projects device state,
/// and the plugin's `publish-event` reaches the durable history with
/// a host-stamped origin.
async fn command_publishes_state_change<B: Backend>() {
    let staged = stage_unchanged(SIMULATED_SWITCH);
    let mut backend = B::new();
    let mut switch = backend.load(staged.path(), "switch", None).await.unwrap();
    assert_eq!(switch.init().await, InitOutcome::Ok);
    let device = switch.devices().remove(0).id;
    assert_eq!(
        projected_switch_state(backend.engine(), &device),
        (Some(false), StateQuality::Fresh),
    );

    let fields = ok_state(switch.command(&device, "switch", "toggle").await);
    assert_eq!(as_bool(field(&fields, "state")), Some(true));
    assert_eq!(
        projected_switch_state(backend.engine(), &device),
        (Some(true), StateQuality::Fresh),
    );

    let events = switch.events();
    assert_eq!(events.len(), 1, "{events:?}");
    let event = &events[0];
    assert_eq!(event.topic, "switch");
    assert_eq!(event.device.as_deref(), Some(device.as_str()));
    assert_eq!(event.plugin_id, "example.simulated-switch");
    assert_eq!(event.instance_id, "switch");
    let EventPayload::StateChanged(change) = &event.payload else {
        panic!("expected state-changed, got {:?}", event.payload);
    };
    assert_eq!(as_bool(field(&change.fields, "state")), Some(true));

    // Unknown actions are the plugin's to reject; the host passes the
    // reply through untouched.
    assert!(matches!(
        switch.command(&device, "switch", "explode").await,
        CommandResult::Err(_)
    ));

    switch.shutdown().await;
    assert_eq!(
        projected_switch_state(backend.engine(), &device).1,
        StateQuality::Stale,
    );
}

/// host-config: per-instance overrides merge over manifest defaults;
/// a malformed override fails the load.
async fn config_overrides<B: Backend>() {
    let staged = stage_unchanged(SIMULATED_SWITCH);
    let mut backend = B::new();
    let overrides: toml::Value = toml::from_str("default_state = true").unwrap();
    let mut switch = backend
        .load(staged.path(), "switch", Some(overrides))
        .await
        .unwrap();
    assert_eq!(switch.init().await, InitOutcome::Ok);
    let device = switch.devices().remove(0).id;
    assert_eq!(
        projected_switch_state(backend.engine(), &device).0,
        Some(true),
    );
    switch.shutdown().await;

    let bad: toml::Value = toml::from_str("default_state = \"yes\"").unwrap();
    let err = backend
        .load(staged.path(), "switch-bad", Some(bad))
        .await
        .err()
        .expect("type-mismatched override must fail the load");
    assert!(err.contains("default_state"), "{err}");
}

/// host-devices capability gate: without `declares_devices`,
/// `register-device` is denied and the plugin's `init` fails.
async fn device_registration_needs_capability<B: Backend>() {
    let staged = stage(SIMULATED_SWITCH, |caps| {
        caps.remove("declares_devices");
    });
    let mut backend = B::new();
    let mut switch = backend.load(staged.path(), "switch", None).await.unwrap();
    let outcome = switch.init().await;
    assert!(
        plugin_error_mentions(&outcome, "PermissionDenied"),
        "{outcome:?}"
    );
    assert_eq!(switch.devices(), Vec::<ObservedDevice>::new());
}

/// storage: writes from `tick` and from a command land in the
/// instance's KV and survive a reload under the same instance id.
async fn storage_round_trip<B: Backend>() {
    let staged = stage_unchanged(KV_COUNTER);
    let mut backend = B::new();
    let mut counter = backend.load(staged.path(), "counter", None).await.unwrap();
    assert_eq!(counter.init().await, InitOutcome::Ok);
    assert_eq!(as_int(counter.storage("count")), None);

    counter.tick().await;
    assert_eq!(as_int(counter.storage("count")), Some(1));
    let fields = ok_state(counter.command("", "counter", "tick").await);
    assert_eq!(as_int(field(&fields, "count")), Some(2));
    assert_eq!(as_int(counter.storage("count")), Some(2));
    counter.shutdown().await;

    let mut again = backend.load(staged.path(), "counter", None).await.unwrap();
    assert_eq!(again.init().await, InitOutcome::Ok);
    let fields = ok_state(again.command("", "counter", "read").await);
    assert_eq!(as_int(field(&fields, "count")), Some(2));
    again.shutdown().await;
}

/// storage capability gate: a zero quota denies every storage call.
async fn storage_needs_quota<B: Backend>() {
    let staged = stage(KV_COUNTER, |caps| {
        caps.insert("storage_quota_kb".into(), toml::Value::Integer(0));
    });
    let mut backend = B::new();
    let mut counter = backend.load(staged.path(), "counter", None).await.unwrap();
    let outcome = counter.init().await;
    assert!(
        plugin_error_mentions(&outcome, "PermissionDenied"),
        "{outcome:?}"
    );
}

/// host-events subscribe + `on-event`: a subscribed plugin receives a
/// host-published event; one that isn't subscribed receives nothing.
async fn event_delivery<B: Backend>() {
    let staged = stage_unchanged(EVENT_RECORDER);
    let mut backend = B::new();
    let mut recorder = backend.load(staged.path(), "recorder", None).await.unwrap();

    let event = || Event {
        device: None,
        timestamp: 0,
        origin_plugin_id: "test.publisher".into(),
        origin_instance_id: "publisher".into(),
        row_id: None,
        call_id: None,
        payload: EventPayload::Custom(CustomEvent {
            topic: "test.ping".into(),
            payload: "{}".into(),
        }),
    };
    // Not subscribed before `init`.
    assert_eq!(recorder.deliver(event()).await, 0);

    assert_eq!(recorder.init().await, InitOutcome::Ok);
    assert_eq!(recorder.deliver(event()).await, 1);
    let fields = ok_state(recorder.command("", "recorder", "count").await);
    assert_eq!(as_int(field(&fields, "count")), Some(1));
    recorder.shutdown().await;
}

/// host-events capability gate: without `subscribes_events`, the
/// plugin's `subscribe` is denied.
async fn subscribe_needs_capability<B: Backend>() {
    let staged = stage(EVENT_RECORDER, |caps| {
        caps.insert("subscribes_events".into(), toml::Value::Boolean(false));
    });
    let mut backend = B::new();
    let mut recorder = backend.load(staged.path(), "recorder", None).await.unwrap();
    let outcome = recorder.init().await;
    assert!(
        plugin_error_mentions(&outcome, "PermissionDenied"),
        "{outcome:?}"
    );
}

macro_rules! conformance {
    ($($scenario:ident),* $(,)?) => {
        mod production {
            $(
                #[tokio::test(flavor = "current_thread")]
                async fn $scenario() {
                    super::$scenario::<super::Production>().await;
                }
            )*
        }
        mod test_host {
            $(
                #[tokio::test(flavor = "current_thread")]
                async fn $scenario() {
                    super::$scenario::<super::Harness>().await;
                }
            )*
        }
    };
}

conformance!(
    devices_register_and_release,
    command_publishes_state_change,
    config_overrides,
    device_registration_needs_capability,
    storage_round_trip,
    storage_needs_quota,
    event_delivery,
    subscribe_needs_capability,
);
