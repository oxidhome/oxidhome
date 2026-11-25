//! [`TestHost`] and its load options.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use oxidhome_core::runtime::dispatcher::call_service_from_host;
use oxidhome_core::runtime::{LoadMode, SupervisorTuning, read_manifest_with_bytes};
use oxidhome_core::{Clock, Engine, PluginInstance, VirtualClock};
use oxidhome_manifest::{CapabilitiesSection, PluginManifest, ServiceGrant};

use crate::TestHostError;
use crate::grant::grant_excess;
use crate::instance::TestPluginInstance;
use crate::live::{IdLease, LiveIds};
use crate::snapshot::HostRecords;
use crate::supervised::SupervisedInstance;
use crate::tempdir::TempDir;
use crate::wit::devices::CommandResult;
use crate::wit::types::{Error as WitError, KeyValue};

/// An in-process plugin host for tests.
///
/// Wraps a production [`Engine`] backed by a fresh `SQLite` database
/// and blob root in a temporary directory, removed once the host and
/// every instance and storage view it handed out are dropped.
/// Instances on the same host share its device registry, service
/// registry, event bus, and stores, exactly as instances in one daemon
/// do; use separate hosts for isolated tests.
///
/// A plugin runs one of two ways:
///
/// - [`Self::load`] — *driven directly*: the test calls each export
///   itself ([`TestPluginInstance`]), so nothing happens between calls
///   and [`TestPluginInstance::advance`] runs the scheduled ticks.
/// - [`Self::start`] — *supervised*: the daemon's own supervisor task
///   runs it ([`SupervisedInstance`]), with scheduled ticks, event
///   delivery, crash restarts, the liveness watchdog, and serving
///   `call-service` requests from other plugins.
///
/// [`Self::new`] runs the host on the real clock. On
/// [`Self::with_virtual_clock`] time stands still until the test moves
/// it ([`Self::advance`]): supervised ticks, `accepted`-command TTLs,
/// the liveness watchdog, the guest's WASI clocks, and the host's
/// event, device-state, and audit timestamps all follow the
/// [`VirtualClock`]. See the crate docs, "Time".
pub struct TestHost {
    // Field order matters: `engine` holds the database open, so it
    // drops before the directory it lives in is removed.
    engine: Engine,
    live: Arc<LiveIds>,
    next_id: AtomicU64,
    state_dir: Arc<TempDir>,
    /// Every loaded instance's secret config values, for snapshot
    /// redaction.
    secrets: Arc<HostRecords>,
}

/// Per-load knobs for [`TestHost::load_with`] and
/// [`TestHost::start_with`]. `Default` loads the plugin the way
/// `oxidhome-core` dev-loads it: a generated instance id, manifest
/// defaults for every config field, and the capabilities the manifest
/// requests.
#[derive(Debug, Clone, Default)]
pub struct LoadOptions {
    instance_id: Option<String>,
    config: Option<toml::Value>,
    grant: Option<CapabilitiesSection>,
    supervision: Option<SupervisorTuning>,
}

impl LoadOptions {
    /// Same as [`LoadOptions::default`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Run the plugin under this instance id instead of a generated
    /// `test-<n>`. Storage, device ids, and event origins are keyed by
    /// it, so reloading with the same id sees the previous
    /// instance's persisted state, as a daemon restart would.
    #[must_use]
    pub fn instance_id(mut self, id: impl Into<String>) -> Self {
        self.instance_id = Some(id.into());
        self
    }

    /// Per-instance config overrides, as a TOML table keyed by the
    /// manifest's `[config.*]` field names. Merged with the manifest
    /// defaults by the production config merge, so unknown keys and
    /// type mismatches fail the load just as they do in the daemon.
    #[must_use]
    pub fn config(mut self, overrides: toml::Value) -> Self {
        self.config = Some(overrides);
        self
    }

    /// Run the plugin under this grant instead of the manifest's full
    /// request — typically to test how it behaves when a capability
    /// is denied.
    ///
    /// The grant takes the path an installed plugin's grant takes: the
    /// loader checks it against the capability-count limits and
    /// applies `requested ∩ granted`. A grant that asks for anything
    /// the manifest doesn't request is refused with
    /// [`TestHostError::GrantExceedsRequest`] (see
    /// [`crate::grant_excess`]), because production would quietly
    /// drop the extra and the test wouldn't be testing what it says.
    #[must_use]
    pub fn grant(mut self, grant: CapabilitiesSection) -> Self {
        self.grant = Some(grant);
        self
    }

    /// Supervisor settings for [`TestHost::start_with`] (ignored by
    /// [`TestHost::load_with`]). Defaults to [`test_supervision`]:
    /// production's watchdog and healthy-reset window with a fast
    /// restart backoff, so a crash-loop test finishes in milliseconds.
    /// Lower `watchdog` to test a hung plugin without waiting out the
    /// production deadline.
    #[must_use]
    pub fn supervision(mut self, tuning: SupervisorTuning) -> Self {
        self.supervision = Some(tuning);
        self
    }
}

/// The supervisor settings [`TestHost::start`] uses by default:
/// [`SupervisorTuning::default`] (the daemon's) with the restart
/// backoff cut to 10–100 ms and at most 3 consecutive restarts.
#[must_use]
pub fn test_supervision() -> SupervisorTuning {
    SupervisorTuning {
        backoff_base: Duration::from_millis(10),
        backoff_max: Duration::from_millis(100),
        max_restarts: 3,
        ..SupervisorTuning::default()
    }
}

/// What [`TestHost::prepare`] resolved for one load or start.
struct Prepared {
    reservation: Reservation,
    plugin_id: String,
    manifest_bytes: Vec<u8>,
    manifest: PluginManifest,
    config: Option<toml::Value>,
    mode: LoadMode,
    supervision: Option<SupervisorTuning>,
    /// The merged config's secret values, for snapshot redaction.
    secrets: Vec<String>,
}

impl TestHost {
    /// Build a host with an empty state directory.
    ///
    /// # Errors
    ///
    /// [`TestHostError::StateDir`] if the temporary directory can't
    /// be created; [`TestHostError::Engine`] if the engine or its
    /// database can't be set up.
    pub fn new() -> Result<Self, TestHostError> {
        Self::build(Clock::system())
    }

    /// Build a host on a fresh [`VirtualClock`], at
    /// [`VirtualClock::new`]'s fixed start (2026-01-01T00:00:00Z).
    ///
    /// # Errors
    ///
    /// As [`Self::new`].
    pub fn with_virtual_clock() -> Result<Self, TestHostError> {
        Self::with_clock(VirtualClock::new())
    }

    /// Build a host on `clock` — e.g. one from
    /// [`VirtualClock::starting_at`], or one shared with another host.
    ///
    /// # Errors
    ///
    /// As [`Self::new`].
    pub fn with_clock(clock: VirtualClock) -> Result<Self, TestHostError> {
        Self::build(Clock::from(clock))
    }

    fn build(clock: Clock) -> Result<Self, TestHostError> {
        let state_dir =
            TempDir::new().map_err(|(path, source)| TestHostError::StateDir { path, source })?;
        let engine = Engine::with_state_dir_and_clock(state_dir.path(), clock)
            .map_err(|e| TestHostError::Engine(e.into()))?;
        Ok(Self {
            engine,
            live: Arc::default(),
            next_id: AtomicU64::new(1),
            state_dir: Arc::new(state_dir),
            secrets: Arc::default(),
        })
    }

    /// Trust the DER certificates `roots` for streaming plugins'
    /// `https://` requests, on top of the system roots. Call before
    /// loading plugins. The pins stay in [`Engine::tls_pins`].
    #[must_use]
    pub fn with_tls_for_tests(mut self, roots: Vec<Vec<u8>>) -> Self {
        self.engine = self.engine.clone().with_tls_for_tests(roots);
        self
    }

    /// The underlying production engine, for assertions the harness
    /// doesn't wrap (device-state projection, event bus subscriptions,
    /// blob store, …).
    #[must_use]
    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    /// The host's state directory (`SQLite` database, blob root).
    #[must_use]
    pub fn state_dir(&self) -> &Path {
        self.state_dir.path()
    }

    /// The host's virtual clock; `None` on a [`Self::new`] host.
    ///
    /// Its own [`VirtualClock::advance`] moves time and fires what
    /// falls due without waiting for anything — the way to move time
    /// while a plugin call is stuck, e.g. past the liveness watchdog.
    #[must_use]
    pub fn virtual_clock(&self) -> Option<&VirtualClock> {
        self.engine.clock().as_virtual()
    }

    /// Move the virtual clock forward by `by`, one timer at a time:
    /// each timer that falls due in the span fires at its own
    /// deadline, and the host waits for the work it triggers —
    /// a supervised instance's tick, an `accepted` command's expiry —
    /// before moving on. So with `tick_interval_ms = 1000`, advancing
    /// 3.5 s runs exactly three periodic ticks. A streaming instance
    /// that holds a readable socket may also get early ticks in that
    /// span (at most one per 100 ms).
    ///
    /// Directly driven instances aren't ticked here: their ticks run
    /// when the test calls [`TestPluginInstance::advance`] (which also
    /// moves this clock) or [`TestPluginInstance::tick`].
    ///
    /// "The work a timer triggers" is its owner's: a supervised tick
    /// counts as done once the supervisor waits for its next tick. An
    /// event that tick published may still be on its way to another
    /// instance's `on-event`, or a tick that trapped may still be
    /// failing its instance; wait for that effect itself. Timers due
    /// at the same instant fire together, in no set order. Advance one
    /// clock from one task at a time (concurrent steps interleave), on
    /// a multi-thread runtime if a plugin call may hang: a spinning
    /// guest holds its worker thread.
    ///
    /// # Errors
    ///
    /// [`TestHostError::RealClock`] on a [`Self::new`] host;
    /// [`TestHostError::ClockStalled`] when woken work doesn't finish
    /// (a hung plugin call: move past it with
    /// [`VirtualClock::advance`] instead).
    pub async fn advance(&self, by: Duration) -> Result<(), TestHostError> {
        let clock = self.virtual_clock().ok_or(TestHostError::RealClock)?;
        crate::clock::advance_to(clock, clock.elapsed().saturating_add(by)).await
    }

    /// Without moving time, wait until everything already due has
    /// fired and the work it triggered has been picked up (every
    /// supervised instance whose tick fired is waiting for its next
    /// one again).
    ///
    /// # Errors
    ///
    /// As [`Self::advance`].
    pub async fn run_until_idle(&self) -> Result<(), TestHostError> {
        let clock = self.virtual_clock().ok_or(TestHostError::RealClock)?;
        crate::clock::settle(clock).await
    }

    /// Load the plugin in `plugin_dir` with default [`LoadOptions`].
    /// Does not call `init`.
    ///
    /// # Errors
    ///
    /// See [`Self::load_with`].
    pub async fn load(
        &self,
        plugin_dir: impl AsRef<Path>,
    ) -> Result<TestPluginInstance, TestHostError> {
        self.load_with(plugin_dir, LoadOptions::default()).await
    }

    /// Load the plugin in `plugin_dir` — a directory holding
    /// `manifest.toml` and the component its `[runtime] wasm` entry
    /// points at. Does not call `init`.
    ///
    /// # Errors
    ///
    /// - [`TestHostError::InvalidInstanceId`] /
    ///   [`TestHostError::DuplicateInstanceId`] for an id the daemon
    ///   would refuse, or one a live instance on this host holds.
    /// - [`TestHostError::Manifest`] when the manifest can't be read,
    ///   parsed, or validated.
    /// - [`TestHostError::GrantExceedsRequest`] for an injected grant
    ///   wider than the manifest's request.
    /// - [`TestHostError::Load`] when the production loader refuses
    ///   the plugin or the component fails to instantiate.
    pub async fn load_with(
        &self,
        plugin_dir: impl AsRef<Path>,
        options: LoadOptions,
    ) -> Result<TestPluginInstance, TestHostError> {
        let plugin_dir = plugin_dir.as_ref();
        let Prepared {
            reservation,
            plugin_id,
            manifest_bytes,
            manifest,
            config,
            mode,
            supervision: _,
            secrets,
        } = self.prepare(plugin_dir, options).await?;
        // Before the guest runs: a start function may store a secret
        // and then fail the load.
        self.secrets.add(secrets.iter().map(String::as_str));
        let inner = PluginInstance::load_with_pinned_manifest(
            &self.engine,
            plugin_dir,
            reservation.id().to_owned(),
            config.as_ref(),
            mode,
            manifest_bytes,
            manifest,
        )
        .await
        .map_err(|e| TestHostError::Load {
            plugin_id,
            source: e.into(),
        })?;
        Ok(TestPluginInstance::new(
            self.engine.clone(),
            inner,
            reservation.keep(),
            Arc::clone(&self.state_dir),
            Arc::clone(&self.secrets),
        ))
    }

    /// Start the plugin in `plugin_dir` under the production
    /// supervisor with default [`LoadOptions`].
    ///
    /// # Errors
    ///
    /// See [`Self::start_with`].
    pub async fn start(
        &self,
        plugin_dir: impl AsRef<Path>,
    ) -> Result<SupervisedInstance, TestHostError> {
        self.start_with(plugin_dir, LoadOptions::default()).await
    }

    /// Start the plugin in `plugin_dir` under the production
    /// supervisor ([`Engine::start_instance`]'s code path, with the
    /// [`LoadOptions::supervision`] settings) and return at once,
    /// while it is still loading. The supervisor loads it, calls
    /// `init`, then serves ticks, commands, event delivery, and
    /// incoming `call-service` requests until it is stopped or
    /// crashes for good; use [`SupervisedInstance::wait_for_running`]
    /// before driving it.
    ///
    /// Must be called on a Tokio runtime that outlives the instance:
    /// the supervisor is a task on it. [`crate::block_on`]'s runtime
    /// qualifies.
    ///
    /// # Errors
    ///
    /// The same up-front checks as [`Self::load_with`]
    /// ([`TestHostError::InvalidInstanceId`],
    /// [`TestHostError::DuplicateInstanceId`],
    /// [`TestHostError::Manifest`],
    /// [`TestHostError::GrantExceedsRequest`]), and
    /// [`TestHostError::Load`] if the engine refuses to start it (e.g.
    /// a singleton plugin already running). A failure while loading
    /// or initialising surfaces later, as the instance's `Failed`
    /// state.
    pub async fn start_with(
        &self,
        plugin_dir: impl AsRef<Path>,
        options: LoadOptions,
    ) -> Result<SupervisedInstance, TestHostError> {
        let plugin_dir = plugin_dir.as_ref();
        let Prepared {
            reservation,
            plugin_id,
            manifest_bytes: _,
            manifest: _,
            config,
            mode,
            supervision,
            secrets,
        } = self.prepare(plugin_dir, options).await?;
        // Before the guest runs, as for `load_with`.
        self.secrets.add(secrets.iter().map(String::as_str));
        let handle = self
            .engine
            .start_instance_with_tuning(
                plugin_dir,
                reservation.id(),
                config,
                mode,
                supervision.unwrap_or_else(test_supervision),
            )
            .await
            .map_err(|e| TestHostError::Load {
                plugin_id,
                source: e.into(),
            })?;
        Ok(SupervisedInstance::new(
            self.engine.clone(),
            handle,
            reservation.keep(),
            Arc::clone(&self.state_dir),
            Arc::clone(&self.secrets),
        ))
    }

    /// Call `command` on service `target` (a host-minted `svc-N`)
    /// through the production dispatcher, as a host-side caller with
    /// instance id [`Self::SERVICE_CALLER`].
    ///
    /// Everything but the caller's grant check applies as for a
    /// plugin's `call-service`: the target must be registered and its
    /// owner supervised and running, `command` must be one the
    /// service declares, `args` must match its typed `params` schema,
    /// the reply is checked against `returns`, and calls that would
    /// loop back into a supervisor parked on the chain are refused.
    /// The caller's grant is the narrowest one that authorizes this
    /// exact call, so the check passes by construction — the test is
    /// the operator here. To test a plugin's `consumes_services` grant,
    /// make the call from a plugin (e.g. under
    /// [`LoadOptions::grant`]).
    ///
    /// # Errors
    ///
    /// The dispatcher's WIT error: `not-found` for an unknown
    /// service, `invalid-argument` for an undeclared command, an
    /// argument that doesn't match the schema, or a refused cycle,
    /// `unavailable` when the owner isn't running or doesn't reply in
    /// time. A command the plugin itself rejects is an
    /// `Ok(CommandResult::Err(_))`.
    pub async fn call_service(
        &self,
        target: impl Into<String>,
        command: impl Into<String>,
        args: Vec<KeyValue>,
    ) -> Result<CommandResult, WitError> {
        let target = target.into();
        let command = command.into();
        let grants: Vec<ServiceGrant> = self
            .engine
            .services()
            .get_owner_plugin_and_local_id(&target)
            .map(|(instance, plugin, service)| ServiceGrant {
                plugin,
                instance,
                service,
                commands: vec![command.clone()],
                caller_instance: Self::SERVICE_CALLER.to_owned(),
            })
            .into_iter()
            .collect();
        call_service_from_host(
            &self.engine,
            Self::SERVICE_CALLER,
            &grants,
            &grants,
            target,
            command,
            args,
        )
        .await
    }

    /// The caller instance id [`Self::call_service`] dispatches as.
    /// Don't give a plugin instance this id: a call from the host to
    /// one of its services would then count as a same-instance call.
    pub const SERVICE_CALLER: &'static str = "oxidhome-test-host";

    /// Resolve the instance id and manifest for a load or start, and
    /// check an injected grant against the manifest's request.
    async fn prepare(
        &self,
        plugin_dir: &Path,
        options: LoadOptions,
    ) -> Result<Prepared, TestHostError> {
        let LoadOptions {
            instance_id,
            config,
            grant,
            supervision,
        } = options;
        let reservation = match instance_id {
            Some(id) => {
                if !oxidhome_core::runtime::is_operator_instance_id(&id) {
                    return Err(TestHostError::InvalidInstanceId(id));
                }
                Reservation::claim(&self.engine, &self.live, id)?
            }
            None => Reservation::claim_generated(&self.engine, &self.live, &self.next_id),
        };

        // Read the manifest once and pin it for the load, as
        // `Engine::start_instance` does, so the grant check below and
        // the loader see the same bytes.
        let (manifest_bytes, manifest) =
            read_manifest_with_bytes(plugin_dir)
                .await
                .map_err(|e| TestHostError::Manifest {
                    path: plugin_dir.to_path_buf(),
                    source: e.into(),
                })?;
        let plugin_id = manifest.plugin.id.clone();
        // What the loader will merge; a config it refuses fails the
        // load (or, supervised, the instance) on its own.
        let secrets = oxidhome_manifest::merge(
            &manifest,
            config
                .as_ref()
                .unwrap_or(&toml::Value::Table(toml::Table::new())),
        )
        .map_or_default(|merged| {
            oxidhome_core::redact::config_secrets(&merged)
                .into_iter()
                .map(str::to_owned)
                .collect()
        });

        let mode = match grant {
            None => LoadMode::Dev,
            Some(grant) => {
                let excess = grant_excess(&manifest.capabilities, &grant);
                if !excess.is_empty() {
                    return Err(TestHostError::GrantExceedsRequest { plugin_id, excess });
                }
                LoadMode::Granted {
                    granted: Arc::new(grant),
                }
            }
        };
        Ok(Prepared {
            reservation,
            plugin_id,
            manifest_bytes,
            manifest,
            config,
            mode,
            supervision,
            secrets,
        })
    }
}

/// Holds an instance id until the load either succeeds (ownership
/// moves to the instance) or fails or is cancelled (dropped here). On
/// drop it first tears down any host state filed under the id —
/// component initializers run during instantiation and may already
/// have called host imports, which the supervisor's reaper would clean
/// up after a failed load — and only then frees the id.
struct Reservation {
    engine: Engine,
    lease: Option<IdLease>,
}

impl Reservation {
    fn claim(engine: &Engine, live: &Arc<LiveIds>, id: String) -> Result<Self, TestHostError> {
        Ok(Self {
            engine: engine.clone(),
            lease: Some(live.claim(engine, id)?),
        })
    }

    /// Claim the next free `test-<n>` id, skipping any a caller chose
    /// explicitly.
    fn claim_generated(engine: &Engine, live: &Arc<LiveIds>, next: &AtomicU64) -> Self {
        loop {
            let id = format!("test-{}", next.fetch_add(1, Ordering::Relaxed));
            if let Ok(reservation) = Self::claim(engine, live, id) {
                return reservation;
            }
        }
    }

    fn id(&self) -> &str {
        self.lease.as_ref().map_or_default(IdLease::id)
    }

    fn keep(mut self) -> IdLease {
        self.lease.take().expect("reservation kept twice")
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if let Some(lease) = self.lease.take() {
            self.engine.release_instance_state(lease.id());
        }
    }
}
