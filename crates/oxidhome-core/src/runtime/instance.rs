//! [`PluginInstance`] — host handle to one running `plugin`-world
//! component. Phase 2 implements the load → init → shutdown cycle;
//! Phase 4 wraps it in the manifest loader so every loaded plugin
//! carries its declared identity, capabilities, and resolved
//! per-instance config.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, anyhow};
use oxidhome_manifest::{InstanceConfig, PluginManifest, merge};
use semver::Version;
use tracing::{Instrument, info_span};
use wasmtime::Store;
use wasmtime::component::{Component, HasSelf, Linker};

use tokio::sync::broadcast::error::TryRecvError;

use crate::auth::Actor;
use crate::host_impl::plugin::Plugin as PluginBindings;
use crate::host_impl::plugin::oxidhome::plugin::devices::{Command, CommandResult};
use crate::host_impl::plugin::oxidhome::plugin::events::Event;
use crate::host_impl::plugin::oxidhome::plugin::types::DeviceId;
use crate::{MIN_SUPPORTED_SDK_VERSION, OXIDHOME_SDK_VERSION};

use super::Engine;
use super::state::PluginState;
use super::watchdog;

/// Read + validate the manifest at `<plugin_dir>/manifest.toml`
/// without instantiating the wasm component. Used by the Phase-6
/// registry's pre-flight singleton check; the full load path
/// re-reads + re-validates inside [`PluginInstance::load`].
///
/// `pub(crate)` for now — only [`crate::Engine::start_instance`]
/// needs the pre-flight parse. The Phase-12 CLI's manifest-validation
/// command will likely want a public variant; that can lift the
/// visibility when it lands.
pub(crate) async fn read_manifest(plugin_dir: &Path) -> anyhow::Result<PluginManifest> {
    let manifest_path = plugin_dir.join("manifest.toml");
    let text = tokio::fs::read_to_string(&manifest_path)
        .await
        .with_context(|| {
            format!(
                "reading manifest from {} (does the plugin dir contain manifest.toml?)",
                manifest_path.display(),
            )
        })?;
    let manifest: PluginManifest =
        toml::from_str(&text).with_context(|| format!("parsing {}", manifest_path.display()))?;
    if let Err(errors) = oxidhome_manifest::validate(&manifest) {
        return Err(anyhow!(
            "manifest {} is invalid:\n  - {}",
            manifest_path.display(),
            errors
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("\n  - "),
        ));
    }
    Ok(manifest)
}

/// One loaded `plugin`-world component, ready to drive through its
/// lifecycle.
///
/// The store carries [`PluginState`] which both Wasmtime (for WASI) and
/// the host trait impls (for `logging`, `host-*`, `storage`) borrow as
/// `&mut self` during host calls.
pub struct PluginInstance {
    bindings: PluginBindings,
    store: Store<PluginState>,
    /// Per-call liveness deadline armed before every host entry point.
    /// Fixed [`watchdog::WATCHDOG_DEFAULT`] in production; the
    /// supervisor lowers it for tests via [`Self::set_watchdog`].
    watchdog: std::time::Duration,
}

/// Why a [`PluginInstance::init`] call failed. The supervisor's
/// `on-trap` restart policy restarts every variant *except*
/// [`InitError::Plugin`] — a clean plugin-`Err` is a deterministic
/// config / capability failure that retrying won't fix.
#[derive(Debug, thiserror::Error)]
pub enum InitError {
    /// The plugin's `init` export returned `Err(message)` — a clean,
    /// deterministic startup failure (bad config, a host call denied
    /// by a missing capability, …).
    #[error("plugin init returned error: {0}")]
    Plugin(String),
    /// A Wasmtime trap while invoking `init` — guest panic,
    /// `unreachable`, OOB, etc.
    #[error("plugin init trapped: {0}")]
    Trap(String),
    /// `init` ran past the liveness watchdog and was interrupted.
    #[error("plugin init was unresponsive (watchdog): {0}")]
    Unresponsive(String),
}

impl PluginInstance {
    /// Load a plugin from its install directory.
    ///
    /// The directory must contain `manifest.toml` (parsed via
    /// `oxidhome-manifest`) and the `.wasm` component the manifest
    /// points at via `[runtime].wasm` (relative to the manifest dir).
    ///
    /// Steps:
    ///
    /// 1. Read + parse `manifest.toml`.
    /// 2. Validate the manifest (`oxidhome_manifest::validate`).
    /// 3. Compatibility-check the plugin's declared `sdk_version`
    ///    against this host's [`OXIDHOME_SDK_VERSION`] and
    ///    [`MIN_SUPPORTED_SDK_VERSION`].
    /// 4. Resolve the per-instance config (`merge` with the
    ///    optional override blob).
    /// 5. Instantiate the wasm component.
    ///
    /// Does **not** call [`Self::init`] — callers run that next.
    pub async fn load(
        engine: &Engine,
        plugin_dir: &Path,
        instance_id: impl Into<String>,
    ) -> anyhow::Result<Self> {
        Self::load_with_overrides(engine, plugin_dir, instance_id, None).await
    }

    /// Same as [`Self::load`], but the caller supplies the user
    /// config-override blob. The host's per-instance config layer
    /// uses this; tests pass `None` to take all defaults.
    ///
    /// # Panics
    /// Panics only if the host's `OXIDHOME_SDK_VERSION` /
    /// `MIN_SUPPORTED_SDK_VERSION` constants fail to parse as
    /// semver — those are compile-time string literals and the
    /// `parse` is essentially a debug assertion on the constants.
    pub async fn load_with_overrides(
        engine: &Engine,
        plugin_dir: &Path,
        instance_id: impl Into<String>,
        overrides: Option<&toml::Value>,
    ) -> anyhow::Result<Self> {
        let plugin_dir = plugin_dir.to_path_buf();
        let instance_id = instance_id.into();
        // `plugin_id = Empty` declares the field up-front so it
        // appears in the span's metadata; we fill it in below once
        // the manifest parses. The Phase-5c log layer's `on_record`
        // handler picks up the deferred value, so events emitted
        // anywhere inside this span (after the parse) attribute to
        // the right plugin. Events between span entry and the
        // parse step — the manifest read itself, the read-error
        // path — still land with `plugin_id` null, which is the
        // honest answer: we don't know the plugin id yet.
        let span = info_span!(
            "plugin.load",
            plugin_dir = %plugin_dir.display(),
            instance_id = %instance_id,
            plugin_id = tracing::field::Empty,
        );
        async move {
            let manifest_path = plugin_dir.join("manifest.toml");
            let manifest_text = tokio::fs::read_to_string(&manifest_path)
                .await
                .with_context(|| {
                    format!(
                        "reading manifest from {} (does the plugin dir contain manifest.toml?)",
                        manifest_path.display(),
                    )
                })?;
            let manifest: PluginManifest = toml::from_str(&manifest_text)
                .with_context(|| format!("parsing {}", manifest_path.display()))?;
            // Record the plugin id onto the active span as soon as
            // it's known. Validation, compatibility-check, and
            // instantiate-time events below will all attribute to
            // it via the Layer's `on_record` hook.
            tracing::Span::current().record("plugin_id", manifest.plugin.id.as_str());
            if let Err(errors) = oxidhome_manifest::validate(&manifest) {
                return Err(anyhow!(
                    "manifest {} is invalid:\n  - {}",
                    manifest_path.display(),
                    errors
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join("\n  - "),
                ));
            }

            // SDK compatibility preflight.
            let core_sdk = OXIDHOME_SDK_VERSION
                .parse::<Version>()
                .expect("OXIDHOME_SDK_VERSION is a valid semver string");
            let min_sdk = MIN_SUPPORTED_SDK_VERSION
                .parse::<Version>()
                .expect("MIN_SUPPORTED_SDK_VERSION is a valid semver string");
            oxidhome_manifest::check_compatibility(
                &manifest.plugin.sdk_version,
                &core_sdk,
                &min_sdk,
            )
            .with_context(|| {
                format!(
                    "rejecting plugin {} (instance {})",
                    manifest.plugin.id, instance_id,
                )
            })?;

            // Resolve per-instance config. An absent override blob is
            // the same as an empty TOML table for merge() — every
            // field falls back on its declared default. Required
            // fields with no default and no override fail loudly.
            let empty_overrides = toml::Value::Table(toml::value::Table::new());
            let overrides_ref = overrides.unwrap_or(&empty_overrides);
            let config = merge(&manifest, overrides_ref).map_err(|errors| {
                anyhow!(
                    "config merge for instance {instance_id} failed:\n  - {}",
                    errors
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join("\n  - "),
                )
            })?;

            let wasm_path = resolve_wasm_path(&plugin_dir, &manifest.runtime.wasm)?;
            let manifest = Arc::new(manifest);
            Self::instantiate(engine, &wasm_path, instance_id, manifest, config).await
        }
        .instrument(span)
        .await
    }

    /// Test-only constructor: skip the manifest-on-disk hop and
    /// supply the parsed `PluginManifest` directly. Useful for unit
    /// tests that want to vary capabilities without writing TOML
    /// fixtures to a tmpdir per scenario. Still runs the SDK-version
    /// compatibility preflight and `merge()` (so the assertions
    /// match the real load path).
    ///
    /// # Panics
    /// See [`Self::load_with_overrides`].
    #[doc(hidden)]
    pub async fn load_with_manifest(
        engine: &Engine,
        wasm_path: &Path,
        instance_id: impl Into<String>,
        manifest: PluginManifest,
        overrides: Option<&toml::Value>,
    ) -> anyhow::Result<Self> {
        let core_sdk = OXIDHOME_SDK_VERSION
            .parse::<Version>()
            .expect("OXIDHOME_SDK_VERSION is a valid semver string");
        let min_sdk = MIN_SUPPORTED_SDK_VERSION
            .parse::<Version>()
            .expect("MIN_SUPPORTED_SDK_VERSION is a valid semver string");
        oxidhome_manifest::check_compatibility(&manifest.plugin.sdk_version, &core_sdk, &min_sdk)
            .context("rejecting test plugin")?;

        let empty_overrides = toml::Value::Table(toml::value::Table::new());
        let overrides_ref = overrides.unwrap_or(&empty_overrides);
        let config = merge(&manifest, overrides_ref).map_err(|errors| {
            anyhow!(
                "test config merge failed:\n  - {}",
                errors
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("\n  - "),
            )
        })?;

        Self::instantiate(engine, wasm_path, instance_id, Arc::new(manifest), config).await
    }

    /// Shared tail: build the Linker, construct `PluginState`, load
    /// the component, instantiate.
    async fn instantiate(
        engine: &Engine,
        wasm_path: &Path,
        instance_id: impl Into<String>,
        manifest: Arc<PluginManifest>,
        config: InstanceConfig,
    ) -> anyhow::Result<Self> {
        let component = Component::from_file(engine.raw(), wasm_path)
            .map_err(anyhow::Error::from)
            .with_context(|| format!("loading component from {}", wasm_path.display()))?;

        let mut linker: Linker<PluginState> = Linker::new(engine.raw());

        // WASI p2 satisfies the `wasi:cli`, `wasi:io`, `wasi:clocks`
        // etc. imports the plugin's libstd pulls in. Plugin world
        // doesn't expose WASI to the plugin author yet (Phase 8
        // does, via the streaming-plugin world), but the
        // libstd-driven imports still need a real implementation.
        wasmtime_wasi::p2::add_to_linker_async(&mut linker)
            .map_err(anyhow::Error::from)
            .context("adding wasi:p2 to linker")?;

        // Host imports declared by the `plugin` world: host-devices,
        // host-events, host-config, storage, logging. All wired
        // through the bindgen-generated `add_to_linker` against
        // `PluginState`. As of Phase 5a, host-devices is gated by the
        // manifest's `declares_devices`; host-config returns the
        // resolved `InstanceConfig`; storage is backed by the shared
        // SQLite KV with per-instance quotas from
        // `capabilities.storage_quota_kb`.
        PluginBindings::add_to_linker::<_, HasSelf<_>>(&mut linker, |state| state)
            .map_err(anyhow::Error::from)
            .context("adding plugin world host imports to linker")?;

        let instance_id = instance_id.into();
        let actor = Actor::plugin(instance_id.clone());

        // Reserve a `kv_usage` row for this instance with the quota
        // declared in the manifest. `register_instance` is idempotent
        // — repeat loads of the same instance id preserve `bytes_used`
        // and only refresh the quota, so a manifest edit + reload
        // picks up the new value without wiping data.
        let quota_bytes = manifest.capabilities.storage_quota_kb.saturating_mul(1024);
        let kv = engine.kv();
        kv.register_instance(&instance_id, quota_bytes)
            .with_context(|| {
                format!(
                    "registering KV usage row for instance {instance_id} (quota {quota_bytes} bytes)",
                )
            })?;

        // Phase 5b: reserve a `blob_usage` row for this instance
        // with the manifest's `blob_quota_mb`. Idempotent like the
        // KV register; positive quota lets calls through, zero
        // gates them off at the host call site.
        let blob_quota_bytes = manifest
            .capabilities
            .blob_quota_mb
            .saturating_mul(1024 * 1024);
        let blobs = engine.blobs();
        blobs
            .register_instance(&instance_id, blob_quota_bytes)
            .with_context(|| {
                format!(
                    "registering blob usage row for instance {instance_id} (quota {blob_quota_bytes} bytes)",
                )
            })?;

        let state = PluginState::new(
            instance_id,
            manifest,
            actor,
            config,
            engine.devices(),
            engine.events(),
            kv,
            engine.event_log(),
            blobs,
        );
        let mut store = Store::new(engine.raw(), state);
        // Phase 7a — `epoch_interruption(true)` starts every store at
        // deadline 0 (already elapsed), which would trap any wasm the
        // component instantiator runs (core-module `start` / component
        // initializers). Arm the *same* watchdog window over
        // instantiation rather than an effectively-infinite one: a
        // `start` function with an infinite loop must be reclaimable
        // too, otherwise it pins the supervisor's worker — exactly the
        // wedge the watchdog exists to prevent. `arm_watchdog` re-arms
        // per host call afterwards. `WATCHDOG_DEFAULT` (not the
        // post-load `set_watchdog` override) is the right ceiling here:
        // legitimate instantiation is near-instant, 30 s is plenty.
        store.set_epoch_deadline(watchdog::deadline_ticks(watchdog::WATCHDOG_DEFAULT));

        let bindings = PluginBindings::instantiate_async(&mut store, &component, &linker)
            .await
            .map_err(anyhow::Error::from)
            .context("instantiating plugin component")?;

        Ok(Self {
            bindings,
            store,
            watchdog: watchdog::WATCHDOG_DEFAULT,
        })
    }

    /// Override the per-call liveness deadline. Production uses the
    /// fixed [`watchdog::WATCHDOG_DEFAULT`]; the Phase-6 supervisor
    /// lowers it from its `SupervisorTuning` so a watchdog test trips
    /// in milliseconds instead of the 30 s default.
    pub(crate) fn set_watchdog(&mut self, timeout: std::time::Duration) {
        self.watchdog = timeout;
    }

    /// Arm the per-call epoch deadline before a host-driven entry
    /// point so a call that never returns is interrupted and the
    /// supervisor regains control. Infallible — `set_epoch_deadline`
    /// can't fail once `epoch_interruption` is on at the engine.
    fn arm_watchdog(&mut self) {
        self.store
            .set_epoch_deadline(watchdog::deadline_ticks(self.watchdog));
    }

    /// Call the plugin's exported `init`. The plugin returns
    /// `Result<(), String>` per the WIT.
    ///
    /// # Errors
    ///
    /// [`InitError::Plugin`] when the plugin's `init` returns `Err`;
    /// [`InitError::Unresponsive`] when the liveness watchdog
    /// interrupts it; [`InitError::Trap`] for any other trap. The
    /// split lets the Phase-6 supervisor apply its `on-trap` policy.
    pub async fn init(&mut self) -> Result<(), InitError> {
        let data = self.store.data();
        let span = info_span!(
            "plugin.init",
            instance_id = %data.instance_id,
            plugin_id = %data.manifest.plugin.id,
        );
        async {
            self.arm_watchdog();
            match self.bindings.call_init(&mut self.store).await {
                Err(trap) => {
                    let err: anyhow::Error = trap.into();
                    let msg = format!("{err:#}");
                    if watchdog::is_watchdog_trap(&err) {
                        Err(InitError::Unresponsive(msg))
                    } else {
                        Err(InitError::Trap(msg))
                    }
                }
                Ok(Err(msg)) => Err(InitError::Plugin(msg)),
                Ok(Ok(())) => Ok(()),
            }
        }
        .instrument(span)
        .await
    }

    /// Call the plugin's exported `tick` — the optional periodic poll
    /// hook. The plugin can't fail this call by contract (WIT `tick`
    /// returns `()`); a trap bubbles up as an error.
    ///
    /// Phase 6's per-instance supervisor drives this off a
    /// `tokio::time::interval` whose cadence is the manifest's
    /// `runtime.tick_interval_ms`. Plugins that declare no interval
    /// are never ticked.
    pub async fn tick(&mut self) -> anyhow::Result<()> {
        let data = self.store.data();
        let span = info_span!(
            "plugin.tick",
            instance_id = %data.instance_id,
            plugin_id = %data.manifest.plugin.id,
        );
        async {
            self.arm_watchdog();
            self.bindings
                .call_tick(&mut self.store)
                .await
                .map_err(anyhow::Error::from)
                .context("invoking plugin tick")
        }
        .instrument(span)
        .await
    }

    /// Call the plugin's exported `shutdown`. The plugin can't fail this
    /// call by contract; trapping bubbles up as an error.
    pub async fn shutdown(&mut self) -> anyhow::Result<()> {
        let data = self.store.data();
        let span = info_span!(
            "plugin.shutdown",
            instance_id = %data.instance_id,
            plugin_id = %data.manifest.plugin.id,
        );
        async {
            self.arm_watchdog();
            self.bindings
                .call_shutdown(&mut self.store)
                .await
                .map_err(anyhow::Error::from)
                .context("invoking plugin shutdown")
        }
        .instrument(span)
        .await
    }

    /// Call the plugin's exported `execute-command` for a device this
    /// instance owns. Phase 3's host-side command routing (in tests
    /// today, in the API/MCP layers later) looks up the device's
    /// owner in [`DeviceRegistry`](crate::DeviceRegistry) and calls
    /// this method on the matching [`PluginInstance`].
    pub async fn execute_command(
        &mut self,
        device: DeviceId,
        cmd: Command,
    ) -> anyhow::Result<CommandResult> {
        let data = self.store.data();
        let span = info_span!(
            "plugin.execute_command",
            instance_id = %data.instance_id,
            plugin_id = %data.manifest.plugin.id,
            device_id = %device,
            capability = %cmd.capability,
            action = %cmd.action,
        );
        async {
            self.arm_watchdog();
            self.bindings
                .call_execute_command(&mut self.store, &device, &cmd)
                .await
                .map_err(anyhow::Error::from)
                .context("invoking plugin execute-command")
        }
        .instrument(span)
        .await
    }

    /// Drain every pending event across this instance's subscriptions
    /// and dispatch matches into the plugin's `on-event` export.
    /// Returns the number of events delivered.
    ///
    /// Phase 3's "host calls `on-event` on the subscriber" plumbing
    /// without the per-instance task model that Phase 6 introduces.
    /// The caller (today: an integration test; tomorrow: a per-
    /// instance tokio task that owns the `Store` and `select!`s
    /// between control commands and bus events) decides when to
    /// drive delivery; the polling shape is a stepping stone, not
    /// the final scheduler.
    pub async fn drain_events(&mut self) -> anyhow::Result<usize> {
        // Two-phase to dodge the conflicting borrow: collecting from
        // `subscriptions` mutably borrows `self.store.data_mut()`,
        // but `call_on_event` needs `&mut self.store` exclusively.
        let pending = self.collect_pending_events();
        // Snapshot the identity fields once before the call loop —
        // building the span per iteration is what matters (each
        // `on_event` call is its own host span, so plugin log lines
        // emitted from inside `on_event` attribute under
        // `plugin.on_event` with both `instance_id` and `plugin_id`).
        // Reading from `self.store.data()` per iteration is fine —
        // these strings don't change for the lifetime of the instance.
        let mut delivered = 0;
        for ev in pending {
            let data = self.store.data();
            let span = info_span!(
                "plugin.on_event",
                instance_id = %data.instance_id,
                plugin_id = %data.manifest.plugin.id,
            );
            async {
                self.arm_watchdog();
                self.bindings
                    .call_on_event(&mut self.store, &ev)
                    .await
                    .map_err(anyhow::Error::from)
                    .context("invoking plugin on-event")
            }
            .instrument(span)
            .await?;
            delivered += 1;
        }
        Ok(delivered)
    }

    /// Pull every available event off each subscription's receiver,
    /// applying the per-subscription filter. Empty/closed/lagged
    /// receivers are skipped silently — the lag counter from
    /// `tokio::sync::broadcast::error::RecvError::Lagged` is the
    /// signal a real driver should surface; here we just continue.
    fn collect_pending_events(&mut self) -> Vec<Event> {
        let mut events = Vec::new();
        let state = self.store.data_mut();
        for sub in &mut state.subscriptions {
            loop {
                match sub.receiver.try_recv() {
                    Ok(ev) => {
                        if sub.matches(&ev) {
                            events.push(ev);
                        }
                    }
                    Err(TryRecvError::Empty | TryRecvError::Closed) => break,
                    // `Lagged(n)` means we missed `n` events; the
                    // receiver itself stays usable and the loop falls
                    // through to the next `try_recv`. Phase 5d's
                    // durable history will let a real driver catch
                    // back up; we just keep draining.
                    Err(TryRecvError::Lagged(_)) => {}
                }
            }
        }
        events
    }

    /// The instance id this state was built with. Currently the plugin's
    /// filename stem; Phase 6 swaps in the manifest-declared id.
    #[must_use]
    pub fn instance_id(&self) -> &str {
        &self.store.data().instance_id
    }

    /// The resolved manifest this instance was loaded from. The
    /// Phase-6 supervisor reads `runtime.tick_interval_ms` and
    /// `runtime.restart` off this to decide its tick cadence and
    /// crash-recovery behaviour.
    #[must_use]
    pub fn manifest(&self) -> &PluginManifest {
        &self.store.data().manifest
    }
}

/// Join `plugin_dir + manifest.runtime.wasm`, canonicalize both, and
/// confirm the resolved `.wasm` lives under the canonical plugin
/// directory. Catches anything the manifest validator's shape check
/// can't see: symlinks pointing outside the plugin dir, races where
/// `plugin_dir` itself is a symlink, etc.
///
/// The validator's `WasmPathProblem` check already rejects absolute
/// paths and `..` components at parse time, so this is defense in
/// depth — but the canonicalize hop catches symlinks, which the
/// purely-syntactic validator can't.
fn resolve_wasm_path(plugin_dir: &Path, rel_wasm: &Path) -> anyhow::Result<std::path::PathBuf> {
    let joined = plugin_dir.join(rel_wasm);
    let canonical_wasm = joined
        .canonicalize()
        .with_context(|| format!("canonicalizing wasm path {}", joined.display()))?;
    let canonical_dir = plugin_dir
        .canonicalize()
        .with_context(|| format!("canonicalizing plugin dir {}", plugin_dir.display()))?;
    if !canonical_wasm.starts_with(&canonical_dir) {
        return Err(anyhow!(
            "runtime.wasm resolves to {}, which is outside the plugin directory {} \
             (symlink? `..`-traversal that snuck past validation?)",
            canonical_wasm.display(),
            canonical_dir.display(),
        ));
    }
    Ok(canonical_wasm)
}
