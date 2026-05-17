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

/// One loaded `plugin`-world component, ready to drive through its
/// lifecycle.
///
/// The store carries [`PluginState`] which both Wasmtime (for WASI) and
/// the host trait impls (for `logging`, `host-*`, `storage`) borrow as
/// `&mut self` during host calls.
pub struct PluginInstance {
    bindings: PluginBindings,
    store: Store<PluginState>,
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
        let span = info_span!(
            "plugin.load",
            plugin_dir = %plugin_dir.display(),
            instance_id = %instance_id,
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

        let state = PluginState::new(
            instance_id,
            manifest,
            actor,
            config,
            engine.devices(),
            engine.events(),
            kv,
            engine.event_log(),
        );
        let mut store = Store::new(engine.raw(), state);

        let bindings = PluginBindings::instantiate_async(&mut store, &component, &linker)
            .await
            .map_err(anyhow::Error::from)
            .context("instantiating plugin component")?;

        Ok(Self { bindings, store })
    }

    /// Call the plugin's exported `init`. The plugin returns
    /// `Result<(), String>` per the WIT — we propagate the error
    /// message through `anyhow`.
    pub async fn init(&mut self) -> anyhow::Result<()> {
        let data = self.store.data();
        let span = info_span!(
            "plugin.init",
            instance_id = %data.instance_id,
            plugin_id = %data.manifest.plugin.id,
        );
        async {
            self.bindings
                .call_init(&mut self.store)
                .await
                .map_err(anyhow::Error::from)
                .context("invoking plugin init")?
                .map_err(|msg| anyhow::anyhow!("plugin init returned error: {msg}"))
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
        let mut delivered = 0;
        for ev in pending {
            self.bindings
                .call_on_event(&mut self.store, &ev)
                .await
                .map_err(anyhow::Error::from)
                .context("invoking plugin on-event")?;
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
