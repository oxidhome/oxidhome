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

use crate::auth::Actor;
use crate::host_impl::plugin::Plugin as PluginBindings;
use crate::host_impl::plugin::oxidhome::plugin::devices::{Command, CommandResult};
use crate::host_impl::plugin::oxidhome::plugin::events::Event;
use crate::host_impl::plugin::oxidhome::plugin::types::{DeviceId, KeyValue, ServiceId};
use crate::{MIN_SUPPORTED_SDK_VERSION, OXIDHOME_SDK_VERSION};

use super::Engine;
use super::state::PluginState;
use super::watchdog;

/// C1b review F1: guard for the installation-UUID lookup in
/// `PluginInstance::instantiate`. Returns `true` when the loaded
/// wasm resides **inside** the plugin root the
/// `InstalledPluginRegistry` row remembers — i.e. the canonicalized
/// `wasm_path` starts with the canonicalized `registry_path`. This
/// handles both flat (`<root>/plugin.wasm`) and nested
/// (`<root>/build/plugin.wasm`, `<root>/target/…`) layouts declared
/// via `[runtime].wasm`. Canonicalizing defeats `..`, symlinks,
/// and non-normalized relative segments.
///
/// Follow-up review H11 hardened the mismatch handling: production
/// (`LoadMode::Installed`) loads whose registry row's path doesn't
/// cover the loaded wasm are refused outright — no synthetic-UUID
/// fallback, because that path silently let a rogue .wasm run under
/// the same `plugin_id` as an installed package. Dev loads
/// (`LoadMode::Dev`) whose registry-row path mismatches are refused
/// too (H11 first cut), so a dev-time argv load can't shadow an
/// installed package's identity either.
fn loaded_dir_matches_registry(wasm_path: &Path, registry_path: &Path) -> bool {
    let Ok(loaded) = std::fs::canonicalize(wasm_path) else {
        return false;
    };
    let Ok(root) = std::fs::canonicalize(registry_path) else {
        return false;
    };
    // `Path::starts_with` matches on component boundaries, so
    // `<root>-attacker/plugin.wasm` won't spuriously match
    // `<root>/`.
    loaded.starts_with(&root)
}

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

/// H11 round-2 F1: caller-declared load provenance. Passed through
/// [`Engine::start_instance`] / [`PluginInstance::load`] all the way
/// to `instantiate`, so the loader can distinguish an API-driven
/// production start (which MUST match a live installation ledger
/// row) from an explicit dev-time load (which may inherit a
/// synthetic identity + manifest-requested capabilities).
///
/// Registry absence was previously treated as authorization for a
/// dev load — under a concurrent uninstall race the reviewer
/// flagged, that let a fresh instance run with manifest-requested
/// caps instead of the persisted grant. The mode makes the choice
/// explicit at every entry point; the loader fails closed for
/// `Installed` if the ledger row it names disappears.
#[derive(Debug, Clone)]
pub enum LoadMode {
    /// API-driven production load. Loader MUST find a live
    /// [`crate::state::InstalledPluginRegistry`] row whose
    /// `installation_uuid` matches `expected` **and** whose
    /// `path` covers the loaded `wasm_path`. Any deviation
    /// (registry cleared mid-flight, path renamed, uuid rotated
    /// by a reinstall) fails the load closed — no silent
    /// synthetic-identity fallback.
    Installed { expected: Arc<str> },
    /// Explicit dev-time load. Loader will:
    ///
    /// - Use the installed grant when the registry has a matching
    ///   row for this `plugin_id` **and** the loaded path covers
    ///   the registry row's path.
    /// - Refuse when the registry row exists but the path
    ///   doesn't match (H11 same-id / different-path).
    /// - Fall back to synthetic UUID + manifest-requested
    ///   capabilities when no row exists at all (nothing to
    ///   shadow). Callers pick this mode by conscious choice —
    ///   argv-loaded plugins in `main.rs`, integration tests,
    ///   the `Engine::new()` in-memory harness.
    Dev,
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
    /// config-override blob. Uses `LoadMode::Dev` — the loader may
    /// fall back to synthetic identity + manifest-requested caps
    /// when no installed ledger row claims `manifest.plugin.id`.
    /// Production (API-driven) loads must go through
    /// [`Self::load_with_mode`] with `LoadMode::Installed` so
    /// the loader fails closed on a concurrent uninstall race.
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
        Self::load_with_mode(engine, plugin_dir, instance_id, overrides, LoadMode::Dev).await
    }

    /// H11 round-2 F1: full-fidelity load with explicit
    /// [`LoadMode`]. The supervisor routes through this so an
    /// API-driven start carries `LoadMode::Installed { expected }`
    /// and the loader refuses to fall back to synthetic identity
    /// when the ledger row disappears mid-flight.
    #[doc(hidden)]
    pub async fn load_with_mode(
        engine: &Engine,
        plugin_dir: &Path,
        instance_id: impl Into<String>,
        overrides: Option<&toml::Value>,
        mode: LoadMode,
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
            // C5 review F3 round-4 F2: read the manifest as
            // **raw bytes** so the same buffer feeds both parse
            // and the load-time digest check further down.
            // Reading as `String` and then re-reading for the
            // hash would reintroduce the TOCTOU window this fix
            // exists to close.
            let manifest_bytes = tokio::fs::read(&manifest_path).await.with_context(|| {
                format!(
                    "reading manifest from {} (does the plugin dir contain manifest.toml?)",
                    manifest_path.display(),
                )
            })?;
            let manifest_text = std::str::from_utf8(&manifest_bytes)
                .with_context(|| format!("manifest {} is not UTF-8", manifest_path.display()))?;
            let manifest: PluginManifest = toml::from_str(manifest_text)
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
            // C5 review F3 round-4 F2: read wasm bytes into
            // memory once, then feed those same bytes to BOTH
            // the digest verification and wasmtime's
            // `Component::from_binary`. That closes the TOCTOU
            // window where an on-disk rewrite between the
            // digest walk and `Component::from_file` could sneak
            // modified code past the check.
            let wasm_bytes = tokio::fs::read(&wasm_path)
                .await
                .with_context(|| format!("reading wasm component from {}", wasm_path.display()))?;
            let manifest = Arc::new(manifest);
            Self::instantiate(
                engine,
                &plugin_dir,
                &wasm_path,
                &manifest_bytes,
                &wasm_bytes,
                instance_id,
                manifest,
                config,
                mode,
            )
            .await
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

        // Test path: no registry entry, so no digest check runs;
        // pass empty manifest bytes so `instantiate` treats this
        // as a dev-time load.
        let wasm_bytes = tokio::fs::read(wasm_path)
            .await
            .with_context(|| format!("reading wasm from {}", wasm_path.display()))?;
        let plugin_dir = wasm_path.parent().unwrap_or(wasm_path).to_path_buf();
        Self::instantiate(
            engine,
            &plugin_dir,
            wasm_path,
            &[],
            &wasm_bytes,
            instance_id,
            Arc::new(manifest),
            config,
            LoadMode::Dev,
        )
        .await
    }

    /// Shared tail: build the Linker, construct `PluginState`, load
    /// the component, instantiate.
    // C1b + C5: the loader body is intentionally long — one path
    // handles the installation-UUID lookup, path/digest guards,
    // quarantine refusal, effective-capabilities computation,
    // per-instance quota registration, and component
    // instantiation. Splitting them would fragment the "resolve
    // grant boundary → apply" contract that the C5 review fixes
    // depend on.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    async fn instantiate(
        engine: &Engine,
        plugin_dir: &Path,
        wasm_path: &Path,
        manifest_bytes: &[u8],
        wasm_bytes: &[u8],
        instance_id: impl Into<String>,
        manifest: Arc<PluginManifest>,
        config: InstanceConfig,
        mode: LoadMode,
    ) -> anyhow::Result<Self> {
        // C5 review F3 round-4 F2: instantiate from the same
        // in-memory wasm bytes the digest check will read, not
        // from the on-disk file. That closes the TOCTOU window
        // where an attacker with FS write access could swap
        // `plugin.wasm` between the digest walk and
        // `Component::from_file`.
        let component = Component::from_binary(engine.raw(), wasm_bytes)
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

        // C1b: pin the installation UUID at load time. If the plugin
        // was installed through the API (`InstalledPluginRegistry`)
        // AND the loaded directory matches the registry row, use
        // the host-minted `inst-<hex>` from SQL; otherwise fall
        // back to the manifest `plugin.id` as a synthetic UUID.
        //
        // C1b review F1: the loaded-directory guard prevents a
        // dev-time load (or a replacement component) whose manifest
        // happens to declare an installed `plugin_id` from inheriting
        // the installed package's UUID and minting the same device
        // ids — exactly the identity-inheritance the C1b change
        // exists to prevent.
        //
        // C5 review F1/F3 codex-fixup: quarantined installations
        // must not fall through to dev-load semantics. The direct
        // `Engine::start_instance(path, ...)` path (argv / test
        // harness) reaches here with `installed_plugins().get()`
        // returning `None`, which would otherwise apply the
        // manifest's requested capabilities + a synthetic UUID —
        // shadowing the operator's quarantine decision. Refuse.
        if engine
            .installed_plugins()
            .is_quarantined(&manifest.plugin.id)
        {
            return Err(anyhow!(
                "plugin {} is quarantined (malformed grant or missing content digest); \
                 reinstall via the API to re-issue the boundary",
                manifest.plugin.id
            ));
        }

        // C5: resolve the **granted** capabilities from the same
        // registry row that gave us the UUID. Falls back to the
        // manifest's requested capabilities when the load path
        // bypasses the registry (dev / test) or the registry
        // entry doesn't match this on-disk directory.
        //
        // C5 review F2: compute the **effective** set —
        // requested ∩ granted — so a stale grant broader than
        // the current manifest can't authorize permissions the
        // manifest no longer asks for.
        //
        // C5 review F3: verify the on-disk content digest
        // matches the registered value before applying the
        // grant. A mismatch means the plugin.wasm / manifest /
        // assets were replaced in place since install; refuse
        // to run the modified bytes under the pre-modification
        // grant. Dev-time loads (no registry row, or mismatched
        // registry path) inherently have no digest to check.
        let requested = &manifest.capabilities;
        let _ = plugin_dir; // retained for future callsites; the
        // digest below already binds to the exact bytes we
        // parsed + will compile.
        // H11 round-2 F1: pick the identity + grant based on the
        // caller-declared `LoadMode`. `Installed { expected }` is
        // API-driven production; the registry row named by
        // `expected` MUST be live and cover this wasm path.
        // `Dev` is explicit dev-time load; may fall back to
        // synthetic identity when no row exists (nothing to
        // shadow), but still refuses when a row exists at a
        // different path (H11 first cut).
        let registry_row = engine.installed_plugins().get(&manifest.plugin.id);
        let (installation_uuid, effective_grant) = match (&mode, registry_row) {
            (LoadMode::Installed { expected }, Some(row))
                if row.installation_uuid == *expected
                    && loaded_dir_matches_registry(wasm_path, &row.path) =>
            {
                // C5 review F3 round-4 F2: hash the SAME
                // in-memory manifest + wasm buffers that
                // `Component::from_binary` will compile
                // from. Reading files again here would
                // reintroduce the TOCTOU window this fix
                // exists to close.
                let on_disk = crate::state::content_digest(manifest_bytes, wasm_bytes);
                if on_disk != *row.content_digest {
                    return Err(anyhow!(
                        "content digest mismatch for plugin {} (installed contents \
                         have been modified since install); reinstall via the API \
                         to re-issue the grant + digest",
                        manifest.plugin.id
                    ));
                }
                let effective = crate::state::effective_capabilities(
                    requested,
                    row.granted_capabilities.as_ref(),
                );
                (row.installation_uuid, Arc::new(effective))
            }
            (LoadMode::Installed { expected }, Some(row)) => {
                // A live row exists but doesn't match — either
                // the uuid rotated (concurrent uninstall +
                // reinstall between the API's `get()` and this
                // load) or the on-disk path drifted from the
                // recorded one. Either way, refuse rather than
                // silently apply a fresh install's grant to what
                // the operator started as install `expected`.
                return Err(anyhow!(
                    "installed plugin {} identity changed between start and load \
                     (expected installation `{expected}`, registry now has \
                     `{live}` at {live_path}); refusing (H11 round-2 F1)",
                    manifest.plugin.id,
                    live = row.installation_uuid,
                    live_path = row.path.display(),
                ));
            }
            (LoadMode::Installed { expected }, None) => {
                // Registry cleared between the API's `get()` and
                // the loader's — concurrent uninstall race.
                // Refuse fail-closed rather than fall back to
                // synthetic identity + manifest-requested caps.
                return Err(anyhow!(
                    "installed plugin {} (installation `{expected}`) disappeared from \
                     the registry between start and load (concurrent uninstall race); \
                     refusing to fall back to dev semantics (H11 round-2 F1)",
                    manifest.plugin.id
                ));
            }
            (LoadMode::Dev, Some(row)) if loaded_dir_matches_registry(wasm_path, &row.path) => {
                let on_disk = crate::state::content_digest(manifest_bytes, wasm_bytes);
                if on_disk != *row.content_digest {
                    return Err(anyhow!(
                        "content digest mismatch for plugin {} (installed contents \
                         have been modified since install); reinstall via the API \
                         to re-issue the grant + digest",
                        manifest.plugin.id
                    ));
                }
                let effective = crate::state::effective_capabilities(
                    requested,
                    row.granted_capabilities.as_ref(),
                );
                (row.installation_uuid, Arc::new(effective))
            }
            (LoadMode::Dev, Some(row)) => {
                // Follow-up review H11: dev-time load whose
                // manifest declares a `plugin_id` that IS
                // installed but at a different path. Was
                // previously fallback-to-synthetic; that shadow
                // let a raw-path load run under manifest-
                // requested capabilities alongside the installed
                // package's identity. Refuse. Dev workflows can
                // uninstall the installation first, or bump the
                // manifest's `plugin_id` for the load under test.
                return Err(anyhow!(
                    "plugin {} is installed at {}, but the loader was pointed at {} — \
                     dev-time loads must not shadow an installed package (H11). \
                     Uninstall the installation first (or use a different plugin_id \
                     in the manifest under test).",
                    manifest.plugin.id,
                    row.path.display(),
                    wasm_path.display(),
                ));
            }
            (LoadMode::Dev, None) => {
                // Genuine dev load: no installed row claims this
                // plugin_id. Synthetic identity + manifest-
                // requested caps. Explicitly opted into via
                // `LoadMode::Dev` — never inferred from registry
                // absence.
                (
                    Arc::<str>::from(manifest.plugin.id.as_str()),
                    Arc::new(requested.clone()),
                )
            }
        };
        let granted_capabilities = effective_grant;

        // Reserve a `kv_usage` row for this instance with the
        // **granted** quota (C5). `register_instance` is
        // idempotent — repeat loads of the same instance id
        // preserve `bytes_used` and only refresh the quota, so
        // an operator-modified grant picks up the new value
        // without wiping data.
        let quota_bytes = granted_capabilities.storage_quota_kb.saturating_mul(1024);
        let kv = engine.kv();
        kv.register_instance(&installation_uuid, &instance_id, quota_bytes)
            .with_context(|| {
                format!(
                    "registering KV usage row for instance {instance_id} \
                     (install {installation_uuid}, quota {quota_bytes} bytes)",
                )
            })?;

        // Phase 5b: reserve a `blob_usage` row for this instance
        // with the **granted** `blob_quota_mb` (C5). Idempotent
        // like the KV register; positive quota lets calls through,
        // zero gates them off at the host call site.
        let blob_quota_bytes = granted_capabilities
            .blob_quota_mb
            .saturating_mul(1024 * 1024);
        let blobs = engine.blobs();
        blobs
            .register_instance(&installation_uuid, &instance_id, blob_quota_bytes)
            .with_context(|| {
                format!(
                    "registering blob usage row for instance {instance_id} \
                     (install {installation_uuid}, quota {blob_quota_bytes} bytes)",
                )
            })?;

        let state = PluginState::new(
            instance_id,
            installation_uuid,
            manifest,
            actor,
            config,
            engine.devices(),
            engine.device_state(),
            engine.events(),
            kv,
            engine.event_log(),
            blobs,
            engine.services(),
            engine.instances(),
        )
        .with_granted_capabilities(granted_capabilities);
        let mut store = Store::new(engine.raw(), state);
        // C4: install the wasmtime resource limiter so linear-memory
        // grows / table extensions / additional instance/memory/table
        // allocations past the module-level ceilings trap at
        // wasmtime's allocation path. The trap surfaces through the
        // supervisor's normal on-trap policy; a `Failed` state is
        // strictly better than an OOM-killed host process.
        store.limiter(|s| &mut s.limits);
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

    /// Call the plugin's exported `execute-service-command` for a
    /// service this instance owns. Phase 7c's `runtime::dispatcher`
    /// routes `host-services::call-service` here on the *owner*
    /// instance's supervisor task — never directly on the caller's,
    /// so the single-`Store` contract is preserved.
    pub async fn execute_service_command(
        &mut self,
        service: ServiceId,
        command: String,
        args: Vec<KeyValue>,
    ) -> anyhow::Result<CommandResult> {
        let data = self.store.data();
        let span = info_span!(
            "plugin.execute_service_command",
            instance_id = %data.instance_id,
            plugin_id = %data.manifest.plugin.id,
            service_id = %service,
            command = %command,
        );
        async {
            self.arm_watchdog();
            self.bindings
                .call_execute_service_command(&mut self.store, &service, &command, &args)
                .await
                .map_err(anyhow::Error::from)
                .context("invoking plugin execute-service-command")
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
        use crate::state::SubscriberMessage;
        let mut events = Vec::new();
        let state = self.store.data_mut();
        for sub in &mut state.subscriptions {
            // C2e: publish filters before enqueue, so every event
            // that reaches `try_recv` already matches. The
            // defensive `matches` check stays in case a future
            // filter shape ends up mutable. Lagged notices are
            // logged and skipped — the supervisor can't do
            // anything useful with them at this layer; if the
            // plugin cares it can subscribe again with more
            // slack, or reconcile via `Logs.Query` / the durable
            // event history.
            while let Ok(SubscriberMessage::Event {
                event: ev,
                skipped_before,
            }) = sub.receiver.try_recv()
            {
                // Follow-up review H4 round-2 F1: lag count now
                // travels with the event; log it (best-effort
                // observability, same shape the pre-fix bare
                // `Lagged` variant produced) then dispatch.
                if skipped_before > 0 {
                    tracing::warn!(
                        subscription_id = sub.id,
                        skipped = skipped_before,
                        "plugin subscription dropped events (C2e per-subscriber queue overflow)",
                    );
                }
                // `Arc::try_unwrap` avoids a clone if we hold the
                // last reference (common case for a single
                // subscriber); otherwise fall back to
                // `Arc::unwrap_or_clone` (Rust 1.76) — clone-on-
                // write per subscription.
                let ev = Arc::unwrap_or_clone(ev);
                if sub.matches(&ev) {
                    events.push(ev);
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

    /// Per-instance wake `Notify` — C2d wake-isolation. Held on
    /// the `PluginState` inside `store.data()` and shared with the
    /// [`EventBus`](crate::state::EventBus) at
    /// `subscribe_with_wake` time. The supervisor's serve loop
    /// awaits `notified()` on this so it only wakes when a
    /// published event matches one of the plugin's active
    /// subscription filters, replacing the pre-C2d unconditional
    /// `subscribe_all()` broadcast wakeup that woke every
    /// supervisor on every publish.
    #[must_use]
    pub fn wake(&self) -> Arc<tokio::sync::Notify> {
        Arc::clone(&self.store.data().wake)
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

#[cfg(test)]
mod loaded_dir_match_tests {
    use super::loaded_dir_matches_registry;
    use std::path::PathBuf;

    fn tempdir(name: &str) -> PathBuf {
        let pid = u64::from(std::process::id());
        let nanos = u64::from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos(),
        );
        let p = std::env::temp_dir().join(format!(
            "oxidhome-loaded-dir-{name}-{}",
            pid.wrapping_mul(1_000_003).wrapping_add(nanos),
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    /// Fixup review F1 (P1): nested `[runtime].wasm` layouts (e.g.
    /// `build/plugin.wasm`) must still match the registry root.
    /// The pre-fix comparison used `wasm_path.parent()` and failed
    /// the guard for legitimate nested layouts.
    #[test]
    fn matches_when_wasm_is_nested_under_registry_root() {
        let root = tempdir("nested-wasm");
        let plugin_root = root.join("plugins").join("example.plugin");
        let build_dir = plugin_root.join("build");
        std::fs::create_dir_all(&build_dir).unwrap();
        let wasm = build_dir.join("plugin.wasm");
        std::fs::write(&wasm, b"\0asm\x01\x00\x00\x00").unwrap();

        assert!(
            loaded_dir_matches_registry(&wasm, &plugin_root),
            "nested build/plugin.wasm must match the plugin root",
        );

        std::fs::remove_dir_all(&root).unwrap();
    }

    /// A wasm loaded from an unrelated directory must NOT match
    /// even if the sibling has a prefix-similar name — the guard
    /// uses component-boundary comparison so `<root>-attacker`
    /// doesn't fool it.
    #[test]
    fn does_not_match_when_wasm_is_outside_the_registry_root() {
        let root = tempdir("outside-wasm");
        let plugin_root = root.join("plugins").join("example.plugin");
        std::fs::create_dir_all(&plugin_root).unwrap();

        let attacker = root.join("plugins").join("example.plugin-attacker");
        std::fs::create_dir_all(&attacker).unwrap();
        let wasm = attacker.join("plugin.wasm");
        std::fs::write(&wasm, b"\0asm\x01\x00\x00\x00").unwrap();

        assert!(
            !loaded_dir_matches_registry(&wasm, &plugin_root),
            "prefix-similar sibling dir must not spuriously match",
        );

        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn matches_flat_layout_at_registry_root() {
        let root = tempdir("flat-wasm");
        let plugin_root = root.join("plugins").join("example.plugin");
        std::fs::create_dir_all(&plugin_root).unwrap();
        let wasm = plugin_root.join("plugin.wasm");
        std::fs::write(&wasm, b"\0asm\x01\x00\x00\x00").unwrap();

        assert!(loaded_dir_matches_registry(&wasm, &plugin_root));

        std::fs::remove_dir_all(&root).unwrap();
    }
}
