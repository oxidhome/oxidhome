//! [`PluginInstance`] — host handle to one running `plugin`-world
//! component. Phase 2 implements the load → init → shutdown cycle;
//! Phase 4 wraps it in the manifest loader so every loaded plugin
//! carries its declared identity, capabilities, and resolved
//! per-instance config.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

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
use super::sandbox::SandboxRole;
use super::state::PluginState;
use super::watchdog;

/// A supervisor's compiled component, kept for its whole lifetime so a
/// restart (and, for a scripting plugin, every sandbox it starts and
/// their restarts) instantiates it again instead of compiling the
/// `.wasm` again (ADR-0001).
///
/// Filled by the supervisor's first successful load. A supervisor's
/// manifest is pinned for its lifetime, and so are the bytes this
/// holds: a sandbox runs exactly the code its parent runs, even in a
/// dev load whose `.wasm` was rebuilt since. A reinstall or upgrade
/// means a new supervisor (stop, uninstall, install, start) and so a
/// new cache; a load that resolves a different installation than the
/// one the component was compiled under is refused rather than served
/// from here.
#[derive(Debug, Default)]
pub(crate) struct ComponentCache {
    slot: Mutex<Option<Arc<CachedComponent>>>,
}

/// The pinned bytes and compiled component in a [`ComponentCache`].
pub(crate) struct CachedComponent {
    wasm_path: PathBuf,
    wasm_bytes: Arc<[u8]>,
    component: Component,
    /// The installation the component was first loaded under.
    installation_uuid: Arc<str>,
}

impl std::fmt::Debug for CachedComponent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedComponent")
            .field("wasm_path", &self.wasm_path)
            .field("installation_uuid", &self.installation_uuid)
            .finish_non_exhaustive()
    }
}

impl ComponentCache {
    fn get(&self) -> Option<Arc<CachedComponent>> {
        self.slot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Keep the first component; a later fill (two sandboxes of a
    /// parent whose cache was still empty) is dropped.
    fn fill(&self, cached: CachedComponent) {
        self.slot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get_or_insert_with(|| Arc::new(cached));
    }
}

/// What a supervised load adds to a plain one.
#[derive(Default)]
pub(crate) struct SupervisedLoad<'a> {
    /// The supervisor's component cache, if it keeps one.
    pub(crate) cache: Option<&'a ComponentCache>,
    /// ADR-0001: the instance's place in the sandbox model, set on its
    /// state before the component is instantiated.
    pub(crate) sandbox: Option<SandboxRole>,
}

/// The component cache handed to `instantiate`, and what it already
/// holds.
#[derive(Default, Clone, Copy)]
struct Compiled<'a> {
    cache: Option<&'a ComponentCache>,
    cached: Option<&'a CachedComponent>,
}

/// Item 8 of the ADR-0001 follow-ups: the embedder entry points
/// (`PluginInstance::load*`, `supervise*`) don't go through the
/// instance registry, so they check here that `instance_id` is one an
/// operator may use and that no registered instance runs under it.
pub(crate) fn check_embedder_instance_id(engine: &Engine, instance_id: &str) -> anyhow::Result<()> {
    if !super::is_operator_instance_id(instance_id) {
        return Err(anyhow!(
            "instance-id `{}` is not permitted (unsafe, or contains `{}`, which is reserved \
             for script sandboxes)",
            crate::auth::invocation::audit_cap(instance_id),
            super::SANDBOX_SEPARATOR,
        ));
    }
    if engine.instances().get(instance_id).is_some() {
        return Err(anyhow!(
            "instance-id `{instance_id}` belongs to a running supervised instance"
        ));
    }
    Ok(())
}

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

/// Phase 6 leftover TOCTOU fix: bytes-capturing manifest read.
/// Returns both the raw manifest bytes and the parsed
/// `PluginManifest`, so [`crate::Engine::start_instance`] can
/// pin the pre-flight snapshot and hand it to the supervisor's
/// first load without a second read from disk. The
/// bytes-discarding wrapper (`read_manifest`) that used to sit
/// alongside this function was removed once its sole caller
/// switched over — the parsed-only variant added zero value
/// beyond the tuple destructure.
///
/// The bytes come back as `Vec<u8>` (not `String`) because the
/// downstream `PluginInstance::load_with_mode` path already works
/// in `&[u8]` — feeding them straight through avoids a re-UTF-8
/// check.
pub async fn read_manifest_with_bytes(
    plugin_dir: &Path,
) -> anyhow::Result<(Vec<u8>, PluginManifest)> {
    let manifest_path = plugin_dir.join("manifest.toml");
    let bytes = tokio::fs::read(&manifest_path).await.with_context(|| {
        format!(
            "reading manifest from {} (does the plugin dir contain manifest.toml?)",
            manifest_path.display(),
        )
    })?;
    let text = std::str::from_utf8(&bytes)
        .with_context(|| format!("manifest {} is not UTF-8", manifest_path.display()))?;
    let manifest: PluginManifest =
        toml::from_str(text).with_context(|| format!("parsing {}", manifest_path.display()))?;
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
    Ok((bytes, manifest))
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
    /// Phase 11 (M5): dev-time load with an explicit, caller-supplied
    /// grant — the `oxidhome-test-host` harness's capability
    /// injection. Never shadows an installed package: the loader
    /// refuses whenever a registry row claims `manifest.plugin.id`.
    /// Otherwise the grant goes through the same boundary an
    /// installed grant does: the capability-count caps
    /// ([`oxidhome_manifest::check_capability_limits_owned`]) and
    /// the requested ∩ granted intersection
    /// ([`crate::state::effective_capabilities`]), so a caller
    /// can't authorize anything the manifest doesn't request.
    Granted {
        granted: Arc<oxidhome_manifest::CapabilitiesSection>,
    },
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
    ///    This is a secondary signal: the manifest is the author's
    ///    claim.
    /// 4. Resolve the per-instance config (`merge` with the
    ///    optional override blob).
    /// 5. Prove from the component binary that its WIT types match
    ///    this host's `oxidhome:plugin` contract
    ///    ([`super::contract::verify_component`]).
    /// 6. Instantiate the wasm component.
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
        let instance_id = instance_id.into();
        check_embedder_instance_id(engine, &instance_id)?;
        Self::load_supervised(
            engine,
            plugin_dir,
            instance_id,
            overrides,
            mode,
            None,
            SupervisedLoad::default(),
        )
        .await
    }

    /// Phase 6 leftover TOCTOU fix + round-2 F3: like
    /// [`Self::load_with_mode`], but skips the on-disk
    /// manifest read and uses the supplied pre-parsed
    /// `(manifest_bytes, manifest)` instead. Used on every
    /// load attempt inside `run_supervisor` (first load
    /// AND every restart), so `start_instance`'s
    /// pre-flight parse — which decided the singleton slot
    /// + `plugin_id` — is the same manifest that
    /// instantiates for the supervisor's lifetime. A
    /// legitimate reinstall between crashes goes through
    /// the install/uninstall API path (per-plugin
    /// lifecycle lock), which starts a fresh supervisor
    /// with a fresh pin.
    #[doc(hidden)]
    pub async fn load_with_pinned_manifest(
        engine: &Engine,
        plugin_dir: &Path,
        instance_id: impl Into<String>,
        overrides: Option<&toml::Value>,
        mode: LoadMode,
        manifest_bytes: Vec<u8>,
        manifest: PluginManifest,
    ) -> anyhow::Result<Self> {
        let instance_id = instance_id.into();
        check_embedder_instance_id(engine, &instance_id)?;
        Self::load_supervised(
            engine,
            plugin_dir,
            instance_id,
            overrides,
            mode,
            Some((manifest_bytes, manifest)),
            SupervisedLoad::default(),
        )
        .await
    }

    /// The load behind every entry point. The supervisor calls it
    /// directly: its instance id is registered (so the embedder check
    /// would refuse it), and it brings its component cache and sandbox
    /// role.
    pub(crate) async fn load_supervised(
        engine: &Engine,
        plugin_dir: &Path,
        instance_id: String,
        overrides: Option<&toml::Value>,
        mode: LoadMode,
        pinned: Option<(Vec<u8>, PluginManifest)>,
        supervised: SupervisedLoad<'_>,
    ) -> anyhow::Result<Self> {
        let plugin_dir = plugin_dir.to_path_buf();
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
            // Phase 6 leftover TOCTOU fix + round-2 F3:
            // if the caller passed a pre-parsed manifest
            // snapshot, use those exact bytes rather than
            // re-reading. The supervisor supplies the
            // pre-flight snapshot on EVERY load attempt so
            // the manifest whose `plugin_id` / `singleton`
            // flag decided the registry slot is the manifest
            // that instantiates for the supervisor's
            // lifetime. `None` reaches this branch only via
            // the un-pinned test-suite paths (`supervise` /
            // `supervise_with_tuning`); those re-read from
            // disk on every attempt.
            let (manifest_bytes, manifest) = if let Some((bytes, manifest)) = pinned {
                (bytes, manifest)
            } else {
                // C5 review F3 round-4 F2: read the manifest
                // as **raw bytes** so the same buffer feeds
                // both parse and the load-time digest check
                // further down. Reading as `String` and then
                // re-reading for the hash would reintroduce
                // the TOCTOU window this fix exists to close.
                let manifest_bytes = tokio::fs::read(&manifest_path).await.with_context(|| {
                    format!(
                        "reading manifest from {} (does the plugin dir contain manifest.toml?)",
                        manifest_path.display(),
                    )
                })?;
                let manifest_text = std::str::from_utf8(&manifest_bytes).with_context(|| {
                    format!("manifest {} is not UTF-8", manifest_path.display())
                })?;
                let manifest: PluginManifest = toml::from_str(manifest_text)
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
                (manifest_bytes, manifest)
            };
            // Record the plugin id onto the active span as soon as
            // it's known. Validation, compatibility-check, and
            // instantiate-time events below will all attribute to
            // it via the Layer's `on_record` hook.
            tracing::Span::current().record("plugin_id", manifest.plugin.id.as_str());

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

            // ADR-0001 follow-up: a supervisor that already compiled
            // the component reuses its bytes and compiled form.
            let cached = supervised.cache.and_then(ComponentCache::get);
            let (wasm_path, wasm_bytes) = if let Some(cached) = &cached {
                (cached.wasm_path.clone(), Arc::clone(&cached.wasm_bytes))
            } else {
                let wasm_path = resolve_wasm_path(&plugin_dir, &manifest.runtime.wasm)?;
                // C5 review F3 round-4 F2: read wasm bytes into
                // memory once, then feed those same bytes to BOTH
                // the digest verification and wasmtime's
                // `Component::from_binary`. That closes the TOCTOU
                // window where an on-disk rewrite between the
                // digest walk and `Component::from_file` could sneak
                // modified code past the check.
                let wasm_bytes = tokio::fs::read(&wasm_path).await.with_context(|| {
                    format!("reading wasm component from {}", wasm_path.display())
                })?;
                (wasm_path, Arc::<[u8]>::from(wasm_bytes))
            };
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
                Compiled {
                    cache: supervised.cache,
                    cached: cached.as_deref(),
                },
                supervised.sandbox,
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
        let instance_id = instance_id.into();
        check_embedder_instance_id(engine, &instance_id)?;
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
        let wasm_bytes: Arc<[u8]> = tokio::fs::read(wasm_path)
            .await
            .with_context(|| format!("reading wasm from {}", wasm_path.display()))?
            .into();
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
            Compiled::default(),
            None,
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
        wasm_bytes: &Arc<[u8]>,
        instance_id: impl Into<String>,
        manifest: Arc<PluginManifest>,
        config: InstanceConfig,
        mode: LoadMode,
        compiled: Compiled<'_>,
        sandbox: Option<SandboxRole>,
    ) -> anyhow::Result<Self> {
        // C5 review F3 round-4 F2: instantiate from the same
        // in-memory wasm bytes the digest check will read, not
        // from the on-disk file. That closes the TOCTOU window
        // where an attacker with FS write access could swap
        // `plugin.wasm` between the digest walk and
        // `Component::from_file`.
        let instance_id = instance_id.into();
        let component = if let Some(cached) = compiled.cached {
            // Verified and compiled from these same bytes by an
            // earlier load of this supervisor.
            cached.component.clone()
        } else {
            // M1: prove from the binary itself that the component was
            // built against this host's `oxidhome:plugin` contract. The
            // manifest's `sdk_version` (checked earlier) is only the
            // author's claim; this is the authoritative check, and it
            // runs on the same in-memory bytes that get compiled.
            super::contract::verify_component(wasm_bytes).with_context(|| {
                format!(
                    "rejecting plugin {} (instance {}): component {} is incompatible with this \
                     host's WIT contract",
                    manifest.plugin.id,
                    instance_id,
                    wasm_path.display(),
                )
            })?;
            engine.note_component_compile();
            Component::from_binary(engine.raw(), wasm_bytes)
                .map_err(anyhow::Error::from)
                .with_context(|| format!("loading component from {}", wasm_path.display()))?
        };

        let mut linker: Linker<PluginState> = Linker::new(engine.raw());

        // WASI p2 satisfies the `wasi:cli`, `wasi:io`, `wasi:clocks`
        // etc. imports the plugin's libstd pulls in. Phase 8: only the
        // streaming worlds also get `wasi:sockets` and `wasi:http`
        // (plus the `host-media` placeholders); a `plugin`-world
        // component importing them fails to instantiate.
        super::network::add_wasi_to_linker(&mut linker, manifest.plugin.world)
            .context("adding WASI to linker")?;

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
                // C5 review F3 round-4 F2 + Phase 13
                // round-3 F2: hash the SAME in-memory
                // manifest + wasm buffers that
                // `Component::from_binary` will compile
                // from, PLUS every declared UI asset read
                // from `plugin_dir` on the way in. Reading
                // manifest / wasm files again here would
                // reintroduce the TOCTOU window this fix
                // exists to close; UI assets are read fresh
                // because the loader doesn't hold them in
                // memory, but the digest still catches a
                // post-install swap on the next start.
                let on_disk = crate::state::recompute_installed_digest(
                    plugin_dir,
                    manifest.as_ref(),
                    manifest_bytes,
                    wasm_bytes,
                )
                .map_err(|reason| {
                    anyhow!(
                        "failed to recompute content digest for plugin {}: {}",
                        manifest.plugin.id,
                        reason
                    )
                })?;
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
                let on_disk = crate::state::recompute_installed_digest(
                    plugin_dir,
                    manifest.as_ref(),
                    manifest_bytes,
                    wasm_bytes,
                )
                .map_err(|reason| {
                    anyhow!(
                        "failed to recompute content digest for plugin {}: {}",
                        manifest.plugin.id,
                        reason
                    )
                })?;
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
            (LoadMode::Granted { .. }, Some(row)) => {
                // Same shadowing hazard as the `Dev` arms above,
                // but an injected grant is never allowed to stand
                // in for an operator-issued one: refuse outright.
                return Err(anyhow!(
                    "plugin {} is installed at {}; an explicitly granted dev-time load \
                     must not shadow an installed package",
                    manifest.plugin.id,
                    row.path.display(),
                ));
            }
            (LoadMode::Granted { granted }, None) => {
                // Phase 11 (M5): validate the injected grant exactly
                // like a persisted one, then intersect it with the
                // manifest's request — the same two steps the
                // installed arms above apply.
                oxidhome_manifest::check_capability_limits_owned(granted).map_err(|errors| {
                    anyhow!(
                        "grant for plugin {} is invalid:\n  - {}",
                        manifest.plugin.id,
                        errors
                            .iter()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>()
                            .join("\n  - "),
                    )
                })?;
                let effective = crate::state::effective_capabilities(requested, granted);
                (
                    Arc::<str>::from(manifest.plugin.id.as_str()),
                    Arc::new(effective),
                )
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
        // A cached component belongs to the installation it was
        // compiled under; a different one (a reinstall racing a
        // restart) gets a fresh supervisor, not these bytes.
        if let Some(cached) = compiled.cached
            && cached.installation_uuid != installation_uuid
        {
            return Err(anyhow!(
                "plugin {} is now installation `{installation_uuid}`, but this supervisor \
                 compiled installation `{}`; stop and start the instance to load it",
                manifest.plugin.id,
                cached.installation_uuid,
            ));
        }

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

        let manifest_world = manifest.plugin.world;
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
        .with_granted_capabilities(granted_capabilities)
        .with_audit_log(engine.audit_log())
        .with_pending_commands(engine.pending_commands());
        // Phase 8: streaming worlds get sockets, checked against the
        // effective `network` rules set just above.
        let state = if super::network::is_streaming(manifest_world) {
            state.with_network_access()
        } else {
            state
        };
        // ADR-0001: the role is in place before any guest code runs,
        // component start functions included.
        let mut state = state;
        state.sandbox = sandbox;
        // Publish the verified component before any guest code runs,
        // so a sandbox started from it can't compile other bytes.
        if compiled.cached.is_none()
            && let Some(cache) = compiled.cache
        {
            cache.fill(CachedComponent {
                wasm_path: wasm_path.to_path_buf(),
                wasm_bytes: Arc::clone(wasm_bytes),
                component: component.clone(),
                installation_uuid: Arc::clone(&state.installation_uuid),
            });
        }
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
                    let msg = self.scrub_own_secrets(format!("{err:#}"));
                    if watchdog::is_watchdog_trap(&err) {
                        Err(InitError::Unresponsive(msg))
                    } else {
                        Err(InitError::Trap(msg))
                    }
                }
                Ok(Err(msg)) => Err(InitError::Plugin(self.scrub_own_secrets(msg))),
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

    /// Call the plugin's exported `on-shutdown`. The plugin can't fail this
    /// call by contract; trapping bubbles up as an error.
    ///
    /// Bounded by the watchdog deadline in wall-clock time too: the
    /// epoch watchdog only interrupts guest code, so a hook blocked in
    /// a host import (a WASI `sleep`, say) is cancelled when the
    /// deadline passes instead. Either way the call fails and the
    /// instance must not be entered again.
    pub async fn shutdown(&mut self) -> anyhow::Result<()> {
        let data = self.store.data();
        let span = info_span!(
            "plugin.shutdown",
            instance_id = %data.instance_id,
            plugin_id = %data.manifest.plugin.id,
        );
        let deadline = self.watchdog;
        async {
            self.arm_watchdog();
            match tokio::time::timeout(deadline, self.bindings.call_on_shutdown(&mut self.store))
                .await
            {
                Ok(result) => result
                    .map_err(anyhow::Error::from)
                    .context("invoking plugin shutdown"),
                Err(_) => Err(anyhow!(
                    "plugin shutdown did not return within {deadline:?}; cancelled"
                )),
            }
        }
        .instrument(span)
        .await
    }

    /// H5: the engine's pending-command table, which also records the
    /// `COMMAND` rows of results its callers no longer wait for.
    pub(crate) fn pending_commands(&self) -> Option<Arc<super::PendingCommands>> {
        self.store.data().pending_commands.clone()
    }

    /// Call the plugin's exported `execute-command` for a device this
    /// instance owns. Phase 3's host-side command routing (in tests
    /// today, in the API/MCP layers later) looks up the device's
    /// owner in [`DeviceRegistry`](crate::DeviceRegistry) and calls
    /// this method on the matching [`PluginInstance`].
    ///
    /// H5: `cmd.id` is the host-minted command id. An `accepted` reply
    /// is registered in the engine's pending-command table here (so
    /// supervised and directly-driven instances behave alike); when it
    /// can't be tracked the reply becomes `unknown`, because the plugin
    /// believes it holds the command.
    pub async fn execute_command(
        &mut self,
        device: DeviceId,
        cmd: Command,
    ) -> anyhow::Result<CommandResult> {
        let data = self.store.data();
        let span = info_span!(
            "plugin.execute_command",
            // H6: the invocation the supervisor scoped around this
            // call (empty for direct, unsupervised calls).
            call_id = crate::auth::invocation::current()
                .map_or_default(|c| c.call_id().to_owned()),
            instance_id = %data.instance_id,
            plugin_id = %data.manifest.plugin.id,
            device_id = %device,
            capability = %cmd.capability,
            action = %cmd.action,
        );
        // Snapshot the identity + capability + owner before the
        // move-into-`call_execute_command` so the H9 projection
        // hook below can attribute an `OkWithState` return to the
        // correct `(device, capability)` slot with the owning
        // instance id.
        let capability = cmd.capability.clone();
        let command_id = cmd.id.clone();
        let device_for_projection = device.clone();
        let owner_instance = data.instance_id.clone();
        let result = async {
            self.arm_watchdog();
            self.bindings
                .call_execute_command(&mut self.store, &device, &cmd)
                .await
                .map_err(anyhow::Error::from)
                .context("invoking plugin execute-command")
        }
        .instrument(span)
        .await?;
        let mut result = result;
        super::command::scrub_and_cap_reply(
            &mut result,
            &crate::redact::config_secrets(&self.store.data().config),
        );
        // H9: `OkWithState` is authoritative state — validate and
        // project it (see `project_command_state`).
        let mut reply = self.map_command_reply(
            result,
            &command_id,
            &owner_instance,
            &device_for_projection,
            &capability,
        );
        // M7: a host-built `unknown` (projection refusal) can quote
        // plugin-registered text such as a unit label.
        if matches!(reply, CommandResult::Unknown(_)) {
            super::command::scrub_and_cap_reply(
                &mut reply,
                &crate::redact::config_secrets(&self.store.data().config),
            );
        }
        Ok(reply)
    }

    /// Project `ok-with-state` and register `accepted` (H5) for a
    /// scrubbed `execute-command` reply.
    fn map_command_reply(
        &self,
        result: CommandResult,
        command_id: &str,
        owner_instance: &str,
        device_for_projection: &DeviceId,
        capability: &str,
    ) -> CommandResult {
        let data = self.store.data();
        match result {
            CommandResult::OkWithState(fields) => project_command_state(
                &data.devices,
                &data.device_state,
                owner_instance,
                device_for_projection,
                capability,
                fields,
            ),
            CommandResult::Accepted => {
                let tracked = match &data.pending_commands {
                    Some(table) => table.register(
                        command_id,
                        owner_instance,
                        device_for_projection,
                        capability,
                        crate::auth::invocation::current_or_host(owner_instance),
                    ),
                    None => Err("this host cannot track accepted commands".to_owned()),
                };
                match tracked {
                    Ok(()) => CommandResult::Accepted,
                    Err(why) => {
                        tracing::warn!(
                            instance_id = %owner_instance,
                            command_id = %command_id,
                            reason = %why,
                            "execute-command returned accepted but the host can't track it",
                        );
                        CommandResult::Unknown(format!(
                            "plugin accepted the command but the host cannot track it: {why}"
                        ))
                    }
                }
            }
            other => other,
        }
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
            call_id = crate::auth::invocation::current()
                .map_or_default(|c| c.call_id().to_owned()),
            instance_id = %data.instance_id,
            plugin_id = %data.manifest.plugin.id,
            service_id = %service,
            command = %command,
        );
        let result = async {
            self.arm_watchdog();
            self.bindings
                .call_execute_service_command(&mut self.store, &service, &command, &args)
                .await
                .map_err(anyhow::Error::from)
                .context("invoking plugin execute-service-command")
        }
        .instrument(span)
        .await?;
        let mut result = result;
        super::command::scrub_and_cap_reply(
            &mut result,
            &crate::redact::config_secrets(&self.store.data().config),
        );
        // H5: service commands complete synchronously. A callee that
        // answers `accepted` may still act later, so the caller hears
        // `unknown`, never `accepted`.
        Ok(match result {
            CommandResult::Accepted => CommandResult::Unknown(
                "service commands complete synchronously; the callee answered `accepted`".into(),
            ),
            other => other,
        })
    }

    /// M7: replace this instance's declared secret values in
    /// plugin-authored text (an `init` error, a trap message) before it
    /// reaches the supervisor's logs or the instance state.
    fn scrub_own_secrets(&self, text: String) -> String {
        match crate::redact::scrub_secret_values(
            &text,
            &crate::redact::config_secrets(&self.store.data().config),
        ) {
            std::borrow::Cow::Owned(scrubbed) => scrubbed,
            std::borrow::Cow::Borrowed(_) => text,
        }
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
        let state = self.store.data_mut();
        // Every event with a row id up to `cutoff` has finished its
        // fan-out (it is in every matching queue); later ones may not
        // have yet.
        let cutoff = state.events.row_watermark().get();
        // One FIFO run per subscription, merged below.
        let mut runs: Vec<VecDeque<(u64, Event)>> = Vec::new();
        for sub in &mut state.subscriptions {
            let mut events = VecDeque::new();
            // A held event goes first; while it is still above the
            // cutoff, the rest of its queue waits behind it (FIFO).
            if let Some((rows_through, ev)) = sub.held.take() {
                if rows_through > cutoff {
                    sub.held = Some((rows_through, ev));
                    continue;
                }
                events.push_back((rows_through, ev));
            }
            // Take at most what is queued now, so publishers refilling
            // the queue can't keep this drain going.
            let queued = sub.receiver.len();
            // C2e: publish filters before enqueue, so every event
            // that reaches `try_recv` already matches. The
            // defensive `matches` check stays in case a future
            // filter shape ends up mutable. Lagged notices are
            // logged and skipped — the supervisor can't do
            // anything useful with them at this layer; if the
            // plugin cares it can subscribe again with more
            // slack, or reconcile via `Logs.Query` / the durable
            // event history.
            for _ in 0..queued {
                let Ok(SubscriberMessage::Event {
                    event: ev,
                    skipped_before,
                    rows_through,
                }) = sub.receiver.try_recv()
                else {
                    break;
                };
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
                if !sub.matches(&ev) {
                    continue;
                }
                // A recorded event fanned out after the cutoff may
                // have an older row still on its way to another
                // queue: hold it, and leave the rest of this queue
                // for the next drain. Its publisher raises the
                // watermark and then wakes this subscription
                // (`notify_one` keeps a permit), so that drain comes.
                // Events without a row id are never held: nothing
                // would wake the plugin for them.
                if rows_through > cutoff && ev.row_id.is_some() {
                    sub.held = Some((rows_through, ev));
                    break;
                }
                events.push_back((rows_through, ev));
            }
            if !events.is_empty() {
                runs.push(events);
            }
        }
        // Each subscription has its own queue, so draining them one
        // after another can hand over row 12 before row 11. Plugins
        // resuming from a `row-id` cursor (`host-events::read-events`)
        // need row-id order, so: recorded publishes are serialized,
        // `rows_through` is the bus watermark at each fan-out (an
        // event's own row id, or the last one fanned out before an
        // event without one), and recorded events above the cutoff
        // are held (above). The queues are merged by their front
        // entries, so no event overtakes an earlier one from its own
        // queue (an unserialized event without a row id can carry a
        // key above a later recorded one). Ties keep subscription
        // order.
        merge_queues(runs)
    }

    /// The instance id this state was built with. Currently the plugin's
    /// filename stem; Phase 6 swaps in the manifest-declared id.
    #[must_use]
    pub fn instance_id(&self) -> &str {
        &self.store.data().instance_id
    }

    /// The host-minted installation UUID this instance was
    /// loaded against — the same `inst-<32 hex>` value the
    /// installed-plugin registry pinned at install time (dev /
    /// argv loads mint a synthetic one at load time). Held on
    /// [`PluginState`] as an `Arc<str>` so cloning is cheap;
    /// the supervisor grabs a clone after each successful load
    /// so [`InstanceHandle::installation_uuid`](crate::InstanceHandle::installation_uuid) can hand it
    /// back to callers (e.g. MCP `oxidhome://blobs/...` reads)
    /// without going through the installed-plugin registry
    /// (which doesn't have a row for dev / argv instances).
    #[must_use]
    pub fn installation_uuid(&self) -> Arc<str> {
        Arc::clone(&self.store.data().installation_uuid)
    }

    /// The resolved manifest this instance was loaded from. The
    /// Phase-6 supervisor reads `runtime.tick_interval_ms` and
    /// `runtime.restart` off this to decide its tick cadence and
    /// crash-recovery behaviour.
    #[must_use]
    pub fn manifest(&self) -> &PluginManifest {
        &self.store.data().manifest
    }

    /// The resolved per-instance config, secrets included. Host-side
    /// only: read surfaces must go through
    /// [`crate::redact::masked_config_view`].
    #[must_use]
    pub fn config(&self) -> &InstanceConfig {
        &self.store.data().config
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

/// Validate and project an `ok-with-state` command reply into the
/// device-state store (H9). Shared by a synchronous `execute-command`
/// reply and an asynchronous `complete-command` (H5); returns the
/// canonicalized reply.
///
/// - Round-3 findings 1/2: the reply is the plugin's authoritative
///   post-command state, so it *replaces* the slot, and it is
///   re-validated after the guest call — a plugin may have removed the
///   device mid-call, or named a capability the device doesn't
///   declare; both skip the projection with a warn.
/// - Round-18 finding 2: the per-slot cap is enforced first, before any
///   ownership / capability check, on borrowed data.
/// - Round-19 finding 1: canonicalization consumes the owned vec, so a
///   large reply is never cloned field by field.
///
/// A reply whose state violates the projection contract (size caps,
/// sensor units) becomes `unknown`, not `err`: the plugin reported
/// success, so the command may well have taken effect, but the host
/// can't vouch for the report (H5: `err` means "did not act").
pub(crate) fn project_command_state(
    devices: &crate::state::DeviceRegistry,
    device_state: &crate::state::DeviceStateStore,
    owner_instance: &str,
    device: &DeviceId,
    capability: &str,
    fields: Vec<KeyValue>,
) -> CommandResult {
    if let Err(overflow) = crate::state::DeviceStateStore::check_snapshot_admission(&fields) {
        tracing::warn!(
            instance_id = %owner_instance,
            device_id = %device,
            capability = %capability,
            overflow = %overflow,
            "command OkWithState exceeds the per-slot cap; reporting outcome_unknown",
        );
        return CommandResult::Unknown(format!(
            "plugin reported success, but its state for `{device}/{capability}` would \
             exceed the projection's per-slot cap ({overflow})",
        ));
    }
    let projection_ok = if let Ok(meta) = devices.get(owner_instance, device) {
        let capability_declared = meta
            .info
            .capabilities
            .iter()
            .any(|spec| super::state::capability_name(spec) == capability);
        if !capability_declared {
            tracing::warn!(
                instance_id = %owner_instance,
                device_id = %device,
                capability = %capability,
                "command returned OkWithState for a capability the device doesn't \
                 declare; skipping state projection",
            );
        }
        // M2: a sensor reading must carry the spec's unit.
        if let Err(e) = super::schema::check_sensor_fields(&meta.info, capability, &fields) {
            // The detail quotes plugin-registered labels (Debug-escaped,
            // so exact-value secret scrubbing can miss them): log it,
            // keep it out of the caller's message.
            tracing::warn!(
                instance_id = %owner_instance,
                device_id = %device,
                capability = %capability,
                error = %e,
                "command OkWithState fails the sensor spec; reporting outcome_unknown",
            );
            return CommandResult::Unknown(format!(
                "plugin reported success, but its state for `{device}/{capability}` does \
                 not match the device's sensor spec"
            ));
        }
        capability_declared
    } else {
        tracing::warn!(
            instance_id = %owner_instance,
            device_id = %device,
            "command returned OkWithState for a device this instance no longer owns; \
             skipping state projection",
        );
        false
    };
    // H9 round-16 finding 2: per-instance aggregate-bytes cap, same
    // semantics as the per-slot cap.
    if projection_ok
        && let Err(overflow) = device_state.check_instance_snapshot_admission(
            device,
            owner_instance,
            capability,
            &fields,
        )
    {
        tracing::warn!(
            instance_id = %owner_instance,
            device_id = %device,
            capability = %capability,
            overflow = %overflow,
            "command OkWithState exceeds the per-instance cap; reporting outcome_unknown",
        );
        return CommandResult::Unknown(format!(
            "plugin reported success, but its state for `{device}/{capability}` would \
             exceed the projection's per-instance aggregate cap ({overflow})",
        ));
    }
    // Runs unconditionally so the projection write and the returned
    // reply see the same last-wins vec.
    let canonical = crate::state::DeviceStateStore::canonicalize_snapshot_fields(fields);
    if projection_ok {
        let received_ms = crate::state::event_log::now_unix_ms();
        device_state.replace_snapshot(
            device.to_owned(),
            owner_instance.to_owned(),
            capability.to_owned(),
            canonical.clone(),
            0, // observed_ms — commands don't carry a plugin timestamp
            received_ms,
        );
    }
    CommandResult::OkWithState(canonical)
}

/// Merge per-subscription FIFO runs of `(rows_through, event)` by
/// their front entries' `(rows_through, row-id)` (no row id sorts
/// last), so no event overtakes an earlier one from its own run. Ties
/// keep run order.
fn merge_queues(mut queues: Vec<VecDeque<(u64, Event)>>) -> Vec<Event> {
    let key = |(rows_through, ev): &(u64, Event)| (*rows_through, ev.row_id.unwrap_or(u64::MAX));
    let mut merged = Vec::with_capacity(queues.iter().map(VecDeque::len).sum());
    while let Some(next) = queues
        .iter()
        .enumerate()
        .filter_map(|(i, q)| q.front().map(|front| (key(front), i)))
        .min()
        .map(|(_, i)| i)
    {
        if let Some((_, ev)) = queues[next].pop_front() {
            merged.push(ev);
        }
    }
    merged
}

#[cfg(test)]
mod merge_queues_tests {
    use super::*;
    use crate::host_impl::plugin::oxidhome::plugin::events::{CustomEvent, EventPayload};

    fn ev(topic: &str, row_id: Option<u64>) -> Event {
        Event {
            device: None,
            timestamp: 0,
            payload: EventPayload::Custom(CustomEvent {
                topic: topic.into(),
                payload: String::new(),
            }),
            origin_plugin_id: "p".into(),
            origin_instance_id: "i".into(),
            row_id,
        }
    }

    fn topics(events: &[Event]) -> Vec<String> {
        events
            .iter()
            .map(|e| match &e.payload {
                EventPayload::Custom(c) => c.topic.clone(),
                _ => unreachable!(),
            })
            .collect()
    }

    #[test]
    fn merges_by_row_id_across_queues() {
        let a = VecDeque::from([(10, ev("a10", Some(10))), (12, ev("a12", Some(12)))]);
        let b = VecDeque::from([(11, ev("b11", Some(11))), (12, ev("b-live", None))]);
        assert_eq!(
            topics(&merge_queues(vec![a, b])),
            ["a10", "b11", "a12", "b-live"]
        );
    }

    #[test]
    fn never_reorders_within_a_queue() {
        // A rowless event stamped with a watermark its recorded
        // successor hadn't enqueued yet still goes first.
        let a = VecDeque::from([(11, ev("live", None)), (11, ev("row11", Some(11)))]);
        let b = VecDeque::from([(11, ev("b11", Some(11)))]);
        assert_eq!(topics(&merge_queues(vec![a, b])), ["b11", "live", "row11"]);
    }
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
