//! [`PluginInstance`] — host handle to one running `plugin`-world
//! component. Phase 2 implements the load → init → shutdown cycle.

use std::path::Path;

use anyhow::Context;
use tracing::{Instrument, info_span};
use wasmtime::Store;
use wasmtime::component::{Component, HasSelf, Linker};

use crate::host_impl::plugin::Plugin as PluginBindings;

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
    /// Read a `.wasm` component from disk, build a Linker that satisfies
    /// every import in the `plugin` world (oxidhome host-* + WASI), and
    /// instantiate. Does **not** call [`Self::init`] — callers run that
    /// next.
    pub async fn load(engine: &Engine, wasm_path: &Path) -> anyhow::Result<Self> {
        let span = info_span!("plugin.load", path = %wasm_path.display());
        async move {
            let component = Component::from_file(engine.raw(), wasm_path)
                .map_err(anyhow::Error::from)
                .with_context(|| format!("loading component from {}", wasm_path.display()))?;

            let mut linker: Linker<PluginState> = Linker::new(engine.raw());

            // WASI p2 satisfies the `wasi:cli`, `wasi:io`, `wasi:clocks`
            // etc. imports the plugin's libstd pulls in. Plugin world
            // doesn't expose WASI to the plugin author yet (Phase 7
            // does, via the streaming-plugin world), but the
            // libstd-driven imports still need a real implementation.
            wasmtime_wasi::p2::add_to_linker_async(&mut linker)
                .map_err(anyhow::Error::from)
                .context("adding wasi:p2 to linker")?;

            // Host imports declared by the `plugin` world: host-devices,
            // host-events, host-config, storage, logging. All wired
            // through the bindgen-generated `add_to_linker` against
            // `PluginState`. Phase 2 only logging is functional — the
            // others stub with `Error::Unavailable`.
            PluginBindings::add_to_linker::<_, HasSelf<_>>(&mut linker, |state| state)
                .map_err(anyhow::Error::from)
                .context("adding plugin world host imports to linker")?;

            let instance_id = wasm_path.file_stem().map_or_else(
                || "plugin".to_string(),
                |s| s.to_string_lossy().into_owned(),
            );
            let state = PluginState::new(instance_id);
            let mut store = Store::new(engine.raw(), state);

            let bindings = PluginBindings::instantiate_async(&mut store, &component, &linker)
                .await
                .map_err(anyhow::Error::from)
                .context("instantiating plugin component")?;

            Ok(Self { bindings, store })
        }
        .instrument(span)
        .await
    }

    /// Call the plugin's exported `init`. The plugin returns
    /// `Result<(), String>` per the WIT — we propagate the error
    /// message through `anyhow`.
    pub async fn init(&mut self) -> anyhow::Result<()> {
        let span = info_span!("plugin.init", instance_id = %self.store.data().instance_id);
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
        let span = info_span!("plugin.shutdown", instance_id = %self.store.data().instance_id);
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

    /// The instance id this state was built with. Currently the plugin's
    /// filename stem; Phase 6 swaps in the manifest-declared id.
    #[must_use]
    pub fn instance_id(&self) -> &str {
        &self.store.data().instance_id
    }
}
