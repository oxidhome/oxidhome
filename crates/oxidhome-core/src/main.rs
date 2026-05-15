//! `oxidhome` host runtime entrypoint.
//!
//! Loads one plugin from its install directory (containing
//! `manifest.toml` + the `.wasm` it points at), runs `init()` →
//! `shutdown()`, prints the round-trip on stdout via
//! `tracing-subscriber`. Phase 6+ grows this into a real daemon with
//! multi-instance lifecycle, the external API (Phase 12), the UI
//! (Phase 13), and the MCP server (Phase 14).

use std::path::PathBuf;

use anyhow::Context;
use oxidhome_core::{Engine, PluginInstance};
use tracing_subscriber::{EnvFilter, fmt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    let plugin_dir: PathBuf = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "usage: {} <plugin-dir>   (directory containing manifest.toml + the .wasm)",
                env!("CARGO_BIN_NAME"),
            )
        })?;

    let engine = Engine::new()?;
    // Phase 4: the host accepts one plugin at a time and mints the
    // instance id from the directory name. Phase 6's lifecycle layer
    // will read multiple plugins from a host config file and mint
    // per-config-row ids.
    let instance_id = plugin_dir
        .file_name()
        .map_or_else(|| "plugin".to_owned(), |s| s.to_string_lossy().into_owned());
    let mut instance = PluginInstance::load(&engine, &plugin_dir, &instance_id)
        .await
        .with_context(|| format!("loading plugin from {}", plugin_dir.display()))?;
    tracing::info!(instance_id = %instance_id, "plugin loaded");

    instance.init().await?;
    instance.shutdown().await?;

    Ok(())
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = fmt().with_env_filter(filter).try_init();
}
