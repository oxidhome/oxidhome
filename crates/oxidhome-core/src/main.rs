//! `oxidhome` host runtime, Phase 2 entrypoint.
//!
//! Loads one `.wasm` plugin component, runs `init()` → `shutdown()`,
//! prints the round-trip on stdout via `tracing-subscriber`. Phase 6+
//! grows this into a real daemon with multi-instance lifecycle, the
//! external API (Phase 11), and the MCP server (Phase 12).

use std::path::PathBuf;

use anyhow::Context;
use oxidhome_core::{Engine, PluginInstance};
use tracing_subscriber::{EnvFilter, fmt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    let wasm_path: PathBuf = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("usage: oxidhome <plugin.wasm>"))?;

    let engine = Engine::new()?;
    let mut instance = PluginInstance::load(&engine, &wasm_path)
        .await
        .with_context(|| format!("loading plugin from {}", wasm_path.display()))?;

    instance.init().await?;
    instance.shutdown().await?;

    Ok(())
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = fmt().with_env_filter(filter).try_init();
}
