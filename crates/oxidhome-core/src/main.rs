//! `oxidhome` host runtime entrypoint.
//!
//! Loads one plugin from its install directory (containing
//! `manifest.toml` + the `.wasm` it points at), runs `init()` →
//! `shutdown()`, prints the round-trip on stdout via
//! `tracing-subscriber`. Phase 6+ grows this into a real daemon with
//! multi-instance lifecycle, the external API (Phase 12), the UI
//! (Phase 13), and the MCP server (Phase 14).
//!
//! ## State directory
//!
//! Phase 5 stores need a `<state_dir>` for `oxidhome.db`. The binary
//! resolves it as:
//!
//! 1. `$OXIDHOME_STATE_DIR` if set.
//! 2. Otherwise `<cwd>/.oxidhome-state`.
//!
//! Phase 12's CLI will replace this with a proper host config file;
//! this is the smallest workable default for the demo runtime.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context;
use oxidhome_core::{Engine, PluginInstance};
use tracing_subscriber::Layer as _;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;
use tracing_subscriber::{EnvFilter, fmt};

/// How long to wait for the log-store writer thread to flush
/// outstanding rows before main returns. 5 s is enough for any
/// realistic backlog at the per-call `SQLite` cost; if the writer is
/// hung beyond that, we'd rather drop the tail than block process
/// exit.
const SHUTDOWN_FLUSH_BUDGET: Duration = Duration::from_secs(5);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let plugin_dir: PathBuf = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "usage: {} <plugin-dir>   (directory containing manifest.toml + the .wasm)",
                env!("CARGO_BIN_NAME"),
            )
        })?;

    let state_dir = resolve_state_dir()?;
    // Engine first — its `log_store` provides the SQLite tracing
    // layer that the global subscriber composes below. Setting the
    // subscriber up before the engine would lose every event the
    // engine emits during construction; setting it up after the
    // plugin loads loses every event during `PluginInstance::load`.
    // So: build engine → install subscriber → load plugin.
    let engine = Engine::with_state_dir(&state_dir).with_context(|| {
        format!(
            "opening engine state at {} — set $OXIDHOME_STATE_DIR to override",
            state_dir.display(),
        )
    })?;
    let log_store = engine.log_store();

    init_tracing(&engine);

    tracing::info!(
        state_dir = %state_dir.display(),
        "host starting",
    );

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

    // Drain the log writer before process exit so the tail of the
    // run actually lands in `<state_dir>/oxidhome.db`. `Drop`'s
    // bounded flush covers unexpected returns, but the explicit
    // call here keeps the happy path deterministic for operators
    // who run the binary in foreground and check the log
    // immediately after.
    if !log_store.flush(SHUTDOWN_FLUSH_BUDGET) {
        tracing::warn!(
            sent = log_store.sent(),
            written = log_store.written(),
            dropped = log_store.dropped(),
            "log_store: flush budget exceeded — some tail rows may be lost",
        );
    }

    Ok(())
}

fn resolve_state_dir() -> anyhow::Result<PathBuf> {
    if let Some(env_dir) = std::env::var_os("OXIDHOME_STATE_DIR") {
        return Ok(PathBuf::from(env_dir));
    }
    let cwd = std::env::current_dir().context("reading current working directory")?;
    Ok(cwd.join(".oxidhome-state"))
}

fn init_tracing(engine: &Engine) {
    // `EnvFilter` wraps the fmt layer **only**, not the whole
    // registry. A registry-level filter would gate *both* layers —
    // the SQLite store would silently miss everything below the
    // env-configured threshold (default `info`), so `trace!` and
    // `debug!` would never reach the persistent log even though the
    // store and schema have first-class slots for them. Phase 5c's
    // contract is "capture every host tracing event"; operators
    // tune stdout verbosity via `RUST_LOG` independently of what
    // we persist. The Phase-12 retention/level config will grow a
    // separate per-host filter for the SQLite layer when there's a
    // workload that needs it.
    //
    // `try_init` returns Err if another subscriber is already
    // global — e.g. an integration test in the same process
    // already called `set_global_default`. Treat that as "tracing
    // is already wired up; we're done" rather than aborting the
    // binary.
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::registry()
        .with(fmt::layer().with_filter(filter))
        .with(engine.log_store().layer())
        .try_init();
}
