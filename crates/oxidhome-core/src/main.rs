//! `oxidhome` host daemon entrypoint.
//!
//! Opens the state directory, mints the first-run admin token if
//! the store is empty, optionally starts one plugin handed on argv
//! (a dev-time affordance — the supervised lifecycle endpoints
//! land in 12-API-f), and then serves the Phase-12 HTTP/WS API
//! until a shutdown signal arrives.
//!
//! ## Environment
//!
//! - `OXIDHOME_STATE_DIR` — path to the daemon's state dir.
//!   Default: `<cwd>/.oxidhome-state`. Contains `oxidhome.db` +
//!   the first-run `admin-token` file.
//! - `OXIDHOME_BIND` — `<ip>:<port>` the API listens on, parsed
//!   as a [`SocketAddr`] (IPv4 / IPv6 literals only — hostnames
//!   like `localhost` are **not** resolved). Default:
//!   [`DEFAULT_BIND`] (loopback-only; the daemon is meant to sit
//!   behind the household reverse proxy / UI for any non-localhost
//!   traffic).
//! - `RUST_LOG` — fmt-subscriber filter for stdout. The `LogStore`
//!   `SQLite` layer captures every level regardless.
//!
//! ## Signals
//!
//! `SIGINT` (ctrl-c) and (on Unix) `SIGTERM` both initiate
//! shutdown. The accept loop stops immediately (in-flight HTTP
//! requests and open `WebSockets` are dropped — see the comment on
//! the `tokio::select!` in `main`), the log writer flushes within
//! [`SHUTDOWN_FLUSH_BUDGET`], and the process exits.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context;
use oxidhome_core::Engine;
use oxidhome_core::api::{ApiConfig, bind, ensure_admin_token, serve};
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

/// Loopback-only by default — the API isn't meant to face the
/// open network. Operators who want a different listen address
/// set `OXIDHOME_BIND`; the daemon parses the value as a
/// `SocketAddr` (so `0.0.0.0:7780` and `[::1]:7780` both work).
const DEFAULT_BIND: &str = "127.0.0.1:7780";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let state_dir = resolve_state_dir()?;
    // Engine first — its `log_store` provides the SQLite tracing
    // layer that the global subscriber composes below.
    //
    // **Bootstrap gap:** events emitted *during* `Engine::with_state_dir`
    // itself (the SQLite migrations, WAL setup, KvStore /
    // EventLog / LogStore construction) land before the subscriber
    // is installed — they're visible on stdout's default-ish
    // tracing target but not persisted. The plugin lifecycle and
    // every subsequent host event are captured.
    let engine = Engine::with_state_dir(&state_dir).with_context(|| {
        format!(
            "opening engine state at {} — set $OXIDHOME_STATE_DIR to override",
            state_dir.display(),
        )
    })?;
    let log_store = engine.log_store();
    init_tracing(&engine);

    let installed = engine.installed_plugins().list();
    tracing::info!(
        state_dir = %state_dir.display(),
        installed_plugins = installed.len(),
        "host starting",
    );
    // 12-API-f: log the installed plugin inventory so operators can
    // confirm what's available before they `start`. The daemon does
    // NOT auto-start anything; each instance has to come up via
    // `POST /api/v1/plugins/{plugin_id}/start` (or the legacy argv
    // dev path below).
    for row in &installed {
        tracing::info!(
            plugin_id = %row.plugin_id,
            version = %row.version,
            path = %row.path.display(),
            "installed plugin available",
        );
    }

    // First-run admin token. Idempotent — only mints when the
    // token store is empty.
    ensure_admin_token(&engine.auth_tokens(), &state_dir)?;

    // Optional dev-time plugin start. Preserves the Phase-6 demo
    // affordance (point at one plugin dir on argv to get it
    // running) so local iteration doesn't need to go through the
    // 12-API-f install endpoints. The handle is held in scope so
    // the supervised task isn't dropped; we don't otherwise act
    // on it from main.
    let _plugin_handle = if let Some(plugin_dir) = std::env::args_os().nth(1) {
        let plugin_dir = PathBuf::from(plugin_dir);
        let instance_id = plugin_dir
            .file_name()
            .map_or_else(|| "plugin".to_owned(), |s| s.to_string_lossy().into_owned());
        let handle = engine
            .start_instance(plugin_dir.clone(), &instance_id, None)
            .await
            .with_context(|| format!("starting plugin from {}", plugin_dir.display()))?;
        tracing::info!(instance_id = %instance_id, "plugin started");
        Some(handle)
    } else {
        None
    };

    // Bind the listener; log the actual bound address (matters
    // when `$OXIDHOME_BIND` ends in `:0` for ephemeral-port
    // testing) before moving into the accept loop.
    let bind_addr = resolve_bind_addr()?;
    let listener = bind(ApiConfig { bind: bind_addr })
        .await
        .with_context(|| format!("binding the API listener at {bind_addr}"))?;
    let actual = listener.local_addr()?;
    tracing::info!(addr = %actual, "oxidhome API listening");

    // Serve until a shutdown signal arrives. `serve` returning
    // Err here means the accept loop itself died (rare); we
    // surface that as the daemon's exit code so systemd / runit
    // can restart.
    //
    // **Hard-drop on signal — deliberate.** Dropping the `serve`
    // future aborts axum's in-flight connection tasks, including
    // any open `events/tail` WebSocket and any HTTP request mid-
    // flight (the actuation `POST /devices/{id}/command` client
    // loses its response even if the command already executed).
    // The "obvious" upgrade — `axum::serve(...).with_graceful_shutdown(...)`
    // — waits for *every* connection to close before returning,
    // and the `events/tail` WS never closes on its own (its
    // `select!` runs until the client hangs up), so a single
    // connected tail client would wedge daemon shutdown
    // indefinitely. A bounded graceful shutdown (HTTP drains for
    // N seconds, then hard-drop) is the right shape if/when an
    // operator hits this; deferring until there's a real
    // incident, since for a home hub a missed actuation response
    // is recoverable from the audit log + state, and a wedged
    // shutdown is not.
    tokio::select! {
        result = serve(engine.clone(), listener) => {
            result.context("api server stopped unexpectedly")?;
        }
        signal = shutdown_signal() => {
            tracing::info!(signal = signal, "shutdown signal received; draining");
        }
    }

    // Drain the log writer before process exit so the tail of the
    // run actually lands in `<state_dir>/oxidhome.db`. `Drop`'s
    // bounded flush covers unexpected returns, but the explicit
    // call here keeps the happy path deterministic for operators
    // who check the log immediately after a graceful shutdown.
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

fn resolve_bind_addr() -> anyhow::Result<SocketAddr> {
    let raw = std::env::var("OXIDHOME_BIND").unwrap_or_else(|_| DEFAULT_BIND.to_string());
    raw.parse::<SocketAddr>()
        .with_context(|| format!("parsing $OXIDHOME_BIND ({raw:?}) as a socket address"))
}

/// Waits for the first arriving shutdown signal and returns its
/// name for the tracing line. On non-Unix platforms only `SIGINT`
/// (ctrl-c) is observable; `SIGTERM` is Unix-only.
async fn shutdown_signal() -> &'static str {
    let ctrl_c = async {
        // `ctrl_c()` returning Err means the handler couldn't
        // be installed (very rare). Treat that as "ctrl-c won't
        // ever fire from here" rather than crashing the daemon.
        if tokio::signal::ctrl_c().await.is_err() {
            std::future::pending::<()>().await;
        }
        "SIGINT"
    };
    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
                "SIGTERM"
            }
            Err(_) => std::future::pending::<&'static str>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = async { std::future::pending::<&'static str>().await };
    tokio::select! {
        s = ctrl_c => s,
        s = terminate => s,
    }
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
    // we persist.
    //
    // `try_init` returns Err if another subscriber is already
    // global — treat that as "tracing is already wired up; we're
    // done" rather than aborting the binary.
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::registry()
        .with(fmt::layer().with_filter(filter))
        .with(engine.log_store().layer())
        .try_init();
}
