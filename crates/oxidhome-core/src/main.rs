//! `oxidhome` host daemon entrypoint.
//!
//! Two modes:
//!
//! - **Default (HTTP daemon)** — opens the state directory,
//!   mints the first-run admin token if the store is empty,
//!   optionally starts one plugin handed on argv (a dev-time
//!   affordance), and serves the Phase-12 HTTP/WS API until a
//!   shutdown signal arrives.
//! - **`mcp-stdio` subcommand (14.5)** — argv[1] = `mcp-stdio`
//!   switches into a subprocess mode that serves MCP framed
//!   JSON-RPC over stdin/stdout, backed by the same `Engine`
//!   layout the HTTP daemon would use. Intended for MCP clients
//!   (Claude Desktop, MCP Inspector, agent SDKs) that spawn
//!   subprocesses. Runs until stdin EOF or client shutdown;
//!   does not bind the HTTP listener.
//! - **`recover-admin-token [--revoke-all]` subcommand (M4)** —
//!   offline break-glass recovery for a lost admin secret. Takes
//!   the exclusive state-dir lock (so it refuses to run while the
//!   daemon or an `mcp-stdio` session is up), mints a fresh
//!   full-access `admin` token, revokes the previous
//!   `admin`-labelled tokens (every token with `--revoke-all`) in
//!   the same transaction, and writes the secret to
//!   `<state_dir>/admin-token`. Never reachable over the network:
//!   it needs filesystem access to the state dir.
//! - **`token list` / `token grant-sensitive <id> <category>
//!   [--device <dev-id>]...` / `token revoke-sensitive <id>
//!   <category>` (H6 slice 2)** — offline: list tokens with their
//!   owner flag, roles, scopes, sensitive grants and deny list, or
//!   edit a token's explicit grants for `lock`, `opener`, `alarm` or
//!   `camera`. No scope or role, the wildcard included, reaches those
//!   without a grant; only the bootstrap / recovered owner token holds
//!   them all.
//! - **`token create <label> [--role <name>]... [--scope <scope>]...
//!   [--sensitive <category>]... [--deny <actions>[@<categories>|{<services>}]]...`
//!   (H6 slice 3)** — offline: mint a token holding owner-defined
//!   roles, printing its secret once.
//! - **`role list|create <name> <json>|update <name> <json>|delete
//!   <name> [--force]` (H6 slice 3)** — offline: the owner's roles.
//! - **`device set-category <dev-id> <category>|--clear` (H6 slice
//!   2)** — offline: the operator's category raise (raise only).
//! - **`tls-pin list [<instance>]` / `tls-pin reset <instance> [<host>
//!   [<port>]]` / `tls-pin reset --all` (Phase 8.2)** — offline: list or
//!   forget the certificates streaming instances trusted on first use for
//!   LAN devices; the next request to a reset device pins again.
//! - **`plugin list` (Phase 8.5)** — offline: the installed plugins
//!   with their network rules (requested, granted, effective), read
//!   without touching the registry.
//! - **`backup <out-dir>` (M3)** — writes a consistent snapshot
//!   of the database, the blob files it indexes and the installed
//!   plugin packages to a new directory with a checksummed
//!   `manifest.json`. Online: safe while the daemon runs.
//! - **`verify-backup <dir>` (M3)** — checks an archive without
//!   touching the state dir.
//! - **`restore <dir>` / `restore --resume` (M3)** — offline:
//!   verifies the archive, then swaps it in under the exclusive
//!   state-dir lock, keeping the replaced state in
//!   `<state_dir>/pre-restore-<unix_ms>/`. `--resume` finishes a
//!   swap that was interrupted by a crash.
//!
//! ## Environment
//!
//! - `OXIDHOME_STATE_DIR` — path to the daemon's state dir.
//!   Default: `<cwd>/.oxidhome-state`. Contains `oxidhome.db` +
//!   the first-run `admin-token` file (removed on the first start
//!   after the token has been used).
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
use oxidhome_core::api::mcp::{
    DaemonConfig, DaemonMode, ENV_BIND, ENV_STATE_DIR, StdioOptions, install_daemon_config,
    serve_stdio_with,
};
use oxidhome_core::api::network_admin::reset_tls_pins;
use oxidhome_core::api::sensitive_admin::{
    grant_sensitive, revoke_sensitive, sensitive_access_report, set_device_category,
    with_offline_db, with_offline_stores,
};
use oxidhome_core::api::{
    ApiConfig, RevokeScope, bind, ensure_admin_token, reconcile_admin_token_files,
    recover_admin_token_offline, serve,
};
use oxidhome_core::auth::{DeviceCategory, SensitiveCategory};
use oxidhome_core::exclusive_lock::acquire_state_dir_lock;
use oxidhome_core::state::{PinFilter, RetentionConfig, RetentionTasks};
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

/// Round-2 F1: per-instance stop deadline on daemon
/// shutdown. Stops fire in parallel, so total wall-clock
/// is bounded by this (not `N * this`). Long enough for
/// a well-behaved plugin's `shutdown` handler to run;
/// short enough that a hung plugin doesn't wedge the
/// daemon indefinitely. A timed-out stop is logged; that
/// supervisor is left running (its reaper is still blocked
/// on the terminal transition) and the subsequent bounded
/// drain will eventually detach it — the tokio runtime
/// teardown that follows process exit aborts every
/// detached task.
const SHUTDOWN_STOP_PER_INSTANCE_DEADLINE: Duration = Duration::from_secs(5);

/// Round-3 F1 + round-6 F1/F2/F3: bounded reaper-drain
/// deadline for daemon shutdown. Best-effort: reapers that
/// don't complete inside this window get detached (their
/// wrapper tasks are aborted; the real reaper tasks stay
/// running). On process exit the tokio runtime teardown
/// aborts the detached tasks, so any post-deadline leak
/// is process-lifetime bounded. Round-5 tried to abort
/// the real reapers + perform equivalent cleanup inline
/// on timeout, but every version of that hit a sharper
/// bug (unregistering a still-running supervisor,
/// mis-targeting recycled generations, deadlocking on
/// the very lock that had wedged the reaper). Best-effort
/// is the correct contract here — see the docstring on
/// [`oxidhome_core::Engine::drain_supervised_instances_with_timeout`]
/// for the full rationale.
const SHUTDOWN_REAPER_DRAIN_DEADLINE: Duration = Duration::from_secs(10);

/// Loopback-only by default — the API isn't meant to face the
/// open network. Operators who want a different listen address
/// set `OXIDHOME_BIND`; the daemon parses the value as a
/// `SocketAddr` (so `0.0.0.0:7780` and `[::1]:7780` both work).
const DEFAULT_BIND: &str = "127.0.0.1:7780";

/// Bound on the runtime shutdown after the mode returns: blocking-pool
/// work still running (a lifecycle operation, an audit row, a
/// retention chunk) gets this long to finish before the process exits.
const SHUTDOWN_RUNTIME_BUDGET: Duration = Duration::from_secs(10);

fn main() -> anyhow::Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let result = runtime.block_on(run_mode());
    // Bounded, unlike dropping the runtime: a blocking task hung on the
    // disk can't keep the process alive. The state-dir lock, if taken,
    // is held past this (see `STATE_DIR_LOCK`).
    runtime.shutdown_timeout(SHUTDOWN_RUNTIME_BUDGET);
    result
}

async fn run_mode() -> anyhow::Result<()> {
    // 14.5: `oxidhome mcp-stdio` runs the MCP server over the
    // process's stdin/stdout instead of the HTTP listener.
    // Intended for MCP clients that spawn subprocesses (Claude
    // Desktop, MCP Inspector, agent SDKs). Detected here so
    // stdout isn't polluted with the daemon's tracing lines
    // before the JSON-RPC session opens.
    if let Some(result) = run_subcommand().await {
        return result;
    }

    let state_dir = resolve_state_dir()?;
    let retention = RetentionConfig::from_env()?;
    // Round-1 P1 on PR #143: enforce single-process ownership of
    // the state dir. `Engine`'s in-memory registries (device,
    // instance, event, service, per-plugin lifecycle locks) are
    // per-process — two `Engine`s against the same state dir
    // would race on plugin start/uninstall + serve stale reads
    // (SQLite WAL only protects the tables themselves, not the
    // supervisor bookkeeping). The lock is held for the process
    // lifetime and released only by the OS when the process
    // ends (see `STATE_DIR_LOCK`).
    hold_state_dir_lock(&state_dir)?;
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

    // M4: finish any interrupted admin-token delivery and drop the
    // plaintext file once its token has been enrolled, then mint
    // the first-run admin token if the store is empty (crash-safe:
    // the secret is on disk before its row is committed).
    reconcile_admin_token_files(&engine.auth_tokens(), &engine.audit_log(), &state_dir)?;
    ensure_admin_token(&engine.auth_tokens(), &engine.audit_log(), &state_dir)?;
    // H6 slice 2 (Q8): warn about tokens that lost sensitive reach.
    sensitive_access_report(&engine.auth_tokens());

    // Optional dev-time plugin start. Preserves the Phase-6 demo
    // affordance (point at one plugin dir on argv to get it
    // running) so local iteration doesn't need to go through the
    // 12-API-f install endpoints. The handle is held in scope so
    // the supervised task isn't dropped; we don't otherwise act
    // on it from main.
    //
    // H11 round-2 F1: argv-driven start is an explicit dev-time
    // load. `LoadMode::Dev` makes that intent visible at the API
    // boundary; the loader will fail hard if the caller-supplied
    // dir happens to shadow an installed `plugin_id` at a
    // different path.
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
    publish_http_config(&state_dir, &retention, bind_addr, actual);
    let retention = spawn_retention(&engine, retention);

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
    // Round-6 F1: capture the serve error (if any)
    // instead of propagating with `?` inside the select —
    // the propagation used to skip stop / drain / log
    // flush on an accept-loop failure. Cleanup still runs,
    // then we return the deferred error at the bottom of
    // main.
    let serve_error: Option<anyhow::Error> = tokio::select! {
        result = serve(engine.clone(), listener) => {
            match result {
                Ok(()) => None,
                Err(err) => Some(err.context("api server stopped unexpectedly")),
            }
        }
        signal = shutdown_signal() => {
            tracing::info!(signal = signal, "shutdown signal received; draining");
            None
        }
    };

    // Round-2 F1 + round-3 F1 + round-7 F3: BEST-EFFORT
    // bounded shutdown of every supervised instance.
    // `stop_all_supervised_instances` gives each supervisor
    // `SHUTDOWN_STOP_PER_INSTANCE_DEADLINE` to reach a
    // terminal state; the subsequent bounded reaper drain
    // gives their cleanup tasks (device / service
    // eviction, `instances.unregister`) up to
    // `SHUTDOWN_REAPER_DRAIN_DEADLINE` to complete. Any
    // reaper still pending at that deadline is DETACHED —
    // the tokio runtime teardown that follows process
    // exit aborts the tail alongside everything else, so
    // per-instance cleanup is process-lifetime bounded but
    // NOT guaranteed to have run before we return here.
    // Pre-round-2 `main` skipped this entire sequence and
    // relied on runtime teardown for every supervisor +
    // reaper, so mid-`init` aborts left partially-cleaned
    // state; this recovers the common case (well-behaved
    // plugins) without wedging the daemon.
    //
    // Round-6 F2: the stop report names any supervisor
    // that didn't reach terminal within the deadline; we
    // don't inspect it here because the bounded drain
    // handles the timed-out subset uniformly (by
    // detaching).
    let _ = engine
        .stop_all_supervised_instances(SHUTDOWN_STOP_PER_INSTANCE_DEADLINE)
        .await;
    let _ = engine
        .drain_supervised_instances_with_timeout(SHUTDOWN_REAPER_DRAIN_DEADLINE)
        .await;
    drain_state_read_audit(&engine).await;
    stop_retention(retention).await;
    close_state_writers(&engine).await;

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

    // Round-6 F1: propagate the serve error (if any) AFTER
    // running the full shutdown-cleanup sequence, so
    // systemd / runit still see a non-zero exit and can
    // restart.
    serve_error.map_or(Ok(()), Err)
}

/// The non-daemon modes, chosen by argv\[1\]; `None` runs the daemon.
async fn run_subcommand() -> Option<anyhow::Result<()>> {
    Some(
        match std::env::args_os()
            .nth(1)
            .as_deref()
            .and_then(|a| a.to_str())
        {
            Some("mcp-stdio") => match parse_stdio_args() {
                Ok(Some(options)) => run_stdio(options).await,
                Ok(None) => Ok(()),
                Err(e) => Err(e),
            },
            Some("recover-admin-token") => run_recover_admin_token(),
            Some("backup") => run_backup(),
            Some("verify-backup") => run_verify_backup(),
            Some("restore") => run_restore(),
            Some("token") => run_token(),
            Some("role") => run_role(),
            Some("device") => run_device(),
            Some("tls-pin") => run_tls_pin(),
            // `oxidhome plugin` alone still starts the daemon with a dev
            // plugin directory named `plugin`.
            Some("plugin") if std::env::args_os().nth(2).is_some() => run_plugin(),
            _ => return None,
        },
    )
}

/// `oxidhome://config` / `GET /api/v1/config`: publish what the HTTP
/// daemon resolved, before the first request can ask. The dev-time
/// plugin directory is argv\[1\], the value `main` starts.
fn publish_http_config(
    state_dir: &std::path::Path,
    retention: &RetentionConfig,
    configured: SocketAddr,
    bound: SocketAddr,
) {
    let mut config = DaemonConfig::resolve(DaemonMode::Http, state_dir, retention)
        .with_listener(configured, bound);
    if let Some(dir) = std::env::args_os().nth(1) {
        config = config.with_dev_plugin_dir(std::path::Path::new(&dir));
    }
    install_daemon_config(config);
}

/// Periodic retention for the event log, the diagnostic log and the
/// audit ledger (limits from `$OXIDHOME_{EVENT_LOG,LOG,AUDIT}_*`; see
/// `oxidhome_core::state::retention`). Low-priority and chunked. Used
/// by both long-running modes (HTTP daemon and `mcp-stdio`); the
/// caller shuts the tasks down before it exits.
fn spawn_retention(engine: &Engine, config: RetentionConfig) -> RetentionTasks {
    let days = |p: &oxidhome_core::state::RetentionPolicy| p.max_age.map(|a| a.as_secs() / 86_400);
    tracing::info!(
        event_log_max_age_days = days(&config.event_log),
        event_log_max_rows = config.event_log.max_rows,
        log_max_age_days = days(&config.logs),
        log_max_rows = config.logs.max_rows,
        audit_max_age_days = days(&config.audit),
        audit_max_rows = config.audit.max_rows,
        "retention",
    );
    engine.spawn_retention(config)
}

/// Stop retention: a chunk still waiting for the writer is cancelled,
/// one already running is waited out. Bounded by
/// [`SHUTDOWN_FLUSH_BUDGET`] so a chunk hung on the disk can't wedge
/// shutdown; [`STATE_DIR_LOCK`] covers that chunk.
async fn stop_retention(tasks: RetentionTasks) {
    if tokio::time::timeout(SHUTDOWN_FLUSH_BUDGET, tasks.shutdown())
        .await
        .is_err()
    {
        tracing::warn!("retention: a chunk was still running at the shutdown deadline");
    }
}

/// Bound on the H2 deny-audit drain at shutdown.
const SHUTDOWN_AUDIT_DRAIN_DEADLINE: Duration = Duration::from_secs(2);

/// Write the `deny` audit rows the stopped plugins queued (H2
/// `get-state`, `read-events`) within [`SHUTDOWN_AUDIT_DRAIN_DEADLINE`].
/// `COMMAND` resolutions are flushed by the command journal's own close
/// (`close_state_writers`).
async fn drain_state_read_audit(engine: &Engine) {
    let engine = engine.clone();
    // One deadline for both the drain and the wait for it, so a
    // blocking pool too busy to start the drain can't stretch it.
    let deadline = std::time::Instant::now() + SHUTDOWN_AUDIT_DRAIN_DEADLINE;
    let drain = tokio::task::spawn_blocking(move || {
        engine.drain_state_read_audit(deadline.saturating_duration_since(std::time::Instant::now()))
    });
    let drained = tokio::time::timeout_at(deadline.into(), drain)
        .await
        .is_ok_and(|joined| joined.unwrap_or(false));
    if !drained {
        tracing::warn!("deny-audit drain timed out; queued rows may be lost at exit");
    }
}

/// The exclusive state-dir lock of a long-running mode. A static is
/// never dropped: the lock stays held until the operating system closes
/// it with the process, after [`main`] shut the runtime down and every
/// thread is gone. Releasing it earlier would let a write still running
/// on another thread (a retention chunk or an orphaned H3 mirror write
/// stuck on a hung disk, an audit row, a lifecycle operation, the
/// checkpointer) touch the database after another process (a restarted
/// daemon, `oxidhome restore`) took the lock.
static STATE_DIR_LOCK: std::sync::OnceLock<std::fs::File> = std::sync::OnceLock::new();

/// Take the state-dir lock and hold it for the rest of the process
/// (see [`STATE_DIR_LOCK`]).
fn hold_state_dir_lock(state_dir: &std::path::Path) -> anyhow::Result<()> {
    let lock = acquire_state_dir_lock(state_dir)?;
    if STATE_DIR_LOCK.set(lock).is_err() {
        anyhow::bail!("state-dir lock taken twice");
    }
    Ok(())
}

/// M4: `oxidhome recover-admin-token [--revoke-all]`. Offline only —
/// [`recover_admin_token_offline`] takes the exclusive state-dir
/// lock, so this fails while the daemon is running. Prints the new
/// token's id and file path, never the secret itself.
fn run_recover_admin_token() -> anyhow::Result<()> {
    const USAGE: &str = "usage: oxidhome recover-admin-token [--revoke-all]";
    let mut scope = RevokeScope::AdminTokens;
    for arg in std::env::args_os().skip(2) {
        match arg.to_str() {
            Some("--revoke-all") => scope = RevokeScope::All,
            Some("-h" | "--help") => {
                println!("{USAGE}");
                println!(
                    "Mints a new full-access `admin` token while the daemon is stopped and \
                     writes it to $OXIDHOME_STATE_DIR/admin-token. Revokes previous `admin` \
                     tokens, or every token with --revoke-all."
                );
                return Ok(());
            }
            _ => anyhow::bail!("unexpected argument `{}`\n{USAGE}", arg.to_string_lossy()),
        }
    }
    init_cli_tracing();

    let state_dir = resolve_state_dir()?;
    let report = recover_admin_token_offline(&state_dir, scope)?;
    println!(
        "new admin token {} written to {}",
        report.token_id,
        report.path.display()
    );
    if report.revoked.is_empty() {
        println!("no tokens revoked");
    } else {
        println!("revoked: {}", report.revoked.join(", "));
    }
    Ok(())
}

/// `oxidhome mcp-stdio [--allow-sensitive <category>]...`. `Ok(None)`
/// means help was printed.
fn parse_stdio_args() -> anyhow::Result<Option<StdioOptions>> {
    const USAGE: &str =
        "usage: oxidhome mcp-stdio [--allow-sensitive <lock|opener|alarm|camera>]...";
    let mut options = StdioOptions::default();
    let mut args = std::env::args().skip(2);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--allow-sensitive" => {
                let value = args.next().ok_or_else(|| {
                    anyhow::anyhow!("--allow-sensitive needs a category\n{USAGE}")
                })?;
                let category: SensitiveCategory =
                    value.parse().map_err(|e| anyhow::anyhow!("{e}\n{USAGE}"))?;
                if !options.allow_sensitive.contains(&category) {
                    options.allow_sensitive.push(category);
                }
            }
            "-h" | "--help" => {
                println!("{USAGE}");
                println!(
                    "Serves MCP over stdin/stdout as the ambient wildcard actor. Commands on locks, \
                     openers and alarms and camera bytes stay out of reach unless named with \
                     --allow-sensitive."
                );
                return Ok(None);
            }
            other => anyhow::bail!("unexpected argument `{other}`\n{USAGE}"),
        }
    }
    Ok(Some(options))
}

/// H6 slice 2: `oxidhome token <list|grant-sensitive|revoke-sensitive>`.
/// Offline, like `recover-admin-token`.
fn run_token() -> anyhow::Result<()> {
    const USAGE: &str = "usage: oxidhome token list\n       \
         oxidhome token create <label> [--role <name>]... [--scope <scope>]... \
         [--sensitive <lock|opener|alarm|camera>]... [--deny <action,...|*>[@<category,...>|{<service,...>}]]...\n       \
         oxidhome token grant-sensitive <token-id> <lock|opener|alarm|camera> [--device <dev-id>]...\n       \
         oxidhome token revoke-sensitive <token-id> <lock|opener|alarm|camera>";
    let args: Vec<String> = std::env::args().skip(2).collect();
    let usage = || anyhow::anyhow!("{USAGE}");
    match args.first().map(String::as_str) {
        Some("-h" | "--help") | None => {
            println!("{USAGE}");
            println!(
                "Roles are the owner's (`oxidhome role list`). Commands on locks, openers and \
                 alarms and camera bytes need an explicit grant; no scope, the wildcard \
                 included, reaches them. Run with the daemon stopped."
            );
            Ok(())
        }
        Some("create") => run_token_create(&args[1..], USAGE),
        Some("list") if args.len() == 1 => run_token_list(),
        Some(cmd @ ("grant-sensitive" | "revoke-sensitive")) => {
            let token_id = args.get(1).ok_or_else(usage)?;
            let category: SensitiveCategory = args
                .get(2)
                .ok_or_else(usage)?
                .parse()
                .map_err(|e| anyhow::anyhow!("{e}\n{USAGE}"))?;
            let mut devices = Vec::new();
            let mut rest = args.iter().skip(3);
            while let Some(flag) = rest.next() {
                match flag.as_str() {
                    "--device" if cmd == "grant-sensitive" => {
                        devices.push(rest.next().ok_or_else(usage)?.clone());
                    }
                    other => anyhow::bail!("unexpected argument `{other}`\n{USAGE}"),
                }
            }
            init_cli_tracing();
            let state_dir = resolve_state_dir()?;
            let (policy, by_role) = with_offline_stores(&state_dir, |stores| {
                let policy = if cmd == "grant-sensitive" {
                    grant_sensitive(&stores.tokens, &stores.audit, token_id, category, &devices)?
                } else {
                    revoke_sensitive(&stores.tokens, &stores.audit, token_id, category)?
                };
                // H6 slice 3: a held role may grant the category too.
                // The change is stored; a failed lookup only loses the note.
                let by_role: Vec<String> = match stores.tokens.roles_by_id(&policy.roles) {
                    Ok(roles) => roles
                        .into_iter()
                        .filter(|r| r.def().is_some_and(|d| d.sensitive.contains(&category)))
                        .map(|r| r.name)
                        .collect(),
                    Err(err) => {
                        eprintln!("note: couldn't read this token's roles: {err}");
                        Vec::new()
                    }
                };
                Ok((policy, by_role))
            })?;
            if !by_role.is_empty() {
                eprintln!(
                    "note: role(s) {} held by this token also grant `{}`",
                    by_role.join(", "),
                    category.as_str(),
                );
            }
            println!(
                "token {token_id} sensitive grants: {}",
                if policy.sensitive.is_empty() {
                    "(none)".to_owned()
                } else {
                    policy
                        .sensitive
                        .iter()
                        .map(|g| g.category.as_str())
                        .collect::<Vec<_>>()
                        .join(",")
                }
            );
            Ok(())
        }
        _ => Err(usage()),
    }
}

/// `oxidhome token list`.
fn run_token_list() -> anyhow::Result<()> {
    init_cli_tracing();
    let state_dir = resolve_state_dir()?;
    with_offline_stores(&state_dir, |stores| {
        for t in oxidhome_core::api::token_admin::summaries(&stores.tokens)? {
            let none = |v: &[String], sep: &str| {
                if v.is_empty() {
                    "-".to_owned()
                } else {
                    v.join(sep)
                }
            };
            println!(
                "{}\t{}\t{}{}\troles={}\tscopes={}\tsensitive={}\tdeny={}",
                t.token_id,
                t.label,
                if t.owner { "owner" } else { "-" },
                if t.revoked { " revoked" } else { "" },
                none(&t.roles, ","),
                if t.policy_valid {
                    none(&t.scopes, ",")
                } else {
                    "(unparseable policy: deny-all)".to_owned()
                },
                none(&t.sensitive, ","),
                none(&t.deny, " "),
            );
        }
        Ok(())
    })
}

/// One `oxidhome role` row.
fn print_role(r: &oxidhome_core::api::token_admin::RoleSummary) {
    let none = |v: &[String], sep: &str| {
        if v.is_empty() {
            "-".to_owned()
        } else {
            v.join(sep)
        }
    };
    println!(
        "{}\t{}\tgrants={}\tsensitive={}\tdeny={}\ttokens={}{}",
        r.role_id,
        r.name,
        none(&r.grants, " "),
        none(&r.sensitive, ","),
        none(&r.deny, " "),
        r.tokens.len(),
        if r.definition_valid {
            ""
        } else {
            "\t(unparseable definition: grants nothing)"
        },
    );
}

/// One offline `oxidhome role` operation.
type RoleOp = dyn FnOnce(&oxidhome_core::api::sensitive_admin::OfflineStores) -> anyhow::Result<()>;

/// H6 slice 3: `oxidhome role <list|create|update|delete>`. Offline.
fn run_role() -> anyhow::Result<()> {
    use oxidhome_core::api::token_admin::{self as admin, Audited, NewRole, RoleSpec};
    const USAGE: &str = "usage: oxidhome role list\n       \
         oxidhome role create <name> <definition-json>\n       \
         oxidhome role update <name> <definition-json>\n       \
         oxidhome role delete <name> [--force]\n\
         definition: {\"grants\": [{\"actions\": [\"device.read\", ...], \"category\": [\"light\"], \
         \"devices\": [\"dev-a1*\"]}], \"sensitive\": [\"lock\"], \"deny\": [{\"actions\": [...], ...}]}";
    const CLI: Audited<'static> = Audited {
        surface: "cli",
        actor_kind: "cli",
        call_id: None,
    };
    let args: Vec<String> = std::env::args().skip(2).collect();
    let spec = |json: &str| -> anyhow::Result<RoleSpec> {
        serde_json::from_str(json).map_err(|e| anyhow::anyhow!("invalid definition: {e}\n{USAGE}"))
    };
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    let op: Box<RoleOp> = match words.as_slice() {
        ["-h" | "--help"] | [] => {
            println!("{USAGE}");
            return Ok(());
        }
        ["list"] => Box::new(|st| {
            for r in admin::role_summaries(&st.tokens)? {
                print_role(&r);
            }
            Ok(())
        }),
        ["create", name, json] => {
            let req = NewRole {
                name: (*name).to_owned(),
                spec: spec(json)?,
            };
            Box::new(move |st| {
                print_role(&admin::create_role(&st.tokens, &st.audit, CLI, &req)?);
                Ok(())
            })
        }
        ["update", name, json] => {
            let (name, spec) = ((*name).to_owned(), spec(json)?);
            Box::new(move |st| {
                let r = admin::update_role(&st.tokens, &st.audit, CLI, &name, &spec)?;
                print_role(&r);
                if !r.tokens.is_empty() {
                    eprintln!(
                        "{} token(s) hold this role and see the change",
                        r.tokens.len()
                    );
                }
                Ok(())
            })
        }
        ["delete", name, rest @ ..] if rest.is_empty() || rest == ["--force"] => {
            let (name, force) = ((*name).to_owned(), !rest.is_empty());
            Box::new(move |st| {
                let r = admin::delete_role(&st.tokens, &st.audit, CLI, &name, force)?;
                if !r.tokens.is_empty() {
                    eprintln!(
                        "deleted; {} token(s) keep a reference that grants nothing: {}",
                        r.tokens.len(),
                        r.tokens.join(" "),
                    );
                }
                Ok(())
            })
        }
        _ => anyhow::bail!("{USAGE}"),
    };
    init_cli_tracing();
    let state_dir = resolve_state_dir()?;
    oxidhome_core::api::sensitive_admin::with_offline_stores(&state_dir, op)
}

/// H6 slice 3: `oxidhome token create`.
fn run_token_create(args: &[String], usage: &str) -> anyhow::Result<()> {
    let req = parse_token_create(args).map_err(|e| anyhow::anyhow!("{e}\n{usage}"))?;
    init_cli_tracing();
    let state_dir = resolve_state_dir()?;
    let minted = with_offline_stores(&state_dir, |stores| {
        // The first token must be the owner: the daemon's bootstrap
        // mints it only into an empty token table.
        if stores.tokens.count()? == 0 {
            anyhow::bail!(
                "no owner token yet: start the daemon once so it mints the owner token, \
                 then create role tokens"
            );
        }
        oxidhome_core::api::token_admin::mint(
            &stores.tokens,
            &stores.audit,
            "cli",
            "cli",
            None,
            &req,
        )
        .map_err(anyhow::Error::from)
    })?;
    let s = &minted.summary;
    eprintln!(
        "token {} ({}) minted: roles={} scopes={} sensitive={} deny={}",
        minted.token_id,
        s.label,
        s.roles.join(","),
        s.scopes.join(","),
        s.sensitive.join(","),
        s.deny.join(" "),
    );
    eprintln!("the secret below is shown once; the host keeps only its hash");
    // Stdout is the delivery channel for the secret (pipe it where it
    // belongs); nothing else is written there.
    let mut out = std::io::stdout().lock();
    std::io::Write::write_all(&mut out, minted.secret.as_bytes())?;
    std::io::Write::write_all(&mut out, b"\n")?;
    Ok(())
}

/// H6 slice 3: the arguments of `oxidhome token create`.
fn parse_token_create(
    args: &[String],
) -> anyhow::Result<oxidhome_core::api::token_admin::MintRequest> {
    use oxidhome_core::api::token_admin::{MintRequest, SelectorSpec};
    let mut req = MintRequest::default();
    let mut label = None;
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        let mut value = || {
            rest.next()
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("`{arg}` needs a value"))
        };
        match arg.as_str() {
            "--role" => req.roles.push(value()?),
            "--scope" => req.scopes.push(value()?),
            "--sensitive" => req.sensitive.push(value()?),
            "--deny" => {
                let v = value()?;
                let list = |l: &str| Some(l.split(',').map(str::to_owned).collect());
                // `<actions>{<services>}` (as listings show it) or
                // `<actions>[@<categories>]`.
                let (actions, category, services) =
                    match v.strip_suffix('}').and_then(|v| v.split_once('{')) {
                        Some((a, svc)) => (a, None, list(svc)),
                        None => match v.split_once('@') {
                            Some((a, c)) => (a, list(c), None),
                            None => (v.as_str(), None, None),
                        },
                    };
                req.deny.push(SelectorSpec {
                    actions: actions.split(',').map(str::to_owned).collect(),
                    category,
                    devices: None,
                    services,
                });
            }
            other if other.starts_with('-') => anyhow::bail!("unexpected argument `{other}`"),
            other if label.is_none() => label = Some(other.to_owned()),
            other => anyhow::bail!("unexpected argument `{other}`"),
        }
    }
    req.label = label.ok_or_else(|| anyhow::anyhow!("missing <label>"))?;
    Ok(req)
}

/// H6 slice 2: `oxidhome device set-category <dev-id> <category>|--clear`.
/// Offline. A raise only adds protection; it never lowers what the
/// host derived.
fn run_device() -> anyhow::Result<()> {
    const USAGE: &str = "usage: oxidhome device set-category <dev-id> <category>|--clear\n\
         categories: alarm lock opener camera light climate media switch sensor other";
    let args: Vec<String> = std::env::args().skip(2).collect();
    match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["set-category", device_id, value] => {
            let category = match *value {
                "--clear" => None,
                v => Some(
                    v.parse::<DeviceCategory>()
                        .map_err(|e| anyhow::anyhow!("{e}\n{USAGE}"))?,
                ),
            };
            init_cli_tracing();
            let state_dir = resolve_state_dir()?;
            let row = with_offline_stores(&state_dir, |stores| {
                set_device_category(&stores.audit, &stores.devices, device_id, category)
            })?;
            println!(
                "device {device_id} category override: {}",
                row.category_override
                    .map_or("(none)", DeviceCategory::as_str)
            );
            Ok(())
        }
        [] | ["-h" | "--help"] => {
            println!("{USAGE}");
            Ok(())
        }
        _ => anyhow::bail!("{USAGE}"),
    }
}

const TLS_PIN_USAGE: &str = "usage: oxidhome tls-pin list [<instance>]\n       \
     oxidhome tls-pin reset [--instance] <instance> [<host> [<port>]]\n       \
     oxidhome tls-pin reset --all\n\
     (scripts: use --instance, which takes any instance id literally)";

/// `oxidhome tls-pin` arguments: whether to reset, and what. `None`
/// asks for the usage.
fn parse_tls_pin_args(args: &[&str]) -> anyhow::Result<Option<(bool, PinFilter)>> {
    const USAGE: &str = TLS_PIN_USAGE;
    let filter = |instance: Option<&str>, host: Option<&str>, port: Option<&str>| {
        let port = port
            .map(|p| {
                p.parse::<u16>()
                    .map_err(|_| anyhow::anyhow!("bad port `{p}`\n{USAGE}"))
            })
            .transpose()?;
        PinFilter {
            instance_id: instance.map(str::to_owned),
            host: host.map(str::to_owned),
            port,
        }
        .validated()
        .map_err(|e| anyhow::anyhow!("{e}\n{USAGE}"))
    };
    let parsed = match args {
        ["list"] => (false, filter(None, None, None)?),
        ["list", instance] => (false, filter(Some(instance), None, None)?),
        ["reset", "--all"] => (true, filter(None, None, None)?),
        ["reset", "--instance", instance, rest @ ..] if rest.len() <= 2 => (
            true,
            filter(Some(instance), rest.first().copied(), rest.get(1).copied())?,
        ),
        // A leading `-` is an option, never an instance (`--instance`
        // takes those literally).
        ["reset", instance, rest @ ..] if !instance.starts_with('-') && rest.len() <= 2 => (
            true,
            filter(Some(instance), rest.first().copied(), rest.get(1).copied())?,
        ),
        [] | ["-h" | "--help"] => return Ok(None),
        _ => anyhow::bail!("{USAGE}"),
    };
    Ok(Some(parsed))
}

/// Phase 8: `oxidhome tls-pin list [<instance>]` /
/// `oxidhome tls-pin reset <instance> [<host> [<port>]]` /
/// `oxidhome tls-pin reset --instance <instance> [<host> [<port>]]` /
/// `oxidhome tls-pin reset --all`. Offline.
fn run_tls_pin() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(2).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let Some((reset, filter)) = parse_tls_pin_args(&args)? else {
        println!("{TLS_PIN_USAGE}");
        return Ok(());
    };
    init_cli_tracing();
    let state_dir = resolve_state_dir()?;
    let pins = with_offline_stores(&state_dir, |stores| {
        if reset {
            reset_tls_pins(&stores.audit, &stores.tls_pins, &filter)
        } else {
            Ok(stores.tls_pins.list(&filter))
        }
    })?;
    if reset {
        println!("removed {} pin(s)", pins.len());
    }
    for pin in pins {
        println!(
            "{}\t{}:{}\tsha256:{}\tpinned_ms={}\tinstallation={}",
            pin.key.instance_id,
            pin.key.host,
            pin.key.port,
            pin.fingerprint.to_hex(),
            pin.pinned_ms,
            pin.installation_uuid
        );
    }
    Ok(())
}

const PLUGIN_USAGE: &str = "usage: oxidhome plugin list";

/// Phase 8.5: `oxidhome plugin list`. Offline and read-only.
fn run_plugin() -> anyhow::Result<()> {
    // `args_os`: a non-UTF-8 argument is a usage error, not a panic.
    let args: Vec<Option<String>> = std::env::args_os()
        .skip(2)
        .map(|a| a.into_string().ok())
        .collect();
    match args
        .iter()
        .map(Option::as_deref)
        .collect::<Vec<_>>()
        .as_slice()
    {
        [Some("list")] => {}
        [Some("-h" | "--help")] => {
            println!("{PLUGIN_USAGE}");
            return Ok(());
        }
        _ => anyhow::bail!("{PLUGIN_USAGE}"),
    }
    init_cli_tracing();
    let state_dir = resolve_state_dir()?;
    let plugins = with_offline_db(&state_dir, |db| {
        oxidhome_core::state::list_installations_offline(&state_dir.join("plugins"), db)
    })?;
    print!("{}", format_plugin_list(&plugins));
    Ok(())
}

/// `text` with control characters escaped (`\u{1b}`), so a manifest
/// can't steer the operator's terminal through what the CLI prints.
fn printable(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        // Bidirectional formatting characters aren't `is_control`, but
        // reorder what a terminal shows.
        let bidi = matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}');
        if c.is_control() || bidi {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
    }
    out
}

/// `oxidhome plugin list` output: a tab-separated line per plugin, then
/// one indented line per network rule, tagged `requested`, `granted` or
/// `effective`. Control characters are escaped.
fn format_plugin_list(plugins: &[oxidhome_core::state::OfflinePlugin]) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    for plugin in plugins {
        match &plugin.status {
            Ok((version, network)) => {
                let _ = writeln!(
                    out,
                    "{}\t{}\tinstallation={}",
                    printable(&plugin.plugin_id),
                    printable(version),
                    printable(&plugin.installation_uuid)
                );
                let (requested, granted, effective) = network.to_strings();
                for (tag, rules) in [
                    ("requested", requested),
                    ("granted", granted),
                    ("effective", effective),
                ] {
                    for rule in rules {
                        let _ = writeln!(out, "\t{tag}\t{}", printable(&rule));
                    }
                }
            }
            Err(why) => {
                let _ = writeln!(
                    out,
                    "{}\tunavailable\tinstallation={}\t{}",
                    printable(&plugin.plugin_id),
                    printable(&plugin.installation_uuid),
                    printable(why)
                );
            }
        }
    }
    out
}

/// Stderr-only tracing for the offline / one-shot subcommands.
fn init_cli_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));
    let _ = tracing_subscriber::registry()
        .with(
            fmt::layer()
                .with_writer(std::io::stderr)
                .with_filter(filter),
        )
        .try_init();
}

/// Parses `<subcommand> <path>` (plus `-h` / `--help`). `Ok(None)`
/// means help was printed.
fn single_path_arg(usage: &str, help: &str) -> anyhow::Result<Option<PathBuf>> {
    let mut path = None;
    for arg in std::env::args_os().skip(2) {
        match arg.to_str() {
            Some("-h" | "--help") => {
                println!("{usage}");
                println!("{help}");
                return Ok(None);
            }
            Some(s) if s.starts_with('-') => {
                anyhow::bail!("unexpected argument `{s}`\n{usage}")
            }
            _ if path.is_none() => path = Some(PathBuf::from(arg)),
            _ => anyhow::bail!("unexpected argument `{}`\n{usage}", arg.to_string_lossy()),
        }
    }
    path.map(Some)
        .ok_or_else(|| anyhow::anyhow!("missing path\n{usage}"))
}

/// M3: `oxidhome backup <out-dir>`. Online — see
/// [`oxidhome_core::backup::create_backup`].
fn run_backup() -> anyhow::Result<()> {
    let Some(out) = single_path_arg(
        "usage: oxidhome backup <out-dir>",
        "Writes a consistent snapshot of $OXIDHOME_STATE_DIR (database, blob files, installed \
         plugins) to the new directory <out-dir>. Safe while the daemon runs.",
    )?
    else {
        return Ok(());
    };
    init_cli_tracing();
    let state_dir = resolve_state_dir()?;
    let report = oxidhome_core::backup::create_backup(&state_dir, &out)?;
    println!(
        "backup written to {} (schema v{}, {} blob(s), {} plugin(s), {} file(s))",
        report.path.display(),
        report.manifest.schema_version,
        report.blobs,
        report.plugins,
        report.manifest.files.len(),
    );
    Ok(())
}

/// M3: `oxidhome verify-backup <dir>`. Read-only.
fn run_verify_backup() -> anyhow::Result<()> {
    let Some(dir) = single_path_arg(
        "usage: oxidhome verify-backup <dir>",
        "Checks a backup archive's checksums, database integrity and index/file consistency.",
    )?
    else {
        return Ok(());
    };
    init_cli_tracing();
    let verified = oxidhome_core::backup::verify_backup(&dir)?;
    println!(
        "backup {} is valid (created_ms {}, schema v{}, {} blob(s), {} plugin(s))",
        dir.display(),
        verified.manifest.created_ms,
        verified.manifest.schema_version,
        verified.blobs,
        verified.plugins,
    );
    Ok(())
}

/// M3: `oxidhome restore <dir>` / `oxidhome restore --resume`.
/// Offline — takes the exclusive state-dir lock.
fn run_restore() -> anyhow::Result<()> {
    const USAGE: &str = "usage: oxidhome restore <dir> | oxidhome restore --resume";
    let mut resume = false;
    let mut archive = None;
    for arg in std::env::args_os().skip(2) {
        match arg.to_str() {
            Some("--resume") => resume = true,
            Some("-h" | "--help") => {
                println!("{USAGE}");
                println!(
                    "With the daemon stopped, verifies the backup at <dir> and swaps it into \
                     $OXIDHOME_STATE_DIR; the replaced state is kept in \
                     pre-restore-<unix_ms>/. --resume finishes an interrupted restore."
                );
                return Ok(());
            }
            Some(s) if s.starts_with('-') => anyhow::bail!("unexpected argument `{s}`\n{USAGE}"),
            _ if archive.is_none() => archive = Some(PathBuf::from(arg)),
            _ => anyhow::bail!("unexpected argument `{}`\n{USAGE}", arg.to_string_lossy()),
        }
    }
    init_cli_tracing();
    let state_dir = resolve_state_dir()?;
    let report = match (resume, archive) {
        (true, None) => {
            let Some(report) = oxidhome_core::backup::resume_restore_offline(&state_dir)? else {
                println!("no interrupted restore in {}", state_dir.display());
                return Ok(());
            };
            report
        }
        (false, Some(archive)) => oxidhome_core::backup::restore_offline(&state_dir, &archive)?,
        _ => anyhow::bail!("{USAGE}"),
    };
    println!(
        "restored backup created_ms {} into {}; previous state kept in {}",
        report.archive_created_ms,
        state_dir.display(),
        report.previous.display(),
    );
    Ok(())
}

fn resolve_state_dir() -> anyhow::Result<PathBuf> {
    if let Some(env_dir) = std::env::var_os(ENV_STATE_DIR) {
        return Ok(PathBuf::from(env_dir));
    }
    let cwd = std::env::current_dir().context("reading current working directory")?;
    Ok(cwd.join(".oxidhome-state"))
}

fn resolve_bind_addr() -> anyhow::Result<SocketAddr> {
    let raw = std::env::var(ENV_BIND).unwrap_or_else(|_| DEFAULT_BIND.to_string());
    raw.parse::<SocketAddr>()
        .with_context(|| format!("parsing $OXIDHOME_BIND ({raw:?}) as a socket address"))
}

/// Bound on the final device-state flush (H2) at shutdown.
const SHUTDOWN_DEVICE_STATE_DEADLINE: Duration = Duration::from_secs(5);

/// H2: final device-state flush after every supervisor stopped, so
/// the persisted projection carries their stale flips. Bounded: a hung
/// disk costs the unflushed changes, which the next boot treats like a
/// crash (their cursors resync).
///
/// Runs on a detached std thread rather than `spawn_blocking`: the
/// Tokio runtime waits for its blocking tasks on teardown, so a flush
/// stuck on the disk would hold the process past the deadline.
/// Flush the write-behind state writers once the supervisors are down:
/// the device-state projection, then the command journal.
async fn close_state_writers(engine: &oxidhome_core::Engine) {
    close_device_state(engine).await;
    close_command_journal(engine).await;
}

async fn close_device_state(engine: &oxidhome_core::Engine) {
    let engine = engine.clone();
    let (tx, rx) = tokio::sync::oneshot::channel();
    let spawned = std::thread::Builder::new()
        .name("device-state-close".into())
        .spawn(move || {
            let _ = tx.send(engine.close_device_state());
        });
    if let Err(err) = spawned {
        tracing::warn!(error = %err, "device-state projection: final flush not started");
        return;
    }
    match tokio::time::timeout(SHUTDOWN_DEVICE_STATE_DEADLINE, rx).await {
        Ok(Ok(true)) => {}
        Ok(Ok(false) | Err(_)) => {
            tracing::warn!("device-state projection: final flush failed");
        }
        Err(_) => tracing::warn!("device-state projection: final flush exceeded its deadline"),
    }
}

/// Bound on draining the H5 command journal at shutdown.
const SHUTDOWN_COMMAND_JOURNAL_DEADLINE: Duration = Duration::from_secs(5);

/// H5: write the `COMMAND` rows the stopped supervisors queued (their
/// pending commands expire as `outcome_unknown` when they stop) and
/// close the journal. Bounded: whatever is still pending afterwards is
/// resolved at the next start.
async fn close_command_journal(engine: &oxidhome_core::Engine) {
    // A dedicated thread, as for the device-state close: the deadline
    // starts now, not once a blocking-pool slot frees up.
    let engine = engine.clone();
    let (tx, rx) = tokio::sync::oneshot::channel();
    let spawned = std::thread::Builder::new()
        .name("command-journal-close".into())
        .spawn(move || {
            let _ = tx.send(engine.close_command_journal(SHUTDOWN_COMMAND_JOURNAL_DEADLINE));
        });
    if let Err(err) = spawned {
        tracing::warn!(error = %err, "command journal: shutdown drain not started");
        return;
    }
    // The close is bounded by the same deadline; the extra second
    // only covers thread start-up.
    let wait = SHUTDOWN_COMMAND_JOURNAL_DEADLINE + Duration::from_secs(1);
    if !matches!(tokio::time::timeout(wait, rx).await, Ok(Ok(true))) {
        tracing::warn!(
            "command journal: shutdown drain incomplete; pending commands resolve at the next start"
        );
    }
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

/// 14.5: MCP subprocess mode. The parent process launched us
/// with filesystem access to `$OXIDHOME_STATE_DIR` (default:
/// `<cwd>/.oxidhome-state`); we open our own `Engine` against
/// that dir and serve MCP framed JSON-RPC over stdin/stdout
/// until the client hangs up (stdin EOF) or issues a JSON-RPC
/// shutdown.
///
/// `SQLite` is opened in WAL mode by [`Engine::with_state_dir`].
/// Round-1 P1 on PR #143: state-dir ownership is EXCLUSIVE
/// across processes (see [`acquire_state_dir_lock`]); running
/// this subprocess against a state dir already owned by the
/// HTTP daemon fails fast.
///
/// Stdout is reserved for the MCP transport, so the stderr
/// pretty-printer takes it. Round-2 P2 on PR #143 additionally
/// attaches the engine's `SQLite` [`LogStore`] tracing layer so
/// this session's own events land in `oxidhome://logs` —
/// otherwise the exclusive-ownership fix left `LogStore` with
/// no writer at all when the daemon isn't running (which is
/// the common case for stdio).
///
/// Shutdown runs the same bounded stop + reaper drain the HTTP
/// daemon uses (round-2 P1 on PR #143) — plugins the client
/// started via `plugins.start` reach a terminal state before
/// the process exits, instead of relying on runtime teardown
/// to abort mid-supervisor.
async fn run_stdio(options: StdioOptions) -> anyhow::Result<()> {
    use tracing_subscriber::fmt::writer::MakeWriterExt;

    let state_dir = resolve_state_dir()?;
    let retention = RetentionConfig::from_env()?;
    // Round-1 P1 on PR #143: exclusive lock, held for the
    // process lifetime (see `STATE_DIR_LOCK`).
    hold_state_dir_lock(&state_dir)?;
    let engine = Engine::with_state_dir(&state_dir).with_context(|| {
        format!(
            "opening engine state at {} — set $OXIDHOME_STATE_DIR to override",
            state_dir.display(),
        )
    })?;
    let log_store = engine.log_store();

    // Tracing → stderr (not stdout, which is the MCP wire) +
    // the engine's `SQLite` `LogStore` layer so events reach
    // `oxidhome://logs`. Round-2 P2 on PR #143: prior to this
    // change the stderr-only subscriber left `LogStore`
    // unwritten under the new exclusive-lock regime (no
    // concurrent daemon means no other writer either).
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::registry()
        .with(
            fmt::layer()
                .with_writer(std::io::stderr.with_max_level(tracing::Level::TRACE))
                .with_filter(filter),
        )
        .with(engine.log_store().layer())
        .try_init();

    install_daemon_config(DaemonConfig::resolve(
        DaemonMode::McpStdio,
        &state_dir,
        &retention,
    ));
    if options.allow_sensitive.is_empty() {
        tracing::info!(
            "mcp-stdio session reaches no sensitive category (lock, opener, alarm, camera); \
             pass --allow-sensitive <category> to opt in",
        );
    } else {
        tracing::warn!(
            target: "auth.sensitive",
            categories = %options
                .allow_sensitive
                .iter()
                .map(|c| c.as_str())
                .collect::<Vec<_>>()
                .join(","),
            "mcp-stdio session allowed sensitive categories",
        );
    }
    let retention = spawn_retention(&engine, retention);
    tracing::info!(
        state_dir = %state_dir.display(),
        "oxidhome mcp-stdio ready — awaiting client on stdin",
    );
    // Round-3 P1 on PR #143: race the transport future against
    // `shutdown_signal` so SIGINT/SIGTERM enter the same bounded
    // stop / drain / flush sequence below instead of falling
    // through to the OS default (immediate termination — plugins
    // aborted mid-supervisor, log tail lost). The prior version
    // awaited `serve_stdio` directly, so ctrl-c bypassed the
    // whole cleanup path.
    let serve_result = tokio::select! {
        result = serve_stdio_with(engine.clone(), options) => result,
        signal = shutdown_signal() => {
            tracing::info!(signal = signal, "shutdown signal received; draining stdio session");
            Ok(())
        }
    };

    // Round-2 P1 on PR #143: same bounded shutdown the HTTP
    // daemon runs. Stdio exposes wildcard `plugins.start`, so
    // live supervisors may exist when the client hangs up;
    // without this the tokio runtime teardown would abort them
    // mid-cleanup and leave partially-evicted device / service
    // state behind. Best-effort by design — deadlines mirror
    // the daemon's so a wedged supervisor doesn't wedge exit.
    let _ = engine
        .stop_all_supervised_instances(SHUTDOWN_STOP_PER_INSTANCE_DEADLINE)
        .await;
    let _ = engine
        .drain_supervised_instances_with_timeout(SHUTDOWN_REAPER_DRAIN_DEADLINE)
        .await;
    drain_state_read_audit(&engine).await;
    stop_retention(retention).await;
    close_state_writers(&engine).await;

    tracing::info!("oxidhome mcp-stdio session closed");
    // Flush the log writer before returning so the tail of the
    // session lands in `<state_dir>/oxidhome.db`. Matches the
    // daemon's happy-path drain (round-2 P2 on PR #143).
    if !log_store.flush(SHUTDOWN_FLUSH_BUDGET) {
        tracing::warn!(
            sent = log_store.sent(),
            written = log_store.written(),
            dropped = log_store.dropped(),
            "log_store: flush budget exceeded — some tail rows may be lost",
        );
    }

    // Propagate the serve error AFTER cleanup so cleanup still
    // runs on a mid-session transport failure.
    serve_result.context("MCP stdio session failed")
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

#[cfg(test)]
mod tests {
    use super::*;

    /// H6 slice 4: `--deny` takes services as listings show them.
    #[test]
    fn token_create_denies_services_or_categories() {
        let args: Vec<String> = [
            "kiosk",
            "--deny",
            "service.call{acme.notify/send,zwave.*}",
            "--deny",
            "device.command@lock,alarm",
            "--deny",
            "*",
        ]
        .map(str::to_owned)
        .to_vec();
        let req = parse_token_create(&args).expect("parse");
        assert_eq!(req.deny[0].actions, vec!["service.call"]);
        assert_eq!(
            req.deny[0].services,
            Some(vec!["acme.notify/send".to_owned(), "zwave.*".to_owned()])
        );
        assert_eq!(req.deny[0].category, None);
        assert_eq!(
            req.deny[1].category,
            Some(vec!["lock".to_owned(), "alarm".to_owned()])
        );
        assert_eq!(req.deny[1].services, None);
        assert_eq!(
            (req.deny[2].category.as_ref(), req.deny[2].services.as_ref()),
            (None, None)
        );
        // A listed deny reads back as itself.
        let listed = oxidhome_core::auth::DenyRule {
            actions: oxidhome_core::auth::ActionSet::of(&[
                oxidhome_core::auth::Action::ServiceCall,
            ]),
            categories: None,
            devices: None,
            services: Some(vec!["acme.notify/send".into(), "acme.alarm".into()]),
        }
        .describe();
        let args: Vec<String> = ["kiosk", "--deny", listed.as_str()]
            .map(str::to_owned)
            .to_vec();
        let req = parse_token_create(&args).expect("parse");
        assert_eq!(
            req.deny[0].services,
            Some(vec!["acme.notify/send".to_owned(), "acme.alarm".to_owned()])
        );
    }

    #[test]
    fn tls_pin_reset_takes_no_option_as_an_instance() {
        for args in [
            &["reset", "--all", "cam"][..],
            &["reset", "--inst", "cam"],
            &["reset", "--inst", "cam", "443"],
            &["reset", "-x"],
            &["reset", "cam", "camera.lan", "443", "extra"],
        ] {
            assert!(parse_tls_pin_args(args).is_err(), "{args:?}");
        }
        let (reset, filter) = parse_tls_pin_args(&["reset", "cam", "camera.lan", "443"])
            .unwrap()
            .unwrap();
        assert!(reset);
        assert_eq!(filter.scope(), "cam/camera.lan:443");
        let (_, filter) = parse_tls_pin_args(&["reset", "--instance", "-odd", "camera.lan"])
            .unwrap()
            .unwrap();
        assert_eq!(filter.scope(), "-odd/camera.lan");
        let (reset, filter) = parse_tls_pin_args(&["reset", "--all"]).unwrap().unwrap();
        assert!(reset);
        assert_eq!(filter.scope(), "*");
        assert!(parse_tls_pin_args(&[]).unwrap().is_none());
    }

    #[test]
    fn plugin_list_shows_each_rule_under_its_plugin() {
        use oxidhome_core::state::{NetworkGrants, OfflinePlugin};
        let rule = |r: &str| r.parse::<oxidhome_manifest::NetworkRule>().unwrap();
        let plugins = [
            OfflinePlugin {
                plugin_id: "net.example.cam".into(),
                installation_uuid: "inst-1".into(),
                status: Ok((
                    "1.2.0".into(),
                    NetworkGrants::new(
                        &[rule("tcp://192.168.0.0/16:554")],
                        &[rule("tcp://192.168.1.20:554")],
                    ),
                )),
            },
            OfflinePlugin {
                plugin_id: "net.example.old".into(),
                installation_uuid: "inst-2".into(),
                status: Err("contents changed since install; reinstall".into()),
            },
        ];
        assert_eq!(
            format_plugin_list(&plugins),
            "net.example.cam\t1.2.0\tinstallation=inst-1\n\
             \trequested\ttcp://192.168.0.0/16:554\n\
             \tgranted\ttcp://192.168.1.20:554\n\
             \teffective\ttcp://192.168.1.20:554\n\
             net.example.old\tunavailable\tinstallation=inst-2\t\
             contents changed since install; reinstall\n"
        );
    }

    #[test]
    fn plugin_list_escapes_control_characters() {
        assert_eq!(
            printable("tcp://a\u{1b}[2Jb.lan:1"),
            "tcp://a\\u{1b}[2Jb.lan:1"
        );
        assert_eq!(printable("plain"), "plain");
        assert_eq!(printable("a\u{202e}b"), "a\\u{202e}b");
    }
}
