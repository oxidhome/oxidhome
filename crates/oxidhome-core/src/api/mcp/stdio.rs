//! Phase 14.5 — MCP stdio transport (`oxidhome mcp-stdio`).
//!
//! Serves the same [`OxidHomeMcpHandler`] the HTTP mount uses,
//! but over `(stdin, stdout)` via rmcp's `transport-io` feature.
//! Intended shape:
//!
//! ```text
//! MCP client (Claude Desktop / MCP Inspector / agent SDK)
//!   ↓ spawn as subprocess
//! oxidhome mcp-stdio
//!   → own Engine against $OXIDHOME_STATE_DIR
//!   → framed JSON-RPC over stdin/stdout
//! ```
//!
//! # Auth
//!
//! No bearer tokens; the trust boundary is the process itself.
//! The parent process launched us with filesystem access to the
//! state dir, so it already has the operator's authority. The
//! handler runs under a wildcard-scope
//! `Actor::api("mcp-stdio-parent-process", ["*"])` so
//! `require_scope` decisions land as `allow`; the audit ledger
//! records every action with that exact token id, distinct from
//! any HTTP token id an operator would mint, so a forensic
//! sweep filters mcp-stdio traffic by matching on it.
//!
//! # Engine ownership
//!
//! The subprocess opens its own [`Engine`] against the state
//! dir. **State-dir ownership is exclusive across processes**
//! (round-1 P1 on PR #143): the daemon and the stdio subprocess
//! each hold per-process in-memory registries (device,
//! instance, event, service, per-plugin lifecycle locks) that
//! `SQLite` WAL does NOT synchronise across processes. Running
//! stdio against a state dir already owned by the HTTP daemon
//! would serve stale reads AND let mutating tools
//! (`plugins.uninstall` in particular) act on an empty
//! subprocess-local instance registry while the daemon's
//! supervisor kept running — deleting a live plugin's on-disk
//! footprint out from under it. The daemon binary and the
//! `mcp-stdio` subprocess both acquire an exclusive
//! `flock` on `<state_dir>/.oxidhome.lock` at startup and fail
//! fast if it's held. Operators who want both surfaces
//! concurrently point them at distinct state dirs (or use the
//! HTTP mount from the stdio client instead).
//!
//! # Shutdown
//!
//! `serve_server` returns when either side closes the transport
//! (stdin EOF, JSON-RPC `shutdown`, or a fatal frame error).
//! Signal handling is the **binary's** responsibility: the
//! `run_stdio` entrypoint (`src/main.rs`) races this call
//! against `shutdown_signal()` in a `tokio::select!` so
//! `SIGINT` / `SIGTERM` enter the same bounded stop + drain
//! sequence the HTTP daemon uses (round-3 P1 on PR #143 — the
//! pre-fix doc's "SIGINT ripples through as stdin EOF" was
//! wrong; on Unix the default `SIGINT` disposition is
//! immediate termination unless a handler is installed).

use tokio::io::{AsyncRead, AsyncWrite};

use crate::Engine;
use crate::auth::Actor;

use super::handler::OxidHomeMcpHandler;

/// Errors surfaceable from [`serve_stdio`]. Split from
/// `anyhow::Error` so the daemon binary can attach its own
/// context (e.g. the state-dir path).
#[derive(Debug, thiserror::Error)]
pub enum ServeStdioError {
    #[error("stdio MCP handshake / serve failed: {0}")]
    Serve(String),
    #[error("stdio MCP session task join failed: {0}")]
    Join(#[from] tokio::task::JoinError),
}

/// Convenience: serve MCP over the process's stdin / stdout
/// until the client disconnects. Called by
/// `oxidhome mcp-stdio`.
pub async fn serve_stdio(engine: Engine) -> Result<(), ServeStdioError> {
    let (stdin, stdout) = rmcp::transport::stdio();
    serve_stdio_over(engine, stdin, stdout).await
}

/// The transport-agnostic core: run one MCP session over the
/// given `(reader, writer)` pair. Public so tests can drive it
/// against a `tokio::io::duplex()` in-memory pipe.
pub async fn serve_stdio_over<R, W>(
    engine: Engine,
    reader: R,
    writer: W,
) -> Result<(), ServeStdioError>
where
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
{
    // Ambient wildcard actor — see the module-doc's "Auth"
    // section for the rationale. The `stdio-parent-process`
    // id lands in the audit ledger under
    // `actor_kind = api` (same shape HTTP tokens use) with a
    // distinct id so operators can filter mcp-stdio traffic
    // from HTTP-token traffic in a forensic sweep.
    let actor = Actor::api("mcp-stdio-parent-process", vec!["*".to_string()]);
    let handler = OxidHomeMcpHandler::for_stdio(engine, actor);

    let service = rmcp::serve_server(handler, (reader, writer))
        .await
        .map_err(|e| ServeStdioError::Serve(e.to_string()))?;
    // `waiting` resolves when the transport closes (stdin EOF
    // or client-initiated shutdown). `Ok(_)` on either quit
    // reason — the session ran to completion.
    let _quit = service.waiting().await?;
    Ok(())
}
