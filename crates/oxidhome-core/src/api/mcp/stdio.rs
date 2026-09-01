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
//! [`Actor::api("mcp-stdio", ["*"])`] so `require_scope`
//! decisions land as `allow`; the audit ledger still records
//! every action under `mcp.stdio` as the actor id, distinct
//! from HTTP token ids for forensic filtering.
//!
//! # Engine ownership
//!
//! The subprocess opens its own [`Engine`] against the state
//! dir. `SQLite` WAL supports multi-process access, so running
//! stdio alongside the HTTP daemon is safe (both see the same
//! device / event / audit tables). Read consistency + write
//! ordering come from WAL's snapshot-isolation guarantees.
//!
//! # Shutdown
//!
//! `serve_server` returns when either side closes the transport
//! (stdin EOF, JSON-RPC `shutdown`, or a fatal frame error). We
//! don't install a signal handler — a `SIGINT` from the parent
//! ripples through as stdin EOF; a `SIGTERM` is the parent's
//! decision to reap the child.

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
