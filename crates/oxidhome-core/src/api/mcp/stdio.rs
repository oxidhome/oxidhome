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
//! `authorize` decisions land as `allow`; the audit ledger
//! records every action with that exact token id, distinct from
//! any HTTP token id an operator would mint, so a forensic
//! sweep filters mcp-stdio traffic by matching on it.
//!
//! The ambient actor is **not** the owner (H6 slice 2, Q7): like any
//! wildcard token it doesn't reach lock / opener / alarm commands or
//! camera bytes. The operator opts in per category when launching the
//! subprocess, `oxidhome mcp-stdio --allow-sensitive lock
//! --allow-sensitive camera` ([`StdioOptions::allow_sensitive`]);
//! allowed sensitive actions are then rate limited and leave `warn`
//! audit rows like any token's.
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
use crate::auth::{Actor, SensitiveCategory, SensitiveGrant};

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

/// Operator choices for an `mcp-stdio` session.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StdioOptions {
    /// Sensitive categories the session may reach
    /// (`--allow-sensitive <category>`, repeatable). Empty by default:
    /// the ambient wildcard actor doesn't reach locks, openers, alarms
    /// or camera bytes.
    pub allow_sensitive: Vec<SensitiveCategory>,
}

/// Audit token id of the ambient `mcp-stdio` actor.
pub const STDIO_TOKEN_ID: &str = "mcp-stdio-parent-process";

/// The ambient actor an `mcp-stdio` session runs as: wildcard scopes,
/// not the owner, plus the operator's `--allow-sensitive` categories.
#[must_use]
pub fn stdio_actor(options: &StdioOptions) -> Actor {
    // See the module-doc's "Auth" section for the rationale. The id
    // lands in the audit ledger under `actor_kind = api` (same shape
    // HTTP tokens use), distinct so operators can filter mcp-stdio
    // traffic from HTTP-token traffic in a forensic sweep.
    Actor::api(STDIO_TOKEN_ID, vec!["*".to_string()]).with_sensitive(
        options
            .allow_sensitive
            .iter()
            .map(|c| SensitiveGrant::all(*c))
            .collect(),
    )
}

/// Convenience: serve MCP over the process's stdin / stdout
/// until the client disconnects, with default [`StdioOptions`].
pub async fn serve_stdio(engine: Engine) -> Result<(), ServeStdioError> {
    serve_stdio_with(engine, StdioOptions::default()).await
}

/// [`serve_stdio`] with explicit [`StdioOptions`]. Called by
/// `oxidhome mcp-stdio`.
pub async fn serve_stdio_with(
    engine: Engine,
    options: StdioOptions,
) -> Result<(), ServeStdioError> {
    let (stdin, stdout) = rmcp::transport::stdio();
    serve_stdio_over_with(engine, &options, stdin, stdout).await
}

/// The transport-agnostic core: run one MCP session over the
/// given `(reader, writer)` pair, with default [`StdioOptions`].
/// Public so tests can drive it against a `tokio::io::duplex()`
/// in-memory pipe.
pub async fn serve_stdio_over<R, W>(
    engine: Engine,
    reader: R,
    writer: W,
) -> Result<(), ServeStdioError>
where
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
{
    serve_stdio_over_with(engine, &StdioOptions::default(), reader, writer).await
}

/// [`serve_stdio_over`] with explicit [`StdioOptions`].
pub async fn serve_stdio_over_with<R, W>(
    engine: Engine,
    options: &StdioOptions,
    reader: R,
    writer: W,
) -> Result<(), ServeStdioError>
where
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
{
    let actor = stdio_actor(options);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{
        Action, ActorKind, DeviceCategory, DeviceClass, InvocationContext, Principal, Resource,
        Transport, authorize,
    };

    fn decide(options: &StdioOptions, category: DeviceCategory, action: Action) -> bool {
        let actor = stdio_actor(options);
        let ctx = InvocationContext::external(Principal::token(
            ActorKind::Api,
            &actor,
            Transport::McpStdio,
        ));
        let resource = Resource::device("dev-0000000000000001", DeviceClass::of(category));
        authorize(&ctx, action, &resource).allow
    }

    #[test]
    fn stdio_actor_reaches_sensitive_categories_only_when_allowed() {
        let default = StdioOptions::default();
        assert!(decide(
            &default,
            DeviceCategory::Light,
            Action::DeviceCommand
        ));
        assert!(!decide(
            &default,
            DeviceCategory::Lock,
            Action::DeviceCommand
        ));
        assert!(!decide(&default, DeviceCategory::Camera, Action::BlobRead));
        assert!(!stdio_actor(&default).is_owner());

        let lock = StdioOptions {
            allow_sensitive: vec![SensitiveCategory::Lock],
        };
        assert!(decide(&lock, DeviceCategory::Lock, Action::DeviceCommand));
        assert!(!decide(
            &lock,
            DeviceCategory::Opener,
            Action::DeviceCommand
        ));
        assert!(!decide(&lock, DeviceCategory::Camera, Action::BlobRead));
    }
}
