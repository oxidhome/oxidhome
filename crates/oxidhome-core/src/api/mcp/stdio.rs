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
//! state dir. The session runs as an ambient actor holding one role,
//! `oxidhome mcp-stdio --role <name>` ([`StdioOptions::role`], the
//! built-in `agent` by default), and is never the owner. The audit
//! ledger records every action with the token id [`STDIO_TOKEN_ID`],
//! distinct from any minted token's, so a forensic sweep filters
//! mcp-stdio traffic by matching on it. Sensitive categories (lock,
//! opener and alarm commands, camera bytes) are reached only when the
//! chosen role grants them, and leave `warn` audit rows like any
//! token's.
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
    #[error("unknown role `{0}`")]
    UnknownRole(String),
    #[error("role `{0}`'s stored definition doesn't parse")]
    BadRole(String),
    #[error("reading role `{0}` failed: {1}")]
    RoleStore(String, String),
}

/// Operator choices for an `mcp-stdio` session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StdioOptions {
    /// The role the session holds (`--role <name>`): built-in or
    /// custom. `agent` by default.
    pub role: String,
}

impl Default for StdioOptions {
    fn default() -> Self {
        Self {
            role: "agent".to_owned(),
        }
    }
}

/// Audit token id of the ambient `mcp-stdio` actor.
pub const STDIO_TOKEN_ID: &str = "mcp-stdio-parent-process";

/// The ambient actor an `mcp-stdio` session runs as: the role
/// `options` names, not the owner.
///
/// # Errors
///
/// [`ServeStdioError::UnknownRole`] when no role has that name or its
/// definition can't be read.
pub fn stdio_actor(engine: &Engine, options: &StdioOptions) -> Result<Actor, ServeStdioError> {
    let name = &options.role;
    if let Some(role) = crate::auth::role::builtin(name) {
        return Ok(Actor::api(STDIO_TOKEN_ID, vec![role]));
    }
    let rows = engine
        .auth_tokens()
        .roles_by_name(std::slice::from_ref(name))
        .map_err(|e| ServeStdioError::RoleStore(name.clone(), e.to_string()))?;
    let row = rows
        .first()
        .ok_or_else(|| ServeStdioError::UnknownRole(name.clone()))?;
    let role = std::sync::Arc::new(
        row.def()
            .ok_or_else(|| ServeStdioError::BadRole(name.clone()))?,
    );
    Ok(Actor::api(STDIO_TOKEN_ID, vec![role]))
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
    let actor = stdio_actor(&engine, options)?;
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

    fn decide(engine: &Engine, role: &str, category: DeviceCategory, action: Action) -> bool {
        let options = StdioOptions { role: role.into() };
        let actor = stdio_actor(engine, &options).expect("role");
        assert!(!actor.is_owner());
        let ctx = InvocationContext::external(Principal::token(
            ActorKind::Api,
            &actor,
            Transport::McpStdio,
        ));
        let resource = Resource::device("dev-0000000000000001", DeviceClass::of(category));
        authorize(&ctx, action, &resource).allow
    }

    #[test]
    fn stdio_actor_holds_the_named_role() {
        let engine = Engine::new().expect("engine");
        assert_eq!(StdioOptions::default().role, "agent");
        assert!(decide(
            &engine,
            "agent",
            DeviceCategory::Light,
            Action::DeviceCommand
        ));
        assert!(!decide(
            &engine,
            "agent",
            DeviceCategory::Lock,
            Action::DeviceCommand
        ));
        assert!(decide(
            &engine,
            "member",
            DeviceCategory::Lock,
            Action::DeviceCommand
        ));
        engine
            .auth_tokens()
            .create_role(
                "doors",
                br#"[{"actions":["device.command"],"category":["lock"]}]"#,
            )
            .unwrap();
        assert!(decide(
            &engine,
            "doors",
            DeviceCategory::Lock,
            Action::DeviceCommand
        ));
        assert!(!decide(
            &engine,
            "doors",
            DeviceCategory::Opener,
            Action::DeviceCommand
        ));
        assert!(matches!(
            stdio_actor(
                &engine,
                &StdioOptions {
                    role: "nope".into()
                }
            ),
            Err(ServeStdioError::UnknownRole(_))
        ));
    }
}
