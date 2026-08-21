//! MCP mount for the host axum router.
//!
//! Builds a [`rmcp`] [`StreamableHttpService`] with a bounded
//! [`BoundedSessionManager`] and mounts it under [`MCP_ENDPOINT`]
//! on the main axum router so REST, Connect, and MCP share one
//! bind and one lifecycle.
//!
//! # What `rmcp` gives us for free
//!
//! - **Notification / response HTTP shape** matching the MCP
//!   HTTP spec: `202 Accepted` for JSON-RPC notifications and
//!   responses, real errors preserved on malformed input
//!   (round-3 F1 from the old SDK — resolved).
//! - **`Origin` + `Host` DNS-rebinding guard** via
//!   [`StreamableHttpServerConfig::allowed_hosts`] /
//!   `allowed_origins` — the default `allowed_hosts` is the
//!   loopback family (`localhost`, `127.0.0.1`, `::1`), which
//!   is exactly the policy our hand-rolled `origin.rs`
//!   middleware enforced (round-2 F2 — resolved).
//! - **Public `SessionManager::close_session`** so eviction
//!   actually terminates the session worker + transport
//!   (round-3 F3 — resolved). We reuse
//!   [`LocalSessionManager`]'s built-in `keep_alive` (5 min
//!   default) for idle eviction.
//!
//! # What we own
//!
//! - The `service_factory` closure that builds an
//!   [`OxidHomeMcpHandler`] per session; the closure carries a
//!   cheap `Engine` clone (Arc-backed internally).
//! - The admission cap via
//!   [`BoundedSessionManager`] — the SDK's own store is
//!   unbounded, so we wrap it.
//! - The final mount path (`/api/v1/mcp`) so REST + Connect
//!   siblings sit under one clean prefix.

use std::sync::Arc;

use axum::Router;
use rmcp::transport::streamable_http_server::{
    StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
};

use crate::Engine;

use super::handler::OxidHomeMcpHandler;
use super::session_store::BoundedSessionManager;

/// Public URL prefix the MCP surface mounts under. Callers
/// POST/GET/DELETE this exact path for the streamable-HTTP
/// transport. Kept public so the CLI walkthrough + integration
/// tests point clients at one string instead of a magic literal
/// that could drift.
pub const MCP_ENDPOINT: &str = "/api/v1/mcp";

/// Maximum concurrent MCP sessions retained in memory. Sized
/// for a home hub with one operator; a session count beyond
/// this range is either an abuser or a client bug. 14.4 wires
/// per-token limits, at which point this becomes a config knob.
const MAX_SESSIONS: usize = 128;

/// Build the MCP mount. The returned router carries its own
/// state (session manager + service factory) and is ready to
/// `.merge` into [`crate::api::build_router`].
///
/// # Scope for 14.1
///
/// - No bearer guard on the mount itself — 14.4 wraps this
///   router in our token layer so the same token store gates
///   MCP + REST. `rmcp`'s built-in `allowed_hosts` allow-list
///   keeps a browser-driven DNS-rebind attempt out today.
/// - Session manager is [`BoundedSessionManager`] with a
///   modest cap ([`MAX_SESSIONS`]); the inner
///   [`LocalSessionManager`]'s 5-minute `keep_alive` handles
///   idle eviction and properly terminates the transport.
/// - `stdio` transport (14.5) and prompts / tools / resources
///   (14.2 / 14.3 / 14.6) land on top of this mount without
///   touching the transport wiring.
pub fn mount_routes(engine: &Engine) -> Router {
    let session_manager = Arc::new(BoundedSessionManager::new(
        LocalSessionManager::default(),
        MAX_SESSIONS,
    ));
    let handler_engine = engine.clone();
    let config = StreamableHttpServerConfig::default()
        // Defense-in-depth alongside the (default) Host
        // loopback allow-list: even when a client sends a
        // spoofed `Host: localhost` header, its `Origin` must
        // also be loopback-family. The default config leaves
        // this list empty (Origin validation off); we opt in
        // so the DNS-rebind hole from PR #119 R2 F2 stays
        // shut on a defense-in-depth basis.
        .with_allowed_origins([
            "http://localhost",
            "https://localhost",
            "http://127.0.0.1",
            "https://127.0.0.1",
            "http://[::1]",
            "https://[::1]",
        ]);
    let service = StreamableHttpService::new(
        move || Ok(OxidHomeMcpHandler::new(handler_engine.clone())),
        session_manager,
        config,
    );
    Router::new().nest_service(MCP_ENDPOINT, service)
}
