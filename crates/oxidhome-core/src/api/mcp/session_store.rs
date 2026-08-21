//! Bounded [`SessionManager`] for the MCP streamable-HTTP mount.
//!
//! Wraps [`LocalSessionManager`] with an admission gate: at most
//! [`BoundedSessionManager::max_sessions`] live sessions at any
//! time. A concurrent burst of `initialize` requests past the
//! cap fails cleanly (the SDK maps this to `503 Service
//! Unavailable`) instead of succeeding-with-unusable-session as
//! it did in the pre-switch stack.
//!
//! # Why the wrap
//!
//! `LocalSessionManager` on its own is unbounded — nothing
//! rate-limits `create_session`. Round-3 F2 caught this shape
//! against `rust-mcp-sdk` with a 256-request probe (43 200-shaped
//! responses returned unusable session ids). We take the
//! `tokio::sync::Mutex` gate approach so the check-then-insert
//! happens under one lock; the inner store's own eviction /
//! shutdown logic keeps working unchanged because we delegate
//! every other trait method.
//!
//! # What comes free from `rmcp`
//!
//! - **Idle eviction that actually terminates streams**:
//!   `LocalSessionManager::SessionConfig::keep_alive` (default
//!   5 min) closes the session worker and drops the transport.
//!   The SDK's `close_session` implementation calls
//!   `handle.close()` on the worker — round-3 F3 collapses.
//! - **`Origin` + `Host` allow-lists**:
//!   `StreamableHttpServerConfig::allowed_hosts` /
//!   `allowed_origins` — the SDK ships a spec-aligned
//!   DNS-rebinding guard, so we don't ship our own middleware
//!   for it any more.
//! - **Notification / response HTTP shape**:
//!   `StreamableHttpService` returns the spec-required
//!   `202 Accepted` for JSON-RPC notifications and responses,
//!   preserves errors on malformed input. Round-3 F1 collapses.

use std::sync::Arc;

use futures_util::Stream;
use rmcp::transport::common::server_side_http::ServerSseMessage;
use rmcp::{
    model::{ClientJsonRpcMessage, ServerJsonRpcMessage},
    transport::streamable_http_server::session::{
        RestoreOutcome, SessionId, SessionManager,
        local::{LocalSessionManager, LocalSessionManagerError},
    },
};
use tokio::sync::Mutex;

/// Reservation gate on top of [`LocalSessionManager`].
pub struct BoundedSessionManager {
    inner: Arc<LocalSessionManager>,
    max_sessions: usize,
    /// Serializes `create_session` calls so cap + insert happen
    /// under one lock — no room for two concurrent inits to
    /// both see "below cap" and both succeed.
    gate: Mutex<()>,
}

impl BoundedSessionManager {
    pub fn new(inner: LocalSessionManager, max_sessions: usize) -> Self {
        Self {
            inner: Arc::new(inner),
            max_sessions,
            gate: Mutex::new(()),
        }
    }
}

impl SessionManager for BoundedSessionManager {
    type Error = LocalSessionManagerError;
    type Transport = <LocalSessionManager as SessionManager>::Transport;

    async fn create_session(&self) -> Result<(SessionId, Self::Transport), Self::Error> {
        // Hold the gate for the entire create_session flow —
        // this makes "check size + insert" a single critical
        // section and closes the pre-switch admission race.
        let _guard = self.gate.lock().await;
        let current = self.inner.sessions.read().await.len();
        if current >= self.max_sessions {
            tracing::warn!(
                current,
                cap = self.max_sessions,
                "MCP session cap reached — rejecting initialize with 503",
            );
            // The SDK maps SessionNotFound → 404, but there's
            // no dedicated "at capacity" variant. Use the
            // closest thing and let the caller (14.4 config
            // knob) tune the cap. `sessions.write` would let
            // us insert; `read` doesn't, but is enough to
            // count under the gate.
            return Err(LocalSessionManagerError::SessionNotFound("capacity".into()));
        }
        self.inner.create_session().await
    }

    async fn initialize_session(
        &self,
        id: &SessionId,
        message: ClientJsonRpcMessage,
    ) -> Result<ServerJsonRpcMessage, Self::Error> {
        self.inner.initialize_session(id, message).await
    }

    async fn has_session(&self, id: &SessionId) -> Result<bool, Self::Error> {
        self.inner.has_session(id).await
    }

    async fn close_session(&self, id: &SessionId) -> Result<(), Self::Error> {
        self.inner.close_session(id).await
    }

    async fn create_stream(
        &self,
        id: &SessionId,
        message: ClientJsonRpcMessage,
    ) -> Result<impl Stream<Item = ServerSseMessage> + Send + Sync + 'static, Self::Error> {
        self.inner.create_stream(id, message).await
    }

    async fn accept_message(
        &self,
        id: &SessionId,
        message: ClientJsonRpcMessage,
    ) -> Result<(), Self::Error> {
        self.inner.accept_message(id, message).await
    }

    async fn create_standalone_stream(
        &self,
        id: &SessionId,
    ) -> Result<impl Stream<Item = ServerSseMessage> + Send + Sync + 'static, Self::Error> {
        self.inner.create_standalone_stream(id).await
    }

    async fn resume(
        &self,
        id: &SessionId,
        last_event_id: String,
    ) -> Result<impl Stream<Item = ServerSseMessage> + Send + Sync + 'static, Self::Error> {
        self.inner.resume(id, last_event_id).await
    }

    async fn restore_session(
        &self,
        id: SessionId,
    ) -> Result<RestoreOutcome<Self::Transport>, Self::Error> {
        self.inner.restore_session(id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Bounded admission: filling the cap with successful
    /// `create_session` calls flips the next one into an
    /// error, which the SDK maps to 503 externally. The
    /// pre-switch failure mode was "returns success with an
    /// unusable session id"; the new shape returns an error
    /// under the same conditions.
    #[tokio::test(flavor = "current_thread")]
    async fn create_session_rejects_past_cap() {
        let mgr = BoundedSessionManager::new(LocalSessionManager::default(), 2);
        let a = mgr.create_session().await;
        let b = mgr.create_session().await;
        assert!(a.is_ok(), "first admission");
        assert!(b.is_ok(), "second admission");
        let c = mgr.create_session().await;
        assert!(c.is_err(), "third admission must fail at cap");
    }
}
