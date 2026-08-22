//! Bounded [`SessionManager`] for the MCP streamable-HTTP mount.
//!
//! Wraps [`LocalSessionManager`] with a semaphore-based
//! admission pool: at most [`BoundedSessionManager::cap`] live
//! sessions at any time. Admission happens *before* the SDK
//! dispatches into `create_session` (see the middleware in
//! [`super::server`]), so a burst of concurrent `initialize`
//! requests past the cap replies `503 Service Unavailable`
//! with no SDK ERROR log, no half-created session, and no
//! client-visible "200 but 404 on follow-ups".
//!
//! # Permit lifecycle
//!
//! 1. Middleware calls [`BoundedSessionManager::try_admit`]
//!    for every POST that could be an `initialize` (no
//!    `mcp-session-id` header, body already buffered under
//!    the middleware's body-deadline). If a permit is
//!    available, it reserves one slot; if not, the middleware
//!    returns 503 before the SDK sees the request.
//! 2. If the response carries a session id header ⇒ the SDK
//!    admitted a real session ⇒ middleware calls
//!    [`Admission::commit`] with that id, which forgets the
//!    permit and records the id in [`Self::live`].
//! 3. On session teardown — client DELETE, worker exit, idle
//!    keep-alive — the SDK calls
//!    [`SessionManager::close_session`] on this wrapper, which
//!    removes the id from [`Self::live`] and returns the slot
//!    to the pool.
//!
//! # Why per-`SessionId` tracking (not a global counter)
//!
//! PR #119 R5 F1. The SDK's `spawn_session_worker` calls
//! `close_session` when the worker exits; the same session can
//! also receive a client `DELETE`, which calls `close_session`
//! again. Two concurrent close paths for the same session both
//! read `sessions.contains_key(id) == true` (the inner map
//! removal is atomic — only one physically removes). A prior
//! shape used a global `AtomicUsize` and both close paths
//! would decrement + release — an extra permit escaped for
//! every double-close, and with N doubles the effective cap
//! grew to `cap + N`. Recording admissions in a
//! `HashSet<SessionId>` and releasing only when
//! [`HashSet::remove`] actually removed the id makes the
//! release exactly-once per session, regardless of how many
//! close paths race.
//!
//! # What comes free from `rmcp`
//!
//! - Idle eviction that actually terminates streams:
//!   `LocalSessionManager::SessionConfig::keep_alive` (default
//!   5 min) closes the session worker and drops the transport.
//! - `Origin` / `Host` allow-lists sit on the SDK's
//!   `StreamableHttpServerConfig`.
//! - Spec-compliant `202 Accepted` for notifications /
//!   responses.

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::Mutex;

use futures_util::Stream;
use rmcp::transport::common::server_side_http::ServerSseMessage;
use rmcp::{
    model::{ClientJsonRpcMessage, ServerJsonRpcMessage},
    transport::streamable_http_server::session::{
        RestoreOutcome, SessionId, SessionManager,
        local::{LocalSessionManager, LocalSessionManagerError},
    },
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Semaphore-backed admission gate on top of
/// [`LocalSessionManager`]. See the module doc.
pub struct BoundedSessionManager {
    inner: Arc<LocalSessionManager>,
    /// One permit per admission slot. `add_permits(1)` returns
    /// a slot to the pool when a live session is torn down.
    permits: Arc<Semaphore>,
    /// Sessions that currently hold a committed admission
    /// permit. Keyed by id so [`SessionManager::close_session`]
    /// releases exactly-once per session even when the SDK's
    /// worker-exit and client-DELETE paths race for the same
    /// id.
    live: Mutex<HashSet<SessionId>>,
    cap: usize,
}

impl BoundedSessionManager {
    pub fn new(inner: LocalSessionManager, cap: usize) -> Self {
        Self {
            inner: Arc::new(inner),
            permits: Arc::new(Semaphore::new(cap)),
            live: Mutex::new(HashSet::new()),
            cap,
        }
    }

    /// Cap this store was created with. Public so the
    /// middleware can log it when it 503s.
    pub fn cap(&self) -> usize {
        self.cap
    }

    /// Try to reserve one admission slot. `Some(Admission)`
    /// under cap; `None` at cap. The returned handle either
    /// [`Admission::commit`]s the slot to a live session or
    /// drops it back to the pool at end-of-scope.
    pub fn try_admit(self: &Arc<Self>) -> Option<Admission> {
        let permit = self.permits.clone().try_acquire_owned().ok()?;
        Some(Admission {
            permit: Some(permit),
            mgr: self.clone(),
        })
    }
}

/// RAII-style handle for a reserved admission slot. Dropping
/// without a `commit` returns the slot to the pool immediately.
pub struct Admission {
    permit: Option<OwnedSemaphorePermit>,
    mgr: Arc<BoundedSessionManager>,
}

impl Admission {
    /// The SDK admitted a real session — attach the reserved
    /// slot to it by id. The permit is deliberately forgotten
    /// so it stays out of the pool until
    /// [`SessionManager::close_session`] removes the id from
    /// [`BoundedSessionManager::live`].
    pub fn commit(mut self, session_id: SessionId) {
        if let Some(permit) = self.permit.take() {
            permit.forget();
            self.mgr
                .live
                .lock()
                .expect("live-session set is not poisoned")
                .insert(session_id);
        }
    }
}

impl SessionManager for BoundedSessionManager {
    type Error = LocalSessionManagerError;
    type Transport = <LocalSessionManager as SessionManager>::Transport;

    async fn create_session(&self) -> Result<(SessionId, Self::Transport), Self::Error> {
        // No cap check here — admission is enforced by the
        // middleware in `super::server` before this call.
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
        self.inner.close_session(id).await?;
        // `remove` returns `true` only for the caller that
        // physically removed the id — a second close for the
        // same session sees `false` and skips `add_permits`.
        let removed = self
            .live
            .lock()
            .expect("live-session set is not poisoned")
            .remove(id);
        if removed {
            self.permits.add_permits(1);
        }
        Ok(())
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

    /// Admissions past the cap return `None`; a released slot
    /// re-opens capacity for the next admission.
    #[tokio::test(flavor = "current_thread")]
    async fn admissions_are_capped_and_released() {
        let mgr = Arc::new(BoundedSessionManager::new(
            LocalSessionManager::default(),
            2,
        ));
        let a = mgr.try_admit().expect("first admission");
        let b = mgr.try_admit().expect("second admission");
        assert!(mgr.try_admit().is_none(), "third admission must fail");

        a.commit(SessionId::from("A"));
        b.commit(SessionId::from("B"));
        assert!(mgr.try_admit().is_none(), "committed slots still hold cap");

        // Simulate the SDK closing session A.
        mgr.close_session(&SessionId::from("A"))
            .await
            .expect("close");
        assert!(
            mgr.try_admit().is_some(),
            "close must return the slot for that session id to the pool",
        );
    }

    /// R5 F1: two concurrent close paths for the same session
    /// (worker-exit + client-DELETE) must release exactly one
    /// permit. Prior shape used a global counter and released
    /// twice — with cap 2 and one session double-closed, an
    /// attacker could grow the effective cap to 3.
    #[tokio::test(flavor = "current_thread")]
    async fn double_close_releases_exactly_one_permit() {
        let mgr = Arc::new(BoundedSessionManager::new(
            LocalSessionManager::default(),
            2,
        ));
        // Both slots committed.
        mgr.try_admit()
            .expect("admit A")
            .commit(SessionId::from("A"));
        mgr.try_admit()
            .expect("admit B")
            .commit(SessionId::from("B"));

        // Two `close_session` calls for A — the worker-exit
        // and client-DELETE shape from the SDK.
        mgr.close_session(&SessionId::from("A"))
            .await
            .expect("close A #1");
        mgr.close_session(&SessionId::from("A"))
            .await
            .expect("close A #2");

        // Exactly one permit should have come back — B is
        // still live, so at most one admission is possible.
        let one = mgr.try_admit();
        assert!(one.is_some(), "one permit returned for A");
        let none = mgr.try_admit();
        assert!(
            none.is_none(),
            "double-close of A must NOT release B's permit — effective cap must stay at 2",
        );
    }

    /// Uncommitted admissions release automatically on drop —
    /// covers the "SDK failed after admit, before session
    /// created" path.
    #[tokio::test(flavor = "current_thread")]
    async fn uncommitted_admission_releases_on_drop() {
        let mgr = Arc::new(BoundedSessionManager::new(
            LocalSessionManager::default(),
            1,
        ));
        {
            let _a = mgr.try_admit().expect("first admission");
            assert!(mgr.try_admit().is_none());
        } // _a dropped without commit → permit auto-returned
        assert!(
            mgr.try_admit().is_some(),
            "dropped (uncommitted) admission must return the slot to the pool",
        );
    }

    /// Closing an id that was never admitted (a restore-store
    /// path we don't use today, or a spurious DELETE from a
    /// client with a stale id) must not release a permit.
    #[tokio::test(flavor = "current_thread")]
    async fn close_of_unknown_id_is_a_noop() {
        let mgr = Arc::new(BoundedSessionManager::new(
            LocalSessionManager::default(),
            1,
        ));
        mgr.try_admit()
            .expect("admit A")
            .commit(SessionId::from("A"));

        // Close a session id we never admitted.
        mgr.close_session(&SessionId::from("ghost"))
            .await
            .expect("close ghost");

        // A's slot must still be reserved — no admission
        // should succeed until A itself is closed.
        assert!(
            mgr.try_admit().is_none(),
            "close of unknown id must NOT free A's slot",
        );
    }
}
