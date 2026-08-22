//! Bounded [`SessionManager`] for the MCP streamable-HTTP mount.
//!
//! Wraps [`LocalSessionManager`] with a semaphore-based
//! admission pool: at most [`BoundedSessionManager::cap`] live
//! sessions at any time. Admission happens *before* the SDK
//! dispatches into `create_session` (see the middleware in
//! [`super::server`]), so a burst of concurrent `initialize`
//! requests past the cap replies `503 Service Unavailable`
//! with no SDK ERROR log, no half-created session, and no
//! client-visible "200 but 404 on follow-ups" (round-4 F2 —
//! resolved).
//!
//! # Permit lifecycle
//!
//! 1. Middleware calls [`BoundedSessionManager::try_admit`]
//!    for every POST that could be an `initialize` (no
//!    `mcp-session-id` header). If a permit is available, it
//!    reserves one slot; if not, the middleware returns 503
//!    before the SDK sees the request.
//! 2. If the response carries a session id header ⇒ the SDK
//!    admitted a real session ⇒ middleware calls
//!    [`Admission::commit`], which forgets the permit and
//!    bumps [`Self::live`].
//! 3. On session teardown — client DELETE, worker exit, idle
//!    keep-alive — the SDK calls
//!    [`SessionManager::close_session`] on this wrapper, which
//!    returns the slot to the pool via [`Self::release`].
//!
//! The `live` counter guards against double-releases: the SDK
//! can invoke `close_session` twice for one session (worker
//! exit + client DELETE), but [`Self::release`] uses
//! `fetch_update` with `checked_sub`, so a second call for the
//! same session is a no-op.
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

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

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
    /// Count of admissions currently attached to live sessions.
    /// Guards [`Self::release`] against double-decrements
    /// (worker-exit + client DELETE for the same session both
    /// route through `close_session`).
    live: AtomicUsize,
    cap: usize,
}

impl BoundedSessionManager {
    pub fn new(inner: LocalSessionManager, cap: usize) -> Self {
        Self {
            inner: Arc::new(inner),
            permits: Arc::new(Semaphore::new(cap)),
            live: AtomicUsize::new(0),
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

    /// Release one admission slot back to the pool if there's
    /// a live one to release. `fetch_update` with `checked_sub`
    /// makes this safe against double-calls (see the module
    /// doc's Permit lifecycle notes).
    fn release(&self) {
        let did = self
            .live
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok();
        if did {
            self.permits.add_permits(1);
        }
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
    /// slot to it. The permit is deliberately forgotten so it
    /// stays out of the pool until the session closes.
    pub fn commit(mut self) {
        if let Some(permit) = self.permit.take() {
            permit.forget();
            self.mgr.live.fetch_add(1, Ordering::SeqCst);
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
        // Snapshot presence before delegating so we only
        // release the admission slot for sessions the wrapper
        // knows about. `release` is idempotent per session via
        // `live`, so a concurrent close_session pair on the
        // same id still nets to one release.
        let was_present = self.inner.sessions.read().await.contains_key(id);
        self.inner.close_session(id).await?;
        if was_present {
            self.release();
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

        a.commit();
        b.commit();
        assert_eq!(mgr.live.load(Ordering::SeqCst), 2);
        // Still no room — committed permits are attached to
        // "live" sessions until `release` fires.
        assert!(mgr.try_admit().is_none());

        mgr.release();
        assert!(
            mgr.try_admit().is_some(),
            "release must re-open a slot in the semaphore",
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

    /// `release` is idempotent per admitted session so the
    /// SDK's worker-exit + client-DELETE double-call for the
    /// same session doesn't over-release.
    #[tokio::test(flavor = "current_thread")]
    async fn release_is_idempotent_per_session() {
        let mgr = Arc::new(BoundedSessionManager::new(
            LocalSessionManager::default(),
            1,
        ));
        mgr.try_admit().expect("admission").commit();
        assert_eq!(mgr.live.load(Ordering::SeqCst), 1);

        mgr.release();
        assert_eq!(mgr.live.load(Ordering::SeqCst), 0);
        // Second release for the same session — must not
        // grant an extra permit.
        mgr.release();
        assert_eq!(mgr.live.load(Ordering::SeqCst), 0);
        assert_eq!(
            mgr.permits.available_permits(),
            1,
            "cap must remain at 1 after a double-release",
        );
    }
}
