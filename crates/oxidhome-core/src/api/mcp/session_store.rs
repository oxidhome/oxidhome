//! Bounded, atomically-admitted MCP session store.
//!
//! PR #119 round-2 F3. The SDK's [`InMemorySessionStore`] is
//! not enough:
//!
//! - `is_full()` and `set()` are separate awaits on the same
//!   trait, so N concurrent `initialize` requests all see
//!   "not full" and all insert — the cap overshoots by the
//!   parallelism factor.
//! - Its idle-TTL sweep drops the [`ServerRuntime`] from the
//!   map without terminating it, so a client that opened a GET
//!   stream keeps its runtime + reader task alive after the
//!   entry vanishes.
//!
//! [`BoundedSessionStore`] fixes the first: `set()` acquires
//! one lock and checks the cap under it, so overshoot is bounded
//! by the store's own concurrency (one at a time) rather than
//! the request concurrency.
//!
//! The second is only partially addressable from outside the
//! SDK: `ServerRuntime::shutdown` is `pub(crate)`, so we can't
//! actively terminate an evicted runtime. We drop the [`Arc`]
//! and let the transport reader detect EOF next time it wakes;
//! the follow-up in [`crate::api::mcp`]'s module doc tracks the
//! upstream request for a public shutdown hook.
//!
//! [`InMemorySessionStore`]:
//!   rust_mcp_sdk::session_store::InMemorySessionStore
//! [`ServerRuntime`]: rust_mcp_sdk::mcp_server::ServerRuntime

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use rust_mcp_sdk::{SessionId, mcp_server::ServerRuntime, session_store::SessionStore};
use tokio::sync::Mutex;

/// One stored session + when it was last touched.
struct Entry {
    runtime: Arc<ServerRuntime>,
    last_access: Instant,
}

/// Atomic-admission session store.
///
/// A single [`tokio::sync::Mutex`] guards a `HashMap`; every
/// mutation runs under it so `is_full` + `set` cannot race with
/// each other and admission is bounded exactly by
/// [`BoundedSessionStore::max_sessions`]. Read paths take the
/// same lock but are extremely short (map lookup + `Arc::clone`).
pub struct BoundedSessionStore {
    inner: Mutex<HashMap<SessionId, Entry>>,
    max_sessions: usize,
    idle_ttl: Duration,
}

impl BoundedSessionStore {
    pub fn new(max_sessions: usize, idle_ttl: Duration) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            max_sessions,
            idle_ttl,
        }
    }

    /// Drops every entry whose `last_access` is older than
    /// [`Self::idle_ttl`]. Runs under the caller's lock — no
    /// deadlock risk. We only drop the [`Arc<ServerRuntime>`];
    /// see the module doc for the SDK-shutdown limitation.
    fn evict_idle(map: &mut HashMap<SessionId, Entry>, idle_ttl: Duration) {
        let now = Instant::now();
        map.retain(|_, entry| now.duration_since(entry.last_access) <= idle_ttl);
    }
}

#[async_trait]
impl SessionStore for BoundedSessionStore {
    async fn get(&self, key: &SessionId) -> Option<Arc<ServerRuntime>> {
        let mut guard = self.inner.lock().await;
        Self::evict_idle(&mut guard, self.idle_ttl);
        let entry = guard.get_mut(key)?;
        entry.last_access = Instant::now();
        Some(Arc::clone(&entry.runtime))
    }

    async fn set(&self, key: SessionId, value: Arc<ServerRuntime>) {
        let mut guard = self.inner.lock().await;
        Self::evict_idle(&mut guard, self.idle_ttl);
        // Reject silently when at cap — the SDK's `set` trait
        // returns `()` and its callers (specifically
        // `start_new_session`) already gated on `is_full`
        // before minting the runtime, so a rejected insert
        // here means the caller lost the atomicity race with
        // a concurrent init. Better to drop the extra
        // runtime than blow the cap.
        if guard.len() >= self.max_sessions {
            tracing::warn!(
                "MCP session store at cap ({}) — silently dropping runtime for session {}. \
                 A concurrent `initialize` won the admission race after this one saw \
                 is_full=false; that's the bounded-overshoot fallback.",
                self.max_sessions,
                &key,
            );
            return;
        }
        guard.insert(
            key,
            Entry {
                runtime: value,
                last_access: Instant::now(),
            },
        );
    }

    async fn delete(&self, key: &SessionId) {
        let mut guard = self.inner.lock().await;
        guard.remove(key);
    }

    async fn has(&self, session: &SessionId) -> bool {
        self.inner.lock().await.contains_key(session)
    }

    async fn keys(&self) -> Vec<SessionId> {
        self.inner.lock().await.keys().cloned().collect()
    }

    async fn values(&self) -> Vec<Arc<ServerRuntime>> {
        self.inner
            .lock()
            .await
            .values()
            .map(|e| Arc::clone(&e.runtime))
            .collect()
    }

    async fn clear(&self) {
        self.inner.lock().await.clear();
    }

    async fn is_full(&self) -> bool {
        let mut guard = self.inner.lock().await;
        Self::evict_idle(&mut guard, self.idle_ttl);
        guard.len() >= self.max_sessions
    }
}
