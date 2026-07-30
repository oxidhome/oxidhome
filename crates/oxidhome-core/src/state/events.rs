//! Per-engine event bus.
//!
//! Fans every `publish-event` call out to every subscriber:
//! plugin instances (via their [`PluginState`] subscription list),
//! host-side integration tests, and — since 12-API-c — the JSON
//! `GET /api/v1/events/tail` WebSocket + the Connect
//! `Events.TailEvents` stream.
//!
//! ## Architecture-review C2d + C2e
//!
//! 1. **C2d — per-instance publish rate limit.** `admit_publish(
//!    instance_id)` consults a token bucket keyed by the publisher's
//!    instance id and refuses over-quota bursts with
//!    [`PublishDenied::RateLimited`]. Defaults chosen so a well-
//!    behaved plugin never trips the limit but a rogue publisher
//!    can't flood the delivery loop.
//! 2. **C2d — filtered wake registration.** Subscribers whose
//!    consumer is a tokio task that needs to be *woken* on delivery
//!    (the plugin supervisor is the concrete case) register an
//!    [`Arc<Notify>`](tokio::sync::Notify) alongside a filter. Each
//!    published event signals only the wakes whose filter matches,
//!    so a plugin whose instance has zero subscriptions is quiet
//!    under any flood.
//! 3. **C2e — per-subscriber `mpsc` queues.** Delivery uses one
//!    [`mpsc::channel`](tokio::sync::mpsc::channel) per subscriber
//!    instead of a shared [`broadcast`](tokio::sync::broadcast)
//!    ring. Each subscriber owns [`SUBSCRIBER_CAPACITY`] slots; a
//!    slow subscriber whose queue fills drops events **for itself
//!    only** (`tracing::warn` + a per-subscriber drop counter). The
//!    pre-C2e broadcast ring shared its 256-slot capacity across
//!    every subscriber, so a single lagging tail client evicted
//!    events for the plugin supervisor and every other tail —
//!    C2d's arrival rate limit bounded the flow into the ring;
//!    C2e's per-subscriber queues bound the retention per
//!    subscriber so one slow reader can't degrade the others.
//!
//! [`broadcast`]: tokio::sync::broadcast
//! [`PluginState`]: crate::runtime::PluginState

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::time::Instant;

use tokio::sync::{Notify, mpsc};

use crate::host_impl::plugin::oxidhome::plugin::events::{Event, EventFilter};
use crate::host_impl::plugin::oxidhome::plugin::types::SubscriptionId;

/// What a subscriber receives on its private mpsc queue. C2e review
/// added the [`Self::Lagged`] variant back: the Connect proto's
/// `Lagged` body and the JSON tail's `{"lagged": N}` frame are the
/// contract the pre-C2e `broadcast::Recv::Lagged` error surfaced;
/// dropping that from the wire meant slow clients silently lost
/// events with no signal to reconcile.
///
/// The payload is an `Arc<Event>` (not `Event`) so `publish` fans
/// out to every subscriber with a cheap ref-count bump instead of
/// a full clone per queue slot — with per-subscriber queues of
/// 256 slots and unbounded custom-event payload size, cloning per
/// slot would multiply retained memory by subscriber count and let
/// an `events:tail` credential OOM the daemon (C2e review P1).
#[derive(Debug, Clone)]
pub enum SubscriberMessage {
    /// A published event routed to this subscriber's queue.
    Event(Arc<Event>),
    /// This subscriber's queue was full at least `skipped` times
    /// since the last delivered message. Emitted at the head of
    /// the next successful send so downstream tail handlers can
    /// surface the gap to their clients.
    Lagged { skipped: u64 },
}

/// C2e — per-subscriber queue depth. A subscriber whose consumer
/// is slower than the publisher(s) drops events past this many
/// unread slots; a `tracing::warn` fires with the subscription id
/// and cumulative drop count. Sized generously (256) — the C2d
/// per-instance publish rate limit already bounds the arrival
/// rate, so this depth is about tolerating brief consumer stalls
/// (GC pause, WebSocket flush blip) without dropping.
const SUBSCRIBER_CAPACITY: usize = 256;

/// Soft cap on concurrent subscribers. An `events:tail` credential
/// could otherwise open arbitrarily many stalled streams and
/// multiply retained queue memory (though the `Arc<Event>` fix in
/// [`publish`] means the *payload* is shared; per-subscriber cost
/// is now dominated by the 256 `Arc` slots ≈ 2 KiB). Exceeding
/// the cap logs an ERROR but doesn't refuse the subscribe — the
/// intent is "operator sees this and adds a per-actor limit
/// upstream" rather than "silently break tooling that opened a
/// spurious extra tail." Fixup review F1 amplification concern.
const SOFT_SUBSCRIBER_CAP: usize = 1024;

/// Rate-limit the per-drop `tracing::warn` in [`publish`]. Log
/// the first drop after any successful send, then every N-th
/// drop, so a flood of overflows against many subscribers doesn't
/// itself flood the log. The exact drop count is always available
/// via [`EventBus::dropped_for`] for tests + operator surfaces.
/// Fixup review F1 amplification concern.
const LOG_EVERY_N_DROPS: u64 = 100;

/// Default per-instance publish rate ceiling (events/second). A
/// well-behaved plugin publishing at natural device cadences
/// (state changes, button events, occasional custom broadcasts) is
/// nowhere near this — 100/sec is one event every 10 ms sustained,
/// which is faster than any real home-automation device fires.
///
/// PR #82 review, F3 (pre-C2e) — the first cut of C2d permitted a
/// 500-event burst against a 256-slot broadcast ring, so one
/// instance's burst alone could evict every subscriber's un-drained
/// events. Bringing the burst below the ring's per-slot capacity
/// bounded worst-case cross-subscriber eviction. C2e's per-subscriber
/// queues make that eviction-across-subscribers impossible in the
/// first place, but the arrival rate limit still matters:
/// it bounds how much a rogue plugin can spend on the delivery
/// loop (per-subscriber `try_send` + filter check) per second.
const DEFAULT_PUBLISH_RATE_PER_SEC: f64 = 100.0;
/// Max burst — how many tokens the bucket can hold. Sized
/// generously enough that a well-behaved plugin's natural bursts
/// (device online, batch state refresh at startup) go through
/// without being throttled, but low enough that a rogue publisher
/// can't monopolize the delivery loop.
const DEFAULT_PUBLISH_BURST: f64 = 64.0;

/// Live pub/sub for plugin-published events.
///
/// Cheap to clone via `Arc<EventBus>` (all internal state lives
/// behind `Arc` slots). Single global instance per
/// [`Engine`](crate::Engine).
#[derive(Debug)]
pub struct EventBus {
    // C2e: per-subscriber `mpsc::Sender`s keyed by subscription id.
    // Held behind `Arc<RwLock>` so both `publish` (read-lock,
    // snapshot Arcs, drop) and subscribe/unsubscribe (write-lock)
    // scale sanely. Inner `Arc<Subscriber>` so the snapshot in
    // `publish` is cheap and the `SubscriberToken` drop can
    // reference the same map through its own `Arc`.
    subscribers: Arc<RwLock<HashMap<SubscriptionId, Arc<Subscriber>>>>,
    next_subscription: AtomicU64,
    // C2d wake registrations: wake_id → (filter, notify). Each
    // entry is one plugin-side subscription that wants its
    // supervisor woken when a matching event fires. Kept separate
    // from `subscribers` because wake and delivery are decoupled
    // by design — external subscribers (JSON tail, Connect tail)
    // don't register a wake; the supervisor's wake registration
    // has a different lifetime scope than the mpsc receiver it
    // pairs with (a plugin instance can drop-and-recreate its
    // receiver across a restart while its supervisor's Notify
    // persists).
    wakes: Arc<WakeRegistry>,
    next_wake: AtomicU64,
    // C2d per-instance publish rate limiter — one token bucket per
    // instance-id, lazily created on first `admit_publish` call.
    // `Mutex<HashMap<...>>` over `RwLock` on the outer lookup to
    // keep the fast path (existing entry) single-lock. Inner
    // buckets carry their own mutex because they're mutated on
    // every read (`consume` updates `tokens` and `last_refill`).
    rate_limiters: Mutex<HashMap<String, Arc<RateLimiter>>>,
    rate_capacity: f64,
    rate_refill_per_sec: f64,
}

/// One subscription's delivery slot. Owned via `Arc` by the
/// `EventBus.subscribers` map so `publish` can snapshot cheaply.
#[derive(Debug)]
struct Subscriber {
    id: SubscriptionId,
    filter: EventFilter,
    sender: mpsc::Sender<SubscriberMessage>,
    /// Per-subscriber cumulative drop counter — incremented every
    /// time `publish` sees `TrySendError::Full` for this
    /// subscription. Exposed via [`EventBus::dropped_for`] for
    /// tests + future operator surfaces; the primary consumer is
    /// the `tracing::warn` emitted on each drop.
    dropped: AtomicU64,
    /// Count of pending lag notices — increments on each `Full`,
    /// drains to zero when the next `try_send` of a
    /// [`SubscriberMessage::Lagged`] frame succeeds. Kept separate
    /// from `dropped` so the cumulative counter (for observability)
    /// isn't reset when we surface a batch to the receiver.
    pending_lag: AtomicU64,
    /// Human-readable subscriber label included in the drop-warn
    /// log so an operator can identify which reader is falling
    /// behind ("plugin `example.foo/instance-1`", "http tail
    /// `client-abc`", …).
    label: String,
}

/// Shared wake-registration storage. Held behind `Arc` by both
/// [`EventBus`] and every [`WakeToken`] so the token can safely
/// deregister on drop even if the bus itself has been dropped
/// (the tail-most Arc holder just sees an empty map).
#[derive(Debug, Default)]
struct WakeRegistry {
    entries: RwLock<HashMap<u64, WakeEntry>>,
}

#[derive(Debug)]
struct WakeEntry {
    filter: EventFilter,
    notify: Arc<Notify>,
}

/// Token bucket. `consume()` refills based on elapsed wall-clock,
/// tries to take one token, returns whether it succeeded.
#[derive(Debug)]
struct RateLimiter {
    state: Mutex<RateState>,
    capacity: f64,
    refill_per_sec: f64,
}

#[derive(Debug)]
struct RateState {
    tokens: f64,
    last_refill: Instant,
}

impl RateLimiter {
    fn new(capacity: f64, refill_per_sec: f64) -> Self {
        Self {
            state: Mutex::new(RateState {
                tokens: capacity,
                last_refill: Instant::now(),
            }),
            capacity,
            refill_per_sec,
        }
    }

    fn consume(&self) -> bool {
        let mut s = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = Instant::now();
        let elapsed = now.duration_since(s.last_refill).as_secs_f64();
        s.tokens = (s.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        s.last_refill = now;
        if s.tokens >= 1.0 {
            s.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

/// Why a publish attempt was refused. Only produced by
/// [`EventBus::try_publish`] — the raw [`EventBus::publish`] path
/// bypasses the rate limiter and never fails.
#[derive(Debug, Clone, PartialEq)]
pub enum PublishDenied {
    /// The instance's per-second publish quota was exhausted.
    /// `capacity` and `refill_per_sec` describe the bucket the
    /// publisher tripped so the operator-visible error can point
    /// at the exact ceiling. `PluginState::publish_event` maps
    /// this to [`WitError::Unavailable`].
    ///
    /// [`WitError::Unavailable`]: crate::host_impl::plugin::oxidhome::plugin::types::Error::Unavailable
    RateLimited {
        instance_id: String,
        capacity: f64,
        refill_per_sec: f64,
    },
}

impl EventBus {
    #[must_use]
    pub fn new() -> Self {
        Self {
            subscribers: Arc::new(RwLock::new(HashMap::new())),
            next_subscription: AtomicU64::new(1),
            wakes: Arc::new(WakeRegistry::default()),
            next_wake: AtomicU64::new(1),
            rate_limiters: Mutex::new(HashMap::new()),
            rate_capacity: DEFAULT_PUBLISH_BURST,
            rate_refill_per_sec: DEFAULT_PUBLISH_RATE_PER_SEC,
        }
    }

    /// Push an event onto the bus. Each subscriber whose filter
    /// matches gets the event delivered to its private
    /// [`SUBSCRIBER_CAPACITY`]-slot mpsc queue via
    /// [`mpsc::Sender::try_send`]; a subscriber whose queue is
    /// full drops the event **for itself** (per-subscriber drop
    /// counter incremented, `tracing::warn` emitted) without
    /// affecting delivery to the other subscribers. Returns the
    /// number of subscribers the event was successfully delivered
    /// to (0 = no matching listeners *or* every match was full).
    ///
    /// Ordering: enqueue-then-signal-wakes (PR #82 review F1).
    /// A subscriber woken by `notify_one` in another task might
    /// otherwise poll its receiver before the `try_send` has
    /// enqueued, drain nothing, and go back to sleep. Signalling
    /// after `try_send` closes the race.
    #[allow(clippy::needless_pass_by_value)]
    pub fn publish(&self, event: Event) -> usize {
        // C2e review F1: wrap the event once in an `Arc` so
        // per-subscriber fan-out is a ref-count bump, not a full
        // clone per queue slot. With unbounded custom-event
        // payloads and unbounded subscriber count, cloning per
        // slot would let an `events:tail` credential amplify one
        // event into O(subscribers × capacity × payload) retained
        // memory and OOM the daemon.
        let event = Arc::new(event);
        // Snapshot the Arc<Subscriber>s under the read lock, then
        // drop the lock before doing per-subscriber `try_send`.
        // `try_send` is non-blocking but the lock scope stays tight,
        // and a slow subscriber's queue-full log can't hold the
        // registry lock (would gate concurrent subscribe /
        // unsubscribe).
        let snapshot: Vec<Arc<Subscriber>> = {
            let subs = self
                .subscribers
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            subs.values().cloned().collect()
        };
        let mut delivered = 0;
        for sub in &snapshot {
            if !filter_matches(&sub.filter, event.as_ref()) {
                continue;
            }
            // C2e review F2: if this subscriber has un-surfaced
            // drops from prior full-queue publishes, try to
            // enqueue a `Lagged` frame first so the receiver can
            // observe the gap. If the queue is still full, the
            // event send will also fail and we accumulate one
            // more into `pending_lag` — the counter drains on
            // the first successful send.
            let pending = sub.pending_lag.load(Ordering::Relaxed);
            if pending > 0
                && sub
                    .sender
                    .try_send(SubscriberMessage::Lagged { skipped: pending })
                    .is_ok()
            {
                // Only zero out the delta we actually surfaced —
                // `pending_lag` may have grown between the load
                // and here from a concurrent publish loop.
                sub.pending_lag.fetch_sub(pending, Ordering::Relaxed);
            }
            match sub
                .sender
                .try_send(SubscriberMessage::Event(Arc::clone(&event)))
            {
                Ok(()) => delivered += 1,
                Err(mpsc::error::TrySendError::Full(_)) => {
                    let total = sub.dropped.fetch_add(1, Ordering::Relaxed) + 1;
                    sub.pending_lag.fetch_add(1, Ordering::Relaxed);
                    // Rate-limit the warn: log the first drop and
                    // then every `LOG_EVERY_N_DROPS`-th to keep
                    // the log line count bounded under a flood
                    // against many overflowing subscribers.
                    // Cumulative count is exposed via
                    // `dropped_for` for observability.
                    if total == 1 || total.is_multiple_of(LOG_EVERY_N_DROPS) {
                        tracing::warn!(
                            subscription_id = sub.id,
                            subscriber = %sub.label,
                            dropped_total = total,
                            capacity = SUBSCRIBER_CAPACITY,
                            "event dropped: subscriber queue full (C2e per-subscriber isolation)",
                        );
                    }
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    // Receiver was dropped without its
                    // `SubscriberToken` (should be rare — the
                    // token is what owns deregistration). Skip
                    // and let the token's Drop clean the entry.
                }
            }
        }
        self.signal_wakes(event.as_ref());
        delivered
    }

    /// Per-subscriber cumulative drop counter. `None` if the
    /// subscription id is unknown (dropped or never existed).
    /// Test / observability accessor.
    #[must_use]
    pub fn dropped_for(&self, subscription_id: SubscriptionId) -> Option<u64> {
        let subs = self
            .subscribers
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        subs.get(&subscription_id)
            .map(|s| s.dropped.load(Ordering::Relaxed))
    }

    /// Consume one publish token from `instance_id`'s bucket. This
    /// is the *admission* half of the rate-limited publish path —
    /// separate from [`Self::publish`] so
    /// [`PluginState::publish_event`](crate::runtime::PluginState)
    /// can rate-check *before* it spends a blocking-pool thread
    /// on the durable event-log write.
    ///
    /// PR #82 review, F2 — the first cut of C2d called
    /// `try_publish` (which combined admission + persistence-side
    /// broadcast) after the durable mirror, so a flooder consumed
    /// disk + threads freely and only got refused on the way out.
    /// Admission now runs first.
    ///
    /// # Errors
    ///
    /// [`PublishDenied::RateLimited`] when the caller's per-second
    /// quota is exhausted.
    pub fn admit_publish(&self, instance_id: &str) -> Result<(), PublishDenied> {
        let limiter = self.limiter_for(instance_id);
        if !limiter.consume() {
            return Err(PublishDenied::RateLimited {
                instance_id: instance_id.to_owned(),
                capacity: self.rate_capacity,
                refill_per_sec: self.rate_refill_per_sec,
            });
        }
        Ok(())
    }

    fn limiter_for(&self, instance_id: &str) -> Arc<RateLimiter> {
        let mut map = self
            .rate_limiters
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(l) = map.get(instance_id) {
            return Arc::clone(l);
        }
        let l = Arc::new(RateLimiter::new(
            self.rate_capacity,
            self.rate_refill_per_sec,
        ));
        map.insert(instance_id.to_owned(), Arc::clone(&l));
        l
    }

    fn signal_wakes(&self, event: &Event) {
        let wakes = self
            .wakes
            .entries
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for entry in wakes.values() {
            if filter_matches(&entry.filter, event) {
                entry.notify.notify_one();
            }
        }
    }

    /// Subscribe to every event on the bus, no filter. Returns an
    /// [`EventSubscription`] whose consumer is expected to `.recv()`
    /// on the receiver directly — no supervisor-wake integration.
    /// Used by external tailers (JSON `/events/tail`, Connect
    /// `Events.TailEvents`) and by integration tests.
    ///
    /// C2e — each call opens a **private** [`SUBSCRIBER_CAPACITY`]-
    /// slot mpsc queue; the receiver's back-pressure isolates it
    /// from every other subscriber.
    pub fn subscribe_all(&self) -> EventSubscription {
        self.subscribe_labeled(
            EventFilter {
                device: None,
                topic: None,
            },
            "subscribe_all",
        )
    }

    /// Subscribe with a filter, without a supervisor-wake
    /// registration. Same shape as [`Self::subscribe_all`] but
    /// carries the filter so `publish` can skip non-matching
    /// events before enqueue (cheaper than filtering on receive).
    pub fn subscribe(&self, filter: EventFilter) -> EventSubscription {
        self.subscribe_labeled(filter, "subscribe")
    }

    /// Subscribe with a caller-supplied label included in the
    /// C2e drop-warn log. Prefer this over [`Self::subscribe`]
    /// for external subscribers whose identity would otherwise be
    /// opaque in the log ("plugin `example.foo/inst-1`",
    /// "http tail `client-abc`").
    pub fn subscribe_labeled(&self, filter: EventFilter, label: &str) -> EventSubscription {
        let (sender, receiver) = mpsc::channel(SUBSCRIBER_CAPACITY);
        let id = self.mint_subscription_id();
        let subscriber = Arc::new(Subscriber {
            id,
            filter: filter.clone(),
            sender,
            dropped: AtomicU64::new(0),
            pending_lag: AtomicU64::new(0),
            label: label.to_owned(),
        });
        {
            let mut subs = self
                .subscribers
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let before = subs.len();
            subs.insert(id, subscriber);
            let after = subs.len();
            // Soft cap: log ERROR when the total subscriber count
            // crosses the cap, so an operator gets an alarm
            // rather than silent memory growth. Doesn't refuse
            // the subscribe — a real per-actor cap belongs at
            // the API layer with actor context.
            if before < SOFT_SUBSCRIBER_CAP && after >= SOFT_SUBSCRIBER_CAP {
                tracing::error!(
                    total = after,
                    cap = SOFT_SUBSCRIBER_CAP,
                    "event bus subscriber count crossed the soft cap; consider adding a per-actor limit at the API layer",
                );
            }
        }
        EventSubscription {
            id,
            filter,
            receiver,
            wake_token: None,
            _slot_token: SubscriberToken {
                id,
                // C2e review F3: `Weak`, not `Arc`. If the token
                // held a strong ref, the registry (and every
                // subscriber's `mpsc::Sender` inside it) would
                // outlive the `EventBus` — a consumer awaiting
                // `recv()` would never see `None` after engine
                // shutdown, hanging the API tail loops.
                subscribers: Arc::downgrade(&self.subscribers),
            },
        }
    }

    /// Subscribe + register the plugin's supervisor wake. Every
    /// published event whose payload matches `filter` signals
    /// `notify.notify_one()` — the supervisor's `select!` arm
    /// awaits `notify.notified()` and calls `drain_events()` after.
    /// C2d wake-isolation entry point.
    ///
    /// The returned subscription owns both a [`WakeToken`] (drops
    /// the wake registration) and a [`SubscriberToken`] (drops the
    /// per-subscriber queue slot). The subscription's lifetime
    /// bounds both.
    pub fn subscribe_with_wake(
        &self,
        filter: EventFilter,
        notify: Arc<Notify>,
    ) -> EventSubscription {
        let wake_id = self.next_wake.fetch_add(1, Ordering::Relaxed);
        {
            let mut wakes = self
                .wakes
                .entries
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            wakes.insert(
                wake_id,
                WakeEntry {
                    filter: filter.clone(),
                    notify,
                },
            );
        }
        let mut sub = self.subscribe_labeled(filter, "subscribe_with_wake");
        sub.wake_token = Some(WakeToken {
            wake_id,
            registry: Arc::clone(&self.wakes),
        });
        sub
    }

    fn mint_subscription_id(&self) -> SubscriptionId {
        self.next_subscription.fetch_add(1, Ordering::Relaxed)
    }
}

/// RAII slot-holder for [`EventBus::subscribers`]. Dropping the
/// enclosing [`EventSubscription`] runs this Drop, which removes
/// the subscriber's `mpsc::Sender` from the bus so `publish` stops
/// walking a dead entry.
///
/// The registry reference is `Weak`, not `Arc`, so a subscription
/// held past the bus's lifetime doesn't keep the registry (and
/// every remaining subscriber's `Sender`) alive — the mpsc
/// receiver's `recv()` correctly returns `None` after engine
/// shutdown. Fixup review F3.
#[derive(Debug)]
struct SubscriberToken {
    id: SubscriptionId,
    subscribers: Weak<RwLock<HashMap<SubscriptionId, Arc<Subscriber>>>>,
}

impl Drop for SubscriberToken {
    fn drop(&mut self) {
        // Registry may have been dropped alongside the bus — no-op
        // if so; the map (and this subscriber's Arc slot) is
        // already gone.
        if let Some(subs) = self.subscribers.upgrade() {
            let mut subs = subs
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            subs.remove(&self.id);
        }
    }
}

/// Owned handle returned by [`EventBus::subscribe_with_wake`].
/// Dropping it deregisters the wake — the subscription's lifetime
/// exactly bounds the wake registration.
#[derive(Debug)]
pub struct WakeToken {
    wake_id: u64,
    registry: Arc<WakeRegistry>,
}

impl Drop for WakeToken {
    fn drop(&mut self) {
        let mut wakes = self
            .registry
            .entries
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        wakes.remove(&self.wake_id);
    }
}

/// One subscriber's receiver + the filter the host promised to
/// apply. C2e: the receiver is a private
/// [`SUBSCRIBER_CAPACITY`]-slot [`mpsc::Receiver`]; back-pressure
/// on this subscriber can't evict events from other subscribers.
///
/// Owns an optional [`WakeToken`] — set by
/// [`EventBus::subscribe_with_wake`] for plugin-side subscriptions
/// that need their supervisor woken on delivery. Owns a
/// [`SubscriberToken`] that removes this subscription's slot from
/// the bus on Drop.
#[derive(Debug)]
pub struct EventSubscription {
    pub id: SubscriptionId,
    pub filter: EventFilter,
    pub receiver: mpsc::Receiver<SubscriberMessage>,
    /// C2d — Some for supervisor-wake-integrated subscriptions,
    /// None for external subscribers that poll `.receiver`
    /// directly. Private because callers never touch it; its
    /// only observable effect is the Drop.
    #[allow(dead_code)]
    wake_token: Option<WakeToken>,
    /// C2e — RAII deregister of the subscriber's mpsc slot on
    /// `EventBus`. Field is prefixed with `_` because it's never
    /// read directly; Rust would otherwise warn about it.
    #[allow(dead_code)]
    _slot_token: SubscriberToken,
}

impl SubscriberMessage {
    /// Expect the [`Self::Event`] variant and return an owned
    /// [`Event`] — cloning only if the `Arc` has additional
    /// holders (i.e. multiple subscribers). Panics on the
    /// [`Self::Lagged`] variant; use plain pattern-matching if
    /// the caller wants to handle both.
    #[must_use]
    pub fn expect_event(self) -> Event {
        match self {
            Self::Event(ev) => Arc::unwrap_or_clone(ev),
            Self::Lagged { skipped } => {
                panic!("expected SubscriberMessage::Event, got Lagged {{ skipped: {skipped} }}")
            }
        }
    }
}

impl EventSubscription {
    /// Returns whether `event` matches this subscription's filter.
    /// Both filter fields are optional; `None` matches everything.
    ///
    /// Topic semantics follow the WIT comment on
    /// `events::event-filter.topic`: capability events
    /// (`state-changed`, `button`, `inference`) use **exact** match
    /// on the capability/topic name; **custom events** use **prefix**
    /// match against `custom-event.topic` so a subscription to
    /// `"automation."` catches every `automation.morning`,
    /// `automation.evening`, etc.
    #[must_use]
    pub fn matches(&self, event: &Event) -> bool {
        filter_matches(&self.filter, event)
    }
}

/// Shared filter check. Extracted from `EventSubscription::matches`
/// so the bus can filter wake registrations without cloning
/// the subscription slot.
#[must_use]
pub(crate) fn filter_matches(filter: &EventFilter, event: &Event) -> bool {
    if let Some(device) = &filter.device
        && event.device.as_ref() != Some(device)
    {
        return false;
    }
    if let Some(topic) = &filter.topic {
        use crate::host_impl::plugin::oxidhome::plugin::events::EventPayload;
        let matches_topic = match &event.payload {
            EventPayload::Custom(c) => c.topic.starts_with(topic),
            _ => topic_of(event) == topic.as_str(),
        };
        if !matches_topic {
            return false;
        }
    }
    true
}

/// Canonical topic string for an [`Event`] — the capability name for
/// device-oriented variants, or the plugin-chosen topic for a
/// `Custom` event. Mirrors the `EventBus::subscribe` filter shape.
#[must_use]
pub(crate) fn topic_of(event: &Event) -> &str {
    use crate::host_impl::plugin::oxidhome::plugin::events::EventPayload;
    match &event.payload {
        EventPayload::StateChanged(sc) => sc.capability.as_str(),
        EventPayload::Button(_) => "button",
        EventPayload::Inference(_) => "inference",
        EventPayload::Custom(c) => c.topic.as_str(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_impl::plugin::oxidhome::plugin::events::{
        CustomEvent, Event, EventPayload, StateChange,
    };

    fn state_change(device: &str, capability: &str) -> Event {
        Event {
            device: Some(device.into()),
            timestamp: 0,
            origin_plugin_id: String::new(),
            origin_instance_id: String::new(),
            payload: EventPayload::StateChanged(StateChange {
                capability: capability.into(),
                fields: Vec::new(),
            }),
        }
    }

    fn custom(device: Option<&str>, topic: &str) -> Event {
        Event {
            device: device.map(Into::into),
            timestamp: 0,
            origin_plugin_id: String::new(),
            origin_instance_id: String::new(),
            payload: EventPayload::Custom(CustomEvent {
                topic: topic.into(),
                payload: String::new(),
            }),
        }
    }

    fn subscription(filter: EventFilter) -> EventSubscription {
        EventBus::new().subscribe(filter)
    }

    #[test]
    fn subscribe_all_matches_everything() {
        let sub = subscription(EventFilter {
            device: None,
            topic: None,
        });
        assert!(sub.matches(&state_change("d-1", "switch")));
        assert!(sub.matches(&custom(None, "automation.morning")));
    }

    #[test]
    fn device_filter_narrows_to_exact_id() {
        let sub = subscription(EventFilter {
            device: Some("d-1".into()),
            topic: None,
        });
        assert!(sub.matches(&state_change("d-1", "switch")));
        assert!(!sub.matches(&state_change("d-2", "switch")));
        // No-device events (custom broadcasts) fail a device
        // filter — you asked for events about d-1, and this event
        // isn't about any device.
        assert!(!sub.matches(&custom(None, "automation.morning")));
    }

    #[test]
    fn topic_filter_prefix_matches_custom_events() {
        let sub = subscription(EventFilter {
            device: None,
            topic: Some("automation.".into()),
        });
        assert!(sub.matches(&custom(None, "automation.morning")));
        assert!(sub.matches(&custom(None, "automation.evening")));
        assert!(!sub.matches(&custom(None, "switch")));
    }

    #[test]
    fn topic_filter_exact_match_for_capability_events() {
        let sub = subscription(EventFilter {
            device: None,
            topic: Some("switch".into()),
        });
        assert!(sub.matches(&state_change("d-1", "switch")));
        assert!(!sub.matches(&state_change("d-1", "dimmer")));
    }

    // ── C2d rate-limit tests ────────────────────────────────────────

    #[test]
    fn admit_publish_ok_under_rate_limit() {
        let bus = EventBus::new();
        for _ in 0..10 {
            bus.admit_publish("alpha")
                .expect("under-limit admission must succeed");
        }
    }

    #[test]
    fn admit_publish_refuses_when_burst_exhausted() {
        let bus = EventBus::new();
        // Consume every token in the burst.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        for _ in 0..DEFAULT_PUBLISH_BURST as u32 {
            bus.admit_publish("alpha").expect("initial burst allowed");
        }
        // Next call should be refused immediately (no time has
        // elapsed to refill).
        let err = bus.admit_publish("alpha").unwrap_err();
        assert!(
            matches!(err, PublishDenied::RateLimited { .. }),
            "got {err:?}",
        );
    }

    #[test]
    fn rate_limits_are_per_instance() {
        let bus = EventBus::new();
        // Exhaust alpha's bucket.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        for _ in 0..DEFAULT_PUBLISH_BURST as u32 {
            bus.admit_publish("alpha").unwrap();
        }
        // Beta gets a fresh bucket.
        bus.admit_publish("beta")
            .expect("distinct instance keeps its own bucket");
    }

    #[test]
    fn default_burst_stays_below_ring_capacity() {
        // Historical PR #82 F3 invariant: burst must stay well
        // below the per-subscriber queue depth so a single
        // instance's full burst can't fill a subscriber's private
        // queue in one shot. Under C2e the "worst affected"
        // subscriber only drops for itself, but keeping the burst
        // under the per-subscriber capacity means a well-behaved
        // subscriber still won't see drops during natural bursts.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let burst = DEFAULT_PUBLISH_BURST as usize;
        assert!(
            burst < SUBSCRIBER_CAPACITY,
            "burst {DEFAULT_PUBLISH_BURST} must be < SUBSCRIBER_CAPACITY {SUBSCRIBER_CAPACITY}",
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn wake_fires_after_send_makes_event_visible() {
        // PR #82 review, F1 regression — the wake must not fire
        // before the event is on the ring, or a woken subscriber
        // draining its receiver can find nothing and sleep before
        // the send lands, losing the event indefinitely. Under a
        // multi-thread runtime the racing tasks make the bad
        // ordering observable.
        let bus = Arc::new(EventBus::new());
        let notify = Arc::new(Notify::new());
        let mut sub = bus.subscribe_with_wake(
            EventFilter {
                device: None,
                topic: None,
            },
            Arc::clone(&notify),
        );

        let bus_publisher = Arc::clone(&bus);
        let subscriber = tokio::spawn(async move {
            notify.notified().await;
            // Post-wake, the event MUST be readable.
            sub.receiver
                .try_recv()
                .expect("event must be visible on the ring by the time wake fires")
        });

        // Give the subscriber time to reach `.notified().await`
        // before we publish, so the race window (if any) is real.
        tokio::task::yield_now().await;
        bus_publisher.publish(custom(None, "test"));

        let msg = tokio::time::timeout(std::time::Duration::from_secs(1), subscriber)
            .await
            .expect("subscriber did not observe the event before timeout")
            .expect("subscriber task panicked");
        let ev = msg.expect_event();
        assert!(matches!(ev.payload, EventPayload::Custom(_)));
    }

    // ── C2d wake-registration tests ─────────────────────────────────

    #[test]
    fn wake_fires_on_matching_publish() {
        let bus = EventBus::new();
        let notify = Arc::new(Notify::new());
        let _sub = bus.subscribe_with_wake(
            EventFilter {
                device: Some("d-1".into()),
                topic: None,
            },
            Arc::clone(&notify),
        );

        // Publish matching event → notify fires; polling
        // `notify.notified()` synchronously after a `notify_one`
        // should resolve immediately.
        bus.publish(state_change("d-1", "switch"));
        let waker = notify.notified();
        // `Notify` semantics: after `notify_one`, the next call to
        // `notified()` (before it awaits) already has permission
        // to complete. Poll once via a bounded runtime.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        rt.block_on(async {
            tokio::time::timeout(std::time::Duration::from_millis(100), waker)
                .await
                .expect("wake must fire on matching publish");
        });
    }

    #[test]
    fn wake_skipped_on_non_matching_publish() {
        let bus = EventBus::new();
        let notify = Arc::new(Notify::new());
        let _sub = bus.subscribe_with_wake(
            EventFilter {
                device: Some("d-1".into()),
                topic: None,
            },
            Arc::clone(&notify),
        );

        // Publish for a *different* device — the filter refuses,
        // the wake must NOT fire.
        bus.publish(state_change("d-99", "switch"));
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let waker = notify.notified();
        let timed_out = rt
            .block_on(async {
                tokio::time::timeout(std::time::Duration::from_millis(30), waker).await
            })
            .is_err();
        assert!(timed_out, "wake fired despite non-matching filter");
    }

    #[test]
    fn wake_deregisters_on_subscription_drop() {
        let bus = EventBus::new();
        let notify = Arc::new(Notify::new());
        {
            let _sub = bus.subscribe_with_wake(
                EventFilter {
                    device: None,
                    topic: None,
                },
                Arc::clone(&notify),
            );
            assert_eq!(bus.wakes.entries.read().unwrap().len(), 1);
        }
        // Subscription dropped → wake gone.
        assert_eq!(bus.wakes.entries.read().unwrap().len(), 0);
    }

    #[test]
    fn subscribe_without_wake_does_not_register() {
        let bus = EventBus::new();
        let _sub = bus.subscribe(EventFilter {
            device: None,
            topic: None,
        });
        assert_eq!(
            bus.wakes.entries.read().unwrap().len(),
            0,
            "plain subscribe must not touch the wake map",
        );
    }

    /// C2e: a subscriber whose queue is full must not evict events
    /// for OTHER subscribers. Fill one subscriber's mpsc queue by
    /// never reading it, publish more than the capacity, then
    /// verify a second subscriber received every event (up to the
    /// same capacity — its own queue would fill if we published
    /// more, but each subscriber independently).
    #[test]
    fn slow_subscriber_does_not_evict_from_other_subscribers() {
        let bus = EventBus::new();
        let filter = EventFilter {
            device: None,
            topic: None,
        };
        let slow = bus.subscribe_labeled(filter.clone(), "slow");
        let mut fast = bus.subscribe_labeled(filter.clone(), "fast");

        // Publish more than the per-subscriber capacity. The slow
        // subscriber's queue will fill after SUBSCRIBER_CAPACITY
        // enqueues; the fast subscriber's queue also gets one
        // event per publish and could fill in principle, but we
        // drain it after each publish so it stays empty.
        let overflow: usize = 32;
        let total: usize = SUBSCRIBER_CAPACITY + overflow;
        let mut fast_events: usize = 0;
        for i in 0..total {
            bus.publish(custom(None, &format!("evt-{i}")));
            while let Ok(msg) = fast.receiver.try_recv() {
                match msg {
                    SubscriberMessage::Event(_) => fast_events += 1,
                    SubscriberMessage::Lagged { skipped } => {
                        panic!("fast subscriber must not lag, got Lagged {{ skipped: {skipped} }}")
                    }
                }
            }
        }

        // Fast subscriber saw every publish.
        assert_eq!(
            fast_events, total,
            "fast subscriber must receive every publish under C2e",
        );

        // Slow subscriber dropped everything past its capacity —
        // the drop counter reflects that, and the pre-C2e shared
        // ring would have evicted from the fast subscriber too.
        let slow_dropped = bus.dropped_for(slow.id).unwrap();
        assert_eq!(
            slow_dropped, overflow as u64,
            "slow subscriber must have dropped exactly the overflow past its capacity",
        );
    }

    /// C2e review F2: an overflow followed by a drain must surface
    /// a `Lagged` frame on the next successful send so the client
    /// can reconcile via the durable history.
    #[test]
    fn overflow_then_drain_surfaces_lag_notice() {
        let bus = EventBus::new();
        let filter = EventFilter {
            device: None,
            topic: None,
        };
        let mut sub = bus.subscribe_labeled(filter, "test");

        // Fill the queue past capacity so N drops accumulate.
        let overflow: u64 = 5;
        for i in 0..(SUBSCRIBER_CAPACITY as u64 + overflow) {
            bus.publish(custom(None, &format!("evt-{i}")));
        }
        assert_eq!(bus.dropped_for(sub.id).unwrap(), overflow);

        // Drain everything already in the queue (the pre-overflow
        // events).
        let mut drained = 0;
        while let Ok(SubscriberMessage::Event(_)) = sub.receiver.try_recv() {
            drained += 1;
        }
        assert_eq!(drained, SUBSCRIBER_CAPACITY);

        // The very next publish MUST land a Lagged frame first,
        // then the event.
        bus.publish(custom(None, "next"));
        let lagged = sub.receiver.try_recv().expect("lagged frame present");
        assert!(
            matches!(lagged, SubscriberMessage::Lagged { skipped } if skipped == overflow),
            "expected Lagged {{ skipped: {overflow} }}, got {lagged:?}",
        );
        let ev = sub.receiver.try_recv().expect("event follows lagged");
        assert!(matches!(ev, SubscriberMessage::Event(_)));
    }

    /// C2e review F3: dropping the `EventBus` must let a consumer
    /// awaiting `recv()` see `None` — the `SubscriberToken` holds
    /// a `Weak` reference to the registry so it doesn't keep the
    /// bus's `Sender` slots alive past its own lifetime.
    #[test]
    fn dropping_bus_closes_subscription_receiver() {
        let bus = EventBus::new();
        let filter = EventFilter {
            device: None,
            topic: None,
        };
        let mut sub = bus.subscribe_labeled(filter, "outliving-bus");

        // Bus drops but subscription (and its receiver) stays.
        drop(bus);

        // `recv()` on the mpsc receiver must observe channel
        // closure — every strong ref to the sender is gone.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        rt.block_on(async {
            let got =
                tokio::time::timeout(std::time::Duration::from_millis(100), sub.receiver.recv())
                    .await
                    .expect("recv must return promptly after bus drop, not hang");
            assert!(got.is_none(), "recv must return None once bus drops");
        });
    }

    /// C2e: dropping an `EventSubscription` deregisters its slot
    /// on the bus. A subsequent publish sees only remaining
    /// subscribers.
    #[test]
    fn dropping_subscription_deregisters_bus_slot() {
        let bus = EventBus::new();
        let filter = EventFilter {
            device: None,
            topic: None,
        };
        let sub_a = bus.subscribe_labeled(filter.clone(), "a");
        let sub_b = bus.subscribe_labeled(filter, "b");
        assert_eq!(bus.subscribers.read().unwrap().len(), 2);

        drop(sub_a);
        assert_eq!(bus.subscribers.read().unwrap().len(), 1);

        // Publish still lands on B — SubscriberToken Drop only
        // touched A's slot.
        let n = bus.publish(custom(None, "solo"));
        assert_eq!(n, 1);
        drop(sub_b);
        assert_eq!(bus.subscribers.read().unwrap().len(), 0);
    }
}
