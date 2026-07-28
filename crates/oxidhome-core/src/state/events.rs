//! Per-engine event bus.
//!
//! A tokio [`broadcast`] channel fans every `publish-event` call out
//! to every subscriber that's awaiting on the shared receiver:
//! plugin instances (via their [`PluginState`] subscription list),
//! host-side integration tests, and — since 12-API-c — the JSON
//! `GET /api/v1/events/tail` WebSocket + the Connect
//! `Events.TailEvents` stream.
//!
//! Two architecture-review C2d additions on top of the broadcast
//! primitive:
//!
//! 1. **Per-instance publish rate limit.** `try_publish(instance_id,
//!    event)` consults a token bucket keyed by the publisher's
//!    instance id and refuses over-quota bursts with
//!    [`PublishDenied::RateLimited`]. Defaults chosen so a well-
//!    behaved plugin never trips the limit but a rogue publisher
//!    can't monopolize the shared broadcast ring's 256-slot
//!    capacity.
//! 2. **Filtered wake registration.** Subscribers whose consumer is
//!    a tokio task that needs to be *woken* on delivery (the plugin
//!    supervisor is the concrete case) register an
//!    [`Arc<Notify>`](tokio::sync::Notify) alongside a filter. Each
//!    published event signals only the wakes whose filter matches,
//!    so a plugin whose instance has zero subscriptions is quiet
//!    under any flood — the pre-C2d supervisor's unconditional
//!    `subscribe_all()` wake receiver had the opposite property
//!    ("every publish wakes every instance") which is exactly the
//!    fan-out amplification the C2 review flagged.
//!
//! [`broadcast`]: tokio::sync::broadcast
//! [`PluginState`]: crate::runtime::PluginState

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use tokio::sync::{Notify, broadcast};

use crate::host_impl::plugin::oxidhome::plugin::events::{Event, EventFilter};
use crate::host_impl::plugin::oxidhome::plugin::types::SubscriptionId;

/// How many events the broadcast channel buffers per subscriber. Slow
/// subscribers that miss this many events get a
/// [`RecvError::Lagged`](tokio::sync::broadcast::error::RecvError::Lagged)
/// reporting how many events were skipped; the receiver itself stays
/// usable (tokio's broadcast channel doesn't invalidate it). Phase 5d's
/// durable history is what makes catching up cheap if a subscriber
/// drops far behind.
const BUS_CAPACITY: usize = 256;

/// Default per-instance publish rate ceiling (events/second). A
/// well-behaved plugin publishing at natural device cadences
/// (state changes, button events, occasional custom broadcasts) is
/// nowhere near this — 100/sec is one event every 10 ms sustained,
/// which is faster than any real home-automation device fires.
///
/// PR #82 review, F3 — the first cut of C2d permitted a 500-event
/// burst against a 256-slot broadcast ring, so one instance's
/// burst alone could evict every subscriber's un-drained events.
/// Bringing the burst well below the ring's per-slot capacity
/// bounds the worst-case cross-subscriber eviction to whatever
/// slack the slowest subscriber has, not the ring's total.
///
/// Not a full fix — per-subscriber queues (filed as a follow-up)
/// are still what closes cross-subscriber eviction properly. The
/// rate limit here bounds the *arrival* rate; per-subscriber
/// queues bound the *retention*.
const DEFAULT_PUBLISH_RATE_PER_SEC: f64 = 100.0;
/// Max burst — how many tokens the bucket can hold. Sized well
/// below [`BUS_CAPACITY`] so a single instance's full burst plus
/// a modest amount of already-buffered events from other
/// publishers fits in the ring without evicting anything.
const DEFAULT_PUBLISH_BURST: f64 = 64.0;

/// Live pub/sub for plugin-published events.
///
/// Cheap to clone via `Arc<EventBus>` (the broadcast channel + the
/// wake/rate-limit maps all share their internal state through
/// `Arc` slots). Single global instance per
/// [`Engine`](crate::Engine).
#[derive(Debug)]
pub struct EventBus {
    sender: broadcast::Sender<Event>,
    next_subscription: AtomicU64,
    // C2d wake registrations: subscription_id → (filter, notify).
    // Each entry is one plugin-side subscription that wants its
    // supervisor woken when a matching event fires. External
    // subscribers (JSON tail, Connect tail) poll the broadcast
    // receiver directly and don't register a wake.
    wakes: Arc<WakeRegistry>,
    next_wake: AtomicU64,
    // C2d per-instance publish rate limiter — one token bucket per
    // instance-id, lazily created on first `try_publish` call.
    // `Mutex<HashMap<...>>` over `RwLock` on the outer lookup to
    // keep the fast path (existing entry) single-lock. Inner
    // buckets carry their own mutex because they're mutated on
    // every read (`consume` updates `tokens` and `last_refill`).
    rate_limiters: Mutex<HashMap<String, Arc<RateLimiter>>>,
    rate_capacity: f64,
    rate_refill_per_sec: f64,
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
        let (sender, _) = broadcast::channel(BUS_CAPACITY);
        Self {
            sender,
            next_subscription: AtomicU64::new(1),
            wakes: Arc::new(WakeRegistry::default()),
            next_wake: AtomicU64::new(1),
            rate_limiters: Mutex::new(HashMap::new()),
            rate_capacity: DEFAULT_PUBLISH_BURST,
            rate_refill_per_sec: DEFAULT_PUBLISH_RATE_PER_SEC,
        }
    }

    /// Push an event onto the bus without rate-limiting or
    /// per-instance attribution. Used by host-side injectors
    /// (integration tests, JSON `/events/tail` handshakes that
    /// synthesize events) that don't have a plugin instance
    /// identity. Returns the number of broadcast subscribers that
    /// received it (0 = no listeners — fine).
    #[allow(clippy::needless_pass_by_value)]
    pub fn publish(&self, event: Event) -> usize {
        // Ordering matters (PR #82 review, F1). The event MUST be
        // on the broadcast ring *before* the wake fires — otherwise
        // a subscriber woken by `notify_one` in another task can
        // drain its receiver, find nothing, and go back to sleep
        // before the send() call actually enqueues the event. Under
        // a multi-thread runtime, that races the supervisor into
        // dropping events on the floor.
        //
        // Cost: one clone of `event` (broadcast::send already clones
        // internally per subscriber, so this is one *extra* clone
        // for the wake-side filter check). Correctness > perf; event
        // payloads are small structs.
        let n = self.sender.send(event.clone()).unwrap_or(0);
        self.signal_wakes(&event);
        n
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
    pub fn subscribe_all(&self) -> EventSubscription {
        EventSubscription {
            id: self.mint_subscription_id(),
            filter: EventFilter {
                device: None,
                topic: None,
            },
            receiver: self.sender.subscribe(),
            wake_token: None,
        }
    }

    /// Subscribe with a filter, without a supervisor-wake
    /// registration. Same shape as [`Self::subscribe_all`] but
    /// carries the filter for consumer-side `.matches()`.
    pub fn subscribe(&self, filter: EventFilter) -> EventSubscription {
        EventSubscription {
            id: self.mint_subscription_id(),
            filter,
            receiver: self.sender.subscribe(),
            wake_token: None,
        }
    }

    /// Subscribe + register the plugin's supervisor wake. Every
    /// published event whose payload matches `filter` signals
    /// `notify.notify_one()` — the supervisor's `select!` arm
    /// awaits `notify.notified()` and calls `drain_events()` after.
    /// C2d wake-isolation entry point.
    ///
    /// The returned subscription owns a
    /// [`WakeToken`] whose `Drop` deregisters the wake from the
    /// bus, so the subscription's lifetime bounds the wake
    /// registration exactly.
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
        EventSubscription {
            id: self.mint_subscription_id(),
            filter,
            receiver: self.sender.subscribe(),
            wake_token: Some(WakeToken {
                wake_id,
                registry: Arc::clone(&self.wakes),
            }),
        }
    }

    fn mint_subscription_id(&self) -> SubscriptionId {
        self.next_subscription.fetch_add(1, Ordering::Relaxed)
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

/// One subscriber's receiver + the filter the host promised to apply.
///
/// Owns its `broadcast::Receiver`; dropping the subscription drops
/// the receiver and frees the slot. Also owns an optional
/// [`WakeToken`] — set by [`EventBus::subscribe_with_wake`] for
/// plugin-side subscriptions that need their supervisor woken on
/// delivery. Dropping the subscription drops the token which
/// deregisters the wake.
#[derive(Debug)]
pub struct EventSubscription {
    pub id: SubscriptionId,
    pub filter: EventFilter,
    pub receiver: broadcast::Receiver<Event>,
    /// C2d — Some for supervisor-wake-integrated subscriptions,
    /// None for external subscribers that poll `.receiver`
    /// directly. The field is private because callers never touch
    /// it; its only observable effect is the Drop.
    #[allow(dead_code)]
    wake_token: Option<WakeToken>,
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
        // PR #82 review, F3 — burst must be sized well below the
        // shared broadcast ring so one instance's full burst can't
        // evict every subscriber's un-drained events. This
        // constant guard fires if someone bumps the burst back
        // above the ring without also fixing the shared-ring
        // isolation story (per-subscriber queues — see C2e).
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let burst = DEFAULT_PUBLISH_BURST as usize;
        assert!(
            burst < BUS_CAPACITY,
            "burst {DEFAULT_PUBLISH_BURST} must be < BUS_CAPACITY {BUS_CAPACITY}",
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

        let ev = tokio::time::timeout(std::time::Duration::from_secs(1), subscriber)
            .await
            .expect("subscriber did not observe the event before timeout")
            .expect("subscriber task panicked");
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
}
