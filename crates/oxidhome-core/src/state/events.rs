//! In-memory event bus.
//!
//! A tokio [`broadcast`] channel fans every `publish-event` call out
//! to every subscriber. Subscriptions today are:
//!
//! - **Host-side listeners** (test harness, Phase 11 external API,
//!   Phase 12 MCP server) — they call [`EventBus::subscribe_all`] and
//!   poll the returned [`broadcast::Receiver`].
//! - **Plugin instances** subscribing via the WIT `host-events`
//!   import — `subscribe`/`unsubscribe` mint a real
//!   `subscription-id`, store the filter + receiver on the plugin's
//!   [`PluginState`](crate::runtime::PluginState), and
//!   [`PluginInstance::drain_events`](crate::PluginInstance::drain_events)
//!   delivers matching events into the plugin's `on-event` export.
//!   Phase 3 ships the polling-drain shape; Phase 6 wraps the same
//!   collection step inside a per-instance tokio task so delivery is
//!   automatic without an explicit driver.
//!
//! Phase 5d wires a parallel durable layer (the `SQLite` event-history
//! store) so the CLI/UI can answer "what happened yesterday". Live
//! pub/sub stays right here.
//!
//! [`broadcast`]: tokio::sync::broadcast

use std::sync::Arc;

use tokio::sync::broadcast;

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

/// Live pub/sub for plugin-published events.
///
/// Cheap to clone (`Arc` internally via the broadcast channel + the
/// next-id counter behind the bus's `Inner`). Single global instance
/// per [`Engine`](crate::Engine).
#[derive(Debug)]
pub struct EventBus {
    sender: broadcast::Sender<Event>,
    next_subscription: std::sync::atomic::AtomicU64,
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

impl EventBus {
    #[must_use]
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel(BUS_CAPACITY);
        Self {
            sender,
            next_subscription: std::sync::atomic::AtomicU64::new(1),
        }
    }

    /// Push an event onto the bus. Returns the number of subscribers
    /// that received it (0 is fine — events with no listeners are
    /// just dropped).
    ///
    /// Phase 5d also writes to the `SQLite` history store from inside
    /// `host_impl::events::publish_event`; this method only handles
    /// live delivery.
    pub fn publish(&self, event: Event) -> usize {
        // `send` errors only when there are zero subscribers; treat
        // that as "0 delivered" rather than a failure.
        self.sender.send(event).unwrap_or(0)
    }

    /// Subscribe to every event on the bus, no filter. Returns an
    /// [`EventSubscription`] that wraps a unique id + a
    /// [`broadcast::Receiver`].
    ///
    /// Filtering is deliberately client-side: the bus stays simple,
    /// each subscriber keeps its own filter copy, and Phase 6's
    /// per-instance dispatch task can fold the host-side filter into
    /// the same loop without re-inventing dispatch.
    pub fn subscribe_all(&self) -> EventSubscription {
        EventSubscription {
            id: self.mint_subscription_id(),
            filter: EventFilter {
                device: None,
                topic: None,
            },
            receiver: self.sender.subscribe(),
        }
    }

    /// Subscribe with a filter. Same machinery as
    /// [`Self::subscribe_all`]; the filter is stored on the
    /// subscription for the consumer to apply per event.
    pub fn subscribe(&self, filter: EventFilter) -> EventSubscription {
        EventSubscription {
            id: self.mint_subscription_id(),
            filter,
            receiver: self.sender.subscribe(),
        }
    }

    fn mint_subscription_id(&self) -> SubscriptionId {
        self.next_subscription
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }
}

/// One subscriber's receiver + the filter the host promised to apply.
///
/// Owns its `broadcast::Receiver`; dropping the subscription drops
/// the receiver and frees the slot.
#[derive(Debug)]
pub struct EventSubscription {
    pub id: SubscriptionId,
    pub filter: EventFilter,
    pub receiver: broadcast::Receiver<Event>,
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
        if let Some(device) = &self.filter.device
            && event.device.as_ref() != Some(device)
        {
            return false;
        }
        if let Some(topic) = &self.filter.topic {
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
}

fn topic_of(event: &Event) -> &str {
    use crate::host_impl::plugin::oxidhome::plugin::events::EventPayload;
    match &event.payload {
        EventPayload::StateChanged(sc) => &sc.capability,
        EventPayload::Button(_) => "button",
        EventPayload::Inference(_) => "inference",
        EventPayload::Custom(c) => &c.topic,
    }
}

/// Helper alias parallel to `SharedDeviceRegistry`. The bus is
/// internally `Arc`-y already (broadcast channels share state via
/// reference counting), but wrapping it in `Arc` keeps the
/// "everything in `PluginState` clones from `Engine`" pattern
/// uniform.
pub type SharedEventBus = Arc<EventBus>;

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
            payload: EventPayload::Custom(CustomEvent {
                topic: topic.into(),
                payload: String::new(),
            }),
        }
    }

    fn subscription(filter: EventFilter) -> EventSubscription {
        EventBus::new().subscribe(filter)
    }

    /// Capability events use exact match — a filter for `"switch"`
    /// matches `state-changed { capability: "switch" }` but not
    /// `"switchable-thingy"`.
    #[test]
    fn capability_topics_match_exactly() {
        let s = subscription(EventFilter {
            device: None,
            topic: Some("switch".into()),
        });
        assert!(s.matches(&state_change("d-1", "switch")));
        assert!(!s.matches(&state_change("d-1", "switch-extra")));
        assert!(!s.matches(&state_change("d-1", "sensor")));
    }

    /// Custom events use prefix match — a filter for `"automation."`
    /// catches `automation.morning` and `automation.evening` but not
    /// `automatic`. The WIT comment on `event-filter.topic` is the
    /// load-bearing spec here.
    #[test]
    fn custom_topics_match_by_prefix() {
        let s = subscription(EventFilter {
            device: None,
            topic: Some("automation.".into()),
        });
        assert!(s.matches(&custom(None, "automation.morning")));
        assert!(s.matches(&custom(None, "automation.evening")));
        assert!(!s.matches(&custom(None, "automatic")));
        assert!(!s.matches(&custom(None, "switch")));
    }

    /// Device filter narrows independently of topic. Both fields
    /// `None` matches everything.
    #[test]
    fn device_filter_narrows() {
        let only_d1 = subscription(EventFilter {
            device: Some("d-1".into()),
            topic: None,
        });
        assert!(only_d1.matches(&state_change("d-1", "switch")));
        assert!(!only_d1.matches(&state_change("d-2", "switch")));

        let all = subscription(EventFilter {
            device: None,
            topic: None,
        });
        assert!(all.matches(&state_change("d-1", "switch")));
        assert!(all.matches(&custom(None, "anything")));
    }
}
