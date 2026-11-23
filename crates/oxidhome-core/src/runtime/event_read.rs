//! `host-events::read-events` — plugin reads of the durable event
//! history (the H4 follow-up), so a plugin can resume `on-event`
//! delivery from the last `row-id` it handled after a restart or a lag.
//!
//! Scope follows live delivery. The call needs
//! `capabilities.subscribes_events` (refused `permission-denied`, with
//! an audit `deny` row, like H2's refused reads), and a row is visible
//! when it matches one of the instance's current subscription filters
//! (the same `filter_matches` the bus uses), so history never shows a
//! plugin more than `on-event` would have. H3 gap markers match every
//! filter and are visible even with no subscription. Rows that aren't
//! visible are skipped silently: the cursor moves past them and the
//! page doesn't say why, as with `list-state`. Allowed reads are
//! traced, not audited.
//!
//! `bytes-val` fields are replaced by a `json-val` marker unless the
//! effective capabilities set `reads_event_bytes`. There is no
//! own-event exemption as in H2: `event_log` doesn't record the
//! publisher's installation, so an instance id reused by another
//! install couldn't be told apart from the original.
//!
//! Each call is one `EventLog::scan_after_cursor`: the cursor check
//! and the reads share one `Db::read` snapshot (M6 read pool), run on
//! the blocking pool behind a small process-wide semaphore, with a
//! deadline (`READ_TIMEOUT`, after which the call is `unavailable`). A page
//! holds at most `MAX_LIMIT` events and about `MAX_PAGE_BYTES`, and a
//! call looks at no more than `SCAN_BUDGET` rows.

use std::sync::{Arc, LazyLock};
use std::time::Duration;

use tokio::sync::Semaphore;

use super::state::PluginState;
use super::state_read::{DeniedRead, queue_deny_audit};
use crate::host_impl::plugin::oxidhome::plugin::events::{Event, EventFilter, EventPayload};
use crate::host_impl::plugin::oxidhome::plugin::host_events::{
    CursorExpired as WitCursorExpired, EventPage, EventRead,
};
use crate::host_impl::plugin::oxidhome::plugin::types::{Error as WitError, KeyValue, Value};
use crate::state::event_log::{ScanPage, ScanStep, is_gap_marker};
use crate::state::events::filter_matches;
use crate::state::{CursorExpired, EventLog, EventLogError};

/// Default and maximum events per page.
const DEFAULT_LIMIT: usize = 64;
const MAX_LIMIT: usize = 256;
/// Approximate byte budget per page (same as `list-state`).
const MAX_PAGE_BYTES: usize = 1024 * 1024;
/// Rows one call looks at, visible or not, so a sparse filter can't
/// make one call walk the whole history.
const SCAN_BUDGET: usize = 1024;
/// History reads in flight from all plugins at once. Further calls
/// wait for a slot (each instance makes at most one call at a time).
const READ_SLOTS: usize = 4;

/// Deadline for one call, waiting for a slot included.
const READ_TIMEOUT: Duration = Duration::from_secs(10);

static READS: LazyLock<Arc<Semaphore>> = LazyLock::new(|| Arc::new(Semaphore::new(READ_SLOTS)));

/// The marker a withheld `bytes-val` becomes.
fn withheld_marker(len: usize) -> Value {
    Value::JsonVal(format!(
        "{{\"withheld\":\"bytes\",\"size_bytes\":{len},\"required_scope\":\"reads_event_bytes\"}}"
    ))
}

fn withhold_bytes(payload: &mut EventPayload) {
    if let EventPayload::StateChanged(sc) = payload {
        for kv in &mut sc.fields {
            if let Value::BytesVal(b) = &kv.value {
                kv.value = withheld_marker(b.len());
            }
        }
    }
}

/// Rough size of an event in a page: its strings and values plus a
/// fixed per-record overhead.
fn approx_size(event: &Event) -> usize {
    const RECORD: usize = 64;
    let value = |v: &Value| match v {
        Value::StringVal(s) | Value::JsonVal(s) => s.len(),
        Value::BytesVal(b) => b.len(),
        Value::BoolVal(_) | Value::IntVal(_) | Value::FloatVal(_) => 8,
    };
    let fields = |kvs: &[KeyValue]| -> usize {
        kvs.iter()
            .map(|kv| kv.key.len() + value(&kv.value) + 16)
            .sum()
    };
    let payload = match &event.payload {
        EventPayload::StateChanged(sc) => sc.capability.len() + fields(&sc.fields),
        EventPayload::Button(_) => RECORD,
        EventPayload::Inference(i) => i.model.len() + i.payload.len() + 16,
        EventPayload::Custom(c) => c.topic.len() + c.payload.len(),
    };
    RECORD
        + event.device.as_ref().map_or(0, String::len)
        + event.origin_plugin_id.len()
        + event.origin_instance_id.len()
        + payload
}

/// Read one page for a reader with `filters` as its subscriptions.
fn read_page(
    log: &EventLog,
    after_id: u64,
    limit: usize,
    filters: &[EventFilter],
    bytes: bool,
) -> Result<Result<ScanPage, CursorExpired>, EventLogError> {
    let mut taken = 0usize;
    let mut size = 0usize;
    log.scan_after_cursor(after_id, SCAN_BUDGET, |event| {
        if !is_gap_marker(event) && !filters.iter().any(|f| filter_matches(f, event)) {
            return ScanStep::Skip;
        }
        if taken >= limit {
            return ScanStep::Full;
        }
        if !bytes {
            withhold_bytes(&mut event.payload);
        }
        let len = approx_size(event);
        if taken > 0 && size + len > MAX_PAGE_BYTES {
            return ScanStep::Full;
        }
        taken += 1;
        size += len;
        ScanStep::Take
    })
}

impl PluginState {
    /// `host-events::read-events`; see the module docs.
    pub(super) async fn read_events_impl(
        &mut self,
        after_id: u64,
        limit: u32,
    ) -> Result<EventRead, WitError> {
        if !self.granted_capabilities.subscribes_events {
            queue_deny_audit(
                self.audit_log.clone(),
                &self.instance_id,
                DeniedRead::Events,
            );
            return Err(WitError::PermissionDenied(
                "read-events requires `capabilities.subscribes_events = true` in the plugin \
                 manifest"
                    .into(),
            ));
        }
        let limit = match usize::try_from(limit).unwrap_or(usize::MAX) {
            0 => DEFAULT_LIMIT,
            n => n.min(MAX_LIMIT),
        };
        let bytes = self.granted_capabilities.reads_event_bytes;
        let log = Arc::clone(&self.event_log);
        let subscriptions = &self.subscriptions;
        let read = async {
            // The permit moves into the closure, so a call cancelled
            // or timed out while its read runs still holds the slot
            // until the read finishes: a hung disk can't pile up
            // blocking threads.
            let permit = Arc::clone(&READS).acquire_owned().await.ok()?;
            let filters: Vec<EventFilter> =
                subscriptions.iter().map(|s| s.filter.clone()).collect();
            tokio::task::spawn_blocking(move || {
                let _permit = permit;
                read_page(&log, after_id, limit, &filters, bytes)
            })
            .await
            .map(Some)
            .transpose()
        };
        // The wasm watchdog only interrupts guest code, so a host call
        // parked here needs its own deadline.
        let read = match tokio::time::timeout(READ_TIMEOUT, read).await {
            Ok(Some(read)) => read,
            Ok(None) => {
                return Err(WitError::Unavailable(
                    "event history is shutting down".into(),
                ));
            }
            Err(_) => {
                tracing::warn!(
                    target: "host.events",
                    instance_id = %self.instance_id,
                    "read-events: history read timed out",
                );
                return Err(WitError::Unavailable("event history read timed out".into()));
            }
        };
        let page = match read {
            Ok(Ok(Ok(page))) => page,
            Ok(Ok(Err(expired))) => {
                tracing::debug!(
                    target: "host.events",
                    instance_id = %self.instance_id,
                    after_id,
                    head_id = expired.head_id,
                    "read-events: cursor expired",
                );
                return Ok(EventRead::CursorExpired(WitCursorExpired {
                    after_id: expired.after_id,
                    oldest_id: expired.oldest_id,
                    head_id: expired.head_id,
                }));
            }
            Ok(Err(err)) => {
                tracing::error!(
                    target: "host.events",
                    instance_id = %self.instance_id,
                    error = %err,
                    "read-events: history read failed",
                );
                return Err(WitError::Unavailable("event history read failed".into()));
            }
            Err(err) => {
                tracing::error!(
                    target: "host.events",
                    instance_id = %self.instance_id,
                    error = %err,
                    "read-events: history read task failed",
                );
                return Err(WitError::Internal("event history read failed".into()));
            }
        };
        tracing::debug!(
            target: "host.events",
            instance_id = %self.instance_id,
            after_id,
            events = page.events.len(),
            next_after_id = page.next_after_id,
            "read-events",
        );
        Ok(EventRead::Page(EventPage {
            events: page.events,
            next_after_id: page.next_after_id,
            head_id: page.head_id,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_impl::plugin::oxidhome::plugin::events::{CustomEvent, StateChange};
    use crate::state::Db;
    use crate::state::{GAP_MARKER_ORIGIN, GAP_MARKER_TOPIC};

    fn custom(topic: &str, payload: &str) -> Event {
        Event {
            device: None,
            timestamp: 0,
            origin_plugin_id: "example.pub".into(),
            origin_instance_id: "pub".into(),
            row_id: None,
            payload: EventPayload::Custom(CustomEvent {
                topic: topic.into(),
                payload: payload.into(),
            }),
        }
    }

    fn camera(device: &str, frame: Vec<u8>) -> Event {
        Event {
            device: Some(device.into()),
            timestamp: 0,
            origin_plugin_id: "example.pub".into(),
            origin_instance_id: "pub".into(),
            row_id: None,
            payload: EventPayload::StateChanged(StateChange {
                capability: "camera".into(),
                fields: vec![KeyValue {
                    key: "frame".into(),
                    value: Value::BytesVal(frame),
                }],
            }),
        }
    }

    fn record(log: &EventLog, events: &[Event]) {
        for ev in events {
            log.record(1, ev, &ev.origin_instance_id, &ev.origin_plugin_id)
                .expect("record");
        }
    }

    fn topic(t: &str) -> EventFilter {
        EventFilter {
            device: None,
            topic: Some(t.into()),
        }
    }

    fn all() -> EventFilter {
        EventFilter {
            device: None,
            topic: None,
        }
    }

    fn page(
        log: &EventLog,
        after: u64,
        limit: usize,
        filters: &[EventFilter],
        bytes: bool,
    ) -> ScanPage {
        read_page(log, after, limit, filters, bytes)
            .expect("read")
            .expect("cursor")
    }

    fn ids(page: &ScanPage) -> Vec<u64> {
        page.events.iter().filter_map(|e| e.row_id).collect()
    }

    fn log() -> EventLog {
        EventLog::new(Arc::new(Db::open_in_memory().expect("db")))
    }

    #[test]
    fn only_rows_matching_a_subscription_are_visible() {
        let log = log();
        record(
            &log,
            &[
                custom("automation.morning", "1"),
                custom("other", "2"),
                camera("dev-1", vec![1]),
                camera("dev-2", vec![2]),
            ],
        );
        let p = page(&log, 0, 0, &[], true);
        assert_eq!(ids(&p), Vec::<u64>::new(), "no subscription, no rows");
        assert_eq!((p.next_after_id, p.head_id), (4, 4));
        let p = page(&log, 0, 10, &[topic("automation.")], true);
        assert_eq!(ids(&p), vec![1]);
        let device = EventFilter {
            device: Some("dev-2".into()),
            topic: None,
        };
        let p = page(&log, 0, 10, &[topic("other"), device], true);
        assert_eq!(ids(&p), vec![2, 4]);
        // The cursor moves past invisible rows.
        assert_eq!(p.next_after_id, 4);
    }

    #[test]
    fn gap_markers_are_always_visible() {
        let log = log();
        record(&log, &[custom("other", "1")]);
        let mut marker = custom(GAP_MARKER_TOPIC, "{}");
        marker.origin_plugin_id = GAP_MARKER_ORIGIN.into();
        marker.origin_instance_id = GAP_MARKER_ORIGIN.into();
        record(&log, &[marker]);
        let p = page(&log, 0, 10, &[], true);
        assert_eq!(ids(&p), vec![2]);
        assert!(is_gap_marker(&p.events[0]));
    }

    #[test]
    fn bytes_are_withheld_without_the_grant() {
        let log = log();
        record(&log, &[camera("dev-1", vec![1, 2, 3])]);
        let withheld = page(&log, 0, 10, &[all()], false);
        let EventPayload::StateChanged(sc) = &withheld.events[0].payload else {
            panic!("not a state change");
        };
        let Value::JsonVal(marker) = &sc.fields[0].value else {
            panic!("bytes not withheld: {:?}", sc.fields[0].value);
        };
        assert!(marker.contains("\"size_bytes\":3"), "{marker}");
        assert!(marker.contains("reads_event_bytes"), "{marker}");
        let full = page(&log, 0, 10, &[all()], true);
        let EventPayload::StateChanged(sc) = &full.events[0].payload else {
            panic!("not a state change");
        };
        assert!(matches!(&sc.fields[0].value, Value::BytesVal(b) if b == &[1, 2, 3]));
    }

    #[test]
    fn pages_are_capped_by_count_and_bytes() {
        let log = log();
        let events: Vec<Event> = (0..300).map(|n| custom("t", &n.to_string())).collect();
        record(&log, &events);
        let p = page(&log, 0, 10, &[all()], true);
        assert_eq!(ids(&p), (1..=10).collect::<Vec<_>>());
        assert_eq!(p.next_after_id, 10);
        // The caller clamps `limit` to `MAX_LIMIT`.
        let p = page(&log, 10, MAX_LIMIT, &[all()], true);
        assert_eq!(p.events.len(), MAX_LIMIT);
        assert_eq!(p.next_after_id, 10 + MAX_LIMIT as u64);

        let big = log_with_big_rows(40, 60 * 1024);
        let p = page(&big, 0, MAX_LIMIT, &[all()], true);
        let total: usize = p.events.iter().map(approx_size).sum();
        assert!(total <= MAX_PAGE_BYTES, "{total}");
        assert!(
            p.events.len() > 1 && p.events.len() < 40,
            "{}",
            p.events.len()
        );
        assert_eq!(p.next_after_id, p.events.len() as u64);
        // One oversized row still makes progress.
        let huge = log_with_big_rows(2, 2 * MAX_PAGE_BYTES);
        let p = page(&huge, 0, MAX_LIMIT, &[all()], true);
        assert_eq!(ids(&p), vec![1]);
    }

    #[test]
    fn a_sparse_filter_stops_at_the_scan_budget() {
        let log = log();
        let events: Vec<Event> = (0..SCAN_BUDGET + 10)
            .map(|n| custom(if n == SCAN_BUDGET + 5 { "rare" } else { "t" }, "x"))
            .collect();
        record(&log, &events);
        let p = page(&log, 0, 10, &[topic("rare")], true);
        assert!(p.events.is_empty());
        assert_eq!(p.next_after_id, SCAN_BUDGET as u64);
        let p = page(&log, p.next_after_id, 10, &[topic("rare")], true);
        assert_eq!(ids(&p), vec![SCAN_BUDGET as u64 + 6]);
        assert_eq!(p.next_after_id, p.head_id);
    }

    #[test]
    fn expired_cursor_is_reported() {
        let log = log();
        record(
            &log,
            &[custom("t", "1"), custom("t", "2"), custom("t", "3")],
        );
        log.trim_older_than(i64::MAX).expect("trim");
        let expired = read_page(&log, 1, 10, &[all()], true)
            .expect("read")
            .expect_err("expired");
        assert_eq!(
            expired,
            CursorExpired {
                after_id: 1,
                oldest_id: None,
                head_id: 3,
            }
        );
    }

    fn log_with_big_rows(n: usize, size: usize) -> EventLog {
        let log = log();
        let events: Vec<Event> = (0..n).map(|_| custom("t", &"x".repeat(size))).collect();
        record(&log, &events);
        log
    }
}
