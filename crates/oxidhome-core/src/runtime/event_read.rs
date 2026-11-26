//! `host-events::read-events` — plugin reads of the durable event
//! history (the H4 follow-up), so a plugin can resume `on-event`
//! delivery from the last `row-id` it handled after a restart or a lag.
//!
//! Scope follows live delivery. The call is `event.subscribe` in the
//! engine (H6 slice 5): it needs `capabilities.subscribes_events`, no
//! plugin deny list on the chain may refuse it, and an external root
//! needs `event.read` (refused `permission-denied`, with an audit
//! `deny` row, like H2's refused reads). A row is visible when it
//! matches one of the instance's current subscription filters (the
//! same `filter_matches` the bus uses) and no deny list on the chain
//! refuses its device, so history never shows a plugin more than
//! `on-event` would have. H3 gap markers match every
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
        + event.call_id.as_ref().map_or(0, String::len)
        + payload
}

/// What a reader may see of a history row, given the plugins upstream
/// of the subscription that matched it.
trait RowAccess {
    /// The row is hidden (a deny list refuses it).
    fn refused(&self, event: &Event, upstream: &[String]) -> bool;
    /// Its `bytes-val` fields may go out.
    fn releases_bytes(&self, event: &Event, upstream: &[String]) -> bool;
}

/// Everything visible, bytes as `bytes` says (tests).
#[cfg(test)]
struct Open {
    bytes: bool,
}

#[cfg(test)]
impl RowAccess for Open {
    fn refused(&self, _: &Event, _: &[String]) -> bool {
        false
    }
    fn releases_bytes(&self, _: &Event, _: &[String]) -> bool {
        self.bytes
    }
}

/// Read one page for a reader with `filters` as its subscriptions,
/// skipping (before counting) the rows `access` hides and withholding
/// the bytes it doesn't release.
fn read_page(
    log: &EventLog,
    after_id: u64,
    limit: usize,
    filters: &[(EventFilter, Arc<[String]>)],
    access: &impl RowAccess,
) -> Result<Result<ScanPage, CursorExpired>, EventLogError> {
    let mut taken = 0usize;
    let mut size = 0usize;
    log.scan_after_cursor(after_id, SCAN_BUDGET, |event| {
        let upstream = if is_gap_marker(event) {
            None
        } else {
            match filters
                .iter()
                .find(|(f, upstream)| filter_matches(f, event) && !access.refused(event, upstream))
            {
                Some((_, upstream)) => Some(upstream),
                None => return ScanStep::Skip,
            }
        };
        if taken >= limit {
            return ScanStep::Full;
        }
        if !upstream.is_some_and(|up| access.releases_bytes(event, up)) {
            withhold_bytes(&mut event.payload);
        }
        let len = approx_size(event);
        if taken > 0 && size + len > MAX_PAGE_BYTES {
            return ScanStep::Full;
        }
        taken += 1;
        size += len;
        if taken >= limit {
            // Stop here rather than decode more rows only to skip them.
            ScanStep::TakeLast
        } else {
            ScanStep::Take
        }
    })
}

/// [`RowAccess`] for a plugin's `read-events` (H6 slice 5). A row is
/// hidden when a deny list (the plugin's, its subscription's upstream
/// plugins', or this call's chain) refuses `event.subscribe` of its
/// device, as at delivery. Bytes go out with `reads_event_bytes` when
/// no list refuses `blob.read` of them and, inside a token's
/// invocation, the token may read them (`blob.read`, with no sensitive
/// obligation: camera bytes, from a camera device or a camera-source
/// instance, are withheld), as for its direct read.
struct HistoryAccess {
    refusal: super::state::EventRefusal,
    classes: crate::state::devices::ClassSnapshot,
    chain: Vec<String>,
    bytes: bool,
    ctx: crate::auth::InvocationContext,
}

impl HistoryAccess {
    fn plugins<'a>(&'a self, upstream: &'a [String]) -> impl Iterator<Item = &'a String> {
        upstream.iter().chain(self.chain.iter())
    }
}

impl RowAccess for HistoryAccess {
    fn refused(&self, event: &Event, upstream: &[String]) -> bool {
        let resource = event.device.as_deref().map_or(
            crate::auth::Resource::pre_check(crate::auth::ResourceKind::Event),
            |d| self.classes.resource(d),
        );
        self.refusal.denies(
            crate::auth::Action::EventSubscribe,
            &resource,
            self.plugins(upstream),
        )
    }

    fn releases_bytes(&self, event: &Event, upstream: &[String]) -> bool {
        if !self.bytes {
            return false;
        }
        let camera = self.classes.instance_is_camera(&event.origin_instance_id);
        let resource = match event.device.as_deref() {
            Some(d) => {
                let class = self.classes.class_of(d);
                crate::auth::Resource::device(
                    d,
                    if camera {
                        class.with_camera_bytes()
                    } else {
                        class
                    },
                )
            }
            None => crate::auth::Resource::blob(event.origin_instance_id.as_str(), "", camera),
        };
        if self.refusal.denies(
            crate::auth::Action::BlobRead,
            &resource,
            self.plugins(upstream),
        ) {
            return false;
        }
        !self.ctx.root().is_external() || {
            let root = crate::auth::authorize(&self.ctx, crate::auth::Action::BlobRead, &resource);
            root.allow && root.obligations.sensitive.is_empty()
        }
    }
}

impl PluginState {
    /// `read-events` is `event.subscribe` in the engine; a refusal is
    /// audited in the background and answered `permission-denied`.
    fn authorize_event_read(&self, ctx: &crate::auth::InvocationContext) -> Result<(), WitError> {
        let decision = crate::auth::authorize_plugin(
            ctx,
            &self.principal(),
            crate::auth::Action::EventSubscribe,
            &crate::auth::Resource::pre_check(crate::auth::ResourceKind::Event),
        );
        if !decision.allow {
            let scope = decision.reason.audit_label().unwrap_or("no-permit");
            queue_deny_audit(
                self.audit_log.clone(),
                &self.instance_id,
                DeniedRead::Events { scope },
            );
            return Err(WitError::PermissionDenied(
                if matches!(
                    decision.reason,
                    crate::auth::Reason::MissingPluginGrant { .. }
                ) {
                    "read-events requires `capabilities.subscribes_events = true` in the \
                     plugin manifest"
                        .into()
                } else {
                    format!("read-events refused (`{scope}`)")
                },
            ));
        }
        Ok(())
    }

    /// `host-events::read-events`; see the module docs.
    pub(super) async fn read_events_impl(
        &mut self,
        after_id: u64,
        limit: u32,
    ) -> Result<EventRead, WitError> {
        let ctx = crate::auth::invocation::current_or_host(&self.instance_id);
        self.authorize_event_read(&ctx)?;
        let limit = match usize::try_from(limit).unwrap_or(usize::MAX) {
            0 => DEFAULT_LIMIT,
            n => n.min(MAX_LIMIT),
        };
        let log = Arc::clone(&self.event_log);
        let subscriptions = &self.subscriptions;
        let access = HistoryAccess {
            refusal: self.event_refusal(),
            // Read before the scan: the registry's locks aren't taken
            // while the scan holds the database connection.
            classes: self.devices.class_snapshot(),
            chain: ctx
                .chain()
                .iter()
                .map(|h| h.caller_plugin.clone())
                .collect(),
            bytes: self.granted_capabilities.reads_event_bytes,
            ctx: ctx.clone(),
        };
        let read = async {
            // The permit moves into the closure, so a call cancelled
            // or timed out while its read runs still holds the slot
            // until the read finishes: a hung disk can't pile up
            // blocking threads.
            let permit = Arc::clone(&READS).acquire_owned().await.ok()?;
            let filters: Vec<(EventFilter, Arc<[String]>)> = subscriptions
                .iter()
                .map(|s| (s.filter.clone(), Arc::clone(&s.upstream)))
                .collect();
            tokio::task::spawn_blocking(move || {
                let _permit = permit;
                read_page(&log, after_id, limit, &filters, &access)
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
        let events = page.events;
        tracing::debug!(
            target: "host.events",
            instance_id = %self.instance_id,
            after_id,
            events = events.len(),
            next_after_id = page.next_after_id,
            "read-events",
        );
        Ok(EventRead::Page(EventPage {
            events,
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
            call_id: None,
            payload: EventPayload::Custom(CustomEvent {
                topic: topic.into(),
                payload: payload.into(),
            }),
        }
    }

    /// H6 slice 4: the page budget counts an event's call id.
    #[test]
    fn page_size_counts_the_call_id() {
        let plain = custom("t", "{}");
        let attributed = Event {
            call_id: Some(format!("call-{:032x}", 1)),
            ..plain.clone()
        };
        assert_eq!(approx_size(&attributed), approx_size(&plain) + 37);
    }

    /// H6 slice 4: a plugin's history page returns each event's call
    /// id as recorded.
    #[test]
    fn history_pages_carry_the_call_id() {
        let log = log();
        let attributed = Event {
            call_id: Some(format!("call-{:032x}", 7)),
            ..custom("t.a", "1")
        };
        record(&log, &[attributed, custom("t.b", "2")]);
        let p = page(&log, 0, 10, &[all()], true);
        let calls: Vec<Option<&str>> = p.events.iter().map(|e| e.call_id.as_deref()).collect();
        let expected = format!("call-{:032x}", 7);
        assert_eq!(calls, vec![Some(expected.as_str()), None]);
    }

    /// Hides the rows of `hidden`'s topic, and only for subscriptions
    /// with an upstream plugin (H6 slice 5 tests).
    struct HideTopic {
        hidden: &'static str,
    }

    impl RowAccess for HideTopic {
        fn refused(&self, event: &Event, upstream: &[String]) -> bool {
            !upstream.is_empty()
                && matches!(&event.payload, EventPayload::Custom(c) if c.topic == self.hidden)
        }
        fn releases_bytes(&self, _: &Event, _: &[String]) -> bool {
            true
        }
    }

    /// H6 slice 5: a hidden row is skipped before it counts toward a
    /// page, and hiding follows the upstream of the subscription that
    /// matched.
    #[test]
    fn hidden_rows_do_not_count_toward_a_page() {
        let log = log();
        record(
            &log,
            &[custom("secret", "1"), custom("t", "2"), custom("t", "3")],
        );
        let upstream: Arc<[String]> = Arc::from(["com.example.caller".to_owned()]);
        let access = HideTopic { hidden: "secret" };
        let p = read_page(&log, 0, 1, &[(all(), Arc::clone(&upstream))], &access)
            .expect("read")
            .expect("cursor");
        let topics: Vec<_> = p
            .events
            .iter()
            .map(|e| match &e.payload {
                EventPayload::Custom(c) => c.topic.clone(),
                _ => unreachable!(),
            })
            .collect();
        assert_eq!(topics, ["t"]);
        // A second subscription without an upstream still sees it.
        let p = read_page(
            &log,
            0,
            10,
            &[(all(), upstream), (all(), Arc::from([]))],
            &access,
        )
        .expect("read")
        .expect("cursor");
        assert_eq!(p.events.len(), 3);
    }

    fn camera(device: &str, frame: Vec<u8>) -> Event {
        Event {
            device: Some(device.into()),
            timestamp: 0,
            origin_plugin_id: "example.pub".into(),
            origin_instance_id: "pub".into(),
            row_id: None,
            call_id: None,
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
        let filters: Vec<_> = filters.iter().map(|f| (f.clone(), Arc::from([]))).collect();
        read_page(log, after, limit, &filters, &Open { bytes })
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
        // A page that fills stops at its last event.
        let p = page(&log, 0, 1, &[topic("automation.")], true);
        assert_eq!((ids(&p), p.next_after_id), (vec![1], 1));
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
        let expired = read_page(
            &log,
            1,
            10,
            &[(all(), Arc::from([]))],
            &Open { bytes: true },
        )
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
