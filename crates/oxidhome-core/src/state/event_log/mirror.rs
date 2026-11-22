//! H3: the durable mirror never gates live delivery.
//!
//! Durability policy. Every event on the bus (`state-changed`,
//! `button`, `inference`, `custom`) is **best-effort mirrored**: the
//! host tries to write it to `event_log` before fan-out so the
//! delivered event carries its `row-id`, but a failed, or slow, write
//! never stops the event from reaching subscribers. Records that must
//! be durable before the action they describe proceeds (the C3 audit
//! ledger, `audit_event`) live on a separate, fail-closed path that
//! this module doesn't touch.
//!
//! Degraded mode. A write that errors, panics, or exceeds
//! [`MirrorPolicy::write_deadline`] puts the mirror into *degraded*
//! mode:
//!
//! - the event is delivered with `row-id: none` (Connect `row_id = 0`,
//!   JSON tail without `id`) and counted as *unrecorded*;
//! - later publishes skip the disk entirely (no per-event stall) until
//!   [`MirrorPolicy::probe_interval`] has passed; the next publish
//!   after that is the recovery probe;
//! - a probe that succeeds writes one **gap marker** row
//!   ([`GAP_MARKER_TOPIC`], origin [`GAP_MARKER_ORIGIN`], payload
//!   [`GapMarker`]) in the same transaction as the probing event, so
//!   the marker's row id sits between the last pre-outage row and the
//!   first post-recovery row.
//!
//! A write that timed out may still commit later. Such a row has an
//! id below every later row, so history order still matches delivery
//! order, but the marker's `unrecorded` count is then an upper bound
//! and a consumer that replays history after seeing that event live
//! (without an id) sees it twice.
//!
//! Callers must serialize [`EventLog::mirror`] calls (the host holds
//! the bus's `publish_sequence` gate around it); the plan → write →
//! settle sequence assumes no other mirror call interleaves.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::{EventLog, EventLogError, insert_row, now_unix_ms, serialize_payload};
use crate::host_impl::plugin::oxidhome::plugin::events::{CustomEvent, Event, EventPayload};

/// Custom-event topic of the history row the host writes when the
/// mirror recovers from degraded mode.
pub const GAP_MARKER_TOPIC: &str = "host.event_log.gap";

/// `plugin_id` and `instance_id` of a gap-marker row. Manifest
/// validation requires a reverse-DNS `plugin.id` (at least one dot),
/// so no plugin can publish under this origin: a row with
/// `plugin_id == "host"` and topic [`GAP_MARKER_TOPIC`] is always
/// host-written.
pub const GAP_MARKER_ORIGIN: &str = "host";

/// Deadline and probe cadence for the degraded-mode state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MirrorPolicy {
    /// How long a publish waits for its durable write before it
    /// delivers the event unrecorded and enters degraded mode. This
    /// bounds how long a slow disk can hold the publish-sequence gate.
    pub write_deadline: Duration,
    /// Minimum time between write attempts while degraded.
    pub probe_interval: Duration,
}

impl Default for MirrorPolicy {
    fn default() -> Self {
        Self {
            write_deadline: Duration::from_secs(2),
            probe_interval: Duration::from_secs(5),
        }
    }
}

/// JSON body of a gap-marker row's custom payload. Describes the
/// events that were delivered live but are missing from history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GapMarker {
    /// Events delivered without a row id during the outage. An upper
    /// bound when a timed-out write committed late (module docs).
    pub unrecorded: u64,
    /// Host receive time of the first unrecorded event.
    pub first_received_ms: i64,
    /// Host receive time of the last unrecorded event.
    pub last_received_ms: i64,
    /// Error of the last failed write attempt.
    pub last_error: String,
}

/// Point-in-time mirror health, exposed on the readiness probe and
/// the MCP `oxidhome://status` resource.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct EventLogHealth {
    /// `true` while publishes are delivered without a durable row.
    pub degraded: bool,
    /// Host time the current outage started.
    pub degraded_since_ms: Option<i64>,
    /// Unrecorded events in the current outage (what the next gap
    /// marker will report).
    pub unrecorded_pending: u64,
    /// Unrecorded events since the daemon started.
    pub unrecorded_total: u64,
    /// Gap markers written since the daemon started.
    pub gap_markers_total: u64,
    /// Error of the last failed write, while degraded.
    pub last_error: Option<String>,
    /// Host time of the last recovery.
    pub last_recovered_ms: Option<i64>,
}

#[derive(Debug)]
struct Outage {
    since_ms: i64,
    first_received_ms: i64,
    last_received_ms: i64,
    unrecorded: u64,
    last_error: String,
    next_probe: Instant,
}

impl Outage {
    fn marker(&self) -> GapMarker {
        GapMarker {
            unrecorded: self.unrecorded,
            first_received_ms: self.first_received_ms,
            last_received_ms: self.last_received_ms,
            last_error: self.last_error.clone(),
        }
    }
}

#[derive(Debug, Default)]
struct MirrorState {
    outage: Option<Outage>,
    unrecorded_total: u64,
    gap_markers_total: u64,
    last_recovered_ms: Option<i64>,
}

/// Shared by every clone of an [`EventLog`].
#[derive(Debug)]
pub(super) struct MirrorShared {
    policy: MirrorPolicy,
    state: Mutex<MirrorState>,
    /// Blocking writes started but not finished. Non-zero outside a
    /// `mirror` call only when a write outlived its deadline; no probe
    /// starts until it drains, so a hung disk can't pile up blocking
    /// threads behind the connection mutex.
    in_flight: Arc<AtomicUsize>,
}

impl MirrorShared {
    pub(super) fn new(policy: MirrorPolicy) -> Self {
        Self {
            policy,
            state: Mutex::new(MirrorState::default()),
            in_flight: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, MirrorState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Decrements `in_flight` when the blocking write finishes, even if
/// it panics.
struct InFlight(Arc<AtomicUsize>);

impl Drop for InFlight {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

enum Plan {
    /// Degraded and no probe due: deliver unrecorded, no disk work.
    Skip,
    /// Attempt the write; `Some` = recovery probe, write this marker
    /// first.
    Write(Option<GapMarker>),
}

impl EventLog {
    /// Best-effort durable write for one published event (H3).
    /// Returns the row id on success, `None` when the event must be
    /// delivered unrecorded. Never fails: write errors move the
    /// mirror into degraded mode instead (module docs).
    pub(crate) async fn mirror(
        &self,
        received_ms: i64,
        event: Event,
        instance_id: String,
        plugin_id: String,
        payload_blob: Vec<u8>,
    ) -> Option<u64> {
        let gap = match self.plan(received_ms) {
            Plan::Skip => return None,
            Plan::Write(gap) => gap,
        };
        let probing = gap.is_some();
        let this = self.clone();
        self.mirror.in_flight.fetch_add(1, Ordering::AcqRel);
        let guard = InFlight(Arc::clone(&self.mirror.in_flight));
        let write = tokio::task::spawn_blocking(move || {
            let _guard = guard;
            this.write_with_gap(
                received_ms,
                &event,
                &instance_id,
                &plugin_id,
                &payload_blob,
                gap.as_ref(),
            )
        });
        let deadline = self.mirror.policy.write_deadline;
        let outcome = match tokio::time::timeout(deadline, write).await {
            Ok(Ok(Ok(id))) => Ok(id),
            Ok(Ok(Err(e))) => Err(format!("write failed: {e}")),
            Ok(Err(join)) => Err(format!("blocking write task panicked: {join}")),
            Err(_) => Err(format!(
                "write exceeded the {}ms deadline (it may still commit)",
                deadline.as_millis(),
            )),
        };
        match outcome {
            Ok(id) => {
                if probing {
                    self.note_recovered(id);
                }
                Some(id)
            }
            Err(reason) => {
                self.note_unrecorded(received_ms, reason, probing);
                None
            }
        }
    }

    /// Current mirror health snapshot.
    #[must_use]
    pub fn health(&self) -> EventLogHealth {
        let st = self.mirror.lock();
        EventLogHealth {
            degraded: st.outage.is_some(),
            degraded_since_ms: st.outage.as_ref().map(|o| o.since_ms),
            unrecorded_pending: st.outage.as_ref().map_or(0, |o| o.unrecorded),
            unrecorded_total: st.unrecorded_total,
            gap_markers_total: st.gap_markers_total,
            last_error: st.outage.as_ref().map(|o| o.last_error.clone()),
            last_recovered_ms: st.last_recovered_ms,
        }
    }

    fn plan(&self, received_ms: i64) -> Plan {
        let mut st = self.mirror.lock();
        let Some(outage) = st.outage.as_mut() else {
            return Plan::Write(None);
        };
        if Instant::now() >= outage.next_probe && self.mirror.in_flight.load(Ordering::Acquire) == 0
        {
            return Plan::Write(Some(outage.marker()));
        }
        outage.unrecorded += 1;
        outage.last_received_ms = received_ms;
        st.unrecorded_total += 1;
        Plan::Skip
    }

    fn note_unrecorded(&self, received_ms: i64, reason: String, probing: bool) {
        let next_probe = Instant::now() + self.mirror.policy.probe_interval;
        let mut st = self.mirror.lock();
        st.unrecorded_total += 1;
        if let Some(outage) = st.outage.as_mut() {
            outage.unrecorded += 1;
            outage.last_received_ms = received_ms;
            outage.next_probe = next_probe;
            tracing::warn!(
                target: "event_log.mirror",
                probing,
                unrecorded = outage.unrecorded,
                error = %reason,
                "event log still degraded: recovery probe failed; live delivery continues without durable row ids",
            );
            outage.last_error = reason;
        } else {
            tracing::error!(
                target: "event_log.mirror",
                error = %reason,
                probe_interval_ms = u64::try_from(self.mirror.policy.probe_interval.as_millis())
                    .unwrap_or(u64::MAX),
                "event log degraded: durable write failed; live delivery continues without durable row ids \
                 and history will carry a gap marker once writes recover",
            );
            st.outage = Some(Outage {
                since_ms: now_unix_ms(),
                first_received_ms: received_ms,
                last_received_ms: received_ms,
                unrecorded: 1,
                last_error: reason,
                next_probe,
            });
        }
    }

    fn note_recovered(&self, first_row_id: u64) {
        let mut st = self.mirror.lock();
        let Some(outage) = st.outage.take() else {
            return;
        };
        st.gap_markers_total += 1;
        st.last_recovered_ms = Some(now_unix_ms());
        tracing::warn!(
            target: "event_log.mirror",
            unrecorded = outage.unrecorded,
            degraded_since_ms = outage.since_ms,
            first_row_id,
            "event log recovered: gap marker written to history",
        );
    }

    /// One transaction: optional gap marker, then the event. Returns
    /// the event's row id.
    fn write_with_gap(
        &self,
        received_ms: i64,
        event: &Event,
        instance_id: &str,
        plugin_id: &str,
        payload_blob: &[u8],
        gap: Option<&GapMarker>,
    ) -> Result<u64, EventLogError> {
        let marker = gap.map(|g| gap_marker_event(g, received_ms)).transpose()?;
        self.db.write(|conn| -> Result<u64, EventLogError> {
            let tx = conn.transaction()?;
            if let Some((marker, blob)) = &marker {
                insert_row(
                    &tx,
                    received_ms,
                    marker,
                    GAP_MARKER_ORIGIN,
                    GAP_MARKER_ORIGIN,
                    blob,
                )?;
            }
            let id = insert_row(
                &tx,
                received_ms,
                event,
                instance_id,
                plugin_id,
                payload_blob,
            )?;
            tx.commit()?;
            Ok(id)
        })
    }
}

fn gap_marker_event(gap: &GapMarker, received_ms: i64) -> Result<(Event, Vec<u8>), EventLogError> {
    let payload = serde_json::to_string(gap).map_err(|source| EventLogError::Encode {
        topic: GAP_MARKER_TOPIC.to_owned(),
        source,
    })?;
    let event = Event {
        device: None,
        timestamp: u64::try_from(received_ms).unwrap_or(0),
        origin_plugin_id: GAP_MARKER_ORIGIN.to_owned(),
        origin_instance_id: GAP_MARKER_ORIGIN.to_owned(),
        row_id: None,
        payload: EventPayload::Custom(CustomEvent {
            topic: GAP_MARKER_TOPIC.to_owned(),
            payload,
        }),
    };
    let blob = serialize_payload(&event.payload, GAP_MARKER_TOPIC)?;
    Ok((event, blob))
}

#[cfg(test)]
mod tests {
    use super::super::{EventOrder, EventQuery};
    use super::*;
    use crate::host_impl::plugin::oxidhome::plugin::events::StateChange;
    use crate::host_impl::plugin::oxidhome::plugin::types::{KeyValue, Value as WitValue};
    use crate::state::db::Db;

    const FAST: MirrorPolicy = MirrorPolicy {
        write_deadline: Duration::from_millis(500),
        probe_interval: Duration::from_millis(50),
    };

    fn log_with(policy: MirrorPolicy) -> EventLog {
        EventLog::with_mirror_policy(Arc::new(Db::open_in_memory().expect("db")), policy)
    }

    fn switch_event(on: bool) -> Event {
        Event {
            device: Some("d-1".into()),
            timestamp: 7,
            origin_plugin_id: "example.alpha".into(),
            origin_instance_id: "alpha".into(),
            row_id: None,
            payload: EventPayload::StateChanged(StateChange {
                capability: "switch".into(),
                fields: vec![KeyValue {
                    key: "state".into(),
                    value: WitValue::BoolVal(on),
                }],
            }),
        }
    }

    async fn publish(log: &EventLog, received_ms: i64) -> Option<u64> {
        let ev = switch_event(true);
        let blob = serialize_payload(&ev.payload, "switch").expect("blob");
        log.mirror(
            received_ms,
            ev,
            "alpha".into(),
            "example.alpha".into(),
            blob,
        )
        .await
    }

    /// Injects a write failure the way a full disk surfaces it: every
    /// `INSERT INTO event_log` aborts inside `SQLite`.
    fn break_writes(log: &EventLog) {
        log.db
            .write(|c| {
                c.execute_batch(
                    "CREATE TRIGGER h3_fail BEFORE INSERT ON event_log \
                     BEGIN SELECT RAISE(ABORT, 'injected: database or disk is full'); END;",
                )
            })
            .expect("install failure trigger");
    }

    fn fix_writes(log: &EventLog) {
        log.db
            .write(|c| c.execute_batch("DROP TRIGGER h3_fail;"))
            .expect("drop failure trigger");
    }

    fn all_rows(log: &EventLog) -> Vec<super::super::HistoricalEvent> {
        log.query(
            &EventQuery {
                order: EventOrder::Asc,
                ..EventQuery::default()
            },
            100,
        )
        .expect("query")
    }

    #[tokio::test(flavor = "current_thread")]
    async fn healthy_mirror_records_and_reports_ok() {
        let log = log_with(FAST);
        let id = publish(&log, 1).await.expect("row id");
        assert_eq!(all_rows(&log).len(), 1);
        assert_eq!(all_rows(&log)[0].id, id);
        assert_eq!(log.health(), EventLogHealth::default());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn write_failure_degrades_then_recovery_writes_gap_marker() {
        let log = log_with(FAST);
        let before = publish(&log, 10).await.expect("healthy write");

        break_writes(&log);
        assert_eq!(publish(&log, 20).await, None, "failed write → unrecorded");
        // Inside the probe interval the mirror skips the disk.
        assert_eq!(publish(&log, 30).await, None);
        let h = log.health();
        assert!(h.degraded);
        assert_eq!(h.unrecorded_pending, 2);
        assert_eq!(h.unrecorded_total, 2);
        assert!(
            h.last_error
                .as_deref()
                .is_some_and(|e| e.contains("disk is full")),
            "{h:?}",
        );

        // A probe that still fails keeps the outage open.
        tokio::time::sleep(FAST.probe_interval * 2).await;
        assert_eq!(publish(&log, 40).await, None);
        assert_eq!(log.health().unrecorded_pending, 3);

        fix_writes(&log);
        tokio::time::sleep(FAST.probe_interval * 2).await;
        let after = publish(&log, 50).await.expect("recovered write");

        let h = log.health();
        assert!(!h.degraded);
        assert_eq!(h.unrecorded_pending, 0);
        assert_eq!(h.unrecorded_total, 3);
        assert_eq!(h.gap_markers_total, 1);
        assert!(h.last_recovered_ms.is_some());

        // History: pre-outage row, gap marker, post-recovery row —
        // row ids strictly increasing, marker in between.
        let rows = all_rows(&log);
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].id, before);
        assert_eq!(rows[2].id, after);
        let marker = &rows[1];
        assert!(before < marker.id && marker.id < after);
        assert_eq!(marker.topic, GAP_MARKER_TOPIC);
        assert_eq!(marker.plugin_id, GAP_MARKER_ORIGIN);
        assert_eq!(marker.instance_id, GAP_MARKER_ORIGIN);
        assert_eq!(marker.device_id, None);
        let EventPayload::Custom(c) = &marker.payload else {
            panic!("marker payload must be custom, got {:?}", marker.payload);
        };
        let gap: GapMarker = serde_json::from_str(&c.payload).expect("gap json");
        assert_eq!(gap.unrecorded, 3);
        assert_eq!(gap.first_received_ms, 20);
        assert_eq!(gap.last_received_ms, 40);
        assert!(gap.last_error.contains("disk is full"), "{gap:?}");

        // A forward cursor parked on the pre-outage row sees the
        // marker before any post-recovery event.
        let page = log
            .query(
                &EventQuery {
                    after_id: Some(before),
                    order: EventOrder::Asc,
                    ..EventQuery::default()
                },
                1,
            )
            .expect("cursor query");
        assert_eq!(page[0].topic, GAP_MARKER_TOPIC);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn failed_recovery_transaction_writes_no_marker() {
        // The marker and the probing event commit together: a probe
        // whose event insert fails must not leave a lone marker that
        // claims the outage ended.
        let log = log_with(FAST);
        break_writes(&log);
        assert_eq!(publish(&log, 1).await, None);
        tokio::time::sleep(FAST.probe_interval * 2).await;
        assert_eq!(publish(&log, 2).await, None);
        assert_eq!(log.count().expect("count"), 0);
        assert_eq!(log.health().gap_markers_total, 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn slow_write_hits_deadline_and_blocks_probes_until_it_drains() {
        let policy = MirrorPolicy {
            write_deadline: Duration::from_millis(100),
            probe_interval: Duration::from_millis(10),
        };
        let log = log_with(policy);
        // Hold the connection mutex from another thread: the
        // mirror's blocking write parks behind it like a hung fsync.
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let (held_tx, held_rx) = std::sync::mpsc::channel::<()>();
        let db = Arc::clone(&log.db);
        let holder = std::thread::spawn(move || {
            db.write(|_| {
                held_tx.send(()).expect("signal");
                release_rx.recv().expect("release");
                Ok::<_, rusqlite::Error>(())
            })
            .expect("hold");
        });
        held_rx.recv().expect("holder took the lock");

        let started = Instant::now();
        assert_eq!(publish(&log, 1).await, None, "deadline → unrecorded");
        assert!(started.elapsed() < Duration::from_secs(5));
        let h = log.health();
        assert!(h.degraded);
        assert!(
            h.last_error
                .as_deref()
                .is_some_and(|e| e.contains("deadline"))
        );

        // Probe due, but the abandoned write is still in flight: skip
        // without touching the disk (no extra blocking thread).
        tokio::time::sleep(policy.probe_interval * 3).await;
        assert_eq!(publish(&log, 2).await, None);
        assert_eq!(
            log.mirror.in_flight.load(Ordering::Acquire),
            1,
            "a skipped probe must not start another blocking write",
        );
        assert_eq!(log.health().unrecorded_pending, 2);

        release_tx.send(()).expect("release");
        holder.join().expect("holder");
        // The abandoned write commits late; wait for it to drain.
        let wait = Instant::now();
        while log.mirror.in_flight.load(Ordering::Acquire) != 0 {
            assert!(
                wait.elapsed() < Duration::from_secs(10),
                "write never drained"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        tokio::time::sleep(policy.probe_interval * 2).await;
        let id = publish(&log, 3).await.expect("probe succeeds");

        // Late row (received 1) < marker < probing event: history
        // order still matches delivery order.
        let rows = all_rows(&log);
        let topics: Vec<&str> = rows.iter().map(|r| r.topic.as_str()).collect();
        assert_eq!(topics, ["switch", GAP_MARKER_TOPIC, "switch"]);
        assert_eq!(rows[0].received_ms, 1);
        assert_eq!(rows[2].id, id);
        assert!(!log.health().degraded);
    }
}
