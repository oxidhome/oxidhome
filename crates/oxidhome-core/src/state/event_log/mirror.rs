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
//!   first post-recovery row. [`Mirrored::gap_markers`] hands it back
//!   so the caller fans it out live just before the probing event.
//!   Markers bypass subscription and history selector filters.
//!
//! A write that timed out may still commit later. Such a row has an
//! id below every later row, so history order still matches delivery
//! order, but the marker's `unrecorded` count is then an upper bound
//! and a consumer that replays history after seeing that event live
//! (without an id) sees it twice. A timed-out *probe* that commits
//! late leaves its marker in history (and fans it out with the next
//! publish) while the outage stays open, so the next marker's count
//! overlaps it.
//!
//! Callers serialize [`EventLog::mirror`] calls (the host holds the
//! bus's `publish_sequence` gate around it). A publish future dropped
//! mid-await (plugin trap, watchdog kill) releases the gate while its
//! write still runs, so:
//!
//! - the blocking write settles the health state itself when it
//!   finishes, and the outcome still counts;
//! - no write starts while an earlier one is in flight — the publish
//!   is delivered unrecorded instead (entering degraded mode if
//!   needed), so writes can't pile up behind a hung connection or
//!   commit out of order;
//! - events skipped while a recovery probe's write runs aren't in its
//!   marker and stay owed to the next one.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
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

/// Whether `event` is a host-written gap marker (origin
/// [`GAP_MARKER_ORIGIN`], topic [`GAP_MARKER_TOPIC`]).
#[must_use]
pub fn is_gap_marker(event: &Event) -> bool {
    event.origin_plugin_id == GAP_MARKER_ORIGIN
        && matches!(&event.payload, EventPayload::Custom(c) if c.topic == GAP_MARKER_TOPIC)
}

const ORPHANED_WRITE: &str =
    "an earlier event-log write is still running (its publish timed out or was cancelled)";

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
    /// `unrecorded` when the current recovery probe was planned —
    /// what its marker covers. Events skipped while that probe's
    /// write runs (possible after a cancelled publish released the
    /// gate) are counted past it and survive the recovery.
    probe_covers: Option<u64>,
    /// Receive-time bounds of the events counted past
    /// `probe_covers`.
    after_probe_ms: Option<(i64, i64)>,
}

impl Outage {
    fn new(received_ms: i64, reason: String, next_probe: Instant) -> Self {
        Self {
            since_ms: now_unix_ms(),
            first_received_ms: received_ms,
            last_received_ms: received_ms,
            unrecorded: 1,
            last_error: reason,
            next_probe,
            probe_covers: None,
            after_probe_ms: None,
        }
    }

    /// Count one more unrecorded event. Bounds are min / max, not
    /// first / last seen: an orphaned write can settle after events
    /// received later.
    fn count(&mut self, received_ms: i64) {
        if self.probe_covers.is_some() {
            self.after_probe_ms = Some(widen(self.after_probe_ms, received_ms));
        }
        self.unrecorded += 1;
        let (first, last) = widen(
            Some((self.first_received_ms, self.last_received_ms)),
            received_ms,
        );
        self.first_received_ms = first;
        self.last_received_ms = last;
    }

    fn marker(&self) -> GapMarker {
        GapMarker {
            unrecorded: self.unrecorded,
            first_received_ms: self.first_received_ms,
            last_received_ms: self.last_received_ms,
            last_error: self.last_error.clone(),
        }
    }
}

fn widen(bounds: Option<(i64, i64)>, t: i64) -> (i64, i64) {
    bounds.map_or((t, t), |(lo, hi)| (lo.min(t), hi.max(t)))
}

#[derive(Debug, Default)]
struct MirrorState {
    outage: Option<Outage>,
    /// Gap markers recovery writes committed that no publish has
    /// fanned out yet — normally just the current one, but a cancelled
    /// publish leaves its marker here for the next mirror call, so
    /// live consumers still see it before any later row id.
    undelivered_markers: Vec<Event>,
    unrecorded_total: u64,
    gap_markers_total: u64,
    last_recovered_ms: Option<i64>,
}

/// Shared by every clone of an [`EventLog`].
#[derive(Debug)]
pub(super) struct MirrorShared {
    policy: MirrorPolicy,
    state: Mutex<MirrorState>,
    /// Blocking writes started but not finished. Non-zero at `plan`
    /// time only when a write was orphaned (it outlived its deadline,
    /// or its publish future was dropped); no write starts until it
    /// drains, so a hung disk can't pile up blocking threads behind
    /// the connection mutex.
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

/// Result of [`EventLog::mirror`].
#[derive(Debug, Default)]
pub(crate) struct Mirrored {
    /// Row id of the published event; `None` = delivered unrecorded.
    pub(crate) row_id: Option<u64>,
    /// Gap markers committed by this publish's recovery write — or
    /// by an earlier one whose publish was cancelled — in row-id
    /// order, each with its `row_id` set. The caller fans them out
    /// before the event so a live cursor can't step over them.
    pub(crate) gap_markers: Vec<Event>,
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
    /// Never fails: write errors move the mirror into degraded mode
    /// instead (module docs). See [`Mirrored`] for what the caller
    /// fans out.
    pub(crate) async fn mirror(
        &self,
        received_ms: i64,
        event: Event,
        instance_id: String,
        plugin_id: String,
        payload_blob: Vec<u8>,
    ) -> Mirrored {
        let gap = match self.plan(received_ms) {
            Plan::Skip => return self.unrecorded_outcome(),
            Plan::Write(gap) => gap,
        };
        let probing = gap.is_some();
        // Exactly one side settles the mirror state for this write:
        // the blocking task when the write finishes (so a publish
        // future dropped mid-await still records the outcome), or
        // this task when the deadline fires first.
        let settled = Arc::new(AtomicBool::new(false));
        let this = self.clone();
        let settled_by_writer = Arc::clone(&settled);
        self.mirror.in_flight.fetch_add(1, Ordering::AcqRel);
        let guard = InFlight(Arc::clone(&self.mirror.in_flight));
        let mut write = tokio::task::spawn_blocking(move || {
            let _guard = guard;
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                this.write_with_gap(
                    received_ms,
                    &event,
                    &instance_id,
                    &plugin_id,
                    &payload_blob,
                    gap.as_ref(),
                )
            }));
            let result = match result {
                Ok(Ok(written)) => Ok(written),
                Ok(Err(e)) => Err(format!("write failed: {e}")),
                Err(_) => Err("blocking write panicked".to_owned()),
            };
            if !settled_by_writer.swap(true, Ordering::AcqRel) {
                this.settle(
                    received_ms,
                    probing,
                    result
                        .as_ref()
                        .map(|(id, marker)| (*id, marker.clone()))
                        .map_err(Clone::clone),
                );
            } else if let Ok((_, Some(marker))) = &result {
                // A recovery write that committed after its deadline:
                // health already counted it as failed and the outage
                // stays open, but the marker row exists and live
                // consumers must still see it before later row ids.
                this.park_late_marker(marker.clone());
            }
            result
        });
        let deadline = self.mirror.policy.write_deadline;
        let joined = if let Ok(joined) = tokio::time::timeout(deadline, &mut write).await {
            joined
        } else {
            if !settled.swap(true, Ordering::AcqRel) {
                self.settle(
                    received_ms,
                    probing,
                    Err(format!(
                        "write exceeded the {}ms deadline (it may still commit)",
                        deadline.as_millis(),
                    )),
                );
                return self.unrecorded_outcome();
            }
            // The writer settled between the deadline firing and the
            // swap; its result is ready.
            write.await
        };
        match joined {
            Ok(Ok((id, _))) => Mirrored {
                row_id: Some(id),
                gap_markers: self.take_undelivered_markers(),
            },
            Ok(Err(_)) => self.unrecorded_outcome(),
            Err(join) => {
                // Only reachable if the runtime cancelled the task
                // before it ran (shutdown).
                if !settled.swap(true, Ordering::AcqRel) {
                    self.settle(
                        received_ms,
                        probing,
                        Err(format!("blocking write task failed: {join}")),
                    );
                }
                self.unrecorded_outcome()
            }
        }
    }

    /// The event goes out without a row id, preceded by any marker a
    /// cancelled publish left undelivered.
    fn unrecorded_outcome(&self) -> Mirrored {
        Mirrored {
            row_id: None,
            gap_markers: self.take_undelivered_markers(),
        }
    }

    fn park_late_marker(&self, marker: Event) {
        let marker_row_id = marker.row_id;
        {
            let mut st = self.mirror.lock();
            st.gap_markers_total += 1;
            st.undelivered_markers.push(marker);
        }
        tracing::warn!(
            target: "event_log.mirror",
            marker_row_id,
            "event log: a timed-out recovery write committed late; its gap marker is in history",
        );
    }

    fn take_undelivered_markers(&self) -> Vec<Event> {
        std::mem::take(&mut self.mirror.lock().undelivered_markers)
    }

    fn settle(
        &self,
        received_ms: i64,
        probing: bool,
        result: Result<(u64, Option<Event>), String>,
    ) {
        match result {
            Ok((id, marker)) if probing => self.note_recovered(id, marker),
            Ok(_) => {}
            Err(reason) => self.note_unrecorded(received_ms, &reason, probing),
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
        // A write still in flight here was orphaned: its publish
        // timed out or was cancelled and released the sequence gate.
        // Writing behind it would queue another blocking thread on
        // the connection mutex, so deliver unrecorded instead.
        let busy = self.mirror.in_flight.load(Ordering::Acquire) > 0;
        let mut st = self.mirror.lock();
        match st.outage.as_mut() {
            None if !busy => return Plan::Write(None),
            Some(outage) if !busy && Instant::now() >= outage.next_probe => {
                outage.probe_covers = Some(outage.unrecorded);
                outage.after_probe_ms = None;
                return Plan::Write(Some(outage.marker()));
            }
            Some(outage) => outage.count(received_ms),
            None => {
                st.outage = Some(Outage::new(
                    received_ms,
                    ORPHANED_WRITE.to_owned(),
                    Instant::now(),
                ));
                st.unrecorded_total += 1;
                drop(st);
                // Logged after the health lock is released (as are all
                // mirror diagnostics), so a slow log sink can't stall
                // `health()` or other publishers on it.
                tracing::error!(
                    target: "event_log.mirror",
                    error = ORPHANED_WRITE,
                    "event log degraded: live delivery continues without durable row ids \
                     and history will carry a gap marker once writes recover",
                );
                return Plan::Skip;
            }
        }
        st.unrecorded_total += 1;
        Plan::Skip
    }

    /// Test hook: enter degraded mode as if a mirror write had
    /// failed, so API tests can observe the degraded signal.
    #[cfg(test)]
    pub(crate) fn degrade_for_test(&self, reason: &str) {
        self.note_unrecorded(0, reason, false);
    }

    fn note_unrecorded(&self, received_ms: i64, reason: &str, probing: bool) {
        let next_probe = Instant::now() + self.mirror.policy.probe_interval;
        let mut st = self.mirror.lock();
        st.unrecorded_total += 1;
        let still_degraded = if let Some(outage) = st.outage.as_mut() {
            outage.count(received_ms);
            outage.probe_covers = None;
            outage.next_probe = next_probe;
            reason.clone_into(&mut outage.last_error);
            Some(outage.unrecorded)
        } else {
            st.outage = Some(Outage::new(received_ms, reason.to_owned(), next_probe));
            None
        };
        drop(st);
        if let Some(unrecorded) = still_degraded {
            tracing::warn!(
                target: "event_log.mirror",
                probing,
                unrecorded,
                error = %reason,
                "event log still degraded: write failed; live delivery continues without durable row ids",
            );
        } else {
            tracing::error!(
                target: "event_log.mirror",
                error = %reason,
                probe_interval_ms = u64::try_from(self.mirror.policy.probe_interval.as_millis())
                    .unwrap_or(u64::MAX),
                "event log degraded: durable write failed; live delivery continues without durable row ids \
                 and history will carry a gap marker once writes recover",
            );
        }
    }

    fn note_recovered(&self, first_row_id: u64, marker: Option<Event>) {
        let mut st = self.mirror.lock();
        // Parked until a publish fans it out (normally the one whose
        // write just committed it, right after this returns).
        st.undelivered_markers.extend(marker);
        let Some(outage) = st.outage.take() else {
            return;
        };
        st.gap_markers_total += 1;
        st.last_recovered_ms = Some(now_unix_ms());
        let covered = outage.probe_covers.unwrap_or(outage.unrecorded);
        let remainder = outage.unrecorded.saturating_sub(covered);
        if remainder > 0 {
            // Skipped while the probe's write ran: not covered by its
            // marker, so keep them for the next one (due right away).
            st.outage = Some(Outage {
                since_ms: now_unix_ms(),
                first_received_ms: outage.after_probe_ms.map_or(0, |b| b.0),
                last_received_ms: outage.after_probe_ms.map_or(0, |b| b.1),
                unrecorded: remainder,
                last_error: "events skipped while the recovery write was running".to_owned(),
                next_probe: Instant::now(),
                probe_covers: None,
                after_probe_ms: None,
            });
        }
        drop(st);
        tracing::warn!(
            target: "event_log.mirror",
            unrecorded = covered,
            degraded_since_ms = outage.since_ms,
            first_row_id,
            "event log recovered: gap marker written to history",
        );
    }

    /// One transaction: optional gap marker, then the event. Returns
    /// the event's row id and the marker with its row id stamped.
    fn write_with_gap(
        &self,
        received_ms: i64,
        event: &Event,
        instance_id: &str,
        plugin_id: &str,
        payload_blob: &[u8],
        gap: Option<&GapMarker>,
    ) -> Result<(u64, Option<Event>), EventLogError> {
        let marker = gap.map(|g| gap_marker_event(g, received_ms)).transpose()?;
        self.db
            .write(|conn| -> Result<(u64, Option<Event>), EventLogError> {
                let tx = conn.transaction()?;
                let gap_marker = match marker {
                    Some((mut marker, blob)) => {
                        let id = insert_row(
                            &tx,
                            received_ms,
                            &marker,
                            GAP_MARKER_ORIGIN,
                            GAP_MARKER_ORIGIN,
                            &blob,
                        )?;
                        marker.row_id = Some(id);
                        Some(marker)
                    }
                    None => None,
                };
                let id = insert_row(
                    &tx,
                    received_ms,
                    event,
                    instance_id,
                    plugin_id,
                    payload_blob,
                )?;
                tx.commit()?;
                Ok((id, gap_marker))
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
    use super::super::{EventOrder, EventQuery, topic_of};
    use super::*;
    use crate::host_impl::plugin::oxidhome::plugin::events::StateChange;
    use crate::host_impl::plugin::oxidhome::plugin::types::{KeyValue, Value as WitValue};
    use crate::state::db::Db;

    const FAST: MirrorPolicy = MirrorPolicy {
        write_deadline: Duration::from_secs(5),
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

    async fn publish_full(log: &EventLog, received_ms: i64) -> Mirrored {
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

    async fn publish(log: &EventLog, received_ms: i64) -> Option<u64> {
        let out = publish_full(log, received_ms).await;
        assert_eq!(out.gap_markers.len(), 0, "unexpected gap marker");
        out.row_id
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
        let mut recovered = publish_full(&log, 50).await;
        let after = recovered.row_id.expect("recovered write");
        let live_marker = recovered
            .gap_markers
            .pop()
            .expect("marker handed back for fan-out");
        assert_eq!(topic_of(&live_marker), GAP_MARKER_TOPIC);
        assert_eq!(live_marker.origin_plugin_id, GAP_MARKER_ORIGIN);

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
        assert_eq!(live_marker.row_id, Some(marker.id));
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

        // Selector filters don't hide the marker; bounds still apply.
        let filtered = log
            .query(
                &EventQuery {
                    device_id: Some("some-other-device".into()),
                    plugin_id: Some("example.other".into()),
                    topic: Some(("switch".into(), super::super::TopicMatch::Exact)),
                    order: EventOrder::Asc,
                    ..EventQuery::default()
                },
                10,
            )
            .expect("filtered query");
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].id, marker.id);
        let bounded = log
            .query(
                &EventQuery {
                    device_id: Some("some-other-device".into()),
                    after_id: Some(marker.id),
                    ..EventQuery::default()
                },
                10,
            )
            .expect("bounded query");
        assert_eq!(bounded.len(), 0);
    }

    #[test]
    fn only_host_origin_custom_events_are_gap_markers() {
        let (marker, _) = gap_marker_event(
            &GapMarker {
                unrecorded: 1,
                first_received_ms: 1,
                last_received_ms: 1,
                last_error: String::new(),
            },
            1,
        )
        .expect("marker");
        assert!(is_gap_marker(&marker));
        let mut forged = marker.clone();
        forged.origin_plugin_id = "example.alpha".into();
        assert!(!is_gap_marker(&forged));
        assert!(!is_gap_marker(&switch_event(true)));
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
            write_deadline: Duration::from_secs(2),
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
        let id = publish_full(&log, 3).await.row_id.expect("probe succeeds");

        // Late row (received 1) < marker < probing event: history
        // order still matches delivery order.
        let rows = all_rows(&log);
        let topics: Vec<&str> = rows.iter().map(|r| r.topic.as_str()).collect();
        assert_eq!(topics, ["switch", GAP_MARKER_TOPIC, "switch"]);
        assert_eq!(rows[0].received_ms, 1);
        assert_eq!(rows[2].id, id);
        assert!(!log.health().degraded);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dropped_publish_future_still_settles_the_outcome() {
        // A plugin trap / watchdog kill drops the publish future
        // mid-await. The blocking write still finishes, and its
        // failure must still put the mirror into degraded mode.
        let log = log_with(MirrorPolicy {
            write_deadline: Duration::from_secs(30),
            probe_interval: Duration::from_secs(30),
        });
        break_writes(&log);
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

        let dropped = tokio::time::timeout(Duration::from_millis(20), publish(&log, 1)).await;
        assert!(
            dropped.is_err(),
            "publish future must be cancelled while parked"
        );
        assert!(!log.health().degraded, "outcome not known yet");

        release_tx.send(()).expect("release");
        holder.join().expect("holder");
        let wait = Instant::now();
        while log.mirror.in_flight.load(Ordering::Acquire) != 0 {
            assert!(
                wait.elapsed() < Duration::from_secs(10),
                "write never drained"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let h = log.health();
        assert!(h.degraded, "{h:?}");
        assert_eq!(h.unrecorded_total, 1);
    }

    /// Holds the connection mutex on another thread until the returned
    /// sender is used (or dropped) — a stand-in for a hung disk.
    fn hold_connection(
        log: &EventLog,
    ) -> (std::sync::mpsc::Sender<()>, std::thread::JoinHandle<()>) {
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let (held_tx, held_rx) = std::sync::mpsc::channel::<()>();
        let db = Arc::clone(&log.db);
        let holder = std::thread::spawn(move || {
            db.write(|_| {
                held_tx.send(()).expect("signal");
                let _ = release_rx.recv();
                Ok::<_, rusqlite::Error>(())
            })
            .expect("hold");
        });
        held_rx.recv().expect("holder took the lock");
        (release_tx, holder)
    }

    async fn drain(log: &EventLog) {
        let wait = Instant::now();
        while log.mirror.in_flight.load(Ordering::Acquire) != 0 {
            assert!(
                wait.elapsed() < Duration::from_secs(10),
                "write never drained"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn orphaned_write_makes_later_publishes_skip_the_disk() {
        // A cancelled publish releases the sequence gate while its
        // write still runs. The next publish must not queue a second
        // blocking write behind it: it goes out unrecorded and the
        // mirror reports degraded until a probe covers the gap.
        let log = log_with(MirrorPolicy {
            write_deadline: Duration::from_secs(30),
            probe_interval: Duration::from_millis(10),
        });
        let (release, holder) = hold_connection(&log);
        let cancelled = tokio::time::timeout(Duration::from_millis(20), publish(&log, 1)).await;
        assert!(cancelled.is_err());

        assert_eq!(publish(&log, 2).await, None);
        assert_eq!(log.mirror.in_flight.load(Ordering::Acquire), 1);
        let h = log.health();
        assert!(h.degraded);
        assert!(
            h.last_error
                .as_deref()
                .is_some_and(|e| e.contains("still running"))
        );

        release.send(()).expect("release");
        holder.join().expect("holder");
        drain(&log).await;
        tokio::time::sleep(Duration::from_millis(30)).await;
        let recovered = publish_full(&log, 3).await;
        assert!(recovered.row_id.is_some());
        assert_eq!(recovered.gap_markers.len(), 1);
        let topics: Vec<String> = all_rows(&log).into_iter().map(|r| r.topic).collect();
        // The orphaned event committed late, below the marker.
        assert_eq!(topics, ["switch", GAP_MARKER_TOPIC, "switch"]);
        assert!(!log.health().degraded);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn events_skipped_during_a_cancelled_probe_survive_its_recovery() {
        let log = log_with(MirrorPolicy {
            write_deadline: Duration::from_secs(30),
            probe_interval: Duration::from_millis(10),
        });
        break_writes(&log);
        assert_eq!(publish(&log, 1).await, None);
        fix_writes(&log);
        tokio::time::sleep(Duration::from_millis(30)).await;

        // Probe parks on the connection, then its publish is dropped.
        let (release, holder) = hold_connection(&log);
        let cancelled =
            tokio::time::timeout(Duration::from_millis(20), publish_full(&log, 2)).await;
        assert!(cancelled.is_err());
        // Skipped while the probe's write runs: not in its marker.
        assert_eq!(publish(&log, 3).await, None);

        release.send(()).expect("release");
        holder.join().expect("holder");
        drain(&log).await;
        let h = log.health();
        assert_eq!(h.gap_markers_total, 1, "{h:?}");
        assert!(
            h.degraded,
            "the event skipped during the probe is still owed a marker"
        );
        assert_eq!(h.unrecorded_pending, 1);

        let mut recovered = publish_full(&log, 4).await;
        // The cancelled probe's marker was never fanned out; it rides
        // ahead of the new one, in row-id order.
        assert_eq!(recovered.gap_markers.len(), 2);
        assert!(recovered.gap_markers[0].row_id < recovered.gap_markers[1].row_id);
        assert!(recovered.gap_markers[1].row_id < recovered.row_id);
        let EventPayload::Custom(c) = recovered.gap_markers.pop().expect("second marker").payload
        else {
            panic!("marker payload must be custom");
        };
        let gap: GapMarker = serde_json::from_str(&c.payload).expect("gap json");
        assert_eq!(gap.unrecorded, 1);
        assert_eq!(gap.first_received_ms, 3);
        assert!(!log.health().degraded);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn gap_bounds_hold_when_an_orphaned_write_fails_late() {
        // A (received 100) is cancelled while its write is parked; B
        // (received 200) is skipped; then A's write fails. The marker
        // must still span 100..=200.
        let log = log_with(MirrorPolicy {
            write_deadline: Duration::from_secs(30),
            probe_interval: Duration::from_millis(10),
        });
        break_writes(&log);
        let (release, holder) = hold_connection(&log);
        let cancelled = tokio::time::timeout(Duration::from_millis(20), publish(&log, 100)).await;
        assert!(cancelled.is_err());
        assert_eq!(publish(&log, 200).await, None);
        release.send(()).expect("release");
        holder.join().expect("holder");
        drain(&log).await;
        assert_eq!(log.health().unrecorded_pending, 2);

        fix_writes(&log);
        tokio::time::sleep(Duration::from_millis(30)).await;
        let mut recovered = publish_full(&log, 300).await;
        let EventPayload::Custom(c) = recovered.gap_markers.pop().expect("marker").payload else {
            panic!("marker payload must be custom");
        };
        let gap: GapMarker = serde_json::from_str(&c.payload).expect("gap json");
        assert_eq!(
            (gap.unrecorded, gap.first_received_ms, gap.last_received_ms),
            (2, 100, 200),
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn late_committed_probe_marker_is_still_delivered() {
        let log = log_with(MirrorPolicy {
            write_deadline: Duration::from_secs(2),
            probe_interval: Duration::from_millis(10),
        });
        break_writes(&log);
        assert_eq!(publish(&log, 1).await, None);
        fix_writes(&log);
        tokio::time::sleep(Duration::from_millis(30)).await;

        // The probe's write parks past its deadline, then commits.
        let (release, holder) = hold_connection(&log);
        assert_eq!(publish(&log, 2).await, None, "probe timed out");
        release.send(()).expect("release");
        holder.join().expect("holder");
        drain(&log).await;
        let h = log.health();
        assert!(h.degraded, "the timed-out probe counted as a failure");
        assert_eq!(h.gap_markers_total, 1, "the late marker is in history");

        tokio::time::sleep(Duration::from_millis(30)).await;
        let recovered = publish_full(&log, 3).await;
        let ids: Vec<Option<u64>> = recovered.gap_markers.iter().map(|m| m.row_id).collect();
        assert_eq!(ids.len(), 2, "late marker rides ahead of the new one");
        assert!(ids[0] < ids[1] && ids[1] < recovered.row_id);
        assert!(!log.health().degraded);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn probe_remainder_bounds_ignore_earlier_failed_probes() {
        let log = log_with(MirrorPolicy {
            write_deadline: Duration::from_secs(30),
            probe_interval: Duration::from_millis(10),
        });
        break_writes(&log);
        assert_eq!(publish(&log, 10).await, None);
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(publish(&log, 20).await, None, "failed probe");
        fix_writes(&log);
        tokio::time::sleep(Duration::from_millis(30)).await;

        let (release, holder) = hold_connection(&log);
        let cancelled =
            tokio::time::timeout(Duration::from_millis(20), publish_full(&log, 30)).await;
        assert!(cancelled.is_err());
        assert_eq!(publish(&log, 40).await, None, "skipped during the probe");
        release.send(()).expect("release");
        holder.join().expect("holder");
        drain(&log).await;

        let mut recovered = publish_full(&log, 50).await;
        let EventPayload::Custom(c) = recovered.gap_markers.pop().expect("marker").payload else {
            panic!("marker payload must be custom");
        };
        let gap: GapMarker = serde_json::from_str(&c.payload).expect("gap json");
        assert_eq!(
            (gap.unrecorded, gap.first_received_ms, gap.last_received_ms),
            (1, 40, 40),
        );
    }
}
