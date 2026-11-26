//! H4: history-to-live handoff for external event streams.
//!
//! [`EventTail`] is the transport-agnostic core of the Connect
//! `TailEvents` stream and the JSON `GET /api/v1/events/tail`
//! WebSocket. It runs in one of two modes:
//!
//! - **Live** (no cursor): events published after the subscription
//!   opened, in publish order. Queue overflow drops events for this
//!   subscriber; the next item is a [`TailItem::Lagged`] notice with
//!   the count and the last row id delivered, which the client passes
//!   as `after_id` on a new stream to recover the dropped events that
//!   are in history.
//! - **Cursor** (`after_id`): every history row with `id > after_id`
//!   exactly once, in id order, followed by live delivery.
//!
//! Cursor-mode handoff. [`EventBus::subscribe_at_head`] subscribes
//! and snapshots the bus's fanned-out row-id watermark `W` under the
//! publish gate, so recorded events split cleanly: rows `<= W` were
//! fanned out before the subscription existed and are read from
//! history; everything fanned out later is in the queue. The stream
//! replays `(after_id, W]` page by page, then drains the queue:
//!
//! - a row id `<= cursor` is a duplicate and is skipped;
//! - `cursor + 1` is delivered and advances the cursor;
//! - a larger id means rows are missing between the cursor and it
//!   (the queue overflowed, or a row committed without being fanned
//!   out — a cancelled publish, or a write that timed out and
//!   committed late), so the stream reads `(cursor, id)` from
//!   history first and then delivers the held event;
//! - an event without a row id (H3 degraded mirror, host simulators)
//!   leaves the cursor alone. Each queued message carries the bus
//!   watermark at its fan-out (`rows_through`); if that is above the
//!   cursor, rows fanned out ahead of the event were dropped, and the
//!   stream replays them before delivering it. Delivery order
//!   therefore matches publish order, and an H3 gap marker (a row
//!   like any other) still arrives before the recovery event.
//! - when the queue is empty and the bus watermark is above the
//!   cursor, rows dropped at the end of a burst are replayed without
//!   waiting for another publish. A row committed without any fan-out
//!   (cancelled publish) is picked up when the next row-id event
//!   arrives.
//!
//! Row ids are dense and retention only deletes an id prefix (see
//! `event_log::cursor`), so a replay range that comes back short
//! means retention pruned rows the stream still owed: the stream
//! emits [`TailItem::CursorExpired`] and ends rather than skip them.
//! A row that commits late after its event went out live without an
//! id is delivered again from history with its id (just before the
//! next row-id event, e.g. the recovery gap marker); that is the one
//! duplicate the cursor protocol allows, and it can only follow an H3
//! write timeout.
//!
//! History reads run on the blocking pool with a bounded number in
//! flight and a deadline, so a hung disk ends the stream with
//! [`TailError::Unavailable`] instead of parking threads.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Semaphore;
use tokio::sync::mpsc::error::TryRecvError;

use super::event_log::{CursorExpired, EventLog, EventLogError, HistoricalEvent};
use super::events::{EventBus, EventSubscription, RowWatermark, SubscriberMessage};
use crate::host_impl::plugin::oxidhome::plugin::events::{Event, EventFilter};

/// Rows per history read while replaying. Small, because a stalled
/// client keeps one decoded page buffered (custom payloads can be
/// large).
const REPLAY_PAGE: usize = 32;

/// History reads (across every tail) allowed in flight at once.
const MAX_CONCURRENT_READS: usize = 8;

/// Deadline for one history read, including the wait for a slot.
const READ_TIMEOUT: Duration = Duration::from_secs(10);

static READ_SLOTS: Semaphore = Semaphore::const_new(MAX_CONCURRENT_READS);

/// One item a tail stream hands its transport.
#[derive(Debug, Clone)]
pub enum TailItem {
    /// A bus event, live or replayed from history.
    Event(Arc<Event>),
    /// The subscriber queue dropped `skipped` events. `resume_after_id`
    /// is the stream's resume cursor when the notice is emitted: the
    /// highest row id delivered so far (in cursor mode possibly
    /// including rows already re-read from history, or the opening
    /// cursor if nothing was delivered yet).
    /// Cursor-mode streams re-read the dropped recorded events from
    /// history themselves, so for them the notice is informational.
    Lagged {
        skipped: u64,
        resume_after_id: Option<u64>,
    },
    /// The cursor can't be resumed without a gap. Always the last
    /// item.
    CursorExpired(CursorExpired),
}

/// Why a tail stream stopped early.
#[derive(Debug, thiserror::Error)]
pub enum TailError {
    #[error("event history read failed: {0}")]
    Storage(#[from] EventLogError),
    #[error("event history unavailable: {0}")]
    Unavailable(&'static str),
}

#[derive(Debug, Clone, Copy)]
enum Mode {
    Live { last_row_id: Option<u64> },
    Cursor { cursor: u64 },
}

/// A live (or cursor-resumed) event stream. See the module docs.
pub struct EventTail {
    subscription: EventSubscription,
    /// Not the bus itself: holding the bus would keep this
    /// subscription's sender alive and `recv()` would never see the
    /// engine shut down.
    watermark: RowWatermark,
    log: Arc<EventLog>,
    mode: Mode,
    /// Cursor mode: replay history through this row id before taking
    /// the next queued event.
    replay_through: u64,
    /// Cursor mode: a live event waiting for the replay up to it.
    held: Option<Arc<Event>>,
    pending: VecDeque<TailItem>,
    finished: bool,
    /// The cursor an accepted `after_id` resolved to, fixed at open.
    accepted_cursor: Option<u64>,
}

impl EventTail {
    /// Open a stream over every bus event. `after_id = None` is live
    /// mode; `Some(id)` replays history rows with `row id > id` first
    /// (`Some(0)`: from the oldest retained row). The subscription
    /// exists when this returns, so a caller can open the stream
    /// before acknowledging the client.
    ///
    /// # Errors
    ///
    /// [`TailError`] if resolving the cursor against history fails.
    /// An expired cursor is not an error: the stream yields a single
    /// [`TailItem::CursorExpired`].
    pub async fn open(
        bus: &EventBus,
        log: Arc<EventLog>,
        after_id: Option<u64>,
        label: &str,
    ) -> Result<Self, TailError> {
        let filter = EventFilter {
            device: None,
            topic: None,
        };
        // Only a cursor needs the watermark, and with it the publish
        // gate; a live-only open never waits behind a disk write.
        let (subscription, fanned_out) = if after_id.is_some() {
            bus.subscribe_at_head(filter, label).await
        } else {
            (bus.subscribe_labeled(filter, label), 0)
        };
        let mut tail = Self {
            subscription,
            watermark: bus.row_watermark(),
            log,
            mode: Mode::Live { last_row_id: None },
            replay_through: 0,
            held: None,
            pending: VecDeque::new(),
            finished: false,
            accepted_cursor: None,
        };
        if let Some(after_id) = after_id {
            match tail.read(move |log| log.resolve_cursor(after_id)).await? {
                Ok(cursor) => {
                    tail.mode = Mode::Cursor { cursor };
                    tail.replay_through = fanned_out;
                    tail.accepted_cursor = Some(cursor);
                }
                Err(expired) => tail.expire(expired),
            }
        }
        Ok(tail)
    }

    /// The cursor an accepted `after_id` resolved to at open (`0`
    /// resolves to just below the oldest retained row); it does not
    /// move as the stream advances. `None` for live-only streams and
    /// cursors already expired at open. The
    /// transports echo it as the `oxidhome-resume-after-id` response
    /// header, so a client can tell a resumed stream from a cursor
    /// that expired at open.
    #[must_use]
    pub fn resume_after_id(&self) -> Option<u64> {
        self.accepted_cursor
    }

    /// Next item, or `Ok(None)` once the stream is over (bus shut
    /// down, or after [`TailItem::CursorExpired`]).
    ///
    /// Cancel-safe: state changes only after each await completes, so
    /// dropping the future (e.g. losing a `select!`) loses nothing.
    ///
    /// # Errors
    ///
    /// [`TailError`] if a history read fails. The stream is over
    /// after an error.
    pub async fn next(&mut self) -> Result<Option<TailItem>, TailError> {
        loop {
            if let Some(item) = self.pending.pop_front() {
                return Ok(Some(item));
            }
            if self.finished {
                return Ok(None);
            }
            if let Mode::Cursor { cursor } = self.mode {
                if cursor < self.replay_through {
                    if let Err(err) = self.replay_page(cursor).await {
                        self.finished = true;
                        return Err(err);
                    }
                    continue;
                }
                if let Some(event) = self.held.take() {
                    self.deliver(event);
                    continue;
                }
            }
            // Sample the watermark BEFORE looking at the queue. If the
            // queue is then empty, every event fanned out before the
            // sample was consumed or dropped, so rows up to it can be
            // replayed without overtaking anything still queued. (A
            // sample taken after the empty check could include a row
            // fanned out behind an event that was enqueued in between.)
            // This recovers rows dropped at the end of a burst with no
            // publish after it.
            let fanned_out = self.watermark.get();
            let message = match self.subscription.receiver.try_recv() {
                Ok(message) => Some(message),
                // The bus is gone, but recorded rows it fanned out may
                // have been dropped from the queue: replay them before
                // ending.
                Err(TryRecvError::Disconnected) => {
                    // Re-read: the last publisher raises the watermark
                    // before it releases the bus, possibly after the
                    // sample above.
                    let fanned_out = self.watermark.get();
                    if let Mode::Cursor { cursor } = self.mode
                        && fanned_out > cursor
                    {
                        self.replay_through = fanned_out;
                        continue;
                    }
                    None
                }
                Err(TryRecvError::Empty) => {
                    if let Mode::Cursor { cursor } = self.mode
                        && fanned_out > cursor
                    {
                        self.replay_through = fanned_out;
                        continue;
                    }
                    // A cursor tail also wakes when the watermark rises
                    // without a message: the row was dropped from the
                    // full queue just before it drained.
                    let watermark = self.watermark.clone();
                    let cursor_wait = async {
                        match self.mode {
                            Mode::Cursor { .. } => watermark.advanced_past(fanned_out).await,
                            Mode::Live { .. } => std::future::pending().await,
                        }
                    };
                    tokio::select! {
                        message = self.subscription.receiver.recv() => match message {
                            Some(message) => Some(message),
                            // Closed while waiting: take the
                            // `Disconnected` path above.
                            None => continue,
                        },
                        () = cursor_wait => continue,
                    }
                }
            };
            match message {
                Some(SubscriberMessage::Event {
                    event,
                    skipped_before,
                    rows_through,
                }) => self.accept(event, skipped_before, rows_through),
                None => self.finished = true,
            }
        }
    }

    /// Replay the next page of `(cursor, replay_through]`.
    async fn replay_page(&mut self, cursor: u64) -> Result<(), TailError> {
        let through = self.replay_through;
        let page = self
            .read(move |log| log.read_dense_range(cursor, through, REPLAY_PAGE))
            .await?;
        let Some(rows) = page else {
            let expired = self.read(move |log| log.cursor_expired(cursor)).await?;
            self.expire(expired);
            return Ok(());
        };
        for row in rows {
            self.deliver(Arc::new(HistoricalEvent::into_event(row)));
        }
        Ok(())
    }

    fn accept(&mut self, event: Arc<Event>, skipped_before: u64, rows_through: u64) {
        if skipped_before > 0 {
            let resume_after_id = match self.mode {
                Mode::Live { last_row_id } => last_row_id,
                Mode::Cursor { cursor } => Some(cursor),
            };
            self.pending.push_back(TailItem::Lagged {
                skipped: skipped_before,
                resume_after_id,
            });
        }
        let Mode::Cursor { cursor } = self.mode else {
            self.deliver(event);
            return;
        };
        // Rows that must reach the client before this event: those
        // below its own row id, or, for an event without one, every
        // row fanned out ahead of it (`rows_through`). Rows beyond the
        // cursor there were dropped from the queue or never fanned
        // out, so read them from history first.
        let before = match event.row_id {
            Some(id) if id <= cursor => return,
            Some(id) => id - 1,
            None => rows_through,
        };
        if before > cursor {
            self.replay_through = before;
            self.held = Some(event);
        } else {
            self.deliver(event);
        }
    }

    /// Queue `event` for delivery and advance the cursor past its row
    /// id.
    fn deliver(&mut self, event: Arc<Event>) {
        if let Some(id) = event.row_id {
            match &mut self.mode {
                Mode::Live { last_row_id } => {
                    *last_row_id = Some(last_row_id.map_or(id, |last| last.max(id)));
                }
                Mode::Cursor { cursor } => *cursor = id,
            }
        }
        self.pending.push_back(TailItem::Event(event));
    }

    fn expire(&mut self, expired: CursorExpired) {
        self.held = None;
        self.pending.push_back(TailItem::CursorExpired(expired));
        self.finished = true;
    }

    /// Run a history read on the blocking pool, bounded in concurrency
    /// and time. A read that outlives its deadline keeps its slot
    /// until it really finishes, so a hung disk can't pile up threads.
    async fn read<R: Send + 'static>(
        &self,
        f: impl FnOnce(&EventLog) -> Result<R, EventLogError> + Send + 'static,
    ) -> Result<R, TailError> {
        let read = async {
            let permit = READ_SLOTS
                .acquire()
                .await
                .map_err(|_| TailError::Unavailable("history reads closed"))?;
            let log = Arc::clone(&self.log);
            tokio::task::spawn_blocking(move || {
                let _permit = permit;
                f(&log)
            })
            .await
            .map_err(|_| TailError::Unavailable("history read panicked"))?
            .map_err(TailError::from)
        };
        tokio::time::timeout(READ_TIMEOUT, read)
            .await
            .map_err(|_| TailError::Unavailable("history read timed out"))?
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use super::*;
    use crate::host_impl::plugin::oxidhome::plugin::events::{CustomEvent, EventPayload};
    use crate::state::db::Db;

    fn event(n: u64) -> Event {
        Event {
            device: None,
            timestamp: n,
            payload: EventPayload::Custom(CustomEvent {
                topic: "test.tail".into(),
                payload: n.to_string(),
            }),
            origin_plugin_id: "example.test".into(),
            origin_instance_id: "inst".into(),
            row_id: None,
        }
    }

    fn setup() -> (Arc<EventBus>, Arc<EventLog>) {
        let log = Arc::new(EventLog::new(Arc::new(Db::open_in_memory().expect("db"))));
        (Arc::new(EventBus::new()), log)
    }

    /// Production publish shape: record + fan out under the publish
    /// gate. `received_ms = n` so tests can trim by it.
    async fn publish_recorded(bus: &EventBus, log: &EventLog, n: u64) -> u64 {
        let gate = bus.publish_sequence();
        let _guard = gate.lock().await;
        #[allow(clippy::cast_possible_wrap)]
        let id = log
            .record(n as i64, &event(n), "inst", "example.test")
            .expect("record");
        bus.publish_with_id(event(n), Some(id));
        id
    }

    async fn next_item(tail: &mut EventTail) -> Option<TailItem> {
        tokio::time::timeout(Duration::from_secs(5), tail.next())
            .await
            .expect("tail item within 5s")
            .expect("tail read")
    }

    async fn next_id(tail: &mut EventTail) -> u64 {
        match next_item(tail).await {
            Some(TailItem::Event(ev)) => ev.row_id.expect("row id"),
            other => panic!("expected a row-id event, got {other:?}"),
        }
    }

    /// Events published while the stream is still replaying its
    /// backlog (several pages) reach the client exactly once and in
    /// order, with no gap at the handoff.
    #[tokio::test(flavor = "multi_thread")]
    async fn handoff_delivers_backlog_and_concurrent_publishes_exactly_once() {
        let (bus, log) = setup();
        for n in 1..=600 {
            publish_recorded(&bus, &log, n).await;
        }
        let mut tail = EventTail::open(&bus, Arc::clone(&log), Some(100), "test")
            .await
            .expect("open");
        // Published after the subscription, before any replay read.
        for n in 601..=610 {
            publish_recorded(&bus, &log, n).await;
        }
        let publisher = {
            let (bus, log) = (Arc::clone(&bus), Arc::clone(&log));
            tokio::spawn(async move {
                for n in 611..=900 {
                    publish_recorded(&bus, &log, n).await;
                    if n % 16 == 0 {
                        tokio::task::yield_now().await;
                    }
                }
            })
        };
        let mut got = Vec::new();
        while got.last() != Some(&900) {
            match next_item(&mut tail).await {
                Some(TailItem::Event(ev)) => got.push(ev.row_id.expect("row id")),
                // A burst can overflow the queue mid-replay; the
                // stream re-reads those rows from history.
                Some(TailItem::Lagged { .. }) => {}
                other => panic!("unexpected {other:?}"),
            }
        }
        publisher.await.expect("publisher");
        assert_eq!(got, (101..=900).collect::<Vec<_>>());
    }

    #[tokio::test]
    async fn live_duplicates_at_or_below_the_cursor_are_skipped() {
        let (bus, log) = setup();
        for n in 1..=3 {
            publish_recorded(&bus, &log, n).await;
        }
        let mut tail = EventTail::open(&bus, Arc::clone(&log), Some(3), "test")
            .await
            .expect("open");
        // A stale re-fan-out of an already-covered row.
        bus.publish_with_id(event(2), Some(2));
        publish_recorded(&bus, &log, 4).await;
        assert_eq!(next_id(&mut tail).await, 4);
    }

    /// H3 events without a row id are delivered in place and don't
    /// move the cursor; the gap marker (a row like any other) and
    /// later rows follow without a spurious replay.
    #[tokio::test]
    async fn row_id_less_events_keep_their_place() {
        let (bus, log) = setup();
        for n in 1..=2 {
            publish_recorded(&bus, &log, n).await;
        }
        let mut tail = EventTail::open(&bus, Arc::clone(&log), Some(0), "test")
            .await
            .expect("open");
        bus.publish(event(100));
        let marker = publish_recorded(&bus, &log, 3).await;
        assert_eq!(next_id(&mut tail).await, 1);
        assert_eq!(next_id(&mut tail).await, 2);
        match next_item(&mut tail).await {
            Some(TailItem::Event(ev)) => {
                assert_eq!(ev.row_id, None);
                assert_eq!(ev.timestamp, 100);
            }
            other => panic!("expected the row-id-less event, got {other:?}"),
        }
        assert_eq!(next_id(&mut tail).await, marker);
    }

    #[tokio::test]
    async fn pruned_cursor_expires_at_open() {
        let (bus, log) = setup();
        for n in 1..=5 {
            publish_recorded(&bus, &log, n).await;
        }
        log.trim_older_than(4).expect("trim");
        let mut tail = EventTail::open(&bus, Arc::clone(&log), Some(1), "test")
            .await
            .expect("open");
        match next_item(&mut tail).await {
            Some(TailItem::CursorExpired(expired)) => assert_eq!(
                expired,
                CursorExpired {
                    after_id: 1,
                    oldest_id: Some(4),
                    head_id: 5,
                }
            ),
            other => panic!("expected cursor_expired, got {other:?}"),
        }
        assert!(next_item(&mut tail).await.is_none());
    }

    #[tokio::test]
    async fn cursor_ahead_of_history_expires() {
        let (bus, log) = setup();
        publish_recorded(&bus, &log, 1).await;
        let mut tail = EventTail::open(&bus, Arc::clone(&log), Some(7), "test")
            .await
            .expect("open");
        assert!(matches!(
            next_item(&mut tail).await,
            Some(TailItem::CursorExpired(CursorExpired {
                after_id: 7,
                head_id: 1,
                ..
            }))
        ));
    }

    /// Retention pruning rows the stream still owes, after the cursor
    /// was accepted, ends the stream with `CursorExpired` instead of
    /// skipping them.
    #[tokio::test]
    async fn rows_pruned_during_replay_expire_the_cursor() {
        let (bus, log) = setup();
        for n in 1..=10 {
            publish_recorded(&bus, &log, n).await;
        }
        let mut tail = EventTail::open(&bus, Arc::clone(&log), Some(2), "test")
            .await
            .expect("open");
        log.trim_older_than(6).expect("trim");
        match next_item(&mut tail).await {
            Some(TailItem::CursorExpired(expired)) => assert_eq!(
                expired,
                CursorExpired {
                    after_id: 2,
                    oldest_id: Some(6),
                    head_id: 10,
                }
            ),
            other => panic!("expected cursor_expired, got {other:?}"),
        }
        assert!(next_item(&mut tail).await.is_none());
    }

    /// Rows dropped at the end of a burst are replayed as soon as the
    /// queue drains, without waiting for another publish.
    #[tokio::test]
    async fn cursor_stream_recovers_a_dropped_burst_tail_without_another_publish() {
        let (bus, log) = setup();
        let mut tail = EventTail::open(&bus, Arc::clone(&log), Some(0), "test")
            .await
            .expect("open");
        for n in 1..=300 {
            publish_recorded(&bus, &log, n).await;
        }
        for want in 1..=300 {
            assert_eq!(next_id(&mut tail).await, want);
        }
    }

    /// An event without a row id that follows dropped rows waits for
    /// them: the lag notice (with its resume point), the dropped rows
    /// from history, then the event.
    #[tokio::test]
    async fn row_id_less_event_after_a_drop_waits_for_the_dropped_rows() {
        let (bus, log) = setup();
        let mut tail = EventTail::open(&bus, Arc::clone(&log), Some(0), "test")
            .await
            .expect("open");
        for n in 1..=300 {
            publish_recorded(&bus, &log, n).await;
        }
        // Leave row 256 queued so the next read doesn't find the
        // queue empty, then publish an event without a row id.
        for want in 1..=255 {
            assert_eq!(next_id(&mut tail).await, want);
        }
        bus.publish(event(1000));
        assert_eq!(next_id(&mut tail).await, 256);
        match next_item(&mut tail).await {
            Some(TailItem::Lagged {
                skipped,
                resume_after_id,
            }) => {
                assert_eq!(skipped, 44);
                assert_eq!(resume_after_id, Some(256));
            }
            other => panic!("expected lagged, got {other:?}"),
        }
        for want in 257..=300 {
            assert_eq!(next_id(&mut tail).await, want);
        }
        match next_item(&mut tail).await {
            Some(TailItem::Event(ev)) => {
                assert_eq!(ev.row_id, None);
                assert_eq!(ev.timestamp, 1000);
            }
            other => panic!("expected the row-id-less event, got {other:?}"),
        }
    }

    /// Live mode stays lossy but tells the client where to resume.
    #[tokio::test]
    async fn live_lag_notice_carries_the_resume_cursor() {
        let (bus, log) = setup();
        let mut tail = EventTail::open(&bus, Arc::clone(&log), None, "test")
            .await
            .expect("open");
        for n in 1..=300 {
            publish_recorded(&bus, &log, n).await;
        }
        for want in 1..=256 {
            assert_eq!(next_id(&mut tail).await, want);
        }
        publish_recorded(&bus, &log, 301).await;
        assert!(matches!(
            next_item(&mut tail).await,
            Some(TailItem::Lagged {
                skipped: 44,
                resume_after_id: Some(256),
            })
        ));
        assert_eq!(next_id(&mut tail).await, 301);
    }

    /// Rows from an earlier daemon run (never fanned out by this bus)
    /// are replayed once the bus is seeded with the history head.
    #[tokio::test]
    async fn rows_from_an_earlier_run_are_replayed() {
        let (bus, log) = setup();
        for n in 1..=3 {
            log.record(0, &event(n), "inst", "example.test")
                .expect("record");
        }
        bus.note_history_head(log.head_id().expect("head"));
        let mut tail = EventTail::open(&bus, Arc::clone(&log), Some(1), "test")
            .await
            .expect("open");
        assert_eq!(next_id(&mut tail).await, 2);
        assert_eq!(next_id(&mut tail).await, 3);
        publish_recorded(&bus, &log, 4).await;
        assert_eq!(next_id(&mut tail).await, 4);
    }

    /// A row committed without being fanned out (cancelled publish)
    /// is read from history when the next live row id jumps past it.
    #[tokio::test]
    async fn unfanned_rows_are_filled_from_history() {
        let (bus, log) = setup();
        let mut tail = EventTail::open(&bus, Arc::clone(&log), Some(0), "test")
            .await
            .expect("open");
        publish_recorded(&bus, &log, 1).await;
        log.record(2, &event(2), "inst", "example.test")
            .expect("record");
        publish_recorded(&bus, &log, 3).await;
        for want in 1..=3 {
            assert_eq!(next_id(&mut tail).await, want);
        }
    }

    /// H3 late commit: event A goes out live without an id, its timed-out
    /// write commits later as row 1, then recovery fans out the gap
    /// marker (2) and the recovery event (3). The cursor stream sees
    /// A, then A again with its id, then the marker, then recovery.
    #[tokio::test]
    async fn late_committed_row_is_replayed_before_the_gap_marker() {
        let (bus, log) = setup();
        let mut tail = EventTail::open(&bus, Arc::clone(&log), Some(0), "test")
            .await
            .expect("open");
        bus.publish(event(1));
        log.record(1, &event(1), "inst", "example.test")
            .expect("late commit");
        publish_recorded(&bus, &log, 2).await;
        publish_recorded(&bus, &log, 3).await;
        match next_item(&mut tail).await {
            Some(TailItem::Event(ev)) => assert_eq!(ev.row_id, None),
            other => panic!("expected A without an id, got {other:?}"),
        }
        for want in 1..=3 {
            assert_eq!(next_id(&mut tail).await, want);
        }
    }

    /// Rows dropped from the queue are still replayed when the bus
    /// shuts down before the tail drains.
    #[tokio::test]
    async fn dropped_rows_are_replayed_before_a_shutdown_ends_the_tail() {
        let (bus, log) = setup();
        let mut tail = EventTail::open(&bus, Arc::clone(&log), Some(0), "test")
            .await
            .expect("open");
        for n in 1..=300 {
            publish_recorded(&bus, &log, n).await;
        }
        drop(bus);
        for want in 1..=300 {
            assert_eq!(next_id(&mut tail).await, want);
        }
        assert!(next_item(&mut tail).await.is_none());
    }

    /// Dropping the last bus owner ends an idle tail in both modes.
    #[tokio::test]
    async fn tail_ends_when_the_bus_is_dropped() {
        for after_id in [None, Some(0)] {
            let (bus, log) = setup();
            let mut tail = EventTail::open(&bus, Arc::clone(&log), after_id, "test")
                .await
                .expect("open");
            drop(bus);
            assert!(next_item(&mut tail).await.is_none(), "{after_id:?}");
        }
    }

    /// A watermark rise with nothing enqueued (the row was dropped
    /// from a full queue) wakes a cursor tail waiting on an empty
    /// queue.
    #[tokio::test]
    async fn watermark_rise_wakes_an_idle_cursor_tail() {
        let (bus, log) = setup();
        let mut tail = EventTail::open(&bus, Arc::clone(&log), Some(0), "test")
            .await
            .expect("open");
        let waiter = tokio::spawn(async move {
            let id = next_id(&mut tail).await;
            (tail, id)
        });
        tokio::task::yield_now().await;
        let id = log
            .record(1, &event(1), "inst", "example.test")
            .expect("record");
        bus.note_history_head(id);
        let (_tail, got) = waiter.await.expect("waiter");
        assert_eq!(got, id);
    }
}
