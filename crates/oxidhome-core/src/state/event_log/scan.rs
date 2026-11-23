//! Bounded forward scans from a resume cursor, for readers that filter
//! rows themselves (the plugin `host-events::read-events` import).
//!
//! [`EventLog::scan_after_cursor`] checks the cursor and walks the
//! rows after it in one `Db::read` snapshot (M6), like
//! [`EventLog::query_after_cursor`], but hands each decoded row to a
//! caller-supplied step instead of returning a fixed row count. The
//! caller decides per row whether to keep it, skip it, or stop because
//! its page is full, and the scan reports the exact cursor to resume
//! from: past every row it looked at, or just before the row it
//! stopped on.

use super::cursor::{CursorExpired, bounds, resolve_on};
use super::{EventLog, EventLogError, StoredEventPayload};
use crate::host_impl::plugin::oxidhome::plugin::events::Event;

/// Rows read per statement. Bounds the memory a scan holds at once
/// (an event payload is at most 64 KiB serialized).
const SCAN_CHUNK: usize = 64;

/// What [`EventLog::scan_after_cursor`] does with one row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanStep {
    /// Keep the row in the page.
    Take,
    /// Leave the row out; the cursor still moves past it.
    Skip,
    /// The page is full: stop before this row, so the next scan starts
    /// with it. Treated as [`Self::Take`] while the page is empty, so
    /// every scan that finds a row makes progress.
    Full,
}

/// One [`EventLog::scan_after_cursor`] result.
#[derive(Debug, Clone)]
pub struct ScanPage {
    /// Kept rows as WIT events (each with its `row-id`), oldest first.
    pub events: Vec<Event>,
    /// Cursor to resume from: the last row the scan consumed (kept or
    /// skipped), or `head_id` once it reached the end of history.
    pub next_after_id: u64,
    /// Highest row id ever assigned, in the scan's snapshot.
    pub head_id: u64,
}

impl EventLog {
    /// Resolve `after_id` (as [`Self::resolve_cursor`]: `0` starts at
    /// the oldest retained row and never expires) and pass up to
    /// `scan_budget` rows after it, oldest first, to `step`. The
    /// cursor check and every read share one `Db::read` closure, so
    /// they see one snapshot and a concurrent prune can't fall
    /// between them. `step` may rewrite the event it keeps (e.g. to
    /// withhold bytes). An expired cursor is the inner `Err`.
    ///
    /// # Errors
    ///
    /// Forwards any SQL or decode error.
    pub fn scan_after_cursor(
        &self,
        after_id: u64,
        scan_budget: usize,
        mut step: impl FnMut(&mut Event) -> ScanStep,
    ) -> Result<Result<ScanPage, CursorExpired>, EventLogError> {
        self.db.read(|conn| {
            let mut pos = match resolve_on(conn, after_id)? {
                Ok(cursor) => cursor,
                Err(expired) => return Ok(Err(expired)),
            };
            let (head_id, _) = bounds(conn)?;
            let mut events = Vec::new();
            let mut left = scan_budget;
            while left > 0 && pos < head_id {
                let want = left.min(SCAN_CHUNK);
                let rows = read_chunk(conn, pos, want)?;
                let short = rows.len() < want;
                for (id, event) in rows {
                    // An undecodable row is skipped (and logged) rather
                    // than failing every read that reaches it.
                    let Some(mut event) = event else {
                        pos = id;
                        left -= 1;
                        continue;
                    };
                    match step(&mut event) {
                        ScanStep::Full if !events.is_empty() => {
                            return Ok(Ok(ScanPage {
                                events,
                                next_after_id: pos,
                                head_id,
                            }));
                        }
                        ScanStep::Take | ScanStep::Full => events.push(event),
                        ScanStep::Skip => {}
                    }
                    pos = id;
                    left -= 1;
                }
                if short {
                    // Nothing after `pos` in this snapshot: every row
                    // up to the snapshot's head has been seen.
                    pos = pos.max(head_id);
                    break;
                }
            }
            Ok(Ok(ScanPage {
                events,
                next_after_id: pos,
                head_id,
            }))
        })
    }
}

/// Up to `limit` rows with `id > after`, oldest first, each decoded on
/// its own: a row whose payload doesn't decode comes back as `None`
/// (with an error log) instead of failing the chunk.
fn read_chunk(
    conn: &rusqlite::Connection,
    after: u64,
    limit: usize,
) -> Result<Vec<(u64, Option<Event>)>, EventLogError> {
    let mut stmt = conn.prepare(
        "SELECT id, payload_ms, device_id, instance_id, plugin_id, topic, payload_blob \
         FROM event_log WHERE id > ?1 ORDER BY id ASC LIMIT ?2",
    )?;
    let mut rows = stmt.query(rusqlite::params![
        i64::try_from(after).unwrap_or(i64::MAX),
        i64::try_from(limit).unwrap_or(i64::MAX),
    ])?;
    let mut out = Vec::with_capacity(limit.min(SCAN_CHUNK));
    while let Some(row) = rows.next()? {
        let id = u64::try_from(row.get::<_, i64>(0)?).unwrap_or(0);
        let payload_ms: i64 = row.get(1)?;
        let topic: String = row.get(5)?;
        let blob: Vec<u8> = row.get(6)?;
        let event = match serde_json::from_slice::<StoredEventPayload>(&blob) {
            Ok(stored) => Some(Event {
                device: row.get(2)?,
                timestamp: u64::try_from(payload_ms).unwrap_or(0),
                origin_plugin_id: row.get(4)?,
                origin_instance_id: row.get(3)?,
                row_id: Some(id),
                payload: stored.into_wit(),
            }),
            Err(err) => {
                tracing::error!(
                    target: "state.event_log",
                    id,
                    topic = %topic,
                    error = %err,
                    "event_log row does not decode; skipped by the history scan",
                );
                None
            }
        };
        out.push((id, event));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::host_impl::plugin::oxidhome::plugin::events::{CustomEvent, EventPayload};
    use crate::state::db::Db;

    fn log_with(rows: u64) -> EventLog {
        let log = EventLog::new(Arc::new(Db::open_in_memory().expect("db")));
        for n in 1..=rows {
            let ev = Event {
                device: None,
                timestamp: n,
                payload: EventPayload::Custom(CustomEvent {
                    topic: if n % 2 == 0 { "even" } else { "odd" }.into(),
                    payload: n.to_string(),
                }),
                origin_plugin_id: "example.test".into(),
                origin_instance_id: "inst".into(),
                row_id: None,
            };
            #[allow(clippy::cast_possible_wrap)]
            log.record(n as i64, &ev, "inst", "example.test")
                .expect("record");
        }
        log
    }

    fn ids(page: &ScanPage) -> Vec<u64> {
        page.events.iter().filter_map(|e| e.row_id).collect()
    }

    fn is_even(e: &Event) -> bool {
        matches!(&e.payload, EventPayload::Custom(c) if c.topic == "even")
    }

    #[test]
    fn skipped_rows_still_advance_the_cursor() {
        let log = log_with(10);
        let page = log
            .scan_after_cursor(0, 4, |e| {
                if is_even(e) {
                    ScanStep::Take
                } else {
                    ScanStep::Skip
                }
            })
            .expect("scan")
            .expect("cursor");
        assert_eq!(ids(&page), vec![2, 4]);
        assert_eq!((page.next_after_id, page.head_id), (4, 10));
        // A trailing skipped row moves the cursor past it.
        let page = log
            .scan_after_cursor(4, 5, |e| {
                if is_even(e) {
                    ScanStep::Take
                } else {
                    ScanStep::Skip
                }
            })
            .expect("scan")
            .expect("cursor");
        assert_eq!(ids(&page), vec![6, 8]);
        assert_eq!(page.next_after_id, 9);
    }

    #[test]
    fn full_stops_before_the_row_and_never_returns_an_empty_page() {
        let log = log_with(5);
        let mut kept = 0;
        let page = log
            .scan_after_cursor(0, 100, |_| {
                kept += 1;
                if kept > 2 {
                    ScanStep::Full
                } else {
                    ScanStep::Take
                }
            })
            .expect("scan")
            .expect("cursor");
        assert_eq!(ids(&page), vec![1, 2]);
        assert_eq!(page.next_after_id, 2);
        // `Full` on the first row still takes it.
        let page = log
            .scan_after_cursor(2, 100, |_| ScanStep::Full)
            .expect("scan")
            .expect("cursor");
        assert_eq!(ids(&page), vec![3]);
        assert_eq!(page.next_after_id, 3);
    }

    #[test]
    fn reaching_the_end_resumes_from_the_head() {
        let log = log_with(130);
        let page = log
            .scan_after_cursor(0, 1000, |_| ScanStep::Skip)
            .expect("scan")
            .expect("cursor");
        assert!(page.events.is_empty());
        assert_eq!((page.next_after_id, page.head_id), (130, 130));
        let page = log
            .scan_after_cursor(130, 1000, |_| ScanStep::Take)
            .expect("scan")
            .expect("cursor");
        assert!(page.events.is_empty());
        assert_eq!(page.next_after_id, 130);
    }

    #[test]
    fn undecodable_rows_are_skipped() {
        let log = log_with(3);
        log.db
            .write(|conn| {
                conn.execute(
                    "UPDATE event_log SET payload_blob = x'7b7d' WHERE id = 2",
                    (),
                )
            })
            .expect("corrupt");
        let page = log
            .scan_after_cursor(0, 10, |_| ScanStep::Take)
            .expect("scan")
            .expect("cursor");
        assert_eq!(ids(&page), vec![1, 3]);
        assert_eq!(page.next_after_id, 3);
    }

    #[test]
    fn expired_cursors_are_reported() {
        let log = log_with(5);
        log.trim_older_than(4).expect("trim");
        let expired = log
            .scan_after_cursor(1, 10, |_| ScanStep::Take)
            .expect("scan")
            .expect_err("expired");
        assert_eq!(
            expired,
            CursorExpired {
                after_id: 1,
                oldest_id: Some(4),
                head_id: 5,
            }
        );
        let page = log
            .scan_after_cursor(0, 10, |_| ScanStep::Take)
            .expect("scan")
            .expect("cursor");
        assert_eq!(ids(&page), vec![4, 5]);
    }
}
