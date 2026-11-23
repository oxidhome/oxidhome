//! H4: resume cursors over `event_log` row ids.
//!
//! Row ids come from `INTEGER PRIMARY KEY AUTOINCREMENT` (migration
//! 16): never reused, and, because every insert goes through the one
//! serialized writer connection and a failed insert rolls its id
//! back with its transaction, **dense** — the rows committed at any
//! moment are exactly `1..=head` minus the ones retention deleted.
//! So a missing id in a range a reader expects to be complete is
//! proof that rows were pruned, which is what lets a cursor stream
//! detect an expired cursor instead of silently skipping rows.

use rusqlite::OptionalExtension as _;
use serde::Serialize;

use super::{EventLog, EventLogError, EventOrder, EventQuery, HistoricalEvent};
use crate::host_impl::plugin::oxidhome::plugin::events::Event;

/// A cursor that can't be resumed without a gap: rows after it were
/// pruned by retention, or it is ahead of history (e.g. after a
/// restore from an older backup). The client resyncs from a state
/// snapshot and reopens with `after_id = head_id`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CursorExpired {
    /// The cursor that couldn't be honored.
    pub after_id: u64,
    /// Oldest row id still in history; `None` if history is empty.
    pub oldest_id: Option<u64>,
    /// Highest row id ever assigned.
    pub head_id: u64,
}

impl EventLog {
    /// Highest row id ever assigned (`0` before the first insert).
    /// Includes rows retention has since deleted.
    ///
    /// # Errors
    ///
    /// Forwards any SQL error.
    pub fn head_id(&self) -> Result<u64, EventLogError> {
        self.db.read(|conn| -> Result<_, EventLogError> {
            let (head, _) = bounds(conn)?;
            Ok(head)
        })
    }

    /// Resolve a client's `after_id` into the cursor a reader resumes
    /// from. `0` means "from the oldest retained row" and never
    /// expires. Any other cursor is valid when it is at most the head
    /// and the row right after it (if one was ever assigned) is still
    /// in history.
    ///
    /// # Errors
    ///
    /// Forwards any SQL error. An expired cursor is the inner `Err`.
    pub fn resolve_cursor(
        &self,
        after_id: u64,
    ) -> Result<Result<u64, CursorExpired>, EventLogError> {
        self.db.read(|conn| -> Result<_, EventLogError> {
            let (head_id, oldest_id) = bounds(conn)?;
            if after_id == 0 {
                return Ok(Ok(oldest_id.map_or(head_id, |oldest| oldest - 1)));
            }
            let expired = CursorExpired {
                after_id,
                oldest_id,
                head_id,
            };
            if after_id > head_id {
                return Ok(Err(expired));
            }
            if after_id == head_id {
                return Ok(Ok(after_id));
            }
            let next: Option<i64> = conn
                .query_row(
                    "SELECT id FROM event_log WHERE id = ?1",
                    [to_sql_id(after_id + 1)],
                    |row| row.get(0),
                )
                .optional()?;
            Ok(if next.is_some() {
                Ok(after_id)
            } else {
                Err(expired)
            })
        })
    }

    /// The [`CursorExpired`] report for `after_id` against the
    /// current history bounds.
    ///
    /// # Errors
    ///
    /// Forwards any SQL error.
    pub fn cursor_expired(&self, after_id: u64) -> Result<CursorExpired, EventLogError> {
        self.db.read(|conn| -> Result<_, EventLogError> {
            let (head_id, oldest_id) = bounds(conn)?;
            Ok(CursorExpired {
                after_id,
                oldest_id,
                head_id,
            })
        })
    }

    /// Rows with `after < id <= through`, oldest first, at most
    /// `limit`. Returns `None` if the result is not the dense run
    /// `after + 1, after + 2, …` — some row in the range was pruned.
    ///
    /// # Errors
    ///
    /// Forwards any SQL or decode error.
    pub fn read_dense_range(
        &self,
        after: u64,
        through: u64,
        limit: usize,
    ) -> Result<Option<Vec<HistoricalEvent>>, EventLogError> {
        if through <= after || limit == 0 {
            return Ok(Some(Vec::new()));
        }
        let rows = self.query(
            &EventQuery {
                after_id: Some(after),
                before_id: Some(through.saturating_add(1)),
                order: EventOrder::Asc,
                ..EventQuery::default()
            },
            limit,
        )?;
        let expected = usize::try_from(through - after).map_or(limit, |n| n.min(limit));
        let dense = rows.len() == expected
            && rows
                .iter()
                .zip(after + 1..)
                .all(|(row, want)| row.id == want);
        Ok(dense.then_some(rows))
    }
}

impl HistoricalEvent {
    /// Rebuild the WIT event this row was recorded from, carrying the
    /// row id it would have had on live delivery.
    #[must_use]
    pub fn into_event(self) -> Event {
        Event {
            device: self.device_id,
            timestamp: self.payload_ms,
            origin_plugin_id: self.plugin_id,
            origin_instance_id: self.instance_id,
            row_id: Some(self.id),
            payload: self.payload,
        }
    }
}

/// `(head_id, oldest_id)`. The head comes from `sqlite_sequence`
/// (survives deletes), floored by `MAX(id)` in case the sequence row
/// is missing.
fn bounds(conn: &rusqlite::Connection) -> Result<(u64, Option<u64>), EventLogError> {
    let (max_id, min_id): (Option<i64>, Option<i64>) =
        conn.query_row("SELECT MAX(id), MIN(id) FROM event_log", (), |row| {
            Ok((row.get(0)?, row.get(1)?))
        })?;
    let seq: Option<i64> = conn
        .query_row(
            "SELECT seq FROM sqlite_sequence WHERE name = 'event_log'",
            (),
            |row| row.get(0),
        )
        .optional()?;
    let head = seq.unwrap_or(0).max(max_id.unwrap_or(0));
    Ok((from_sql_id(head), min_id.map(from_sql_id)))
}

fn from_sql_id(id: i64) -> u64 {
    u64::try_from(id).unwrap_or(0)
}

fn to_sql_id(id: u64) -> i64 {
    i64::try_from(id).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::host_impl::plugin::oxidhome::plugin::events::{CustomEvent, EventPayload};
    use crate::state::db::Db;

    fn event(n: u64) -> Event {
        Event {
            device: None,
            timestamp: n,
            payload: EventPayload::Custom(CustomEvent {
                topic: "test.cursor".into(),
                payload: n.to_string(),
            }),
            origin_plugin_id: "example.test".into(),
            origin_instance_id: "inst".into(),
            row_id: None,
        }
    }

    fn log_with(rows: u64) -> EventLog {
        let log = EventLog::new(Arc::new(Db::open_in_memory().expect("db")));
        for n in 1..=rows {
            #[allow(clippy::cast_possible_wrap)]
            log.record(n as i64, &event(n), "inst", "example.test")
                .expect("record");
        }
        log
    }

    #[test]
    fn resolve_cursor_accepts_retained_and_head_cursors() {
        let log = log_with(5);
        assert_eq!(log.head_id().expect("head"), 5);
        assert_eq!(log.resolve_cursor(0).expect("q"), Ok(0));
        assert_eq!(log.resolve_cursor(3).expect("q"), Ok(3));
        assert_eq!(log.resolve_cursor(5).expect("q"), Ok(5));
    }

    #[test]
    fn resolve_cursor_expires_pruned_and_future_cursors() {
        let log = log_with(5);
        // Rows 1..=3 have received_ms 1..=3.
        assert_eq!(log.trim_older_than(4).expect("trim"), 3);
        let expired = |after_id| CursorExpired {
            after_id,
            oldest_id: Some(4),
            head_id: 5,
        };
        assert_eq!(log.resolve_cursor(2).expect("q"), Err(expired(2)));
        assert_eq!(log.resolve_cursor(3).expect("q"), Ok(3));
        assert_eq!(log.resolve_cursor(6).expect("q"), Err(expired(6)));
        // `0` starts at the oldest retained row.
        assert_eq!(log.resolve_cursor(0).expect("q"), Ok(3));
    }

    #[test]
    fn resolve_cursor_on_fully_pruned_history_uses_head() {
        let log = log_with(3);
        log.trim_older_than(i64::MAX).expect("trim");
        assert_eq!(log.head_id().expect("head"), 3);
        assert_eq!(log.resolve_cursor(0).expect("q"), Ok(3));
        assert_eq!(log.resolve_cursor(3).expect("q"), Ok(3));
        assert_eq!(
            log.resolve_cursor(1).expect("q"),
            Err(CursorExpired {
                after_id: 1,
                oldest_id: None,
                head_id: 3,
            })
        );
    }

    #[test]
    fn read_dense_range_detects_holes() {
        let log = log_with(6);
        let ids = |rows: Option<Vec<HistoricalEvent>>| {
            rows.map(|r| r.into_iter().map(|e| e.id).collect::<Vec<_>>())
        };
        assert_eq!(
            ids(log.read_dense_range(1, 4, 10).expect("q")),
            Some(vec![2, 3, 4])
        );
        assert_eq!(
            ids(log.read_dense_range(1, 6, 2).expect("q")),
            Some(vec![2, 3])
        );
        log.db
            .write(|conn| conn.execute("DELETE FROM event_log WHERE id = 3", ()))
            .expect("delete");
        assert_eq!(ids(log.read_dense_range(1, 4, 10).expect("q")), None);
        assert_eq!(
            ids(log.read_dense_range(3, 6, 10).expect("q")),
            Some(vec![4, 5, 6])
        );
    }
}
