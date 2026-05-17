//! Durable mirror of the live `EventBus`.
//!
//! Phase 5d's read side: every event a plugin publishes lands in the
//! `event_log` table so the CLI/UI (Phase 12) can answer questions
//! like "what did the front-door sensor do yesterday?" Plugins keep
//! using `subscribe`/`on-event` for live delivery; they don't query
//! history themselves (host-only — by design, see `03_core.md` §5d).
//!
//! Trust separation on timestamps:
//!
//! - `received_ms` is the host's wall-clock at receive time, set by
//!   [`EventLog::record`]. Ordering, retention, and query time-range
//!   filters all use this column.
//! - `payload_ms` is the plugin's self-reported
//!   `events::event.timestamp` — informational only. A buggy or
//!   malicious plugin can't backdate / future-date history or poison
//!   retention trims because nothing trusts this value for those
//!   decisions.
//!
//! Encoding: WIT `event-payload` variants are mirrored in a small
//! tagged JSON enum so each row carries the variant tag plus its
//! payload. Same pattern as [`super::kv::StoredValue`]. Postcard
//! (smaller wire format) is an optimization for later; the store
//! reads opaque BLOBs so a future migration can re-encode in place
//! without touching this code.

use std::sync::Arc;

use rusqlite::params;
use serde::{Deserialize, Serialize};

use crate::host_impl::plugin::oxidhome::plugin::capabilities::ButtonEvent;
use crate::host_impl::plugin::oxidhome::plugin::events::{
    CustomEvent, Event, EventPayload, InferenceResult, StateChange,
};
use crate::host_impl::plugin::oxidhome::plugin::types::{KeyValue, Value as WitValue};

use super::db::Db;

/// Errors returned by [`EventLog`]. Maps onto the WIT `error` variant
/// in `host_impl::events::publish_event` via the same `Internal`-or-
/// pass-through shape `KvError` uses.
#[derive(Debug, thiserror::Error)]
pub enum EventLogError {
    /// `payload` encode / decode failed. Shouldn't happen for any
    /// WIT-produced event, but surfacing it beats panicking.
    #[error("encoding event payload (topic `{topic}`): {source}")]
    Encode {
        topic: String,
        #[source]
        source: serde_json::Error,
    },
    /// `SQLite` returned an error during the operation.
    #[error("sqlite error: {0}")]
    Sql(#[from] rusqlite::Error),
}

/// One row from `event_log`, decoded back into typed Rust. Returned
/// from [`EventLog::query`]. Carries both timestamps so a query
/// consumer can compare what the plugin claimed (`payload_ms`)
/// against when the host actually saw it (`received_ms`).
///
/// `received_ms` is `i64` (host's `SystemTime → UNIX_EPOCH` math);
/// `payload_ms` is `u64` to match the WIT `unix-ms` alias the plugin
/// fills in.
#[derive(Debug, Clone)]
pub struct HistoricalEvent {
    pub id: u64,
    pub received_ms: i64,
    pub payload_ms: u64,
    pub device_id: Option<String>,
    pub instance_id: String,
    pub plugin_id: String,
    pub topic: String,
    pub payload: EventPayload,
}

/// Query shape for [`EventLog::query`]. Every field is optional and
/// AND-combined; `None` everywhere returns the most recent `limit`
/// rows from the whole table. Time bounds are inclusive on both ends
/// and use `received_ms` (host-side, never the plugin's claim).
///
/// Topic semantics:
///
/// - `Some((s, TopicMatch::Exact))` → `topic = s`. Use for
///   capability events (`"switch"`, `"button"`, `"inference"`).
/// - `Some((s, TopicMatch::Prefix))` → `topic LIKE 's%'`. Use for
///   custom-event topic prefixes (`"automation."` → every
///   `automation.morning`, `automation.evening`, …).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct EventQuery {
    pub since_ms: Option<i64>,
    pub until_ms: Option<i64>,
    pub device_id: Option<String>,
    pub instance_id: Option<String>,
    pub plugin_id: Option<String>,
    pub topic: Option<(String, TopicMatch)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TopicMatch {
    Exact,
    Prefix,
}

/// Per-engine durable event history. Cheap to clone — holds an
/// `Arc<Db>`.
#[derive(Clone)]
pub struct EventLog {
    db: Arc<Db>,
}

impl EventLog {
    #[must_use]
    pub fn new(db: Arc<Db>) -> Self {
        Self { db }
    }

    /// Insert one event. `received_ms` is the host's wall-clock at
    /// capture time; the caller fills it in (typically via
    /// `now_unix_ms()` or a synthetic value from tests). `instance_id`
    /// and `plugin_id` are the publisher's manifest-resolved
    /// identity, plumbed in by `host_impl::events::publish_event`.
    /// Returns the row's `INTEGER PRIMARY KEY`.
    ///
    /// # Errors
    ///
    /// - [`EventLogError::Encode`] if the WIT payload variant can't
    ///   be JSON-encoded (should never happen for the standard
    ///   shapes).
    /// - [`EventLogError::Sql`] for any underlying `SQLite` error.
    pub fn record(
        &self,
        received_ms: i64,
        event: &Event,
        instance_id: &str,
        plugin_id: &str,
    ) -> Result<u64, EventLogError> {
        let topic = topic_of(event).to_owned();
        let stored = StoredEventPayload::from_wit(&event.payload);
        let payload_blob = serde_json::to_vec(&stored).map_err(|source| EventLogError::Encode {
            topic: topic.clone(),
            source,
        })?;
        let device_id = event.device.clone();
        // WIT `unix-ms` is `u64`; `SQLite` INTEGER is `i64`. Clamp the
        // upper end so a plugin that claims `u64::MAX` lands as
        // `i64::MAX` on disk rather than wrapping negative.
        let payload_ms = i64::try_from(event.timestamp).unwrap_or(i64::MAX);
        let instance_id_owned = instance_id.to_owned();
        let plugin_id_owned = plugin_id.to_owned();

        self.db.write(move |conn| -> Result<u64, EventLogError> {
            conn.execute(
                "INSERT INTO event_log(received_ms, payload_ms, device_id, instance_id, plugin_id, topic, payload_blob) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    received_ms,
                    payload_ms,
                    device_id,
                    instance_id_owned,
                    plugin_id_owned,
                    topic,
                    payload_blob,
                ],
            )?;
            // `last_insert_rowid` returns the just-inserted PRIMARY
            // KEY for the active connection. Safe to cast: `SQLite`'s
            // ROWID is a signed i64 but always positive for normal
            // INTEGER PRIMARY KEY values.
            #[allow(clippy::cast_sign_loss)]
            Ok(conn.last_insert_rowid() as u64)
        })
    }

    /// Query the history. Returns at most `limit` rows, ordered by
    /// `received_ms DESC, id DESC` (newest first; the `id` tiebreak
    /// matches the natural insertion order for events that share a
    /// millisecond).
    ///
    /// # Errors
    ///
    /// - [`EventLogError::Sql`] for any underlying `SQLite` error.
    /// - [`EventLogError::Encode`] if a stored row has a malformed
    ///   `payload_blob` (would mean the table was hand-edited or
    ///   migrated incorrectly).
    pub fn query(
        &self,
        filter: &EventQuery,
        limit: usize,
    ) -> Result<Vec<HistoricalEvent>, EventLogError> {
        // Build a parameterized WHERE clause + ordered params list.
        // Avoids string-templating columns and uses `?N` binds for
        // every value. The query planner picks among `evt_received`
        // and the various `(col, received_ms)` indexes based on
        // selectivity.
        use std::fmt::Write as _;

        let mut sql = String::from(
            "SELECT id, received_ms, payload_ms, device_id, instance_id, plugin_id, topic, payload_blob \
             FROM event_log WHERE 1=1",
        );
        let mut binds: Vec<rusqlite::types::Value> = Vec::new();

        let push = |binds: &mut Vec<rusqlite::types::Value>,
                        sql: &mut String,
                        clause: &str,
                        v: rusqlite::types::Value| {
            binds.push(v);
            // `?N` requires N to match the bind count — splice the
            // index in as we go so the SQL stays in sync with the
            // binds vec.
            let _ = write!(sql, " AND {clause} ?{}", binds.len());
        };

        if let Some(t) = filter.since_ms {
            push(&mut binds, &mut sql, "received_ms >=", t.into());
        }
        if let Some(t) = filter.until_ms {
            push(&mut binds, &mut sql, "received_ms <=", t.into());
        }
        if let Some(d) = &filter.device_id {
            push(&mut binds, &mut sql, "device_id =", d.clone().into());
        }
        if let Some(i) = &filter.instance_id {
            push(&mut binds, &mut sql, "instance_id =", i.clone().into());
        }
        if let Some(p) = &filter.plugin_id {
            push(&mut binds, &mut sql, "plugin_id =", p.clone().into());
        }
        if let Some((t, m)) = &filter.topic {
            match m {
                TopicMatch::Exact => {
                    push(&mut binds, &mut sql, "topic =", t.clone().into());
                }
                // Prefix-match via `substr(topic, 1, length(?)) = ?` —
                // same shape used by `kv::list_keys`, both correct on
                // TEXT (character-prefix equality) and free of `LIKE`'s
                // wildcard-escaping hazards.
                TopicMatch::Prefix => {
                    binds.push(rusqlite::types::Value::Text(t.clone()));
                    let n_left = binds.len();
                    binds.push(rusqlite::types::Value::Text(t.clone()));
                    let n_right = binds.len();
                    let _ = write!(
                        sql,
                        " AND substr(topic, 1, length(?{n_left})) = ?{n_right}",
                    );
                }
            }
        }

        binds.push(rusqlite::types::Value::Integer(
            i64::try_from(limit).unwrap_or(i64::MAX),
        ));
        let _ = write!(sql, " ORDER BY received_ms DESC, id DESC LIMIT ?{}", binds.len());

        self.db.read(|conn| -> Result<_, EventLogError> {
            let mut stmt = conn.prepare(&sql)?;
            let binds: Vec<&dyn rusqlite::ToSql> =
                binds.iter().map(|v| v as &dyn rusqlite::ToSql).collect();
            let mut rows = stmt.query(binds.as_slice())?;
            let mut out = Vec::new();
            while let Some(row) = rows.next()? {
                let id: i64 = row.get(0)?;
                let received_ms: i64 = row.get(1)?;
                let payload_ms: i64 = row.get(2)?;
                let device_id: Option<String> = row.get(3)?;
                let instance_id: String = row.get(4)?;
                let plugin_id: String = row.get(5)?;
                let topic: String = row.get(6)?;
                let blob: Vec<u8> = row.get(7)?;
                let stored: StoredEventPayload =
                    serde_json::from_slice(&blob).map_err(|source| EventLogError::Encode {
                        topic: topic.clone(),
                        source,
                    })?;
                // `payload_ms` is stored as i64 (`SQLite` INTEGER) but
                // the API hands it back as the u64 the WIT contract
                // promises. Negative values would mean a corrupted row
                // — clamp to 0 rather than wrap.
                #[allow(clippy::cast_sign_loss)]
                out.push(HistoricalEvent {
                    id: id as u64,
                    received_ms,
                    payload_ms: u64::try_from(payload_ms).unwrap_or(0),
                    device_id,
                    instance_id,
                    plugin_id,
                    topic,
                    payload: stored.into_wit(),
                });
            }
            Ok(out)
        })
    }

    /// Delete every event with `received_ms < cutoff_ms`. Returns the
    /// number of rows removed. The retention scheduler (Phase 12) will
    /// call this periodically; for now it's just a knob for tests.
    ///
    /// # Errors
    ///
    /// Forwards any SQL error.
    pub fn trim_older_than(&self, cutoff_ms: i64) -> Result<usize, EventLogError> {
        self.db.write(|conn| -> Result<_, EventLogError> {
            Ok(conn.execute(
                "DELETE FROM event_log WHERE received_ms < ?1",
                params![cutoff_ms],
            )?)
        })
    }

    /// Total row count. Mostly for tests + future status endpoints.
    ///
    /// # Errors
    ///
    /// Forwards any SQL error.
    pub fn count(&self) -> Result<u64, EventLogError> {
        let n: i64 = self.db.read(|conn| -> Result<_, EventLogError> {
            Ok(conn.query_row("SELECT COUNT(*) FROM event_log", (), |row| row.get(0))?)
        })?;
        #[allow(clippy::cast_sign_loss)]
        Ok(n as u64)
    }
}

/// Stable host-side mirror of WIT [`EventPayload`]. Tagged JSON so
/// deserialization knows which variant to rebuild and a future
/// migration can swap encodings without dropping rows.
#[derive(Serialize, Deserialize)]
#[serde(tag = "t", content = "v")]
enum StoredEventPayload {
    StateChanged(StoredStateChange),
    Button(StoredButtonEvent),
    Inference(StoredInferenceResult),
    Custom(StoredCustomEvent),
}

#[derive(Serialize, Deserialize)]
struct StoredStateChange {
    capability: String,
    fields: Vec<StoredKeyValue>,
}

#[derive(Serialize, Deserialize, Clone, Copy)]
enum StoredButtonEvent {
    Pressed,
    Released,
    SinglePress,
    DoublePress,
    LongPress,
    /// Rotational delta; positive = clockwise (matches WIT comment).
    Rotated(f64),
}

#[derive(Serialize, Deserialize)]
struct StoredInferenceResult {
    model: String,
    payload: String,
    // WIT `unix-ms` is `u64`. Stored as `u64` here so the round-trip
    // back to the WIT type is lossless.
    frame_timestamp: Option<u64>,
}

#[derive(Serialize, Deserialize)]
struct StoredCustomEvent {
    topic: String,
    payload: String,
}

#[derive(Serialize, Deserialize)]
struct StoredKeyValue {
    key: String,
    value: StoredValue,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "t", content = "v")]
enum StoredValue {
    Bool(bool),
    Int(i64),
    Float(f64),
    String(String),
    Bytes(Vec<u8>),
    Json(String),
}

impl StoredEventPayload {
    fn from_wit(payload: &EventPayload) -> Self {
        match payload {
            EventPayload::StateChanged(sc) => Self::StateChanged(StoredStateChange {
                capability: sc.capability.clone(),
                fields: sc.fields.iter().map(StoredKeyValue::from_wit).collect(),
            }),
            EventPayload::Button(b) => Self::Button(StoredButtonEvent::from_wit(*b)),
            EventPayload::Inference(i) => Self::Inference(StoredInferenceResult {
                model: i.model.clone(),
                payload: i.payload.clone(),
                frame_timestamp: i.frame_timestamp,
            }),
            EventPayload::Custom(c) => Self::Custom(StoredCustomEvent {
                topic: c.topic.clone(),
                payload: c.payload.clone(),
            }),
        }
    }

    fn into_wit(self) -> EventPayload {
        match self {
            Self::StateChanged(sc) => EventPayload::StateChanged(StateChange {
                capability: sc.capability,
                fields: sc
                    .fields
                    .into_iter()
                    .map(StoredKeyValue::into_wit)
                    .collect(),
            }),
            Self::Button(b) => EventPayload::Button(b.into_wit()),
            Self::Inference(i) => EventPayload::Inference(InferenceResult {
                model: i.model,
                payload: i.payload,
                frame_timestamp: i.frame_timestamp,
            }),
            Self::Custom(c) => EventPayload::Custom(CustomEvent {
                topic: c.topic,
                payload: c.payload,
            }),
        }
    }
}

impl StoredButtonEvent {
    fn from_wit(b: ButtonEvent) -> Self {
        match b {
            ButtonEvent::Pressed => Self::Pressed,
            ButtonEvent::Released => Self::Released,
            ButtonEvent::SinglePress => Self::SinglePress,
            ButtonEvent::DoublePress => Self::DoublePress,
            ButtonEvent::LongPress => Self::LongPress,
            ButtonEvent::Rotated(delta) => Self::Rotated(delta),
        }
    }

    fn into_wit(self) -> ButtonEvent {
        match self {
            Self::Pressed => ButtonEvent::Pressed,
            Self::Released => ButtonEvent::Released,
            Self::SinglePress => ButtonEvent::SinglePress,
            Self::DoublePress => ButtonEvent::DoublePress,
            Self::LongPress => ButtonEvent::LongPress,
            Self::Rotated(delta) => ButtonEvent::Rotated(delta),
        }
    }
}

impl StoredKeyValue {
    fn from_wit(kv: &KeyValue) -> Self {
        Self {
            key: kv.key.clone(),
            value: StoredValue::from_wit(kv.value.clone()),
        }
    }

    fn into_wit(self) -> KeyValue {
        KeyValue {
            key: self.key,
            value: self.value.into_wit(),
        }
    }
}

impl StoredValue {
    fn from_wit(v: WitValue) -> Self {
        match v {
            WitValue::BoolVal(b) => Self::Bool(b),
            WitValue::IntVal(i) => Self::Int(i),
            WitValue::FloatVal(f) => Self::Float(f),
            WitValue::StringVal(s) => Self::String(s),
            WitValue::BytesVal(b) => Self::Bytes(b),
            WitValue::JsonVal(s) => Self::Json(s),
        }
    }

    fn into_wit(self) -> WitValue {
        match self {
            Self::Bool(b) => WitValue::BoolVal(b),
            Self::Int(i) => WitValue::IntVal(i),
            Self::Float(f) => WitValue::FloatVal(f),
            Self::String(s) => WitValue::StringVal(s),
            Self::Bytes(b) => WitValue::BytesVal(b),
            Self::Json(s) => WitValue::JsonVal(s),
        }
    }
}

/// Normalized topic for an [`Event`]. Mirrors the `topic_of` helper
/// in `state::events` (live-bus side) so subscribe-by-topic and
/// query-by-topic look at the same string.
fn topic_of(event: &Event) -> &str {
    match &event.payload {
        EventPayload::StateChanged(sc) => &sc.capability,
        EventPayload::Button(_) => "button",
        EventPayload::Inference(_) => "inference",
        EventPayload::Custom(c) => &c.topic,
    }
}

/// Returns the current Unix time in ms, capped at `i64::MAX` and
/// `0` on clock-before-epoch. Exposed for the runtime-state caller
/// in `host_impl::events::publish_event` so the `received_ms` it
/// stores matches the store's own assumptions.
#[must_use]
pub(crate) fn now_unix_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn log() -> EventLog {
        EventLog::new(Arc::new(Db::open_in_memory().expect("db")))
    }

    fn switch_event(device: &str, state: bool, ts: u64) -> Event {
        Event {
            device: Some(device.into()),
            timestamp: ts,
            payload: EventPayload::StateChanged(StateChange {
                capability: "switch".into(),
                fields: vec![KeyValue {
                    key: "state".into(),
                    value: WitValue::BoolVal(state),
                }],
            }),
        }
    }

    fn custom_event(topic: &str, payload_ms: u64) -> Event {
        Event {
            device: None,
            timestamp: payload_ms,
            payload: EventPayload::Custom(CustomEvent {
                topic: topic.into(),
                payload: "{}".into(),
            }),
        }
    }

    #[test]
    fn record_then_query_returns_the_row() {
        let log = log();
        let id = log
            .record(
                100,
                &switch_event("d-1", true, 99),
                "alpha",
                "example.alpha",
            )
            .expect("record");
        assert!(id >= 1);

        let rows = log.query(&EventQuery::default(), 16).expect("query");
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row.received_ms, 100);
        assert_eq!(row.payload_ms, 99);
        assert_eq!(row.device_id.as_deref(), Some("d-1"));
        assert_eq!(row.instance_id, "alpha");
        assert_eq!(row.plugin_id, "example.alpha");
        assert_eq!(row.topic, "switch");
        match &row.payload {
            EventPayload::StateChanged(sc) => {
                assert_eq!(sc.capability, "switch");
                assert_eq!(sc.fields.len(), 1);
                assert!(matches!(sc.fields[0].value, WitValue::BoolVal(true)));
            }
            other => panic!("expected StateChanged, got {other:?}"),
        }
    }

    /// Every WIT `EventPayload` variant survives the JSON
    /// encode/decode hop intact. Catches any future drift where a
    /// new variant gets added to the WIT but the `StoredEventPayload`
    /// mirror forgets to follow.
    #[test]
    fn each_payload_variant_round_trips() {
        let log = log();
        let events: [(&str, Event); 4] = [
            ("switch", switch_event("d-1", false, 1)),
            (
                "button",
                Event {
                    device: Some("d-2".into()),
                    timestamp: 2,
                    payload: EventPayload::Button(ButtonEvent::DoublePress),
                },
            ),
            (
                "inference",
                Event {
                    device: None,
                    timestamp: 3,
                    payload: EventPayload::Inference(InferenceResult {
                        model: "yolov8n".into(),
                        payload: r#"{"hits":[]}"#.into(),
                        frame_timestamp: Some(2999),
                    }),
                },
            ),
            ("automation.morning", custom_event("automation.morning", 4)),
        ];

        for (i, (_topic, ev)) in events.iter().enumerate() {
            let received_ms = i64::try_from(100 + i).unwrap_or(i64::MAX);
            log.record(received_ms, ev, "alpha", "example.alpha")
                .expect("record");
        }

        let mut rows = log.query(&EventQuery::default(), 16).expect("query");
        rows.sort_by_key(|r| r.received_ms);
        assert_eq!(rows.len(), events.len());

        for ((_expected_topic, expected), row) in events.iter().zip(rows.iter()) {
            assert_eq!(row.payload_ms, expected.timestamp);
            // Both topics derived through `topic_of`, so equality
            // here is what the live bus uses too.
            assert_eq!(row.topic, super::topic_of(expected));
            // Payload variant tag matches.
            assert_eq!(
                std::mem::discriminant(&row.payload),
                std::mem::discriminant(&expected.payload),
            );
        }
    }

    /// Filter by `device_id` narrows to the one device's events.
    #[test]
    fn query_filters_by_device() {
        let log = log();
        log.record(1, &switch_event("d-1", true, 0), "alpha", "example.alpha")
            .expect("record");
        log.record(2, &switch_event("d-2", true, 0), "alpha", "example.alpha")
            .expect("record");
        log.record(3, &switch_event("d-1", false, 0), "alpha", "example.alpha")
            .expect("record");

        let rows = log
            .query(
                &EventQuery {
                    device_id: Some("d-1".into()),
                    ..EventQuery::default()
                },
                16,
            )
            .expect("query");
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|r| r.device_id.as_deref() == Some("d-1")));
    }

    /// Filter by topic, exact and prefix flavors. Exact catches
    /// `"switch"`; prefix `"automation."` catches both
    /// `automation.morning` and `automation.evening` but not
    /// `automatic`.
    #[test]
    fn query_filters_by_topic() {
        let log = log();
        log.record(1, &switch_event("d-1", true, 0), "alpha", "example.alpha")
            .expect("record");
        log.record(
            2,
            &custom_event("automation.morning", 0),
            "alpha",
            "example.alpha",
        )
        .expect("record");
        log.record(
            3,
            &custom_event("automation.evening", 0),
            "alpha",
            "example.alpha",
        )
        .expect("record");
        log.record(4, &custom_event("automatic", 0), "alpha", "example.alpha")
            .expect("record");

        let exact = log
            .query(
                &EventQuery {
                    topic: Some(("switch".into(), TopicMatch::Exact)),
                    ..EventQuery::default()
                },
                16,
            )
            .expect("query");
        assert_eq!(exact.len(), 1);

        let prefix = log
            .query(
                &EventQuery {
                    topic: Some(("automation.".into(), TopicMatch::Prefix)),
                    ..EventQuery::default()
                },
                16,
            )
            .expect("query");
        assert_eq!(prefix.len(), 2);
        assert!(prefix.iter().all(|r| r.topic.starts_with("automation.")));
    }

    /// Time-range filter narrows to `[since_ms, until_ms]` inclusive
    /// on both ends.
    #[test]
    fn query_filters_by_time_range() {
        let log = log();
        for t in [10_i64, 20, 30, 40, 50] {
            #[allow(clippy::cast_sign_loss)]
            let payload_ms = t as u64;
            log.record(
                t,
                &switch_event("d-1", true, payload_ms),
                "alpha",
                "example.alpha",
            )
            .expect("record");
        }
        let rows = log
            .query(
                &EventQuery {
                    since_ms: Some(20),
                    until_ms: Some(40),
                    ..EventQuery::default()
                },
                16,
            )
            .expect("query");
        assert_eq!(rows.len(), 3);
        let mut times: Vec<_> = rows.iter().map(|r| r.received_ms).collect();
        times.sort_unstable();
        assert_eq!(times, vec![20, 30, 40]);
    }

    /// Query order is newest-first, with `id` as the tiebreak for
    /// same-millisecond rows. Useful for tailing the last N.
    #[test]
    fn query_orders_newest_first() {
        let log = log();
        for t in [10, 20, 30] {
            log.record(t, &switch_event("d-1", true, 0), "alpha", "example.alpha")
                .expect("record");
        }
        let rows = log.query(&EventQuery::default(), 16).expect("query");
        let times: Vec<_> = rows.iter().map(|r| r.received_ms).collect();
        assert_eq!(times, vec![30, 20, 10]);
    }

    /// `limit` is honored — exceeding stops at `limit`, smaller is
    /// returned in full.
    #[test]
    fn query_honors_limit() {
        let log = log();
        for t in 0..10 {
            log.record(t, &switch_event("d-1", true, 0), "alpha", "example.alpha")
                .expect("record");
        }
        let rows = log.query(&EventQuery::default(), 3).expect("query");
        assert_eq!(rows.len(), 3);
    }

    /// `trim_older_than(cutoff)` deletes strictly-older rows; rows at
    /// exactly `cutoff` survive (`received_ms < cutoff_ms`).
    #[test]
    fn trim_drops_old_rows() {
        let log = log();
        for t in [10, 20, 30, 40, 50] {
            log.record(t, &switch_event("d-1", true, 0), "alpha", "example.alpha")
                .expect("record");
        }
        let dropped = log.trim_older_than(30).expect("trim");
        assert_eq!(dropped, 2, "rows at received_ms < 30 should drop (10, 20)");

        let remaining: Vec<_> = log
            .query(&EventQuery::default(), 16)
            .expect("query")
            .into_iter()
            .map(|r| r.received_ms)
            .collect();
        assert_eq!(remaining, vec![50, 40, 30]);
    }

    #[test]
    fn count_matches_table_size() {
        let log = log();
        assert_eq!(log.count().expect("count"), 0);
        log.record(1, &switch_event("d-1", true, 0), "alpha", "example.alpha")
            .expect("record");
        log.record(2, &switch_event("d-1", false, 0), "alpha", "example.alpha")
            .expect("record");
        assert_eq!(log.count().expect("count"), 2);
    }

    /// File-backed store survives a `Db` drop + reopen. Plain Phase
    /// 5a-style restart test for the table; the example integration
    /// test in `tests/event_history.rs` exercises the same shape
    /// through `Engine::with_state_dir`.
    #[test]
    fn rows_survive_db_reopen() {
        let dir = tempdir_for_test();
        let path = dir.path.clone();
        {
            let db = Arc::new(Db::open_file(&path).expect("open"));
            let log = EventLog::new(db);
            log.record(100, &switch_event("d-1", true, 0), "alpha", "example.alpha")
                .expect("record");
        }
        let db = Arc::new(Db::open_file(&path).expect("reopen"));
        let log = EventLog::new(db);
        let rows = log.query(&EventQuery::default(), 16).expect("query");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].device_id.as_deref(), Some("d-1"));
    }

    // Tiny tempdir helper — same shape as `state::db::tests`.
    struct TempDir {
        path: std::path::PathBuf,
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
    fn tempdir_for_test() -> TempDir {
        let base = std::env::temp_dir();
        let path = base.join(format!(
            "oxidhome-eventlog-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos()),
        ));
        std::fs::create_dir_all(&path).expect("mk tempdir");
        TempDir { path }
    }
}
