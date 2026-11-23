//! OxidHome Phase 3 example: a passive event recorder.
//!
//! Subscribes to every event on the bus during `init` and logs each
//! one through `on_event` — together with `examples/simulated-switch`
//! it exercises the plugin-side dispatch path. It also keeps a running
//! count of received events, readable via the `recorder::count`
//! command, so Phase 6's tokio supervisor can prove event delivery
//! through an [`InstanceHandle`] without scraping logs.
//!
//! Event history: the recorder keeps the highest `row-id` it handled
//! in KV storage. On `init` it subscribes, then replays the recorded
//! events after that cursor through `host::events::History` (catching
//! up on what it missed while stopped), and `on_event` skips events the
//! catch-up already handled. `recorder::history` reports the catch-up;
//! `recorder::read-events after=<id> limit=<n>` reads one page, and
//! `recorder::resubscribe topic=<t>` narrows the subscription (which
//! also narrows what history shows); `recorder::subscribe topic=<t>`
//! adds one.
//!
//! H2: `recorder::read-state device=<id>` and `recorder::list-state`
//! read the host's device-state projection through `host-state`.
//! Reading another plugin's devices needs a
//! `[[capabilities.reads_state]]` grant, which the shipped manifest
//! deliberately leaves out (tests stage one in).

use oxidhome_sdk::Plugin;
use oxidhome_sdk::bindings::oxidhome::plugin::devices::{Command, CommandResult};
use oxidhome_sdk::bindings::oxidhome::plugin::events::{Event, EventPayload};
use oxidhome_sdk::bindings::oxidhome::plugin::types::{Error, KeyValue, SubscriptionId, Value};
use oxidhome_sdk::host;
use oxidhome_sdk::host::events::{Cursor, EventRead, History};

/// KV key holding the last handled row id.
const CURSOR_KEY: &str = "cursor";

#[derive(Default)]
struct EventRecorder {
    /// How many new events `on_event` has received this run.
    count: i64,
    /// Events `on_event` skipped because the catch-up handled them.
    duplicates: i64,
    /// Events replayed from history during `init`.
    caught_up: i64,
    /// Whether the saved cursor had expired at `init`.
    expired: bool,
    cursor: Cursor,
    subscriptions: Vec<SubscriptionId>,
}

impl EventRecorder {
    /// Save the cursor. Best effort: without a storage grant the
    /// recorder still works, it just starts over after a restart.
    fn save_cursor(&self) {
        let _ = host::storage::set_typed(CURSOR_KEY, &self.cursor.after_id());
    }

    /// Replay history after the saved cursor, up to the head.
    fn catch_up(&mut self) -> Result<(), String> {
        loop {
            let mut history = History::new(self.cursor.after_id());
            for event in history.by_ref() {
                let event = event.map_err(|e| format!("history read failed: {e:?}"))?;
                if self.cursor.advance(&event) {
                    self.caught_up += 1;
                    log_event(&event, self.count + self.caught_up);
                }
            }
            if let Some(expired) = history.expired() {
                oxidhome_sdk::tracing::warn!(
                    after_id = expired.after_id,
                    head_id = expired.head_id,
                    "event-recorder cursor expired; resuming from the head",
                );
                self.expired = true;
                self.cursor = Cursor::new(expired.head_id);
                break;
            }
            self.cursor.skip_to(history.after_id());
            // Checkpoint each batch, so a restart resumes from here.
            self.save_cursor();
            if history.caught_up() {
                break;
            }
        }
        self.save_cursor();
        Ok(())
    }
}

impl Plugin for EventRecorder {
    fn init(&mut self) -> Result<(), String> {
        let _ = oxidhome_sdk::logging::init();
        // Subscribe before reading history, so nothing published
        // during the catch-up is missed; `on_event` drops the overlap.
        let id = host::subscribe_all().map_err(|e| format!("subscribe failed: {e:?}"))?;
        self.subscriptions.push(id);
        let saved = match host::storage::get_typed::<u64>(CURSOR_KEY) {
            Ok(saved) => saved.unwrap_or(0),
            // No storage grant: run without a saved cursor.
            Err(host::storage::StorageError::Host(Error::PermissionDenied(_))) => 0,
            // Anything else would silently restart from the oldest
            // row; refuse to start instead.
            Err(e) => return Err(format!("reading the saved cursor failed: {e}")),
        };
        self.cursor = Cursor::new(saved);
        self.catch_up()?;
        oxidhome_sdk::tracing::info!(caught_up = self.caught_up, "event-recorder ready");
        Ok(())
    }

    fn shutdown(&mut self) {
        oxidhome_sdk::tracing::info!("event-recorder stopped");
    }

    fn on_event(&mut self, event: Event) {
        if !self.cursor.advance(&event) {
            self.duplicates += 1;
            return;
        }
        self.count += 1;
        log_event(&event, self.count);
        // Checkpoint only once the event is handled, so a crash before
        // this point replays it rather than skipping it.
        if event.row_id.is_some() {
            self.save_cursor();
        }
    }

    fn execute_command(&mut self, _device: String, cmd: Command) -> CommandResult {
        match (cmd.capability.as_str(), cmd.action.as_str()) {
            ("recorder", "count") => CommandResult::OkWithState(vec![KeyValue {
                key: "count".into(),
                value: Value::IntVal(self.count),
            }]),
            ("recorder", "history") => CommandResult::OkWithState(vec![
                int("caught_up", self.caught_up),
                int("duplicates", self.duplicates),
                uint("cursor", self.cursor.after_id()),
                KeyValue {
                    key: "expired".into(),
                    value: Value::BoolVal(self.expired),
                },
            ]),
            ("recorder", "read-events") => read_events(&cmd.args),
            ("recorder", "resubscribe") => self.resubscribe(&cmd.args, true),
            ("recorder", "subscribe") => self.resubscribe(&cmd.args, false),
            ("recorder", "read-state") => read_state(&cmd.args),
            ("recorder", "list-state") => {
                match host::state::list_all(&host::state::StateFilter {
                    device: None,
                    capability: None,
                }) {
                    Ok(entries) => CommandResult::OkWithState(vec![KeyValue {
                        key: "entries".into(),
                        value: Value::IntVal(i64::try_from(entries.len()).unwrap_or(i64::MAX)),
                    }]),
                    Err(e) => CommandResult::Err(e),
                }
            }
            _ => CommandResult::Err(Error::InvalidArgument(format!(
                "unsupported {}::{}",
                cmd.capability, cmd.action,
            ))),
        }
    }
}

impl EventRecorder {
    /// `recorder::resubscribe topic=<t>`: replace every subscription
    /// with one on `topic` (`replace`); `recorder::subscribe topic=<t>`
    /// adds one.
    fn resubscribe(&mut self, args: &[KeyValue], replace: bool) -> CommandResult {
        let Some(Value::StringVal(topic)) = arg(args, "topic") else {
            return CommandResult::Err(Error::InvalidArgument("missing `topic` argument".into()));
        };
        if replace {
            for id in self.subscriptions.drain(..) {
                let _ = host::unsubscribe(id);
            }
        }
        match host::subscribe_topic(topic.clone()) {
            Ok(id) => {
                self.subscriptions.push(id);
                CommandResult::OkWithState(Vec::new())
            }
            Err(e) => CommandResult::Err(e),
        }
    }
}

/// Log one handled event (live or replayed) in a stable shape, so the
/// integration test's log-capture assertion can match it.
fn log_event(event: &Event, seen: i64) {
    let topic = match &event.payload {
        EventPayload::StateChanged(sc) => sc.capability.clone(),
        EventPayload::Button(_) => "button".to_string(),
        EventPayload::Inference(_) => "inference".to_string(),
        EventPayload::Custom(c) => c.topic.clone(),
    };
    let device = event.device.as_deref().unwrap_or("<no-device>");
    oxidhome_sdk::tracing::info!(
        topic = %topic,
        device = %device,
        count = seen,
        "event-recorder received event",
    );
}

fn arg<'a>(args: &'a [KeyValue], key: &str) -> Option<&'a Value> {
    args.iter().find(|kv| kv.key == key).map(|kv| &kv.value)
}

fn int(key: &str, v: i64) -> KeyValue {
    KeyValue {
        key: key.into(),
        value: Value::IntVal(v),
    }
}

fn uint(key: &str, v: u64) -> KeyValue {
    int(key, i64::try_from(v).unwrap_or(i64::MAX))
}

/// `recorder::read-events after=<id> limit=<n>`: one page of history,
/// summarized as `ids` (comma-separated row ids), `next_after_id`,
/// `head_id`, and counts of `bytes` fields and `withheld` markers; or
/// `expired_head_id` / `expired_oldest_id` for an expired cursor.
fn read_events(args: &[KeyValue]) -> CommandResult {
    let num = |key| match arg(args, key) {
        Some(Value::IntVal(n)) => u64::try_from(*n).unwrap_or(0),
        _ => 0,
    };
    let limit = u32::try_from(num("limit")).unwrap_or(u32::MAX);
    match host::events::read_after(num("after"), limit) {
        Ok(EventRead::Page(page)) => {
            let ids: Vec<String> = page
                .events
                .iter()
                .filter_map(|e| e.row_id)
                .map(|id| id.to_string())
                .collect();
            let (mut bytes, mut withheld) = (0, 0);
            for event in &page.events {
                if let EventPayload::StateChanged(sc) = &event.payload {
                    for kv in &sc.fields {
                        match &kv.value {
                            Value::BytesVal(_) => bytes += 1,
                            Value::JsonVal(j)
                                if j.starts_with("{\"withheld\":\"bytes\",")
                                    && j.ends_with("\"required_scope\":\"reads_event_bytes\"}") =>
                            {
                                withheld += 1;
                            }
                            _ => {}
                        }
                    }
                }
            }
            CommandResult::OkWithState(vec![
                KeyValue {
                    key: "ids".into(),
                    value: Value::StringVal(ids.join(",")),
                },
                uint("next_after_id", page.next_after_id),
                uint("head_id", page.head_id),
                int("bytes", bytes),
                int("withheld", withheld),
            ])
        }
        Ok(EventRead::CursorExpired(expired)) => CommandResult::OkWithState(vec![
            uint("expired_head_id", expired.head_id),
            uint("expired_oldest_id", expired.oldest_id.unwrap_or(0)),
        ]),
        Err(e) => CommandResult::Err(e),
    }
}

/// `recorder::read-state device=<id>`: read another device's current
/// state through the H2 `host-state` import (needs a
/// `[[capabilities.reads_state]]` grant) and echo it back as
/// `<capability>.<field>` keys plus `<capability>.quality`.
fn read_state(args: &[KeyValue]) -> CommandResult {
    let Some(Value::StringVal(device)) = arg(args, "device") else {
        return CommandResult::Err(Error::InvalidArgument("missing `device` argument".into()));
    };
    let entries = match host::state::get(device) {
        Ok(entries) => entries,
        Err(e) => return CommandResult::Err(e),
    };
    let mut out = Vec::new();
    for entry in entries {
        let quality = if host::state::is_fresh(&entry) {
            "fresh"
        } else {
            "stale"
        };
        out.push(KeyValue {
            key: format!("{}.quality", entry.capability),
            value: Value::StringVal(quality.into()),
        });
        for kv in entry.fields {
            out.push(KeyValue {
                key: format!("{}.{}", entry.capability, kv.key),
                value: kv.value,
            });
        }
    }
    CommandResult::OkWithState(out)
}

oxidhome_sdk::plugin!(EventRecorder);
