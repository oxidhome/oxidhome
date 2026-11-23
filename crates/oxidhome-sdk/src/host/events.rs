//! Reads of the host's durable event history, the plugin side of
//! `host-events::read-events`.
//!
//! - [`read_after`] — one page of events after a cursor.
//! - [`History`] — an iterator over the pages up to the head.
//! - [`Cursor`] — the last `row-id` handled, to dedupe live delivery
//!   against a catch-up.
//!
//! History shows a plugin the events its current subscriptions match
//! (the ones `on-event` would deliver) plus host gap markers. It needs
//! `[capabilities] subscribes_events = true`; raw `bytes-val` fields
//! come back as a `json-val` marker unless the manifest also sets
//! `reads_event_bytes = true` (and the operator's grant keeps it).
//!
//! ## Resuming after a restart
//!
//! Keep the highest `row-id` you handled (for example in KV storage,
//! `host::storage`), and in `init`:
//!
//! 1. subscribe first, so nothing published during the catch-up is
//!    missed (it is delivered to `on-event` after `init` returns);
//! 2. read history from the saved cursor with [`History`] and handle
//!    each event;
//! 3. in `on-event`, skip events [`Cursor::advance`] has already seen.
//!
//! ```no_run
//! use oxidhome_sdk::host::{self, events::{Cursor, History}};
//!
//! # fn handle(_: &oxidhome_sdk::bindings::oxidhome::plugin::events::Event) {}
//! let mut cursor = Cursor::new(
//!     host::storage::get_typed::<u64>("cursor").ok().flatten().unwrap_or(0),
//! );
//! host::subscribe_topic("automation.").expect("subscribe");
//! loop {
//!     let mut history = History::new(cursor.after_id());
//!     for event in history.by_ref() {
//!         match event {
//!             Ok(event) => {
//!                 if cursor.advance(&event) {
//!                     handle(&event);
//!                 }
//!             }
//!             Err(err) => panic!("history: {err:?}"),
//!         }
//!     }
//!     if let Some(expired) = history.expired() {
//!         // Rows after the cursor were pruned: resume from the head
//!         // and rebuild what you track from `host::state`.
//!         cursor = Cursor::new(expired.head_id);
//!         break;
//!     }
//!     cursor.skip_to(history.after_id());
//!     // `History` stops after `MAX_HISTORY_PAGES` pages; go on until
//!     // it has reached the head.
//!     if history.caught_up() {
//!         break;
//!     }
//! }
//! let _ = host::storage::set_typed("cursor", &cursor.after_id());
//! ```
//!
//! The cursor only sees the events delivered to it. When a plugin's
//! live queue overflows, the host drops events for it (and logs a
//! warning), and the next delivered event moves the cursor past them.
//! A plugin that must not miss a recorded event can treat `on-event`
//! as a signal and handle events from history instead: read from its
//! cursor on each delivery, and handle directly only events without a
//! `row-id` (which history doesn't have).
//!
//! These functions call wit-bindgen import stubs, so they only link
//! inside a wasm component; see the coverage note in [`super`].
//!
//! [`read_after`]: crate::host::events::read_after
//! [`History`]: crate::host::events::History
//! [`Cursor`]: crate::host::events::Cursor
//! [`Cursor::advance`]: crate::host::events::Cursor::advance
//! [`super`]: crate::host

use crate::bindings::oxidhome::plugin::events::Event;
use crate::bindings::oxidhome::plugin::host_events;
pub use crate::bindings::oxidhome::plugin::host_events::{CursorExpired, EventPage, EventRead};
use crate::bindings::oxidhome::plugin::types::Error;

/// Pages [`History`] reads before it stops (up to 256 events each).
/// Guards a plugin against an unbounded loop; continue with a new
/// [`History`] from [`History::after_id`].
pub const MAX_HISTORY_PAGES: usize = 64;

/// One page of recorded events with `row-id > after_id` (see the
/// module docs for which events are visible). `limit` is in events;
/// 0 means the host default (64), and the host caps it at 256.
///
/// # Errors
///
/// [`Error::PermissionDenied`] without `subscribes_events`;
/// [`Error::Unavailable`] when the history can't be read.
pub fn read_after(after_id: u64, limit: u32) -> Result<EventRead, Error> {
    host_events::read_events(after_id, limit)
}

/// Iterator over recorded events after a cursor, page by page, until
/// it reaches the history head seen by the last page, the cursor
/// expires, a read fails, or [`MAX_HISTORY_PAGES`] pages were read.
///
/// An error is yielded once and ends the iteration. Check
/// [`Self::expired`] and [`Self::caught_up`] afterwards, and continue
/// from [`Self::after_id`].
#[derive(Debug)]
pub struct History {
    /// Resume cursor: past every event yielded so far, and past the
    /// whole page once its last event was yielded.
    after_id: u64,
    /// The current page's `next-after-id`; where the next read starts.
    page_end: u64,
    limit: u32,
    buffered: std::vec::IntoIter<Event>,
    pages: usize,
    /// No more reads: head reached, cursor expired or a read failed.
    done: bool,
    /// The last page reached the head.
    at_head: bool,
    expired: Option<CursorExpired>,
}

impl History {
    /// Start after `after_id` (0 is the oldest retained row) with the
    /// host's default page size.
    #[must_use]
    pub fn new(after_id: u64) -> Self {
        Self::with_limit(after_id, 0)
    }

    /// Like [`Self::new`] with `limit` events per page.
    #[must_use]
    pub fn with_limit(after_id: u64, limit: u32) -> Self {
        Self {
            after_id,
            page_end: after_id,
            limit,
            buffered: Vec::new().into_iter(),
            pages: 0,
            done: false,
            at_head: false,
            expired: None,
        }
    }

    /// The cursor to resume from: past every event this iterator has
    /// yielded, and past the rows this plugin can't see once a page
    /// has been yielded in full. Events still buffered are not
    /// covered, so stopping mid-page loses nothing.
    #[must_use]
    pub fn after_id(&self) -> u64 {
        self.after_id
    }

    /// The expiry report, if the cursor expired.
    #[must_use]
    pub fn expired(&self) -> Option<CursorExpired> {
        self.expired
    }

    /// Whether every event up to the head seen by the last page has
    /// been yielded. `false` after a failed read or an expired cursor.
    #[must_use]
    pub fn caught_up(&self) -> bool {
        self.at_head && self.buffered.as_slice().is_empty()
    }

    /// Take in one `read-events` answer.
    fn apply(&mut self, read: EventRead) {
        self.pages += 1;
        match read {
            EventRead::Page(page) => {
                self.page_end = self.page_end.max(page.next_after_id);
                self.at_head = page.next_after_id >= page.head_id;
                self.done = self.at_head;
                self.buffered = page.events.into_iter();
                self.settle();
            }
            EventRead::CursorExpired(expired) => {
                self.expired = Some(expired);
                self.done = true;
            }
        }
    }

    /// Once the page is fully yielded, the cursor moves to its end.
    fn settle(&mut self) {
        if self.buffered.as_slice().is_empty() {
            self.after_id = self.after_id.max(self.page_end);
        }
    }
}

impl Iterator for History {
    type Item = Result<Event, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(event) = self.buffered.next() {
                if let Some(id) = event.row_id {
                    self.after_id = self.after_id.max(id);
                }
                self.settle();
                return Some(Ok(event));
            }
            if self.done || self.pages >= MAX_HISTORY_PAGES {
                return None;
            }
            match read_after(self.page_end, self.limit) {
                Ok(read) => self.apply(read),
                Err(err) => {
                    self.done = true;
                    return Some(Err(err));
                }
            }
        }
    }
}

/// The highest `row-id` a plugin has handled, used to drop the
/// duplicates between a history catch-up and live `on-event`
/// delivery.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Cursor {
    after_id: u64,
}

impl Cursor {
    /// A cursor after `after_id` (0: nothing handled yet).
    #[must_use]
    pub fn new(after_id: u64) -> Self {
        Self { after_id }
    }

    /// The highest row id handled so far.
    #[must_use]
    pub fn after_id(&self) -> u64 {
        self.after_id
    }

    /// Record `event` and return whether it is new: `false` for an
    /// event whose `row-id` is at or below the cursor. An event
    /// without a row id is not in history (the host couldn't record
    /// it); it is always new and leaves the cursor where it is.
    pub fn advance(&mut self, event: &Event) -> bool {
        match event.row_id {
            Some(id) if id <= self.after_id => false,
            Some(id) => {
                self.after_id = id;
                true
            }
            None => true,
        }
    }

    /// Move the cursor forward to `after_id` (e.g. a page's
    /// `next-after-id`, past rows this plugin can't see). Never moves
    /// it back.
    pub fn skip_to(&mut self, after_id: u64) {
        self.after_id = self.after_id.max(after_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bindings::oxidhome::plugin::events::{CustomEvent, EventPayload};

    fn event(row_id: Option<u64>) -> Event {
        Event {
            device: None,
            timestamp: 0,
            origin_plugin_id: String::new(),
            origin_instance_id: String::new(),
            row_id,
            payload: EventPayload::Custom(CustomEvent {
                topic: "t".into(),
                payload: String::new(),
            }),
        }
    }

    #[test]
    fn cursor_drops_seen_rows_and_keeps_unrecorded_events() {
        let mut cursor = Cursor::new(5);
        assert!(!cursor.advance(&event(Some(5))));
        assert!(!cursor.advance(&event(Some(3))));
        assert!(cursor.advance(&event(Some(6))));
        assert_eq!(cursor.after_id(), 6);
        assert!(cursor.advance(&event(None)));
        assert_eq!(cursor.after_id(), 6);
        cursor.skip_to(4);
        assert_eq!(cursor.after_id(), 6);
        cursor.skip_to(9);
        assert_eq!(cursor.after_id(), 9);
    }

    #[test]
    fn history_follows_pages_and_expiry() {
        let mut history = History::new(2);
        history.apply(EventRead::Page(EventPage {
            events: vec![event(Some(4)), event(Some(6))],
            next_after_id: 7,
            head_id: 10,
        }));
        // Nothing yielded yet: the cursor stays put.
        assert_eq!(history.after_id(), 2);
        assert!(!history.done);
        assert!(!history.caught_up());
        assert_eq!(
            history.next().map(|e| e.ok().and_then(|e| e.row_id)),
            Some(Some(4))
        );
        assert_eq!(history.after_id(), 4);
        assert_eq!(
            history.next().map(|e| e.ok().and_then(|e| e.row_id)),
            Some(Some(6))
        );
        // The page is fully yielded: past its skipped rows too.
        assert_eq!(history.after_id(), 7);
        history.apply(EventRead::Page(EventPage {
            events: Vec::new(),
            next_after_id: 10,
            head_id: 10,
        }));
        assert_eq!(history.after_id(), 10);
        assert!(history.caught_up());
        assert!(history.next().is_none());

        let mut expired = History::new(1);
        expired.apply(EventRead::CursorExpired(CursorExpired {
            after_id: 1,
            oldest_id: Some(5),
            head_id: 9,
        }));
        assert!(!expired.caught_up());
        assert_eq!(expired.expired().map(|e| e.head_id), Some(9));
        assert!(expired.next().is_none());

        // A failed read ends the iteration without claiming the head.
        let mut failed = History::new(1);
        failed.done = true;
        assert!(!failed.caught_up());
    }
}
