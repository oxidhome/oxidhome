//! Read access to the host-owned device-state projection (H2), the
//! plugin side of the WIT `host-state` interface.
//!
//! - [`get`] — every visible capability entry of one device.
//! - [`list`] — one page of visible entries, optionally filtered by
//!   device and capability.
//! - [`list_all`] — [`list`] followed page by page.
//! - [`field`] — look one field up in an entry.
//!
//! A plugin always sees the devices it registered itself. Other
//! devices need a `[[capabilities.reads_state]]` grant in the
//! manifest:
//!
//! ```toml
//! [[capabilities.reads_state]]
//! plugin = "example.simulated-switch"
//! capabilities = ["switch"]
//! ```
//!
//! Check [`DeviceState::quality`]: a `stale` entry is the last value
//! the host knew, not a live reading (the owner stopped, the device was
//! removed, or the host restarted and the owner hasn't republished).
//!
//! These functions call wit-bindgen import stubs, so they only link
//! inside a wasm component; see the coverage note in [`super`].
//!
//! [`get`]: crate::host::state::get
//! [`list`]: crate::host::state::list
//! [`list_all`]: crate::host::state::list_all
//! [`field`]: crate::host::state::field
//! [`DeviceState::quality`]: crate::bindings::oxidhome::plugin::host_state::DeviceState
//! [`super`]: crate::host

use crate::bindings::oxidhome::plugin::host_state;
pub use crate::bindings::oxidhome::plugin::host_state::{
    DeviceState, StateFilter, StatePage, StateQuality,
};
use crate::bindings::oxidhome::plugin::types::{Error, Value};

/// Pages [`list_all`] reads before it stops (64 devices each, so up to
/// 4096 devices). Guards a plugin against an unbounded loop.
pub const MAX_LIST_ALL_PAGES: usize = 64;

/// Every visible capability entry of `device`, sorted by capability.
///
/// # Errors
///
/// [`Error::NotFound`] when nothing is visible: the host has no state
/// for the device, or none of it is visible to this plugin (the host
/// doesn't say which).
pub fn get(device: &str) -> Result<Vec<DeviceState>, Error> {
    host_state::get_state(device)
}

/// One page of visible entries matching `filter`. Pass `None` for the
/// first page and the previous page's `next_cursor` after that.
/// `limit` is in devices (0 means the host default). A page can be
/// short, or empty, while `next_cursor` is set.
///
/// # Errors
///
/// Forwards any host [`Error`]; [`Error::InvalidArgument`] for a cursor
/// from an earlier host process.
pub fn list(filter: &StateFilter, cursor: Option<&str>, limit: u32) -> Result<StatePage, Error> {
    host_state::list_state(filter, cursor, limit)
}

/// Every visible entry matching `filter`, reading at most
/// [`MAX_LIST_ALL_PAGES`] pages (a result cut off there is partial;
/// use [`list`] to page further). Pages are separate reads, so entries
/// from different pages may come from different revisions; compare
/// [`DeviceState::revision`] when that matters.
///
/// # Errors
///
/// Forwards any host [`Error`].
pub fn list_all(filter: &StateFilter) -> Result<Vec<DeviceState>, Error> {
    let mut out = Vec::new();
    let mut cursor: Option<String> = None;
    for _ in 0..MAX_LIST_ALL_PAGES {
        let page = list(filter, cursor.as_deref(), 0)?;
        out.extend(page.entries);
        match page.next_cursor {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }
    Ok(out)
}

/// The value of `key` in `entry`, if present.
#[must_use]
pub fn field<'a>(entry: &'a DeviceState, key: &str) -> Option<&'a Value> {
    entry
        .fields
        .iter()
        .find(|kv| kv.key == key)
        .map(|kv| &kv.value)
}

/// Whether `entry` is a live value from the owner's current life.
#[must_use]
pub fn is_fresh(entry: &DeviceState) -> bool {
    matches!(entry.quality, StateQuality::Fresh)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bindings::oxidhome::plugin::types::KeyValue;

    fn entry(quality: StateQuality) -> DeviceState {
        DeviceState {
            device: "dev-1".into(),
            capability: "switch".into(),
            fields: vec![KeyValue {
                key: "on".into(),
                value: Value::BoolVal(true),
            }],
            revision: 1,
            received_ms: 2,
            observed_ms: 3,
            quality,
        }
    }

    #[test]
    fn field_and_freshness_helpers() {
        let e = entry(StateQuality::Fresh);
        assert!(matches!(field(&e, "on"), Some(Value::BoolVal(true))));
        assert!(field(&e, "missing").is_none());
        assert!(is_fresh(&e));
        assert!(!is_fresh(&entry(StateQuality::Stale)));
    }
}
