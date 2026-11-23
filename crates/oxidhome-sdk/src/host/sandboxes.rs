//! Script sandboxes from the plugin side of the WIT `host-sandboxes`
//! interface (ADR-0001).
//!
//! A scripting plugin runs each user script in its own sandbox: a
//! child instance of the calling instance, built from the same
//! component, with its own store and supervisor. The component's
//! [`Plugin::init`](crate::Plugin::init) calls
//! [`current`](crate::host::sandboxes::current) to tell the
//! two roles apart: `None` in the instance the operator started,
//! `Some(script)` inside a sandbox.
//!
//! Scripts call each other through
//! [`crate::host::call_service`], like any other
//! cross-instance call, so the host's `consumes_services` grants,
//! deadlines, cycle checks and audit apply. A script addresses another
//! by its sandbox instance id,
//! [`instance_id`](crate::host::sandboxes::instance_id)`(parent, local_id)`.
//!
//! Starting sandboxes needs `[capabilities] script_sandboxes` > 0 in
//! the manifest. End-to-end coverage lives in
//! `oxidhome-core/tests/script_sandboxes.rs` with the `script-host`
//! example.
//
// rustdoc merges these docs with the `sandboxes` item docs in
// `host.rs` and resolves links from the `host` module, so the targets
// above are crate-absolute paths.

use crate::bindings::oxidhome::plugin::host_sandboxes;
pub use crate::bindings::oxidhome::plugin::host_sandboxes::{SandboxInfo, SandboxScript};
use crate::bindings::oxidhome::plugin::types::Error;

/// Separator between a parent instance id and a script's local id in a
/// sandbox instance id.
pub const SEPARATOR: char = '~';

/// The instance id of the sandbox `local_id` started by `parent`.
#[must_use]
pub fn instance_id(parent: &str, local_id: &str) -> String {
    format!("{parent}{SEPARATOR}{local_id}")
}

/// Start a sandbox running `source` and return its instance id. Starting
/// a live `local_id` again with the same source returns the same id.
///
/// # Errors
///
/// [`Error::PermissionDenied`] when `script_sandboxes` is 0 or this
/// instance is itself a sandbox; [`Error::InvalidArgument`] for a bad
/// `local_id`, oversized source, or a live `local_id` running different
/// source; [`Error::Unavailable`] when the limit is reached or a
/// previous sandbox with this id is still stopping.
pub fn start(local_id: &str, source: &str) -> Result<String, Error> {
    host_sandboxes::start_sandbox(local_id, source)
}

/// Stop a sandbox this instance started. It stops in the background.
///
/// # Errors
///
/// [`Error::NotFound`] if no such sandbox is live.
pub fn stop(local_id: &str) -> Result<(), Error> {
    host_sandboxes::stop_sandbox(local_id)
}

/// The live sandboxes this instance started.
#[must_use]
pub fn list() -> Vec<SandboxInfo> {
    host_sandboxes::list_sandboxes()
}

/// Inside a sandbox, the script it runs; `None` elsewhere.
#[must_use]
pub fn current() -> Option<SandboxScript> {
    host_sandboxes::current_sandbox()
}

#[cfg(test)]
mod tests {
    #[test]
    fn instance_id_uses_the_separator() {
        assert_eq!(super::instance_id("main", "house-mode"), "main~house-mode");
    }
}
