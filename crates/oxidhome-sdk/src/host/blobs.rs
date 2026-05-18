//! Per-instance blob store from the plugin side of the WIT
//! `blob-store` interface — Phase 5b.
//!
//! Mirrors the WIT surface verbatim (no streaming resource handles
//! yet — the WIT itself is buffered for Phase 5b v1). Plugin
//! authors call `oxidhome_sdk::host::blobs::write(name, &bytes,
//! Some("image/jpeg"))` to store a blob, then `read_by_name` /
//! `read` to fetch it back, `list_blobs` to enumerate, `delete` to
//! drop one.
//!
//! All entry points forward into wit-bindgen-generated stubs;
//! calling them from a native test binary fails to link. End-to-end
//! coverage lives in `oxidhome-core/tests/blob_persistence.rs`
//! against `Engine::with_state_dir`.

use crate::bindings::oxidhome::plugin::blob_store;
pub use crate::bindings::oxidhome::plugin::blob_store::{BlobId, BlobInfo};
use crate::bindings::oxidhome::plugin::types::Error;

/// Write a blob in one shot. `name` is the human-readable key the
/// plugin will use to fetch / overwrite later (e.g.
/// `"snapshot-2026-05-08T10-15-00.jpg"`). Overwriting an existing
/// name is atomic on the host side — readers always see the old
/// blob or the new one, never a half-written file. Returns the
/// host-minted [`BlobId`] for the new blob; plugins that pass IDs
/// around (e.g. through a `state-changed` event) can use [`read`]
/// against it.
///
/// # Errors
///
/// Forwards any host [`Error`] — typically [`Error::PermissionDenied`]
/// when the manifest's `blob_quota_mb` is `0` or the write would
/// exceed the quota.
pub fn write(name: &str, data: &[u8], mime: Option<&str>) -> Result<BlobId, Error> {
    blob_store::write(name, data, mime)
}

/// Read a blob by its host-minted ID.
///
/// # Errors
///
/// [`Error::NotFound`] when no blob with that id exists for this
/// instance.
pub fn read(id: &BlobId) -> Result<Vec<u8>, Error> {
    blob_store::read(id)
}

/// Read a blob by the user-chosen name. The common case — plugins
/// usually pick the name at write time and fetch by name later.
///
/// # Errors
///
/// [`Error::NotFound`] when no blob with that name exists for this
/// instance.
pub fn read_by_name(name: &str) -> Result<Vec<u8>, Error> {
    blob_store::read_by_name(name)
}

/// Look up metadata without fetching the byte payload. Useful for
/// `list_blobs` consumers that need one specific row's details.
///
/// # Errors
///
/// [`Error::NotFound`] if no blob with that name.
pub fn get_info(name: &str) -> Result<BlobInfo, Error> {
    blob_store::get_info(name)
}

/// Drop a blob by name. Returns `Ok(())` whether the blob existed
/// or not (the WIT delete contract makes no distinction).
///
/// # Errors
///
/// Forwards host errors.
pub fn delete(name: &str) -> Result<(), Error> {
    blob_store::delete(name)
}

/// List blobs whose name starts with `prefix`. Empty prefix
/// enumerates every blob the instance owns. Ordering is
/// lexicographic by name.
///
/// # Errors
///
/// Forwards host errors.
pub fn list_blobs(prefix: &str) -> Result<Vec<BlobInfo>, Error> {
    blob_store::list_blobs(prefix)
}
