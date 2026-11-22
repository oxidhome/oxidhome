//! Minimal self-deleting temp directory for the host's state.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Removed (recursively, best effort) on drop.
#[derive(Debug)]
pub(crate) struct TempDir {
    path: PathBuf,
}

impl TempDir {
    /// Create `oxidhome-test-host-<pid>-<nanos>-<n>` under the system
    /// temp dir. The counter keeps two hosts created in the same
    /// nanosecond by one process apart.
    /// On failure, returns the path it tried to create with the error.
    pub(crate) fn new() -> Result<Self, (PathBuf, std::io::Error)> {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let path = std::env::temp_dir().join(format!(
            "oxidhome-test-host-{}-{nanos}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed),
        ));
        match std::fs::create_dir(&path) {
            Ok(()) => Ok(Self { path }),
            Err(e) => Err((path, e)),
        }
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
