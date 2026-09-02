//! Exclusive per-state-dir file lock (round-1 P1 on PR #143).
//!
//! The [`crate::Engine`]'s in-memory registries —
//! [`crate::DeviceRegistry`], [`crate::InstanceRegistry`],
//! [`crate::EventBus`], the service registry, per-plugin
//! lifecycle locks — are per-process and NOT synchronised
//! through the shared `SQLite` state file. Two `Engine`s
//! against the same state dir would race on plugin start /
//! uninstall and see divergent supervisor bookkeeping; the
//! `mcp-stdio` subprocess could greenlight
//! `plugins.uninstall` because its local instance registry is
//! empty while the HTTP daemon still holds the plugin's file
//! handles open.
//!
//! The lock file lives at `<state_dir>/.oxidhome.lock` and is
//! held via `flock(LOCK_EX | LOCK_NB)` for the calling
//! process's lifetime — kernel drops it on process exit, so
//! there's no shutdown plumbing needed. The returned `File`
//! MUST be kept in scope; dropping it releases the lock.
//!
//! Unix-only for now — matches the daemon's supported target
//! list (see `ARCHITECTURE.md`). A Windows implementation
//! via `LockFileEx` is straightforward when needed.

use std::fs::File;
use std::path::Path;

use anyhow::Context;

/// File name of the lock file, relative to the state dir.
pub const LOCK_FILE_NAME: &str = ".oxidhome.lock";

/// Acquire an exclusive lock on `<state_dir>/.oxidhome.lock`.
/// Returns the open `File` on success; the caller MUST keep it
/// alive for as long as it wants the lock held (dropping the
/// file releases the lock).
///
/// Fails fast (does NOT block) when another process already
/// holds the lock — returning a clear error naming the state
/// dir so an operator can find the conflicting process.
///
/// # Errors
///
/// - `state_dir` couldn't be created or the lock file couldn't
///   be opened.
/// - Another process holds the exclusive lock on the file.
pub fn acquire_state_dir_lock(state_dir: &Path) -> anyhow::Result<File> {
    std::fs::create_dir_all(state_dir).with_context(|| {
        format!(
            "creating state dir {} before acquiring exclusive lock",
            state_dir.display(),
        )
    })?;
    let lock_path = state_dir.join(LOCK_FILE_NAME);
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .with_context(|| format!("opening state-dir lock file {}", lock_path.display()))?;
    try_lock_exclusive(&file, state_dir)?;
    Ok(file)
}

#[cfg(unix)]
fn try_lock_exclusive(file: &File, state_dir: &Path) -> anyhow::Result<()> {
    use std::os::unix::io::AsRawFd;

    // SAFETY: `file.as_raw_fd()` is a valid, open file
    // descriptor for the lifetime of `file` (which we borrow).
    // `LOCK_EX | LOCK_NB` returns -1 on contention with
    // `errno == EWOULDBLOCK`; we surface that as a clear
    // diagnostic rather than blocking (a blocking acquire
    // would silently hang a fresh `oxidhome mcp-stdio`
    // launched while the daemon is running).
    // Retry on EINTR: `flock(2)` is a system call and can be
    // interrupted by an incoming signal. Treating that as a
    // hard failure would surface as a spurious "flock failed"
    // diagnostic on a daemon that just happened to catch a
    // SIGCHLD (or any handler-installed signal) mid-startup
    // — round-4 Copilot on PR #143. The loop is bounded by
    // the kernel's actual acquisition outcome; a genuinely
    // contended lock still returns EWOULDBLOCK/EAGAIN
    // immediately (LOCK_NB), and a genuinely broken syscall
    // returns EBADF/EINVAL/etc. without cycling.
    let rc = loop {
        // SAFETY: `file.as_raw_fd()` is a valid, open file
        // descriptor for the lifetime of `file` (borrowed).
        #[allow(unsafe_code)]
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        break rc;
    };
    if rc == -1 {
        let err = std::io::Error::last_os_error();
        // `EWOULDBLOCK` / `EAGAIN` both mean "another holder
        // has the lock." POSIX permits `EAGAIN`; Linux aliases
        // it to `EWOULDBLOCK` but not every Unix does, so
        // matching both keeps the contention diagnostic
        // correct across platforms (round-3 Copilot on PR
        // #143). Other errno values (`EBADF`, `EINVAL`,
        // `ENOLCK`, permission errors on quirky filesystems)
        // surface with the raw error so an operator can
        // distinguish "someone else is running" from "this
        // filesystem doesn't support flock" — round-2 P2 on
        // PR #143 flagged the prior misleading catch-all.
        let raw = err.raw_os_error();
        if raw == Some(libc::EWOULDBLOCK) || raw == Some(libc::EAGAIN) {
            anyhow::bail!(
                "another `oxidhome` process is already using state dir {} \
                 (set $OXIDHOME_STATE_DIR to a distinct dir, or stop the other process)",
                state_dir.display(),
            );
        }
        anyhow::bail!(
            "acquiring exclusive lock on state dir {} failed: {} \
             (this filesystem may not support flock — check the state-dir setup)",
            state_dir.display(),
            err,
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn try_lock_exclusive(_file: &File, state_dir: &Path) -> anyhow::Result<()> {
    // Non-Unix hosts aren't officially supported for the
    // daemon today. Rather than silently skipping the check —
    // which is the property this module is here to
    // guarantee — refuse the launch and point the operator
    // at the Unix build.
    anyhow::bail!(
        "exclusive state-dir ownership is currently only enforced on Unix; \
         the `oxidhome` daemon and `mcp-stdio` subprocess are unsupported on this platform \
         (state dir: {})",
        state_dir.display(),
    )
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn second_lock_on_same_dir_fails_fast() {
        let dir = tempdir();
        let first =
            acquire_state_dir_lock(dir.path()).expect("first lock on empty dir must succeed");
        let err =
            acquire_state_dir_lock(dir.path()).expect_err("second lock must fail; got success");
        let msg = format!("{err:#}");
        assert!(
            msg.contains(&dir.path().display().to_string()),
            "diagnostic must name the state dir; got: {msg}",
        );
        // Round-2 P2 on PR #143: diagnostic must specifically
        // name "another process" for the EWOULDBLOCK path
        // (contrasted with generic "flock failed" for other
        // errno).
        assert!(
            msg.contains("already using"),
            "diagnostic must identify the contention case; got: {msg}",
        );
        drop(first);
        // Once the first lock is dropped a fresh acquire
        // succeeds — the kernel releases the flock with the
        // file handle.
        let _third = acquire_state_dir_lock(dir.path()).expect("post-drop reacquire must succeed");
    }

    #[test]
    fn distinct_dirs_are_independent() {
        let a = tempdir();
        let b = tempdir();
        let _la = acquire_state_dir_lock(a.path()).expect("lock a");
        let _lb = acquire_state_dir_lock(b.path()).expect("lock b");
    }

    #[test]
    fn creates_missing_state_dir() {
        let parent = tempdir();
        let nested = parent.path().join("fresh").join("state");
        assert!(!nested.exists());
        let _lock = acquire_state_dir_lock(&nested).expect("acquire on missing dir");
        assert!(nested.is_dir(), "state dir must be created");
        assert!(
            nested.join(LOCK_FILE_NAME).is_file(),
            "lock file must be created inside it",
        );
    }

    /// Minimal tempdir helper — the test crate's `_support`
    /// tempdir isn't reachable from a lib-crate `mod tests`.
    /// RAII cleanup on drop.
    struct TempDir {
        path: std::path::PathBuf,
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
    impl TempDir {
        fn path(&self) -> &Path {
            &self.path
        }
    }
    fn tempdir() -> TempDir {
        // Uniqueness within this process comes from a static
        // atomic counter. `create_dir` (not `create_dir_all`)
        // fails if the dir already exists, so we retry with a
        // fresh suffix — that closes the round-3 Copilot
        // finding on PR #143 (pid+nanos alone could collide
        // across a very tight loop).
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let base_dir = std::env::temp_dir();
        let pid = std::process::id();
        loop {
            let n = SEQ.fetch_add(1, Ordering::Relaxed);
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos());
            let candidate = base_dir.join(format!("oxidhome-lock-test-{pid}-{nanos}-{n}"));
            match std::fs::create_dir(&candidate) {
                Ok(()) => return TempDir { path: candidate },
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(err) => panic!("mk tempdir: {err}"),
            }
        }
    }
}
