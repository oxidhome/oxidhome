//! First-run admin-token bootstrap.
//!
//! On daemon startup, if the token store is empty, mint one
//! full-access token with label `admin` and write the plaintext to
//! `<state_dir>/admin-token` (mode 0o600). The operator picks it up
//! once for first-time CLI / API setup; from then on it's treated
//! like any other token and can be rotated or revoked.
//!
//! The file is **only** written when the store is empty — a fresh
//! engine with persisted tokens already on disk won't have its
//! `admin-token` overwritten. The plaintext only exists in this file
//! and in operator memory; the store keeps just the hash.

use std::path::Path;
use std::sync::Arc;

use anyhow::Context;

use crate::state::{IssuedToken, TokenStore};

/// Default scope blob for the bootstrap token — the JSON `"*"`
/// sentinel that future scope-policy enforcement will treat as
/// "all scopes". The shape is intentionally trivial in this PR;
/// 12-API-b lands the full scope-policy parser.
const ADMIN_SCOPE_JSON: &[u8] = b"\"*\"";

/// If `tokens` is empty, mint an `admin` token and write its
/// plaintext to `<state_dir>/admin-token`. Returns `Some(token)` if
/// a new admin was issued, `None` if the store already had tokens
/// (so the caller can log the right one-liner).
///
/// **Filesystem permissions.** The token file is created with mode
/// `0o600` on Unix so a misconfigured state dir doesn't leak the
/// secret to other local users. On non-Unix platforms the mode bits
/// are ignored — `state_dir` is expected to be operator-owned.
///
/// # Errors
///
/// - DB errors from [`TokenStore::count`] / [`TokenStore::create`].
/// - I/O errors creating or writing the file. The token row stays
///   in the DB on file-write failure; the caller can log the id
///   and rotate manually rather than re-mint.
pub fn ensure_admin_token(
    tokens: &Arc<TokenStore>,
    state_dir: &Path,
) -> anyhow::Result<Option<IssuedToken>> {
    let count = tokens.count().context("counting tokens")?;
    if count > 0 {
        return Ok(None);
    }

    let issued = tokens
        .create("admin", ADMIN_SCOPE_JSON)
        .context("minting admin token")?;

    let path = state_dir.join("admin-token");
    write_secret(&path, &issued.plaintext)
        .with_context(|| format!("writing admin token to {}", path.display()))?;

    tracing::info!(
        token_id = %issued.id,
        path = %path.display(),
        "minted admin token (first-run bootstrap)",
    );

    Ok(Some(issued))
}

/// Write `secret` to `path` with `0o600` permissions on Unix. The
/// permissions are set before the bytes go in — a partial-write
/// failure can't leave a world-readable file behind.
fn write_secret(path: &Path, secret: &str) -> std::io::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(secret.as_bytes())?;
    f.write_all(b"\n")?;
    f.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::Db;

    #[test]
    fn bootstrap_mints_when_store_empty() {
        let tmp = tempdir();
        let tokens = Arc::new(TokenStore::new(Arc::new(Db::open_in_memory().unwrap())));
        let issued = ensure_admin_token(&tokens, tmp.path())
            .expect("bootstrap")
            .expect("a token should have been minted");
        let on_disk = std::fs::read_to_string(tmp.path().join("admin-token")).unwrap();
        assert!(on_disk.starts_with("oxh_"));
        assert!(on_disk.contains(&issued.plaintext));
    }

    #[test]
    fn bootstrap_is_no_op_when_store_has_tokens() {
        let tmp = tempdir();
        let tokens = Arc::new(TokenStore::new(Arc::new(Db::open_in_memory().unwrap())));
        // Pre-seed.
        tokens.create("preexisting", b"{}").unwrap();
        let outcome = ensure_admin_token(&tokens, tmp.path()).expect("bootstrap");
        assert!(outcome.is_none());
        assert!(!tmp.path().join("admin-token").exists());
    }

    #[cfg(unix)]
    #[test]
    fn admin_token_file_is_owner_readable_only() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempdir();
        let tokens = Arc::new(TokenStore::new(Arc::new(Db::open_in_memory().unwrap())));
        ensure_admin_token(&tokens, tmp.path()).unwrap();
        let meta = std::fs::metadata(tmp.path().join("admin-token")).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "expected 0o600 perms, got {mode:o}");
    }

    /// Minimal tempdir helper — keeps the dep surface from adding
    /// `tempfile` just for two unit tests.
    fn tempdir() -> TempDir {
        let pid = u64::from(std::process::id());
        let nanos = u64::from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos(),
        );
        let base = std::env::temp_dir().join(format!(
            "oxidhome-bootstrap-{}",
            pid.wrapping_mul(1_000_003).wrapping_add(nanos),
        ));
        std::fs::create_dir_all(&base).unwrap();
        TempDir { path: base }
    }

    struct TempDir {
        path: std::path::PathBuf,
    }
    impl TempDir {
        fn path(&self) -> &Path {
            &self.path
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}
