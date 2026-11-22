//! First-run admin-token bootstrap, its startup reconciliation, and
//! the offline recovery path.
//!
//! ## Bootstrap (daemon startup)
//!
//! If the token store is empty, mint one full-access token with
//! label `admin` and deliver the plaintext to
//! `<state_dir>/admin-token` (mode `0o600`). The operator picks it
//! up once for first-time CLI / API setup.
//!
//! **Crash safety (architecture-review M4).** The secret is durably
//! on disk *before* its row is committed, so there is no state in
//! which the store holds a token whose secret was never delivered:
//!
//! 1. Generate the token in memory ([`TokenStore::generate`]).
//! 2. Write it to `<state_dir>/admin-token.pending-<id>` (`0o600`,
//!    `create_new`, fsynced, directory fsynced).
//! 3. Record the audit intent (fail-closed).
//! 4. Insert the row iff the store is empty.
//! 5. Atomically rename the pending file to `admin-token`.
//!
//! A failure at 2–4 removes the pending file and leaves the store
//! untouched, so the next start mints again. A failure at 5 deletes
//! the never-used row ([`TokenStore::delete_undelivered`]) so the
//! next start mints again; if even that delete fails, the pending
//! file is kept and [`reconcile_admin_token_files`] promotes it on
//! the next start. A crash between 4 and 5 is handled the same way.
//!
//! ## Startup reconciliation
//!
//! [`reconcile_admin_token_files`] runs before the bootstrap on
//! every daemon start:
//!
//! - A pending file whose token is live in the store is promoted to
//!   `admin-token` (finishes an interrupted bootstrap or recovery).
//!   A pending file whose token isn't live is removed.
//! - `admin-token` itself is removed once its token has been used
//!   (`last_used_ms` set — the operator has enrolled it in a client)
//!   or is no longer live (revoked / unknown). The plaintext doesn't
//!   linger on disk after enrollment.
//!
//! ## Offline recovery
//!
//! [`recover_admin_token_offline`] (the `oxidhome recover-admin-token`
//! subcommand) is the break-glass path for an operator who lost the
//! admin secret. It is deliberately **not** reachable over any
//! network API: it requires write access to the state dir and takes
//! the exclusive state-dir lock, so it only runs while the daemon
//! (and any `mcp-stdio` session) is stopped. It mints a fresh
//! `admin` token, revokes the previous `admin`-labelled tokens (or
//! every token with [`RevokeScope::All`]) in the same transaction,
//! and delivers the secret through the same pending-file → rename
//! sequence.
//!
//! ## Audit
//!
//! Every mint, revoke, promotion and post-enrollment file removal
//! lands in the `audit_event` ledger with the same two-phase
//! intent/finalize contract the API middleware uses. Rows use
//! `method = "LOCAL"`, `path = host.auth.*` (daemon) or
//! `cli.auth.*` (recovery command), and `token_id` = the token the
//! action applies to, so `GET /api/v1/audit?token_id=<id>` shows a
//! token's full lineage.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context;

use crate::auth::ActorKind;
use crate::state::{AuditEntry, AuditLog, IssuedToken, TokenError, TokenStore};

/// Default scope blob for the bootstrap token: a JSON array
/// containing the single wildcard `"*"` element. The array shape
/// is what [`crate::api::parse_scopes`](crate::api) (and 12-API-b's
/// scope-policy enforcer that builds on it) expects — a bare
/// `"\"*\""` string would silently degrade to deny-all on the
/// fail-closed parser path and silently lock the break-glass token
/// out of every scoped route. The wildcard contract: 12-API-b's
/// enforcer treats a scope entry equal to `"*"` as "any scope".
/// `bootstrap_blob_parses_as_wildcard_scope` pins this so the two
/// halves can't drift.
pub(crate) const ADMIN_SCOPE_JSON: &[u8] = br#"["*"]"#;

/// Label of the bootstrap / recovery-minted admin token.
pub const ADMIN_TOKEN_LABEL: &str = "admin";

/// File name of the delivered admin secret, relative to the state dir.
pub const ADMIN_TOKEN_FILE: &str = "admin-token";

/// The daemon's database file under the state dir (see
/// [`crate::state::Db::open_file`]). Recovery refuses to run without
/// it rather than silently creating an empty state dir.
const DB_FILE_NAME: &str = "oxidhome.db";

/// Prefix of the not-yet-promoted secret file. The token id follows.
const PENDING_PREFIX: &str = "admin-token.pending-";

/// Audit `method` for host-local (non-HTTP) auth lifecycle rows.
pub const AUDIT_METHOD_LOCAL: &str = "LOCAL";
/// Audit `actor_kind` for actions the daemon takes on its own behalf.
pub const AUDIT_ACTOR_HOST: &str = "host";
/// Audit path: first-run admin token minted.
pub const AUDIT_PATH_BOOTSTRAP: &str = "host.auth.bootstrap";
/// Audit path: an interrupted bootstrap / recovery's pending secret
/// file was promoted to `admin-token` at startup.
pub const AUDIT_PATH_PENDING_PROMOTED: &str = "host.auth.pending_promoted";
/// Audit path: `admin-token` removed after the token was enrolled.
pub const AUDIT_PATH_FILE_REMOVED: &str = "host.auth.admin_file_removed";
/// Audit path: offline recovery minted a replacement admin token.
pub const AUDIT_PATH_RECOVER: &str = "cli.auth.recover";
/// Audit path: offline recovery revoked a token.
pub const AUDIT_PATH_RECOVER_REVOKE: &str = "cli.auth.revoke";

/// If `tokens` is empty, mint an `admin` token and deliver its
/// plaintext to `<state_dir>/admin-token`. Returns `Some(token)` if
/// this call minted the admin, `None` if the store already had
/// tokens (including the case where a second process raced to mint —
/// exactly one winner; the loser gets `None`).
///
/// See the module doc for the crash-safe ordering. On any error the
/// store is left without an undelivered admin row (best-effort
/// rollback; if the rollback itself fails, the pending file holds
/// the secret and the next start's reconciliation promotes it).
///
/// **Filesystem permissions.** The token file is created with mode
/// `0o600` on Unix so a misconfigured state dir doesn't leak the
/// secret to other local users. On non-Unix platforms the mode bits
/// are ignored — `state_dir` is expected to be operator-owned.
///
/// # Errors
///
/// - DB errors reading or writing the token store.
/// - Audit-ledger errors recording the intent (fail-closed: no mint).
/// - I/O errors writing or promoting the secret file.
pub fn ensure_admin_token(
    tokens: &Arc<TokenStore>,
    audit: &AuditLog,
    state_dir: &Path,
) -> anyhow::Result<Option<IssuedToken>> {
    // Fast path: no file I/O and no audit row on every boot of an
    // already-provisioned host. The insert below re-checks inside
    // its own transaction, so this read isn't load-bearing.
    if tokens.count().context("counting tokens")? > 0 {
        return Ok(None);
    }

    let issued = TokenStore::generate();
    let pending = pending_path(state_dir, &issued.id);
    write_new_secret(&pending, &issued.plaintext)
        .with_context(|| format!("writing admin token to {}", pending.display()))?;

    let audit_id = match record_intent(audit, AUDIT_ACTOR_HOST, &issued.id, AUDIT_PATH_BOOTSTRAP) {
        Ok(id) => id,
        Err(err) => {
            remove_quietly(&pending);
            return Err(err.context("recording admin-token bootstrap intent"));
        }
    };

    match tokens.insert_if_empty(&issued, ADMIN_TOKEN_LABEL, ADMIN_SCOPE_JSON) {
        Ok(true) => {}
        Ok(false) => {
            remove_quietly(&pending);
            finalize(audit, audit_id, Outcome::Conflict);
            return Ok(None);
        }
        Err(err) => {
            remove_quietly(&pending);
            finalize(audit, audit_id, Outcome::Error);
            return Err(anyhow::Error::new(err).context("minting admin token"));
        }
    }

    let path = state_dir.join(ADMIN_TOKEN_FILE);
    if let Err(err) = promote(&pending, &path, state_dir) {
        finalize(audit, audit_id, Outcome::Error);
        // Roll back so the store is empty again and the next start
        // re-mints. If the rollback fails the pending file is the
        // only copy of a live secret — keep it for reconciliation.
        match tokens.delete_undelivered(&issued.id) {
            Ok(_) => remove_quietly(&pending),
            Err(del_err) => tracing::error!(
                token_id = %issued.id,
                pending = %pending.display(),
                error = %del_err,
                "admin-token rollback failed; the pending file will be promoted on next start",
            ),
        }
        return Err(err.context(format!("delivering admin token to {}", path.display())));
    }
    finalize(audit, audit_id, Outcome::Allow);

    tracing::info!(
        token_id = %issued.id,
        path = %path.display(),
        "minted admin token (first-run bootstrap); the file is removed on the first \
         daemon start after the token has been used — store it in your client config",
    );

    Ok(Some(issued))
}

/// Startup reconciliation of the on-disk admin secret files. Run
/// before [`ensure_admin_token`]. See the module doc.
///
/// # Errors
///
/// DB / audit errors, or I/O errors other than "file not found".
/// A token-store verdict of unknown / revoked / malformed is not an
/// error — it marks the file as stale.
pub fn reconcile_admin_token_files(
    tokens: &TokenStore,
    audit: &AuditLog,
    state_dir: &Path,
) -> anyhow::Result<()> {
    let final_path = state_dir.join(ADMIN_TOKEN_FILE);

    // 1. Pending files: promote live ones (oldest first, so the
    //    newest live secret ends up in `admin-token`), drop the rest.
    let mut live = Vec::new();
    for pending in list_pending(state_dir)? {
        match read_token_file(&pending)?.map(|s| tokens.verify_read_only(&s)) {
            None => {}
            Some(Ok(rec)) => live.push((rec.created_ms, rec.id, pending)),
            Some(Err(TokenError::Sqlite(e))) => {
                return Err(anyhow::Error::new(e).context("verifying pending admin token"));
            }
            Some(Err(_)) => {
                tracing::info!(path = %pending.display(), "removing stale pending admin-token file");
                remove_file_if_exists(&pending)?;
            }
        }
    }
    live.sort();
    for (_, token_id, pending) in live {
        audited(
            audit,
            AUDIT_ACTOR_HOST,
            &token_id,
            AUDIT_PATH_PENDING_PROMOTED,
            || promote(&pending, &final_path, state_dir),
        )
        .with_context(|| format!("promoting {}", pending.display()))?;
        tracing::warn!(
            token_id = %token_id,
            path = %final_path.display(),
            "completed an interrupted admin-token delivery",
        );
    }

    // 2. The delivered file: remove once enrolled or no longer live.
    let Some(secret) = read_token_file(&final_path)? else {
        return Ok(());
    };
    match tokens.verify_read_only(&secret) {
        Ok(rec) if rec.last_used_ms.is_some() => {
            audited(
                audit,
                AUDIT_ACTOR_HOST,
                &rec.id,
                AUDIT_PATH_FILE_REMOVED,
                || remove_file_if_exists(&final_path),
            )?;
            tracing::info!(
                token_id = %rec.id,
                path = %final_path.display(),
                "admin token has been used; removed its plaintext file",
            );
        }
        Ok(_) => {}
        Err(TokenError::Sqlite(e)) => {
            return Err(anyhow::Error::new(e).context("verifying admin token file"));
        }
        Err(_) => {
            tracing::info!(
                path = %final_path.display(),
                "admin-token file no longer matches a live token; removing it",
            );
            remove_file_if_exists(&final_path)?;
        }
    }
    Ok(())
}

/// Which existing tokens [`recover_admin_token`] revokes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RevokeScope {
    /// Revoke every active token labelled [`ADMIN_TOKEN_LABEL`] —
    /// the previous bootstrap / recovery tokens. Other tokens keep
    /// working.
    #[default]
    AdminTokens,
    /// Revoke every active token (credential-compromise response).
    All,
}

/// Outcome of [`recover_admin_token`].
#[derive(Debug)]
pub struct RecoveryReport {
    /// Id of the newly-minted admin token.
    pub token_id: String,
    /// Where the plaintext was written.
    pub path: PathBuf,
    /// Ids revoked in the same transaction.
    pub revoked: Vec<String>,
}

/// Offline break-glass recovery: open `state_dir` under the
/// exclusive state-dir lock (fails if the daemon or an `mcp-stdio`
/// session is running), then [`recover_admin_token`]. This is what
/// `oxidhome recover-admin-token` runs.
///
/// # Errors
///
/// - The state dir is locked by another process, or can't be opened.
/// - Any error from [`recover_admin_token`].
pub fn recover_admin_token_offline(
    state_dir: &Path,
    scope: RevokeScope,
) -> anyhow::Result<RecoveryReport> {
    if !state_dir.join(DB_FILE_NAME).exists() {
        anyhow::bail!(
            "no oxidhome database under {} — nothing to recover \
             (set $OXIDHOME_STATE_DIR to the daemon's state dir)",
            state_dir.display(),
        );
    }
    let _lock = crate::exclusive_lock::acquire_state_dir_lock(state_dir)
        .context("recovery needs exclusive access — stop the daemon first")?;
    let engine = crate::Engine::with_state_dir(state_dir)
        .with_context(|| format!("opening engine state at {}", state_dir.display()))?;
    let report = recover_admin_token(&engine.auth_tokens(), &engine.audit_log(), state_dir, scope);
    // Flush whatever this process logged into the store before the
    // lock drops.
    let _ = engine.log_store().flush(std::time::Duration::from_secs(5));
    report
}

/// Mint a replacement admin token, revoke the tokens selected by
/// `scope` in the same transaction, and deliver the secret to
/// `<state_dir>/admin-token`. The caller must hold the state-dir
/// lock; use [`recover_admin_token_offline`] outside tests.
///
/// # Errors
///
/// - I/O errors writing the pending secret (nothing changed).
/// - Audit intent errors (fail-closed: nothing changed).
/// - DB errors (nothing changed — the mint + revokes are one tx).
/// - I/O errors promoting the pending file. The DB change is
///   committed at that point; the error names the pending file,
///   which holds the new secret and is promoted on next start.
pub fn recover_admin_token(
    tokens: &TokenStore,
    audit: &AuditLog,
    state_dir: &Path,
    scope: RevokeScope,
) -> anyhow::Result<RecoveryReport> {
    let cli = ActorKind::Cli.as_str();
    let to_revoke: Vec<String> = tokens
        .list()
        .context("listing tokens")?
        .into_iter()
        .filter(|t| t.revoked_ms.is_none())
        .filter(|t| scope == RevokeScope::All || t.label == ADMIN_TOKEN_LABEL)
        .map(|t| t.id)
        .collect();

    let issued = TokenStore::generate();
    let pending = pending_path(state_dir, &issued.id);
    write_new_secret(&pending, &issued.plaintext)
        .with_context(|| format!("writing admin token to {}", pending.display()))?;

    // Fail-closed: every intent row lands before the mutation.
    let mut intents = Vec::with_capacity(to_revoke.len() + 1);
    let intent_result = (|| -> anyhow::Result<()> {
        intents.push(record_intent(audit, cli, &issued.id, AUDIT_PATH_RECOVER)?);
        for id in &to_revoke {
            intents.push(record_intent(audit, cli, id, AUDIT_PATH_RECOVER_REVOKE)?);
        }
        Ok(())
    })();
    if let Err(err) = intent_result {
        remove_quietly(&pending);
        for id in intents {
            finalize(audit, id, Outcome::Error);
        }
        return Err(err.context("recording recovery audit intent"));
    }

    let revoked =
        match tokens.insert_and_revoke(&issued, ADMIN_TOKEN_LABEL, ADMIN_SCOPE_JSON, &to_revoke) {
            Ok(revoked) => revoked,
            Err(err) => {
                remove_quietly(&pending);
                for id in intents {
                    finalize(audit, id, Outcome::Error);
                }
                return Err(anyhow::Error::new(err).context("minting recovery admin token"));
            }
        };
    // The mutation is committed: finalize as allowed regardless of
    // the delivery step (the pending file already holds the secret).
    for id in intents {
        finalize(audit, id, Outcome::Allow);
    }

    let path = state_dir.join(ADMIN_TOKEN_FILE);
    promote(&pending, &path, state_dir).with_context(|| {
        format!(
            "the new admin token (id {}) was minted but moving {} to {} failed; \
             read the secret from the former, or start the daemon to promote it",
            issued.id,
            pending.display(),
            path.display(),
        )
    })?;

    tracing::warn!(
        token_id = %issued.id,
        revoked = ?revoked,
        "offline admin-token recovery minted a replacement token",
    );
    Ok(RecoveryReport {
        token_id: issued.id,
        path,
        revoked,
    })
}

// ── files ────────────────────────────────────────────────────────

fn pending_path(state_dir: &Path, token_id: &str) -> PathBuf {
    state_dir.join(format!("{PENDING_PREFIX}{token_id}"))
}

fn list_pending(state_dir: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let entries = match std::fs::read_dir(state_dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => {
            return Err(
                anyhow::Error::new(e).context(format!("listing state dir {}", state_dir.display()))
            );
        }
    };
    let mut out = Vec::new();
    for entry in entries {
        let entry = entry.context("reading state dir entry")?;
        if entry
            .file_name()
            .to_str()
            .is_some_and(|n| n.starts_with(PENDING_PREFIX))
        {
            out.push(entry.path());
        }
    }
    Ok(out)
}

/// Read a secret file. `Ok(None)` if it doesn't exist.
fn read_token_file(path: &Path) -> anyhow::Result<Option<String>> {
    match std::fs::read_to_string(path) {
        Ok(s) => Ok(Some(s.trim().to_string())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(anyhow::Error::new(e).context(format!("reading {}", path.display()))),
    }
}

/// Create `path` (must not exist) with `0o600` permissions on Unix,
/// write `secret`, and fsync both the file and its directory, so
/// the secret is durable before any DB row refers to it. The
/// permissions are set at creation — a partial-write failure can't
/// leave a world-readable file behind. On failure the partial file
/// is removed.
fn write_new_secret(path: &Path, secret: &str) -> std::io::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    let result = (|| {
        f.write_all(secret.as_bytes())?;
        f.write_all(b"\n")?;
        f.sync_all()?;
        sync_parent(path)
    })();
    if result.is_err() {
        drop(f);
        remove_quietly(path);
    }
    result
}

/// Atomically move the pending secret into place and make the rename
/// durable.
fn promote(pending: &Path, dest: &Path, state_dir: &Path) -> anyhow::Result<()> {
    std::fs::rename(pending, dest)
        .with_context(|| format!("renaming {} to {}", pending.display(), dest.display()))?;
    sync_dir(state_dir).with_context(|| format!("syncing {}", state_dir.display()))
}

fn sync_parent(path: &Path) -> std::io::Result<()> {
    match path.parent() {
        Some(dir) => sync_dir(dir),
        None => Ok(()),
    }
}

fn sync_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        std::fs::File::open(dir)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Ok(())
    }
}

fn remove_file_if_exists(path: &Path) -> anyhow::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => {
            sync_parent(path).with_context(|| format!("syncing after removing {}", path.display()))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(anyhow::Error::new(e).context(format!("removing {}", path.display()))),
    }
}

fn remove_quietly(path: &Path) {
    if let Err(e) = std::fs::remove_file(path)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        tracing::warn!(path = %path.display(), error = %e, "failed to remove admin-token file");
    }
}

// ── audit ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
enum Outcome {
    Allow,
    Conflict,
    Error,
}

fn record_intent(
    audit: &AuditLog,
    actor_kind: &str,
    token_id: &str,
    path: &str,
) -> anyhow::Result<u64> {
    let entry = AuditEntry {
        id: 0,
        intent_ms: 0,
        finalized_ms: None,
        token_id: token_id.to_string(),
        actor_kind: actor_kind.to_string(),
        method: AUDIT_METHOD_LOCAL.into(),
        path: path.to_string(),
        // Ignored by `record_intent`.
        status: 0,
        decision: "pending".into(),
        required_scope: None,
        execution_outcome: None,
        domain_error: None,
        credential_fp: None,
    };
    audit
        .record_intent(&entry)
        .map_err(|e| anyhow::Error::new(e).context(format!("audit intent for {path}")))
}

/// Best-effort, like the API middleware's finalize: the action has
/// already happened (or been abandoned) and the pending row is the
/// operator-visible signal if this update fails.
fn finalize(audit: &AuditLog, id: u64, outcome: Outcome) {
    let (status, decision, exec) = match outcome {
        Outcome::Allow => (200, "allow", Some("success")),
        Outcome::Conflict => (409, "deny", None),
        Outcome::Error => (500, "error", None),
    };
    if let Err(err) = audit.finalize(id, status, decision, None, exec, None) {
        tracing::error!(audit_id = id, error = %err, "failed to finalize auth audit row");
    }
}

/// Two-phase audit around a single local action.
fn audited<T>(
    audit: &AuditLog,
    actor_kind: &str,
    token_id: &str,
    path: &str,
    op: impl FnOnce() -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    let id = record_intent(audit, actor_kind, token_id, path)?;
    let result = op();
    finalize(
        audit,
        id,
        if result.is_ok() {
            Outcome::Allow
        } else {
            Outcome::Error
        },
    );
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::parse_scopes;
    use crate::state::{AuditQuery, Db};

    /// Pins the wildcard contract: `ADMIN_SCOPE_JSON` must parse
    /// through `parse_scopes` to a non-empty scope list containing
    /// the wildcard sentinel `"*"`. Pre-fix this PR shipped the
    /// blob as `b"\"*\""` (a JSON string, not an array), which
    /// silently failed parsing → empty scopes → 12-API-b would
    /// have locked the break-glass admin token out of every scoped
    /// route. This test makes the bootstrap blob and the parser
    /// impossible to drift independently.
    #[test]
    fn bootstrap_blob_parses_as_wildcard_scope() {
        let scopes = parse_scopes(ADMIN_SCOPE_JSON)
            .expect("ADMIN_SCOPE_JSON must parse through the scope parser");
        assert_eq!(
            scopes,
            vec!["*".to_string()],
            "bootstrap blob must surface the wildcard sentinel verbatim",
        );
    }

    struct Fixture {
        db: Arc<Db>,
        tokens: Arc<TokenStore>,
        audit: AuditLog,
        dir: TempDir,
    }

    fn fixture() -> Fixture {
        let db = Arc::new(Db::open_in_memory().unwrap());
        Fixture {
            tokens: Arc::new(TokenStore::new(Arc::clone(&db))),
            audit: AuditLog::new(Arc::clone(&db)),
            db,
            dir: tempdir(),
        }
    }

    impl Fixture {
        fn bootstrap(&self) -> anyhow::Result<Option<IssuedToken>> {
            ensure_admin_token(&self.tokens, &self.audit, self.dir.path())
        }
        fn reconcile(&self) -> anyhow::Result<()> {
            reconcile_admin_token_files(&self.tokens, &self.audit, self.dir.path())
        }
        fn admin_file(&self) -> PathBuf {
            self.dir.path().join(ADMIN_TOKEN_FILE)
        }
        fn read_admin_file(&self) -> Option<String> {
            std::fs::read_to_string(self.admin_file())
                .ok()
                .map(|s| s.trim().to_string())
        }
        fn pending_files(&self) -> Vec<PathBuf> {
            list_pending(self.dir.path()).unwrap()
        }
        fn audit_rows(&self, path: &str) -> Vec<AuditEntry> {
            self.audit
                .query(
                    &AuditQuery {
                        path: Some(path.to_string()),
                        ..AuditQuery::default()
                    },
                    100,
                )
                .unwrap()
        }
        fn sql(&self, stmt: &str) {
            self.db.write(|c| c.execute_batch(stmt)).expect("test SQL");
        }
    }

    #[test]
    fn bootstrap_mints_when_store_empty() {
        let fx = fixture();
        let issued = fx.bootstrap().unwrap().expect("minted");
        assert_eq!(
            fx.read_admin_file().as_deref(),
            Some(issued.plaintext.as_str())
        );
        assert!(fx.pending_files().is_empty());
        assert!(fx.tokens.verify_read_only(&issued.plaintext).is_ok());

        let rows = fx.audit_rows(AUDIT_PATH_BOOTSTRAP);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].token_id, issued.id);
        assert_eq!(rows[0].actor_kind, AUDIT_ACTOR_HOST);
        assert_eq!(rows[0].decision, "allow");
        assert_eq!(rows[0].method, AUDIT_METHOD_LOCAL);
    }

    #[test]
    fn bootstrap_is_no_op_when_store_has_tokens() {
        let fx = fixture();
        fx.tokens.create("preexisting", b"{}").unwrap();
        assert!(fx.bootstrap().unwrap().is_none());
        assert!(!fx.admin_file().exists());
        assert!(fx.audit_rows(AUDIT_PATH_BOOTSTRAP).is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn admin_token_file_is_owner_readable_only() {
        use std::os::unix::fs::PermissionsExt;
        let fx = fixture();
        fx.bootstrap().unwrap();
        let mode = std::fs::metadata(fx.admin_file())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "expected 0o600 perms, got {mode:o}");
    }

    /// The M4 scenario: the secret can't be written. Pre-fix the
    /// row stayed behind and every later boot skipped the mint.
    #[test]
    fn secret_write_failure_leaves_store_empty_and_retry_mints() {
        let fx = fixture();
        let missing = fx.dir.path().join("does-not-exist");
        let err = ensure_admin_token(&fx.tokens, &fx.audit, &missing).unwrap_err();
        assert!(
            format!("{err:#}").contains("writing admin token"),
            "{err:#}"
        );
        assert_eq!(fx.tokens.count().unwrap(), 0, "no undelivered row");
        assert!(fx.audit_rows(AUDIT_PATH_BOOTSTRAP).is_empty());

        let issued = fx.bootstrap().unwrap().expect("retry mints");
        assert_eq!(
            fx.read_admin_file().as_deref(),
            Some(issued.plaintext.as_str())
        );
    }

    #[test]
    fn audit_intent_failure_mints_nothing() {
        let fx = fixture();
        fx.sql(
            "CREATE TRIGGER no_audit BEFORE INSERT ON audit_event \
             BEGIN SELECT RAISE(ABORT, 'audit down'); END;",
        );
        assert!(fx.bootstrap().is_err());
        assert_eq!(fx.tokens.count().unwrap(), 0);
        assert!(fx.pending_files().is_empty());
        assert!(!fx.admin_file().exists());
    }

    #[test]
    fn db_insert_failure_removes_pending_secret() {
        let fx = fixture();
        fx.sql(
            "CREATE TRIGGER no_tokens BEFORE INSERT ON auth_token \
             BEGIN SELECT RAISE(ABORT, 'db down'); END;",
        );
        assert!(fx.bootstrap().is_err());
        assert_eq!(fx.tokens.count().unwrap(), 0);
        assert!(fx.pending_files().is_empty());
        assert!(!fx.admin_file().exists());
        let rows = fx.audit_rows(AUDIT_PATH_BOOTSTRAP);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].decision, "error");
    }

    /// Rename into place fails (here: `admin-token` is a non-empty
    /// directory). The committed row is rolled back so the next
    /// start can mint again.
    #[test]
    fn promote_failure_rolls_back_row() {
        let fx = fixture();
        std::fs::create_dir(fx.admin_file()).unwrap();
        std::fs::write(fx.admin_file().join("blocker"), b"x").unwrap();
        assert!(fx.bootstrap().is_err());
        assert_eq!(fx.tokens.count().unwrap(), 0, "row rolled back");
        assert!(fx.pending_files().is_empty());
        assert_eq!(fx.audit_rows(AUDIT_PATH_BOOTSTRAP)[0].decision, "error");

        std::fs::remove_dir_all(fx.admin_file()).unwrap();
        let issued = fx.bootstrap().unwrap().expect("retry mints");
        assert_eq!(
            fx.read_admin_file().as_deref(),
            Some(issued.plaintext.as_str())
        );
    }

    /// Rename fails *and* the rollback delete fails: the pending
    /// file must survive, and reconciliation promotes it.
    #[test]
    fn promote_and_rollback_failure_keeps_pending_for_reconcile() {
        let fx = fixture();
        std::fs::create_dir(fx.admin_file()).unwrap();
        std::fs::write(fx.admin_file().join("blocker"), b"x").unwrap();
        fx.sql(
            "CREATE TRIGGER no_delete BEFORE DELETE ON auth_token \
             BEGIN SELECT RAISE(ABORT, 'db down'); END;",
        );
        assert!(fx.bootstrap().is_err());
        assert_eq!(fx.tokens.count().unwrap(), 1);
        let pending = fx.pending_files();
        assert_eq!(pending.len(), 1, "secret kept on disk");
        let secret = std::fs::read_to_string(&pending[0]).unwrap();

        std::fs::remove_dir_all(fx.admin_file()).unwrap();
        fx.reconcile().unwrap();
        assert_eq!(fx.read_admin_file().as_deref(), Some(secret.trim()));
        assert!(fx.pending_files().is_empty());
        assert_eq!(fx.audit_rows(AUDIT_PATH_PENDING_PROMOTED).len(), 1);
    }

    /// Crash between the commit and the rename.
    #[test]
    fn reconcile_promotes_live_pending_and_drops_stale_pending() {
        let fx = fixture();
        let live = TokenStore::generate();
        write_new_secret(&pending_path(fx.dir.path(), &live.id), &live.plaintext).unwrap();
        assert!(
            fx.tokens
                .insert_if_empty(&live, ADMIN_TOKEN_LABEL, ADMIN_SCOPE_JSON)
                .unwrap()
        );
        // Crash before the insert: never committed.
        let dead = TokenStore::generate();
        write_new_secret(&pending_path(fx.dir.path(), &dead.id), &dead.plaintext).unwrap();

        fx.reconcile().unwrap();
        assert_eq!(
            fx.read_admin_file().as_deref(),
            Some(live.plaintext.as_str())
        );
        assert!(fx.pending_files().is_empty());
        // The store is non-empty, so the bootstrap is a no-op.
        assert!(fx.bootstrap().unwrap().is_none());
        assert_eq!(
            fx.read_admin_file().as_deref(),
            Some(live.plaintext.as_str())
        );
    }

    #[test]
    fn reconcile_removes_file_after_enrollment_only() {
        let fx = fixture();
        let issued = fx.bootstrap().unwrap().unwrap();
        fx.reconcile().unwrap();
        assert!(fx.admin_file().exists(), "unused token keeps its file");

        fx.tokens.verify(&issued.plaintext).unwrap();
        fx.reconcile().unwrap();
        assert!(!fx.admin_file().exists(), "enrolled token's file removed");
        let rows = fx.audit_rows(AUDIT_PATH_FILE_REMOVED);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].token_id, issued.id);
        assert_eq!(rows[0].decision, "allow");
        // The token itself keeps working.
        assert!(fx.tokens.verify_read_only(&issued.plaintext).is_ok());
    }

    #[test]
    fn reconcile_removes_file_for_revoked_token() {
        let fx = fixture();
        let issued = fx.bootstrap().unwrap().unwrap();
        fx.tokens.revoke(&issued.id).unwrap();
        fx.reconcile().unwrap();
        assert!(!fx.admin_file().exists());
    }

    /// A host already in the M4 lockout state (row, no secret)
    /// recovers through the offline path.
    #[test]
    fn recovery_replaces_lost_admin_token() {
        let fx = fixture();
        let lost = fx
            .tokens
            .create(ADMIN_TOKEN_LABEL, ADMIN_SCOPE_JSON)
            .unwrap();
        let other = fx.tokens.create("ci", b"[]").unwrap();
        assert!(
            fx.bootstrap().unwrap().is_none(),
            "store non-empty: no re-mint"
        );

        let report =
            recover_admin_token(&fx.tokens, &fx.audit, fx.dir.path(), RevokeScope::default())
                .unwrap();
        assert_eq!(report.revoked, vec![lost.id.clone()]);
        let secret = fx.read_admin_file().unwrap();
        let rec = fx.tokens.verify_read_only(&secret).unwrap();
        assert_eq!(rec.id, report.token_id);
        assert_eq!(rec.label, ADMIN_TOKEN_LABEL);
        assert_eq!(
            parse_scopes(&rec.scope_json).unwrap(),
            vec!["*".to_string()]
        );
        assert!(matches!(
            fx.tokens.verify_read_only(&lost.plaintext),
            Err(TokenError::Revoked)
        ));
        assert!(fx.tokens.verify_read_only(&other.plaintext).is_ok());
        assert!(fx.pending_files().is_empty());

        let minted = fx.audit_rows(AUDIT_PATH_RECOVER);
        assert_eq!(minted.len(), 1);
        assert_eq!(minted[0].token_id, report.token_id);
        assert_eq!(minted[0].actor_kind, "cli");
        assert_eq!(minted[0].decision, "allow");
        let revoked = fx.audit_rows(AUDIT_PATH_RECOVER_REVOKE);
        assert_eq!(revoked.len(), 1);
        assert_eq!(revoked[0].token_id, lost.id);
        assert_eq!(revoked[0].decision, "allow");
    }

    #[test]
    fn recovery_revoke_all_revokes_every_token() {
        let fx = fixture();
        let a = fx
            .tokens
            .create(ADMIN_TOKEN_LABEL, ADMIN_SCOPE_JSON)
            .unwrap();
        let b = fx.tokens.create("ci", b"[]").unwrap();
        let report =
            recover_admin_token(&fx.tokens, &fx.audit, fx.dir.path(), RevokeScope::All).unwrap();
        let mut revoked = report.revoked.clone();
        revoked.sort();
        let mut expected = vec![a.id, b.id];
        expected.sort();
        assert_eq!(revoked, expected);
        assert!(fx.tokens.verify_read_only(&b.plaintext).is_err());
    }

    #[test]
    fn recovery_db_failure_changes_nothing() {
        let fx = fixture();
        let old = fx
            .tokens
            .create(ADMIN_TOKEN_LABEL, ADMIN_SCOPE_JSON)
            .unwrap();
        fx.sql(
            "CREATE TRIGGER no_tokens BEFORE INSERT ON auth_token \
             BEGIN SELECT RAISE(ABORT, 'db down'); END;",
        );
        assert!(
            recover_admin_token(&fx.tokens, &fx.audit, fx.dir.path(), RevokeScope::default())
                .is_err()
        );
        assert!(
            fx.tokens.verify_read_only(&old.plaintext).is_ok(),
            "revoke rolled back"
        );
        assert!(fx.pending_files().is_empty());
        assert!(!fx.admin_file().exists());
        assert_eq!(fx.audit_rows(AUDIT_PATH_RECOVER)[0].decision, "error");
        assert_eq!(
            fx.audit_rows(AUDIT_PATH_RECOVER_REVOKE)[0].decision,
            "error"
        );
    }

    #[test]
    fn recovery_audit_failure_changes_nothing() {
        let fx = fixture();
        let old = fx
            .tokens
            .create(ADMIN_TOKEN_LABEL, ADMIN_SCOPE_JSON)
            .unwrap();
        fx.sql(
            "CREATE TRIGGER no_audit BEFORE INSERT ON audit_event \
             BEGIN SELECT RAISE(ABORT, 'audit down'); END;",
        );
        assert!(
            recover_admin_token(&fx.tokens, &fx.audit, fx.dir.path(), RevokeScope::default())
                .is_err()
        );
        assert_eq!(fx.tokens.count().unwrap(), 1);
        assert!(fx.tokens.verify_read_only(&old.plaintext).is_ok());
        assert!(fx.pending_files().is_empty());
    }

    /// Delivery fails after the commit: the error names the
    /// pending file, which still holds the live secret.
    #[test]
    fn recovery_promote_failure_keeps_secret_on_disk() {
        let fx = fixture();
        std::fs::create_dir(fx.admin_file()).unwrap();
        std::fs::write(fx.admin_file().join("blocker"), b"x").unwrap();
        let err = recover_admin_token(&fx.tokens, &fx.audit, fx.dir.path(), RevokeScope::default())
            .unwrap_err();
        let pending = fx.pending_files();
        assert_eq!(pending.len(), 1);
        assert!(format!("{err:#}").contains(&pending[0].display().to_string()));
        let secret = std::fs::read_to_string(&pending[0]).unwrap();
        assert!(fx.tokens.verify_read_only(secret.trim()).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn offline_recovery_refuses_while_state_dir_is_locked() {
        let dir = tempdir();
        drop(crate::Engine::with_state_dir(dir.path()).unwrap());
        let _held = crate::exclusive_lock::acquire_state_dir_lock(dir.path()).unwrap();
        let err = recover_admin_token_offline(dir.path(), RevokeScope::default()).unwrap_err();
        assert!(format!("{err:#}").contains("stop the daemon"), "{err:#}");
        assert!(!dir.path().join(ADMIN_TOKEN_FILE).exists());
    }

    #[cfg(unix)]
    #[test]
    fn offline_recovery_end_to_end() {
        let dir = tempdir();
        let lost_id = {
            let engine = crate::Engine::with_state_dir(dir.path()).unwrap();
            // M4 lockout: a row exists, the secret is gone.
            engine
                .auth_tokens()
                .create(ADMIN_TOKEN_LABEL, ADMIN_SCOPE_JSON)
                .unwrap()
                .id
        };
        let report = recover_admin_token_offline(dir.path(), RevokeScope::default()).unwrap();
        assert_eq!(report.revoked, vec![lost_id]);

        let engine = crate::Engine::with_state_dir(dir.path()).unwrap();
        let secret = std::fs::read_to_string(&report.path).unwrap();
        assert_eq!(
            engine
                .auth_tokens()
                .verify_read_only(secret.trim())
                .unwrap()
                .id,
            report.token_id,
        );
    }

    #[test]
    fn offline_recovery_refuses_without_a_database() {
        let dir = tempdir();
        let err = recover_admin_token_offline(dir.path(), RevokeScope::default()).unwrap_err();
        assert!(format!("{err:#}").contains("nothing to recover"), "{err:#}");
        assert!(!dir.path().join(ADMIN_TOKEN_FILE).exists());
    }

    /// Minimal tempdir helper — keeps the dep surface from adding
    /// `tempfile` just for these unit tests.
    fn tempdir() -> TempDir {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        let base = std::env::temp_dir().join(format!(
            "oxidhome-bootstrap-{}-{seq}-{nanos}",
            std::process::id(),
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
