//! Phase 12 token store — the `auth_token` `SQLite` table.
//!
//! Tokens are 256-bit values minted from a CSPRNG, displayed to the
//! operator **once** at issuance, and stored only as a SHA-256 hash
//! on the host. Argon2/bcrypt would be overengineering for a
//! uniformly-random 256-bit secret (those slow KDFs defend against
//! brute-force on low-entropy passwords; against ~2^256 candidates,
//! brute force is infeasible regardless of hash cost).
//!
//! Token administration is host-only — the CLI is the only path that
//! mints, rotates, or revokes tokens. The API consults the store
//! during request authentication; it never issues tokens itself.
//!
//! ## Wire shape
//!
//! Plaintext tokens are presented as a base64url-no-pad encoding of
//! the 32-byte secret prefixed with `oxh_` so they're easy to spot
//! in logs and config files (and so we can refuse to load anything
//! that doesn't have the prefix as a quick sanity gate). The id and
//! the hash are derived from the secret itself, so the same secret
//! never produces two different rows.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use rand::TryRng;
use rusqlite::{OptionalExtension, params};
use sha2::{Digest, Sha256};
use thiserror::Error;

use super::db::Db;

/// Plaintext-token prefix. Helps operators spot a token in logs +
/// config dumps, and lets [`TokenStore::verify`] reject any input
/// that obviously isn't an `OxidHome` token without doing a DB lookup.
const TOKEN_PREFIX: &str = "oxh_";

/// Raw secret length, in bytes. 256 bits of CSPRNG output.
const TOKEN_BYTES: usize = 32;

/// Errors the token store surfaces. All variants are
/// host-only — the API maps them to opaque 401/403 responses so the
/// client can't distinguish "no such token" from "wrong shape".
#[derive(Debug, Error)]
pub enum TokenError {
    /// Underlying `SQLite` error from `rusqlite`.
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// The presented secret didn't match the expected shape: an
    /// `oxh_` prefix followed by base64url-encoded 32 bytes. The
    /// API rejects it without hashing or DB lookup.
    #[error("malformed token")]
    Malformed,
    /// The secret hash didn't match any row.
    #[error("unknown token")]
    Unknown,
    /// The matching row has a non-null `revoked_ms`.
    #[error("token revoked")]
    Revoked,
}

/// What the store hands back on a successful verify. `Clone` is
/// cheap; callers stash it on the request extension.
#[derive(Debug, Clone)]
pub struct TokenRecord {
    pub id: String,
    pub label: String,
    /// Scope policy bytes verbatim. The auth layer parses this on
    /// each verify; if parse fails the token is treated as deny-all
    /// rather than panicked on (the store doesn't enforce shape on
    /// insert beyond "valid UTF-8 JSON").
    pub scope_json: Vec<u8>,
    pub created_ms: i64,
    pub last_used_ms: Option<i64>,
    pub revoked_ms: Option<i64>,
    /// H6 slice 2: `true` for the owner token, the one the host minted
    /// at first-run bootstrap or with `recover-admin-token`. Set only
    /// by those two code paths (and the migration's backfill from
    /// their audit rows); never from a label or an API call.
    pub owner: bool,
}

/// Newly-minted token. The plaintext field is the **only** copy of
/// the secret; once dropped, the operator must rotate to get a new
/// one.
#[derive(Debug)]
pub struct IssuedToken {
    pub id: String,
    pub plaintext: String,
}

/// Resolution of `auth_token.last_used_ms` (M6). A verify within
/// this window of the token's last recorded use skips the UPDATE,
/// so a busy client costs one write per minute instead of one per
/// request. A token's first use is always written (the bootstrap's
/// "has the admin token been used" check and
/// `TokenStore::delete_undelivered` key on NULL vs. set).
pub const LAST_USED_RESOLUTION_MS: i64 = 60_000;

/// Bound on the in-process "last written" map; cleared when full.
/// Only tokens that verified successfully ever enter it.
const LAST_USED_CACHE_MAX: usize = 1024;

/// In-memory + SQLite-backed token registry. One per [`Engine`](crate::Engine).
#[derive(Debug)]
pub struct TokenStore {
    db: Arc<Db>,
    /// `token_id -> last_used_ms` this process wrote, for callers
    /// that bump without a fresh row in hand
    /// ([`Self::touch_last_used`]).
    last_written: Mutex<HashMap<String, i64>>,
}

impl TokenStore {
    #[must_use]
    pub fn new(db: Arc<Db>) -> Self {
        Self {
            db,
            last_written: Mutex::new(HashMap::new()),
        }
    }

    /// Mint a fresh token with `label` and the given `scope_json`
    /// blob. Returns the id + plaintext (the only copy — caller
    /// must surface it to the operator immediately).
    pub fn create(&self, label: &str, scope_json: &[u8]) -> Result<IssuedToken, TokenError> {
        let secret = generate_secret();
        let plaintext = format_token(&secret);
        let hash = sha256(&secret);
        let id = derive_id(&hash);
        let now = now_ms();

        let label_owned = label.to_string();
        let scope_owned = scope_json.to_vec();
        let id_for_db = id.clone();
        let hash_for_db = hash.to_vec();
        self.db.write(move |conn| -> Result<(), TokenError> {
            conn.execute(
                "INSERT INTO auth_token \
                   (id, label, hash, scope_json, created_ms, last_used_ms, revoked_ms) \
                 VALUES (?1, ?2, ?3, ?4, ?5, NULL, NULL)",
                params![id_for_db, label_owned, hash_for_db, scope_owned, now],
            )?;
            Ok(())
        })?;

        Ok(IssuedToken { id, plaintext })
    }

    /// Look up a token by id. Used by [`Self::revoke`] / the CLI's
    /// `token show`. Returns `Ok(None)` if no such row exists.
    pub fn get(&self, token_id: &str) -> Result<Option<TokenRecord>, TokenError> {
        let id_owned = token_id.to_string();
        let rec = self
            .db
            .read(move |conn| -> Result<Option<TokenRecord>, TokenError> {
                let mut stmt = conn.prepare(
                    "SELECT id, label, scope_json, created_ms, last_used_ms, revoked_ms, owner \
                 FROM auth_token WHERE id = ?1",
                )?;
                let row = stmt
                    .query_row(params![id_owned], row_to_record)
                    .map(Some)
                    .or_else(|e| match e {
                        rusqlite::Error::QueryReturnedNoRows => Ok(None),
                        other => Err(TokenError::from(other)),
                    })?;
                Ok(row)
            })?;
        Ok(rec)
    }

    /// Snapshot of every token. Pre-sized; the lock-hold time scales
    /// with the row count, which is small (operators don't mint
    /// thousands of tokens). Used by the CLI's `token list`.
    pub fn list(&self) -> Result<Vec<TokenRecord>, TokenError> {
        let rows = self
            .db
            .read(|conn| -> Result<Vec<TokenRecord>, TokenError> {
                let mut stmt = conn.prepare(
                    "SELECT id, label, scope_json, created_ms, last_used_ms, revoked_ms, owner \
                 FROM auth_token ORDER BY created_ms ASC",
                )?;
                let iter = stmt.query_map([], row_to_record)?;
                let mut out = Vec::new();
                for r in iter {
                    out.push(r?);
                }
                Ok(out)
            })?;
        Ok(rows)
    }

    /// Verify a plaintext bearer secret and return the matching
    /// record. On success, bumps `last_used_ms` unless it was
    /// recorded within [`LAST_USED_RESOLUTION_MS`]. The error variants
    /// the API rejects with are intentionally indistinguishable from
    /// the outside (all map to 401) so an attacker can't probe id
    /// shape, validity, or revocation state.
    ///
    /// **Locking.** The lookup runs on a pooled reader (`db.read()`)
    /// and only the `last_used_ms` bump takes the writer, at most
    /// once per [`LAST_USED_RESOLUTION_MS`] per token (M6). The
    /// gap between read and write is benign: at worst two concurrent
    /// verifies of the same token write `last_used_ms` to nearly
    /// identical values, and a `revoke` interleaved between the
    /// two bumps a now-revoked token's "last used" by a few
    /// milliseconds — neither leaks privilege.
    pub fn verify(&self, presented: &str) -> Result<TokenRecord, TokenError> {
        let rec = self.verify_read_only(presented)?;
        // Best-effort `last_used_ms` bump. Lock-contention failures
        // are deliberately swallowed inside `touch_last_used`: the
        // token is already verified, and missing a timestamp update
        // is strictly less bad than rejecting the request.
        let last_used = self.bump_last_used(&rec.id, rec.last_used_ms);
        Ok(TokenRecord {
            last_used_ms: Some(last_used),
            ..rec
        })
    }

    /// Read-only half of [`Self::verify`]: parses + hashes the
    /// presented bearer, looks the row up, checks the `revoked_ms`
    /// gate. Does NOT bump `last_used_ms` — that's the writable
    /// half. Split out so the MCP rate limiter can key on a
    /// resolved `token_id` (or a shared "unauthenticated" sentinel)
    /// without doing a durable write on every rejected request
    /// (round-3 P1 on PR #140).
    pub fn verify_read_only(&self, presented: &str) -> Result<TokenRecord, TokenError> {
        let secret = parse_token(presented).ok_or(TokenError::Malformed)?;
        let hash = sha256(&secret);
        let hash_for_db = hash.to_vec();
        self.db
            .read(move |conn| -> Result<TokenRecord, TokenError> {
                let mut stmt = conn.prepare(
                    "SELECT id, label, scope_json, created_ms, last_used_ms, revoked_ms, owner \
                 FROM auth_token WHERE hash = ?1",
                )?;
                let row = stmt
                    .query_row(params![hash_for_db], row_to_record)
                    .map_err(|e| match e {
                        rusqlite::Error::QueryReturnedNoRows => TokenError::Unknown,
                        other => TokenError::from(other),
                    })?;
                if row.revoked_ms.is_some() {
                    return Err(TokenError::Revoked);
                }
                Ok(row)
            })
    }

    /// Best-effort `last_used_ms` bump for a token whose id is
    /// already known (typically because [`Self::verify_read_only`]
    /// resolved it upstream). The MCP rate limiter calls
    /// [`Self::verify_read_only`] before the audit path, then
    /// `require_token` calls this to complete the write half
    /// without redoing the SELECT (round-3 P1 on PR #140).
    /// Coalesced like [`Self::verify`]: skipped if this process
    /// wrote the token's `last_used_ms` within
    /// [`LAST_USED_RESOLUTION_MS`]. Returns the recorded timestamp.
    #[must_use]
    pub fn touch_last_used(&self, token_id: &str) -> i64 {
        self.bump_last_used(token_id, self.cached_last_used(token_id))
    }

    /// [`Self::touch_last_used`] for a caller that already holds the
    /// row from [`Self::verify_read_only`] (`recorded` is its
    /// `last_used_ms`): coalesces on the newer of that and this
    /// process's last write, so eviction from the in-process map
    /// never forces a write.
    #[must_use]
    pub fn touch_last_used_from(&self, token_id: &str, recorded: Option<i64>) -> i64 {
        let recorded = recorded.max(self.cached_last_used(token_id));
        self.bump_last_used(token_id, recorded)
    }

    /// Whether a `last_used_ms` value is recent enough that a bump
    /// would be coalesced away. Lets async callers skip the blocking
    /// hop entirely. A value ahead of the clock (wall-clock rollback)
    /// counts as current, matching the SQL re-check.
    #[must_use]
    pub fn last_used_is_current(recorded: Option<i64>) -> bool {
        recorded.is_some_and(|t| t > now_ms().saturating_sub(LAST_USED_RESOLUTION_MS))
    }

    fn cached_last_used(&self, token_id: &str) -> Option<i64> {
        self.last_written
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(token_id)
            .copied()
    }

    /// Write `last_used_ms = now` unless `recorded` (the row's value
    /// from [`Self::verify`], or this process's last write from
    /// [`Self::touch_last_used`]) is less than
    /// [`LAST_USED_RESOLUTION_MS`] old (or ahead of the clock).
    /// `None` (never used) always writes. Returns the timestamp now on record (best effort: a
    /// failed write is logged and `now` returned, as before M6).
    fn bump_last_used(&self, token_id: &str, recorded: Option<i64>) -> i64 {
        if let Some(t) = recorded
            && Self::last_used_is_current(recorded)
        {
            return t;
        }
        let now = now_ms();
        let Some(on_record) = touch_last_used(&self.db, token_id, now) else {
            return now;
        };
        let mut map = self
            .last_written
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if map.len() >= LAST_USED_CACHE_MAX && !map.contains_key(token_id) {
            map.clear();
        }
        map.insert(token_id.to_string(), on_record);
        on_record
    }

    /// Mark a token revoked. Idempotent — calling on an already-
    /// revoked token leaves the original `revoked_ms`. Returns
    /// `true` if a row was newly revoked, `false` otherwise (the
    /// token didn't exist or was already revoked).
    pub fn revoke(&self, token_id: &str) -> Result<bool, TokenError> {
        let id_owned = token_id.to_string();
        let now = now_ms();
        let changed = self.db.write(move |conn| -> Result<bool, TokenError> {
            let n = conn.execute(
                "UPDATE auth_token SET revoked_ms = ?1 \
                 WHERE id = ?2 AND revoked_ms IS NULL",
                params![now, id_owned],
            )?;
            Ok(n > 0)
        })?;
        Ok(changed)
    }

    /// Row count. Used by tests + the CLI's future `token list`.
    /// (Bootstrap goes through [`Self::insert_owner_if_empty`] so the
    /// check-then-insert race doesn't matter.)
    pub fn count(&self) -> Result<u64, TokenError> {
        let n = self.db.read(|conn| -> Result<i64, TokenError> {
            let n: i64 = conn.query_row("SELECT COUNT(*) FROM auth_token", [], |r| r.get(0))?;
            Ok(n)
        })?;
        #[allow(clippy::cast_sign_loss)]
        Ok(n as u64)
    }

    /// Atomic "mint exactly one token iff the table is empty".
    /// Runs the count + insert inside one `BEGIN IMMEDIATE` write
    /// transaction, so two daemons racing against the same `SQLite`
    /// file see exactly one winner (the loser observes `count > 0`
    /// inside the transaction and rolls back).
    ///
    /// Returns `Ok(Some(issued))` when a token is minted, `Ok(None)`
    /// when the table already had at least one row.
    pub fn create_if_empty(
        &self,
        label: &str,
        scope_json: &[u8],
    ) -> Result<Option<IssuedToken>, TokenError> {
        let issued = Self::generate();
        Ok(if self.insert_first(&issued, label, scope_json, false)? {
            Some(issued)
        } else {
            None
        })
    }

    /// Generate a fresh token **without** touching the database.
    ///
    /// M4: the first-run bootstrap and the offline recovery command
    /// need the secret (and its id) in hand *before* the row is
    /// committed, so the plaintext can be durably written to disk
    /// first. A row whose secret was never delivered is exactly
    /// the unrecoverable state M4 removes. Pair with
    /// [`Self::insert_owner_if_empty`] or [`Self::insert_owner_and_revoke`].
    #[must_use]
    pub fn generate() -> IssuedToken {
        let secret = generate_secret();
        let plaintext = format_token(&secret);
        let id = derive_id(&sha256(&secret));
        IssuedToken { id, plaintext }
    }

    /// Insert a token produced by [`Self::generate`] **as the owner**
    /// (when `scope_json` is the minted `["*"]`) iff the table is
    /// empty — the first-run bootstrap — inside one `BEGIN IMMEDIATE` transaction (see
    /// [`Self::create_if_empty`] for the race argument). Returns
    /// `true` if the row was inserted.
    ///
    /// # Errors
    ///
    /// [`TokenError::Malformed`] if `issued.plaintext` isn't a token
    /// this module produced; [`TokenError::Sqlite`] on DB failure.
    pub fn insert_owner_if_empty(
        &self,
        issued: &IssuedToken,
        label: &str,
        scope_json: &[u8],
    ) -> Result<bool, TokenError> {
        self.insert_first(issued, label, scope_json, true)
    }

    fn insert_first(
        &self,
        issued: &IssuedToken,
        label: &str,
        scope_json: &[u8],
        owner: bool,
    ) -> Result<bool, TokenError> {
        let row = PendingRow::new(issued, label, scope_json, owner)?;
        self.durable_write(move |conn| -> Result<bool, TokenError> {
            let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let existing: i64 =
                tx.query_row("SELECT COUNT(*) FROM auth_token", [], |r| r.get(0))?;
            if existing > 0 {
                // Implicit rollback on drop; no row was written.
                return Ok(false);
            }
            row.insert(&tx)?;
            tx.commit()?;
            Ok(true)
        })
    }

    /// Insert a token produced by [`Self::generate`] **as the owner**
    /// and revoke every still-active id in `revoke_ids`, all in one
    /// transaction — the offline recovery command's rotation step.
    /// Any other live owner is revoked in the same transaction and
    /// listed in the result. The row is marked owner only when
    /// `scope_json` is the minted `["*"]`; this and [`Self::insert_owner_if_empty`] are the only
    /// owner-minting inserts (H6 slice 2): every other insert
    /// ([`Self::create`], [`Self::create_if_empty`]) is a plain token.
    /// Either the new token exists *and* the old ones are revoked,
    /// or nothing changed. Returns the ids that were newly revoked
    /// (already-revoked or unknown ids are skipped).
    ///
    /// # Errors
    ///
    /// [`TokenError::Malformed`] if `issued.plaintext` isn't a token
    /// this module produced; [`TokenError::Sqlite`] on DB failure.
    pub fn insert_owner_and_revoke(
        &self,
        issued: &IssuedToken,
        label: &str,
        scope_json: &[u8],
        revoke_ids: &[String],
    ) -> Result<Vec<String>, TokenError> {
        let row = PendingRow::new(issued, label, scope_json, true)?;
        let revoke_ids = revoke_ids.to_vec();
        let now = row.created_ms;
        self.durable_write(move |conn| -> Result<Vec<String>, TokenError> {
            let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let mut revoked = Vec::with_capacity(revoke_ids.len());
            for id in revoke_ids {
                let n = tx.execute(
                    "UPDATE auth_token SET revoked_ms = ?1 \
                     WHERE id = ?2 AND revoked_ms IS NULL",
                    params![now, id],
                )?;
                if n > 0 {
                    revoked.push(id);
                }
            }
            // One owner at a time: a still-live previous owner is
            // revoked with the rotation even when the caller didn't
            // name it (H6 slice 2; a unique index enforces it too).
            if row.is_owner() {
                let previous: Vec<String> = {
                    let mut stmt = tx.prepare(
                        "SELECT id FROM auth_token WHERE owner = 1 AND revoked_ms IS NULL",
                    )?;
                    stmt.query_map([], |r| r.get(0))?
                        .collect::<Result<_, _>>()?
                };
                for id in previous {
                    tx.execute(
                        "UPDATE auth_token SET revoked_ms = ?1 WHERE id = ?2",
                        params![now, id],
                    )?;
                    revoked.push(id);
                }
            }
            row.insert(&tx)?;
            tx.commit()?;
            Ok(revoked)
        })
    }

    /// Replace a token's policy blob (`scope_json`). The offline
    /// `oxidhome token grant-sensitive` / `revoke-sensitive` commands
    /// use it; the API never does. Returns `false` when no live token
    /// has that id.
    ///
    /// # Errors
    ///
    /// [`TokenError::Sqlite`] on DB failure.
    pub fn set_policy(&self, token_id: &str, scope_json: &[u8]) -> Result<bool, TokenError> {
        let id_owned = token_id.to_string();
        let blob = scope_json.to_vec();
        self.durable_write(move |conn| -> Result<bool, TokenError> {
            let n = conn.execute(
                "UPDATE auth_token SET scope_json = ?2 WHERE id = ?1 AND revoked_ms IS NULL",
                params![id_owned, blob],
            )?;
            Ok(n > 0)
        })
    }

    /// Hard-delete a token row that was **never used** (null
    /// `last_used_ms`, not revoked). Only the bootstrap uses this,
    /// to roll back a freshly-minted admin row whose secret could
    /// not be delivered to `<state_dir>/admin-token` — leaving the
    /// row behind would make the store non-empty and block the
    /// next boot's re-mint (M4). A tombstone (`revoke`) would have
    /// the same blocking effect, so a delete is the only rollback
    /// that keeps the bootstrap retryable; the guard keeps it from
    /// erasing the lineage of a token that ever authenticated
    /// anything. Returns `true` if a row was deleted.
    ///
    /// # Errors
    ///
    /// [`TokenError::Sqlite`] on DB failure.
    pub(crate) fn delete_undelivered(&self, token_id: &str) -> Result<bool, TokenError> {
        let id_owned = token_id.to_string();
        self.durable_write(move |conn| -> Result<bool, TokenError> {
            let n = conn.execute(
                "DELETE FROM auth_token \
                 WHERE id = ?1 AND last_used_ms IS NULL AND revoked_ms IS NULL",
                params![id_owned],
            )?;
            Ok(n > 0)
        })
    }
}

impl TokenStore {
    /// Run `f` with `PRAGMA synchronous = FULL` so its commit is
    /// fsynced before returning. The shared connection runs WAL +
    /// `synchronous = NORMAL`, under which a committed transaction
    /// can be lost on power failure. The bootstrap / recovery paths
    /// order file operations (promote or unlink a secret) after a
    /// token commit, so that commit must be durable first (M4).
    /// The pragma is restored to `NORMAL` afterwards. A failed
    /// restore is logged, not returned: `f` has already committed,
    /// and reporting failure would make the caller discard the
    /// secret of a token that exists. The connection then stays at
    /// `FULL`, which is safe (only slower).
    fn durable_write<R: Send>(
        &self,
        f: impl FnOnce(&mut rusqlite::Connection) -> Result<R, TokenError>,
    ) -> Result<R, TokenError> {
        self.db.write(move |conn| -> Result<R, TokenError> {
            conn.pragma_update(None, "synchronous", "FULL")?;
            let result = f(conn);
            if let Err(err) = conn.pragma_update(None, "synchronous", "NORMAL") {
                tracing::warn!(
                    target: "auth.token",
                    error = %err,
                    "failed to restore synchronous = NORMAL; connection stays at FULL",
                );
            }
            result
        })
    }
}

/// Id of the token `plaintext` encodes, without a DB lookup.
/// `None` if it isn't a well-formed token. Lets the bootstrap
/// audit a stale secret file against the token it named even
/// when that token is revoked or unknown.
pub(crate) fn token_id_of(plaintext: &str) -> Option<String> {
    parse_token(plaintext).map(|s| derive_id(&sha256(&s)))
}

/// Row values for an INSERT of a [`TokenStore::generate`]d token.
/// Re-derives the hash + id from the plaintext so a caller can't
/// insert a row whose id doesn't match its secret.
struct PendingRow {
    id: String,
    label: String,
    hash: Vec<u8>,
    scope_json: Vec<u8>,
    created_ms: i64,
    owner: bool,
}

impl PendingRow {
    fn new(
        issued: &IssuedToken,
        label: &str,
        scope_json: &[u8],
        owner: bool,
    ) -> Result<Self, TokenError> {
        let secret = parse_token(&issued.plaintext).ok_or(TokenError::Malformed)?;
        let hash = sha256(&secret);
        let id = derive_id(&hash);
        if id != issued.id {
            return Err(TokenError::Malformed);
        }
        Ok(Self {
            id,
            label: label.to_string(),
            hash: hash.to_vec(),
            scope_json: scope_json.to_vec(),
            created_ms: now_ms(),
            owner,
        })
    }

    /// Whether the row is inserted as the owner.
    fn is_owner(&self) -> bool {
        self.owner && self.scope_json.as_slice() == br#"["*"]"#
    }

    /// Insert the row, as the owner token when it was built for one
    /// (bootstrap or recovery, H6 slice 2) and its scope is the minted
    /// `["*"]`.
    fn insert(&self, conn: &rusqlite::Connection) -> Result<(), TokenError> {
        let owner = self.is_owner();
        conn.execute(
            "INSERT INTO auth_token \
               (id, label, hash, scope_json, created_ms, last_used_ms, revoked_ms, owner) \
             VALUES (?1, ?2, ?3, ?4, ?5, NULL, NULL, ?6)",
            params![
                self.id,
                self.label,
                self.hash,
                self.scope_json,
                self.created_ms,
                owner
            ],
        )?;
        Ok(())
    }
}

fn row_to_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<TokenRecord> {
    Ok(TokenRecord {
        id: row.get(0)?,
        label: row.get(1)?,
        scope_json: row.get(2)?,
        created_ms: row.get(3)?,
        last_used_ms: row.get(4)?,
        revoked_ms: row.get(5)?,
        owner: row.get::<_, i64>(6)? != 0,
    })
}

fn generate_secret() -> [u8; TOKEN_BYTES] {
    let mut buf = [0u8; TOKEN_BYTES];
    // `SysRng` is rand 0.10's stateless OS-CSPRNG interface
    // (the renamed-from-0.9 `OsRng`). Token minting is rare; we
    // pull bytes straight from the OS rather than threading a
    // seeded PRNG.
    rand::rngs::SysRng
        .try_fill_bytes(&mut buf)
        .expect("OS CSPRNG must be available for token generation");
    buf
}

fn sha256(input: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(input);
    h.finalize().into()
}

/// Format `secret` as `oxh_<base64url-no-pad>`.
fn format_token(secret: &[u8; TOKEN_BYTES]) -> String {
    let body = base64url_no_pad(secret);
    format!("{TOKEN_PREFIX}{body}")
}

/// Parse a presented bearer string back into the 32-byte secret.
/// Returns `None` for anything that doesn't have the prefix or
/// doesn't decode to exactly [`TOKEN_BYTES`] bytes.
fn parse_token(presented: &str) -> Option<[u8; TOKEN_BYTES]> {
    let body = presented.strip_prefix(TOKEN_PREFIX)?;
    let bytes = base64url_no_pad_decode(body)?;
    bytes.as_slice().try_into().ok()
}

/// Derive a stable token id from the hash. First 12 bytes of the
/// hash, encoded base64url-no-pad — 16 chars, ~96 bits, plenty for
/// uniqueness across a hub's token table (operators mint a handful).
fn derive_id(hash: &[u8; 32]) -> String {
    base64url_no_pad(&hash[..12])
}

/// Best-effort `last_used_ms = now` write, re-checked under the
/// writer so concurrent verifies that all read a stale value write
/// once, and an older `now` never overwrites a newer value. Returns
/// the value on record afterwards (`None` if the write failed or the
/// row is gone). Failures are logged and swallowed; the caller has
/// already authenticated.
fn touch_last_used(db: &Db, token_id: &str, now: i64) -> Option<i64> {
    let id_for_db = token_id.to_string();
    match db.write(move |conn| -> Result<Option<i64>, TokenError> {
        let n = conn.execute(
            "UPDATE auth_token SET last_used_ms = ?1 \
             WHERE id = ?2 AND (last_used_ms IS NULL OR last_used_ms <= ?3)",
            params![now, id_for_db, now.saturating_sub(LAST_USED_RESOLUTION_MS)],
        )?;
        if n > 0 {
            return Ok(Some(now));
        }
        Ok(conn
            .query_row(
                "SELECT last_used_ms FROM auth_token WHERE id = ?1",
                params![id_for_db],
                |row| row.get::<_, Option<i64>>(0),
            )
            .optional()?
            .flatten())
    }) {
        Ok(on_record) => on_record,
        Err(err) => {
            tracing::warn!(
                target: "auth.token",
                token_id = %token_id,
                error = %err,
                "failed to bump last_used_ms; verify itself succeeded",
            );
            None
        }
    }
}

fn now_ms() -> i64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    i64::try_from(now).unwrap_or(i64::MAX)
}

const B64URL: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Tiny base64url encoder (no padding). Avoids pulling `base64` in
/// just for these two helpers; the bytes-in shapes are always
/// fixed-size (32 secret bytes, 12 id bytes) so there's no risk of
/// a pathological input.
fn base64url_no_pad(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    let mut i = 0;
    while i + 3 <= input.len() {
        let n =
            (u32::from(input[i]) << 16) | (u32::from(input[i + 1]) << 8) | u32::from(input[i + 2]);
        out.push(B64URL[((n >> 18) & 0x3F) as usize] as char);
        out.push(B64URL[((n >> 12) & 0x3F) as usize] as char);
        out.push(B64URL[((n >> 6) & 0x3F) as usize] as char);
        out.push(B64URL[(n & 0x3F) as usize] as char);
        i += 3;
    }
    match input.len() - i {
        1 => {
            let n = u32::from(input[i]) << 16;
            out.push(B64URL[((n >> 18) & 0x3F) as usize] as char);
            out.push(B64URL[((n >> 12) & 0x3F) as usize] as char);
        }
        2 => {
            let n = (u32::from(input[i]) << 16) | (u32::from(input[i + 1]) << 8);
            out.push(B64URL[((n >> 18) & 0x3F) as usize] as char);
            out.push(B64URL[((n >> 12) & 0x3F) as usize] as char);
            out.push(B64URL[((n >> 6) & 0x3F) as usize] as char);
        }
        _ => {}
    }
    out
}

/// Canonical-only base64url-no-pad decoder. The trailing
/// partial-group bits MUST be zero — otherwise multiple distinct
/// input strings would decode to the same output, and a token
/// wouldn't have a single canonical text form. Today the only
/// caller is [`parse_token`] and the only operator-facing path
/// produces tokens via our own `base64url_no_pad` encoder (which
/// is canonical), so non-canonical input is already a "couldn't
/// come from us" signal; rejecting it keeps the property explicit.
fn base64url_no_pad_decode(input: &str) -> Option<Vec<u8>> {
    if input.is_empty() {
        return Some(Vec::new());
    }
    // A canonical encoding has length ≡ 0, 2, or 3 mod 4.
    // (Length ≡ 1 mod 4 is impossible — it would need ≥4 trailing
    // bits, but only 0/2/4 bits of slop are possible after the
    // 8-bit boundary.)
    if input.len() % 4 == 1 {
        return None;
    }
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for &c in bytes {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        };
        buf = (buf << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            // Mask to the low byte first, then truncate to u8.
            // Equivalent in value to `(buf >> bits) as u8 & 0xFF`,
            // but the explicit mask + `try_from` keeps clippy's
            // `cast_possible_truncation` happy.
            let byte = u8::try_from((buf >> bits) & 0xFF).expect("masked to one byte");
            out.push(byte);
        }
    }
    // Trailing 2- or 4-bit remainder MUST be zero for a canonical
    // encoding. With `bits` left at 0/2/4 after the loop and the
    // input length mod-4 already constrained to 0/2/3 above, the
    // last char contributes only 2 or 4 unconsumed low bits — those
    // must all be zero, else multiple distinct inputs would round-
    // trip to the same bytes.
    if buf & ((1 << bits) - 1) != 0 {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh() -> Arc<Db> {
        let db = Db::open_in_memory().expect("db");
        Arc::new(db)
    }

    #[test]
    fn create_and_verify_roundtrip() {
        let store = TokenStore::new(fresh());
        let issued = store.create("admin", b"{}").expect("create");
        assert!(issued.plaintext.starts_with("oxh_"));
        assert_eq!(store.count().unwrap(), 1);

        let rec = store.verify(&issued.plaintext).expect("verify");
        assert_eq!(rec.id, issued.id);
        assert_eq!(rec.label, "admin");
        assert!(rec.last_used_ms.is_some());
        assert!(rec.revoked_ms.is_none());
    }

    #[test]
    fn malformed_tokens_are_rejected() {
        let store = TokenStore::new(fresh());
        store.create("admin", b"{}").unwrap();
        assert!(matches!(
            store.verify("not-a-token"),
            Err(TokenError::Malformed)
        ));
        assert!(matches!(
            store.verify("oxh_short"),
            Err(TokenError::Malformed)
        ));
    }

    #[test]
    fn unknown_token_yields_unknown_error() {
        let store = TokenStore::new(fresh());
        store.create("admin", b"{}").unwrap();
        // Synthesize a 32-byte secret that won't match our row.
        let other = format_token(&[7u8; TOKEN_BYTES]);
        assert!(matches!(store.verify(&other), Err(TokenError::Unknown)));
    }

    #[test]
    fn revoked_token_cannot_verify() {
        let store = TokenStore::new(fresh());
        let issued = store.create("admin", b"{}").unwrap();
        assert!(store.revoke(&issued.id).expect("revoke"));
        assert!(matches!(
            store.verify(&issued.plaintext),
            Err(TokenError::Revoked)
        ));
        // Idempotent: second revoke reports no change.
        assert!(!store.revoke(&issued.id).unwrap());
    }

    #[test]
    fn list_orders_by_creation() {
        let store = TokenStore::new(fresh());
        let a = store.create("a", b"{}").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let b = store.create("b", b"{}").unwrap();
        let listed = store.list().unwrap();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].id, a.id);
        assert_eq!(listed[1].id, b.id);
    }

    #[test]
    fn base64url_roundtrip_is_lossless() {
        for input in [&b""[..], b"\x00", b"\x01\x02\x03", b"\xff\xfe\xfd\xfc"] {
            let enc = base64url_no_pad(input);
            let dec = base64url_no_pad_decode(&enc).expect("decode");
            assert_eq!(dec, input);
        }
    }

    /// Canonicality check: trailing partial-group bits must be zero.
    /// `AA` (canonical) decodes to `[0]`; `AB`, `AC`, `AD` all have
    /// non-zero trailing bits and would all round-trip to `[0]` if
    /// we accepted them — so we reject. Same logic for the 32-byte
    /// 43-char case the token format uses (last char must come from
    /// the 4-bit-aligned subset).
    #[test]
    fn base64url_rejects_non_canonical_trailing_bits() {
        // 2-char form: canonical only when the low 4 bits of the
        // second char are zero. Encoded body == decoded one byte.
        assert_eq!(base64url_no_pad_decode("AA").as_deref(), Some(&[0u8][..]));
        assert!(base64url_no_pad_decode("AB").is_none());
        assert!(base64url_no_pad_decode("AC").is_none());
        // Length ≡ 1 mod 4 is structurally impossible.
        assert!(base64url_no_pad_decode("A").is_none());
        // Wrong charset.
        assert!(base64url_no_pad_decode("A+").is_none());
        assert!(base64url_no_pad_decode("A/").is_none());
    }

    /// `create_if_empty` mints on an empty store, becomes a no-op
    /// once any token exists, and (most importantly) does both in
    /// the same `BEGIN IMMEDIATE` write so two concurrent calls
    /// can't both mint. Hard to drive a real two-process race in
    /// a unit test; the next-best signal is "first call mints,
    /// second call sees the row and returns None even with the
    /// same `db` handle".
    #[test]
    fn create_if_empty_mints_once_then_is_noop() {
        let store = TokenStore::new(fresh());
        let first = store
            .create_if_empty("admin", b"[\"*\"]")
            .expect("first call");
        assert!(first.is_some(), "first call should mint");
        assert_eq!(store.count().unwrap(), 1);
        // A generic insert is never the owner (H6 slice 2).
        assert!(!store.list().unwrap()[0].owner);

        let second = store
            .create_if_empty("admin", b"[\"*\"]")
            .expect("second call");
        assert!(second.is_none(), "second call must see the row and bail");
        assert_eq!(store.count().unwrap(), 1, "still exactly one row");
    }

    #[test]
    fn insert_owner_and_revoke_is_atomic_rotation() {
        let store = TokenStore::new(fresh());
        let old = store.create("admin", b"[\"*\"]").unwrap();
        let other = store.create("ci", b"[]").unwrap();
        let new = TokenStore::generate();
        let revoked = store
            .insert_owner_and_revoke(
                &new,
                "admin",
                b"[\"*\"]",
                &[old.id.clone(), "no-such-id".into()],
            )
            .unwrap();
        assert_eq!(revoked, vec![old.id.clone()]);
        assert!(matches!(
            store.verify(&old.plaintext),
            Err(TokenError::Revoked)
        ));
        assert!(store.verify(&new.plaintext).is_ok());
        assert!(store.verify(&other.plaintext).is_ok());
    }

    /// Every auth-lifecycle write goes through `durable_write`,
    /// which hands the shared connection back at
    /// `synchronous = NORMAL` (1) on both the success and error
    /// paths. Each call starts from `OFF` (0) so a method that
    /// bypasses `durable_write` leaves 0 behind and fails here.
    #[test]
    fn auth_lifecycle_writes_go_through_durable_write() {
        let db = fresh();
        let store = TokenStore::new(Arc::clone(&db));
        let reset = || {
            db.write(|c| c.pragma_update(None, "synchronous", "OFF"))
                .unwrap();
        };
        let sync = || -> i64 {
            db.read(|c| c.pragma_query_value(None, "synchronous", |r| r.get(0)))
                .unwrap()
        };

        reset();
        let first = TokenStore::generate();
        assert!(store.insert_owner_if_empty(&first, "admin", b"[]").unwrap());
        assert_eq!(sync(), 1, "insert_owner_if_empty");

        reset();
        store
            .insert_owner_and_revoke(
                &TokenStore::generate(),
                "admin",
                b"[]",
                std::slice::from_ref(&first.id),
            )
            .unwrap();
        assert_eq!(sync(), 1, "insert_owner_and_revoke");

        reset();
        let unused = store.create("x", b"[]").unwrap();
        reset();
        assert!(store.delete_undelivered(&unused.id).unwrap());
        assert_eq!(sync(), 1, "delete_undelivered");

        db.write(|c| {
            c.execute_batch(
                "CREATE TRIGGER boom BEFORE INSERT ON auth_token \
                 BEGIN SELECT RAISE(ABORT, 'boom'); END;",
            )
        })
        .unwrap();
        reset();
        assert!(
            store
                .insert_owner_and_revoke(&TokenStore::generate(), "admin", b"[]", &[])
                .is_err()
        );
        assert_eq!(sync(), 1, "error path");
    }

    #[test]
    fn insert_rejects_mismatched_id() {
        let store = TokenStore::new(fresh());
        let mut forged = TokenStore::generate();
        forged.id = "not-the-derived-id".into();
        assert!(matches!(
            store.insert_owner_if_empty(&forged, "admin", b"[]"),
            Err(TokenError::Malformed)
        ));
        assert_eq!(store.count().unwrap(), 0);
    }

    #[test]
    fn delete_undelivered_spares_used_or_revoked_tokens() {
        let store = TokenStore::new(fresh());
        let fresh_tok = store.create("admin", b"[]").unwrap();
        let used = store.create("used", b"[]").unwrap();
        store.verify(&used.plaintext).unwrap();
        let revoked = store.create("revoked", b"[]").unwrap();
        store.revoke(&revoked.id).unwrap();

        assert!(store.delete_undelivered(&fresh_tok.id).unwrap());
        assert!(!store.delete_undelivered(&used.id).unwrap());
        assert!(!store.delete_undelivered(&revoked.id).unwrap());
        assert_eq!(store.count().unwrap(), 2);
    }

    /// Verify still bumps `last_used_ms` after the split into
    /// `db.read` + `db.write`, and a token's first use is always
    /// written even with M6 coalescing.
    #[test]
    fn verify_bumps_last_used_ms_via_separate_write() {
        let store = TokenStore::new(fresh());
        let issued = store.create("admin", b"[\"*\"]").unwrap();
        let pre = store.get(&issued.id).unwrap().unwrap();
        assert!(pre.last_used_ms.is_none());
        let rec = store.verify(&issued.plaintext).expect("verify");
        assert!(rec.last_used_ms.is_some());
        let post = store.get(&issued.id).unwrap().unwrap();
        assert!(post.last_used_ms.is_some());
        assert_eq!(rec.last_used_ms, post.last_used_ms);
    }

    fn set_last_used(db: &Db, id: &str, ms: i64) {
        db.write(|c| {
            c.execute(
                "UPDATE auth_token SET last_used_ms = ?1 WHERE id = ?2",
                params![ms, id],
            )
        })
        .unwrap();
    }

    /// M6: verifies inside the resolution window coalesce into the
    /// recorded value; once it is older than the window, the next
    /// verify writes again.
    #[test]
    fn verify_coalesces_last_used_within_resolution() {
        let db = fresh();
        let store = TokenStore::new(Arc::clone(&db));
        let issued = store.create("admin", b"[\"*\"]").unwrap();
        let recent = now_ms() - 1_000;
        set_last_used(&db, &issued.id, recent);
        let rec = store.verify(&issued.plaintext).unwrap();
        assert_eq!(rec.last_used_ms, Some(recent));
        let row = store.get(&issued.id).unwrap().unwrap();
        assert_eq!(row.last_used_ms, Some(recent), "no write inside the window");

        let stale = now_ms() - 2 * LAST_USED_RESOLUTION_MS;
        set_last_used(&db, &issued.id, stale);
        let rec = store.verify(&issued.plaintext).unwrap();
        let row = store.get(&issued.id).unwrap().unwrap();
        assert!(
            row.last_used_ms.unwrap() > stale,
            "stale value is refreshed"
        );
        assert_eq!(rec.last_used_ms, row.last_used_ms);
    }

    /// M6: `touch_last_used` (no row in hand) coalesces on this
    /// process's own last write.
    #[test]
    fn touch_last_used_coalesces_on_process_writes() {
        let db = fresh();
        let store = TokenStore::new(Arc::clone(&db));
        let issued = store.create("mcp", b"[\"*\"]").unwrap();
        let first = store.touch_last_used(&issued.id);
        let row = store.get(&issued.id).unwrap().unwrap();
        assert_eq!(row.last_used_ms, Some(first), "first touch writes");
        // Make the row stale behind the cache's back: a second touch
        // inside the window must not write.
        set_last_used(&db, &issued.id, 1);
        let second = store.touch_last_used(&issued.id);
        assert_eq!(second, first);
        let row = store.get(&issued.id).unwrap().unwrap();
        assert_eq!(row.last_used_ms, Some(1));
    }

    /// M6: the write re-checks under the writer, so a verify that
    /// read a stale value doesn't write once another verify has, and
    /// an older timestamp never overwrites a newer one.
    #[test]
    fn last_used_write_rechecks_under_the_writer() {
        let db = fresh();
        let store = TokenStore::new(Arc::clone(&db));
        let issued = store.create("admin", b"[\"*\"]").unwrap();
        let newer = now_ms();
        set_last_used(&db, &issued.id, newer);
        let older = newer - 5_000;
        assert_eq!(touch_last_used(&db, &issued.id, older), Some(newer));
        let row = store.get(&issued.id).unwrap().unwrap();
        assert_eq!(row.last_used_ms, Some(newer));
        assert_eq!(touch_last_used(&db, "missing", newer), None);
    }

    /// M6 review: a value ahead of the clock (wall-clock rollback)
    /// is current, so verifies don't fall through to the writer.
    #[test]
    fn future_last_used_is_current() {
        let db = fresh();
        let store = TokenStore::new(Arc::clone(&db));
        let issued = store.create("admin", b"[\"*\"]").unwrap();
        let future = now_ms() + 10 * LAST_USED_RESOLUTION_MS;
        set_last_used(&db, &issued.id, future);
        assert!(TokenStore::last_used_is_current(Some(future)));
        let rec = store.verify(&issued.plaintext).unwrap();
        assert_eq!(rec.last_used_ms, Some(future));
        assert!(!TokenStore::last_used_is_current(None));
    }

    /// M6 review: the MCP path coalesces on the row it verified,
    /// even with nothing in the process cache.
    #[test]
    fn touch_last_used_from_coalesces_on_the_row() {
        let db = fresh();
        let store = TokenStore::new(Arc::clone(&db));
        let issued = store.create("mcp", b"[\"*\"]").unwrap();
        let recent = now_ms() - 1_000;
        set_last_used(&db, &issued.id, recent);
        let rec = store.verify_read_only(&issued.plaintext).unwrap();
        // Stale the row behind the record's back: the record wins.
        set_last_used(&db, &issued.id, 1);
        assert_eq!(
            store.touch_last_used_from(&rec.id, rec.last_used_ms),
            recent
        );
        assert_eq!(
            store.get(&issued.id).unwrap().unwrap().last_used_ms,
            Some(1)
        );
    }
}
