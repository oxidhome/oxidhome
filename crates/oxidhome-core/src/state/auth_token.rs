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

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use rand::TryRngCore;
use rusqlite::params;
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
}

/// Newly-minted token. The plaintext field is the **only** copy of
/// the secret; once dropped, the operator must rotate to get a new
/// one.
#[derive(Debug)]
pub struct IssuedToken {
    pub id: String,
    pub plaintext: String,
}

/// In-memory + SQLite-backed token registry. One per [`Engine`](crate::Engine).
#[derive(Debug)]
pub struct TokenStore {
    db: Arc<Db>,
}

impl TokenStore {
    #[must_use]
    pub fn new(db: Arc<Db>) -> Self {
        Self { db }
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
                    "SELECT id, label, scope_json, created_ms, last_used_ms, revoked_ms \
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
                    "SELECT id, label, scope_json, created_ms, last_used_ms, revoked_ms \
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
    /// record. On success, bumps `last_used_ms`. The error variants
    /// the API rejects with are intentionally indistinguishable from
    /// the outside (all map to 401) so an attacker can't probe id
    /// shape, validity, or revocation state.
    pub fn verify(&self, presented: &str) -> Result<TokenRecord, TokenError> {
        let secret = parse_token(presented).ok_or(TokenError::Malformed)?;
        let hash = sha256(&secret);
        let now = now_ms();

        let hash_for_db = hash.to_vec();
        let rec = self
            .db
            .write(move |conn| -> Result<TokenRecord, TokenError> {
                let mut stmt = conn.prepare(
                    "SELECT id, label, scope_json, created_ms, last_used_ms, revoked_ms \
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
                conn.execute(
                    "UPDATE auth_token SET last_used_ms = ?1 WHERE id = ?2",
                    params![now, row.id],
                )?;
                Ok(TokenRecord {
                    last_used_ms: Some(now),
                    ..row
                })
            })?;
        Ok(rec)
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

    /// Row count. Used by the bootstrap path to detect a
    /// first-run / empty store (so it can mint the admin token).
    pub fn count(&self) -> Result<u64, TokenError> {
        let n = self.db.read(|conn| -> Result<i64, TokenError> {
            let n: i64 = conn.query_row("SELECT COUNT(*) FROM auth_token", [], |r| r.get(0))?;
            Ok(n)
        })?;
        #[allow(clippy::cast_sign_loss)]
        Ok(n as u64)
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
    })
}

fn generate_secret() -> [u8; TOKEN_BYTES] {
    let mut buf = [0u8; TOKEN_BYTES];
    rand::rngs::OsRng
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

fn base64url_no_pad_decode(input: &str) -> Option<Vec<u8>> {
    if input.is_empty() {
        return Some(Vec::new());
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
}
