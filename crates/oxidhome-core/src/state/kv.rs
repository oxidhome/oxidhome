//! Per-instance KV store backed by `SQLite`.
//!
//! [`KvStore`] owns the read/write logic for the `kv` and `kv_usage`
//! tables defined in [`super::db`]. Each [`crate::Engine`] holds one
//! `Arc<KvStore>`; when a plugin loads, the host calls
//! [`KvStore::register_instance`] with the installation's
//! `installation_uuid` (host-minted at install time — see
//! [`crate::state::InstalledPluginRegistry`]), the caller-supplied
//! `instance_id`, and the manifest-declared quota. Every subsequent
//! host call routes through the same `(installation_uuid, instance_id)`
//! tuple, so per-instance state is scoped to the *live* install: an
//! uninstall + reinstall of the same `plugin_id` gets a fresh uuid
//! and therefore a fresh keyspace, and [`KvStore::purge_installation`]
//! wipes every row for a tombstoned install so orphan data doesn't
//! survive on disk. See migration 14 in `state/db.rs` for the schema
//! shape.
//!
//! Encoding: WIT `value` variants are wrapped in a small typed
//! enum and serialized to bytes via `serde_json` so the store carries
//! the variant tag along with the payload. JSON is fine for Phase 5
//! values (kilobytes per write, low write rate); a more compact
//! `postcard`-style format can drop in later without a migration —
//! the store sees opaque BLOBs.
//!
//! Quota enforcement: `set` opens a `BEGIN IMMEDIATE` transaction so
//! a concurrent writer can't race past the check. The transaction
//! computes the new `bytes_used` (factoring in any existing row's
//! contribution that's about to be replaced) and refuses the write
//! when it would push past `bytes_quota`.

use std::sync::Arc;

use rusqlite::OptionalExtension;
use rusqlite::params;
use serde::{Deserialize, Serialize};

use crate::host_impl::plugin::oxidhome::plugin::types::Value as WitValue;

use super::db::Db;

/// Errors returned by [`KvStore`]. Surface into the WIT `storage`
/// interface mapping in `host_impl::storage`.
#[derive(Debug, thiserror::Error)]
pub enum KvError {
    /// The instance hasn't been registered (no quota row in
    /// `kv_usage`). Means the host's manifest gate let the call
    /// through but didn't pre-register the instance — that's a host
    /// bug, never a plugin bug, so this is `Internal` from the WIT
    /// side.
    #[error(
        "instance `{instance_id}` (installation `{installation_uuid}`) \
         is not registered with the KV store"
    )]
    UnregisteredInstance {
        installation_uuid: String,
        instance_id: String,
    },
    /// A `set` was refused because completing it would push the
    /// instance over its quota.
    #[error(
        "quota exceeded for instance `{instance_id}` \
         (installation `{installation_uuid}`): \
         {would_use} bytes would be used / {allowed} allowed"
    )]
    QuotaExceeded {
        installation_uuid: String,
        instance_id: String,
        would_use: u64,
        allowed: u64,
    },
    /// `value` encode / decode failed. Should be unreachable for any
    /// WIT-produced value, but surfacing it beats panicking.
    #[error("encoding value for key `{key}`: {source}")]
    Encode {
        key: String,
        #[source]
        source: serde_json::Error,
    },
    /// `SQLite` returned an error during the operation.
    #[error("sqlite error: {0}")]
    Sql(#[from] rusqlite::Error),
}

/// Per-instance KV store. Cheap to clone — holds an `Arc<Db>`.
#[derive(Clone)]
pub struct KvStore {
    db: Arc<Db>,
}

impl KvStore {
    #[must_use]
    pub fn new(db: Arc<Db>) -> Self {
        Self { db }
    }

    /// Reserve a `kv_usage` slot for `(installation_uuid, instance_id)`
    /// with the given quota. Idempotent — re-registering an existing
    /// tuple updates its quota in place (so a manifest edit + reload
    /// picks up the new value without wiping the data). A quota of `0`
    /// is the manifest-default "storage gated off" signal — the host's
    /// `storage::Host` impl refuses every call before we ever see one,
    /// but the row still gets written so subsequent code that joins
    /// against `kv_usage` doesn't trip on a missing entry.
    ///
    /// # Errors
    ///
    /// `SQLite` errors surface as [`KvError::Sql`].
    pub fn register_instance(
        &self,
        installation_uuid: &str,
        instance_id: &str,
        quota_bytes: u64,
    ) -> Result<(), KvError> {
        // `INSERT ... ON CONFLICT` keeps existing `bytes_used` and
        // only refreshes the quota. Quota stored as i64 (rusqlite has
        // no native u64 bind for INTEGER columns); cap to i64::MAX.
        let quota_i64 = i64::try_from(quota_bytes).unwrap_or(i64::MAX);
        self.db.write(|conn| -> Result<(), KvError> {
            conn.execute(
                "INSERT INTO kv_usage(installation_uuid, instance_id, bytes_used, bytes_quota) \
                 VALUES (?1, ?2, 0, ?3) \
                 ON CONFLICT(installation_uuid, instance_id) DO UPDATE \
                    SET bytes_quota = excluded.bytes_quota",
                params![installation_uuid, instance_id, quota_i64],
            )?;
            Ok(())
        })
    }

    /// Read a single value. `Ok(None)` for "no such key" — there's no
    /// other shape the WIT contract distinguishes.
    ///
    /// # Errors
    ///
    /// SQL errors as [`KvError::Sql`]; encoding-decode failures (which
    /// would mean stored data corrupted) as [`KvError::Encode`].
    pub fn get(
        &self,
        installation_uuid: &str,
        instance_id: &str,
        key: &str,
    ) -> Result<Option<WitValue>, KvError> {
        let bytes: Option<Vec<u8>> = self.db.read(|conn| -> Result<_, KvError> {
            Ok(conn
                .query_row(
                    "SELECT value FROM kv \
                     WHERE installation_uuid = ?1 AND instance_id = ?2 AND key = ?3",
                    params![installation_uuid, instance_id, key],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .optional()?)
        })?;
        let Some(bytes) = bytes else {
            return Ok(None);
        };
        let stored: StoredValue =
            serde_json::from_slice(&bytes).map_err(|source| KvError::Encode {
                key: key.to_owned(),
                source,
            })?;
        Ok(Some(stored.into_wit()))
    }

    /// Write a value. Transactional: opens `BEGIN IMMEDIATE`, computes
    /// what `bytes_used` would become, and refuses with
    /// [`KvError::QuotaExceeded`] if the new total would exceed the
    /// instance's quota. Triggers maintain `bytes_used` so the next
    /// caller's check sees the right number.
    ///
    /// # Errors
    ///
    /// - [`KvError::UnregisteredInstance`] if the tuple never
    ///   called `register_instance`.
    /// - [`KvError::QuotaExceeded`] when the write would push past
    ///   the quota.
    /// - [`KvError::Sql`] for any underlying `SQLite` error.
    /// - [`KvError::Encode`] if the WIT value can't be JSON-encoded
    ///   (should never happen for the standard variants).
    ///
    /// # Panics
    ///
    /// Panics if `key.len() + value_payload.len()` overflows an
    /// `i64`. The triggers store sizes as `INTEGER` (i64) in `SQLite`,
    /// so a value pushing past that ceiling can't be accounted for
    /// anyway — and any plugin attempting an exabyte-scale write is
    /// already past the per-instance quota.
    pub fn set(
        &self,
        installation_uuid: &str,
        instance_id: &str,
        key: &str,
        value: WitValue,
    ) -> Result<(), KvError> {
        let stored = StoredValue::from_wit(value);
        let payload = serde_json::to_vec(&stored).map_err(|source| KvError::Encode {
            key: key.to_owned(),
            source,
        })?;
        // `key.len()` is bytes (UTF-8 source) — same units the
        // `SQLite` `length(BLOB)`/`length(TEXT)` triggers use. `i64`
        // cast: keys are bounded by the plugin author, and host
        // values are sub-megabyte; if any of these overflow i64
        // we've already hit a much bigger problem.
        let new_entry_bytes =
            i64::try_from(key.len() + payload.len()).expect("key + value size fits in i64");

        let installation_uuid_owned = installation_uuid.to_owned();
        let instance_id_owned = instance_id.to_owned();
        let key_owned = key.to_owned();
        self.db.write(move |conn| -> Result<(), KvError> {
            let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;

            // Look up the quota and any existing row's size so we can
            // do the math in one query before committing.
            let Some((bytes_used, bytes_quota)) = tx
                .query_row(
                    "SELECT bytes_used, bytes_quota FROM kv_usage \
                     WHERE installation_uuid = ?1 AND instance_id = ?2",
                    params![installation_uuid_owned, instance_id_owned],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
                )
                .optional()?
            else {
                return Err(KvError::UnregisteredInstance {
                    installation_uuid: installation_uuid_owned,
                    instance_id: instance_id_owned,
                });
            };

            // `length(key)` on a TEXT column counts characters, not
            // bytes — cast to BLOB so we get the same byte total the
            // Rust-side `key.len()` math used to project
            // `new_entry_bytes`. Migration 14's triggers use the same
            // shape so the persisted `kv_usage.bytes_used` stays in
            // sync.
            let old_size: Option<i64> = tx
                .query_row(
                    "SELECT length(CAST(key AS BLOB)) + length(value) FROM kv \
                     WHERE installation_uuid = ?1 AND instance_id = ?2 AND key = ?3",
                    params![installation_uuid_owned, instance_id_owned, key_owned],
                    |row| row.get(0),
                )
                .optional()?;

            let projected = bytes_used - old_size.unwrap_or(0) + new_entry_bytes;
            if projected > bytes_quota {
                return Err(KvError::QuotaExceeded {
                    installation_uuid: installation_uuid_owned,
                    instance_id: instance_id_owned,
                    would_use: projected.try_into().unwrap_or(u64::MAX),
                    allowed: bytes_quota.try_into().unwrap_or(0),
                });
            }

            let updated_ms = now_unix_ms();
            tx.execute(
                "INSERT INTO kv(installation_uuid, instance_id, key, value, updated_ms) \
                 VALUES (?1, ?2, ?3, ?4, ?5) \
                 ON CONFLICT(installation_uuid, instance_id, key) DO UPDATE \
                    SET value = excluded.value, updated_ms = excluded.updated_ms",
                params![
                    installation_uuid_owned,
                    instance_id_owned,
                    key_owned,
                    payload,
                    updated_ms
                ],
            )?;

            tx.commit()?;
            Ok(())
        })
    }

    /// Drop a key. Returns `Ok(())` whether the key was present or not
    /// — the WIT `storage::delete` contract makes no distinction, so
    /// neither do we.
    ///
    /// # Errors
    ///
    /// Forwards any SQL error.
    pub fn delete(
        &self,
        installation_uuid: &str,
        instance_id: &str,
        key: &str,
    ) -> Result<(), KvError> {
        self.db.write(|conn| -> Result<(), KvError> {
            conn.execute(
                "DELETE FROM kv \
                 WHERE installation_uuid = ?1 AND instance_id = ?2 AND key = ?3",
                params![installation_uuid, instance_id, key],
            )?;
            Ok(())
        })
    }

    /// List keys beginning with `prefix`. Ordering is lexicographic,
    /// matching `SQLite`'s default for `ORDER BY key`.
    ///
    /// # Errors
    ///
    /// Forwards any SQL error.
    pub fn list_keys(
        &self,
        installation_uuid: &str,
        instance_id: &str,
        prefix: &str,
    ) -> Result<Vec<String>, KvError> {
        // `substr(key, 1, length(?)) = ?` is the simplest correct
        // shape: on TEXT, SQLite's `length`/`substr` both work in
        // *characters* (UTF-8 codepoints), so this is a literal
        // character-prefix equality test. Both `key` and the
        // parameter are TEXT, so the units match on both sides of
        // the `=` — any `&str` prefix matches keys whose first
        // `chars().count()` characters equal the prefix's characters,
        // without the escaping hazards of `LIKE` or the codepoint-bound
        // arithmetic an open-coded range would need.
        //
        // (Quota accounting is the *byte* count, computed separately
        // via `length(CAST(key AS BLOB))` in migration 14's triggers
        // — that's correctness for "bytes used"; the listing here
        // is character-level prefix matching, which is what callers
        // want.)
        self.db.read(|conn| -> Result<Vec<String>, KvError> {
            let mut stmt = conn.prepare(
                "SELECT key FROM kv \
                 WHERE installation_uuid = ?1 AND instance_id = ?2 \
                   AND substr(key, 1, length(?3)) = ?3 \
                 ORDER BY key",
            )?;
            let mut rows = stmt.query(params![installation_uuid, instance_id, prefix])?;
            let mut keys = Vec::new();
            while let Some(row) = rows.next()? {
                keys.push(row.get::<_, String>(0)?);
            }
            Ok(keys)
        })
    }

    /// Current `(bytes_used, bytes_quota)` for an instance. Used by
    /// tests and the future status / debug endpoints.
    ///
    /// # Errors
    ///
    /// SQL error from the usage lookup.
    pub fn usage(
        &self,
        installation_uuid: &str,
        instance_id: &str,
    ) -> Result<Option<(u64, u64)>, KvError> {
        let row = self.db.read(|conn| -> Result<_, KvError> {
            Ok(conn
                .query_row(
                    "SELECT bytes_used, bytes_quota FROM kv_usage \
                     WHERE installation_uuid = ?1 AND instance_id = ?2",
                    params![installation_uuid, instance_id],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
                )
                .optional()?)
        })?;
        Ok(row.map(|(used, quota)| (used.try_into().unwrap_or(0), quota.try_into().unwrap_or(0))))
    }

    /// Wipe every KV row (and its usage-accounting row) for the
    /// installation tombstoned at `installation_uuid`. Called from
    /// [`crate::state::InstalledPluginRegistry::uninstall`] so a
    /// subsequent reinstall of the same `plugin_id` sees an empty
    /// keyspace — H2's central invariant.
    ///
    /// Idempotent: purging an install that had no rows is a no-op
    /// (returns 0). Runs in a single write transaction so partial
    /// failure leaves the store consistent (both tables purged or
    /// neither).
    ///
    /// # Errors
    ///
    /// Forwards any `SQLite` error verbatim.
    pub fn purge_installation(&self, installation_uuid: &str) -> Result<usize, KvError> {
        let uuid_owned = installation_uuid.to_owned();
        self.db.write(move |conn| -> Result<usize, KvError> {
            let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            // Drop `kv_usage` first so the `kv_usage_delete` triggers
            // firing on the `kv` DELETE don't do wasted work updating
            // rows that are about to disappear anyway.
            let usage_rows = tx.execute(
                "DELETE FROM kv_usage WHERE installation_uuid = ?1",
                params![uuid_owned],
            )?;
            let kv_rows = tx.execute(
                "DELETE FROM kv WHERE installation_uuid = ?1",
                params![uuid_owned],
            )?;
            tx.commit()?;
            Ok(usage_rows + kv_rows)
        })
    }
}

fn now_unix_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

/// On-disk shape for a WIT `value`. Tagged so deserialization knows
/// which variant to rebuild; serialized as JSON for now (see module
/// header).
#[derive(Serialize, Deserialize)]
#[serde(tag = "t", content = "v")]
enum StoredValue {
    Bool(bool),
    Int(i64),
    Float(f64),
    String(String),
    Bytes(Vec<u8>),
    Json(String),
}

impl StoredValue {
    fn from_wit(v: WitValue) -> Self {
        match v {
            WitValue::BoolVal(b) => Self::Bool(b),
            WitValue::IntVal(i) => Self::Int(i),
            WitValue::FloatVal(f) => Self::Float(f),
            WitValue::StringVal(s) => Self::String(s),
            WitValue::BytesVal(b) => Self::Bytes(b),
            WitValue::JsonVal(s) => Self::Json(s),
        }
    }

    fn into_wit(self) -> WitValue {
        match self {
            Self::Bool(b) => WitValue::BoolVal(b),
            Self::Int(i) => WitValue::IntVal(i),
            Self::Float(f) => WitValue::FloatVal(f),
            Self::String(s) => WitValue::StringVal(s),
            Self::Bytes(b) => WitValue::BytesVal(b),
            Self::Json(s) => WitValue::JsonVal(s),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Standing installation uuid for tests that don't care about
    /// isolation between installs. Real code always passes the
    /// per-install uuid the `InstalledPluginRegistry` minted.
    const INST_A: &str = "inst-test-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const INST_B: &str = "inst-test-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn store() -> KvStore {
        KvStore::new(Arc::new(Db::open_in_memory().expect("db")))
    }

    #[test]
    fn register_then_get_returns_none_for_missing_key() {
        let kv = store();
        kv.register_instance(INST_A, "alpha", 1024)
            .expect("register");
        assert!(kv.get(INST_A, "alpha", "k").expect("get").is_none());
    }

    #[test]
    fn set_then_get_round_trips_each_variant() {
        let kv = store();
        kv.register_instance(INST_A, "alpha", 8 * 1024)
            .expect("register");
        let cases = vec![
            ("b", WitValue::BoolVal(true)),
            ("i", WitValue::IntVal(-42)),
            ("f", WitValue::FloatVal(0.5)),
            ("s", WitValue::StringVal("hi".into())),
            ("bytes", WitValue::BytesVal(vec![0xde, 0xad])),
            ("j", WitValue::JsonVal("{\"k\":1}".into())),
        ];
        for (key, val) in &cases {
            kv.set(INST_A, "alpha", key, val.clone()).expect("set");
        }
        for (key, want) in &cases {
            let got = kv.get(INST_A, "alpha", key).expect("get").expect("present");
            assert!(
                values_match(&got, want),
                "key {key}: got {got:?} want {want:?}",
            );
        }
    }

    #[test]
    fn overwrite_keeps_one_row_and_accounts_correctly() {
        let kv = store();
        kv.register_instance(INST_A, "alpha", 1024)
            .expect("register");
        kv.set(INST_A, "alpha", "n", WitValue::IntVal(1))
            .expect("set 1");
        let (used1, _) = kv.usage(INST_A, "alpha").expect("usage").expect("present");
        kv.set(
            INST_A,
            "alpha",
            "n",
            WitValue::StringVal("ten-character".into()),
        )
        .expect("set 2");
        let (used2, _) = kv.usage(INST_A, "alpha").expect("usage").expect("present");
        assert!(
            used2 > used1,
            "overwrite with bigger value should grow bytes_used: {used1} -> {used2}",
        );
    }

    #[test]
    fn delete_removes_key_and_refunds_usage() {
        let kv = store();
        kv.register_instance(INST_A, "alpha", 1024)
            .expect("register");
        kv.set(INST_A, "alpha", "k", WitValue::StringVal("v".into()))
            .expect("set");
        let (before, _) = kv.usage(INST_A, "alpha").expect("usage").expect("present");
        kv.delete(INST_A, "alpha", "k").expect("delete");
        let (after, _) = kv.usage(INST_A, "alpha").expect("usage").expect("present");
        assert_eq!(after, 0, "delete should refund bytes (was {before})");
        assert!(kv.get(INST_A, "alpha", "k").expect("get").is_none());
    }

    #[test]
    fn quota_exceeded_refuses_write_and_keeps_old_value() {
        let kv = store();
        // 32-byte quota — small enough that one moderate string write
        // blows past it.
        kv.register_instance(INST_A, "alpha", 32).expect("register");
        kv.set(INST_A, "alpha", "k", WitValue::IntVal(1))
            .expect("first set");
        let err = kv
            .set(INST_A, "alpha", "k2", WitValue::StringVal("x".repeat(64)))
            .unwrap_err();
        match err {
            KvError::QuotaExceeded {
                allowed, would_use, ..
            } => {
                assert_eq!(allowed, 32);
                assert!(would_use > 32);
            }
            other => panic!("expected QuotaExceeded, got {other:?}"),
        }
        // First write must still be readable.
        let got = kv.get(INST_A, "alpha", "k").expect("get").expect("present");
        assert!(values_match(&got, &WitValue::IntVal(1)));
    }

    /// Regression for the byte-vs-character mismatch between the
    /// Rust-side projection (`key.len()` in bytes) and the trigger's
    /// `length(key)` on TEXT (characters). A non-ASCII key like
    /// `"αβγ"` is 6 UTF-8 bytes but 3 characters; under the
    /// pre-migration-2 triggers a 100-byte quota would accept many
    /// more `"αβγ"`-keyed writes than the byte budget allowed.
    /// Migration 2's `length(CAST(key AS BLOB))` brings both sides
    /// onto bytes; migration 14 keeps that shape.
    #[test]
    fn quota_uses_byte_count_for_non_ascii_keys() {
        let kv = store();
        kv.register_instance(INST_A, "alpha", 64).expect("register");
        // "αβγ" = 3 chars / 6 bytes. The empty-tagged
        // StoredValue::Int(0) payload is ~10 bytes of JSON.
        // First write: 6 + 10 ≈ 16 bytes ≤ 64 quota.
        kv.set(INST_A, "alpha", "αβγ", WitValue::IntVal(0))
            .expect("first non-ascii write");
        let (used_1, _) = kv.usage(INST_A, "alpha").expect("usage").expect("present");
        // `bytes_used` must reflect the 6-byte key, not 3.
        assert!(
            used_1 > 6,
            "bytes_used should count UTF-8 bytes (key alone is 6); got {used_1} for a 6-byte key + payload",
        );

        // Add three more non-ASCII keys. Each adds ~16 bytes. The
        // pre-fix accounting would land bytes_used at ~13 per row
        // and let a fifth row in; the byte-correct accounting refuses
        // anything past the 64-byte quota.
        let mut over = false;
        for i in 1..10 {
            let k = format!("αβγ-{i}");
            match kv.set(INST_A, "alpha", &k, WitValue::IntVal(0)) {
                Ok(()) => {}
                Err(KvError::QuotaExceeded { .. }) => {
                    over = true;
                    break;
                }
                Err(e) => panic!("unexpected error: {e:?}"),
            }
        }
        assert!(
            over,
            "quota should refuse a non-ASCII write once byte total exceeds 64",
        );

        // Final `bytes_used` must stay under the byte quota — the
        // pre-fix accounting could have let it pass while the
        // triggers undercounted.
        let (used_final, quota) = kv.usage(INST_A, "alpha").expect("usage").expect("present");
        assert_eq!(quota, 64);
        assert!(
            used_final <= quota,
            "bytes_used ({used_final}) must stay within quota ({quota})",
        );
    }

    #[test]
    fn list_keys_returns_matching_prefix_in_order() {
        let kv = store();
        kv.register_instance(INST_A, "alpha", 4096)
            .expect("register");
        for k in ["aa", "ab", "ba", "bb"] {
            kv.set(INST_A, "alpha", k, WitValue::BoolVal(true))
                .expect("set");
        }
        let mut keys = kv.list_keys(INST_A, "alpha", "a").expect("list");
        keys.sort();
        assert_eq!(keys, vec!["aa".to_string(), "ab".to_string()]);
        let bs = kv.list_keys(INST_A, "alpha", "b").expect("list");
        assert_eq!(bs, vec!["ba".to_string(), "bb".to_string()]);
        let none = kv.list_keys(INST_A, "alpha", "z").expect("list");
        assert!(none.is_empty());
    }

    /// Regression for the byte-level `prefix_upper_bound` shape we
    /// replaced with `substr(key, 1, length(?)) = ?`. See the
    /// pre-H2 revision of this file for the analysis.
    #[test]
    fn list_keys_non_ascii_prefix_does_not_overmatch() {
        let kv = store();
        kv.register_instance(INST_A, "alpha", 4096)
            .expect("register");
        for k in ["ÿ-keep", "Ā-drop", "z-drop", "ÿabc-keep"] {
            kv.set(INST_A, "alpha", k, WitValue::BoolVal(true))
                .expect("set");
        }
        let mut keys = kv.list_keys(INST_A, "alpha", "ÿ").expect("list");
        keys.sort();
        assert_eq!(
            keys,
            vec!["ÿ-keep".to_string(), "ÿabc-keep".to_string()],
            "prefix `ÿ` should match only keys that literally start with U+00FF",
        );
    }

    #[test]
    fn list_keys_isolated_per_instance() {
        let kv = store();
        kv.register_instance(INST_A, "alpha", 4096)
            .expect("register a");
        kv.register_instance(INST_A, "beta", 4096)
            .expect("register b");
        kv.set(INST_A, "alpha", "x", WitValue::IntVal(1))
            .expect("alpha");
        kv.set(INST_A, "beta", "x", WitValue::IntVal(2))
            .expect("beta");
        let a_keys = kv.list_keys(INST_A, "alpha", "").expect("list a");
        let b_keys = kv.list_keys(INST_A, "beta", "").expect("list b");
        assert_eq!(a_keys, vec!["x".to_string()]);
        assert_eq!(b_keys, vec!["x".to_string()]);
        let a_val = kv
            .get(INST_A, "alpha", "x")
            .expect("get a")
            .expect("present");
        let b_val = kv
            .get(INST_A, "beta", "x")
            .expect("get b")
            .expect("present");
        assert!(values_match(&a_val, &WitValue::IntVal(1)));
        assert!(values_match(&b_val, &WitValue::IntVal(2)));
    }

    #[test]
    fn unregistered_instance_set_returns_unregistered() {
        let kv = store();
        let err = kv
            .set(INST_A, "ghost", "k", WitValue::BoolVal(false))
            .unwrap_err();
        assert!(
            matches!(
                err,
                KvError::UnregisteredInstance { ref instance_id, .. } if instance_id == "ghost"
            ),
            "got {err:?}",
        );
    }

    #[test]
    fn re_register_updates_quota_in_place() {
        let kv = store();
        kv.register_instance(INST_A, "alpha", 32)
            .expect("register 32");
        kv.set(INST_A, "alpha", "k", WitValue::IntVal(1))
            .expect("set");
        kv.register_instance(INST_A, "alpha", 4096)
            .expect("re-register 4096");
        let (used, quota) = kv.usage(INST_A, "alpha").expect("usage").expect("present");
        assert_eq!(quota, 4096);
        assert!(used > 0, "re-register should preserve bytes_used");
    }

    /// H2: two installations of the same `plugin_id` (same `instance_id`
    /// string, different `installation_uuid`) must not share KV
    /// state. A `set` under one uuid is invisible to the other.
    #[test]
    fn installation_uuid_isolates_state_from_same_instance_id() {
        let kv = store();
        kv.register_instance(INST_A, "shared-id", 4096)
            .expect("register a");
        kv.register_instance(INST_B, "shared-id", 4096)
            .expect("register b");
        kv.set(INST_A, "shared-id", "k", WitValue::IntVal(1))
            .expect("set a");
        kv.set(INST_B, "shared-id", "k", WitValue::IntVal(2))
            .expect("set b");

        let a = kv
            .get(INST_A, "shared-id", "k")
            .expect("get a")
            .expect("present");
        let b = kv
            .get(INST_B, "shared-id", "k")
            .expect("get b")
            .expect("present");
        assert!(values_match(&a, &WitValue::IntVal(1)));
        assert!(values_match(&b, &WitValue::IntVal(2)));

        // `list_keys` respects the isolation too.
        let a_keys = kv.list_keys(INST_A, "shared-id", "").expect("list a");
        let b_keys = kv.list_keys(INST_B, "shared-id", "").expect("list b");
        assert_eq!(a_keys, vec!["k".to_string()]);
        assert_eq!(b_keys, vec!["k".to_string()]);
    }

    /// H2: `purge_installation` wipes every row (kv + `kv_usage`) for
    /// the tombstoned install. Other installs' rows are left intact.
    #[test]
    fn purge_installation_wipes_only_that_installations_rows() {
        let kv = store();
        kv.register_instance(INST_A, "alpha", 4096)
            .expect("register a");
        kv.register_instance(INST_B, "alpha", 4096)
            .expect("register b");
        kv.set(INST_A, "alpha", "k", WitValue::IntVal(1))
            .expect("set a");
        kv.set(INST_A, "alpha", "j", WitValue::IntVal(2))
            .expect("set a2");
        kv.set(INST_B, "alpha", "k", WitValue::IntVal(3))
            .expect("set b");

        let removed = kv.purge_installation(INST_A).expect("purge");
        assert!(
            removed >= 3,
            "purge should remove kv rows + usage row (got {removed})",
        );
        assert!(kv.usage(INST_A, "alpha").expect("usage a").is_none());
        assert!(kv.get(INST_A, "alpha", "k").expect("get a").is_none());
        // Untouched install still has its data.
        let b = kv
            .get(INST_B, "alpha", "k")
            .expect("get b")
            .expect("present");
        assert!(values_match(&b, &WitValue::IntVal(3)));
    }

    /// `purge_installation` on an install that never registered is
    /// a no-op — the DELETE hits zero rows, and callers relying on
    /// idempotence (uninstall retries) don't have to special-case it.
    #[test]
    fn purge_installation_is_idempotent() {
        let kv = store();
        assert_eq!(kv.purge_installation(INST_A).expect("purge"), 0);
        assert_eq!(kv.purge_installation(INST_A).expect("purge"), 0);
    }

    fn values_match(a: &WitValue, b: &WitValue) -> bool {
        match (a, b) {
            (WitValue::BoolVal(x), WitValue::BoolVal(y)) => x == y,
            (WitValue::IntVal(x), WitValue::IntVal(y)) => x == y,
            (WitValue::FloatVal(x), WitValue::FloatVal(y)) => (x - y).abs() < f64::EPSILON,
            (WitValue::StringVal(x), WitValue::StringVal(y))
            | (WitValue::JsonVal(x), WitValue::JsonVal(y)) => x == y,
            (WitValue::BytesVal(x), WitValue::BytesVal(y)) => x == y,
            _ => false,
        }
    }
}
