//! Per-instance KV reads/writes from the plugin side of the WIT
//! `storage` interface.
//!
//! Each plugin instance has its own keyspace, sized by
//! `capabilities.storage_quota_kb` in `manifest.toml`. Values are the
//! WIT `value` variant — primitives plus `bytes-val` and `json-val`.
//! See [`super::config`] for the matching typed-getter pattern; the
//! same `get_typed::<T: DeserializeOwned>` shape lives here too so
//! storage and config feel the same from the plugin author's seat.
//!
//! All five entry points forward into wit-bindgen-generated stubs;
//! calling them from a native test binary fails to link. The native
//! unit tests in this module cover the pure helpers
//! (`encode_value`/`decode_value` round-trip + error mapping); the
//! WIT-touching wrappers are exercised end-to-end through
//! `oxidhome-core/tests/storage_persistence.rs` and the `kv-counter`
//! example.
//!
//! Error shape mirrors [`super::config`]: a plain [`Error`] for
//! straight host failures, [`StorageError`] (`Host` / `Deserialize`)
//! for the `get_typed` / `set_typed` helpers.

use crate::bindings::oxidhome::plugin::storage;
use crate::bindings::oxidhome::plugin::types::{Error, Value};

/// Error returned by [`get_typed`] / [`set_typed`] when the host
/// responded fine but the value couldn't be deserialized into the
/// plugin's `T`, or vice versa for `set`.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    /// The host returned an `error` variant — typically
    /// [`Error::PermissionDenied`] when storage is gated off or the
    /// instance's KV quota would be exceeded.
    #[error("host storage call failed: {0:?}")]
    Host(Error),
    /// Type mismatch: stored value can't be deserialized into `T`,
    /// or `T` can't be encoded into a WIT value.
    #[error("storage key `{key}` could not be (de)serialized: {source}")]
    Codec {
        key: String,
        #[source]
        source: serde_json::Error,
    },
}

/// Look up a single value, untyped. Returns `Ok(None)` when the host
/// has no entry for `key` — first-boot / never-written semantics.
///
/// # Errors
///
/// Forwards any host [`Error`] verbatim.
pub fn get(key: &str) -> Result<Option<Value>, Error> {
    storage::get(key)
}

/// Look up a single value and deserialize it into `T`. The WIT
/// `value` variant is bridged through `serde_json::Value` so
/// primitives + structured payloads (via `JsonVal`) both work.
///
/// # Errors
///
/// - [`StorageError::Host`] if the host returned a typed error.
/// - [`StorageError::Codec`] if the value's shape didn't match `T`.
pub fn get_typed<T>(key: &str) -> Result<Option<T>, StorageError>
where
    T: serde::de::DeserializeOwned,
{
    let raw = storage::get(key).map_err(StorageError::Host)?;
    let Some(value) = raw else { return Ok(None) };
    decode_value(key, value).map(Some)
}

/// Write a raw WIT [`Value`]. Quota enforcement happens on the host
/// — over-quota writes surface as [`Error::PermissionDenied`] with
/// `"quota exceeded: …"` in the message.
///
/// # Errors
///
/// Forwards any host error.
pub fn set(key: &str, val: &Value) -> Result<(), Error> {
    storage::set(key, val)
}

/// Serialize `value: &T` to a WIT [`Value::JsonVal`] and write it.
///
/// `set_typed` always picks `JsonVal` — plugin code that wants a
/// specific WIT variant (`BoolVal`, `IntVal`, …) should call [`set`]
/// directly with the constructed `Value`. Using `JsonVal` here keeps
/// the round-trip simple: anything serde supports goes through.
///
/// # Errors
///
/// - [`StorageError::Codec`] if `T` can't be JSON-encoded.
/// - [`StorageError::Host`] for any host-side failure (quota,
///   permission, sqlite).
pub fn set_typed<T>(key: &str, value: &T) -> Result<(), StorageError>
where
    T: serde::Serialize,
{
    let encoded = serde_json::to_string(value).map_err(|source| StorageError::Codec {
        key: key.to_owned(),
        source,
    })?;
    storage::set(key, &Value::JsonVal(encoded)).map_err(StorageError::Host)
}

/// Drop a key. Returns `Ok(())` whether the key existed or not (the
/// WIT contract makes no distinction).
///
/// # Errors
///
/// Forwards any host error.
pub fn delete(key: &str) -> Result<(), Error> {
    storage::delete(key)
}

/// List keys beginning with `prefix`. Order is lexicographic; an
/// empty `prefix` enumerates every key in the instance.
///
/// # Errors
///
/// Forwards any host error.
pub fn list_keys(prefix: &str) -> Result<Vec<String>, Error> {
    storage::list_keys(prefix)
}

/// Map one WIT [`Value`] into the plugin's `T`. Pure — extracted so
/// the conversion logic can be unit-tested natively without the
/// wit-bindgen-generated stubs.
fn decode_value<T>(key: &str, value: Value) -> Result<T, StorageError>
where
    T: serde::de::DeserializeOwned,
{
    let json = value_to_json(value)?;
    serde_json::from_value(json).map_err(|source| StorageError::Codec {
        key: key.to_owned(),
        source,
    })
}

/// Same mapping as [`super::config::value_to_json`] — kept local to
/// keep the storage module self-contained. Phase-5b's blob-store
/// helpers will follow the same shape.
fn value_to_json(value: Value) -> Result<serde_json::Value, StorageError> {
    use serde_json::Value as J;
    Ok(match value {
        Value::BoolVal(b) => J::Bool(b),
        Value::IntVal(i) => J::Number(i.into()),
        Value::FloatVal(f) => serde_json::Number::from_f64(f)
            .map(J::Number)
            .ok_or_else(|| StorageError::Codec {
                key: "<float-val>".into(),
                source: serde_json::Error::io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "non-finite float in stored value",
                )),
            })?,
        Value::StringVal(s) => J::String(s),
        Value::BytesVal(b) => J::Array(b.into_iter().map(|byte| J::Number(byte.into())).collect()),
        Value::JsonVal(text) => {
            serde_json::from_str(&text).map_err(|source| StorageError::Codec {
                key: "<json-val>".into(),
                source,
            })?
        }
    })
}

#[cfg(test)]
mod tests {
    //! Native-target tests for the pure helpers. The WIT-touching
    //! wrappers are end-to-end-tested through
    //! `oxidhome-core/tests/storage_persistence.rs`.

    use super::*;
    use serde::Deserialize;

    #[test]
    fn decode_round_trips_primitives() {
        let i: i64 = decode_value("k", Value::IntVal(42)).expect("int");
        assert_eq!(i, 42);
        let s: String = decode_value("k", Value::StringVal("hi".into())).expect("str");
        assert_eq!(s, "hi");
        let b: bool = decode_value("k", Value::BoolVal(true)).expect("bool");
        assert!(b);
    }

    #[test]
    fn decode_round_trips_struct_through_json_val() {
        #[derive(Deserialize, PartialEq, Debug)]
        struct S {
            n: u32,
            label: String,
        }
        let got: S =
            decode_value("k", Value::JsonVal(r#"{"n":7,"label":"go"}"#.into())).expect("struct");
        assert_eq!(
            got,
            S {
                n: 7,
                label: "go".into()
            }
        );
    }

    #[test]
    fn decode_reports_key_on_type_mismatch() {
        let res: Result<bool, _> = decode_value("n", Value::IntVal(1));
        match res.unwrap_err() {
            StorageError::Codec { key, .. } => assert_eq!(key, "n"),
            StorageError::Host(e) => panic!("expected Codec, got Host({e:?})"),
        }
    }

    // `set_typed`'s encode hop relies on `serde_json::to_string`
    // for any `T: Serialize`. There's no native test for the
    // encode-failure path because `serde_json` is famously
    // accepting — non-finite floats land as `null`, recursive
    // types loop until stack overflow, etc., so a synthetic
    // failure here would be testing serde rather than this module.
    // The error mapping itself is the same shape as the decode side
    // covered above.
}
