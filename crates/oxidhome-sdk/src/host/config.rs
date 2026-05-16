//! Per-instance config reads from the plugin side of the WIT
//! `host-config` interface.
//!
//! The host resolves each plugin instance's config from
//! `manifest.toml`'s `[config]` defaults folded with any
//! user-supplied override blob (see [`oxidhome-manifest`'s
//! `merge`](../../../oxidhome_manifest/fn.merge.html)). The plugin
//! reads it back through these helpers:
//!
//! - [`get`] — raw WIT [`Value`] for one key. Useful when the
//!   plugin wants to match on the variant itself.
//! - [`get_typed`] — deserialize one key into any
//!   `T: DeserializeOwned`. Bridges WIT `value` through
//!   `serde_json::Value` so primitives *and* structured payloads
//!   carried as `json-val` work transparently.
//! - [`list`] — every config key the host resolved, as a
//!   `HashMap<String, Value>`.
//!
//! All three forward into the wit-bindgen-generated import; calling
//! them from a native test binary fails to link — see the unit-test
//! exemption note in [`super`].

use std::collections::HashMap;

use crate::bindings::oxidhome::plugin::host_config;
use crate::bindings::oxidhome::plugin::types::{Error, Value};

/// Error returned by [`get_typed`] when the host responded fine but
/// the value couldn't be deserialized into the plugin's `T`.
///
/// `get_typed` also forwards plain host errors as
/// [`ConfigError::Host`] so callers can match on
/// `Error::Unavailable` etc. without juggling two error types.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The host returned an `error` variant — typically
    /// [`Error::Unavailable`] when the config surface isn't ready,
    /// or [`Error::PermissionDenied`] when a future phase gates
    /// config reads.
    #[error("host config read failed: {0:?}")]
    Host(Error),
    /// The host returned a value, but `serde_json::from_value::<T>`
    /// refused it — usually a type mismatch between the manifest's
    /// declared schema and the plugin's `T`. The `key` is included
    /// so a plugin reading several fields can tell which one is
    /// wrong.
    #[error("config key `{key}` could not be deserialized: {source}")]
    Deserialize {
        key: String,
        #[source]
        source: serde_json::Error,
    },
}

/// Look up a single config value, untyped. Returns `Ok(None)` when
/// the host has no entry for `key` (the manifest may declare it but
/// flag it `required = false` with no default).
///
/// # Errors
///
/// Forwards any host [`Error`] verbatim.
pub fn get(key: &str) -> Result<Option<Value>, Error> {
    host_config::get_config(key)
}

/// Look up a single config value and deserialize it into `T`.
///
/// Maps the WIT `value` variant to a `serde_json::Value` and then
/// hands it to `serde_json::from_value::<T>(...)`. Practical effect:
///
/// - `get_typed::<bool>("enabled")` ⇒ `BoolVal` works.
/// - `get_typed::<i64>("port")` ⇒ `IntVal` works.
/// - `get_typed::<String>("host")` ⇒ `StringVal` works.
/// - `get_typed::<MyStruct>("options")` ⇒ host must have returned a
///   `JsonVal` containing JSON the struct can deserialize from.
///
/// Returns `Ok(None)` when the host has no entry for `key`.
///
/// # Errors
///
/// - [`ConfigError::Host`] if the host returned a typed error.
/// - [`ConfigError::Deserialize`] if the value's shape didn't match
///   `T` (e.g. asking for `bool` and getting `IntVal`).
pub fn get_typed<T>(key: &str) -> Result<Option<T>, ConfigError>
where
    T: serde::de::DeserializeOwned,
{
    let raw = host_config::get_config(key).map_err(ConfigError::Host)?;
    let Some(value) = raw else { return Ok(None) };
    deserialize_value(key, value).map(Some)
}

/// Every config key the host resolved for this instance, keyed by
/// the same dot-joined path the manifest used.
///
/// # Errors
///
/// Forwards any host [`Error`] verbatim.
pub fn list() -> Result<HashMap<String, Value>, Error> {
    let kvs = host_config::list_config()?;
    Ok(kvs.into_iter().map(|kv| (kv.key, kv.value)).collect())
}

/// Convert one WIT [`Value`] into the plugin's `T`. Extracted out of
/// [`get_typed`] so the *conversion logic* — which is pure and
/// doesn't touch the wit-bindgen-generated stubs — can be exercised
/// in native unit tests.
fn deserialize_value<T>(key: &str, value: Value) -> Result<T, ConfigError>
where
    T: serde::de::DeserializeOwned,
{
    let json = value_to_json(value)?;
    serde_json::from_value(json).map_err(|source| ConfigError::Deserialize {
        key: key.to_owned(),
        source,
    })
}

/// Map a WIT [`Value`] variant to a [`serde_json::Value`]. `JsonVal`
/// strings are parsed; everything else maps to its natural JSON
/// shape. Returns [`ConfigError::Deserialize`] when a `JsonVal`'s
/// payload isn't valid JSON, with the key marker `"<json-val>"` so
/// the caller can see this came from the payload-parse hop rather
/// than the final `from_value::<T>` hop.
fn value_to_json(value: Value) -> Result<serde_json::Value, ConfigError> {
    use serde_json::Value as J;
    Ok(match value {
        Value::BoolVal(b) => J::Bool(b),
        Value::IntVal(i) => J::Number(i.into()),
        Value::FloatVal(f) => {
            // serde_json's Number can't carry NaN / ±inf. Manifest
            // validation already rejects non-finite floats; treat any
            // sneaking-through value as a deserialize failure rather
            // than panicking on the `from_f64` unwrap.
            serde_json::Number::from_f64(f)
                .map(J::Number)
                .ok_or_else(|| ConfigError::Deserialize {
                    key: "<float-val>".into(),
                    source: serde_json::Error::io(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "non-finite float in host config value",
                    )),
                })?
        }
        Value::StringVal(s) => J::String(s),
        Value::BytesVal(b) => J::Array(b.into_iter().map(|byte| J::Number(byte.into())).collect()),
        Value::JsonVal(text) => {
            serde_json::from_str(&text).map_err(|source| ConfigError::Deserialize {
                key: "<json-val>".into(),
                source,
            })?
        }
    })
}

#[cfg(test)]
mod tests {
    //! The pure conversion logic — `deserialize_value` /
    //! `value_to_json` — runs fine on the native target. The two
    //! host-touching wrappers ([`get`], [`get_typed`], [`list`])
    //! resolve only under Wasmtime; their end-to-end coverage is in
    //! `oxidhome-core/tests/config_overrides.rs`.

    use super::*;
    use serde::Deserialize;

    #[test]
    fn bool_value_deserializes_to_bool() {
        let got: bool = deserialize_value("on", Value::BoolVal(true)).expect("bool");
        assert!(got);
    }

    #[test]
    fn int_value_deserializes_to_i64() {
        let got: i64 = deserialize_value("port", Value::IntVal(8080)).expect("int");
        assert_eq!(got, 8080);
    }

    #[test]
    fn float_value_deserializes_to_f64() {
        let got: f64 = deserialize_value("ratio", Value::FloatVal(0.5)).expect("float");
        assert!((got - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn string_value_deserializes_to_string() {
        let got: String = deserialize_value("host", Value::StringVal("ok".into())).expect("string");
        assert_eq!(got, "ok");
    }

    /// `JsonVal` is the structured-payload escape hatch — its body
    /// is a JSON string, so a complex `T` lands through
    /// `serde_json::from_str` on the payload.
    #[test]
    fn json_value_deserializes_to_struct() {
        #[derive(Deserialize, PartialEq, Debug)]
        struct Inner {
            mode: String,
            attempts: u32,
        }
        let payload = r#"{"mode":"fast","attempts":3}"#;
        let got: Inner =
            deserialize_value("policy", Value::JsonVal(payload.into())).expect("inner");
        assert_eq!(
            got,
            Inner {
                mode: "fast".into(),
                attempts: 3,
            }
        );
    }

    /// Asking for the wrong type surfaces as a `Deserialize` error
    /// naming the key — that's what makes the error actionable when
    /// a plugin reads several config fields in one call.
    #[test]
    fn type_mismatch_reports_key_in_error() {
        let res: Result<bool, _> = deserialize_value("port", Value::IntVal(8080));
        let err = res.unwrap_err();
        match err {
            ConfigError::Deserialize { key, .. } => assert_eq!(key, "port"),
            ConfigError::Host(e) => panic!("expected Deserialize, got Host({e:?})"),
        }
    }

    /// Malformed JSON inside a `JsonVal` is reported with a
    /// `<json-val>` key marker so the caller can tell the failure
    /// happened during payload parsing, not during the final
    /// `from_value::<T>` hop.
    #[test]
    fn malformed_json_val_reports_json_val_marker() {
        let res: Result<serde_json::Value, _> =
            deserialize_value("policy", Value::JsonVal("{ not json".into()));
        let err = res.unwrap_err();
        match err {
            ConfigError::Deserialize { key, .. } => assert_eq!(key, "<json-val>"),
            ConfigError::Host(e) => panic!("expected Deserialize, got Host({e:?})"),
        }
    }

    /// Non-finite floats are blocked by the manifest validator, but
    /// if one slips through (e.g. an `IntVal` reinterpreted, or a
    /// future host change), it shows up as a deserialize failure
    /// rather than a panic from `Number::from_f64`.
    #[test]
    fn non_finite_float_does_not_panic() {
        let res: Result<f64, _> = deserialize_value("ratio", Value::FloatVal(f64::NAN));
        let err = res.unwrap_err();
        match err {
            ConfigError::Deserialize { ref key, .. } => assert_eq!(key, "<float-val>"),
            ConfigError::Host(e) => panic!("expected Deserialize, got Host({e:?})"),
        }
    }

    /// `bytes-val` round-trips as a JSON array of integers — a
    /// `Vec<u8>` deserialize on top of that recovers the bytes.
    #[test]
    fn bytes_value_deserializes_to_vec_u8() {
        let got: Vec<u8> =
            deserialize_value("sig", Value::BytesVal(vec![0xde, 0xad, 0xbe, 0xef])).expect("bytes");
        assert_eq!(got, vec![0xde, 0xad, 0xbe, 0xef]);
    }
}
