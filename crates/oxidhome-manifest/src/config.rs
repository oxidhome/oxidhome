//! Per-instance config schema + the merge that produces runtime values.
//!
//! The manifest declares an editable shape under `[config.<key>]`
//! tables; the user's host config carries instance-specific overrides
//! as a `toml::Value`. [`merge`] folds the two into a typed
//! [`InstanceConfig`] the host hands to plugins.
//!
//! Type system:
//! - `bool` — true/false
//! - `int`  — i64
//! - `float` — f64
//! - `string` — arbitrary
//! - `enum` — string-valued, restricted to a declared `values` list
//! - `nested` — recursive `[config.<key>.fields.<subkey>]` schema
//! - `secret` — string-valued credential (password, API key, token).
//!   See [Secret fields](#secret-fields).
//!
//! # Secret fields
//!
//! ```toml
//! [config.api_key]
//! type = "secret"
//! required = true      # optional, defaults to true
//! description = "Cloud API key."
//! ```
//!
//! A `secret` field holds a string the owning plugin needs but nobody
//! else should read back:
//!
//! - It never has a `default`: a manifest ships inside the plugin
//!   package and is served by the schema endpoint, so it is not a
//!   place for credentials. The value arrives as a per-instance
//!   override (the same `config_overrides` every other field uses).
//! - `required = false` makes it optional; an unset optional secret is
//!   simply absent from the resolved config.
//! - The resolved value is a [`ConfigValue::Secret`] wrapping a
//!   [`SecretString`], whose `Debug` and `Serialize` impls both emit
//!   [`MASKED`] (`"***"`). Only the owning plugin's `host-config` calls
//!   see the plaintext, through [`SecretString::expose`]. Every host
//!   read surface (REST, Connect, MCP) renders the field as masked with
//!   a `set` flag instead.
//! - Merge errors for a secret never echo the value (there is no range
//!   or enum check to fail, and a type mismatch reports only the type).

use std::collections::BTreeMap;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};

use crate::manifest::PluginManifest;
use crate::validate::ValidationError;

/// One field in the manifest's `[config]` table.
///
/// Stored shape on disk:
///
/// ```toml
/// [config.default_state]
/// type = "bool"
/// default = false
/// description = "Initial state of the switch."
/// ```
///
/// `type` discriminates the variant; the `default`/`values`/`fields`
/// keys are interpreted per variant.
//
// Strict deserialization is implemented by hand below rather than
// derived: serde's `deny_unknown_fields` on internally-tagged enums
// combined with `#[serde(flatten)]` doesn't reliably reject unknown
// keys, so a typo'd `defualt` or a misplaced `min` on a `bool` would
// silently disappear. The custom `Deserialize` impl below routes the
// TOML table through a strict helper, then dispatches on `type` and
// rejects any field that isn't part of the chosen variant. Serialize
// remains derived since the typed enum naturally produces the right
// on-disk shape.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ConfigField {
    #[serde(flatten)]
    pub ty: ConfigFieldType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Type tag + default payload for one config field. Internally tagged
/// by the `type` key so the TOML shape is the natural one above.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ConfigFieldType {
    Bool {
        #[serde(default)]
        default: Option<bool>,
    },
    Int {
        #[serde(default)]
        default: Option<i64>,
        #[serde(default)]
        min: Option<i64>,
        #[serde(default)]
        max: Option<i64>,
    },
    Float {
        #[serde(default)]
        default: Option<f64>,
        #[serde(default)]
        min: Option<f64>,
        #[serde(default)]
        max: Option<f64>,
    },
    String {
        #[serde(default)]
        default: Option<String>,
    },
    Enum {
        values: Vec<String>,
        #[serde(default)]
        default: Option<String>,
    },
    Nested {
        fields: BTreeMap<String, ConfigField>,
    },
    /// A credential. String-valued, never defaulted, masked on every
    /// host read surface. See the [module docs](self#secret-fields).
    Secret {
        /// `false` lets the instance start without the secret set.
        #[serde(default = "default_true")]
        required: bool,
    },
}

fn default_true() -> bool {
    true
}

/// Strict-key helper used by [`ConfigField`]'s custom `Deserialize`.
///
/// Every possible per-variant key is listed once with `#[serde(default)]`
/// so omission is OK. `deny_unknown_fields` then refuses anything
/// outside this set, which catches typos like `defualt = true` at parse
/// time. The dispatch in [`ConfigField::deserialize`] additionally
/// rejects keys that *exist* in the helper but don't apply to the
/// declared `type` — e.g. `min` on a `bool`, or `values` on an `int`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigFieldHelper {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    default: Option<toml::Value>,
    #[serde(default)]
    min: Option<toml::Value>,
    #[serde(default)]
    max: Option<toml::Value>,
    #[serde(default)]
    values: Option<Vec<String>>,
    #[serde(default)]
    fields: Option<BTreeMap<String, ConfigField>>,
    #[serde(default)]
    required: Option<toml::Value>,
}

impl<'de> Deserialize<'de> for ConfigField {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let h = ConfigFieldHelper::deserialize(d)?;
        let ty = match h.kind.as_str() {
            "bool" => {
                ensure_unset::<D>(&h, &["values", "fields", "min", "max", "required"], "bool")?;
                let default = match h.default {
                    None => None,
                    Some(toml::Value::Boolean(b)) => Some(b),
                    Some(other) => {
                        return Err(D::Error::custom(format!(
                            "config field `type = \"bool\"`: `default` must be a boolean, got {}",
                            type_name(&other),
                        )));
                    }
                };
                ConfigFieldType::Bool { default }
            }
            "int" => {
                ensure_unset::<D>(&h, &["values", "fields", "required"], "int")?;
                let default = take_int::<D>(h.default, "default")?;
                let min = take_int::<D>(h.min, "min")?;
                let max = take_int::<D>(h.max, "max")?;
                ConfigFieldType::Int { default, min, max }
            }
            "float" => {
                ensure_unset::<D>(&h, &["values", "fields", "required"], "float")?;
                let default = take_float::<D>(h.default, "default")?;
                let min = take_float::<D>(h.min, "min")?;
                let max = take_float::<D>(h.max, "max")?;
                ConfigFieldType::Float { default, min, max }
            }
            "string" => {
                ensure_unset::<D>(
                    &h,
                    &["values", "fields", "min", "max", "required"],
                    "string",
                )?;
                let default = match h.default {
                    None => None,
                    Some(toml::Value::String(s)) => Some(s),
                    Some(other) => {
                        return Err(D::Error::custom(format!(
                            "config field `type = \"string\"`: `default` must be a string, got {}",
                            type_name(&other),
                        )));
                    }
                };
                ConfigFieldType::String { default }
            }
            "enum" => {
                ensure_unset::<D>(&h, &["fields", "min", "max", "required"], "enum")?;
                let values = h.values.ok_or_else(|| {
                    D::Error::custom("config field `type = \"enum\"` requires `values`")
                })?;
                let default = match h.default {
                    None => None,
                    Some(toml::Value::String(s)) => Some(s),
                    Some(other) => {
                        return Err(D::Error::custom(format!(
                            "config field `type = \"enum\"`: `default` must be a string, got {}",
                            type_name(&other),
                        )));
                    }
                };
                ConfigFieldType::Enum { values, default }
            }
            "nested" => {
                ensure_unset::<D>(
                    &h,
                    &["default", "values", "min", "max", "required"],
                    "nested",
                )?;
                let fields = h.fields.ok_or_else(|| {
                    D::Error::custom("config field `type = \"nested\"` requires `fields`")
                })?;
                ConfigFieldType::Nested { fields }
            }
            "secret" => parse_secret::<D>(&h)?,
            other => {
                return Err(D::Error::custom(format!(
                    "unknown config field `type` `{other}` \
                     (expected bool/int/float/string/enum/nested/secret)"
                )));
            }
        };
        Ok(ConfigField {
            ty,
            description: h.description,
        })
    }
}

/// `type = "secret"` arm of [`ConfigField`]'s `Deserialize`.
fn parse_secret<'de, D: Deserializer<'de>>(
    h: &ConfigFieldHelper,
) -> Result<ConfigFieldType, D::Error> {
    if h.default.is_some() {
        return Err(D::Error::custom(
            "config field `type = \"secret\"`: `default` is not allowed — a manifest \
             ships with the package and is served by the schema endpoint, so it must \
             not carry credentials; supply the value as a per-instance config override",
        ));
    }
    ensure_unset::<D>(h, &["values", "fields", "min", "max"], "secret")?;
    let required = match &h.required {
        None => true,
        Some(toml::Value::Boolean(b)) => *b,
        Some(other) => {
            return Err(D::Error::custom(format!(
                "config field `type = \"secret\"`: `required` must be a boolean, got {}",
                type_name(other),
            )));
        }
    };
    Ok(ConfigFieldType::Secret { required })
}

/// Helper: return an error if any of the named helper fields is
/// `Some(_)`. Used to reject category-mismatched keys like `min` on a
/// `bool` field or `values` on an `int`.
fn ensure_unset<'de, D: Deserializer<'de>>(
    h: &ConfigFieldHelper,
    disallowed: &[&str],
    kind: &str,
) -> Result<(), D::Error> {
    for key in disallowed {
        let present = match *key {
            "default" => h.default.is_some(),
            "min" => h.min.is_some(),
            "max" => h.max.is_some(),
            "values" => h.values.is_some(),
            "fields" => h.fields.is_some(),
            "required" => h.required.is_some(),
            _ => false,
        };
        if present {
            return Err(D::Error::custom(format!(
                "config field `type = \"{kind}\"`: `{key}` is not valid for this type"
            )));
        }
    }
    Ok(())
}

fn take_int<'de, D: Deserializer<'de>>(
    v: Option<toml::Value>,
    key: &str,
) -> Result<Option<i64>, D::Error> {
    match v {
        None => Ok(None),
        Some(toml::Value::Integer(n)) => Ok(Some(n)),
        Some(other) => Err(D::Error::custom(format!(
            "config field `type = \"int\"`: `{key}` must be an integer, got {}",
            type_name(&other),
        ))),
    }
}

fn take_float<'de, D: Deserializer<'de>>(
    v: Option<toml::Value>,
    key: &str,
) -> Result<Option<f64>, D::Error> {
    match v {
        None => Ok(None),
        Some(toml::Value::Float(n)) => Ok(Some(n)),
        // Accept an integer literal where a float is expected so authors
        // can write `min = 0` rather than `min = 0.0`. TOML treats them
        // as distinct types but the manifest UX shouldn't. Precision
        // loss is theoretically possible for `|n| > 2^53` but the
        // manifest values we see in practice are small constants.
        #[allow(clippy::cast_precision_loss)]
        Some(toml::Value::Integer(n)) => Ok(Some(n as f64)),
        Some(other) => Err(D::Error::custom(format!(
            "config field `type = \"float\"`: `{key}` must be a float, got {}",
            type_name(&other),
        ))),
    }
}

/// The placeholder every host surface renders in place of a secret
/// value.
pub const MASKED: &str = "***";

/// A secret config value. The plaintext is reachable only through
/// [`Self::expose`]; `Debug` and `Serialize` both emit [`MASKED`], so a
/// stray `{:?}`, `tracing` field, or JSON encoding of an
/// [`InstanceConfig`] cannot leak it.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(transparent)]
pub struct SecretString(String);

impl SecretString {
    /// Wrap a plaintext secret.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The plaintext. Call this only on the path that hands the value to
    /// the owning plugin (`host-config`) or that scrubs it from text.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for SecretString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretString({MASKED:?})")
    }
}

impl Serialize for SecretString {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(MASKED)
    }
}

/// Resolved value for a single config field after defaults are
/// applied and user overrides are merged in.
///
/// `Serialize` is lossy for [`Self::Secret`] by design (it emits
/// [`MASKED`]); `Deserialize` never produces a `Secret` because the
/// untagged representation can't tell it from a `String`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ConfigValue {
    Bool(bool),
    Int(i64),
    Float(f64),
    String(String),
    Nested(BTreeMap<String, ConfigValue>),
    /// A `type = "secret"` field's value. Masked everywhere except
    /// [`SecretString::expose`].
    Secret(SecretString),
}

/// The whole resolved config for one plugin instance — what the host
/// hands to `host-config::*` after manifest defaults are merged with
/// user overrides.
pub type InstanceConfig = BTreeMap<String, ConfigValue>;

/// Where a resolved value came from. Threaded through the per-type
/// `resolve_*` helpers so that downstream range / finite / enum
/// checks can attribute errors correctly: a default-sourced value
/// that fails a check is a *schema* problem (the manifest author's
/// fault), while an override-sourced value that fails is a *runtime
/// override* problem (the deployment's fault). Without this
/// distinction `merge()` called without a prior `validate()` would
/// report schema bugs as override errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ValueSource {
    /// Value came from the manifest's declared `default`.
    Default,
    /// Value came from the user-supplied override blob.
    Override,
}

/// Fold the manifest's `[config]` defaults with a user-supplied
/// override `toml::Value` (a TOML table keyed by config-field names)
/// into a typed [`InstanceConfig`].
///
/// Errors are *collected* into a `Vec<ValidationError>` so the CLI
/// install dialog can surface every problem at once. Unknown override
/// keys, missing required values (a field with no default and no
/// override), and type mismatches are all reported.
///
/// # Errors
///
/// Returns `Err` whenever any field can't be resolved or any override
/// is malformed. The `Ok` path is always a fully-typed
/// [`InstanceConfig`].
pub fn merge(
    manifest: &PluginManifest,
    overrides: &toml::Value,
) -> Result<InstanceConfig, Vec<ValidationError>> {
    let mut errors = Vec::new();
    let toml::Value::Table(override_table) = overrides else {
        errors.push(ValidationError::ConfigOverrideShape {
            path: "<root>".to_owned(),
        });
        return Err(errors);
    };

    // Unknown override keys → error.
    for k in override_table.keys() {
        if !manifest.config.contains_key(k) {
            errors.push(ValidationError::UnknownConfigKey { key: k.clone() });
        }
    }

    let mut out = InstanceConfig::new();
    for (name, field) in &manifest.config {
        let override_val = override_table.get(name);
        // A `None` from `resolve_field` means the field couldn't be
        // resolved (no override, no default); the error is already
        // pushed.
        if let Some(v) = resolve_field(name, field, override_val, &mut errors) {
            out.insert(name.clone(), v);
        }
    }

    if errors.is_empty() {
        Ok(out)
    } else {
        Err(errors)
    }
}

fn resolve_field(
    path: &str,
    field: &ConfigField,
    override_val: Option<&toml::Value>,
    errors: &mut Vec<ValidationError>,
) -> Option<ConfigValue> {
    match &field.ty {
        ConfigFieldType::Bool { default } => resolve_bool(path, *default, override_val, errors),
        ConfigFieldType::Int { default, min, max } => {
            resolve_int(path, *default, *min, *max, override_val, errors)
        }
        ConfigFieldType::Float { default, min, max } => {
            resolve_float(path, *default, *min, *max, override_val, errors)
        }
        ConfigFieldType::String { default } => {
            resolve_string(path, default.as_deref(), override_val, errors)
        }
        ConfigFieldType::Enum { values, default } => {
            resolve_enum(path, values, default.as_deref(), override_val, errors)
        }
        ConfigFieldType::Nested { fields } => resolve_nested(path, fields, override_val, errors),
        ConfigFieldType::Secret { required } => {
            resolve_secret(path, *required, override_val, errors)
        }
    }
}

fn resolve_secret(
    path: &str,
    required: bool,
    override_val: Option<&toml::Value>,
    errors: &mut Vec<ValidationError>,
) -> Option<ConfigValue> {
    // Errors here name the type only, never the value — the override
    // may be the credential itself.
    if let Some(v) = override_val {
        if let Some(s) = v.as_str() {
            return Some(ConfigValue::Secret(SecretString::new(s)));
        }
        errors.push(ValidationError::ConfigTypeMismatch {
            path: path.to_owned(),
            expected: "string",
            got: type_name(v),
        });
        return None;
    }
    if required {
        errors.push(ValidationError::ConfigRequired {
            path: path.to_owned(),
        });
    }
    None
}

/// Dotted paths (`broker.password`) of every `type = "secret"` field in
/// `fields`, recursing into `nested` tables. Sorted.
#[must_use]
pub fn secret_paths(fields: &BTreeMap<String, ConfigField>) -> Vec<String> {
    fn walk(prefix: &str, fields: &BTreeMap<String, ConfigField>, out: &mut Vec<String>) {
        for (name, field) in fields {
            let path = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}.{name}")
            };
            match &field.ty {
                ConfigFieldType::Secret { .. } => out.push(path),
                ConfigFieldType::Nested { fields } => walk(&path, fields, out),
                _ => {}
            }
        }
    }
    let mut out = Vec::new();
    walk("", fields, &mut out);
    out
}

fn resolve_bool(
    path: &str,
    default: Option<bool>,
    override_val: Option<&toml::Value>,
    errors: &mut Vec<ValidationError>,
) -> Option<ConfigValue> {
    if let Some(v) = override_val {
        if let Some(b) = v.as_bool() {
            return Some(ConfigValue::Bool(b));
        }
        errors.push(ValidationError::ConfigTypeMismatch {
            path: path.to_owned(),
            expected: "bool",
            got: type_name(v),
        });
        return None;
    }
    if let Some(d) = default {
        return Some(ConfigValue::Bool(d));
    }
    errors.push(ValidationError::ConfigRequired {
        path: path.to_owned(),
    });
    None
}

fn resolve_int(
    path: &str,
    default: Option<i64>,
    min: Option<i64>,
    max: Option<i64>,
    override_val: Option<&toml::Value>,
    errors: &mut Vec<ValidationError>,
) -> Option<ConfigValue> {
    // Override and default are distinct error categories:
    // override-present-but-wrong-type pushes `TypeMismatch` and stops
    // (the field isn't "missing"); no-override-and-no-default pushes
    // `Required`. Without this split a single bad override produced
    // *two* errors (TypeMismatch + Required) which read as
    // contradictory.
    let (val, source) = if let Some(v) = override_val {
        let Some(n) = v.as_integer() else {
            errors.push(ValidationError::ConfigTypeMismatch {
                path: path.to_owned(),
                expected: "int",
                got: type_name(v),
            });
            return None;
        };
        (n, ValueSource::Override)
    } else {
        let Some(d) = default else {
            errors.push(ValidationError::ConfigRequired {
                path: path.to_owned(),
            });
            return None;
        };
        (d, ValueSource::Default)
    };
    check_range(path, val, min, max, source, errors);
    Some(ConfigValue::Int(val))
}

fn resolve_float(
    path: &str,
    default: Option<f64>,
    min: Option<f64>,
    max: Option<f64>,
    override_val: Option<&toml::Value>,
    errors: &mut Vec<ValidationError>,
) -> Option<ConfigValue> {
    // Same split as `resolve_int` — see the comment there for why
    // override-vs-default needs distinct error paths.
    let (val, source) = if let Some(v) = override_val {
        let parsed = match v {
            toml::Value::Float(n) => *n,
            // Accept TOML integer literals (`ratio = 1`) for float
            // fields, matching the schema parser (`take_float`).
            // Without this, `min = 1` works in the manifest but
            // `ratio = 1` in a user override fails with a confusing
            // type mismatch. Precision loss is theoretically possible
            // for `|n| > 2^53` but the values we see in practice are
            // small constants.
            #[allow(clippy::cast_precision_loss)]
            toml::Value::Integer(n) => *n as f64,
            _ => {
                errors.push(ValidationError::ConfigTypeMismatch {
                    path: path.to_owned(),
                    expected: "float",
                    got: type_name(v),
                });
                return None;
            }
        };
        (parsed, ValueSource::Override)
    } else {
        let Some(d) = default else {
            errors.push(ValidationError::ConfigRequired {
                path: path.to_owned(),
            });
            return None;
        };
        (d, ValueSource::Default)
    };
    // NaN / ±inf comparisons against the declared bounds are always
    // false, so reject non-finite values explicitly rather than
    // letting them slip into `InstanceConfig`. The `role` field
    // attributes the error to the right source — "default" when
    // `merge()` is called without a prior `validate()` against a
    // schema whose default is non-finite, "override" when a user
    // override is non-finite.
    if !val.is_finite() {
        errors.push(ValidationError::ConfigFloatNotFinite {
            path: path.to_owned(),
            role: match source {
                ValueSource::Default => "default",
                ValueSource::Override => "override",
            },
            got: val,
        });
        return None;
    }
    check_range_f(path, val, min, max, source, errors);
    Some(ConfigValue::Float(val))
}

fn resolve_string(
    path: &str,
    default: Option<&str>,
    override_val: Option<&toml::Value>,
    errors: &mut Vec<ValidationError>,
) -> Option<ConfigValue> {
    if let Some(v) = override_val {
        if let Some(s) = v.as_str() {
            return Some(ConfigValue::String(s.to_owned()));
        }
        errors.push(ValidationError::ConfigTypeMismatch {
            path: path.to_owned(),
            expected: "string",
            got: type_name(v),
        });
        return None;
    }
    if let Some(d) = default {
        return Some(ConfigValue::String(d.to_owned()));
    }
    errors.push(ValidationError::ConfigRequired {
        path: path.to_owned(),
    });
    None
}

fn resolve_enum(
    path: &str,
    values: &[String],
    default: Option<&str>,
    override_val: Option<&toml::Value>,
    errors: &mut Vec<ValidationError>,
) -> Option<ConfigValue> {
    // `validate` flags an empty-values enum schema, but `merge` may
    // be called directly without a prior `validate` (e.g. CLI test
    // harnesses), so emit the same specific error here rather than
    // falling through to a confusing `ConfigEnumOutOfRange { allowed:
    // [] }`.
    if values.is_empty() {
        errors.push(ValidationError::ConfigEnumEmpty {
            path: path.to_owned(),
        });
        return None;
    }
    // Same override-vs-default split as `resolve_int` — a wrong-type
    // override stops at `TypeMismatch` rather than also emitting
    // `Required`.
    let (val, source): (String, ValueSource) = if let Some(v) = override_val {
        let Some(s) = v.as_str() else {
            errors.push(ValidationError::ConfigTypeMismatch {
                path: path.to_owned(),
                expected: "string",
                got: type_name(v),
            });
            return None;
        };
        (s.to_owned(), ValueSource::Override)
    } else {
        let Some(d) = default else {
            errors.push(ValidationError::ConfigRequired {
                path: path.to_owned(),
            });
            return None;
        };
        (d.to_owned(), ValueSource::Default)
    };
    if !values.iter().any(|allowed| allowed == &val) {
        // Pick the variant by source: a default that's not in
        // `values` is a schema bug; an override that's not in
        // `values` is the deployment's problem. The two have the
        // same field shape but distinct messages so the operator
        // sees which side to fix.
        errors.push(match source {
            ValueSource::Default => ValidationError::ConfigEnumDefaultOutOfRange {
                path: path.to_owned(),
                got: val.clone(),
                allowed: values.to_vec(),
            },
            ValueSource::Override => ValidationError::ConfigEnumOutOfRange {
                path: path.to_owned(),
                got: val.clone(),
                allowed: values.to_vec(),
            },
        });
        return None;
    }
    Some(ConfigValue::String(val))
}

fn resolve_nested(
    path: &str,
    fields: &BTreeMap<String, ConfigField>,
    override_val: Option<&toml::Value>,
    errors: &mut Vec<ValidationError>,
) -> Option<ConfigValue> {
    let empty = toml::value::Table::new();
    let sub_table = match override_val {
        None => &empty,
        Some(toml::Value::Table(t)) => t,
        Some(v) => {
            errors.push(ValidationError::ConfigTypeMismatch {
                path: path.to_owned(),
                expected: "table",
                got: type_name(v),
            });
            return None;
        }
    };

    // Unknown sub-keys → error.
    for k in sub_table.keys() {
        if !fields.contains_key(k) {
            errors.push(ValidationError::UnknownConfigKey {
                key: format!("{path}.{k}"),
            });
        }
    }

    let mut nested = BTreeMap::new();
    for (sub_name, sub_field) in fields {
        let sub_path = format!("{path}.{sub_name}");
        if let Some(v) = resolve_field(&sub_path, sub_field, sub_table.get(sub_name), errors) {
            nested.insert(sub_name.clone(), v);
        }
    }
    Some(ConfigValue::Nested(nested))
}

fn check_range(
    path: &str,
    val: i64,
    min: Option<i64>,
    max: Option<i64>,
    source: ValueSource,
    errors: &mut Vec<ValidationError>,
) {
    // `validate` flags `min > max` schemas ahead of time, but `merge`
    // may be called without it (e.g. CLI test harnesses). Surface the
    // schema error here too rather than letting the inverted bounds
    // produce confusing `ConfigOutOfRange` pairs (`>= 100` *and*
    // `<= 10`) for any value in the world.
    if let Some(min) = min
        && let Some(max) = max
        && min > max
    {
        errors.push(ValidationError::ConfigIntRangeInvalid {
            path: path.to_owned(),
            min,
            max,
        });
        return;
    }
    if let Some(min) = min
        && val < min
    {
        errors.push(int_out_of_range(path, val, Some(min), max, source));
    }
    if let Some(max) = max
        && val > max
    {
        errors.push(int_out_of_range(path, val, min, Some(max), source));
    }
}

fn int_out_of_range(
    path: &str,
    val: i64,
    min: Option<i64>,
    max: Option<i64>,
    source: ValueSource,
) -> ValidationError {
    match source {
        // A default value that falls outside the declared bounds is
        // a schema bug — same finding the validator emits when it
        // runs the schema-side check.
        ValueSource::Default => ValidationError::ConfigIntDefaultOutOfRange {
            path: path.to_owned(),
            got: val,
            min,
            max,
        },
        // An override outside the bounds is a runtime/deployment
        // problem; the variant's message is phrased as a "config
        // override" issue.
        ValueSource::Override => {
            // Preserve the existing single-bound format so the
            // operator sees which side they tripped.
            let bound = if let Some(min) = min
                && val < min
            {
                format!(">= {min}")
            } else if let Some(max) = max {
                format!("<= {max}")
            } else {
                // Unreachable in practice — `check_range` calls this
                // only when one bound failed — but emit something
                // useful rather than panic.
                "(unspecified)".to_owned()
            };
            ValidationError::ConfigOutOfRange {
                path: path.to_owned(),
                bound,
                got: val.to_string(),
            }
        }
    }
}

fn check_range_f(
    path: &str,
    val: f64,
    min: Option<f64>,
    max: Option<f64>,
    source: ValueSource,
    errors: &mut Vec<ValidationError>,
) {
    // `validate()` already reports non-finite bounds at the schema
    // level via `check_float_finite`, but `merge()` may be called
    // standalone — without that pre-check a `min = NaN` or
    // `max = +inf` would slip past the range check (NaN comparisons
    // are always false) and let any value through. Mirror the
    // finiteness check here so a malformed schema fails merge too.
    let mut schema_broken = false;
    if let Some(m) = min
        && !m.is_finite()
    {
        errors.push(ValidationError::ConfigFloatNotFinite {
            path: path.to_owned(),
            role: "min",
            got: m,
        });
        schema_broken = true;
    }
    if let Some(m) = max
        && !m.is_finite()
    {
        errors.push(ValidationError::ConfigFloatNotFinite {
            path: path.to_owned(),
            role: "max",
            got: m,
        });
        schema_broken = true;
    }
    if schema_broken {
        // Don't run range comparisons against a non-finite bound; the
        // result would be garbage and would layer noise on top of the
        // schema error.
        return;
    }

    // See `check_range`. Float bounds add an extra wrinkle: NaN
    // comparisons are always false, so we only treat the schema as
    // invalid when both bounds are *finite*. The non-finite case is
    // already handled above.
    if let Some(min) = min
        && let Some(max) = max
        && min > max
    {
        errors.push(ValidationError::ConfigFloatRangeInvalid {
            path: path.to_owned(),
            min,
            max,
        });
        return;
    }
    if let Some(min) = min
        && val < min
    {
        errors.push(float_out_of_range(path, val, Some(min), max, source));
    }
    if let Some(max) = max
        && val > max
    {
        errors.push(float_out_of_range(path, val, min, Some(max), source));
    }
}

fn float_out_of_range(
    path: &str,
    val: f64,
    min: Option<f64>,
    max: Option<f64>,
    source: ValueSource,
) -> ValidationError {
    match source {
        ValueSource::Default => ValidationError::ConfigFloatDefaultOutOfRange {
            path: path.to_owned(),
            got: val,
            min,
            max,
        },
        ValueSource::Override => {
            let bound = if let Some(min) = min
                && val < min
            {
                format!(">= {min}")
            } else if let Some(max) = max {
                format!("<= {max}")
            } else {
                "(unspecified)".to_owned()
            };
            ValidationError::ConfigOutOfRange {
                path: path.to_owned(),
                bound,
                got: val.to_string(),
            }
        }
    }
}

fn type_name(v: &toml::Value) -> &'static str {
    match v {
        toml::Value::String(_) => "string",
        toml::Value::Integer(_) => "int",
        toml::Value::Float(_) => "float",
        toml::Value::Boolean(_) => "bool",
        toml::Value::Datetime(_) => "datetime",
        toml::Value::Array(_) => "array",
        toml::Value::Table(_) => "table",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use semver::Version;

    fn manifest_with(fields: BTreeMap<String, ConfigField>) -> PluginManifest {
        use crate::manifest::{
            CapabilitiesSection, PluginSection, RestartPolicy, RuntimeSection, World,
        };
        PluginManifest {
            manifest_version: 1,
            plugin: PluginSection {
                id: "x.y".into(),
                name: "n".into(),
                version: Version::new(0, 1, 0),
                authors: vec![],
                description: None,
                source: None,
                license: None,
                keywords: vec![],
                world: World::Plugin,
                sdk_version: Version::new(0, 1, 0),
            },
            runtime: RuntimeSection {
                wasm: "x.wasm".into(),
                singleton: false,
                tick_interval_ms: None,
                restart: RestartPolicy::default(),
            },
            capabilities: CapabilitiesSection::default(),
            config: fields,
            ui: None,
        }
    }

    fn field_bool(default: Option<bool>, desc: &str) -> ConfigField {
        ConfigField {
            ty: ConfigFieldType::Bool { default },
            description: Some(desc.into()),
        }
    }

    /// Typo'd key inside `[config.<name>]` must be caught at parse
    /// time. Previously the inner enum had no `deny_unknown_fields`
    /// (and serde's behavior with internally-tagged + flatten doesn't
    /// reliably refuse extra keys), so `defualt = true` would land
    /// silently as a bool field with no default.
    #[test]
    fn typo_in_default_key_rejected() {
        let err = toml::from_str::<ConfigField>(
            r#"
type = "bool"
defualt = true
description = "x"
"#,
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("unknown field") || msg.contains("defualt"),
            "expected unknown-field error, got: {msg}",
        );
    }

    #[test]
    fn bool_rejects_int_keys() {
        for bad in [
            "type = \"bool\"\nmin = 1\n",
            "type = \"bool\"\nmax = 10\n",
            "type = \"bool\"\nvalues = [\"a\"]\n",
            "type = \"bool\"\nfields = {}\n",
        ] {
            let err = toml::from_str::<ConfigField>(bad).unwrap_err();
            assert!(
                err.to_string().contains("not valid for this type"),
                "expected category-mismatch for `{bad}`, got {err}",
            );
        }
    }

    #[test]
    fn int_rejects_enum_or_nested_keys() {
        let err =
            toml::from_str::<ConfigField>("type = \"int\"\nvalues = [\"a\", \"b\"]\n").unwrap_err();
        assert!(err.to_string().contains("not valid for this type"));

        let err = toml::from_str::<ConfigField>("type = \"int\"\nfields = {}\n").unwrap_err();
        assert!(err.to_string().contains("not valid for this type"));
    }

    #[test]
    fn float_min_max_accept_integer_literal() {
        // TOML distinguishes `0` and `0.0`; the manifest UX shouldn't.
        let f: ConfigField = toml::from_str(
            r#"
type = "float"
default = 0.5
min = 0
max = 1
"#,
        )
        .unwrap();
        let ConfigFieldType::Float { default, min, max } = f.ty else {
            panic!("expected Float, got {:?}", f.ty)
        };
        assert_eq!(default, Some(0.5));
        assert_eq!(min, Some(0.0));
        assert_eq!(max, Some(1.0));
    }

    #[test]
    fn int_default_must_be_integer() {
        let err = toml::from_str::<ConfigField>("type = \"int\"\ndefault = 1.5\n").unwrap_err();
        assert!(err.to_string().contains("must be an integer"));
    }

    #[test]
    fn bool_default_must_be_bool() {
        let err =
            toml::from_str::<ConfigField>("type = \"bool\"\ndefault = \"yes\"\n").unwrap_err();
        assert!(err.to_string().contains("must be a boolean"));
    }

    #[test]
    fn enum_requires_values() {
        let err = toml::from_str::<ConfigField>("type = \"enum\"\ndefault = \"a\"\n").unwrap_err();
        assert!(err.to_string().contains("requires `values`"));
    }

    #[test]
    fn nested_requires_fields() {
        let err = toml::from_str::<ConfigField>("type = \"nested\"\n").unwrap_err();
        assert!(err.to_string().contains("requires `fields`"));
    }

    #[test]
    fn unknown_type_rejected() {
        let err = toml::from_str::<ConfigField>("type = \"datetime\"\n").unwrap_err();
        assert!(err.to_string().contains("unknown config field `type`"));
    }

    #[test]
    fn merge_uses_defaults_when_no_override() {
        let mut fields = BTreeMap::new();
        fields.insert("default_state".into(), field_bool(Some(false), "d"));
        let m = manifest_with(fields);
        let cfg = merge(&m, &toml::Value::Table(toml::value::Table::new())).unwrap();
        assert_eq!(cfg.get("default_state"), Some(&ConfigValue::Bool(false)));
    }

    #[test]
    fn merge_applies_override() {
        let mut fields = BTreeMap::new();
        fields.insert("default_state".into(), field_bool(Some(false), "d"));
        let m = manifest_with(fields);
        let overrides: toml::Value = toml::from_str("default_state = true").unwrap();
        let cfg = merge(&m, &overrides).unwrap();
        assert_eq!(cfg.get("default_state"), Some(&ConfigValue::Bool(true)));
    }

    #[test]
    fn merge_rejects_unknown_key() {
        let m = manifest_with(BTreeMap::new());
        let overrides: toml::Value = toml::from_str("unexpected = 42").unwrap();
        let errors = merge(&m, &overrides).unwrap_err();
        assert!(errors.iter().any(
            |e| matches!(e, ValidationError::UnknownConfigKey { key } if key == "unexpected")
        ));
    }

    #[test]
    fn merge_rejects_type_mismatch() {
        let mut fields = BTreeMap::new();
        fields.insert("flag".into(), field_bool(Some(false), "d"));
        let m = manifest_with(fields);
        let overrides: toml::Value = toml::from_str("flag = \"oops\"").unwrap();
        let errors = merge(&m, &overrides).unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ValidationError::ConfigTypeMismatch { .. }))
        );
    }

    #[test]
    fn merge_reports_missing_required() {
        let mut fields = BTreeMap::new();
        fields.insert(
            "required".into(),
            ConfigField {
                ty: ConfigFieldType::String { default: None },
                description: None,
            },
        );
        let m = manifest_with(fields);
        let errors = merge(&m, &toml::Value::Table(toml::value::Table::new())).unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ValidationError::ConfigRequired { .. }))
        );
    }

    #[test]
    fn merge_int_with_range() {
        let mut fields = BTreeMap::new();
        fields.insert(
            "port".into(),
            ConfigField {
                ty: ConfigFieldType::Int {
                    default: None,
                    min: Some(1),
                    max: Some(65535),
                },
                description: None,
            },
        );
        let m = manifest_with(fields);
        // out of range
        let overrides: toml::Value = toml::from_str("port = 99999").unwrap();
        let errors = merge(&m, &overrides).unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ValidationError::ConfigOutOfRange { .. }))
        );
        // in range
        let overrides: toml::Value = toml::from_str("port = 8080").unwrap();
        let cfg = merge(&m, &overrides).unwrap();
        assert_eq!(cfg.get("port"), Some(&ConfigValue::Int(8080)));
    }

    #[test]
    fn merge_enum_constrains_values() {
        let mut fields = BTreeMap::new();
        fields.insert(
            "mode".into(),
            ConfigField {
                ty: ConfigFieldType::Enum {
                    values: vec!["off".into(), "on".into(), "auto".into()],
                    default: Some("off".into()),
                },
                description: None,
            },
        );
        let m = manifest_with(fields);

        let cfg = merge(&m, &toml::Value::Table(toml::value::Table::new())).unwrap();
        assert_eq!(cfg.get("mode"), Some(&ConfigValue::String("off".into())));

        let overrides: toml::Value = toml::from_str("mode = \"auto\"").unwrap();
        let cfg = merge(&m, &overrides).unwrap();
        assert_eq!(cfg.get("mode"), Some(&ConfigValue::String("auto".into())));

        let overrides: toml::Value = toml::from_str("mode = \"weird\"").unwrap();
        let errors = merge(&m, &overrides).unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ValidationError::ConfigEnumOutOfRange { .. }))
        );
    }

    #[test]
    fn merge_rejects_non_table_root() {
        let m = manifest_with(BTreeMap::new());
        let errors = merge(&m, &toml::Value::String("not a table".into())).unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ValidationError::ConfigOverrideShape { .. }))
        );
    }

    #[test]
    fn merge_int_type_mismatch_in_override() {
        let mut fields = BTreeMap::new();
        fields.insert(
            "port".into(),
            ConfigField {
                ty: ConfigFieldType::Int {
                    default: None,
                    min: None,
                    max: None,
                },
                description: None,
            },
        );
        let m = manifest_with(fields);
        let overrides: toml::Value = toml::from_str("port = \"oops\"").unwrap();
        let errors = merge(&m, &overrides).unwrap_err();
        assert!(errors.iter().any(|e| matches!(
            e,
            ValidationError::ConfigTypeMismatch {
                expected: "int",
                ..
            }
        )));
    }

    #[test]
    fn merge_float_with_default_and_range() {
        let mut fields = BTreeMap::new();
        fields.insert(
            "ratio".into(),
            ConfigField {
                ty: ConfigFieldType::Float {
                    default: Some(0.5),
                    min: Some(0.0),
                    max: Some(1.0),
                },
                description: None,
            },
        );
        let m = manifest_with(fields);
        // default used
        let cfg = merge(&m, &toml::Value::Table(toml::value::Table::new())).unwrap();
        assert_eq!(cfg.get("ratio"), Some(&ConfigValue::Float(0.5)));
        // override under min
        let overrides: toml::Value = toml::from_str("ratio = -0.1").unwrap();
        let errs = merge(&m, &overrides).unwrap_err();
        assert!(
            errs.iter()
                .any(|e| matches!(e, ValidationError::ConfigOutOfRange { .. }))
        );
        // override over max
        let overrides: toml::Value = toml::from_str("ratio = 2.0").unwrap();
        let errs = merge(&m, &overrides).unwrap_err();
        assert!(
            errs.iter()
                .any(|e| matches!(e, ValidationError::ConfigOutOfRange { .. }))
        );
        // override with wrong type
        let overrides: toml::Value = toml::from_str("ratio = \"oops\"").unwrap();
        let errs = merge(&m, &overrides).unwrap_err();
        assert!(errs.iter().any(|e| matches!(
            e,
            ValidationError::ConfigTypeMismatch {
                expected: "float",
                ..
            }
        )));
    }

    #[test]
    fn merge_float_override_accepts_integer_literal() {
        // TOML distinguishes `0` and `0.0`; the manifest UX shouldn't —
        // and `take_float` already accepts `min = 1` in the schema, so
        // `ratio = 1` in an override must work too.
        let mut fields = BTreeMap::new();
        fields.insert(
            "ratio".into(),
            ConfigField {
                ty: ConfigFieldType::Float {
                    default: Some(0.5),
                    min: Some(0.0),
                    max: Some(2.0),
                },
                description: None,
            },
        );
        let m = manifest_with(fields);

        let overrides: toml::Value = toml::from_str("ratio = 1").unwrap();
        let cfg = merge(&m, &overrides).unwrap();
        assert_eq!(cfg.get("ratio"), Some(&ConfigValue::Float(1.0)));

        // Out-of-range integer literal still trips the range check.
        let overrides: toml::Value = toml::from_str("ratio = 3").unwrap();
        let errs = merge(&m, &overrides).unwrap_err();
        assert!(
            errs.iter()
                .any(|e| matches!(e, ValidationError::ConfigOutOfRange { .. }))
        );
    }

    #[test]
    fn merge_float_override_still_rejects_non_numeric() {
        // The integer-literal carve-out shouldn't accidentally let
        // strings or bools through.
        let mut fields = BTreeMap::new();
        fields.insert(
            "ratio".into(),
            ConfigField {
                ty: ConfigFieldType::Float {
                    default: None,
                    min: None,
                    max: None,
                },
                description: None,
            },
        );
        let m = manifest_with(fields);
        let overrides: toml::Value = toml::from_str("ratio = \"oops\"").unwrap();
        let errs = merge(&m, &overrides).unwrap_err();
        assert!(errs.iter().any(|e| matches!(
            e,
            ValidationError::ConfigTypeMismatch {
                expected: "float",
                ..
            }
        )));
    }

    /// A wrong-type override should emit `TypeMismatch` *only* — never
    /// also `Required`. Previously the `val.or_else(push)?` shape
    /// couldn't tell "no value" from "already-errored" and pushed both,
    /// which reads as contradictory ("expected float, got string" +
    /// "required field has no value").
    #[test]
    fn type_mismatch_does_not_also_emit_required() {
        let mut fields = BTreeMap::new();
        fields.insert(
            "i".into(),
            ConfigField {
                ty: ConfigFieldType::Int {
                    default: None,
                    min: None,
                    max: None,
                },
                description: None,
            },
        );
        fields.insert(
            "f".into(),
            ConfigField {
                ty: ConfigFieldType::Float {
                    default: None,
                    min: None,
                    max: None,
                },
                description: None,
            },
        );
        fields.insert(
            "e".into(),
            ConfigField {
                ty: ConfigFieldType::Enum {
                    values: vec!["a".into(), "b".into()],
                    default: None,
                },
                description: None,
            },
        );
        let m = manifest_with(fields);
        let overrides: toml::Value = toml::from_str(
            r#"
i = "oops"
f = "oops"
e = 42
"#,
        )
        .unwrap();
        let errs = merge(&m, &overrides).unwrap_err();
        // Exactly one TypeMismatch per field, no spurious Required.
        let mismatches = errs
            .iter()
            .filter(|e| matches!(e, ValidationError::ConfigTypeMismatch { .. }))
            .count();
        let requires = errs
            .iter()
            .filter(|e| matches!(e, ValidationError::ConfigRequired { .. }))
            .count();
        assert_eq!(mismatches, 3, "one TypeMismatch per field: got {errs:?}");
        assert_eq!(
            requires, 0,
            "no Required on type-mismatch path: got {errs:?}"
        );
    }

    #[test]
    fn merge_float_no_default_is_required() {
        let mut fields = BTreeMap::new();
        fields.insert(
            "f".into(),
            ConfigField {
                ty: ConfigFieldType::Float {
                    default: None,
                    min: None,
                    max: None,
                },
                description: None,
            },
        );
        let m = manifest_with(fields);
        let errs = merge(&m, &toml::Value::Table(toml::value::Table::new())).unwrap_err();
        assert!(
            errs.iter()
                .any(|e| matches!(e, ValidationError::ConfigRequired { .. }))
        );
    }

    #[test]
    fn merge_string_type_mismatch() {
        let mut fields = BTreeMap::new();
        fields.insert(
            "name".into(),
            ConfigField {
                ty: ConfigFieldType::String { default: None },
                description: None,
            },
        );
        let m = manifest_with(fields);
        let overrides: toml::Value = toml::from_str("name = 42").unwrap();
        let errs = merge(&m, &overrides).unwrap_err();
        assert!(errs.iter().any(|e| matches!(
            e,
            ValidationError::ConfigTypeMismatch {
                expected: "string",
                ..
            }
        )));
    }

    #[test]
    fn merge_string_default_used() {
        let mut fields = BTreeMap::new();
        fields.insert(
            "name".into(),
            ConfigField {
                ty: ConfigFieldType::String {
                    default: Some("anon".into()),
                },
                description: None,
            },
        );
        let m = manifest_with(fields);
        let cfg = merge(&m, &toml::Value::Table(toml::value::Table::new())).unwrap();
        assert_eq!(cfg.get("name"), Some(&ConfigValue::String("anon".into())));
    }

    #[test]
    fn merge_enum_type_mismatch_in_override() {
        let mut fields = BTreeMap::new();
        fields.insert(
            "mode".into(),
            ConfigField {
                ty: ConfigFieldType::Enum {
                    values: vec!["off".into(), "on".into()],
                    default: Some("off".into()),
                },
                description: None,
            },
        );
        let m = manifest_with(fields);
        let overrides: toml::Value = toml::from_str("mode = 42").unwrap();
        let errs = merge(&m, &overrides).unwrap_err();
        assert!(errs.iter().any(|e| matches!(
            e,
            ValidationError::ConfigTypeMismatch {
                expected: "string",
                ..
            }
        )));
    }

    #[test]
    fn merge_int_invalid_range_emits_schema_error() {
        // `merge` may be invoked without a prior `validate`; in that
        // case an inverted bound (`min > max`) shouldn't manifest as
        // a pair of confusing `ConfigOutOfRange` findings ("got X, must
        // be >= 100 *and* <= 10") — it's a schema bug, surfaced via
        // `ConfigIntRangeInvalid`.
        let mut fields = BTreeMap::new();
        fields.insert(
            "n".into(),
            ConfigField {
                ty: ConfigFieldType::Int {
                    default: None,
                    min: Some(100),
                    max: Some(10),
                },
                description: None,
            },
        );
        let m = manifest_with(fields);
        let overrides: toml::Value = toml::from_str("n = 50").unwrap();
        let errs = merge(&m, &overrides).unwrap_err();
        assert!(
            errs.iter().any(|e| matches!(
                e,
                ValidationError::ConfigIntRangeInvalid {
                    min: 100,
                    max: 10,
                    ..
                }
            )),
            "expected ConfigIntRangeInvalid, got {errs:?}",
        );
        assert!(
            !errs
                .iter()
                .any(|e| matches!(e, ValidationError::ConfigOutOfRange { .. })),
            "should not fall through to ConfigOutOfRange: {errs:?}",
        );
    }

    #[test]
    fn merge_float_invalid_range_emits_schema_error() {
        let mut fields = BTreeMap::new();
        fields.insert(
            "f".into(),
            ConfigField {
                ty: ConfigFieldType::Float {
                    default: None,
                    min: Some(1.0),
                    max: Some(0.5),
                },
                description: None,
            },
        );
        let m = manifest_with(fields);
        let overrides: toml::Value = toml::from_str("f = 0.7").unwrap();
        let errs = merge(&m, &overrides).unwrap_err();
        assert!(
            errs.iter()
                .any(|e| matches!(e, ValidationError::ConfigFloatRangeInvalid { .. })),
            "expected ConfigFloatRangeInvalid, got {errs:?}",
        );
        assert!(
            !errs
                .iter()
                .any(|e| matches!(e, ValidationError::ConfigOutOfRange { .. })),
            "should not fall through to ConfigOutOfRange: {errs:?}",
        );
    }

    /// When `merge()` is called without a prior `validate()`, an
    /// out-of-bounds *default* should be attributed to the schema
    /// (`ConfigIntDefaultOutOfRange`), not to a missing override
    /// (`ConfigOutOfRange`, which reads as a runtime issue). This
    /// pins the `ValueSource::Default` path through `check_range`.
    #[test]
    fn merge_int_default_out_of_range_uses_default_variant() {
        let mut fields = BTreeMap::new();
        fields.insert(
            "n".into(),
            ConfigField {
                ty: ConfigFieldType::Int {
                    default: Some(5),
                    min: Some(10),
                    max: Some(20),
                },
                description: None,
            },
        );
        let m = manifest_with(fields);
        // No override → resolved value is the default 5, which is
        // below min 10.
        let errs = merge(&m, &toml::Value::Table(toml::value::Table::new())).unwrap_err();
        assert!(
            errs.iter().any(|e| matches!(
                e,
                ValidationError::ConfigIntDefaultOutOfRange {
                    got: 5,
                    min: Some(10),
                    ..
                }
            )),
            "expected ConfigIntDefaultOutOfRange, got {errs:?}",
        );
        assert!(
            !errs
                .iter()
                .any(|e| matches!(e, ValidationError::ConfigOutOfRange { .. })),
            "should not use the override-flavored ConfigOutOfRange for a default: {errs:?}",
        );
    }

    #[test]
    fn merge_float_default_out_of_range_uses_default_variant() {
        let mut fields = BTreeMap::new();
        fields.insert(
            "f".into(),
            ConfigField {
                ty: ConfigFieldType::Float {
                    default: Some(0.1),
                    min: Some(1.0),
                    max: Some(2.0),
                },
                description: None,
            },
        );
        let m = manifest_with(fields);
        let errs = merge(&m, &toml::Value::Table(toml::value::Table::new())).unwrap_err();
        assert!(
            errs.iter()
                .any(|e| matches!(e, ValidationError::ConfigFloatDefaultOutOfRange { .. })),
            "expected ConfigFloatDefaultOutOfRange, got {errs:?}",
        );
        assert!(
            !errs
                .iter()
                .any(|e| matches!(e, ValidationError::ConfigOutOfRange { .. })),
            "should not use ConfigOutOfRange for a default: {errs:?}",
        );
    }

    #[test]
    fn merge_enum_default_not_in_values_uses_default_variant() {
        let mut fields = BTreeMap::new();
        fields.insert(
            "mode".into(),
            ConfigField {
                ty: ConfigFieldType::Enum {
                    values: vec!["off".into(), "on".into()],
                    default: Some("oops".into()),
                },
                description: None,
            },
        );
        let m = manifest_with(fields);
        // No override → resolved value is the default "oops", which
        // isn't in `values`. The default-specific variant should
        // fire, not the runtime/override one.
        let errs = merge(&m, &toml::Value::Table(toml::value::Table::new())).unwrap_err();
        assert!(
            errs.iter().any(|e| matches!(
                e,
                ValidationError::ConfigEnumDefaultOutOfRange { got, .. } if got == "oops"
            )),
            "expected ConfigEnumDefaultOutOfRange, got {errs:?}",
        );
        assert!(
            !errs
                .iter()
                .any(|e| matches!(e, ValidationError::ConfigEnumOutOfRange { .. })),
            "should not use ConfigEnumOutOfRange for a default: {errs:?}",
        );
    }

    /// `validate()` reports non-finite `min`/`max` bounds at the
    /// schema level, but `merge()` may be called standalone — and a
    /// `NaN` bound silently disables the range check (NaN
    /// comparisons are always false). Mirror the finiteness check
    /// in `check_range_f` so a malformed schema can't slip past
    /// merge without an error.
    #[test]
    fn merge_float_non_finite_bound_reported() {
        for (min, max, role) in [
            (Some(f64::NAN), None, "min"),
            (Some(f64::INFINITY), None, "min"),
            (None, Some(f64::NAN), "max"),
            (None, Some(f64::NEG_INFINITY), "max"),
        ] {
            let mut fields = BTreeMap::new();
            fields.insert(
                "f".into(),
                ConfigField {
                    ty: ConfigFieldType::Float {
                        default: Some(0.5),
                        min,
                        max,
                    },
                    description: None,
                },
            );
            let m = manifest_with(fields);
            let errs = merge(&m, &toml::Value::Table(toml::value::Table::new())).unwrap_err();
            assert!(
                errs.iter().any(|e| matches!(
                    e,
                    ValidationError::ConfigFloatNotFinite { role: r, .. } if *r == role
                )),
                "expected ConfigFloatNotFinite with role={role}, got {errs:?}",
            );
        }
    }

    #[test]
    fn merge_float_non_finite_default_role_is_default() {
        let mut fields = BTreeMap::new();
        fields.insert(
            "f".into(),
            ConfigField {
                ty: ConfigFieldType::Float {
                    default: Some(f64::NAN),
                    min: None,
                    max: None,
                },
                description: None,
            },
        );
        let m = manifest_with(fields);
        let errs = merge(&m, &toml::Value::Table(toml::value::Table::new())).unwrap_err();
        assert!(
            errs.iter().any(|e| matches!(
                e,
                ValidationError::ConfigFloatNotFinite {
                    role: "default",
                    ..
                }
            )),
            "expected role=\"default\" for non-finite default, got {errs:?}",
        );
    }

    #[test]
    fn merge_enum_empty_values_emits_specific_error() {
        // `merge` may be called without `validate` (e.g. test harnesses);
        // it must emit `ConfigEnumEmpty` rather than the confusing
        // `ConfigEnumOutOfRange { allowed: [] }` that would otherwise
        // fall through.
        let mut fields = BTreeMap::new();
        fields.insert(
            "mode".into(),
            ConfigField {
                ty: ConfigFieldType::Enum {
                    values: vec![],
                    default: Some("anything".into()),
                },
                description: None,
            },
        );
        let m = manifest_with(fields);
        let errs = merge(&m, &toml::Value::Table(toml::value::Table::new())).unwrap_err();
        assert!(
            errs.iter()
                .any(|e| matches!(e, ValidationError::ConfigEnumEmpty { .. })),
            "expected ConfigEnumEmpty, got {errs:?}",
        );
        // And specifically not the wrong variant.
        assert!(
            !errs.iter().any(
                |e| matches!(e, ValidationError::ConfigEnumOutOfRange { allowed, .. } if allowed.is_empty())
            ),
            "should not fall through to ConfigEnumOutOfRange",
        );
    }

    #[test]
    fn merge_enum_required_without_default() {
        let mut fields = BTreeMap::new();
        fields.insert(
            "mode".into(),
            ConfigField {
                ty: ConfigFieldType::Enum {
                    values: vec!["off".into(), "on".into()],
                    default: None,
                },
                description: None,
            },
        );
        let m = manifest_with(fields);
        let errs = merge(&m, &toml::Value::Table(toml::value::Table::new())).unwrap_err();
        assert!(
            errs.iter()
                .any(|e| matches!(e, ValidationError::ConfigRequired { .. }))
        );
    }

    #[test]
    fn merge_nested_type_mismatch_at_block() {
        let mut inner = BTreeMap::new();
        inner.insert(
            "host".into(),
            ConfigField {
                ty: ConfigFieldType::String {
                    default: Some("localhost".into()),
                },
                description: None,
            },
        );
        let mut fields = BTreeMap::new();
        fields.insert(
            "broker".into(),
            ConfigField {
                ty: ConfigFieldType::Nested { fields: inner },
                description: None,
            },
        );
        let m = manifest_with(fields);
        let overrides: toml::Value = toml::from_str("broker = \"oops\"").unwrap();
        let errs = merge(&m, &overrides).unwrap_err();
        assert!(errs.iter().any(|e| matches!(
            e,
            ValidationError::ConfigTypeMismatch {
                expected: "table",
                ..
            }
        )));
    }

    #[test]
    fn merge_nested_unknown_sub_key() {
        let mut inner = BTreeMap::new();
        inner.insert(
            "host".into(),
            ConfigField {
                ty: ConfigFieldType::String {
                    default: Some("localhost".into()),
                },
                description: None,
            },
        );
        let mut fields = BTreeMap::new();
        fields.insert(
            "broker".into(),
            ConfigField {
                ty: ConfigFieldType::Nested { fields: inner },
                description: None,
            },
        );
        let m = manifest_with(fields);
        let overrides: toml::Value = toml::from_str("[broker]\nstray = \"x\"\n").unwrap();
        let errs = merge(&m, &overrides).unwrap_err();
        assert!(errs.iter().any(
            |e| matches!(e, ValidationError::UnknownConfigKey { key } if key == "broker.stray")
        ));
    }

    #[test]
    fn type_name_covers_every_toml_variant() {
        use toml::Value;
        assert_eq!(type_name(&Value::String("x".into())), "string");
        assert_eq!(type_name(&Value::Integer(1)), "int");
        assert_eq!(type_name(&Value::Float(1.0)), "float");
        assert_eq!(type_name(&Value::Boolean(true)), "bool");
        assert_eq!(type_name(&Value::Array(vec![])), "array");
        assert_eq!(type_name(&Value::Table(toml::value::Table::new())), "table");
        let dt: toml::value::Datetime = "1979-05-27T07:32:00Z".parse().unwrap();
        assert_eq!(type_name(&Value::Datetime(dt)), "datetime");
    }

    #[test]
    fn merge_rejects_non_finite_float_override() {
        let mut fields = BTreeMap::new();
        fields.insert(
            "r".into(),
            ConfigField {
                ty: ConfigFieldType::Float {
                    default: Some(0.5),
                    min: Some(0.0),
                    max: Some(1.0),
                },
                description: None,
            },
        );
        let m = manifest_with(fields);
        // TOML can't directly express NaN/inf in its literal grammar,
        // so we hand-build a `toml::Value`.
        let mut t = toml::value::Table::new();
        t.insert("r".into(), toml::Value::Float(f64::NAN));
        let errs = merge(&m, &toml::Value::Table(t)).unwrap_err();
        assert!(errs.iter().any(|e| matches!(
            e,
            ValidationError::ConfigFloatNotFinite {
                role: "override",
                ..
            }
        )));

        let mut t = toml::value::Table::new();
        t.insert("r".into(), toml::Value::Float(f64::INFINITY));
        let errs = merge(&m, &toml::Value::Table(t)).unwrap_err();
        assert!(errs.iter().any(|e| matches!(
            e,
            ValidationError::ConfigFloatNotFinite {
                role: "override",
                ..
            }
        )));
    }

    /// End-to-end TOML round-trip for a nested config schema. The
    /// previous tests only exercised programmatically-constructed
    /// `ConfigFieldType::Nested`; this one pins the on-disk shape
    /// (`[config.<key>] type = "nested" [config.<key>.fields.<subkey>]`)
    /// against the deserializer + the `merge()` consumer.
    #[test]
    fn nested_config_parses_from_toml_and_merges() {
        // Nested schema on disk: `type = "nested"` on the outer
        // table, with each sub-field declared as a `[fields.<name>]`
        // sub-table.
        let raw = r#"
type = "nested"
description = "MQTT broker settings"

[fields.host]
type = "string"
default = "localhost"
description = "Hostname"

[fields.port]
type = "int"
default = 1883
min = 1
max = 65535
"#;
        let field: ConfigField = toml::from_str(raw).expect("nested field must parse");
        let ConfigFieldType::Nested { fields } = &field.ty else {
            panic!("expected Nested, got {:?}", field.ty);
        };
        assert!(fields.contains_key("host"));
        assert!(fields.contains_key("port"));

        // Plug it into a manifest and merge with an override that
        // touches only one sub-field; the other resolves from default.
        let mut top_fields = BTreeMap::new();
        top_fields.insert("broker".into(), field);
        let m = manifest_with(top_fields);

        let overrides: toml::Value = toml::from_str("[broker]\nhost = \"mqtt.local\"\n").unwrap();
        let cfg = merge(&m, &overrides).unwrap();
        let ConfigValue::Nested(inner) = cfg.get("broker").unwrap() else {
            panic!("expected Nested at broker");
        };
        assert_eq!(
            inner.get("host"),
            Some(&ConfigValue::String("mqtt.local".into())),
        );
        assert_eq!(inner.get("port"), Some(&ConfigValue::Int(1883)));
    }

    #[test]
    fn merge_nested() {
        let mut inner = BTreeMap::new();
        inner.insert(
            "host".into(),
            ConfigField {
                ty: ConfigFieldType::String {
                    default: Some("localhost".into()),
                },
                description: None,
            },
        );
        inner.insert(
            "port".into(),
            ConfigField {
                ty: ConfigFieldType::Int {
                    default: Some(1883),
                    min: None,
                    max: None,
                },
                description: None,
            },
        );
        let mut fields = BTreeMap::new();
        fields.insert(
            "broker".into(),
            ConfigField {
                ty: ConfigFieldType::Nested { fields: inner },
                description: None,
            },
        );
        let m = manifest_with(fields);

        let overrides: toml::Value = toml::from_str("[broker]\nhost = \"mqtt.local\"\n").unwrap();
        let cfg = merge(&m, &overrides).unwrap();
        let ConfigValue::Nested(inner) = cfg.get("broker").unwrap() else {
            panic!("expected nested");
        };
        assert_eq!(
            inner.get("host"),
            Some(&ConfigValue::String("mqtt.local".into())),
        );
        assert_eq!(inner.get("port"), Some(&ConfigValue::Int(1883)));
    }

    fn secret_field(required: bool) -> ConfigField {
        ConfigField {
            ty: ConfigFieldType::Secret { required },
            description: None,
        }
    }

    #[test]
    fn secret_parses_with_required_defaulting_to_true() {
        let f: ConfigField = toml::from_str("type = \"secret\"\ndescription = \"k\"\n").unwrap();
        assert_eq!(f.ty, ConfigFieldType::Secret { required: true });
        let f: ConfigField = toml::from_str("type = \"secret\"\nrequired = false\n").unwrap();
        assert_eq!(f.ty, ConfigFieldType::Secret { required: false });
    }

    #[test]
    fn secret_rejects_default_and_foreign_keys() {
        let err = toml::from_str::<ConfigField>("type = \"secret\"\ndefault = \"hunter2\"\n")
            .unwrap_err()
            .to_string();
        assert!(err.contains("`default` is not allowed"), "{err}");
        assert!(
            !err.contains("hunter2"),
            "error must not echo the value: {err}"
        );
        for bad in [
            "type = \"secret\"\nmin = 1\n",
            "type = \"secret\"\nvalues = [\"a\"]\n",
            "type = \"secret\"\nfields = {}\n",
        ] {
            let err = toml::from_str::<ConfigField>(bad).unwrap_err();
            assert!(err.to_string().contains("not valid for this type"), "{err}");
        }
        let err =
            toml::from_str::<ConfigField>("type = \"secret\"\nrequired = \"yes\"\n").unwrap_err();
        assert!(err.to_string().contains("must be a boolean"), "{err}");
    }

    #[test]
    fn required_key_is_secret_only() {
        let err =
            toml::from_str::<ConfigField>("type = \"string\"\nrequired = true\n").unwrap_err();
        assert!(err.to_string().contains("not valid for this type"), "{err}");
    }

    #[test]
    fn secret_round_trips_schema_serialization() {
        let f = secret_field(false);
        let toml_text = toml::to_string(&f).unwrap();
        let back: ConfigField = toml::from_str(&toml_text).unwrap();
        assert_eq!(back, f);
    }

    #[test]
    fn secret_merge_wraps_value_and_masks_debug_and_serialize() {
        let mut fields = BTreeMap::new();
        fields.insert("api_key".to_owned(), secret_field(true));
        let m = manifest_with(fields);
        let overrides: toml::Value = toml::from_str("api_key = \"hunter2\"\n").unwrap();
        let cfg = merge(&m, &overrides).unwrap();
        let Some(ConfigValue::Secret(secret)) = cfg.get("api_key") else {
            panic!("expected a secret, got {cfg:?}");
        };
        assert_eq!(secret.expose(), "hunter2");
        let debug = format!("{cfg:?}");
        assert!(!debug.contains("hunter2"), "{debug}");
        let json = toml::to_string(&cfg).unwrap();
        assert!(!json.contains("hunter2"), "{json}");
        assert!(json.contains(MASKED), "{json}");
    }

    #[test]
    fn secret_merge_required_and_optional() {
        let mut fields = BTreeMap::new();
        fields.insert("needed".to_owned(), secret_field(true));
        fields.insert("maybe".to_owned(), secret_field(false));
        let m = manifest_with(fields);
        let empty = toml::Value::Table(toml::value::Table::new());
        let errors = merge(&m, &empty).unwrap_err();
        assert_eq!(
            errors,
            vec![ValidationError::ConfigRequired {
                path: "needed".into()
            }]
        );
        let overrides: toml::Value = toml::from_str("needed = \"x\"\n").unwrap();
        let cfg = merge(&m, &overrides).unwrap();
        assert!(cfg.contains_key("needed"));
        assert!(
            !cfg.contains_key("maybe"),
            "unset optional secret is absent"
        );
    }

    #[test]
    fn secret_type_mismatch_does_not_echo_value() {
        let mut fields = BTreeMap::new();
        fields.insert("pin".to_owned(), secret_field(true));
        let m = manifest_with(fields);
        let overrides: toml::Value = toml::from_str("pin = 987654\n").unwrap();
        let errors = merge(&m, &overrides).unwrap_err();
        let text = errors.iter().map(ToString::to_string).collect::<String>();
        assert!(text.contains("expected string, got int"), "{text}");
        assert!(!text.contains("987654"), "{text}");
    }

    #[test]
    fn secret_paths_walks_nested_tables() {
        let mut inner = BTreeMap::new();
        inner.insert("password".to_owned(), secret_field(true));
        inner.insert(
            "host".to_owned(),
            ConfigField {
                ty: ConfigFieldType::String { default: None },
                description: None,
            },
        );
        let mut fields = BTreeMap::new();
        fields.insert(
            "broker".to_owned(),
            ConfigField {
                ty: ConfigFieldType::Nested { fields: inner },
                description: None,
            },
        );
        fields.insert("token".to_owned(), secret_field(false));
        assert_eq!(
            secret_paths(&fields),
            vec!["broker.password".to_owned(), "token".to_owned()]
        );
    }
}
