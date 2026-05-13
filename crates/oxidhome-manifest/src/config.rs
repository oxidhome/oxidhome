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
}

impl<'de> Deserialize<'de> for ConfigField {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let h = ConfigFieldHelper::deserialize(d)?;
        let ty = match h.kind.as_str() {
            "bool" => {
                ensure_unset::<D>(&h, &["values", "fields", "min", "max"], "bool")?;
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
                ensure_unset::<D>(&h, &["values", "fields"], "int")?;
                let default = take_int::<D>(h.default, "default")?;
                let min = take_int::<D>(h.min, "min")?;
                let max = take_int::<D>(h.max, "max")?;
                ConfigFieldType::Int { default, min, max }
            }
            "float" => {
                ensure_unset::<D>(&h, &["values", "fields"], "float")?;
                let default = take_float::<D>(h.default, "default")?;
                let min = take_float::<D>(h.min, "min")?;
                let max = take_float::<D>(h.max, "max")?;
                ConfigFieldType::Float { default, min, max }
            }
            "string" => {
                ensure_unset::<D>(&h, &["values", "fields", "min", "max"], "string")?;
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
                ensure_unset::<D>(&h, &["fields", "min", "max"], "enum")?;
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
                ensure_unset::<D>(&h, &["default", "values", "min", "max"], "nested")?;
                let fields = h.fields.ok_or_else(|| {
                    D::Error::custom("config field `type = \"nested\"` requires `fields`")
                })?;
                ConfigFieldType::Nested { fields }
            }
            other => {
                return Err(D::Error::custom(format!(
                    "unknown config field `type` `{other}` \
                     (expected bool/int/float/string/enum/nested)"
                )));
            }
        };
        Ok(ConfigField {
            ty,
            description: h.description,
        })
    }
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

/// Resolved value for a single config field after defaults are
/// applied and user overrides are merged in.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ConfigValue {
    Bool(bool),
    Int(i64),
    Float(f64),
    String(String),
    Nested(BTreeMap<String, ConfigValue>),
}

/// The whole resolved config for one plugin instance — what the host
/// hands to `host-config::*` after manifest defaults are merged with
/// user overrides.
pub type InstanceConfig = BTreeMap<String, ConfigValue>;

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
    }
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
    let val = if let Some(v) = override_val {
        if let Some(n) = v.as_integer() {
            Some(n)
        } else {
            errors.push(ValidationError::ConfigTypeMismatch {
                path: path.to_owned(),
                expected: "int",
                got: type_name(v),
            });
            None
        }
    } else {
        default
    };
    let val = val.or_else(|| {
        errors.push(ValidationError::ConfigRequired {
            path: path.to_owned(),
        });
        None
    })?;
    check_range(path, val, min, max, errors);
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
    let val = if let Some(v) = override_val {
        // Accept TOML integer literals (`ratio = 1`) for float fields,
        // matching the schema parser (`take_float`). Without this,
        // `min = 1` works in the manifest but `ratio = 1` in a user
        // override fails with a confusing type mismatch. Precision
        // loss is theoretically possible for `|n| > 2^53` but the
        // values we see in practice are small constants.
        match v {
            toml::Value::Float(n) => Some(*n),
            #[allow(clippy::cast_precision_loss)]
            toml::Value::Integer(n) => Some(*n as f64),
            _ => {
                errors.push(ValidationError::ConfigTypeMismatch {
                    path: path.to_owned(),
                    expected: "float",
                    got: type_name(v),
                });
                None
            }
        }
    } else {
        default
    };
    let val = val.or_else(|| {
        errors.push(ValidationError::ConfigRequired {
            path: path.to_owned(),
        });
        None
    })?;
    // NaN / ±inf comparisons against the declared bounds are always
    // false, so reject non-finite overrides explicitly rather than
    // letting them slip into `InstanceConfig`.
    if !val.is_finite() {
        errors.push(ValidationError::ConfigFloatNotFinite {
            path: path.to_owned(),
            role: "override",
            got: val,
        });
        return None;
    }
    check_range_f(path, val, min, max, errors);
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
    let candidate: Option<String> = if let Some(v) = override_val {
        if let Some(s) = v.as_str() {
            Some(s.to_owned())
        } else {
            errors.push(ValidationError::ConfigTypeMismatch {
                path: path.to_owned(),
                expected: "string",
                got: type_name(v),
            });
            None
        }
    } else {
        default.map(ToOwned::to_owned)
    };
    let val = candidate.or_else(|| {
        errors.push(ValidationError::ConfigRequired {
            path: path.to_owned(),
        });
        None
    })?;
    if !values.iter().any(|allowed| allowed == &val) {
        errors.push(ValidationError::ConfigEnumOutOfRange {
            path: path.to_owned(),
            got: val.clone(),
            allowed: values.to_vec(),
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
    errors: &mut Vec<ValidationError>,
) {
    if let Some(min) = min
        && val < min
    {
        errors.push(ValidationError::ConfigOutOfRange {
            path: path.to_owned(),
            bound: format!(">= {min}"),
            got: val.to_string(),
        });
    }
    if let Some(max) = max
        && val > max
    {
        errors.push(ValidationError::ConfigOutOfRange {
            path: path.to_owned(),
            bound: format!("<= {max}"),
            got: val.to_string(),
        });
    }
}

fn check_range_f(
    path: &str,
    val: f64,
    min: Option<f64>,
    max: Option<f64>,
    errors: &mut Vec<ValidationError>,
) {
    if let Some(min) = min
        && val < min
    {
        errors.push(ValidationError::ConfigOutOfRange {
            path: path.to_owned(),
            bound: format!(">= {min}"),
            got: val.to_string(),
        });
    }
    if let Some(max) = max
        && val > max
    {
        errors.push(ValidationError::ConfigOutOfRange {
            path: path.to_owned(),
            bound: format!("<= {max}"),
            got: val.to_string(),
        });
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
        use crate::manifest::{CapabilitiesSection, PluginSection, RuntimeSection, World};
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
                fuel_per_call: None,
                memory_max_mb: None,
                call_timeout_ms: None,
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
}
