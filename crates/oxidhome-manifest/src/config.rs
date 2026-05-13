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

use serde::{Deserialize, Serialize};

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
// `deny_unknown_fields` is *not* applied here: it interacts badly
// with `#[serde(flatten)]` on internally-tagged enums (serde sees
// fields routed via flatten as "unknown" at the outer struct). The
// inner `ConfigFieldType` keeps `deny_unknown_fields` so per-variant
// payloads are still strictly validated.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConfigField {
    #[serde(flatten)]
    pub ty: ConfigFieldType,
    #[serde(default)]
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
        if let Some(n) = v.as_float() {
            Some(n)
        } else {
            errors.push(ValidationError::ConfigTypeMismatch {
                path: path.to_owned(),
                expected: "float",
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
