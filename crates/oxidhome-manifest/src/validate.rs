//! Manifest validator — every problem in one pass.
//!
//! [`validate`] takes a parsed [`PluginManifest`] and returns
//! `Ok(())` or `Err(Vec<ValidationError>)`. Errors are *collected*,
//! never fail-fast: the CLI install dialog and the host loader both
//! surface every issue to the operator at once so fixing the manifest
//! is iterative-feeling.

use thiserror::Error;

use crate::config::{ConfigField, ConfigFieldType};
use crate::manifest::PluginManifest;

/// One validator finding. Variants carry the original location and
/// enough context for the error message to point a human at the line
/// to fix.
#[derive(Debug, Clone, PartialEq, Error)]
pub enum ValidationError {
    #[error(
        "unsupported manifest_version {got}; the highest version this build knows is {known_max}"
    )]
    UnsupportedManifestVersion { got: u32, known_max: u32 },

    #[error(
        "plugin.id `{got}` does not match the reverse-DNS shape \
         (`[a-z0-9][a-z0-9-]*(\\.[a-z0-9-]+)+` — e.g. `example.simulated-switch`)"
    )]
    InvalidPluginId { got: String },

    #[error(
        "capability `{got}` declared in `capabilities.declares_devices` \
         is not a known device capability"
    )]
    UnknownDeclaredDeviceCapability { got: String },

    #[error(
        "config field `{path}`: enum `default` `{got}` is not in `values` (allowed: {allowed:?})"
    )]
    ConfigEnumDefaultOutOfRange {
        path: String,
        got: String,
        allowed: Vec<String>,
    },

    #[error("config field `{path}`: int `default` {got} is outside [{min:?}, {max:?}]")]
    ConfigIntDefaultOutOfRange {
        path: String,
        got: i64,
        min: Option<i64>,
        max: Option<i64>,
    },

    #[error("config field `{path}`: float `default` {got} is outside [{min:?}, {max:?}]")]
    ConfigFloatDefaultOutOfRange {
        path: String,
        got: f64,
        min: Option<f64>,
        max: Option<f64>,
    },

    #[error("config field `{path}`: enum has no `values` declared")]
    ConfigEnumEmpty { path: String },

    // --- merge-time errors. Validation calls don't emit these, but
    //     `merge` reuses the same vocabulary so the surfacing layer can
    //     show "everything wrong with this manifest+overrides" in one
    //     pile. ---
    #[error("config override `{key}` references a field not declared in the manifest")]
    UnknownConfigKey { key: String },

    #[error(
        "config override `{path}`: required field has no value (no manifest default, no override)"
    )]
    ConfigRequired { path: String },

    #[error("config override `{path}`: expected {expected}, got {got}")]
    ConfigTypeMismatch {
        path: String,
        expected: &'static str,
        got: &'static str,
    },

    #[error("config override `{path}`: {got} is out of range ({bound})")]
    ConfigOutOfRange {
        path: String,
        bound: String,
        got: String,
    },

    #[error("config override `{path}`: `{got}` is not in the allowed enum values {allowed:?}")]
    ConfigEnumOutOfRange {
        path: String,
        got: String,
        allowed: Vec<String>,
    },

    #[error("config overrides root `{path}` must be a TOML table")]
    ConfigOverrideShape { path: String },
}

/// Highest `manifest_version` this build recognises. Bump when a new
/// version is added (and keep deserialization for the old one).
pub const KNOWN_MAX_MANIFEST_VERSION: u32 = 1;

/// Run every check against `m` and collect all findings.
///
/// # Errors
///
/// Returns `Err` with one or more findings whenever the manifest has
/// any problem. The `Ok(())` path means the manifest is well-formed
/// and ready to be merged with user overrides.
pub fn validate(m: &PluginManifest) -> Result<(), Vec<ValidationError>> {
    let mut errors = Vec::new();

    if m.manifest_version > KNOWN_MAX_MANIFEST_VERSION {
        errors.push(ValidationError::UnsupportedManifestVersion {
            got: m.manifest_version,
            known_max: KNOWN_MAX_MANIFEST_VERSION,
        });
    }

    if !is_reverse_dns(&m.plugin.id) {
        errors.push(ValidationError::InvalidPluginId {
            got: m.plugin.id.clone(),
        });
    }

    for cap in &m.capabilities.declares_devices {
        if !is_known_device_capability(cap) {
            errors.push(ValidationError::UnknownDeclaredDeviceCapability { got: cap.clone() });
        }
    }

    for (path, field) in &m.config {
        validate_config_field(path, field, &mut errors);
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

fn validate_config_field(path: &str, field: &ConfigField, errors: &mut Vec<ValidationError>) {
    match &field.ty {
        ConfigFieldType::Bool { .. } | ConfigFieldType::String { .. } => {}
        ConfigFieldType::Int { default, min, max } => {
            if let Some(d) = default {
                if let Some(min) = min
                    && d < min
                {
                    errors.push(ValidationError::ConfigIntDefaultOutOfRange {
                        path: path.to_owned(),
                        got: *d,
                        min: Some(*min),
                        max: *max,
                    });
                }
                if let Some(max) = max
                    && d > max
                {
                    errors.push(ValidationError::ConfigIntDefaultOutOfRange {
                        path: path.to_owned(),
                        got: *d,
                        min: *min,
                        max: Some(*max),
                    });
                }
            }
        }
        ConfigFieldType::Float { default, min, max } => {
            if let Some(d) = default {
                if let Some(min) = min
                    && d < min
                {
                    errors.push(ValidationError::ConfigFloatDefaultOutOfRange {
                        path: path.to_owned(),
                        got: *d,
                        min: Some(*min),
                        max: *max,
                    });
                }
                if let Some(max) = max
                    && d > max
                {
                    errors.push(ValidationError::ConfigFloatDefaultOutOfRange {
                        path: path.to_owned(),
                        got: *d,
                        min: *min,
                        max: Some(*max),
                    });
                }
            }
        }
        ConfigFieldType::Enum { values, default } => {
            if values.is_empty() {
                errors.push(ValidationError::ConfigEnumEmpty {
                    path: path.to_owned(),
                });
            }
            if let Some(d) = default
                && !values.is_empty()
                && !values.contains(d)
            {
                errors.push(ValidationError::ConfigEnumDefaultOutOfRange {
                    path: path.to_owned(),
                    got: d.clone(),
                    allowed: values.clone(),
                });
            }
        }
        ConfigFieldType::Nested { fields } => {
            for (sub_name, sub_field) in fields {
                let sub_path = format!("{path}.{sub_name}");
                validate_config_field(&sub_path, sub_field, errors);
            }
        }
    }
}

/// Reverse-DNS: at least two dot-separated labels, each label is
/// `[a-z0-9]` followed by `[a-z0-9-]*`. Hand-rolled to keep the crate
/// free of a regex dep.
fn is_reverse_dns(s: &str) -> bool {
    if !s.contains('.') {
        return false;
    }
    s.split('.').all(is_valid_label)
}

fn is_valid_label(label: &str) -> bool {
    let mut chars = label.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_lowercase() && !first.is_ascii_digit() {
        return false;
    }
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// 0.1 capability names the WIT knows. Kept in sync with
/// `wit/oxidhome.wit` `capability-spec`. The `extension(...)` form is
/// open; manifests declaring a plain capability that isn't on this
/// list fails validation.
const KNOWN_DEVICE_CAPABILITIES: &[&str] = &[
    "switch",
    "dimmer",
    "color-light",
    "sensor",
    "button",
    "video-stream",
    "audio-stream",
];

fn is_known_device_capability(s: &str) -> bool {
    // The `extension(...)` arm in the WIT is escape-hatch syntax
    // plugin authors can use for capabilities outside the standard
    // set. Accept it verbatim.
    if s.starts_with("extension(") && s.ends_with(')') {
        return true;
    }
    KNOWN_DEVICE_CAPABILITIES.contains(&s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{CapabilitiesSection, PluginSection, RuntimeSection, World};
    use semver::Version;
    use std::collections::BTreeMap;

    fn ok_manifest() -> PluginManifest {
        PluginManifest {
            manifest_version: 1,
            plugin: PluginSection {
                id: "example.simulated-switch".into(),
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
            capabilities: CapabilitiesSection {
                declares_devices: vec!["switch".into()],
                ..CapabilitiesSection::default()
            },
            config: BTreeMap::new(),
            ui: None,
        }
    }

    #[test]
    fn clean_manifest_validates() {
        validate(&ok_manifest()).expect("clean must pass");
    }

    #[test]
    fn flags_unsupported_manifest_version() {
        let mut m = ok_manifest();
        m.manifest_version = 99;
        let errs = validate(&m).unwrap_err();
        assert!(
            errs.iter()
                .any(|e| matches!(e, ValidationError::UnsupportedManifestVersion { .. }))
        );
    }

    #[test]
    fn flags_invalid_plugin_id() {
        for bad in [
            "noDots",
            "UPPER.case",
            "trailing.",
            ".leading",
            "double..dot",
            "spaces in id",
        ] {
            let mut m = ok_manifest();
            m.plugin.id = bad.into();
            let errs = validate(&m).unwrap_err();
            assert!(
                errs.iter()
                    .any(|e| matches!(e, ValidationError::InvalidPluginId { .. })),
                "expected InvalidPluginId for `{bad}`, got {errs:?}",
            );
        }
    }

    #[test]
    fn accepts_extension_capabilities() {
        let mut m = ok_manifest();
        m.capabilities.declares_devices = vec!["extension(window-shade)".into()];
        validate(&m).expect("extension(...) is the escape hatch");
    }

    #[test]
    fn flags_unknown_declared_device_capability() {
        let mut m = ok_manifest();
        m.capabilities.declares_devices = vec!["teleporter".into()];
        let errs = validate(&m).unwrap_err();
        assert!(
            errs.iter().any(|e| matches!(
                e,
                ValidationError::UnknownDeclaredDeviceCapability { got } if got == "teleporter"
            )),
            "got {errs:?}",
        );
    }

    #[test]
    fn flags_enum_with_default_outside_values() {
        let mut m = ok_manifest();
        m.config.insert(
            "mode".into(),
            ConfigField {
                ty: ConfigFieldType::Enum {
                    values: vec!["off".into(), "on".into()],
                    default: Some("auto".into()),
                },
                description: None,
            },
        );
        let errs = validate(&m).unwrap_err();
        assert!(
            errs.iter()
                .any(|e| matches!(e, ValidationError::ConfigEnumDefaultOutOfRange { .. }))
        );
    }

    #[test]
    fn flags_int_default_out_of_range() {
        let mut m = ok_manifest();
        m.config.insert(
            "port".into(),
            ConfigField {
                ty: ConfigFieldType::Int {
                    default: Some(99999),
                    min: Some(1),
                    max: Some(65535),
                },
                description: None,
            },
        );
        let errs = validate(&m).unwrap_err();
        assert!(
            errs.iter()
                .any(|e| matches!(e, ValidationError::ConfigIntDefaultOutOfRange { .. }))
        );
    }

    #[test]
    fn flags_empty_enum_values() {
        let mut m = ok_manifest();
        m.config.insert(
            "mode".into(),
            ConfigField {
                ty: ConfigFieldType::Enum {
                    values: vec![],
                    default: None,
                },
                description: None,
            },
        );
        let errs = validate(&m).unwrap_err();
        assert!(
            errs.iter()
                .any(|e| matches!(e, ValidationError::ConfigEnumEmpty { path } if path == "mode"))
        );
    }

    #[test]
    fn flags_float_default_out_of_range() {
        let mut m = ok_manifest();
        m.config.insert(
            "ratio_under".into(),
            ConfigField {
                ty: ConfigFieldType::Float {
                    default: Some(-0.5),
                    min: Some(0.0),
                    max: Some(1.0),
                },
                description: None,
            },
        );
        m.config.insert(
            "ratio_over".into(),
            ConfigField {
                ty: ConfigFieldType::Float {
                    default: Some(1.5),
                    min: Some(0.0),
                    max: Some(1.0),
                },
                description: None,
            },
        );
        let errs = validate(&m).unwrap_err();
        let count = errs
            .iter()
            .filter(|e| matches!(e, ValidationError::ConfigFloatDefaultOutOfRange { .. }))
            .count();
        assert_eq!(count, 2);
    }

    #[test]
    fn flags_int_default_below_min() {
        let mut m = ok_manifest();
        m.config.insert(
            "n".into(),
            ConfigField {
                ty: ConfigFieldType::Int {
                    default: Some(-1),
                    min: Some(0),
                    max: None,
                },
                description: None,
            },
        );
        let errs = validate(&m).unwrap_err();
        assert!(errs.iter().any(|e| matches!(
            e,
            ValidationError::ConfigIntDefaultOutOfRange { got: -1, .. }
        )));
    }

    #[test]
    fn passes_when_int_default_inside_range() {
        let mut m = ok_manifest();
        m.config.insert(
            "n".into(),
            ConfigField {
                ty: ConfigFieldType::Int {
                    default: Some(50),
                    min: Some(0),
                    max: Some(100),
                },
                description: None,
            },
        );
        validate(&m).expect("in-range default should pass");
    }

    #[test]
    fn passes_when_float_default_inside_range() {
        let mut m = ok_manifest();
        m.config.insert(
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
        validate(&m).expect("in-range default should pass");
    }

    #[test]
    fn passes_when_enum_default_in_values() {
        let mut m = ok_manifest();
        m.config.insert(
            "mode".into(),
            ConfigField {
                ty: ConfigFieldType::Enum {
                    values: vec!["a".into(), "b".into()],
                    default: Some("a".into()),
                },
                description: None,
            },
        );
        validate(&m).expect("default in values should pass");
    }

    #[test]
    fn recurses_into_nested_config() {
        let mut inner = BTreeMap::new();
        inner.insert(
            "port".into(),
            ConfigField {
                ty: ConfigFieldType::Int {
                    default: Some(99999),
                    min: Some(1),
                    max: Some(65535),
                },
                description: None,
            },
        );
        let mut m = ok_manifest();
        m.config.insert(
            "broker".into(),
            ConfigField {
                ty: ConfigFieldType::Nested { fields: inner },
                description: None,
            },
        );
        let errs = validate(&m).unwrap_err();
        assert!(errs.iter().any(|e| matches!(
            e,
            ValidationError::ConfigIntDefaultOutOfRange { path, .. } if path == "broker.port"
        )));
    }
}
