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

/// One validator finding. Each variant carries the manifest *field
/// path* (e.g. `"plugin.id"`, `"config.broker.host"`) plus enough
/// context for the error message to point a human at what to fix.
/// Source-line / column / span information from the TOML parser is
/// not threaded through today — `toml` exposes spans via
/// `serde_spanned`, and a future Phase-4 follow-up can wire them
/// into these variants when the install dialog needs them.
#[derive(Debug, Clone, PartialEq, Error)]
pub enum ValidationError {
    #[error("unsupported manifest_version {got}; this build supports only {supported:?}")]
    UnsupportedManifestVersion { got: u32, supported: Vec<u32> },

    #[error(
        "plugin.id `{got}` does not match the reverse-DNS shape \
         (`[a-z0-9][a-z0-9-]*(\\.[a-z0-9][a-z0-9-]*)+` — every label must start with \
         `[a-z0-9]`; e.g. `example.simulated-switch`)"
    )]
    InvalidPluginId { got: String },

    #[error(
        "capability `{got}` declared in `capabilities.declares_devices` \
         is not a known device capability"
    )]
    UnknownDeclaredDeviceCapability { got: String },

    #[error(
        "plugin.keywords has {count} entries; the cap is {max}. Trim the list — \
         beyond that it's harder to skim than the plugin's name and description."
    )]
    TooManyKeywords { count: usize, max: usize },

    #[error("plugin.keywords[{index}] `{got}` is invalid: {reason}")]
    InvalidKeyword {
        index: usize,
        got: String,
        reason: &'static str,
    },

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

    #[error("config field `{path}`: declared range is invalid (min={min:?} > max={max:?})")]
    ConfigIntRangeInvalid { path: String, min: i64, max: i64 },

    #[error("config field `{path}`: declared range is invalid (min={min:?} > max={max:?})")]
    ConfigFloatRangeInvalid { path: String, min: f64, max: f64 },

    #[error(
        "config field `{path}`: float `{role}` is not finite ({got}). NaN and ±inf are not \
         valid config values."
    )]
    ConfigFloatNotFinite {
        path: String,
        role: &'static str,
        got: f64,
    },

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

/// Every `manifest_version` this build accepts. Add to this list when
/// a new manifest schema is introduced (and keep deserialization for
/// the old one, per the format-evolution policy in the per-crate
/// plan).
pub const SUPPORTED_MANIFEST_VERSIONS: &[u32] = &[1];

/// Maximum number of entries allowed in `plugin.keywords`. Soft cap
/// to keep the UI's filter chip list readable; beyond this a plugin
/// author probably wants a `description` instead.
pub const MAX_KEYWORDS: usize = 16;

/// Maximum length of a single keyword in characters.
pub const MAX_KEYWORD_LEN: usize = 50;

/// Run every check against `m` and collect all findings.
///
/// # Errors
///
/// Returns `Err` with one or more findings whenever the manifest has
/// any problem. The `Ok(())` path means the manifest is well-formed
/// and ready to be merged with user overrides.
pub fn validate(m: &PluginManifest) -> Result<(), Vec<ValidationError>> {
    let mut errors = Vec::new();

    if !SUPPORTED_MANIFEST_VERSIONS.contains(&m.manifest_version) {
        errors.push(ValidationError::UnsupportedManifestVersion {
            got: m.manifest_version,
            supported: SUPPORTED_MANIFEST_VERSIONS.to_vec(),
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

    validate_keywords(&m.plugin.keywords, &mut errors);

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
            validate_int_field(path, *default, *min, *max, errors);
        }
        ConfigFieldType::Float { default, min, max } => {
            validate_float_field(path, *default, *min, *max, errors);
        }
        ConfigFieldType::Enum { values, default } => {
            validate_enum_field(path, values, default.as_deref(), errors);
        }
        ConfigFieldType::Nested { fields } => {
            for (sub_name, sub_field) in fields {
                let sub_path = format!("{path}.{sub_name}");
                validate_config_field(&sub_path, sub_field, errors);
            }
        }
    }
}

fn validate_int_field(
    path: &str,
    default: Option<i64>,
    min: Option<i64>,
    max: Option<i64>,
    errors: &mut Vec<ValidationError>,
) {
    if let Some(min) = min
        && let Some(max) = max
        && min > max
    {
        errors.push(ValidationError::ConfigIntRangeInvalid {
            path: path.to_owned(),
            min,
            max,
        });
    }
    let Some(d) = default else { return };
    if let Some(min) = min
        && d < min
    {
        errors.push(ValidationError::ConfigIntDefaultOutOfRange {
            path: path.to_owned(),
            got: d,
            min: Some(min),
            max,
        });
    }
    if let Some(max) = max
        && d > max
    {
        errors.push(ValidationError::ConfigIntDefaultOutOfRange {
            path: path.to_owned(),
            got: d,
            min,
            max: Some(max),
        });
    }
}

fn validate_float_field(
    path: &str,
    default: Option<f64>,
    min: Option<f64>,
    max: Option<f64>,
    errors: &mut Vec<ValidationError>,
) {
    // NaN / ±inf bypass `<`/`>` comparisons silently — reject them up
    // front so a malformed default doesn't fall through into runtime
    // values.
    check_float_finite(path, default, "default", errors);
    check_float_finite(path, min, "min", errors);
    check_float_finite(path, max, "max", errors);

    if let Some(min) = min
        && let Some(max) = max
        && min.is_finite()
        && max.is_finite()
        && min > max
    {
        errors.push(ValidationError::ConfigFloatRangeInvalid {
            path: path.to_owned(),
            min,
            max,
        });
    }
    let Some(d) = default else { return };
    if !d.is_finite() {
        return;
    }
    if let Some(min) = min
        && min.is_finite()
        && d < min
    {
        errors.push(ValidationError::ConfigFloatDefaultOutOfRange {
            path: path.to_owned(),
            got: d,
            min: Some(min),
            max,
        });
    }
    if let Some(max) = max
        && max.is_finite()
        && d > max
    {
        errors.push(ValidationError::ConfigFloatDefaultOutOfRange {
            path: path.to_owned(),
            got: d,
            min,
            max: Some(max),
        });
    }
}

fn validate_enum_field(
    path: &str,
    values: &[String],
    default: Option<&str>,
    errors: &mut Vec<ValidationError>,
) {
    if values.is_empty() {
        errors.push(ValidationError::ConfigEnumEmpty {
            path: path.to_owned(),
        });
    }
    if let Some(d) = default
        && !values.is_empty()
        && !values.iter().any(|v| v == d)
    {
        errors.push(ValidationError::ConfigEnumDefaultOutOfRange {
            path: path.to_owned(),
            got: d.to_owned(),
            allowed: values.to_vec(),
        });
    }
}

/// Validate `plugin.keywords`. The UI uses these for filter/group
/// facets, so they need a predictable shape:
/// - lowercase kebab-case: first char `[a-z0-9]`, then `[a-z0-9-]*`
/// - 1 to [`MAX_KEYWORD_LEN`] chars
/// - at most [`MAX_KEYWORDS`] per plugin
fn validate_keywords(keywords: &[String], errors: &mut Vec<ValidationError>) {
    if keywords.len() > MAX_KEYWORDS {
        errors.push(ValidationError::TooManyKeywords {
            count: keywords.len(),
            max: MAX_KEYWORDS,
        });
    }
    for (index, kw) in keywords.iter().enumerate() {
        let reason = keyword_problem(kw);
        if let Some(reason) = reason {
            errors.push(ValidationError::InvalidKeyword {
                index,
                got: kw.clone(),
                reason,
            });
        }
    }
}

fn keyword_problem(kw: &str) -> Option<&'static str> {
    if kw.is_empty() {
        return Some("empty");
    }
    if kw.len() > MAX_KEYWORD_LEN {
        return Some("exceeds 50 characters");
    }
    if !is_valid_keyword(kw) {
        return Some("must be lowercase kebab-case (`[a-z0-9][a-z0-9-]*`)");
    }
    None
}

fn is_valid_keyword(s: &str) -> bool {
    let mut chars = s.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_lowercase() && !first.is_ascii_digit() {
        return false;
    }
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// Push a `ConfigFloatNotFinite` if `v` is `Some(NaN)` or `Some(±inf)`.
/// The validator runs this for `default`, `min`, and `max` separately
/// so the operator sees which field is malformed.
fn check_float_finite(
    path: &str,
    v: Option<f64>,
    role: &'static str,
    errors: &mut Vec<ValidationError>,
) {
    if let Some(v) = v
        && !v.is_finite()
    {
        errors.push(ValidationError::ConfigFloatNotFinite {
            path: path.to_owned(),
            role,
            got: v,
        });
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
    fn keywords_accept_typical_shapes() {
        let mut m = ok_manifest();
        m.plugin.keywords = vec![
            "switch".into(),
            "matter".into(),
            "home-assistant-compat".into(),
            "zigbee2mqtt".into(),
            "v2".into(), // digit-led labels are fine
        ];
        validate(&m).expect("typical keywords should pass");
    }

    #[test]
    fn keywords_reject_too_many() {
        let mut m = ok_manifest();
        m.plugin.keywords = (0..=MAX_KEYWORDS).map(|i| format!("k{i}")).collect();
        let errs = validate(&m).unwrap_err();
        assert!(errs.iter().any(|e| matches!(
            e,
            ValidationError::TooManyKeywords { count, max } if *max == MAX_KEYWORDS && *count == MAX_KEYWORDS + 1
        )));
    }

    #[test]
    fn keywords_reject_empty_string() {
        let mut m = ok_manifest();
        m.plugin.keywords = vec!["ok".into(), String::new()];
        let errs = validate(&m).unwrap_err();
        assert!(errs.iter().any(|e| matches!(
            e,
            ValidationError::InvalidKeyword {
                index: 1,
                reason: "empty",
                ..
            }
        )));
    }

    #[test]
    fn keywords_reject_too_long() {
        let mut m = ok_manifest();
        let long = "a".repeat(MAX_KEYWORD_LEN + 1);
        m.plugin.keywords = vec![long.clone()];
        let errs = validate(&m).unwrap_err();
        assert!(errs.iter().any(|e| matches!(
            e,
            ValidationError::InvalidKeyword { reason: "exceeds 50 characters", got, .. } if got == &long
        )));
    }

    #[test]
    fn keywords_reject_bad_charset() {
        let mut m = ok_manifest();
        m.plugin.keywords = vec![
            "UPPER".into(),      // uppercase
            "with space".into(), // space
            "trailing-".into(),  // valid (trailing dash is allowed by `[a-z0-9-]*`)
            "-leading".into(),   // leading dash → invalid
            "spe!cial".into(),   // punctuation
        ];
        let errs = validate(&m).unwrap_err();
        let kebab_errs: Vec<_> = errs
            .iter()
            .filter(|e| matches!(
                e,
                ValidationError::InvalidKeyword { reason: r, .. } if r.starts_with("must be lowercase kebab-case")
            ))
            .collect();
        // UPPER, "with space", "-leading", "spe!cial" — 4 invalid.
        // "trailing-" is allowed because the grammar is `first [a-z0-9], rest [a-z0-9-]*`.
        assert_eq!(kebab_errs.len(), 4, "got {errs:?}");
    }

    #[test]
    fn manifest_version_zero_rejected() {
        let mut m = ok_manifest();
        m.manifest_version = 0;
        let errs = validate(&m).unwrap_err();
        assert!(errs.iter().any(|e| matches!(
            e,
            ValidationError::UnsupportedManifestVersion { got: 0, .. }
        )));
    }

    #[test]
    fn flags_int_range_invalid() {
        let mut m = ok_manifest();
        m.config.insert(
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
        let errs = validate(&m).unwrap_err();
        assert!(errs.iter().any(|e| matches!(
            e,
            ValidationError::ConfigIntRangeInvalid {
                min: 100,
                max: 10,
                ..
            }
        )));
    }

    #[test]
    fn flags_float_range_invalid() {
        let mut m = ok_manifest();
        m.config.insert(
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
        let errs = validate(&m).unwrap_err();
        assert!(
            errs.iter()
                .any(|e| matches!(e, ValidationError::ConfigFloatRangeInvalid { .. }))
        );
    }

    #[test]
    fn flags_non_finite_float_default() {
        for (role, v) in [
            ("default", f64::NAN),
            ("default", f64::INFINITY),
            ("default", f64::NEG_INFINITY),
        ] {
            let mut m = ok_manifest();
            m.config.insert(
                "f".into(),
                ConfigField {
                    ty: ConfigFieldType::Float {
                        default: Some(v),
                        min: None,
                        max: None,
                    },
                    description: None,
                },
            );
            let errs = validate(&m).unwrap_err();
            assert!(
                errs.iter().any(|e| matches!(
                    e,
                    ValidationError::ConfigFloatNotFinite { role: r, .. } if *r == role
                )),
                "expected NotFinite for {role} = {v}, got {errs:?}",
            );
        }
    }

    #[test]
    fn flags_non_finite_float_min_and_max() {
        let mut m = ok_manifest();
        m.config.insert(
            "f".into(),
            ConfigField {
                ty: ConfigFieldType::Float {
                    default: Some(0.5),
                    min: Some(f64::NAN),
                    max: Some(f64::INFINITY),
                },
                description: None,
            },
        );
        let errs = validate(&m).unwrap_err();
        assert!(
            errs.iter()
                .any(|e| matches!(e, ValidationError::ConfigFloatNotFinite { role: "min", .. }))
        );
        assert!(
            errs.iter()
                .any(|e| matches!(e, ValidationError::ConfigFloatNotFinite { role: "max", .. }))
        );
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
