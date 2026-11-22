//! Typed capability and service-command contracts (architecture
//! review M2).
//!
//! The WIT carries three machine-readable contracts the host enforces
//! here, at the boundary, so consumers never have to parse a human
//! hint:
//!
//! - **Extension capabilities** are `(namespace, name, version)`
//!   records. [`check_device_info`] validates them with
//!   [`oxidhome_manifest::ExtensionId`], the same rules the manifest
//!   validator applies to `declares_devices`, and
//!   [`extension_capability_key`] renders the capability key both
//!   sides gate on.
//! - **Sensor units** are a closed WIT variant. The named cases are
//!   the contract ([`unit_code`] is each case's stable code in the
//!   state projection); `other(label)` is a display-only fallback the
//!   host keeps apart (`unit = "other"`, `unit_label = <label>`) and
//!   refuses when the label spells a named code. Sensor
//!   `state-changed` deltas and `ok-with-state` replies may only
//!   restate the spec's unit ([`check_sensor_fields`]).
//! - **Service commands** carry `params` / `returns` field schemas.
//!   [`check_service_info`] validates them at `register-service` /
//!   `update-service`; [`check_args`] gates every `call-service`
//!   before dispatch and [`check_result`] gates the callee's reply.

use std::collections::HashSet;

use crate::host_impl::plugin::oxidhome::plugin::capabilities::{
    CapabilitySpec, CapabilityState, ExtensionSpec, SensorSpec, Unit,
};
use crate::host_impl::plugin::oxidhome::plugin::devices::{CommandResult, DeviceInfo};
use crate::host_impl::plugin::oxidhome::plugin::services::{
    CommandSpec, FieldConstraint, FieldSpec, ServiceInfo, ValueKind,
};
use crate::host_impl::plugin::oxidhome::plugin::types::{Error as WitError, KeyValue, Value};

/// Most commands one service may declare.
pub(crate) const MAX_COMMANDS_PER_SERVICE: usize = 64;
/// Most fields one `params` or `returns` list may declare.
pub(crate) const MAX_FIELDS_PER_SCHEMA: usize = 32;
/// Most values a `one-of` constraint may list.
pub(crate) const MAX_ONE_OF_VALUES: usize = 64;
/// Longest `one-of` value, in bytes.
pub(crate) const MAX_ONE_OF_VALUE_LEN: usize = 256;
/// Longest command or field name, in bytes.
pub(crate) const MAX_NAME_LEN: usize = 64;
/// Longest command or field description, in bytes.
pub(crate) const MAX_DESCRIPTION_LEN: usize = 1024;
/// Longest `unit::other` label, in bytes.
pub(crate) const MAX_UNIT_LABEL_LEN: usize = 32;

/// Code `unit::other` is projected as. Never a named unit's code.
pub(crate) const OTHER_UNIT_CODE: &str = "other";

/// Every named unit's code, for refusing an `other` label that spells
/// one. Kept in step with [`unit_code`] by `named_unit_codes_match`.
const NAMED_UNIT_CODES: &[&str] = &[
    "unitless",
    "percent",
    "celsius",
    "fahrenheit",
    "kelvin",
    "lux",
    "watt",
    "kilowatt",
    "watt-hour",
    "kilowatt-hour",
    "volt",
    "ampere",
    "hertz",
    "pascal",
    "hectopascal",
    "ppm",
    "ppb",
    "microgram-per-cubic-meter",
    "millimeter",
    "meter",
    "meter-per-second",
    "liter",
    "cubic-meter",
    "gram",
    "kilogram",
    "second",
    "degree",
    "decibel",
    "dbm",
];

/// Stable code for a unit: the WIT case name, or [`OTHER_UNIT_CODE`]
/// for the non-contractual fallback.
pub(crate) fn unit_code(unit: &Unit) -> &'static str {
    match unit {
        Unit::Unitless => "unitless",
        Unit::Percent => "percent",
        Unit::Celsius => "celsius",
        Unit::Fahrenheit => "fahrenheit",
        Unit::Kelvin => "kelvin",
        Unit::Lux => "lux",
        Unit::Watt => "watt",
        Unit::Kilowatt => "kilowatt",
        Unit::WattHour => "watt-hour",
        Unit::KilowattHour => "kilowatt-hour",
        Unit::Volt => "volt",
        Unit::Ampere => "ampere",
        Unit::Hertz => "hertz",
        Unit::Pascal => "pascal",
        Unit::Hectopascal => "hectopascal",
        Unit::Ppm => "ppm",
        Unit::Ppb => "ppb",
        Unit::MicrogramPerCubicMeter => "microgram-per-cubic-meter",
        Unit::Millimeter => "millimeter",
        Unit::Meter => "meter",
        Unit::MeterPerSecond => "meter-per-second",
        Unit::Liter => "liter",
        Unit::CubicMeter => "cubic-meter",
        Unit::Gram => "gram",
        Unit::Kilogram => "kilogram",
        Unit::Second => "second",
        Unit::Degree => "degree",
        Unit::Decibel => "decibel",
        Unit::Dbm => "dbm",
        Unit::Other(_) => OTHER_UNIT_CODE,
    }
}

/// `(code, label)` identity of a unit, for equality without a
/// `PartialEq` derive on the generated type.
fn unit_identity(unit: &Unit) -> (&'static str, Option<&str>) {
    match unit {
        Unit::Other(label) => (OTHER_UNIT_CODE, Some(label.as_str())),
        named => (unit_code(named), None),
    }
}

/// Human-readable unit for error messages.
fn unit_display(unit: &Unit) -> String {
    match unit {
        Unit::Other(label) => format!("other({label:?})"),
        named => unit_code(named).to_owned(),
    }
}

/// The capability key for an extension spec,
/// `extension(<namespace>/<name>@<version>)`. Rendered without
/// validation so it can name a spec in an error message; callers that
/// gate on it run [`check_device_info`] first.
pub(crate) fn extension_capability_key(spec: &ExtensionSpec) -> String {
    format!(
        "extension({}/{}@{})",
        spec.namespace, spec.name, spec.version
    )
}

/// Projection fields for a sensor measurement: `value` and `unit` (the
/// code), plus `unit_label` for the `other` fallback.
pub(crate) fn measurement_fields(value: f64, unit: &Unit) -> Vec<KeyValue> {
    let mut fields = vec![
        KeyValue {
            key: "value".into(),
            value: Value::FloatVal(value),
        },
        KeyValue {
            key: "unit".into(),
            value: Value::StringVal(unit_code(unit).to_owned()),
        },
    ];
    if let Unit::Other(label) = unit {
        fields.push(KeyValue {
            key: "unit_label".into(),
            value: Value::StringVal(label.clone()),
        });
    }
    fields
}

/// How a sensor field bag reaches the projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SensorWrite {
    /// `state-changed` delta: merged into the slot, so the unit may be
    /// left out (the seeded one stays).
    Delta,
    /// `ok-with-state` reply: replaces the slot, so it must carry the
    /// unit (and the label, for `other`) or the reading would lose it.
    Snapshot,
}

/// A sensor `state-changed` delta or `ok-with-state` reply may restate
/// `unit` / `unit_label`, but only as the device's sensor spec
/// declares them; anything else would put a free-form unit back into
/// the projection. A [`SensorWrite::Snapshot`] must restate them. No-op
/// for other capabilities.
pub(crate) fn check_sensor_fields(
    info: &DeviceInfo,
    capability: &str,
    fields: &[KeyValue],
    write: SensorWrite,
) -> Result<(), String> {
    if capability != "sensor" {
        return Ok(());
    }
    let Some(spec_unit) = info.capabilities.iter().find_map(|c| match c {
        CapabilitySpec::Sensor(s) => Some(&s.unit),
        _ => None,
    }) else {
        return Ok(());
    };
    let (code, label) = unit_identity(spec_unit);
    for kv in fields {
        match (kv.key.as_str(), &kv.value) {
            ("unit", Value::StringVal(v)) if v == code => {}
            ("unit_label", Value::StringVal(v)) if Some(v.as_str()) == label => {}
            ("unit" | "unit_label", _) => {
                return Err(format!(
                    "sensor field `{}` must match the sensor spec's unit `{}`",
                    kv.key,
                    unit_display(spec_unit)
                ));
            }
            _ => {}
        }
    }
    if write == SensorWrite::Snapshot {
        let has = |key: &str| fields.iter().any(|kv| kv.key == key);
        let missing = if !has("unit") {
            Some("unit")
        } else if label.is_some() && !has("unit_label") {
            Some("unit_label")
        } else {
            None
        };
        if let Some(key) = missing {
            return Err(format!(
                "a sensor reply replaces the reading, so it must include `{key}` \
                 (the sensor spec's unit is `{}`)",
                unit_display(spec_unit)
            ));
        }
    }
    Ok(())
}

fn check_unit(unit: &Unit) -> Result<(), String> {
    let Unit::Other(label) = unit else {
        return Ok(());
    };
    if label.trim().is_empty() {
        return Err("unit `other` needs a non-blank label".into());
    }
    if label.len() > MAX_UNIT_LABEL_LEN {
        return Err(format!(
            "unit `other` label is {} bytes; the cap is {MAX_UNIT_LABEL_LEN}",
            label.len()
        ));
    }
    if label.chars().any(char::is_control) {
        return Err("unit `other` label contains control characters".into());
    }
    let lower = label.trim().to_ascii_lowercase();
    if lower == OTHER_UNIT_CODE || NAMED_UNIT_CODES.contains(&lower.as_str()) {
        return Err(format!(
            "unit `other({label:?})` spells a named unit; use the named `unit` case instead"
        ));
    }
    Ok(())
}

fn check_sensor_spec(spec: &SensorSpec) -> Result<(), String> {
    check_unit(&spec.unit)?;
    for bound in [spec.min, spec.max].into_iter().flatten() {
        if !bound.is_finite() {
            return Err(format!("sensor range bound {bound} is not finite"));
        }
    }
    if let (Some(min), Some(max)) = (spec.min, spec.max)
        && min > max
    {
        return Err(format!("sensor range min {min} is greater than max {max}"));
    }
    Ok(())
}

/// Validate the typed parts of a `register-device` / `update-device`
/// payload: extension identities, sensor units and ranges, and that a
/// sensor's `initial-state` reading uses its spec's unit. Every
/// failure is `invalid-argument`.
pub(crate) fn check_device_info(info: &DeviceInfo) -> Result<(), WitError> {
    let invalid =
        |msg: String| WitError::InvalidArgument(format!("device `{}`: {msg}", info.local_id));
    let mut sensor_unit = None;
    for spec in &info.capabilities {
        match spec {
            CapabilitySpec::Extension(ext) => {
                oxidhome_manifest::ExtensionId::new(
                    ext.namespace.as_str(),
                    ext.name.as_str(),
                    ext.version,
                )
                .map_err(|e| {
                    invalid(format!(
                        "extension capability `{}` is invalid: {e}",
                        extension_capability_key(ext)
                    ))
                })?;
            }
            CapabilitySpec::Sensor(sensor) => {
                check_sensor_spec(sensor).map_err(invalid)?;
                sensor_unit = Some(&sensor.unit);
            }
            _ => {}
        }
    }
    for state in &info.initial_state {
        if let CapabilityState::Sensor(m) = state {
            check_unit(&m.unit).map_err(invalid)?;
            // A missing sensor spec is refused by the declaration gate
            // with a clearer message; only compare when both exist.
            if let Some(spec_unit) = sensor_unit
                && unit_identity(spec_unit) != unit_identity(&m.unit)
            {
                return Err(invalid(format!(
                    "initial sensor reading is in `{}` but the sensor spec declares `{}`",
                    unit_display(&m.unit),
                    unit_display(spec_unit),
                )));
            }
        }
    }
    Ok(())
}

/// `[A-Za-z0-9][A-Za-z0-9_-]*`, at most [`MAX_NAME_LEN`] bytes.
fn is_schema_name(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    name.len() <= MAX_NAME_LEN
        && first.is_ascii_alphanumeric()
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

fn check_description(what: &str, description: Option<&String>) -> Result<(), String> {
    match description {
        Some(d) if d.len() > MAX_DESCRIPTION_LEN => Err(format!(
            "{what} description is {} bytes; the cap is {MAX_DESCRIPTION_LEN}",
            d.len()
        )),
        _ => Ok(()),
    }
}

fn kind_name(kind: ValueKind) -> &'static str {
    match kind {
        ValueKind::BoolVal => "bool-val",
        ValueKind::IntVal => "int-val",
        ValueKind::FloatVal => "float-val",
        ValueKind::StringVal => "string-val",
        ValueKind::BytesVal => "bytes-val",
        ValueKind::JsonVal => "json-val",
    }
}

fn kind_of(value: &Value) -> ValueKind {
    match value {
        Value::BoolVal(_) => ValueKind::BoolVal,
        Value::IntVal(_) => ValueKind::IntVal,
        Value::FloatVal(_) => ValueKind::FloatVal,
        Value::StringVal(_) => ValueKind::StringVal,
        Value::BytesVal(_) => ValueKind::BytesVal,
        Value::JsonVal(_) => ValueKind::JsonVal,
    }
}

fn check_field_spec(list: &str, field: &FieldSpec) -> Result<(), String> {
    let at = || format!("{list} field `{}`", field.name);
    if !is_schema_name(&field.name) {
        return Err(format!(
            "{list} field name {:?} must be 1-{MAX_NAME_LEN} characters of [A-Za-z0-9_-], \
             starting with a letter or digit",
            field.name
        ));
    }
    check_description(&at(), field.description.as_ref())?;
    let Some(constraint) = &field.constraint else {
        return Ok(());
    };
    match (constraint, field.kind) {
        (FieldConstraint::OneOf(values), ValueKind::StringVal) => {
            if values.is_empty() {
                return Err(format!("{}: `one-of` lists no values", at()));
            }
            if values.len() > MAX_ONE_OF_VALUES {
                return Err(format!(
                    "{}: `one-of` lists {} values; the cap is {MAX_ONE_OF_VALUES}",
                    at(),
                    values.len()
                ));
            }
            let mut seen = HashSet::new();
            for v in values {
                if v.len() > MAX_ONE_OF_VALUE_LEN {
                    return Err(format!(
                        "{}: a `one-of` value is {} bytes; the cap is {MAX_ONE_OF_VALUE_LEN}",
                        at(),
                        v.len()
                    ));
                }
                if !seen.insert(v.as_str()) {
                    return Err(format!("{}: `one-of` lists {v:?} twice", at()));
                }
            }
        }
        (FieldConstraint::IntRange(r), ValueKind::IntVal) => {
            if let (Some(min), Some(max)) = (r.min, r.max)
                && min > max
            {
                return Err(format!(
                    "{}: range min {min} is greater than max {max}",
                    at()
                ));
            }
        }
        (FieldConstraint::FloatRange(r), ValueKind::FloatVal) => {
            for bound in [r.min, r.max].into_iter().flatten() {
                if !bound.is_finite() {
                    return Err(format!("{}: range bound {bound} is not finite", at()));
                }
            }
            if let (Some(min), Some(max)) = (r.min, r.max)
                && min > max
            {
                return Err(format!(
                    "{}: range min {min} is greater than max {max}",
                    at()
                ));
            }
        }
        (constraint, kind) => {
            let constraint = match constraint {
                FieldConstraint::OneOf(_) => "one-of",
                FieldConstraint::IntRange(_) => "int-range",
                FieldConstraint::FloatRange(_) => "float-range",
            };
            return Err(format!(
                "{}: a `{constraint}` constraint does not apply to a `{}` field",
                at(),
                kind_name(kind)
            ));
        }
    }
    Ok(())
}

fn check_field_list(list: &str, fields: &[FieldSpec]) -> Result<(), String> {
    if fields.len() > MAX_FIELDS_PER_SCHEMA {
        return Err(format!(
            "{list} declares {} fields; the cap is {MAX_FIELDS_PER_SCHEMA}",
            fields.len()
        ));
    }
    let mut seen = HashSet::new();
    for field in fields {
        check_field_spec(list, field)?;
        if !seen.insert(field.name.as_str()) {
            return Err(format!("{list} declares field `{}` twice", field.name));
        }
    }
    Ok(())
}

/// Validate a `register-service` / `update-service` payload's command
/// schemas. Every failure is `invalid-argument`.
pub(crate) fn check_service_info(info: &ServiceInfo) -> Result<(), WitError> {
    let invalid =
        |msg: String| WitError::InvalidArgument(format!("service `{}`: {msg}", info.local_id));
    if info.commands.len() > MAX_COMMANDS_PER_SERVICE {
        return Err(invalid(format!(
            "declares {} commands; the cap is {MAX_COMMANDS_PER_SERVICE}",
            info.commands.len()
        )));
    }
    let mut seen = HashSet::new();
    for cmd in &info.commands {
        if !is_schema_name(&cmd.name) {
            return Err(invalid(format!(
                "command name {:?} must be 1-{MAX_NAME_LEN} characters of [A-Za-z0-9_-], \
                 starting with a letter or digit",
                cmd.name
            )));
        }
        if !seen.insert(cmd.name.as_str()) {
            return Err(invalid(format!("declares command `{}` twice", cmd.name)));
        }
        let at = format!("command `{}`", cmd.name);
        check_description(&at, cmd.description.as_ref()).map_err(invalid)?;
        check_field_list(&format!("{at} params"), &cmd.params).map_err(invalid)?;
        check_field_list(&format!("{at} returns"), &cmd.returns).map_err(invalid)?;
    }
    Ok(())
}

fn check_value(field: &FieldSpec, value: &Value) -> Result<(), String> {
    let actual = kind_of(value);
    if actual != field.kind {
        return Err(format!(
            "field `{}` must be `{}`, got `{}`",
            field.name,
            kind_name(field.kind),
            kind_name(actual)
        ));
    }
    if let Value::JsonVal(text) = value
        && serde_json::from_str::<serde::de::IgnoredAny>(text).is_err()
    {
        return Err(format!("field `{}` is not valid JSON", field.name));
    }
    match (&field.constraint, value) {
        (Some(FieldConstraint::OneOf(allowed)), Value::StringVal(s)) if !allowed.contains(s) => {
            Err(format!(
                "field `{}` is {s:?}; expected one of {allowed:?}",
                field.name
            ))
        }
        (Some(FieldConstraint::IntRange(r)), Value::IntVal(n))
            if r.min.is_some_and(|min| *n < min) || r.max.is_some_and(|max| *n > max) =>
        {
            Err(format!(
                "field `{}` is {n}; expected {}..={}",
                field.name,
                r.min.map_or_else(String::new, |v| v.to_string()),
                r.max.map_or_else(String::new, |v| v.to_string()),
            ))
        }
        (Some(FieldConstraint::FloatRange(r)), Value::FloatVal(x))
            if x.is_nan()
                || r.min.is_some_and(|min| *x < min)
                || r.max.is_some_and(|max| *x > max) =>
        {
            Err(format!(
                "field `{}` is {x}; expected {}..={}",
                field.name,
                r.min.map_or_else(String::new, |v| v.to_string()),
                r.max.map_or_else(String::new, |v| v.to_string()),
            ))
        }
        _ => Ok(()),
    }
}

/// Check `values` against `schema`: no duplicate or undeclared keys,
/// every required field present, every value of the declared kind
/// and inside its constraint.
fn check_fields(schema: &[FieldSpec], values: &[KeyValue]) -> Result<(), String> {
    let mut seen = HashSet::new();
    for kv in values {
        if !seen.insert(kv.key.as_str()) {
            return Err(format!("field `{}` appears more than once", kv.key));
        }
        let field = schema
            .iter()
            .find(|f| f.name == kv.key)
            .ok_or_else(|| format!("field `{}` is not declared", kv.key))?;
        check_value(field, &kv.value)?;
    }
    if let Some(missing) = schema
        .iter()
        .find(|f| f.required && !seen.contains(f.name.as_str()))
    {
        return Err(format!("required field `{}` is missing", missing.name));
    }
    Ok(())
}

/// The spec of `command` on `info`, or `invalid-argument` when the
/// service doesn't declare it.
pub(crate) fn find_command<'a>(
    info: &'a ServiceInfo,
    service: &str,
    command: &str,
) -> Result<&'a CommandSpec, WitError> {
    info.commands
        .iter()
        .find(|c| c.name == command)
        .ok_or_else(|| {
            WitError::InvalidArgument(format!(
                "service `{service}` declares no command `{command}`"
            ))
        })
}

/// Gate a `call-service`'s `args` on the command's `params` schema.
pub(crate) fn check_args(
    service: &str,
    spec: &CommandSpec,
    args: &[KeyValue],
) -> Result<(), WitError> {
    check_fields(&spec.params, args).map_err(|e| {
        WitError::InvalidArgument(format!("call-service `{}` on `{service}`: {e}", spec.name))
    })
}

/// Gate the callee's reply on the command's `returns` schema. An
/// `err` passes through untouched; a reply that breaks the schema
/// becomes `internal` (the callee broke its own contract).
pub(crate) fn check_result(
    service: &str,
    spec: &CommandSpec,
    result: CommandResult,
) -> Result<CommandResult, WitError> {
    let violation = match &result {
        CommandResult::Err(_) => None,
        CommandResult::Ok => spec
            .returns
            .iter()
            .find(|f| f.required)
            .map(|f| format!("replied `ok` without required field `{}`", f.name)),
        CommandResult::OkWithState(fields) => check_fields(&spec.returns, fields).err(),
    };
    match violation {
        None => Ok(result),
        Some(e) => Err(WitError::Internal(format!(
            "service `{service}` command `{}` broke its `returns` schema: {e}",
            spec.name
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_impl::plugin::oxidhome::plugin::services::{FloatRange, IntRange};

    const ALL_NAMED: &[Unit] = &[
        Unit::Unitless,
        Unit::Percent,
        Unit::Celsius,
        Unit::Fahrenheit,
        Unit::Kelvin,
        Unit::Lux,
        Unit::Watt,
        Unit::Kilowatt,
        Unit::WattHour,
        Unit::KilowattHour,
        Unit::Volt,
        Unit::Ampere,
        Unit::Hertz,
        Unit::Pascal,
        Unit::Hectopascal,
        Unit::Ppm,
        Unit::Ppb,
        Unit::MicrogramPerCubicMeter,
        Unit::Millimeter,
        Unit::Meter,
        Unit::MeterPerSecond,
        Unit::Liter,
        Unit::CubicMeter,
        Unit::Gram,
        Unit::Kilogram,
        Unit::Second,
        Unit::Degree,
        Unit::Decibel,
        Unit::Dbm,
    ];

    #[test]
    fn named_unit_codes_match() {
        let codes: Vec<&str> = ALL_NAMED.iter().map(unit_code).collect();
        assert_eq!(codes, NAMED_UNIT_CODES);
        assert!(!NAMED_UNIT_CODES.contains(&OTHER_UNIT_CODE));
    }

    #[test]
    fn other_unit_label_rules() {
        assert!(check_unit(&Unit::Other("steps".into())).is_ok());
        for bad in ["", "  ", "Celsius", "other", "a\nb", &"x".repeat(40)] {
            assert!(
                check_unit(&Unit::Other(bad.into())).is_err(),
                "{bad:?} should be refused"
            );
        }
    }

    fn device(caps: Vec<CapabilitySpec>, state: Vec<CapabilityState>) -> DeviceInfo {
        DeviceInfo {
            local_id: "d".into(),
            name: "d".into(),
            manufacturer: None,
            model: None,
            firmware: None,
            capabilities: caps,
            initial_state: state,
            metadata: Vec::new(),
        }
    }

    fn sensor(unit: Unit, min: Option<f64>, max: Option<f64>) -> CapabilitySpec {
        CapabilitySpec::Sensor(SensorSpec { unit, min, max })
    }

    fn reading(unit: Unit) -> CapabilityState {
        use crate::host_impl::plugin::oxidhome::plugin::capabilities::Measurement;
        CapabilityState::Sensor(Measurement { value: 1.0, unit })
    }

    #[test]
    fn device_sensor_checks() {
        check_device_info(&device(
            vec![sensor(Unit::Celsius, Some(-40.0), Some(85.0))],
            vec![reading(Unit::Celsius)],
        ))
        .unwrap();
        check_device_info(&device(
            vec![sensor(Unit::Other("steps".into()), None, None)],
            vec![reading(Unit::Other("steps".into()))],
        ))
        .unwrap();
        for bad in [
            device(vec![sensor(Unit::Celsius, Some(5.0), Some(1.0))], vec![]),
            device(vec![sensor(Unit::Celsius, Some(f64::NAN), None)], vec![]),
            device(
                vec![sensor(Unit::Celsius, None, Some(f64::INFINITY))],
                vec![],
            ),
            device(
                vec![sensor(Unit::Celsius, None, None)],
                vec![reading(Unit::Fahrenheit)],
            ),
            device(
                vec![sensor(Unit::Other("a".into()), None, None)],
                vec![reading(Unit::Other("b".into()))],
            ),
            device(vec![sensor(Unit::Other("lux".into()), None, None)], vec![]),
        ] {
            assert!(
                matches!(check_device_info(&bad), Err(WitError::InvalidArgument(_))),
                "{bad:?} should be refused"
            );
        }
    }

    #[test]
    fn sensor_fields_must_restate_the_spec_unit() {
        let info = device(vec![sensor(Unit::Celsius, None, None)], vec![]);
        let unit = |v: &str| KeyValue {
            key: "unit".into(),
            value: Value::StringVal(v.into()),
        };
        let value = KeyValue {
            key: "value".into(),
            value: Value::FloatVal(1.0),
        };
        check_sensor_fields(
            &info,
            "sensor",
            std::slice::from_ref(&value),
            SensorWrite::Delta,
        )
        .unwrap();
        assert!(
            check_sensor_fields(
                &info,
                "sensor",
                std::slice::from_ref(&value),
                SensorWrite::Snapshot
            )
            .is_err(),
            "a snapshot reply must carry the unit"
        );
        check_sensor_fields(
            &info,
            "sensor",
            &[value, unit("celsius")],
            SensorWrite::Snapshot,
        )
        .unwrap();
        assert!(
            check_sensor_fields(&info, "sensor", &[unit("fahrenheit")], SensorWrite::Delta)
                .is_err()
        );
        assert!(
            check_sensor_fields(
                &info,
                "sensor",
                &[KeyValue {
                    key: "unit_label".into(),
                    value: Value::StringVal("x".into()),
                }],
                SensorWrite::Delta,
            )
            .is_err()
        );
        // Other capabilities are not the sensor's business.
        check_sensor_fields(&info, "switch", &[unit("anything")], SensorWrite::Snapshot).unwrap();

        let other = device(
            vec![sensor(Unit::Other("steps".into()), None, None)],
            vec![],
        );
        let label = |v: &str| KeyValue {
            key: "unit_label".into(),
            value: Value::StringVal(v.into()),
        };
        check_sensor_fields(
            &other,
            "sensor",
            &[unit("other"), label("steps")],
            SensorWrite::Snapshot,
        )
        .unwrap();
        assert!(
            check_sensor_fields(&other, "sensor", &[unit("other")], SensorWrite::Snapshot).is_err(),
            "an `other` snapshot must carry its label"
        );
        assert!(
            check_sensor_fields(&other, "sensor", &[label("paces")], SensorWrite::Delta).is_err()
        );
    }

    #[test]
    fn device_extension_checks() {
        let ext = |namespace: &str, name: &str, version| {
            CapabilitySpec::Extension(ExtensionSpec {
                namespace: namespace.into(),
                name: name.into(),
                version,
            })
        };
        check_device_info(&device(vec![ext("com.acme", "window-shade", 2)], vec![])).unwrap();
        assert_eq!(
            extension_capability_key(&ExtensionSpec {
                namespace: "com.acme".into(),
                name: "window-shade".into(),
                version: 2,
            }),
            "extension(com.acme/window-shade@2)"
        );
        for bad in [
            ext("acme", "x", 1),
            ext("com.acme", "x", 0),
            ext("com.acme", "a/b", 1),
            ext("oxidhome.std", "x", 1),
        ] {
            assert!(
                matches!(
                    check_device_info(&device(vec![bad.clone()], vec![])),
                    Err(WitError::InvalidArgument(_))
                ),
                "{bad:?} should be refused"
            );
        }
    }

    fn field(name: &str, kind: ValueKind) -> FieldSpec {
        FieldSpec {
            name: name.into(),
            kind,
            required: true,
            description: None,
            constraint: None,
        }
    }

    fn with(mut f: FieldSpec, c: FieldConstraint) -> FieldSpec {
        f.constraint = Some(c);
        f
    }

    fn command(params: Vec<FieldSpec>, returns: Vec<FieldSpec>) -> CommandSpec {
        CommandSpec {
            name: "set".into(),
            description: None,
            params,
            returns,
        }
    }

    fn service(commands: Vec<CommandSpec>) -> ServiceInfo {
        ServiceInfo {
            local_id: "s".into(),
            name: "s".into(),
            metadata: Vec::new(),
            commands,
        }
    }

    #[test]
    fn service_schema_checks() {
        let good = command(
            vec![
                with(
                    field("mode", ValueKind::StringVal),
                    FieldConstraint::OneOf(vec!["home".into(), "away".into()]),
                ),
                with(
                    field("level", ValueKind::IntVal),
                    FieldConstraint::IntRange(IntRange {
                        min: Some(0),
                        max: Some(100),
                    }),
                ),
            ],
            vec![field("value", ValueKind::IntVal)],
        );
        check_service_info(&service(vec![good.clone()])).unwrap();

        let mut dup_cmd = good.clone();
        dup_cmd.params.clear();
        let mut bad_name = good.clone();
        bad_name.name = "set mode".into();
        let mut dup_field = good.clone();
        dup_field.params.push(field("mode", ValueKind::IntVal));
        let mismatched = command(
            vec![with(
                field("x", ValueKind::IntVal),
                FieldConstraint::OneOf(vec!["a".into()]),
            )],
            vec![],
        );
        let empty_one_of = command(
            vec![with(
                field("x", ValueKind::StringVal),
                FieldConstraint::OneOf(vec![]),
            )],
            vec![],
        );
        let inverted = command(
            vec![with(
                field("x", ValueKind::FloatVal),
                FieldConstraint::FloatRange(FloatRange {
                    min: Some(2.0),
                    max: Some(1.0),
                }),
            )],
            vec![],
        );
        let too_many = command(
            (0..=MAX_FIELDS_PER_SCHEMA)
                .map(|i| field(&format!("f{i}"), ValueKind::BoolVal))
                .collect(),
            vec![],
        );
        for bad in [
            service(vec![good.clone(), dup_cmd]),
            service(vec![bad_name]),
            service(vec![dup_field]),
            service(vec![mismatched]),
            service(vec![empty_one_of]),
            service(vec![inverted]),
            service(vec![too_many]),
        ] {
            assert!(
                matches!(check_service_info(&bad), Err(WitError::InvalidArgument(_))),
                "{bad:?} should be refused"
            );
        }
    }

    fn kv(key: &str, value: Value) -> KeyValue {
        KeyValue {
            key: key.into(),
            value,
        }
    }

    #[test]
    fn args_are_checked_against_params() {
        let mut optional = field("note", ValueKind::JsonVal);
        optional.required = false;
        let spec = command(
            vec![
                with(
                    field("mode", ValueKind::StringVal),
                    FieldConstraint::OneOf(vec!["home".into(), "away".into()]),
                ),
                with(
                    field("ratio", ValueKind::FloatVal),
                    FieldConstraint::FloatRange(FloatRange {
                        min: Some(0.0),
                        max: Some(1.0),
                    }),
                ),
                optional,
            ],
            vec![],
        );
        let ok = [
            kv("mode", Value::StringVal("home".into())),
            kv("ratio", Value::FloatVal(0.5)),
        ];
        check_args("svc-1", &spec, &ok).unwrap();
        let mut with_json = ok.to_vec();
        with_json.push(kv("note", Value::JsonVal("{\"a\":1}".into())));
        check_args("svc-1", &spec, &with_json).unwrap();

        let cases: Vec<Vec<KeyValue>> = vec![
            // missing required
            vec![kv("mode", Value::StringVal("home".into()))],
            // wrong kind
            vec![
                kv("mode", Value::IntVal(1)),
                kv("ratio", Value::FloatVal(0.5)),
            ],
            // outside one-of
            vec![
                kv("mode", Value::StringVal("vacation".into())),
                kv("ratio", Value::FloatVal(0.5)),
            ],
            // out of range / NaN
            vec![
                kv("mode", Value::StringVal("home".into())),
                kv("ratio", Value::FloatVal(1.5)),
            ],
            vec![
                kv("mode", Value::StringVal("home".into())),
                kv("ratio", Value::FloatVal(f64::NAN)),
            ],
            // undeclared + duplicate
            {
                let mut v = ok.to_vec();
                v.push(kv("extra", Value::BoolVal(true)));
                v
            },
            {
                let mut v = ok.to_vec();
                v.push(kv("mode", Value::StringVal("away".into())));
                v
            },
            // invalid JSON
            {
                let mut v = ok.to_vec();
                v.push(kv("note", Value::JsonVal("{".into())));
                v
            },
        ];
        for args in cases {
            assert!(
                matches!(
                    check_args("svc-1", &spec, &args),
                    Err(WitError::InvalidArgument(_))
                ),
                "{args:?} should be refused"
            );
        }
    }

    #[test]
    fn int_range_bounds_are_inclusive() {
        let spec = command(
            vec![with(
                field("n", ValueKind::IntVal),
                FieldConstraint::IntRange(IntRange {
                    min: Some(1),
                    max: Some(3),
                }),
            )],
            vec![],
        );
        for n in [1, 3] {
            check_args("svc-1", &spec, &[kv("n", Value::IntVal(n))]).unwrap();
        }
        for n in [0, 4] {
            assert!(check_args("svc-1", &spec, &[kv("n", Value::IntVal(n))]).is_err());
        }
    }

    #[test]
    fn results_are_checked_against_returns() {
        let spec = command(vec![], vec![field("value", ValueKind::IntVal)]);
        let good = CommandResult::OkWithState(vec![kv("value", Value::IntVal(1))]);
        assert!(check_result("svc-1", &spec, good).is_ok());
        let err = CommandResult::Err(WitError::NotFound("x".into()));
        assert!(matches!(
            check_result("svc-1", &spec, err),
            Ok(CommandResult::Err(_))
        ));
        for bad in [
            CommandResult::Ok,
            CommandResult::OkWithState(vec![kv("value", Value::StringVal("1".into()))]),
            CommandResult::OkWithState(vec![
                kv("value", Value::IntVal(1)),
                kv("extra", Value::IntVal(2)),
            ]),
        ] {
            assert!(
                matches!(
                    check_result("svc-1", &spec, bad),
                    Err(WitError::Internal(_))
                ),
                "reply should break the schema"
            );
        }
        // No `returns` schema: plain `ok` is the only valid success.
        let none = command(vec![], vec![]);
        assert!(check_result("svc-1", &none, CommandResult::Ok).is_ok());
        assert!(
            check_result(
                "svc-1",
                &none,
                CommandResult::OkWithState(vec![kv("v", Value::IntVal(1))])
            )
            .is_err()
        );
    }

    #[test]
    fn unknown_command_is_invalid_argument() {
        let info = service(vec![command(vec![], vec![])]);
        assert!(find_command(&info, "svc-1", "set").is_ok());
        assert!(matches!(
            find_command(&info, "svc-1", "nope"),
            Err(WitError::InvalidArgument(_))
        ));
    }
}
