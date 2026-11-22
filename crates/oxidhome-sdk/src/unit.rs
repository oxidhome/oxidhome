//! Sensor-unit helpers (architecture review M2).
//!
//! The host requires every sensor `state-changed` event and
//! `ok-with-state` reply to carry the sensor's unit as fields: `unit`
//! (the unit's code, its WIT case name) plus `unit_label` for the
//! non-contractual [`Unit::Other`] fallback. [`sensor_fields`] builds
//! exactly that bag, so plugins never spell unit codes by hand.

use crate::Unit;
use crate::bindings::oxidhome::plugin::types::{KeyValue, Value};

/// Stable code of a unit: its WIT case name (`"celsius"`,
/// `"kilowatt-hour"`, ...), or `"other"` for [`Unit::Other`].
#[must_use]
pub fn unit_code(unit: &Unit) -> &'static str {
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
        Unit::Other(_) => "other",
    }
}

/// The field bag for one sensor reading in `unit`: `value`, `unit`,
/// and `unit_label` for [`Unit::Other`]. Pass it to
/// [`host::publish_state_change`](crate::host::publish_state_change)
/// with capability `"sensor"`, or return it from `execute_command` as
/// `ok-with-state`. `unit` must be the one the sensor's spec declares.
#[must_use]
pub fn sensor_fields(value: f64, unit: &Unit) -> Vec<KeyValue> {
    let mut fields = vec![
        KeyValue {
            key: "value".into(),
            value: Value::FloatVal(value),
        },
        KeyValue {
            key: "unit".into(),
            value: Value::StringVal(unit_code(unit).into()),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn named_unit_fields() {
        let fields = sensor_fields(21.5, &Unit::KilowattHour);
        assert_eq!(fields.len(), 2);
        assert!(matches!(&fields[1].value, Value::StringVal(s) if s == "kilowatt-hour"));
    }

    #[test]
    fn other_unit_carries_its_label() {
        let fields = sensor_fields(3.0, &Unit::Other("steps".into()));
        assert!(matches!(&fields[1].value, Value::StringVal(s) if s == "other"));
        assert_eq!(fields[2].key, "unit_label");
        assert!(matches!(&fields[2].value, Value::StringVal(s) if s == "steps"));
    }
}
