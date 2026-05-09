//! Strongly-typed builder for [`DeviceInfo`].
//!
//! Plugins can construct [`bindings::oxidhome::plugin::devices::DeviceInfo`]
//! directly, but the WIT record has eight fields and uses
//! `Vec<…>` lists where most plugins want to push items one at a
//! time. [`Device`] wraps the record and exposes a fluent API:
//!
//! ```ignore
//! use oxidhome_sdk::{Device, host};
//! use oxidhome_sdk::bindings::oxidhome::plugin::capabilities::{
//!     CapabilitySpec, CapabilityState, Switchable,
//! };
//!
//! let id = host::register_device(
//!     Device::new("kitchen-light", "Kitchen Light")
//!         .manufacturer("Acme")
//!         .model("Switch-1")
//!         .capability(CapabilitySpec::Switch)
//!         .initial_state(CapabilityState::Switch(Switchable { state: false }))
//!         .build(),
//! )
//! .expect("register-device");
//! ```

use crate::bindings::oxidhome::plugin::capabilities::{CapabilitySpec, CapabilityState};
use crate::bindings::oxidhome::plugin::devices::DeviceInfo;
use crate::bindings::oxidhome::plugin::types::KeyValue;

/// Fluent builder for [`DeviceInfo`].
///
/// Construct with [`Device::new`]; chain setters; finalize with
/// [`Device::build`] (or pass directly to
/// [`host::register_device`](crate::host::register_device), which
/// accepts the builder).
#[derive(Debug, Clone)]
pub struct Device {
    info: DeviceInfo,
}

impl Device {
    /// Start a new device with `local_id` (the plugin-internal handle
    /// the plugin uses to refer to it before the host returns the
    /// canonical `device-id`) and a human-readable `name`.
    pub fn new(local_id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            info: DeviceInfo {
                local_id: local_id.into(),
                name: name.into(),
                manufacturer: None,
                model: None,
                firmware: None,
                capabilities: Vec::new(),
                initial_state: Vec::new(),
                metadata: Vec::new(),
            },
        }
    }

    #[must_use]
    pub fn manufacturer(mut self, manufacturer: impl Into<String>) -> Self {
        self.info.manufacturer = Some(manufacturer.into());
        self
    }

    #[must_use]
    pub fn model(mut self, model: impl Into<String>) -> Self {
        self.info.model = Some(model.into());
        self
    }

    #[must_use]
    pub fn firmware(mut self, firmware: impl Into<String>) -> Self {
        self.info.firmware = Some(firmware.into());
        self
    }

    /// Append a capability the device supports.
    #[must_use]
    pub fn capability(mut self, spec: CapabilitySpec) -> Self {
        self.info.capabilities.push(spec);
        self
    }

    /// Append an initial-state snapshot for one stateful capability.
    /// The host treats `initial_state` as a hint, not a requirement —
    /// devices that can't report state at registration time can leave
    /// it empty and let the first `state-changed` event populate the
    /// view.
    #[must_use]
    pub fn initial_state(mut self, state: CapabilityState) -> Self {
        self.info.initial_state.push(state);
        self
    }

    /// Append a `key=value` pair to the free-form metadata bag.
    #[must_use]
    pub fn metadata(mut self, entry: KeyValue) -> Self {
        self.info.metadata.push(entry);
        self
    }

    /// Finalize the builder and return the underlying [`DeviceInfo`].
    /// Most callers don't need this — pass the [`Device`] directly to
    /// [`host::register_device`](crate::host::register_device).
    #[must_use]
    pub fn build(self) -> DeviceInfo {
        self.info
    }

    /// Borrow the in-progress [`DeviceInfo`] for inspection without
    /// consuming the builder.
    #[must_use]
    pub fn info(&self) -> &DeviceInfo {
        &self.info
    }
}

impl From<Device> for DeviceInfo {
    fn from(d: Device) -> Self {
        d.info
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bindings::oxidhome::plugin::capabilities::{
        CapabilityState, ColorLightSpec, SensorSpec, Switchable,
    };
    use crate::bindings::oxidhome::plugin::types::Value;

    #[test]
    fn new_starts_with_minimal_info() {
        let d = Device::new("local-1", "Living Room");
        let info = d.info();
        assert_eq!(info.local_id, "local-1");
        assert_eq!(info.name, "Living Room");
        assert!(info.manufacturer.is_none());
        assert!(info.model.is_none());
        assert!(info.firmware.is_none());
        assert!(info.capabilities.is_empty());
        assert!(info.initial_state.is_empty());
        assert!(info.metadata.is_empty());
    }

    #[test]
    fn fluent_setters_populate_each_field() {
        let info = Device::new("d-1", "Light")
            .manufacturer("Acme")
            .model("X-1")
            .firmware("1.0.0")
            .capability(CapabilitySpec::Switch)
            .capability(CapabilitySpec::ColorLight(ColorLightSpec {
                supports_hsv: true,
                supports_color_temp: false,
                color_temp_min_kelvin: None,
                color_temp_max_kelvin: None,
            }))
            .initial_state(CapabilityState::Switch(Switchable { state: false }))
            .metadata(KeyValue {
                key: "room".into(),
                value: Value::StringVal("living".into()),
            })
            .build();

        assert_eq!(info.manufacturer.as_deref(), Some("Acme"));
        assert_eq!(info.model.as_deref(), Some("X-1"));
        assert_eq!(info.firmware.as_deref(), Some("1.0.0"));
        assert_eq!(info.capabilities.len(), 2);
        assert!(matches!(info.capabilities[0], CapabilitySpec::Switch));
        assert!(matches!(
            info.capabilities[1],
            CapabilitySpec::ColorLight(_)
        ));
        assert_eq!(info.initial_state.len(), 1);
        assert!(matches!(
            info.initial_state[0],
            CapabilityState::Switch(Switchable { state: false })
        ));
        assert_eq!(info.metadata.len(), 1);
        assert_eq!(info.metadata[0].key, "room");
    }

    #[test]
    fn capabilities_and_initial_state_append_in_order() {
        let info = Device::new("d-1", "Sensor")
            .capability(CapabilitySpec::Sensor(SensorSpec {
                unit: "celsius".into(),
                min: Some(-40.0),
                max: Some(125.0),
            }))
            .capability(CapabilitySpec::Button)
            .build();
        assert!(matches!(info.capabilities[0], CapabilitySpec::Sensor(_)));
        assert!(matches!(info.capabilities[1], CapabilitySpec::Button));
    }

    #[test]
    fn into_deviceinfo_consumes_builder() {
        let d = Device::new("d-1", "Switch").manufacturer("Acme");
        let info: DeviceInfo = d.into();
        assert_eq!(info.manufacturer.as_deref(), Some("Acme"));
    }
}
