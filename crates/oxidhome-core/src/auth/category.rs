//! Host-derived device categories and the sensitive categories that a
//! wildcard never covers (H6 slice 2).
//!
//! A device's [`DeviceClass`] is derived by the host from the
//! capabilities the plugin registered, never set by the plugin:
//!
//! | Capability | Category | Sensitive |
//! |------------|----------|-----------|
//! | `alarm-panel`, `siren` | `alarm` | commands |
//! | `lock` | `lock` | commands |
//! | `opener` | `opener` | commands |
//! | `video-stream` | `camera` | bytes and blobs (camera control is not) |
//! | `color-light`, or `dimmer` with `switch` | `light` | no |
//! | `audio-stream` | `media` | no |
//! | `switch` | `switch` | no |
//! | `sensor` | `sensor` | no |
//! | `dimmer` alone, `button`, any `extension(...)` | `other` | no |
//!
//! A device's category is the highest-precedence category any of its
//! capabilities implies ([`DeviceCategory::ALL`] is in precedence
//! order). Its sensitive set is every sensitive category any of them
//! implies, so a lock with a camera needs the `lock` grant to command
//! it and the `camera` grant for its bytes.
//!
//! There are no known extension ids yet, so every `extension(...)`
//! capability is `other`: a device that only has unknown extensions
//! is usable by wildcard tokens and not protected. The operator can
//! raise it (`climate` has no capability today and is reachable only
//! that way).
//!
//! The host keeps a durable floor per device id: the sensitive
//! categories it has ever derived for the device, plus the operator's
//! raise, so a plugin cannot turn a known lock into a switch by
//! re-registering it (see [`crate::state::DeviceMetaStore`]).

use std::fmt;
use std::str::FromStr;

use crate::host_impl::plugin::oxidhome::plugin::capabilities::CapabilitySpec;

/// What kind of device this is, as far as authorization is concerned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DeviceCategory {
    /// Alarm panel or siren. Sensitive.
    Alarm,
    /// Door lock. Sensitive.
    Lock,
    /// Garage door, gate, motorized door or window. Sensitive.
    Opener,
    /// Camera. Its bytes and blobs are sensitive; control is not.
    Camera,
    /// Light.
    Light,
    /// Heating, cooling, ventilation. Operator-set only today.
    Climate,
    /// Audio source or player.
    Media,
    /// Plug or relay.
    Switch,
    /// Sensor.
    Sensor,
    /// Anything else, including devices with only unknown extensions.
    Other,
}

impl DeviceCategory {
    /// Every category, highest precedence first.
    pub const ALL: [DeviceCategory; 10] = [
        DeviceCategory::Alarm,
        DeviceCategory::Lock,
        DeviceCategory::Opener,
        DeviceCategory::Camera,
        DeviceCategory::Light,
        DeviceCategory::Climate,
        DeviceCategory::Media,
        DeviceCategory::Switch,
        DeviceCategory::Sensor,
        DeviceCategory::Other,
    ];

    /// Stable lowercase name, as stored and shown on the wire.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            DeviceCategory::Alarm => "alarm",
            DeviceCategory::Lock => "lock",
            DeviceCategory::Opener => "opener",
            DeviceCategory::Camera => "camera",
            DeviceCategory::Light => "light",
            DeviceCategory::Climate => "climate",
            DeviceCategory::Media => "media",
            DeviceCategory::Switch => "switch",
            DeviceCategory::Sensor => "sensor",
            DeviceCategory::Other => "other",
        }
    }

    /// The sensitive category this category is, if it is one.
    #[must_use]
    pub const fn sensitive(self) -> Option<SensitiveCategory> {
        match self {
            DeviceCategory::Alarm => Some(SensitiveCategory::Alarm),
            DeviceCategory::Lock => Some(SensitiveCategory::Lock),
            DeviceCategory::Opener => Some(SensitiveCategory::Opener),
            DeviceCategory::Camera => Some(SensitiveCategory::Camera),
            _ => None,
        }
    }

    /// The higher-precedence of two categories.
    #[must_use]
    pub fn max(self, other: Self) -> Self {
        // `ALL` is in precedence order and the derive orders variants
        // the same way, so the smaller discriminant wins.
        std::cmp::min(self, other)
    }
}

impl fmt::Display for DeviceCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An unknown category or sensitive-category name.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown category `{0}`")]
pub struct UnknownCategory(pub String);

impl FromStr for DeviceCategory {
    type Err = UnknownCategory;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|c| c.as_str() == s)
            .ok_or_else(|| UnknownCategory(s.to_owned()))
    }
}

/// A category that a wildcard scope never covers. Only a token that
/// names it in its sensitive grants (or the owner token) reaches it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SensitiveCategory {
    /// Commands to lock devices.
    Lock,
    /// Commands to opener devices.
    Opener,
    /// Commands to alarm panels and sirens.
    Alarm,
    /// Camera bytes and blobs.
    Camera,
}

impl SensitiveCategory {
    /// Every sensitive category.
    pub const ALL: [SensitiveCategory; 4] = [
        SensitiveCategory::Lock,
        SensitiveCategory::Opener,
        SensitiveCategory::Alarm,
        SensitiveCategory::Camera,
    ];

    /// Stable lowercase name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            SensitiveCategory::Lock => "lock",
            SensitiveCategory::Opener => "opener",
            SensitiveCategory::Alarm => "alarm",
            SensitiveCategory::Camera => "camera",
        }
    }

    /// The audit label of a deny for want of this grant
    /// (`required_scope` = `sensitive:<category>`).
    #[must_use]
    pub const fn deny_label(self) -> &'static str {
        match self {
            SensitiveCategory::Lock => "sensitive:lock",
            SensitiveCategory::Opener => "sensitive:opener",
            SensitiveCategory::Alarm => "sensitive:alarm",
            SensitiveCategory::Camera => "sensitive:camera",
        }
    }

    /// The device category of the same name.
    #[must_use]
    pub const fn category(self) -> DeviceCategory {
        match self {
            SensitiveCategory::Lock => DeviceCategory::Lock,
            SensitiveCategory::Opener => DeviceCategory::Opener,
            SensitiveCategory::Alarm => DeviceCategory::Alarm,
            SensitiveCategory::Camera => DeviceCategory::Camera,
        }
    }

    /// `true` for the categories whose device *commands* are
    /// sensitive (`lock`, `opener`, `alarm`); `camera` is sensitive for
    /// its bytes only.
    #[must_use]
    pub const fn guards_commands(self) -> bool {
        !matches!(self, SensitiveCategory::Camera)
    }

    const fn bit(self) -> u8 {
        match self {
            SensitiveCategory::Lock => 1,
            SensitiveCategory::Opener => 2,
            SensitiveCategory::Alarm => 4,
            SensitiveCategory::Camera => 8,
        }
    }
}

impl fmt::Display for SensitiveCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for SensitiveCategory {
    type Err = UnknownCategory;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|c| c.as_str() == s)
            .ok_or_else(|| UnknownCategory(s.to_owned()))
    }
}

/// A set of sensitive categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct SensitiveSet(u8);

impl SensitiveSet {
    /// The empty set.
    #[must_use]
    pub const fn empty() -> Self {
        Self(0)
    }

    /// `true` when the set holds `category`.
    #[must_use]
    pub const fn contains(self, category: SensitiveCategory) -> bool {
        self.0 & category.bit() != 0
    }

    /// Add `category`.
    pub fn insert(&mut self, category: SensitiveCategory) {
        self.0 |= category.bit();
    }

    /// The union of two sets.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// `true` when every category of `self` is in `other`.
    #[must_use]
    pub const fn is_subset(self, other: Self) -> bool {
        self.0 & !other.0 == 0
    }

    /// `true` when the set is empty.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The categories in the set, in [`SensitiveCategory::ALL`] order.
    pub fn iter(self) -> impl Iterator<Item = SensitiveCategory> {
        SensitiveCategory::ALL
            .into_iter()
            .filter(move |c| self.contains(*c))
    }

    /// Comma-separated names (`lock,camera`), the stored form.
    #[must_use]
    pub fn to_csv(self) -> String {
        self.iter()
            .map(SensitiveCategory::as_str)
            .collect::<Vec<_>>()
            .join(",")
    }

    /// Parse [`Self::to_csv`]'s form. Unknown names are returned in
    /// the error so the caller can decide; an empty string is the
    /// empty set.
    ///
    /// # Errors
    ///
    /// [`UnknownCategory`] for the first name that isn't a sensitive
    /// category.
    pub fn from_csv(s: &str) -> Result<Self, UnknownCategory> {
        let mut set = Self::empty();
        for name in s.split(',').filter(|n| !n.is_empty()) {
            set.insert(name.parse()?);
        }
        Ok(set)
    }
}

impl FromIterator<SensitiveCategory> for SensitiveSet {
    fn from_iter<I: IntoIterator<Item = SensitiveCategory>>(iter: I) -> Self {
        let mut set = Self::empty();
        for c in iter {
            set.insert(c);
        }
        set
    }
}

/// The host-owned classification of one device: its display category
/// and every sensitive category it falls under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeviceClass {
    category: DeviceCategory,
    sensitive: SensitiveSet,
}

impl Default for DeviceClass {
    fn default() -> Self {
        Self::other()
    }
}

impl DeviceClass {
    /// `other`, not sensitive: an unknown or unclassified device.
    #[must_use]
    pub const fn other() -> Self {
        Self {
            category: DeviceCategory::Other,
            sensitive: SensitiveSet::empty(),
        }
    }

    /// The class of a device that is exactly `category`.
    #[must_use]
    pub fn of(category: DeviceCategory) -> Self {
        Self {
            category,
            sensitive: category.sensitive().into_iter().collect(),
        }
    }

    /// Derive the class from a device's registered capabilities.
    #[must_use]
    pub fn derive(capabilities: &[CapabilitySpec]) -> Self {
        let has = |f: fn(&CapabilitySpec) -> bool| capabilities.iter().any(f);
        let dimmable_switch = has(|c| matches!(c, CapabilitySpec::Dimmer))
            && has(|c| matches!(c, CapabilitySpec::Switch));
        let mut class = Self::other();
        if dimmable_switch {
            class = class.raised(DeviceCategory::Light);
        }
        for cap in capabilities {
            class = class.raised(capability_category(cap));
        }
        class
    }

    /// `self` with `category` added: the display category becomes the
    /// higher-precedence one and the sensitive set grows.
    #[must_use]
    pub fn raised(self, category: DeviceCategory) -> Self {
        let mut sensitive = self.sensitive;
        if let Some(s) = category.sensitive() {
            sensitive.insert(s);
        }
        Self {
            category: self.category.max(category),
            sensitive,
        }
    }

    /// `self` with every sensitive category of `set` added.
    #[must_use]
    pub fn with_sensitive(self, set: SensitiveSet) -> Self {
        set.iter().fold(self, |class, s| class.raised(s.category()))
    }

    /// Display category.
    #[must_use]
    pub const fn category(self) -> DeviceCategory {
        self.category
    }

    /// Every sensitive category the device falls under.
    #[must_use]
    pub const fn sensitive(self) -> SensitiveSet {
        self.sensitive
    }

    /// `true` when the device's bytes are camera bytes.
    #[must_use]
    pub const fn is_camera(self) -> bool {
        self.sensitive.contains(SensitiveCategory::Camera)
    }
}

/// The category one capability implies on its own. `dimmer` alone is
/// `other`; together with `switch` it is `light` (see
/// [`DeviceClass::derive`]).
fn capability_category(cap: &CapabilitySpec) -> DeviceCategory {
    match cap {
        CapabilitySpec::AlarmPanel(_) | CapabilitySpec::Siren => DeviceCategory::Alarm,
        CapabilitySpec::Lock => DeviceCategory::Lock,
        CapabilitySpec::Opener(_) => DeviceCategory::Opener,
        CapabilitySpec::VideoStream => DeviceCategory::Camera,
        CapabilitySpec::ColorLight(_) => DeviceCategory::Light,
        CapabilitySpec::AudioStream => DeviceCategory::Media,
        CapabilitySpec::Switch => DeviceCategory::Switch,
        CapabilitySpec::Sensor(_) => DeviceCategory::Sensor,
        // No extension id is known to the host yet: an unknown
        // extension is `other` and not sensitive (open question 3).
        CapabilitySpec::Dimmer | CapabilitySpec::Button | CapabilitySpec::Extension(_) => {
            DeviceCategory::Other
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_impl::plugin::oxidhome::plugin::capabilities::{
        AlarmMode, AlarmPanelSpec, ColorLightSpec, ExtensionSpec, OpenerKind, OpenerSpec,
    };

    fn ext() -> CapabilitySpec {
        CapabilitySpec::Extension(ExtensionSpec {
            namespace: "com.acme".into(),
            name: "door-thing".into(),
            version: 1,
        })
    }

    #[test]
    fn derivation_table() {
        let cases: Vec<(Vec<CapabilitySpec>, DeviceCategory, &[SensitiveCategory])> = vec![
            (
                vec![CapabilitySpec::Lock],
                DeviceCategory::Lock,
                &[SensitiveCategory::Lock],
            ),
            (
                vec![CapabilitySpec::Opener(OpenerSpec {
                    kind: OpenerKind::GarageDoor,
                    supports_position: false,
                })],
                DeviceCategory::Opener,
                &[SensitiveCategory::Opener],
            ),
            (
                vec![CapabilitySpec::AlarmPanel(AlarmPanelSpec {
                    modes: vec![AlarmMode::ArmedAway],
                    code_required: true,
                })],
                DeviceCategory::Alarm,
                &[SensitiveCategory::Alarm],
            ),
            (
                vec![CapabilitySpec::Siren],
                DeviceCategory::Alarm,
                &[SensitiveCategory::Alarm],
            ),
            (
                vec![CapabilitySpec::VideoStream, CapabilitySpec::AudioStream],
                DeviceCategory::Camera,
                &[SensitiveCategory::Camera],
            ),
            (
                vec![CapabilitySpec::Switch, CapabilitySpec::Dimmer],
                DeviceCategory::Light,
                &[],
            ),
            (vec![CapabilitySpec::Dimmer], DeviceCategory::Other, &[]),
            (
                vec![CapabilitySpec::ColorLight(ColorLightSpec {
                    supports_hsv: true,
                    supports_color_temp: false,
                    color_temp_min_kelvin: None,
                    color_temp_max_kelvin: None,
                })],
                DeviceCategory::Light,
                &[],
            ),
            (vec![CapabilitySpec::Switch], DeviceCategory::Switch, &[]),
            (
                vec![CapabilitySpec::AudioStream],
                DeviceCategory::Media,
                &[],
            ),
            (vec![CapabilitySpec::Button], DeviceCategory::Other, &[]),
            (vec![], DeviceCategory::Other, &[]),
            // A doorbell with a lock and a camera: lock wins the
            // display category, both are sensitive.
            (
                vec![
                    CapabilitySpec::Button,
                    CapabilitySpec::VideoStream,
                    CapabilitySpec::Lock,
                ],
                DeviceCategory::Lock,
                &[SensitiveCategory::Lock, SensitiveCategory::Camera],
            ),
        ];
        for (caps, category, sensitive) in cases {
            let class = DeviceClass::derive(&caps);
            assert_eq!(class.category(), category, "{caps:?}");
            assert_eq!(
                class.sensitive(),
                sensitive.iter().copied().collect::<SensitiveSet>(),
                "{caps:?}"
            );
        }
    }

    #[test]
    fn unknown_extension_only_device_is_other_and_not_sensitive() {
        let class = DeviceClass::derive(&[ext(), ext()]);
        assert_eq!(class.category(), DeviceCategory::Other);
        assert!(class.sensitive().is_empty());
        // An extension next to a lock doesn't dilute the lock.
        let class = DeviceClass::derive(&[ext(), CapabilitySpec::Lock]);
        assert_eq!(class.category(), DeviceCategory::Lock);
    }

    #[test]
    fn raising_only_adds() {
        let class = DeviceClass::of(DeviceCategory::Lock).raised(DeviceCategory::Switch);
        assert_eq!(class.category(), DeviceCategory::Lock);
        assert!(class.sensitive().contains(SensitiveCategory::Lock));
        let class = DeviceClass::of(DeviceCategory::Switch).raised(DeviceCategory::Opener);
        assert_eq!(class.category(), DeviceCategory::Opener);
    }

    #[test]
    fn names_round_trip() {
        for c in DeviceCategory::ALL {
            assert_eq!(c.as_str().parse::<DeviceCategory>(), Ok(c));
        }
        for s in SensitiveCategory::ALL {
            assert_eq!(s.as_str().parse::<SensitiveCategory>(), Ok(s));
            assert_eq!(s.category().sensitive(), Some(s));
            assert_eq!(s.deny_label(), format!("sensitive:{s}"));
        }
        assert!("door".parse::<DeviceCategory>().is_err());
        assert!("light".parse::<SensitiveCategory>().is_err());
        let set: SensitiveSet = [SensitiveCategory::Camera, SensitiveCategory::Lock]
            .into_iter()
            .collect();
        assert_eq!(set.to_csv(), "lock,camera");
        assert_eq!(SensitiveSet::from_csv("lock,camera"), Ok(set));
        assert_eq!(SensitiveSet::from_csv(""), Ok(SensitiveSet::empty()));
        assert!(SensitiveSet::from_csv("lock,door").is_err());
    }
}
