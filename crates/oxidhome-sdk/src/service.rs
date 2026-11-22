//! Strongly-typed builders for [`ServiceInfo`], [`CommandSpec`], and
//! command [`Field`] schemas (Phase 7, typed in M2).
//!
//! Plugins can construct the WIT records directly, but [`Service`]
//! offers the same fluent shape as [`Device`](crate::Device):
//!
//! ```ignore
//! use oxidhome_sdk::{CommandSpec, Field, Service, host};
//!
//! let id = host::register_service(
//!     Service::new("house-mode", "House Mode")
//!         .command(
//!             CommandSpec::new("set_mode")
//!                 .param(Field::string("mode").one_of(["occupied", "vacant"])),
//!         )
//!         .command(CommandSpec::new("current_mode").returns(Field::string("mode")))
//!         .build(),
//! )
//! .expect("register-service");
//! ```
//!
//! The schemas are a contract the host enforces: it refuses a
//! malformed schema at `register-service`, refuses a `call-service`
//! whose `args` don't match `params` before the plugin sees it, and
//! turns an `ok-with-state` reply that doesn't match `returns` into an
//! `internal` error for the caller. A plugin's
//! `execute_service_command` therefore only ever receives declared
//! commands with well-typed arguments.

use crate::bindings::oxidhome::plugin::services::{
    CommandSpec as WitCommandSpec, FieldConstraint, FieldSpec, FloatRange, IntRange, ServiceInfo,
    ValueKind,
};
use crate::bindings::oxidhome::plugin::types::KeyValue;

/// Fluent builder for [`ServiceInfo`].
///
/// Construct with [`Service::new`]; chain setters; finalize with
/// [`Service::build`] (or pass the builder straight to
/// [`host::register_service`](crate::host::register_service)).
#[derive(Debug, Clone)]
pub struct Service {
    info: ServiceInfo,
}

impl Service {
    /// Start a new service with `local_id` (the plugin-internal handle
    /// before the host returns the canonical `service-id`) and a
    /// human-readable `name`. `name` must appear in the manifest's
    /// `[capabilities] declares_services` or `register_service` is
    /// refused.
    pub fn new(local_id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            info: ServiceInfo {
                local_id: local_id.into(),
                name: name.into(),
                metadata: Vec::new(),
                commands: Vec::new(),
            },
        }
    }

    /// Append a command the service accepts.
    #[must_use]
    pub fn command(mut self, spec: CommandSpec) -> Self {
        self.info.commands.push(spec.build());
        self
    }

    /// Append a `key=value` pair to the free-form metadata bag.
    #[must_use]
    pub fn metadata(mut self, entry: KeyValue) -> Self {
        self.info.metadata.push(entry);
        self
    }

    /// Finalize the builder and return the underlying [`ServiceInfo`].
    #[must_use]
    pub fn build(self) -> ServiceInfo {
        self.info
    }

    /// Borrow the in-progress [`ServiceInfo`] without consuming.
    #[must_use]
    pub fn info(&self) -> &ServiceInfo {
        &self.info
    }
}

impl From<Service> for ServiceInfo {
    fn from(s: Service) -> Self {
        s.info
    }
}

/// Fluent builder for a service [`command-spec`](WitCommandSpec).
#[derive(Debug, Clone)]
pub struct CommandSpec {
    spec: WitCommandSpec,
}

impl CommandSpec {
    /// Start a command named `name` (the verb `execute-service-command`
    /// matches on) that takes no arguments and replies with plain
    /// `ok`. Names are 1-64 characters of `[A-Za-z0-9_-]`.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            spec: WitCommandSpec {
                name: name.into(),
                description: None,
                params: Vec::new(),
                returns: Vec::new(),
            },
        }
    }

    /// Set a human-readable description. Informational only.
    #[must_use]
    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.spec.description = Some(description.into());
        self
    }

    /// Declare an argument the command accepts.
    #[must_use]
    pub fn param(mut self, field: Field) -> Self {
        self.spec.params.push(field.build());
        self
    }

    /// Declare a field of the command's `ok-with-state` reply.
    #[must_use]
    pub fn returns(mut self, field: Field) -> Self {
        self.spec.returns.push(field.build());
        self
    }

    /// Finalize into the WIT [`command-spec`](WitCommandSpec).
    #[must_use]
    pub fn build(self) -> WitCommandSpec {
        self.spec
    }
}

/// Fluent builder for one [`field-spec`](FieldSpec) of a command's
/// `params` or `returns`. Fields are required unless marked
/// [`optional`](Field::optional).
#[derive(Debug, Clone)]
pub struct Field {
    spec: FieldSpec,
}

impl Field {
    fn new(name: impl Into<String>, kind: ValueKind) -> Self {
        Self {
            spec: FieldSpec {
                name: name.into(),
                kind,
                required: true,
                description: None,
                constraint: None,
            },
        }
    }

    /// A `bool-val` field.
    pub fn bool(name: impl Into<String>) -> Self {
        Self::new(name, ValueKind::BoolVal)
    }

    /// An `int-val` field.
    pub fn int(name: impl Into<String>) -> Self {
        Self::new(name, ValueKind::IntVal)
    }

    /// A `float-val` field.
    pub fn float(name: impl Into<String>) -> Self {
        Self::new(name, ValueKind::FloatVal)
    }

    /// A `string-val` field.
    pub fn string(name: impl Into<String>) -> Self {
        Self::new(name, ValueKind::StringVal)
    }

    /// A `bytes-val` field.
    pub fn bytes(name: impl Into<String>) -> Self {
        Self::new(name, ValueKind::BytesVal)
    }

    /// A `json-val` field. The host checks the value parses as JSON.
    pub fn json(name: impl Into<String>) -> Self {
        Self::new(name, ValueKind::JsonVal)
    }

    /// Mark the field optional.
    #[must_use]
    pub fn optional(mut self) -> Self {
        self.spec.required = false;
        self
    }

    /// Set a human-readable description. Informational only.
    #[must_use]
    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.spec.description = Some(description.into());
        self
    }

    /// Restrict a string field to these values. The host refuses the
    /// schema if the field isn't a string field.
    #[must_use]
    pub fn one_of<I, S>(mut self, values: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.spec.constraint = Some(FieldConstraint::OneOf(
            values.into_iter().map(Into::into).collect(),
        ));
        self
    }

    /// Bound an int field, inclusively; `None` leaves a side open.
    /// The host refuses the schema if the field isn't an int field.
    #[must_use]
    pub fn int_range(mut self, min: impl Into<Option<i64>>, max: impl Into<Option<i64>>) -> Self {
        self.spec.constraint = Some(FieldConstraint::IntRange(IntRange {
            min: min.into(),
            max: max.into(),
        }));
        self
    }

    /// Bound a float field, inclusively; `None` leaves a side open.
    /// A bounded float field refuses NaN. The host refuses the schema
    /// if the field isn't a float field.
    #[must_use]
    pub fn float_range(mut self, min: impl Into<Option<f64>>, max: impl Into<Option<f64>>) -> Self {
        self.spec.constraint = Some(FieldConstraint::FloatRange(FloatRange {
            min: min.into(),
            max: max.into(),
        }));
        self
    }

    /// Finalize into the WIT [`field-spec`](FieldSpec).
    #[must_use]
    pub fn build(self) -> FieldSpec {
        self.spec
    }
}

impl From<Field> for FieldSpec {
    fn from(f: Field) -> Self {
        f.spec
    }
}

impl From<CommandSpec> for WitCommandSpec {
    fn from(c: CommandSpec) -> Self {
        c.spec
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bindings::oxidhome::plugin::types::Value;

    #[test]
    fn new_starts_minimal() {
        let s = Service::new("local-1", "House Mode");
        let info = s.info();
        assert_eq!(info.local_id, "local-1");
        assert_eq!(info.name, "House Mode");
        assert!(info.metadata.is_empty());
        assert!(info.commands.is_empty());
    }

    #[test]
    fn fluent_setters_populate_fields() {
        let info = Service::new("hm", "House Mode")
            .metadata(KeyValue {
                key: "group".into(),
                value: Value::StringVal("home".into()),
            })
            .command(
                CommandSpec::new("set_mode")
                    .description("Set the house mode")
                    .param(Field::string("mode").one_of(["occupied", "vacant"])),
            )
            .command(CommandSpec::new("current_mode"))
            .build();

        assert_eq!(info.metadata.len(), 1);
        assert_eq!(info.commands.len(), 2);
        assert_eq!(info.commands[0].name, "set_mode");
        assert_eq!(
            info.commands[0].description.as_deref(),
            Some("Set the house mode")
        );
        assert_eq!(info.commands[0].params.len(), 1);
        assert!(info.commands[0].returns.is_empty());
        assert_eq!(info.commands[1].name, "current_mode");
        assert!(info.commands[1].description.is_none());
    }

    #[test]
    fn field_builders_set_kind_requiredness_and_constraint() {
        let f = Field::int("level")
            .optional()
            .description("0-100")
            .int_range(0, 100)
            .build();
        assert_eq!(f.name, "level");
        assert_eq!(f.kind, ValueKind::IntVal);
        assert!(!f.required);
        assert_eq!(f.description.as_deref(), Some("0-100"));
        assert!(matches!(
            f.constraint,
            Some(FieldConstraint::IntRange(IntRange {
                min: Some(0),
                max: Some(100)
            }))
        ));

        let f = Field::float("ratio").float_range(None, 1.0).build();
        assert!(f.required);
        assert!(matches!(
            f.constraint,
            Some(FieldConstraint::FloatRange(FloatRange { min: None, max: Some(m) })) if m.to_bits() == 1.0_f64.to_bits()
        ));

        for (field, kind) in [
            (Field::bool("b"), ValueKind::BoolVal),
            (Field::string("s"), ValueKind::StringVal),
            (Field::bytes("y"), ValueKind::BytesVal),
            (Field::json("j"), ValueKind::JsonVal),
        ] {
            assert_eq!(FieldSpec::from(field).kind, kind);
        }

        let cmd = CommandSpec::new("get").returns(Field::int("value")).build();
        assert!(cmd.params.is_empty());
        assert_eq!(cmd.returns[0].name, "value");
    }

    #[test]
    fn into_serviceinfo_consumes_builder() {
        let info: ServiceInfo = Service::new("hm", "House Mode").into();
        assert_eq!(info.name, "House Mode");
    }
}
