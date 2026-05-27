//! Strongly-typed builders for [`ServiceInfo`] and [`CommandSpec`]
//! (Phase 7).
//!
//! Plugins can construct the WIT records directly, but [`Service`]
//! offers the same fluent shape as [`Device`](crate::Device):
//!
//! ```ignore
//! use oxidhome_sdk::{Service, CommandSpec, host};
//!
//! let id = host::register_service(
//!     Service::new("house-mode", "House Mode")
//!         .command(CommandSpec::new("set_mode").arg_hint("mode: string"))
//!         .command(CommandSpec::new("current_mode"))
//!         .build(),
//! )
//! .expect("register-service");
//! ```

use crate::bindings::oxidhome::plugin::services::{CommandSpec as WitCommandSpec, ServiceInfo};
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
    /// matches on).
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            spec: WitCommandSpec {
                name: name.into(),
                description: None,
                arg_hints: Vec::new(),
            },
        }
    }

    /// Set a human-readable description.
    #[must_use]
    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.spec.description = Some(description.into());
        self
    }

    /// Append a free-form argument hint (e.g. `"mode: string"`).
    #[must_use]
    pub fn arg_hint(mut self, hint: impl Into<String>) -> Self {
        self.spec.arg_hints.push(hint.into());
        self
    }

    /// Finalize into the WIT [`command-spec`](WitCommandSpec).
    #[must_use]
    pub fn build(self) -> WitCommandSpec {
        self.spec
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
                    .arg_hint("mode: string — occupied/vacant"),
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
        assert_eq!(info.commands[0].arg_hints.len(), 1);
        assert_eq!(info.commands[1].name, "current_mode");
        assert!(info.commands[1].description.is_none());
    }

    #[test]
    fn into_serviceinfo_consumes_builder() {
        let info: ServiceInfo = Service::new("hm", "House Mode").into();
        assert_eq!(info.name, "House Mode");
    }
}
