//! Namespaced, versioned extension capability ids (architecture
//! review M2).
//!
//! A plugin-defined capability is identified by a reverse-DNS
//! `namespace`, a `name`, and a major schema `version`, mirroring the
//! WIT `capabilities.extension-spec` record. Manifests and the host's
//! state projection spell the same identity as one capability key,
//! `extension(<namespace>/<name>@<version>)`, e.g.
//! `extension(com.acme/window-shade@1)`.
//!
//! The host validates the WIT record with [`ExtensionId::new`] at
//! `register-device`; the manifest validator parses
//! `declares_devices` entries with [`ExtensionId::parse_capability`].
//! Both go through the same rules, so a key the manifest accepts is
//! exactly one the host can produce.

use std::fmt;

use thiserror::Error;

/// Longest accepted `namespace` + `/` + `name`, in bytes.
pub const MAX_EXTENSION_ID_LEN: usize = 128;

/// Namespaces whose first label is this are reserved for capabilities
/// the host itself defines.
pub const RESERVED_NAMESPACE_LABEL: &str = "oxidhome";

/// A validated extension capability identity.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ExtensionId {
    namespace: String,
    name: String,
    version: u32,
}

/// Why an extension identity is malformed.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ExtensionIdError {
    #[error(
        "namespace `{0}` is not reverse-DNS (two or more dot-separated labels of \
         `[a-z0-9][a-z0-9-]*`, e.g. `com.acme`)"
    )]
    InvalidNamespace(String),
    #[error("namespace `{0}` is reserved for the host (first label `oxidhome`)")]
    ReservedNamespace(String),
    #[error("name `{0}` is not a single `[a-z0-9][a-z0-9-]*` label")]
    InvalidName(String),
    #[error("schema version must be 1 or greater (got 0)")]
    ZeroVersion,
    #[error("`<namespace>/<name>` is {len} bytes; the cap is {MAX_EXTENSION_ID_LEN}")]
    TooLong { len: usize },
    #[error(
        "`{0}` is not `extension(<namespace>/<name>@<version>)`, \
         e.g. `extension(com.acme/window-shade@1)`"
    )]
    Malformed(String),
}

impl ExtensionId {
    /// Validate the three parts of an identity.
    ///
    /// # Errors
    ///
    /// The first rule the parts break.
    pub fn new(
        namespace: impl Into<String>,
        name: impl Into<String>,
        version: u32,
    ) -> Result<Self, ExtensionIdError> {
        let namespace = namespace.into();
        let name = name.into();
        let len = namespace.len() + 1 + name.len();
        if len > MAX_EXTENSION_ID_LEN {
            return Err(ExtensionIdError::TooLong { len });
        }
        let labels: Vec<&str> = namespace.split('.').collect();
        if labels.len() < 2 || !labels.iter().all(|l| is_label(l)) {
            return Err(ExtensionIdError::InvalidNamespace(namespace));
        }
        if labels[0] == RESERVED_NAMESPACE_LABEL {
            return Err(ExtensionIdError::ReservedNamespace(namespace));
        }
        if !is_label(&name) {
            return Err(ExtensionIdError::InvalidName(name));
        }
        if version == 0 {
            return Err(ExtensionIdError::ZeroVersion);
        }
        Ok(Self {
            namespace,
            name,
            version,
        })
    }

    /// Parse a capability key of the form
    /// `extension(<namespace>/<name>@<version>)`.
    ///
    /// Returns `None` when `key` doesn't start with `extension(` at
    /// all (it names some other capability), `Some(Err(_))` when it
    /// does but is malformed.
    #[must_use]
    pub fn parse_capability(key: &str) -> Option<Result<Self, ExtensionIdError>> {
        let rest = key.strip_prefix("extension(")?;
        let malformed = || ExtensionIdError::Malformed(key.to_owned());
        let parsed = (|| {
            let body = rest.strip_suffix(')').ok_or_else(malformed)?;
            let (id, version) = body.rsplit_once('@').ok_or_else(malformed)?;
            let (namespace, name) = id.split_once('/').ok_or_else(malformed)?;
            // `u32::from_str` accepts a leading `+`; the key form is
            // canonical, so only plain digits without leading zeros.
            if version.is_empty()
                || !version.bytes().all(|b| b.is_ascii_digit())
                || (version.len() > 1 && version.starts_with('0'))
            {
                return Err(malformed());
            }
            let version: u32 = version.parse().map_err(|_| malformed())?;
            Self::new(namespace, name, version)
        })();
        Some(parsed)
    }

    /// Reverse-DNS namespace, e.g. `com.acme`.
    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// Name within the namespace, e.g. `window-shade`.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Major schema version.
    #[must_use]
    pub fn version(&self) -> u32 {
        self.version
    }

    /// The capability key, `extension(<namespace>/<name>@<version>)`.
    #[must_use]
    pub fn capability_key(&self) -> String {
        self.to_string()
    }
}

impl fmt::Display for ExtensionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "extension({}/{}@{})",
            self.namespace, self.name, self.version
        )
    }
}

/// `[a-z0-9][a-z0-9-]*`.
pub(crate) fn is_label(label: &str) -> bool {
    let mut chars = label.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first.is_ascii_lowercase() || first.is_ascii_digit())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_id_round_trips_through_its_key() {
        let id = ExtensionId::new("com.acme", "window-shade", 1).unwrap();
        assert_eq!(id.capability_key(), "extension(com.acme/window-shade@1)");
        let parsed = ExtensionId::parse_capability(&id.capability_key())
            .unwrap()
            .unwrap();
        assert_eq!(parsed, id);
        assert_eq!(parsed.namespace(), "com.acme");
        assert_eq!(parsed.name(), "window-shade");
        assert_eq!(parsed.version(), 1);
    }

    #[test]
    fn non_extension_keys_are_not_parsed() {
        assert!(ExtensionId::parse_capability("switch").is_none());
    }

    #[test]
    fn rejects_bad_parts() {
        assert!(matches!(
            ExtensionId::new("acme", "x", 1),
            Err(ExtensionIdError::InvalidNamespace(_))
        ));
        assert!(matches!(
            ExtensionId::new("Com.Acme", "x", 1),
            Err(ExtensionIdError::InvalidNamespace(_))
        ));
        assert!(matches!(
            ExtensionId::new("com..acme", "x", 1),
            Err(ExtensionIdError::InvalidNamespace(_))
        ));
        assert!(matches!(
            ExtensionId::new("oxidhome.core", "x", 1),
            Err(ExtensionIdError::ReservedNamespace(_))
        ));
        assert!(matches!(
            ExtensionId::new("com.acme", "a/b", 1),
            Err(ExtensionIdError::InvalidName(_))
        ));
        assert!(matches!(
            ExtensionId::new("com.acme", "", 1),
            Err(ExtensionIdError::InvalidName(_))
        ));
        assert!(matches!(
            ExtensionId::new("com.acme", "x", 0),
            Err(ExtensionIdError::ZeroVersion)
        ));
        assert!(matches!(
            ExtensionId::new("com.acme", "x".repeat(200), 1),
            Err(ExtensionIdError::TooLong { .. })
        ));
    }

    #[test]
    fn rejects_malformed_keys() {
        for bad in [
            "extension(window-shade)",
            "extension(com.acme/window-shade)",
            "extension(com.acme/window-shade@)",
            "extension(com.acme/window-shade@+1)",
            "extension(com.acme/window-shade@01)",
            "extension(com.acme/window-shade@1",
            "extension(com.acme/window-shade@99999999999)",
            "extension()",
        ] {
            assert!(
                matches!(ExtensionId::parse_capability(bad), Some(Err(_))),
                "{bad} should be refused"
            );
        }
    }
}
