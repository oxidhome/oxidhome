//! SDK version compatibility — the host's preflight that a plugin's
//! declared `sdk_version` is accepted by this build.
//!
//! Policy, mirroring the cross-cutting decision in ARCHITECTURE.md /
//! the per-crate plan:
//!
//! 1. `plugin_sdk >= min_supported`. Older plugins are refused.
//! 2. **Until 1.0:** `plugin_sdk` must be in the same `0.x` line as
//!    `core_sdk` (same minor when major is `0`). 0.x is "anything can
//!    break" by convention; we treat each minor as its own ABI.
//! 3. **Post-1.0:** standard semver — same major as `core_sdk`.
//!
//! The CLI uses this for `oxidhome plugin install` preflight; the
//! core loader uses it on every load.

use semver::Version;
use thiserror::Error;

/// One reason a plugin's declared `sdk_version` is unacceptable.
///
/// Error messages name all three versions so the operator can adjust
/// either the plugin or the host without guessing.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CompatError {
    #[error(
        "plugin sdk_version {plugin} is below the host's minimum supported version {min_supported} \
         (host currently ships SDK {core})"
    )]
    BelowMinimum {
        plugin: Version,
        core: Version,
        min_supported: Version,
    },
    #[error(
        "plugin sdk_version {plugin} is incompatible with the host's SDK {core}: \
         pre-1.0 requires matching `0.x` minor, post-1.0 requires matching major"
    )]
    AbiMismatch { plugin: Version, core: Version },
}

/// Run the compatibility preflight.
///
/// # Errors
///
/// Returns the first reason `plugin_sdk` is unacceptable. The check
/// stops at the first hit because the two reasons are mutually
/// exclusive (a version below the minimum is below it; an ABI
/// mismatch implies a different minor / major).
pub fn check(
    plugin_sdk: &Version,
    core_sdk: &Version,
    min_supported: &Version,
) -> Result<(), CompatError> {
    if plugin_sdk < min_supported {
        return Err(CompatError::BelowMinimum {
            plugin: plugin_sdk.clone(),
            core: core_sdk.clone(),
            min_supported: min_supported.clone(),
        });
    }

    let abi_match = if core_sdk.major == 0 {
        // Pre-1.0: each minor is its own ABI line.
        plugin_sdk.major == 0 && plugin_sdk.minor == core_sdk.minor
    } else {
        // Post-1.0: standard semver — same major is compatible.
        plugin_sdk.major == core_sdk.major
    };

    if !abi_match {
        return Err(CompatError::AbiMismatch {
            plugin: plugin_sdk.clone(),
            core: core_sdk.clone(),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Version {
        s.parse().unwrap()
    }

    #[test]
    fn matching_pre_1_0_passes() {
        check(&v("0.1.0"), &v("0.1.5"), &v("0.1.0")).unwrap();
        check(&v("0.1.3"), &v("0.1.5"), &v("0.1.0")).unwrap();
    }

    #[test]
    fn matching_post_1_0_passes() {
        check(&v("1.2.0"), &v("1.5.0"), &v("1.0.0")).unwrap();
        check(&v("2.0.0"), &v("2.7.3"), &v("2.0.0")).unwrap();
    }

    #[test]
    fn below_minimum_pre_1_0_rejected() {
        let err = check(&v("0.1.0"), &v("0.2.0"), &v("0.2.0")).unwrap_err();
        assert!(matches!(err, CompatError::BelowMinimum { .. }));
    }

    #[test]
    fn below_minimum_post_1_0_rejected() {
        let err = check(&v("1.0.5"), &v("1.2.0"), &v("1.2.0")).unwrap_err();
        assert!(matches!(err, CompatError::BelowMinimum { .. }));
    }

    #[test]
    fn cross_minor_pre_1_0_rejected() {
        let err = check(&v("0.2.0"), &v("0.1.0"), &v("0.0.0")).unwrap_err();
        assert!(matches!(err, CompatError::AbiMismatch { .. }));
    }

    #[test]
    fn cross_major_post_1_0_rejected() {
        let err = check(&v("2.0.0"), &v("1.0.0"), &v("1.0.0")).unwrap_err();
        assert!(matches!(err, CompatError::AbiMismatch { .. }));
    }

    #[test]
    fn pre_to_post_1_0_rejected_either_way() {
        let err = check(&v("1.0.0"), &v("0.1.0"), &v("0.0.0")).unwrap_err();
        assert!(matches!(err, CompatError::AbiMismatch { .. }));
        let err = check(&v("0.1.0"), &v("1.0.0"), &v("0.0.0")).unwrap_err();
        assert!(matches!(err, CompatError::AbiMismatch { .. }));
    }

    #[test]
    fn error_message_names_all_three_versions() {
        let err = check(&v("0.1.0"), &v("0.3.0"), &v("0.2.0")).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("0.1.0"), "plugin: {msg}");
        assert!(msg.contains("0.2.0"), "min_supported: {msg}");
        assert!(msg.contains("0.3.0"), "core: {msg}");
    }
}
