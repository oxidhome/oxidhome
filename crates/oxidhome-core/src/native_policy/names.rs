//! Grammar for the logical names plugins pass to native media and
//! inference: sink names, recording profiles, model names, and model
//! versions.
//!
//! None of these is ever a filesystem path. The host maps a sink name into
//! the plugin instance's own namespace (`<plugin-id>/<instance-id>/<name>`)
//! and looks profiles and models up in host-owned registries. The grammar
//! is still strict — no `/`, no `..`, no whitespace — so a later bug that
//! does join one onto a path can't escape its directory.

/// Longest sink name, recording profile, or model name.
pub const MAX_LOGICAL_NAME_LEN: usize = 64;
/// Longest model version string.
pub const MAX_MODEL_VERSION_LEN: usize = 32;

/// Which kind of name failed, for the error message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameKind {
    SinkName,
    RecordingProfile,
    ModelName,
    ModelVersion,
}

impl std::fmt::Display for NameKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::SinkName => "sink name",
            Self::RecordingProfile => "recording profile",
            Self::ModelName => "model name",
            Self::ModelVersion => "model version",
        })
    }
}

/// Why a name was rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NameError {
    #[error("{0} is empty")]
    Empty(NameKind),
    #[error("{kind} is longer than {max} bytes")]
    TooLong { kind: NameKind, max: usize },
    #[error("{0} must start with an ASCII letter or digit")]
    BadStart(NameKind),
    #[error("{0} contains a character outside its allowed set")]
    InvalidChar(NameKind),
    #[error("{0} must not contain '..'")]
    DotDot(NameKind),
}

/// `output-sink` name for `rtsp` / `hls`: 1–64 bytes of `[a-z0-9_-]`,
/// starting with a letter or digit.
pub fn validate_sink_name(name: &str) -> Result<(), NameError> {
    validate_logical(name, NameKind::SinkName)
}

/// `output-sink::record-to-storage` profile name. Same grammar as
/// [`validate_sink_name`].
pub fn validate_recording_profile(name: &str) -> Result<(), NameError> {
    validate_logical(name, NameKind::RecordingProfile)
}

/// Model registry name (`load-model`, `inference-tap-config.model`). Same
/// grammar as [`validate_sink_name`].
pub fn validate_model_name(name: &str) -> Result<(), NameError> {
    validate_logical(name, NameKind::ModelName)
}

/// Model version pin: 1–32 bytes of `[A-Za-z0-9.+-]`, starting with a
/// letter or digit, never containing `..`.
pub fn validate_model_version(version: &str) -> Result<(), NameError> {
    let kind = NameKind::ModelVersion;
    check_shape(version, kind, MAX_MODEL_VERSION_LEN)?;
    if !version
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'+' | b'-'))
    {
        return Err(NameError::InvalidChar(kind));
    }
    if version.contains("..") {
        return Err(NameError::DotDot(kind));
    }
    Ok(())
}

fn validate_logical(name: &str, kind: NameKind) -> Result<(), NameError> {
    check_shape(name, kind, MAX_LOGICAL_NAME_LEN)?;
    if !name
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_'))
    {
        return Err(NameError::InvalidChar(kind));
    }
    Ok(())
}

/// Length bounds and first-character rule shared by every name kind.
fn check_shape(name: &str, kind: NameKind, max: usize) -> Result<(), NameError> {
    let Some(first) = name.bytes().next() else {
        return Err(NameError::Empty(kind));
    };
    if name.len() > max {
        return Err(NameError::TooLong { kind, max });
    }
    if !first.is_ascii_alphanumeric() {
        return Err(NameError::BadStart(kind));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_logical_names() {
        for name in [
            "main",
            "sub-stream",
            "cam_1",
            "0",
            &"a".repeat(MAX_LOGICAL_NAME_LEN),
        ] {
            assert_eq!(validate_sink_name(name), Ok(()), "{name}");
            assert_eq!(validate_recording_profile(name), Ok(()), "{name}");
            assert_eq!(validate_model_name(name), Ok(()), "{name}");
        }
    }

    #[test]
    fn rejects_paths_and_odd_names() {
        let kind = NameKind::SinkName;
        assert_eq!(validate_sink_name(""), Err(NameError::Empty(kind)));
        assert_eq!(
            validate_sink_name(&"a".repeat(MAX_LOGICAL_NAME_LEN + 1)),
            Err(NameError::TooLong {
                kind,
                max: MAX_LOGICAL_NAME_LEN
            })
        );
        for name in ["-x", "_x", "/etc", ".hidden", ".."] {
            assert_eq!(
                validate_sink_name(name),
                Err(NameError::BadStart(kind)),
                "{name}"
            );
        }
        for name in [
            "a/b",
            "a..b",
            "a.b",
            "Main",
            "a b",
            "a\\b",
            "caf\u{e9}",
            "a\0",
        ] {
            assert_eq!(
                validate_sink_name(name),
                Err(NameError::InvalidChar(kind)),
                "{name:?}"
            );
        }
        assert_eq!(
            validate_model_name("../yolo"),
            Err(NameError::BadStart(NameKind::ModelName))
        );
        assert_eq!(
            validate_recording_profile("x/../../etc"),
            Err(NameError::InvalidChar(NameKind::RecordingProfile))
        );
    }

    #[test]
    fn model_versions() {
        for v in ["1", "1.2.3", "2024-06-01", "1.0.0-rc.1+build.5", "v8n"] {
            assert_eq!(validate_model_version(v), Ok(()), "{v}");
        }
        let kind = NameKind::ModelVersion;
        assert_eq!(validate_model_version(""), Err(NameError::Empty(kind)));
        assert_eq!(validate_model_version(".1"), Err(NameError::BadStart(kind)));
        assert_eq!(validate_model_version("1..2"), Err(NameError::DotDot(kind)));
        assert_eq!(
            validate_model_version("1/2"),
            Err(NameError::InvalidChar(kind))
        );
        assert_eq!(
            validate_model_version("1 2"),
            Err(NameError::InvalidChar(kind))
        );
        assert_eq!(
            validate_model_version(&"1".repeat(MAX_MODEL_VERSION_LEN + 1)),
            Err(NameError::TooLong {
                kind,
                max: MAX_MODEL_VERSION_LEN
            })
        );
    }
}
