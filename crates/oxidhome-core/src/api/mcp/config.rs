//! The daemon's effective configuration, served read-only as the MCP
//! `oxidhome://config` resource and `GET /api/v1/config`.
//!
//! This is the *host* configuration: where state lives, what address
//! the API listens on, retention, the stdout log filter and
//! the MCP mount's compiled-in limits, plus the build and plugin
//! contract versions. Per-instance plugin config is a different thing
//! and stays on `oxidhome://plugins/{id}` (masked, M7).
//!
//! Every setting carries the [`ConfigSource`] it came from (`default`,
//! `env` or `flag`) and, when an environment variable can override it,
//! that variable's name. The daemon has no config file.
//!
//! The binary resolves its settings once at startup and hands the
//! result to [`install_daemon_config`]. The snapshot is process-wide
//! on purpose: env vars and argv are process-level, and the exclusive
//! state-dir lock already limits a process to one daemon. A process
//! that never installs one (an embedded [`crate::Engine`], tests)
//! serves `"daemon": null` with the build and limit sections intact.
//!
//! The body holds no secrets by construction (the admin token lives in
//! a file whose *path* is derivable from `state_dir`, never its
//! content). It still goes through [`crate::redact::redact_json`] on
//! both surfaces, so a credential-looking value in, say, a directory
//! name is masked like anywhere else.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::OnceLock;
use std::time::Duration;

use serde::Serialize;

use crate::state::{
    AUDIT_RETENTION_ENV, EVENT_LOG_RETENTION_ENV, LOG_RETENTION_ENV, RetentionConfig, RetentionEnv,
    RetentionPolicy,
};

/// Environment variable naming the state directory.
pub const ENV_STATE_DIR: &str = "OXIDHOME_STATE_DIR";

/// Environment variable naming the API listen address.
pub const ENV_BIND: &str = "OXIDHOME_BIND";

/// Environment variable holding the stdout log filter.
pub const ENV_LOG_FILTER: &str = "RUST_LOG";

/// Stdout log filter used when [`ENV_LOG_FILTER`] is unset or invalid.
pub const DEFAULT_LOG_FILTER: &str = "info";

/// Where a setting's value came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigSource {
    /// The built-in default.
    Default,
    /// An environment variable.
    Env,
    /// A command-line argument.
    Flag,
}

/// One setting: its effective value and where it came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Setting<T> {
    /// The value the daemon is using.
    pub value: T,
    /// Where `value` came from.
    pub source: ConfigSource,
    /// The environment variable that overrides this setting, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env: Option<&'static str>,
}

impl<T> Setting<T> {
    /// A compiled-in value no variable or flag can change.
    fn fixed(value: T) -> Self {
        Self {
            value,
            source: ConfigSource::Default,
            env: None,
        }
    }

    /// A value `env` can override: [`ConfigSource::Env`] when the
    /// variable is set, else [`ConfigSource::Default`]. The daemon
    /// refuses to start on a set-but-invalid value, so "set" means
    /// "applied".
    fn from_env(value: T, env: &'static str) -> Self {
        let source = if std::env::var_os(env).is_some() {
            ConfigSource::Env
        } else {
            ConfigSource::Default
        };
        Self {
            value,
            source,
            env: Some(env),
        }
    }
}

/// How the daemon process is serving.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DaemonMode {
    /// The HTTP daemon (REST, Connect, MCP over streamable HTTP).
    Http,
    /// `oxidhome mcp-stdio`: MCP over stdin/stdout, no listener.
    McpStdio,
}

/// One table's retention, as applied by its retention task.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct RetentionView {
    /// Maximum event age in days; `null` = no age limit.
    max_age_days: Setting<Option<u64>>,
    /// Maximum rows kept; `null` = no row limit.
    max_rows: Setting<Option<u64>>,
    /// Seconds between passes.
    interval_secs: Setting<u64>,
    /// Seconds before the first pass.
    first_delay_secs: Setting<u64>,
}

impl RetentionView {
    fn new(retention: &RetentionPolicy, env: &RetentionEnv) -> Self {
        Self {
            max_age_days: Setting::from_env(
                retention.max_age.map(|age| age.as_secs() / 86_400),
                env.days_var,
            ),
            max_rows: Setting::from_env(retention.max_rows, env.rows_var),
            interval_secs: Setting::fixed(retention.interval.as_secs()),
            first_delay_secs: Setting::fixed(retention.first_delay.as_secs()),
        }
    }
}

/// The settings the binary resolved at startup. Build with
/// [`DaemonConfig::resolve`], add the listener with
/// [`DaemonConfig::with_listener`], then [`install_daemon_config`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DaemonConfig {
    mode: DaemonMode,
    /// Lossy UTF-8: the daemon accepts any OS path, JSON can't carry
    /// every one.
    state_dir: Setting<String>,
    /// Configured listen address. HTTP mode only.
    #[serde(skip_serializing_if = "Option::is_none")]
    bind: Option<Setting<SocketAddr>>,
    /// Address actually bound (differs from `bind` for port `0`).
    #[serde(skip_serializing_if = "Option::is_none")]
    listen_addr: Option<SocketAddr>,
    /// Plugin directory passed on argv (dev-time start).
    #[serde(skip_serializing_if = "Option::is_none")]
    dev_plugin_dir: Option<Setting<String>>,
    log_filter: Setting<String>,
    event_log_retention: RetentionView,
    /// Diagnostic-log (`log_event`) retention.
    log_retention: RetentionView,
    /// Audit-ledger (`audit_event`) retention.
    audit_retention: RetentionView,
}

impl DaemonConfig {
    /// Snapshot the settings the daemon resolved: `state_dir` and
    /// `retention` are the values it is using. Sources are read from
    /// the environment, so call this from the process that resolved
    /// them.
    #[must_use]
    pub fn resolve(mode: DaemonMode, state_dir: &Path, retention: &RetentionConfig) -> Self {
        Self {
            mode,
            state_dir: Setting::from_env(lossy(state_dir), ENV_STATE_DIR),
            bind: None,
            listen_addr: None,
            dev_plugin_dir: None,
            log_filter: effective_log_filter(),
            event_log_retention: RetentionView::new(&retention.event_log, &EVENT_LOG_RETENTION_ENV),
            log_retention: RetentionView::new(&retention.logs, &LOG_RETENTION_ENV),
            audit_retention: RetentionView::new(&retention.audit, &AUDIT_RETENTION_ENV),
        }
    }

    /// Record the configured and the bound API address.
    #[must_use]
    pub fn with_listener(mut self, configured: SocketAddr, bound: SocketAddr) -> Self {
        // `main.rs` reads the variable with `env::var`, so a
        // non-Unicode value falls back to the default there.
        let source = if std::env::var(ENV_BIND).is_ok() {
            ConfigSource::Env
        } else {
            ConfigSource::Default
        };
        self.bind = Some(Setting {
            value: configured,
            source,
            env: Some(ENV_BIND),
        });
        self.listen_addr = Some(bound);
        self
    }

    /// Record the plugin directory passed on argv.
    #[must_use]
    pub fn with_dev_plugin_dir(mut self, dir: &Path) -> Self {
        self.dev_plugin_dir = Some(Setting {
            value: lossy(dir),
            source: ConfigSource::Flag,
            env: None,
        });
        self
    }
}

fn lossy(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// The filter `main.rs` hands `EnvFilter`: `RUST_LOG` when it parses,
/// else [`DEFAULT_LOG_FILTER`] (an invalid value falls back silently,
/// so it reports as the default).
fn effective_log_filter() -> Setting<String> {
    let from_env = std::env::var(ENV_LOG_FILTER)
        .ok()
        .filter(|raw| tracing_subscriber::EnvFilter::try_new(raw).is_ok());
    match from_env {
        Some(raw) => Setting {
            value: mask_span_fields(&raw),
            source: ConfigSource::Env,
            env: Some(ENV_LOG_FILTER),
        },
        None => Setting {
            value: DEFAULT_LOG_FILTER.to_owned(),
            source: ConfigSource::Default,
            env: Some(ENV_LOG_FILTER),
        },
    }
}

/// Replace the field-value part of every span directive
/// (`target[span{field=value}]=level`) with `***`. Field filters can
/// match on arbitrary values, credentials included, and the key-based
/// M7 rules don't see inside a directive string. Targets and levels
/// stay readable.
fn mask_span_fields(filter: &str) -> String {
    // `EnvFilter`'s grammar: inside a `[span]` selector, `{` opens the
    // field list and the first `}` closes it, with no nesting, quoting
    // or escapes. Outside a selector `{` is a literal target character.
    let mut out = String::with_capacity(filter.len());
    let mut in_span = false;
    let mut in_fields = false;
    for c in filter.chars() {
        if in_fields {
            if c == '}' {
                out.push('}');
                in_fields = false;
            }
            continue;
        }
        match c {
            '[' => in_span = true,
            ']' => in_span = false,
            '{' if in_span => {
                out.push_str("{***");
                in_fields = true;
                continue;
            }
            _ => {}
        }
        out.push(c);
    }
    if in_fields {
        out.push('}');
    }
    out
}

static DAEMON_CONFIG: OnceLock<DaemonConfig> = OnceLock::new();

/// Publish the daemon's resolved configuration. Once per process:
/// returns `false` (and keeps the first snapshot) when one is already
/// installed.
pub fn install_daemon_config(config: DaemonConfig) -> bool {
    DAEMON_CONFIG.set(config).is_ok()
}

/// Compiled-in MCP mount limits. The production mount
/// ([`super::mount_routes`]) uses exactly these; none is tunable at
/// runtime yet.
#[derive(Debug, Serialize)]
struct McpLimits {
    max_sessions: Setting<usize>,
    max_pending_bodies: Setting<usize>,
    request_body_deadline_ms: Setting<u64>,
    max_request_body_bytes: Setting<usize>,
    max_response_body_bytes: Setting<u64>,
    max_resource_text_bytes: Setting<usize>,
    rate_limit: RateLimits,
}

#[derive(Debug, Serialize)]
struct RateLimits {
    per_bearer_burst: Setting<u32>,
    per_bearer_refill_per_sec: Setting<f64>,
    ingress_burst: Setting<u32>,
    ingress_refill_per_sec: Setting<f64>,
}

impl McpLimits {
    fn compiled() -> Self {
        use super::rate_limit::{
            DEFAULT_BUCKET_CAPACITY, DEFAULT_INGRESS_CAPACITY, DEFAULT_INGRESS_TOKENS_PER_SECOND,
            DEFAULT_TOKENS_PER_SECOND,
        };
        use super::server::{
            MAX_REQUEST_BODY_BYTES, MAX_RESPONSE_BODY_BYTES, MAX_SESSIONS, PENDING_BODY_GATE,
            REQUEST_BODY_DEADLINE,
        };
        Self {
            max_sessions: Setting::fixed(MAX_SESSIONS),
            max_pending_bodies: Setting::fixed(PENDING_BODY_GATE),
            request_body_deadline_ms: Setting::fixed(duration_ms(REQUEST_BODY_DEADLINE)),
            max_request_body_bytes: Setting::fixed(MAX_REQUEST_BODY_BYTES),
            max_response_body_bytes: Setting::fixed(MAX_RESPONSE_BODY_BYTES),
            max_resource_text_bytes: Setting::fixed(super::resources::MAX_TEXT_BODY_BYTES),
            rate_limit: RateLimits {
                per_bearer_burst: Setting::fixed(DEFAULT_BUCKET_CAPACITY),
                per_bearer_refill_per_sec: Setting::fixed(DEFAULT_TOKENS_PER_SECOND),
                ingress_burst: Setting::fixed(DEFAULT_INGRESS_CAPACITY),
                ingress_refill_per_sec: Setting::fixed(DEFAULT_INGRESS_TOKENS_PER_SECOND),
            },
        }
    }
}

fn duration_ms(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// Wire body of `oxidhome://config` and `GET /api/v1/config`.
#[derive(Debug, Serialize)]
pub(crate) struct ConfigBody<'a> {
    /// Daemon crate version.
    version: &'static str,
    /// SDK version this host ships with.
    sdk_version: &'static str,
    /// Oldest plugin `sdk_version` the loader accepts.
    min_supported_sdk_version: &'static str,
    /// Version of the `oxidhome:plugin` WIT package this host
    /// implements.
    wit_version: String,
    /// `null` when the process never installed a snapshot.
    daemon: Option<&'a DaemonConfig>,
    mcp: McpLimits,
}

/// Build the body from the installed snapshot.
pub(crate) fn config_body() -> ConfigBody<'static> {
    config_body_for(DAEMON_CONFIG.get())
}

fn config_body_for(daemon: Option<&DaemonConfig>) -> ConfigBody<'_> {
    ConfigBody {
        version: env!("CARGO_PKG_VERSION"),
        sdk_version: crate::OXIDHOME_SDK_VERSION,
        min_supported_sdk_version: crate::MIN_SUPPORTED_SDK_VERSION,
        wit_version: crate::runtime::contract::host_contract_version(),
        daemon,
        mcp: McpLimits::compiled(),
    }
}

/// `config_body` as redacted JSON, for the REST surface. The MCP
/// resource redacts in its shared encoder instead.
pub(crate) fn config_json() -> serde_json::Value {
    redacted(&config_body())
}

fn redacted(body: &ConfigBody<'_>) -> serde_json::Value {
    // Plain structs, string keys: serialization can't fail.
    let mut value = serde_json::to_value(body).unwrap_or(serde_json::Value::Null);
    crate::redact::redact_json(&mut value);
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> DaemonConfig {
        DaemonConfig {
            mode: DaemonMode::Http,
            state_dir: Setting {
                value: "/var/lib/oxidhome".to_owned(),
                source: ConfigSource::Env,
                env: Some(ENV_STATE_DIR),
            },
            bind: Some(Setting::fixed("127.0.0.1:7780".parse().unwrap())),
            listen_addr: Some("127.0.0.1:7780".parse().unwrap()),
            dev_plugin_dir: None,
            log_filter: Setting::fixed(DEFAULT_LOG_FILTER.to_owned()),
            event_log_retention: RetentionView::new(
                &RetentionConfig::default().event_log,
                &EVENT_LOG_RETENTION_ENV,
            ),
            log_retention: RetentionView::new(&RetentionConfig::default().logs, &LOG_RETENTION_ENV),
            audit_retention: RetentionView::new(
                &RetentionConfig::default().audit,
                &AUDIT_RETENTION_ENV,
            ),
        }
    }

    #[test]
    fn body_carries_versions_sources_and_limits() {
        let daemon = sample();
        let body = serde_json::to_value(config_body_for(Some(&daemon))).unwrap();
        assert_eq!(body["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(body["sdk_version"], crate::OXIDHOME_SDK_VERSION);
        assert_eq!(
            body["wit_version"],
            crate::runtime::contract::host_contract_version()
        );
        assert_eq!(body["daemon"]["mode"], "http");
        assert_eq!(body["daemon"]["state_dir"]["value"], "/var/lib/oxidhome");
        assert_eq!(body["daemon"]["state_dir"]["source"], "env");
        assert_eq!(body["daemon"]["state_dir"]["env"], ENV_STATE_DIR);
        let retention = &body["daemon"]["event_log_retention"];
        assert_eq!(retention["max_age_days"]["value"], 30);
        assert_eq!(
            retention["max_rows"]["env"], EVENT_LOG_RETENTION_ENV.rows_var,
            "overridable settings name their variable",
        );
        assert!(
            retention["interval_secs"].get("env").is_none(),
            "fixed settings name no variable",
        );
        assert_eq!(
            body["daemon"]["audit_retention"]["max_age_days"]["value"],
            365
        );
        assert_eq!(
            body["daemon"]["log_retention"]["max_rows"]["env"],
            "OXIDHOME_LOG_MAX_ROWS"
        );
        assert_eq!(body["mcp"]["max_sessions"]["value"], 128);
        assert_eq!(body["mcp"]["max_sessions"]["source"], "default");
        assert_eq!(body["mcp"]["rate_limit"]["per_bearer_burst"]["value"], 60);
    }

    #[test]
    fn missing_snapshot_serializes_as_null_daemon() {
        let body = serde_json::to_value(config_body_for(None)).unwrap();
        assert!(body["daemon"].is_null());
        assert!(body["mcp"].is_object());
    }

    #[test]
    fn disabled_retention_limits_are_null() {
        let view = RetentionView::new(
            &RetentionPolicy {
                max_age: None,
                max_rows: None,
                ..RetentionPolicy::defaults(&EVENT_LOG_RETENTION_ENV)
            },
            &EVENT_LOG_RETENTION_ENV,
        );
        let json = serde_json::to_value(view).unwrap();
        assert!(json["max_age_days"]["value"].is_null());
        assert!(json["max_rows"]["value"].is_null());
    }

    #[test]
    fn span_field_values_are_masked() {
        assert_eq!(
            mask_span_fields("info,oxidhome=debug"),
            "info,oxidhome=debug"
        );
        assert_eq!(
            mask_span_fields("warn,[request{url=https://alice:pw@hub/}]=debug"),
            "warn,[request{***}]=debug",
        );
        assert_eq!(mask_span_fields("x[s{unterminated"), "x[s{***}");
        // `\{` is a literal brace inside a field value, not a nesting
        // level; the directives after it stay visible.
        let filter = r"app[request{message=\{}]=debug,other=trace";
        assert!(tracing_subscriber::EnvFilter::try_new(filter).is_ok());
        assert_eq!(
            mask_span_fields(filter),
            "app[request{***}]=debug,other=trace"
        );
        // Outside a span selector `{` is part of a target name.
        let filter = "worker{=warn,oxidhome_core=debug";
        assert!(tracing_subscriber::EnvFilter::try_new(filter).is_ok());
        assert_eq!(mask_span_fields(filter), filter);
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_state_dir_still_serializes() {
        use std::os::unix::ffi::OsStrExt as _;
        let dir = Path::new(std::ffi::OsStr::from_bytes(b"/srv/\xff/state"));
        let cfg = DaemonConfig::resolve(DaemonMode::McpStdio, dir, &RetentionConfig::default());
        let json = serde_json::to_value(config_body_for(Some(&cfg))).unwrap();
        assert!(json["daemon"]["state_dir"]["value"].is_string());
    }

    #[test]
    fn dev_plugin_dir_is_a_flag() {
        let cfg = sample().with_dev_plugin_dir(Path::new("/tmp/plugin"));
        let json = serde_json::to_value(&cfg).unwrap();
        assert_eq!(json["dev_plugin_dir"]["source"], "flag");
        assert!(json["dev_plugin_dir"].get("env").is_none());
    }

    /// The body has no secret by construction, but it still goes
    /// through M7: a credential-looking value in a path is masked.
    #[test]
    fn rest_body_is_redacted() {
        let mut daemon = sample();
        daemon.state_dir.value = "/srv/password=hunter2/state".to_owned();
        let value = redacted(&config_body_for(Some(&daemon)));
        let dir = value["daemon"]["state_dir"]["value"].as_str().unwrap();
        assert!(!dir.contains("hunter2"), "secret survived: {dir}");
    }
}
