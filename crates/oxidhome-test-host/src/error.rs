//! The harness's error type.

use std::path::PathBuf;

/// Boxed source error. `oxidhome-core` reports failures as
/// `anyhow::Error`; the harness keeps them as the source of a typed
/// variant so callers can match on *what* failed.
type Source = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Everything a [`crate::TestHost`] or [`crate::TestPluginInstance`]
/// call can fail with.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TestHostError {
    /// Creating the throwaway state directory failed.
    #[error("creating the test host state directory under {path}")]
    StateDir {
        /// Directory the harness tried to create.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// Building the host engine (Wasmtime, `SQLite` state) failed.
    #[error("building the host engine")]
    Engine(#[source] Source),
    /// The instance id is one the host refuses: empty, too long, a
    /// path separator, the reserved `*` wildcard, or the `~` reserved
    /// for script sandbox ids.
    #[error("instance id `{0}` is not permitted")]
    InvalidInstanceId(String),
    /// Another live instance on this host already uses the id.
    #[error("instance id `{0}` is already in use on this test host")]
    DuplicateInstanceId(String),
    /// Reading, parsing, or validating `manifest.toml` failed.
    #[error("reading the plugin manifest from {path}")]
    Manifest {
        /// Plugin directory the manifest was read from.
        path: PathBuf,
        /// Underlying error.
        #[source]
        source: Source,
    },
    /// The injected grant asks for capabilities the manifest doesn't
    /// request. Production intersects grants with the request, so
    /// such a grant can never take effect; the harness refuses it
    /// rather than run the plugin under an impossible boundary.
    #[error(
        "grant for plugin `{plugin_id}` exceeds what its manifest requests: {}",
        excess.join("; ")
    )]
    GrantExceedsRequest {
        /// `plugin.id` from the manifest.
        plugin_id: String,
        /// One entry per capability the grant adds.
        excess: Vec<String>,
    },
    /// The production loader refused or failed to instantiate the
    /// component (bad grant, SDK version mismatch, config merge
    /// error, invalid component, …).
    #[error("loading plugin `{plugin_id}`")]
    Load {
        /// `plugin.id` from the manifest.
        plugin_id: String,
        /// Underlying error.
        #[source]
        source: Source,
    },
    /// The plugin's `init` returned an error, trapped, or timed out.
    #[error(transparent)]
    Init(#[from] oxidhome_core::InitError),
    /// A call into the plugin (`tick`, `execute-command`, `on-event`,
    /// `on-shutdown`) trapped or timed out, or a supervised instance's
    /// supervisor was gone.
    #[error("calling plugin export `{export}`")]
    Call {
        /// WIT export that was called.
        export: &'static str,
        /// Underlying error.
        #[source]
        source: Source,
    },
    /// Reading the instance's KV storage failed.
    #[error("reading plugin storage")]
    Storage(#[from] oxidhome_core::state::KvError),
    /// Reading the event history failed.
    #[error("reading the event log")]
    EventLog(#[from] oxidhome_core::state::EventLogError),
    /// Reading the instance's blobs failed (or the named blob doesn't
    /// exist).
    #[error("reading plugin blobs")]
    Blobs(#[from] oxidhome_core::state::BlobError),
    /// A supervised instance stopped or failed before reaching
    /// `Running`.
    #[error("instance `{instance_id}` did not reach Running: {state:?}")]
    NotRunning {
        /// The instance's id.
        instance_id: String,
        /// The state it ended in, e.g. `Failed { error }` naming the
        /// crash.
        state: oxidhome_core::InstanceState,
    },
    /// The harness's own bookkeeping task for a supervised instance
    /// failed.
    #[error("tracking a supervised instance")]
    Supervisor(#[source] Source),
    /// Reading the audit ledger failed.
    #[error("reading the audit ledger")]
    Audit(#[from] oxidhome_core::state::AuditLogError),
    /// Rows the host writes in the background didn't reach the audit
    /// ledger in time, so an audit snapshot would be partial.
    #[error("the {writer} did not drain into the audit ledger in time")]
    AuditBacklog {
        /// Which background writer: the refused-read audit or the
        /// command journal.
        writer: &'static str,
    },
    /// A virtual-clock operation on a host built with
    /// [`crate::TestHost::new`], which runs on the real clock.
    #[error(
        "this test host runs on the real clock; build it with \
         `TestHost::with_virtual_clock` to move time"
    )]
    RealClock,
    /// The virtual clock didn't settle: a task woken by a timer
    /// didn't get back to waiting within the harness's real-time
    /// bound — typically a plugin call that never returns. Move time
    /// past its watchdog with [`crate::VirtualClock::advance`], which
    /// doesn't wait.
    #[error(
        "the virtual clock did not settle at +{elapsed:?} within {limit:?} of real time \
         (a task woken by a timer is still busy — a plugin call that never returns?)"
    )]
    ClockStalled {
        /// Virtual time since the clock started.
        elapsed: std::time::Duration,
        /// The real-time bound that ran out.
        limit: std::time::Duration,
    },
}

impl TestHostError {
    pub(crate) fn call(export: &'static str, source: anyhow::Error) -> Self {
        Self::Call {
            export,
            source: source.into(),
        }
    }
}
