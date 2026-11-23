//! [`TestPluginInstance`] — one loaded plugin plus assertion helpers.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use oxidhome_core::state::{BlobInfo, DeviceMeta, HistoricalEvent, ServiceMeta};
use oxidhome_core::{CommandOutcome, Engine, PluginInstance, VirtualClock};
use oxidhome_manifest::PluginManifest;

use crate::TestHostError;
use crate::live::IdLease;
use crate::snapshot::{CommandRecord, Secrets, Snapshot, SnapshotOptions};
use crate::tempdir::TempDir;
use crate::view::{InstanceRef, StorageView};
use crate::wit::devices::{Command, CommandResult};
use crate::wit::events::Event;
use crate::wit::types::{DeviceId, ServiceId};

/// A plugin instance loaded by a [`crate::TestHost`].
///
/// Each driver method calls the matching plugin export once, on the
/// caller's task, and returns when the export does — there is no
/// background supervisor, so `tick` and event delivery happen exactly
/// when the test asks for them.
///
/// Dropping the instance (or calling [`Self::shutdown`]) runs the
/// host-side teardown the daemon's supervisor runs when an instance
/// stops: its devices and services leave the registries and its
/// device-state projection turns stale.
///
/// The instance keeps its host's state directory alive, so it stays
/// usable even after the [`crate::TestHost`] that loaded it is dropped.
///
/// A directly driven instance can call other plugins' services (its
/// `call-service` goes through the production dispatcher), but it
/// can't *serve* them: the dispatcher routes a call to the owner's
/// supervisor task. Run a service provider with
/// [`crate::TestHost::start`] instead.
pub struct TestPluginInstance {
    // Field order: the store and engine close before the state
    // directory they live in is removed; the id lease goes after the
    // `Drop` teardown has run.
    inner: PluginInstance,
    engine: Engine,
    lease: IdLease,
    state_dir: Arc<TempDir>,
    /// Time since load on a real-clock host, moved by `advance`.
    elapsed: Duration,
    /// On a virtual-clock host: the clock's time at load, which the
    /// tick schedule counts from.
    loaded_at: Duration,
    secrets: Arc<Secrets>,
    commands: Mutex<Vec<CommandRecord>>,
}

impl TestPluginInstance {
    pub(crate) fn new(
        engine: Engine,
        inner: PluginInstance,
        lease: IdLease,
        state_dir: Arc<TempDir>,
        secrets: Arc<Secrets>,
    ) -> Self {
        secrets.add(oxidhome_core::redact::config_secrets(inner.config()));
        let loaded_at = engine
            .clock()
            .as_virtual()
            .map_or(Duration::ZERO, VirtualClock::elapsed);
        Self {
            inner,
            engine,
            lease,
            state_dir,
            elapsed: Duration::ZERO,
            loaded_at,
            secrets,
            commands: Mutex::default(),
        }
    }

    /// The instance id the plugin runs under.
    #[must_use]
    pub fn instance_id(&self) -> &str {
        self.inner.instance_id()
    }

    /// The installation identity storage and device ids are keyed by.
    /// For a test load this is the manifest's `plugin.id`.
    #[must_use]
    pub fn installation_uuid(&self) -> Arc<str> {
        self.inner.installation_uuid()
    }

    /// The parsed manifest the instance was loaded from.
    #[must_use]
    pub fn manifest(&self) -> &PluginManifest {
        self.inner.manifest()
    }

    /// Call the plugin's `init` export.
    ///
    /// # Errors
    ///
    /// [`TestHostError::Init`] when `init` returns an error, traps,
    /// or runs past the liveness watchdog.
    pub async fn init(&mut self) -> Result<(), TestHostError> {
        Ok(self.inner.init().await?)
    }

    /// Call the plugin's `tick` export once, now. Doesn't move the
    /// virtual clock; see [`Self::advance`] for ticking on the
    /// manifest's schedule.
    ///
    /// # Errors
    ///
    /// [`TestHostError::Call`] when the export traps or times out.
    pub async fn tick(&mut self) -> Result<(), TestHostError> {
        self.inner
            .tick()
            .await
            .map_err(|e| TestHostError::call("tick", e))
    }

    /// Call the plugin's `execute-command` export for `device`. The
    /// result goes through the same post-processing as in the daemon:
    /// an `ok-with-state` reply updates the host's device-state
    /// projection (or becomes `unknown` when it breaks the
    /// projection's caps), and an `accepted` reply is registered as a
    /// pending command the plugin can finish with `complete-command`.
    /// `command.id` is passed through as given; use a `cmd-` prefixed
    /// id if the plugin may answer `accepted`.
    ///
    /// The call and its H5 outcome are recorded for the snapshot's
    /// `commands` section ([`crate::SnapshotOptions::commands`]).
    ///
    /// # Errors
    ///
    /// [`TestHostError::Call`] when the export traps or times out. A
    /// command the plugin rejects is an `Ok(CommandResult::Err(_))`.
    pub async fn send_command(
        &mut self,
        device: impl Into<DeviceId>,
        command: Command,
    ) -> Result<CommandResult, TestHostError> {
        let device = device.into();
        let mut record = CommandRecord {
            device: device.clone(),
            capability: command.capability.clone(),
            action: command.action.clone(),
            command_id: command.id.clone(),
            outcome: CommandOutcome::Accepted,
        };
        let result = self.inner.execute_command(device, command).await;
        record.outcome = match &result {
            Ok(reply) => CommandOutcome::from_plugin(reply.clone()),
            // The plugin was entered: whatever it did may stand.
            Err(_) => CommandOutcome::Unknown {
                message: "execute-command trapped".into(),
            },
        };
        self.commands
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(record);
        result.map_err(|e| TestHostError::call("execute-command", e))
    }

    /// Publish `event` on the host's event bus, then hand this
    /// instance every event waiting on its subscriptions through its
    /// `on-event` export. Returns how many events the plugin received.
    ///
    /// Delivery follows production rules: the plugin only sees the
    /// event if it subscribed with a matching filter, which in turn
    /// needs the `subscribes_events` capability. Other instances on
    /// the same host receive the event too, on their next
    /// [`Self::deliver_pending_events`]. The event is published the
    /// way host-side simulators publish: it skips the durable event
    /// log, so the plugin sees `row-id: none` and the origin fields
    /// exactly as the test set them.
    ///
    /// # Errors
    ///
    /// [`TestHostError::Call`] when `on-event` traps or times out.
    pub async fn deliver_event(&mut self, event: Event) -> Result<usize, TestHostError> {
        self.engine.events().publish(event);
        self.deliver_pending_events().await
    }

    /// Hand this instance every event waiting on its subscriptions
    /// through its `on-event` export, as the daemon's supervisor does
    /// when the bus wakes it. Returns how many events were delivered.
    ///
    /// # Errors
    ///
    /// [`TestHostError::Call`] when `on-event` traps or times out.
    pub async fn deliver_pending_events(&mut self) -> Result<usize, TestHostError> {
        self.inner
            .drain_events()
            .await
            .map_err(|e| TestHostError::call("on-event", e))
    }

    /// Call the plugin's `on-shutdown` export, then run the host-side
    /// teardown (see the type docs).
    ///
    /// # Errors
    ///
    /// [`TestHostError::Call`] when the export traps or times out; the
    /// teardown runs either way.
    pub async fn shutdown(mut self) -> Result<(), TestHostError> {
        // `Drop` runs the teardown once `self` goes out of scope.
        self.inner
            .shutdown()
            .await
            .map_err(|e| TestHostError::call("on-shutdown", e))
    }

    /// Devices this instance currently has registered, sorted by
    /// device id.
    #[must_use]
    pub fn devices(&self) -> Vec<Arc<DeviceMeta>> {
        self.view().devices()
    }

    /// Services this instance currently has registered, sorted by
    /// local id.
    #[must_use]
    pub fn services(&self) -> Vec<Arc<ServiceMeta>> {
        self.view().services()
    }

    /// The host-minted id (`svc-N`) of this instance's service with
    /// `local_id`, if it has registered one — what another plugin
    /// passes to `call-service`.
    #[must_use]
    pub fn service_id(&self, local_id: &str) -> Option<ServiceId> {
        self.view().service_id(local_id)
    }

    /// Every event this instance id has published, oldest first, as
    /// recorded in the host's durable event log — with the host-stamped
    /// origin and receive time. Includes events from earlier instances
    /// loaded under the same id on this host.
    ///
    /// # Errors
    ///
    /// [`TestHostError::EventLog`] if the log can't be read.
    pub fn events(&self) -> Result<Vec<HistoricalEvent>, TestHostError> {
        self.view().events()
    }

    /// This instance's KV storage.
    #[must_use]
    pub fn storage(&self) -> StorageView {
        self.view().storage()
    }

    /// Blobs this instance has written, sorted by name.
    ///
    /// # Errors
    ///
    /// [`TestHostError::Blobs`] if the blob index can't be read.
    pub fn blobs(&self) -> Result<Vec<BlobInfo>, TestHostError> {
        self.view().blobs()
    }

    /// The contents of this instance's blob called `name`.
    ///
    /// # Errors
    ///
    /// [`TestHostError::Blobs`] if there is no such blob or it can't
    /// be read.
    pub fn read_blob(&self, name: &str) -> Result<Vec<u8>, TestHostError> {
        self.view().read_blob(name)
    }

    /// A [`Snapshot`] of everything this instance has in the host:
    /// the default sections ([`SnapshotOptions::default`]).
    ///
    /// # Errors
    ///
    /// When the event log, storage, or blob index can't be read.
    pub fn snapshot(&self) -> Result<Snapshot, TestHostError> {
        self.snapshot_with(&SnapshotOptions::default())
    }

    /// A [`Snapshot`] with the sections and stamps `options` asks for.
    ///
    /// # Errors
    ///
    /// When the event log, storage, blob index, or audit ledger can't
    /// be read.
    pub fn snapshot_with(&self, options: &SnapshotOptions) -> Result<Snapshot, TestHostError> {
        self.view().snapshot(options)
    }

    /// Time since the instance was loaded, as the tick schedule of
    /// [`Self::advance`] counts it: on a virtual-clock host, the host
    /// clock's time since load (whoever moved it); on a real-clock
    /// host, the instance's own clock, moved only by
    /// [`Self::advance`]. Real time never moves it.
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        match self.engine.clock().as_virtual() {
            Some(clock) => clock.elapsed().saturating_sub(self.loaded_at),
            None => self.elapsed,
        }
    }

    /// Move time forward by `by` and call `tick` once for every
    /// `runtime.tick_interval_ms` boundary crossed, the way the
    /// daemon's supervisor would over that span: the first tick lands
    /// one interval after load (the supervisor's first lands one
    /// interval after `Running`), then one per interval. A plugin
    /// without `tick_interval_ms` is never ticked. Returns how many
    /// ticks ran.
    ///
    /// The schedule is the one the supervisor aims for; it doesn't
    /// model a host that falls behind (the supervisor then delays
    /// rather than bursts missed ticks).
    ///
    /// On a [`crate::TestHost::with_virtual_clock`] host this moves the
    /// host's clock, so the plugin's WASI clocks and the host's
    /// timestamps read each tick's time, and the host's other timers
    /// (supervised ticks, `accepted`-command TTLs) fire in order with
    /// these ticks, as [`crate::TestHost::advance`] fires them. On a
    /// real-clock host the clock is the instance's own and only
    /// schedules its ticks. See the crate docs, "Time".
    ///
    /// # Errors
    ///
    /// [`TestHostError::Call`] when a tick traps or times out. The
    /// clock then stays at that tick's boundary and the remaining
    /// ticks don't run. [`TestHostError::ClockStalled`] as for
    /// [`crate::TestHost::advance`].
    pub async fn advance(&mut self, by: Duration) -> Result<usize, TestHostError> {
        let interval = self
            .manifest()
            .runtime
            .tick_interval_ms
            .filter(|ms| *ms > 0)
            .map(Duration::from_millis);
        let Some(clock) = self.engine.clock().as_virtual().cloned() else {
            let target = self.elapsed.saturating_add(by);
            let mut ticks = 0;
            if let Some(interval) = interval {
                // Next boundary strictly after the current time; `None`
                // once it would overflow `Duration`, i.e. never reached.
                while let Some(next) = next_boundary(self.elapsed, interval)
                    && next <= target
                {
                    self.elapsed = next;
                    self.tick().await?;
                    ticks += 1;
                }
            }
            self.elapsed = target;
            return Ok(ticks);
        };
        let target = clock.elapsed().saturating_add(by);
        let mut ticks = 0;
        while let Some(next) = interval
            .and_then(|i| next_boundary(self.elapsed(), i))
            .and_then(|since_load| self.loaded_at.checked_add(since_load))
            && next <= target
        {
            // The host's timers due up to (and at) the tick go first.
            crate::clock::run_timers_until(&clock, next).await?;
            clock.advance_to(next);
            crate::clock::settle(&clock).await?;
            self.tick().await?;
            ticks += 1;
        }
        crate::clock::advance_to(&clock, target).await?;
        Ok(ticks)
    }

    /// The production instance this wraps, for calls the harness
    /// doesn't cover (e.g. `execute-service-command` without going
    /// through the dispatcher).
    #[must_use]
    pub fn inner_mut(&mut self) -> &mut PluginInstance {
        &mut self.inner
    }

    fn view(&self) -> InstanceRef<'_> {
        InstanceRef {
            engine: &self.engine,
            state_dir: &self.state_dir,
            installation_uuid: self.installation_uuid(),
            instance_id: self.instance_id(),
            secrets: &self.secrets,
            commands: &self.commands,
        }
    }
}

/// The first multiple of `interval` strictly after `now`.
fn next_boundary(now: Duration, interval: Duration) -> Option<Duration> {
    let into = now.as_nanos() % interval.as_nanos();
    let into = Duration::new(
        u64::try_from(into / 1_000_000_000).ok()?,
        u32::try_from(into % 1_000_000_000).ok()?,
    );
    now.checked_sub(into)?.checked_add(interval)
}

impl Drop for TestPluginInstance {
    fn drop(&mut self) {
        // The lease (a field) frees the id after this teardown.
        self.engine.release_instance_state(self.lease.id());
    }
}

#[cfg(test)]
mod tests {
    use super::next_boundary;
    use std::time::Duration;

    #[test]
    fn boundaries_are_strictly_after_now() {
        let second = Duration::from_secs(1);
        assert_eq!(next_boundary(Duration::ZERO, second), Some(second));
        assert_eq!(
            next_boundary(Duration::from_millis(999), second),
            Some(second)
        );
        assert_eq!(next_boundary(second, second), Some(2 * second));
        assert_eq!(
            next_boundary(Duration::from_millis(4500), second),
            Some(Duration::from_secs(5))
        );
        assert_eq!(next_boundary(Duration::MAX, second), None);
    }
}
