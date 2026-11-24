//! The host's time source.
//!
//! Every time-dependent decision the runtime makes about a plugin
//! reads one [`Clock`], owned by the [`Engine`](crate::Engine):
//!
//! - wall-clock stamps: event receive times, device-state
//!   `received_ms`, audit-ledger `intent_ms` / `finalized_ms`;
//! - the guest's `wasi:clocks` wall and monotonic clocks;
//! - the supervisor's `tick_interval_ms` schedule;
//! - the `accepted`-command TTL (H5);
//! - the event bus's per-instance publish rate buckets and the
//!   per-instance plugin log rate bucket;
//! - the network policy's resolved-address grant TTL and its
//!   denial-audit rate bucket (streaming worlds);
//! - the liveness watchdog's epoch counter.
//!
//! [`Clock::system`] — the default, and the only clock the daemon
//! uses — reads the operating system and Tokio exactly as the call
//! sites did before the seam existed: `SystemTime::now()`,
//! `tokio::time::Instant::now()`, `tokio::time::sleep_until`, a
//! `tokio::time::interval_at` with [`MissedTickBehavior::Delay`], the
//! guest's default WASI clocks, and the watchdog's epoch-ticker
//! thread.
//!
//! A [`VirtualClock`] is the test seam (`oxidhome-test-host`): time
//! stands still until the test moves it, so ticks, TTL expiries, the
//! watchdog, and every recorded timestamp are deterministic.
//!
//! Not on the clock: KV and blob write times, log-store and
//! command-journal row times (with the journal's `COMMAND` audit
//! rows), request and call-service deadlines (H6 invocation
//! deadlines), restart backoff, shutdown grace periods, retention
//! cutoffs, the API and MCP surfaces' relative time filters, and the
//! network I/O deadlines of streaming worlds (DNS lookup, TCP connect,
//! HTTP first-byte and between-bytes timeouts), which bound real
//! sockets. They keep reading real time under a virtual clock too.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::time::{Instant, MissedTickBehavior};
use wasmtime::Engine as WasmtimeEngine;
use wasmtime_wasi::{HostMonotonicClock, HostWallClock, WasiCtxBuilder};

use crate::runtime::watchdog::{EPOCH_TICK_MS, EpochTicker};

/// Where the host reads time from. Cheap to clone; clones share the
/// source. See the module docs.
#[derive(Clone, Debug, Default)]
pub struct Clock {
    source: Source,
}

#[derive(Clone, Debug, Default)]
enum Source {
    #[default]
    System,
    Virtual(VirtualClock),
}

impl Clock {
    /// The operating-system clock — what the daemon runs on.
    #[must_use]
    pub fn system() -> Self {
        Self::default()
    }

    /// Whether this is a [`VirtualClock`].
    #[must_use]
    pub fn is_virtual(&self) -> bool {
        matches!(self.source, Source::Virtual(_))
    }

    /// The virtual clock behind this one, if any.
    #[must_use]
    pub fn as_virtual(&self) -> Option<&VirtualClock> {
        match &self.source {
            Source::System => None,
            Source::Virtual(v) => Some(v),
        }
    }

    /// Wall-clock time.
    #[must_use]
    pub fn now(&self) -> SystemTime {
        match &self.source {
            Source::System => SystemTime::now(),
            Source::Virtual(v) => v.now(),
        }
    }

    /// Wall-clock time in Unix milliseconds: `0` before the epoch,
    /// capped at `i64::MAX`.
    #[must_use]
    pub fn now_unix_ms(&self) -> i64 {
        unix_ms(self.now())
    }

    /// The current instant on the timeline [`Self::sleep_until`] and
    /// [`Self::tick_interval`] measure. Compare it only with instants
    /// from the same clock.
    #[must_use]
    pub fn instant(&self) -> Instant {
        match &self.source {
            Source::System => Instant::now(),
            Source::Virtual(v) => v.instant(),
        }
    }

    /// [`Self::instant`] as a `std` instant, for host code that keeps
    /// `std::time::Instant`s: `std::time::Instant::now()` on the system
    /// clock (as before the seam), the virtual instant on a virtual one.
    #[must_use]
    pub(crate) fn std_instant(&self) -> std::time::Instant {
        match &self.source {
            Source::System => std::time::Instant::now(),
            Source::Virtual(v) => v.instant().into_std(),
        }
    }

    /// A future that completes once [`Self::instant`] reaches
    /// `deadline` (`tokio::time::sleep_until` on the system clock).
    ///
    /// On a virtual clock, a sleep that fired counts as work in
    /// progress ([`VirtualClock::is_settled`] is `false`) until it is
    /// dropped: keep it until the work it triggers is done.
    #[must_use]
    pub fn sleep_until(&self, deadline: Instant) -> Sleep {
        match &self.source {
            Source::System => Sleep(SleepInner::System(Box::pin(tokio::time::sleep_until(
                deadline,
            )))),
            Source::Virtual(v) => Sleep(SleepInner::Virtual(v.sleep(deadline))),
        }
    }

    /// A tick schedule whose first tick lands at `start`, then one per
    /// `period`; a late tick delays the schedule instead of bursting
    /// ([`MissedTickBehavior::Delay`]).
    ///
    /// # Panics
    ///
    /// When `period` is zero.
    #[must_use]
    pub fn tick_interval(&self, start: Instant, period: Duration) -> Interval {
        assert!(!period.is_zero(), "tick interval period must be non-zero");
        match &self.source {
            Source::System => {
                let mut interval = tokio::time::interval_at(start, period);
                interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
                Interval(IntervalInner::System(interval))
            }
            Source::Virtual(v) => Interval(IntervalInner::Virtual(v.interval(start, period))),
        }
    }

    /// Point the guest's `wasi:clocks` at this clock. A no-op on the
    /// system clock, which keeps Wasmtime's defaults.
    pub(crate) fn configure_wasi(&self, wasi: &mut WasiCtxBuilder) {
        if let Source::Virtual(v) = &self.source {
            wasi.wall_clock(GuestWallClock(Arc::clone(&v.shared)));
            wasi.monotonic_clock(GuestMonotonicClock(Arc::clone(&v.shared)));
        }
    }

    /// Start moving `engine`'s epoch counter, which the liveness
    /// watchdog's deadlines count: the [`EpochTicker`] thread on the
    /// system clock, [`VirtualClock::advance`] on a virtual one.
    pub(crate) fn drive_epoch(&self, engine: &Arc<WasmtimeEngine>) {
        match &self.source {
            Source::System => EpochTicker::spawn(engine),
            Source::Virtual(v) => v.lock().engines.push(Arc::downgrade(engine)),
        }
    }
}

impl From<VirtualClock> for Clock {
    fn from(clock: VirtualClock) -> Self {
        Self {
            source: Source::Virtual(clock),
        }
    }
}

/// Unix milliseconds of `t`: `0` before the epoch, capped at
/// `i64::MAX`.
fn unix_ms(t: SystemTime) -> i64 {
    t.duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

/// Future returned by [`Clock::sleep_until`].
pub struct Sleep(SleepInner);

enum SleepInner {
    System(Pin<Box<tokio::time::Sleep>>),
    Virtual(VirtualSleep),
}

impl fmt::Debug for Sleep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            SleepInner::System(s) => f.debug_tuple("Sleep").field(s).finish(),
            SleepInner::Virtual(s) => f.debug_tuple("Sleep").field(&s.at).finish(),
        }
    }
}

impl Future for Sleep {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        match &mut self.0 {
            SleepInner::System(s) => s.as_mut().poll(cx),
            SleepInner::Virtual(s) => s.poll(cx),
        }
    }
}

/// Tick schedule returned by [`Clock::tick_interval`].
#[derive(Debug)]
pub struct Interval(IntervalInner);

#[derive(Debug)]
enum IntervalInner {
    System(tokio::time::Interval),
    Virtual(VirtualInterval),
}

impl Interval {
    /// Wait for the next tick. Cancel-safe: a dropped call loses no
    /// tick.
    pub async fn tick(&mut self) -> Instant {
        match &mut self.0 {
            IntervalInner::System(i) => i.tick().await,
            IntervalInner::Virtual(i) => std::future::poll_fn(|cx| i.poll_tick(cx)).await,
        }
    }
}

/// How late a tick must be before Tokio's `MissedTickBehavior::Delay`
/// reschedules from now rather than from the missed tick.
const DELAY_THRESHOLD: Duration = Duration::from_millis(5);

/// Default start of a [`VirtualClock`]: 2026-01-01T00:00:00Z.
pub const VIRTUAL_CLOCK_DEFAULT_START: Duration = Duration::from_hours(490_896);

/// Most epoch increments one [`VirtualClock::advance`] applies (about
/// 27.8 hours of watchdog ticks), so a jump costs at most that many
/// atomic adds. A watchdog deadline longer than that needs more than
/// one advance to trip.
const MAX_EPOCH_TICKS_PER_ADVANCE: u128 = 1_000_000;

/// A clock that only moves when told to — the test seam behind
/// [`Clock`].
///
/// Wall time starts at a fixed instant ([`VIRTUAL_CLOCK_DEFAULT_START`]
/// unless given) and the guest's monotonic clock at zero; both move
/// only through [`Self::advance`] / [`Self::advance_to`], which also
/// fire the timers ([`Clock::sleep_until`], [`Clock::tick_interval`])
/// that fall due and bump the watchdog's epoch once per 100 ms
/// boundary crossed. Real time passing changes nothing.
///
/// What a virtual clock can't control: a guest blocked in a WASI
/// sleep still sleeps for real (its deadline is measured on the
/// virtual clock, the wait on Tokio's), and everything the
/// [module docs](self) list as not on the clock.
///
/// Cheap to clone; clones share the time.
#[derive(Clone)]
pub struct VirtualClock {
    shared: Arc<Shared>,
}

struct Shared {
    start: SystemTime,
    /// The real instant virtual instants are offsets from.
    origin: Instant,
    state: Mutex<State>,
    /// Signalled whenever a timer fires or registers, or an interval's
    /// owner comes back for its next tick — what
    /// [`VirtualClock::settled`] waits on.
    changed: tokio::sync::Notify,
}

#[derive(Default)]
struct State {
    elapsed: Duration,
    next_id: u64,
    /// Registered timers by id: the time since start each is due at,
    /// and who to wake.
    timers: BTreeMap<u64, Timer>,
    /// Work in progress: intervals that fired and whose owner hasn't
    /// come back for the next tick yet, and sleeps that fired and
    /// haven't been dropped yet.
    busy: BTreeSet<u64>,
    engines: Vec<Weak<WasmtimeEngine>>,
}

struct Timer {
    at: Duration,
    waker: Option<Waker>,
}

impl State {
    /// Register a timer due at `at`, before anyone polls it: a timer
    /// exists from the moment it is created, so a clock step can't
    /// pass it unseen and a settle check waits for its owner.
    fn register(&mut self, at: Duration) -> u64 {
        self.next_id += 1;
        let id = self.next_id;
        self.timers.insert(id, Timer { at, waker: None });
        id
    }

    fn set_waker(&mut self, id: u64, waker: &Waker) {
        if let Some(timer) = self.timers.get_mut(&id) {
            match &mut timer.waker {
                Some(w) if w.will_wake(waker) => {}
                slot => *slot = Some(waker.clone()),
            }
        }
    }
}

impl fmt::Debug for VirtualClock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.lock();
        f.debug_struct("VirtualClock")
            .field("start", &self.shared.start)
            .field("elapsed", &state.elapsed)
            .field("timers", &state.timers.len())
            .field("busy", &state.busy.len())
            .finish_non_exhaustive()
    }
}

impl Default for VirtualClock {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtualClock {
    /// A clock at [`VIRTUAL_CLOCK_DEFAULT_START`].
    #[must_use]
    pub fn new() -> Self {
        Self::starting_at(UNIX_EPOCH + VIRTUAL_CLOCK_DEFAULT_START)
    }

    /// A clock whose wall time starts at `start`.
    #[must_use]
    pub fn starting_at(start: SystemTime) -> Self {
        Self {
            shared: Arc::new(Shared {
                start,
                origin: Instant::now(),
                state: Mutex::default(),
                changed: tokio::sync::Notify::new(),
            }),
        }
    }

    /// Wall time at which the clock started.
    #[must_use]
    pub fn start(&self) -> SystemTime {
        self.shared.start
    }

    /// Virtual time since the clock started.
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        self.lock().elapsed
    }

    /// Current virtual wall time.
    #[must_use]
    pub fn now(&self) -> SystemTime {
        self.shared.start + self.elapsed()
    }

    /// Current virtual wall time in Unix milliseconds.
    #[must_use]
    pub fn now_unix_ms(&self) -> i64 {
        unix_ms(self.now())
    }

    /// Current instant on the clock's timeline (see
    /// [`Clock::instant`]).
    #[must_use]
    pub fn instant(&self) -> Instant {
        self.shared.origin + self.elapsed()
    }

    /// Move the clock forward by `by`, firing every timer that falls
    /// due on the way and bumping the watchdog epoch. Returns at once,
    /// without waiting for the woken tasks to run (see
    /// [`Self::settled`]). Timers due at different points of the jump
    /// all fire at its end; step with [`Self::next_deadline`] to fire
    /// them one at a time.
    pub fn advance(&self, by: Duration) {
        self.step(|now| now.saturating_add(by));
    }

    /// Move the clock to `elapsed` since its start, as
    /// [`Self::advance`]. A time in the past leaves it where it is.
    pub fn advance_to(&self, elapsed: Duration) {
        self.step(|_| elapsed);
    }

    /// Move the clock to `target(now)`, read and applied under one
    /// lock so concurrent advances add up.
    fn step(&self, target: impl FnOnce(Duration) -> Duration) {
        let wake = {
            let mut state = self.lock();
            let elapsed = target(state.elapsed);
            if elapsed <= state.elapsed {
                return;
            }
            // The epoch moves before the new time is observable: a
            // call that starts at the new time arms its watchdog
            // against the new epoch, not one the jump then overtakes.
            let ticks = epoch_ticks(state.elapsed, elapsed);
            state.engines.retain(|e| e.strong_count() > 0);
            for engine in state.engines.iter().filter_map(Weak::upgrade) {
                for _ in 0..ticks {
                    engine.increment_epoch();
                }
            }
            state.elapsed = elapsed;
            state
                .timers
                .values_mut()
                .filter(|t| t.at <= elapsed)
                .filter_map(|t| t.waker.take())
                .collect::<Vec<Waker>>()
        };
        for waker in wake {
            waker.wake();
        }
        self.shared.changed.notify_waiters();
    }

    /// When the earliest registered timer is due, as time since the
    /// clock started; `None` when no timer is registered. May be at or
    /// before [`Self::elapsed`] while a due timer hasn't fired yet.
    #[must_use]
    pub fn next_deadline(&self) -> Option<Duration> {
        self.lock().timers.values().map(|t| t.at).min()
    }

    /// How many timers are registered.
    #[must_use]
    pub fn pending_timers(&self) -> usize {
        self.lock().timers.len()
    }

    /// Whether every timer that is due has fired, every tick interval
    /// that fired is being waited on again, and every sleep that fired
    /// was dropped — the work the current time triggered is done.
    #[must_use]
    pub fn is_settled(&self) -> bool {
        let state = self.lock();
        state.busy.is_empty() && state.timers.values().all(|t| t.at > state.elapsed)
    }

    /// Wait until [`Self::is_settled`]. Unbounded: a task that never
    /// gets back to its tick interval (a hung plugin) keeps this
    /// pending, so callers bound it themselves.
    pub async fn settled(&self) {
        loop {
            let changed = self.shared.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.is_settled() {
                return;
            }
            changed.await;
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.shared.lock()
    }

    fn offset_of(&self, instant: Instant) -> Duration {
        instant.saturating_duration_since(self.shared.origin)
    }

    fn sleep(&self, deadline: Instant) -> VirtualSleep {
        let at = self.offset_of(deadline);
        let id = self.lock().register(at);
        self.shared.changed.notify_waiters();
        VirtualSleep {
            shared: Arc::clone(&self.shared),
            id,
            at,
            fired: false,
        }
    }

    fn interval(&self, start: Instant, period: Duration) -> VirtualInterval {
        let next = self.offset_of(start);
        let id = self.lock().register(next);
        self.shared.changed.notify_waiters();
        VirtualInterval {
            shared: Arc::clone(&self.shared),
            id,
            next,
            period,
        }
    }
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Epoch increments for moving from `from` to `to`: one per
/// [`EPOCH_TICK_MS`] boundary crossed, as the real ticker would.
fn epoch_ticks(from: Duration, to: Duration) -> u128 {
    let tick = u128::from(EPOCH_TICK_MS);
    (to.as_millis() / tick)
        .saturating_sub(from.as_millis() / tick)
        .min(MAX_EPOCH_TICKS_PER_ADVANCE)
}

struct VirtualSleep {
    shared: Arc<Shared>,
    /// Both the timer id and the busy-set key.
    id: u64,
    at: Duration,
    fired: bool,
}

impl VirtualSleep {
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        if self.fired {
            return Poll::Ready(());
        }
        let mut state = self.shared.lock();
        if state.elapsed >= self.at {
            // Fired: the timer becomes work in progress under one
            // lock, so a settle check never sees neither. It stays
            // busy until the sleep is dropped.
            state.timers.remove(&self.id);
            state.busy.insert(self.id);
            drop(state);
            self.fired = true;
            self.shared.changed.notify_waiters();
            return Poll::Ready(());
        }
        state.set_waker(self.id, cx.waker());
        Poll::Pending
    }
}

impl Drop for VirtualSleep {
    fn drop(&mut self) {
        let mut state = self.shared.lock();
        let removed = state.timers.remove(&self.id).is_some() | state.busy.remove(&self.id);
        drop(state);
        if removed {
            self.shared.changed.notify_waiters();
        }
    }
}

struct VirtualInterval {
    shared: Arc<Shared>,
    /// Both the timer id and the busy-set key.
    id: u64,
    next: Duration,
    period: Duration,
}

impl fmt::Debug for VirtualInterval {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VirtualInterval")
            .field("next", &self.next)
            .field("period", &self.period)
            .finish_non_exhaustive()
    }
}

impl VirtualInterval {
    fn poll_tick(&mut self, cx: &mut Context<'_>) -> Poll<Instant> {
        let mut state = self.shared.lock();
        // The owner is back for the next tick: it finished the last.
        let mut changed = state.busy.remove(&self.id);
        let poll = if state.elapsed >= self.next {
            // Fired: the timer moves to the next tick and the interval
            // is marked busy under one lock, so a settle check never
            // sees neither.
            state.busy.insert(self.id);
            changed = true;
            let fired = self.next;
            // `MissedTickBehavior::Delay`, as Tokio applies it: a tick
            // more than 5 ms late puts the next a full period after
            // now; a less late one keeps the schedule.
            self.next = if state.elapsed > fired.saturating_add(DELAY_THRESHOLD) {
                state.elapsed.saturating_add(self.period)
            } else {
                fired.saturating_add(self.period)
            };
            state.timers.insert(
                self.id,
                Timer {
                    at: self.next,
                    waker: None,
                },
            );
            Poll::Ready(self.shared.origin + fired)
        } else {
            state.set_waker(self.id, cx.waker());
            Poll::Pending
        };
        drop(state);
        if changed {
            self.shared.changed.notify_waiters();
        }
        poll
    }
}

impl Drop for VirtualInterval {
    fn drop(&mut self) {
        let mut state = self.shared.lock();
        let removed = state.timers.remove(&self.id).is_some() | state.busy.remove(&self.id);
        drop(state);
        if removed {
            self.shared.changed.notify_waiters();
        }
    }
}

struct GuestWallClock(Arc<Shared>);

impl HostWallClock for GuestWallClock {
    fn resolution(&self) -> Duration {
        Duration::from_nanos(1)
    }

    fn now(&self) -> Duration {
        // As the host's `now`, clamped at the epoch only at the end.
        let now = self.0.start + self.0.lock().elapsed;
        now.duration_since(UNIX_EPOCH).unwrap_or_default()
    }
}

struct GuestMonotonicClock(Arc<Shared>);

impl HostMonotonicClock for GuestMonotonicClock {
    fn resolution(&self) -> u64 {
        1
    }

    fn now(&self) -> u64 {
        u64::try_from(self.0.lock().elapsed.as_nanos()).unwrap_or(u64::MAX)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn noop_cx() -> Context<'static> {
        Context::from_waker(Waker::noop())
    }

    #[test]
    fn system_clock_reads_real_time() {
        let clock = Clock::system();
        assert!(!clock.is_virtual());
        assert!(clock.as_virtual().is_none());
        let before = SystemTime::now();
        let now = clock.now();
        assert!(now >= before);
        assert!(clock.now_unix_ms() > 1_700_000_000_000);
    }

    #[test]
    fn virtual_time_moves_only_when_advanced() {
        let v = VirtualClock::new();
        let clock = Clock::from(v.clone());
        assert!(clock.is_virtual());
        assert_eq!(clock.now(), UNIX_EPOCH + VIRTUAL_CLOCK_DEFAULT_START);
        assert_eq!(
            clock.now_unix_ms(),
            1_767_225_600_000,
            "2026-01-01T00:00:00Z"
        );
        let t0 = clock.instant();
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(clock.instant(), t0);
        v.advance(Duration::from_millis(1500));
        assert_eq!(v.elapsed(), Duration::from_millis(1500));
        assert_eq!(clock.instant(), t0 + Duration::from_millis(1500));
        assert_eq!(clock.now_unix_ms(), 1_767_225_601_500);
        // Never backwards.
        v.advance_to(Duration::from_secs(1));
        assert_eq!(v.elapsed(), Duration::from_millis(1500));
        let later = VirtualClock::starting_at(UNIX_EPOCH + Duration::from_secs(10));
        assert_eq!(later.now_unix_ms(), 10_000);
        assert_eq!(later.start(), UNIX_EPOCH + Duration::from_secs(10));
        assert!(format!("{v:?}").contains("elapsed"));
    }

    #[test]
    fn sleep_fires_when_its_deadline_is_reached() {
        let v = VirtualClock::new();
        let clock = Clock::from(v.clone());
        let mut sleep = clock.sleep_until(clock.instant() + Duration::from_secs(5));
        let mut cx = noop_cx();
        assert!(Pin::new(&mut sleep).poll(&mut cx).is_pending());
        assert_eq!(v.pending_timers(), 1);
        assert_eq!(v.next_deadline(), Some(Duration::from_secs(5)));
        assert!(v.is_settled());
        v.advance(Duration::from_secs(4));
        assert!(Pin::new(&mut sleep).poll(&mut cx).is_pending());
        v.advance(Duration::from_secs(1));
        assert!(!v.is_settled(), "a due timer hasn't fired yet");
        assert!(Pin::new(&mut sleep).poll(&mut cx).is_ready());
        assert!(Pin::new(&mut sleep).poll(&mut cx).is_ready());
        assert_eq!(v.pending_timers(), 0);
        assert!(!v.is_settled(), "fired, but its owner still holds it");
        assert!(format!("{sleep:?}").starts_with("Sleep"));
        drop(sleep);
        assert!(v.is_settled());

        // A dropped sleep deregisters.
        let mut dropped = clock.sleep_until(clock.instant() + Duration::from_secs(1));
        assert!(Pin::new(&mut dropped).poll(&mut cx).is_pending());
        assert_eq!(v.pending_timers(), 1);
        drop(dropped);
        assert_eq!(v.pending_timers(), 0);
        assert_eq!(v.next_deadline(), None);
    }

    #[test]
    fn interval_ticks_on_schedule_and_tracks_its_owner() {
        let v = VirtualClock::new();
        let clock = Clock::from(v.clone());
        let mut interval = clock.tick_interval(clock.instant() + Duration::from_secs(1), {
            Duration::from_secs(1)
        });
        let IntervalInner::Virtual(inner) = &mut interval.0 else {
            panic!("virtual interval expected");
        };
        let mut cx = noop_cx();
        assert!(inner.poll_tick(&mut cx).is_pending());
        assert_eq!(v.next_deadline(), Some(Duration::from_secs(1)));
        v.advance(Duration::from_secs(1));
        assert!(inner.poll_tick(&mut cx).is_ready());
        assert!(!v.is_settled(), "the owner is still handling the tick");
        assert!(inner.poll_tick(&mut cx).is_pending());
        assert!(v.is_settled());
        assert_eq!(v.next_deadline(), Some(Duration::from_secs(2)));
        // A late tick delays the schedule (no burst).
        v.advance(Duration::from_millis(3500));
        assert!(inner.poll_tick(&mut cx).is_ready());
        assert!(inner.poll_tick(&mut cx).is_pending());
        assert_eq!(v.next_deadline(), Some(Duration::from_millis(5500)));
        // Up to 5 ms late keeps the schedule, as Tokio does.
        v.advance(Duration::from_millis(1001));
        assert!(inner.poll_tick(&mut cx).is_ready());
        assert!(inner.poll_tick(&mut cx).is_pending());
        assert_eq!(v.next_deadline(), Some(Duration::from_millis(6500)));
        assert!(format!("{interval:?}").contains("VirtualInterval"));
        drop(interval);
        assert_eq!(v.pending_timers(), 0);
        assert!(v.is_settled());
    }

    #[test]
    #[should_panic(expected = "non-zero")]
    fn zero_period_is_refused() {
        let _ = Clock::system().tick_interval(Instant::now(), Duration::ZERO);
    }

    #[tokio::test]
    async fn system_sleep_and_interval_use_tokio() {
        let clock = Clock::system();
        clock
            .sleep_until(clock.instant() + Duration::from_millis(1))
            .await;
        let mut interval = clock.tick_interval(clock.instant(), Duration::from_millis(1));
        interval.tick().await;
        interval.tick().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn settled_waits_for_the_woken_task() {
        let v = VirtualClock::new();
        let clock = Clock::from(v.clone());
        let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut sleep = clock.sleep_until(clock.instant() + Duration::from_secs(1));
        let task = tokio::spawn({
            let done = Arc::clone(&done);
            async move {
                (&mut sleep).await;
                // Work after the timer, before the sleep drops.
                std::thread::sleep(Duration::from_millis(50));
                done.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        });
        v.advance(Duration::from_secs(1));
        v.settled().await;
        assert!(done.load(std::sync::atomic::Ordering::SeqCst));
        task.await.unwrap();
    }

    #[test]
    fn epoch_ticks_count_crossed_boundaries() {
        let ms = Duration::from_millis;
        assert_eq!(epoch_ticks(ms(0), ms(99)), 0);
        assert_eq!(epoch_ticks(ms(99), ms(100)), 1);
        assert_eq!(epoch_ticks(ms(0), ms(30_050)), 300);
        assert_eq!(
            epoch_ticks(Duration::ZERO, Duration::from_secs(1_000_000)),
            MAX_EPOCH_TICKS_PER_ADVANCE
        );
    }

    #[test]
    fn advance_bumps_registered_engines() {
        let mut cfg = wasmtime::Config::new();
        cfg.epoch_interruption(true);
        let engine = Arc::new(WasmtimeEngine::new(&cfg).unwrap());
        let v = VirtualClock::new();
        Clock::from(v.clone()).drive_epoch(&engine);
        // Observable through a store deadline: armed at 2 ticks, it
        // is reached after 200 ms of virtual time, not before. The
        // module exports one empty function, `f`.
        let wasm: &[u8] = &[
            0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // header
            0x01, 0x04, 0x01, 0x60, 0x00, 0x00, // type: () -> ()
            0x03, 0x02, 0x01, 0x00, // func 0: type 0
            0x07, 0x05, 0x01, 0x01, b'f', 0x00, 0x00, // export "f"
            0x0a, 0x04, 0x01, 0x02, 0x00, 0x0b, // body: end
        ];
        let module = wasmtime::Module::new(&engine, wasm).unwrap();
        let mut store = wasmtime::Store::new(&engine, ());
        let instance = wasmtime::Instance::new(&mut store, &module, &[]).unwrap();
        let f = instance.get_typed_func::<(), ()>(&mut store, "f").unwrap();
        store.set_epoch_deadline(2);
        v.advance(Duration::from_millis(100));
        f.call(&mut store, ())
            .expect("one tick: before the deadline");
        v.advance(Duration::from_millis(100));
        let err = f.call(&mut store, ()).unwrap_err();
        assert_eq!(
            err.downcast_ref::<wasmtime::Trap>(),
            Some(&wasmtime::Trap::Interrupt)
        );
        drop(store);
        drop(engine);
        v.advance(Duration::from_millis(100));
        assert_eq!(v.lock().engines.len(), 0, "dead engines are pruned");
    }

    #[test]
    fn guest_clocks_read_virtual_time() {
        let v = VirtualClock::new();
        let wall = GuestWallClock(Arc::clone(&v.shared));
        let mono = GuestMonotonicClock(Arc::clone(&v.shared));
        assert_eq!(wall.now(), VIRTUAL_CLOCK_DEFAULT_START);
        assert_eq!(mono.now(), 0);
        v.advance(Duration::from_millis(250));
        assert_eq!(
            wall.now(),
            VIRTUAL_CLOCK_DEFAULT_START + Duration::from_millis(250)
        );
        assert_eq!(mono.now(), 250_000_000);
        assert_eq!(wall.resolution(), Duration::from_nanos(1));
        assert_eq!(mono.resolution(), 1);
        let mut builder = WasiCtxBuilder::new();
        Clock::from(v).configure_wasi(&mut builder);
        Clock::system().configure_wasi(&mut builder);

        // Before the epoch, guest and host agree once time passes it.
        let early = VirtualClock::starting_at(UNIX_EPOCH - Duration::from_secs(1));
        let wall = GuestWallClock(Arc::clone(&early.shared));
        assert_eq!(wall.now(), Duration::ZERO);
        early.advance(Duration::from_secs(2));
        assert_eq!(wall.now(), Duration::from_secs(1));
        assert_eq!(early.now_unix_ms(), 1000);
    }

    #[test]
    fn concurrent_advances_add_up() {
        let v = VirtualClock::new();
        std::thread::scope(|s| {
            for _ in 0..8 {
                s.spawn(|| {
                    for _ in 0..100 {
                        v.advance(Duration::from_millis(1));
                    }
                });
            }
        });
        assert_eq!(v.elapsed(), Duration::from_millis(800));
    }
}
