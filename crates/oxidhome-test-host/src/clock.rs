//! Driving a [`VirtualClock`]: step it through its timers in order and
//! wait for the tasks they wake.

use std::time::Duration;

use oxidhome_core::VirtualClock;

use crate::TestHostError;

/// How long (in real time) [`settle`] waits for woken tasks before it
/// gives up with [`TestHostError::ClockStalled`].
pub(crate) const SETTLE_LIMIT: Duration = Duration::from_secs(30);

/// Wait until the work the clock's current time triggered is done:
/// every due timer fired, every tick interval that fired is waited on
/// again, and every sleep that fired was dropped (see
/// [`VirtualClock::is_settled`]).
pub(crate) async fn settle(clock: &VirtualClock) -> Result<(), TestHostError> {
    tokio::time::timeout(SETTLE_LIMIT, clock.settled())
        .await
        .map_err(|_| TestHostError::ClockStalled {
            elapsed: clock.elapsed(),
            limit: SETTLE_LIMIT,
        })
}

/// Fire, in order, every timer due at or before `until` (time since
/// the clock started), settling after each step. Leaves the clock at
/// the last timer it fired, or where it was.
pub(crate) async fn run_timers_until(
    clock: &VirtualClock,
    until: Duration,
) -> Result<(), TestHostError> {
    loop {
        settle(clock).await?;
        match clock.next_deadline() {
            // Settled, so every registered timer is in the future.
            Some(at) if at <= until => clock.advance_to(at),
            _ => return Ok(()),
        }
    }
}

/// Move the clock to `target`, firing the timers on the way one
/// deadline at a time.
pub(crate) async fn advance_to(
    clock: &VirtualClock,
    target: Duration,
) -> Result<(), TestHostError> {
    run_timers_until(clock, target).await?;
    clock.advance_to(target);
    settle(clock).await
}
