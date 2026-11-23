//! Driving a [`VirtualClock`]: step it through its timers in order and
//! wait for the tasks they wake.

use std::time::Duration;

use oxidhome_core::VirtualClock;

use crate::TestHostError;

/// How long (in real time) [`settle`] waits for woken tasks before it
/// gives up with [`TestHostError::ClockStalled`].
pub(crate) const SETTLE_LIMIT: Duration = Duration::from_secs(30);

/// Wait until the work the clock's current time triggered has been
/// picked up: every due timer fired and every tick interval that
/// fired is waited on again (see [`VirtualClock::is_settled`]). When a
/// one-shot timer fired, also give its task a moment to run the code
/// after it.
pub(crate) async fn settle(clock: &VirtualClock) -> Result<(), TestHostError> {
    let deadline = tokio::time::Instant::now() + SETTLE_LIMIT;
    loop {
        if tokio::time::timeout_at(deadline, clock.settled())
            .await
            .is_err()
        {
            return Err(TestHostError::ClockStalled {
                elapsed: clock.elapsed(),
                limit: SETTLE_LIMIT,
            });
        }
        if clock.take_fired() == 0 {
            return Ok(());
        }
        // The task that awaited the timer runs on in the same poll;
        // let it (and anything it woke) finish, then check again.
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
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
