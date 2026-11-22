//! [`block_on`] — drive the harness from a plain `#[test]`.

use std::future::Future;
use std::sync::OnceLock;

/// Run `future` to completion on the harness's shared Tokio runtime
/// and return its output, so a synchronous `#[test]` can use the
/// `async` API:
///
/// ```no_run
/// use oxidhome_test_host::{TestHost, block_on};
///
/// #[test]
/// fn counts_ticks() {
///     let host = TestHost::new().unwrap();
///     let mut counter = block_on(host.load("path/to/kv-counter")).unwrap();
///     block_on(counter.init()).unwrap();
///     block_on(counter.tick()).unwrap();
/// }
/// ```
///
/// Every call uses the same process-wide multi-threaded runtime
/// (built on first use, two worker threads), so tasks spawned during
/// one call — the supervisor of a [`crate::SupervisedInstance`],
/// say — keep running between calls and in later ones. Calls from
/// several test threads at once are fine.
///
/// # Panics
///
/// When called from inside an async context (a `#[tokio::test]` or
/// another `block_on`): there, `.await` the future instead. Also if
/// the runtime can't be built.
pub fn block_on<F: Future>(future: F) -> F::Output {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RUNTIME
        .get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_name("oxidhome-test-host")
                .enable_all()
                .build()
                .expect("building the oxidhome-test-host runtime")
        })
        .block_on(future)
}
