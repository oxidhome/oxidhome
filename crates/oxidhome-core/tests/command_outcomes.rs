//! H5 follow-ups (ADR-0003 implementation notes): pending `accepted`
//! commands survive a daemon restart, queued commands refused by a
//! restarting or terminal supervisor are audited when their caller has
//! gone, and service calls carry the same dispatch ticket as device
//! commands.

#[path = "support.rs"]
mod support;

use std::future::Future as _;
use std::time::Duration;

use oxidhome_core::auth::{ActorKind, InvocationContext, Principal, Transport};
use oxidhome_core::host_impl::plugin::oxidhome::plugin::devices::{Command, CommandResult};
use oxidhome_core::host_impl::plugin::oxidhome::plugin::types::{
    Error as WitError, KeyValue, Value,
};
use oxidhome_core::runtime::LoadMode;
use oxidhome_core::runtime::dispatcher;
use oxidhome_core::state::{AuditEntry, AuditQuery};
use oxidhome_core::{
    Actor, CommandOutcome, Engine, InstanceHandle, InstanceState, SupervisorTuning,
};

fn api_root() -> InvocationContext {
    let actor = Actor::api("tok-h5", vec!["*".into()]);
    InvocationContext::external(Principal::token(ActorKind::Api, &actor, Transport::Rest))
}

fn toggle(lost: bool) -> Command {
    let args = if lost {
        vec![KeyValue {
            key: "lost".into(),
            value: Value::BoolVal(true),
        }]
    } else {
        Vec::new()
    };
    Command {
        id: String::new(),
        capability: "switch".into(),
        action: "toggle".into(),
        args,
    }
}

fn first_device_of(engine: &Engine, instance: &str) -> String {
    engine
        .devices()
        .list()
        .into_iter()
        .find(|m| m.owner_instance == instance)
        .expect("instance registered a device")
        .id
        .clone()
}

/// The `COMMAND` rows of `engine`'s ledger matching `pick`.
fn command_rows(engine: &Engine, pick: impl Fn(&AuditEntry) -> bool) -> Vec<AuditEntry> {
    engine
        .audit_log()
        .query(&AuditQuery::default(), 500)
        .expect("audit")
        .into_iter()
        .filter(|r| r.method == "COMMAND" && pick(r))
        .collect()
}

/// Poll until a `COMMAND` row matching `pick` lands.
async fn command_row(engine: &Engine, pick: impl Fn(&AuditEntry) -> bool) -> AuditEntry {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(row) = command_rows(engine, &pick).into_iter().next() {
            return row;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "no matching COMMAND row"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn start_deferred(engine: &Engine) -> (InstanceHandle, String) {
    let _wasm = support::build_example("deferred-switch", "deferred_switch.wasm");
    let dir = support::workspace_root()
        .join("examples")
        .join("deferred-switch");
    let handle = engine
        .start_instance(dir, "deferred", None)
        .await
        .expect("start");
    handle.wait_for_running().await.expect("running");
    let device = first_device_of(engine, "deferred");
    (handle, device)
}

/// A daemon that stops while an externally-rooted `accepted` command is
/// pending (here: a second process opening the same state dir, as the
/// restarted daemon would) resolves it at boot: a `COMMAND` row with
/// `outcome_unknown`, `domain_error = daemon_restart`, and the request's
/// call id. A command the plugin completed first leaves nothing to
/// reconcile.
#[tokio::test(flavor = "multi_thread")]
async fn pending_command_is_resolved_after_a_daemon_restart() {
    let state_dir = support::tempdir("h5-restart");
    let engine = Engine::with_state_dir(state_dir.path()).expect("engine");
    let (handle, device) = start_deferred(&engine).await;

    // Completed by the plugin's next tick.
    let done_root = api_root();
    let done = handle
        .execute_command_in(done_root, device.clone(), toggle(false))
        .await;
    assert!(matches!(done.outcome, CommandOutcome::Accepted), "{done:?}");
    let completed = command_row(&engine, |r| {
        r.command_id.as_deref() == Some(done.command_id.as_str())
    })
    .await;
    assert_eq!(completed.command_outcome.as_deref(), Some("completed"));

    // Never completed.
    let lost_root = api_root();
    let call_id = lost_root.call_id().to_owned();
    let lost = handle
        .execute_command_in(lost_root, device.clone(), toggle(true))
        .await;
    assert!(matches!(lost.outcome, CommandOutcome::Accepted), "{lost:?}");
    assert!(
        engine
            .pending_commands()
            .flush_journal(Duration::from_secs(5))
    );

    // The "restarted daemon". The first engine is left as a crashed
    // process would be: its instance never stops.
    let restarted = Engine::with_state_dir(state_dir.path()).expect("restarted engine");
    let rows = command_rows(&restarted, |r| {
        r.domain_error.as_deref() == Some("daemon_restart")
    });
    assert_eq!(rows.len(), 1, "{rows:?}");
    let row = &rows[0];
    assert_eq!(row.command_id.as_deref(), Some(lost.command_id.as_str()));
    assert_eq!(row.command_outcome.as_deref(), Some("outcome_unknown"));
    assert_eq!(row.call_id.as_deref(), Some(call_id.as_str()));
    assert_eq!(row.token_id, "tok-h5");
    assert_eq!(row.path, format!("device.command/{device}"));
    assert_eq!(row.decision, "allow");
    // Exactly one final row for the completed command.
    let done_rows = command_rows(&restarted, |r| {
        r.command_id.as_deref() == Some(done.command_id.as_str())
    });
    assert_eq!(done_rows.len(), 1, "{done_rows:?}");

    // The old process's instance stopping late (its journal outliving
    // the takeover) must not add a second final row.
    handle.stop().await.expect("stop");
    engine.drain_supervised_instances().await;
    assert!(engine.close_command_journal(Duration::from_secs(5)));
    let finals = command_rows(&restarted, |r| {
        r.command_id.as_deref() == Some(lost.command_id.as_str())
    });
    assert_eq!(finals.len(), 1, "one final row per command: {finals:?}");

    // Reconciled once: a further restart finds nothing.
    drop(restarted);
    let again = Engine::with_state_dir(state_dir.path()).expect("third engine");
    assert_eq!(
        command_rows(&again, |r| r.domain_error.as_deref()
            == Some("daemon_restart"))
        .len(),
        1
    );
}

/// A clean stop expires the instance's pending commands
/// (`instance_stopped`) and deletes their persisted rows, so the next
/// boot has nothing to reconcile.
#[tokio::test(flavor = "multi_thread")]
async fn clean_stop_leaves_nothing_to_reconcile() {
    let state_dir = support::tempdir("h5-clean-stop");
    let engine = Engine::with_state_dir(state_dir.path()).expect("engine");
    let (handle, device) = start_deferred(&engine).await;
    let report = handle
        .execute_command_in(api_root(), device, toggle(true))
        .await;
    assert!(matches!(report.outcome, CommandOutcome::Accepted));
    handle.stop().await.expect("stop");
    engine.drain_supervised_instances().await;
    assert!(engine.close_command_journal(Duration::from_secs(5)));
    let stopped = command_rows(&engine, |r| {
        r.command_id.as_deref() == Some(report.command_id.as_str())
    });
    assert_eq!(stopped.len(), 1, "{stopped:?}");
    assert_eq!(stopped[0].domain_error.as_deref(), Some("instance_stopped"));
    assert_eq!(
        stopped[0].command_outcome.as_deref(),
        Some("outcome_unknown")
    );

    let restarted = Engine::with_state_dir(state_dir.path()).expect("restarted engine");
    assert_eq!(
        command_rows(&restarted, |r| r.domain_error.as_deref()
            == Some("daemon_restart")),
        Vec::<AuditEntry>::new()
    );
}

/// The stop expiry is queued before the terminal state is published:
/// a journal closed as soon as the instance is terminal, without
/// waiting for the reaper, already holds it.
#[tokio::test(flavor = "multi_thread")]
async fn stop_expiry_is_queued_before_the_terminal_state() {
    let state_dir = support::tempdir("h5-stop-order");
    let engine = Engine::with_state_dir(state_dir.path()).expect("engine");
    let (handle, device) = start_deferred(&engine).await;
    let report = handle
        .execute_command_in(api_root(), device, toggle(true))
        .await;
    assert!(matches!(report.outcome, CommandOutcome::Accepted));
    handle.stop().await.expect("stop");
    assert!(matches!(
        handle.wait_terminal().await,
        InstanceState::Stopped
    ));
    assert!(engine.close_command_journal(Duration::from_secs(5)));
    let stopped = command_rows(&engine, |r| {
        r.command_id.as_deref() == Some(report.command_id.as_str())
    });
    assert_eq!(stopped.len(), 1, "{stopped:?}");
    assert_eq!(stopped[0].domain_error.as_deref(), Some("instance_stopped"));
}

/// Enqueue `cmd` for `handle` under `root` and drop the caller right
/// after: the client disconnected while the command was queued.
async fn enqueue_and_disconnect(handle: &InstanceHandle, root: InvocationContext, device: String) {
    let send = handle.execute_command_in(root, device, toggle(false));
    let mut send = std::pin::pin!(send);
    // One poll enqueues the command; dropping the future right after,
    // with no await in between, is the caller leaving before any reply.
    let polled = std::future::poll_fn(|cx| std::task::Poll::Ready(send.as_mut().poll(cx))).await;
    if let std::task::Poll::Ready(report) = polled {
        panic!("the command was answered before the caller left: {report:?}");
    }
}

/// A command queued while the instance waits out a restart backoff is
/// refused (`rejected`, or `timed_out` once its caller is gone); when
/// its caller already disconnected, the refusal is still audited as a
/// `COMMAND` row. A current-thread
/// runtime keeps the supervisor from answering before the caller drops.
#[tokio::test(flavor = "current_thread")]
async fn command_refused_in_restart_backoff_is_audited_for_a_gone_caller() {
    let _wasm = support::build_example("crasher", "crasher.wasm");
    let dir = support::workspace_root().join("examples").join("crasher");
    let engine = Engine::new().expect("engine");
    let overrides: toml::Value = toml::from_str("crash_on = \"command\"").unwrap();
    let handle = engine
        .start_instance_with_tuning(
            dir,
            "crasher",
            Some(overrides),
            LoadMode::Dev,
            SupervisorTuning {
                backoff_base: Duration::from_mins(1),
                backoff_max: Duration::from_mins(1),
                ..SupervisorTuning::default()
            },
        )
        .await
        .expect("start");
    handle.wait_for_running().await.expect("running");
    let device = first_device_of(&engine, "crasher");

    // The trap sends the instance into its restart backoff.
    let first = handle.execute_command(device.clone(), toggle(false)).await;
    assert!(matches!(first.outcome, CommandOutcome::Unknown { .. }));
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while !matches!(handle.state(), InstanceState::Restarting { .. }) {
        assert!(tokio::time::Instant::now() < deadline, "never restarting");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let root = api_root();
    let call_id = root.call_id().to_owned();
    enqueue_and_disconnect(&handle, root, device.clone()).await;
    let row = command_row(&engine, |r| r.call_id.as_deref() == Some(call_id.as_str())).await;
    // The caller was gone before the refusal: `timed_out` (it never
    // ran, safe to retry), as for a stop refusing its queue.
    assert_eq!(row.command_outcome.as_deref(), Some("timed_out"));
    assert_eq!(row.path, format!("device.command/{device}"));
    assert!(
        row.command_id
            .as_deref()
            .is_some_and(|id| id.starts_with("cmd-"))
    );
    handle.stop().await.expect("stop");
}

/// A command still queued when its supervisor goes terminal is refused
/// rather than dropped; a gone caller's refusal is audited. The first
/// command wedges the `hang` plugin until the watchdog fails it, with
/// the second one queued behind.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn command_queued_at_a_terminal_supervisor_is_audited_for_a_gone_caller() {
    let _wasm = support::build_example("hang", "hang.wasm");
    let dir = support::workspace_root().join("examples").join("hang");
    let engine = Engine::new().expect("engine");
    let overrides: toml::Value = toml::from_str("phase = \"command\"").unwrap();
    let handle = engine
        .start_instance_with_tuning(
            dir,
            "hang",
            Some(overrides),
            LoadMode::Dev,
            SupervisorTuning {
                watchdog: Duration::from_secs(2),
                max_restarts: 0,
                ..SupervisorTuning::default()
            },
        )
        .await
        .expect("start");
    handle.wait_for_running().await.expect("running");
    let device = first_device_of(&engine, "hang");

    let wedged = tokio::spawn({
        let handle = handle.clone();
        let device = device.clone();
        async move { handle.execute_command(device, toggle(false)).await }
    });
    // Let the supervisor enter the spinning command.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let root = api_root();
    let call_id = root.call_id().to_owned();
    enqueue_and_disconnect(&handle, root, device).await;

    let wedged = wedged.await.expect("join");
    assert!(
        matches!(wedged.outcome, CommandOutcome::Unknown { .. }),
        "{wedged:?}"
    );
    assert!(matches!(
        handle.wait_terminal().await,
        InstanceState::Failed { .. }
    ));
    let row = command_row(&engine, |r| r.call_id.as_deref() == Some(call_id.as_str())).await;
    // The caller was gone before the refusal: `timed_out` (it never
    // ran, safe to retry), as for a stop refusing its queue.
    assert_eq!(row.command_outcome.as_deref(), Some("timed_out"));
}

/// H5 for `call-service`: a call whose deadline passes after the
/// callee started answers `unknown` (it may have acted); a call whose
/// deadline passes while it waits in the callee's queue answers
/// `unavailable` (it never ran, safe to retry). The hop rows record the
/// same split.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)] // one linear end-to-end narrative
async fn service_call_timeout_is_unknown_once_started_and_unavailable_while_queued() {
    let _wasm = support::build_example("hang", "hang.wasm");
    let dir = support::workspace_root().join("examples").join("hang");
    let engine = Engine::new().expect("engine");
    let overrides: toml::Value = toml::from_str("phase = \"service\"").unwrap();
    let handle = engine
        .start_instance_with_tuning(
            dir,
            "spinner",
            Some(overrides),
            LoadMode::Dev,
            SupervisorTuning {
                watchdog: Duration::from_secs(3),
                max_restarts: 0,
                ..SupervisorTuning::default()
            },
        )
        .await
        .expect("start");
    handle.wait_for_running().await.expect("running");
    let service = engine.services().list()[0].id.clone();
    let grants = [oxidhome_manifest::ServiceGrant {
        plugin: "example.hang".into(),
        instance: "*".into(),
        service: "spinner".into(),
        commands: vec!["spin".into()],
        caller_instance: "*".into(),
    }];
    let call = |deadline: Duration| {
        let engine = engine.clone();
        let service = service.clone();
        let root = api_root().with_deadline(Some(tokio::time::Instant::now() + deadline));
        let call_id = root.call_id().to_owned();
        let grants = grants.clone();
        let task = tokio::spawn(async move {
            dispatcher::call_service_from_host_in(
                &engine,
                root,
                "test-driver",
                &grants,
                &grants,
                service,
                "spin",
                Vec::new(),
            )
            .await
        });
        (call_id, task)
    };

    let (running_id, running) = call(Duration::from_millis(1500));
    tokio::time::sleep(Duration::from_millis(300)).await;
    let (queued_id, queued) = call(Duration::from_millis(300));

    // Both answers come from the reply deadlines, well before the 3 s
    // watchdog ends the spinning call.
    let started_at = tokio::time::Instant::now();
    match queued.await.expect("join") {
        Err(WitError::Unavailable(message)) => {
            assert!(
                message.contains("before the callee started it; it did not run"),
                "{message}"
            );
        }
        other => panic!("expected unavailable, got {other:?}"),
    }
    // The withdrawn call, still queued behind the spinning one, no
    // longer counts as in flight: only the running call does.
    assert_eq!(engine.services().active_call_count(&service), 1);
    match running.await.expect("join") {
        Ok(CommandResult::Unknown(message)) => {
            assert!(
                message.contains("deadline passed while instance"),
                "{message}"
            );
        }
        other => panic!("expected unknown, got {other:?}"),
    }
    assert!(
        started_at.elapsed() < Duration::from_secs(2),
        "the replies waited for the watchdog"
    );

    let hop = |call_id: String| {
        let engine = engine.clone();
        async move {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
            loop {
                let rows = engine
                    .audit_log()
                    .query(
                        &AuditQuery {
                            call_id: Some(call_id.clone()),
                            ..AuditQuery::default()
                        },
                        10,
                    )
                    .expect("audit");
                if let Some(row) = rows.into_iter().find(|r| r.finalized_ms.is_some()) {
                    return row;
                }
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "hop row never finalized"
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
    };
    let started = hop(running_id).await;
    assert_eq!(started.decision, "allow", "{started:?}");
    assert_eq!(started.execution_outcome, None);
    let never_ran = hop(queued_id).await;
    assert_eq!(never_ran.decision, "error", "{never_ran:?}");
    assert_eq!(never_ran.status, 503);

    assert!(matches!(
        handle.wait_terminal().await,
        InstanceState::Failed { .. }
    ));
}

/// A caller cancelled mid-`call-service` (its future dropped) still
/// gets its hop row finalized from the dispatch ticket: `allow` with no
/// execution outcome once the callee started, `error` / 503 while the
/// call was still queued (and it then never runs).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)] // one linear end-to-end narrative
async fn cancelled_service_caller_finalizes_its_hop_row() {
    let _wasm = support::build_example("hang", "hang.wasm");
    let dir = support::workspace_root().join("examples").join("hang");
    let engine = Engine::new().expect("engine");
    let overrides: toml::Value = toml::from_str("phase = \"service\"").unwrap();
    let handle = engine
        .start_instance_with_tuning(
            dir,
            "spinner",
            Some(overrides),
            LoadMode::Dev,
            SupervisorTuning {
                watchdog: Duration::from_secs(3),
                max_restarts: 0,
                ..SupervisorTuning::default()
            },
        )
        .await
        .expect("start");
    handle.wait_for_running().await.expect("running");
    let service = engine.services().list()[0].id.clone();
    let grants = [oxidhome_manifest::ServiceGrant {
        plugin: "example.hang".into(),
        instance: "*".into(),
        service: "spinner".into(),
        commands: vec!["spin".into()],
        caller_instance: "*".into(),
    }];
    let call = || {
        let engine = engine.clone();
        let service = service.clone();
        let root =
            api_root().with_deadline(Some(tokio::time::Instant::now() + Duration::from_secs(10)));
        let call_id = root.call_id().to_owned();
        let grants = grants.clone();
        let task = tokio::spawn(async move {
            dispatcher::call_service_from_host_in(
                &engine,
                root,
                "test-driver",
                &grants,
                &grants,
                service,
                "spin",
                Vec::new(),
            )
            .await
        });
        (call_id, task)
    };
    let hop = |call_id: String| {
        let engine = engine.clone();
        async move {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
            loop {
                let rows = engine
                    .audit_log()
                    .query(
                        &AuditQuery {
                            call_id: Some(call_id.clone()),
                            ..AuditQuery::default()
                        },
                        10,
                    )
                    .expect("audit");
                if let Some(row) = rows.into_iter().find(|r| r.finalized_ms.is_some()) {
                    return row;
                }
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "hop row never finalized"
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
    };

    let (running_id, running) = call();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let (queued_id, queued) = call();
    // Both calls hold their refcount, so both are past their hop's
    // intent write and dispatched.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while engine.services().active_call_count(&service) < 2 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "calls never dispatched"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    // Give the supervisor time to enter the first call.
    tokio::time::sleep(Duration::from_millis(100)).await;
    queued.abort();
    running.abort();

    // Both rows are finalized long before the 3 s watchdog ends the
    // spinning call.
    let started_at = tokio::time::Instant::now();
    let never_ran = hop(queued_id).await;
    assert_eq!(never_ran.decision, "error", "{never_ran:?}");
    assert_eq!(never_ran.status, 503);
    let started = hop(running_id).await;
    assert_eq!(started.decision, "allow", "{started:?}");
    assert_eq!(started.execution_outcome, None);
    assert!(
        started_at.elapsed() < Duration::from_secs(2),
        "the hop rows waited for the watchdog"
    );
    // The withdrawn call holds no refcount; only the spinning one does.
    assert_eq!(engine.services().active_call_count(&service), 1);

    assert!(matches!(
        handle.wait_terminal().await,
        InstanceState::Failed { .. }
    ));
}
