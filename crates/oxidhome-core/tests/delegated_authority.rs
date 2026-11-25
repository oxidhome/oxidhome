//! H6 slice 4 — delegation and events.
//!
//! Drives `service-bouncer` instances through the dispatcher under
//! external roots: every `call-service` hop needs the root's own
//! `service.call` permit (the `services:call` scope, or a role grant
//! naming the service) on top of the calling plugin's
//! `consumes_services` grant, and the root's denies refuse it. Events a
//! request causes carry its call id (live, and in `event_log`), and a
//! subscriber's `on-event` reaction records it as `caused_by` on its
//! own hop rows.

#[path = "support.rs"]
mod support;

use std::sync::Arc;
use std::time::{Duration, Instant};

use oxidhome_core::auth::{
    Action, ActionSet, ActorKind, DenyRule, InvocationContext, Principal, RoleDef, RoleGrant,
    TokenPolicy, Transport,
};
use oxidhome_core::host_impl::plugin::oxidhome::plugin::devices::CommandResult;
use oxidhome_core::host_impl::plugin::oxidhome::plugin::types::{
    Error as WitError, ServiceId, Value,
};
use oxidhome_core::runtime::dispatcher;
use oxidhome_core::state::{AuditEntry, AuditQuery, EventQuery};
use oxidhome_core::{Actor, Engine, InstanceHandle};

const PLUGIN: &str = "example.service-bouncer";

struct Bouncers {
    engine: Engine,
    instances: Vec<InstanceHandle>,
    _state: support::TempDir,
}

impl Bouncers {
    async fn start(names: &[&str]) -> Self {
        let _wasm = support::build_example("service-bouncer", "service_bouncer.wasm");
        let dir = support::workspace_root()
            .join("examples")
            .join("service-bouncer");
        let state = support::tempdir("delegated-authority");
        let engine = Engine::with_state_dir(state.path()).expect("engine");
        let mut instances = Vec::new();
        for name in names {
            let handle = engine
                .start_instance(dir.clone(), *name, None)
                .await
                .expect("start bouncer");
            handle.wait_for_running().await.expect("bouncer Running");
            instances.push(handle);
        }
        Self {
            engine,
            instances,
            _state: state,
        }
    }

    fn service(&self, owner: &str) -> ServiceId {
        self.engine
            .services()
            .list()
            .into_iter()
            .find(|m| m.owner_instance == owner)
            .expect("service registered")
            .id
            .clone()
    }

    fn set(&self, instance: &str, key: &str, value: String) {
        self.engine
            .kv()
            .set(PLUGIN, instance, key, Value::StringVal(value))
            .expect("kv set");
    }

    /// `kick` on `target` from a test driver whose own grant allows
    /// it, as an invocation rooted at `actor`.
    async fn kick_as(
        &self,
        actor: &Actor,
        target: &str,
    ) -> (String, Result<CommandResult, WitError>) {
        let grants = [oxidhome_manifest::ServiceGrant {
            plugin: PLUGIN.into(),
            instance: "*".into(),
            service: "bouncer".into(),
            commands: vec!["kick".into()],
            caller_instance: "*".into(),
        }];
        let root =
            InvocationContext::external(Principal::token(ActorKind::Api, actor, Transport::Rest));
        let call_id = root.call_id().to_owned();
        let outcome = dispatcher::call_service_from_host_in(
            &self.engine,
            root,
            "test-driver",
            &grants,
            &grants,
            self.service(target),
            "kick",
            Vec::new(),
        )
        .await;
        (call_id, outcome)
    }

    /// The `CALL` rows matching `query` once `n` of them are final.
    async fn hop_rows(&self, query: AuditQuery, n: usize) -> Vec<AuditEntry> {
        let audit = self.engine.audit_log();
        let started = Instant::now();
        loop {
            let mut rows: Vec<_> = audit
                .query(&query, 50)
                .expect("query")
                .into_iter()
                .filter(|r| r.method == dispatcher::SERVICE_CALL_AUDIT_METHOD)
                .collect();
            if rows.len() >= n && rows.iter().all(|r| r.finalized_ms.is_some()) {
                rows.sort_by_key(|r| r.id);
                return rows;
            }
            assert!(
                started.elapsed() < Duration::from_secs(10),
                "hop rows not final: {rows:?}"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    async fn stop(self) {
        for handle in self.instances {
            handle.stop().await.expect("stop");
        }
    }
}

fn by_call(call_id: &str) -> AuditQuery {
    AuditQuery {
        call_id: Some(call_id.to_owned()),
        ..AuditQuery::default()
    }
}

fn role(name: &str, grants: Vec<RoleGrant>, deny: Vec<DenyRule>) -> Arc<RoleDef> {
    Arc::new(RoleDef {
        id: "role-0123456789abcdef".into(),
        name: name.into(),
        grants,
        sensitive: Vec::new(),
        deny,
    })
}

fn service_grant(services: &[&str]) -> RoleGrant {
    RoleGrant {
        actions: ActionSet::of(&[Action::ServiceCall]),
        categories: None,
        devices: None,
        services: Some(services.iter().map(|s| (*s).to_owned()).collect()),
    }
}

/// A token without `services:call` can't have any hop made for it,
/// even though the calling plugin's grant allows the call; with the
/// scope (or the wildcard) both hops of the chain run.
#[tokio::test(flavor = "multi_thread")]
async fn every_hop_needs_the_roots_service_call_permit() {
    let b = Bouncers::start(&["alpha", "beta"]).await;
    b.set("alpha", "bounce_to", b.service("beta"));

    let narrow = Actor::api("tok-narrow", vec!["devices:command".into()]);
    let (call_id, outcome) = b.kick_as(&narrow, "alpha").await;
    assert!(
        matches!(&outcome, Err(WitError::PermissionDenied(m)) if m.contains("root principal")),
        "got {outcome:?}"
    );
    let rows = b.hop_rows(by_call(&call_id), 1).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].decision, "deny");
    assert_eq!(rows[0].status, 403);
    assert_eq!(rows[0].required_scope.as_deref(), Some("services:call"));
    assert_eq!(rows[0].token_id, "tok-narrow");

    for scopes in [vec!["services:call".to_string()], vec!["*".to_string()]] {
        let actor = Actor::api("tok-calls", scopes);
        let (call_id, outcome) = b.kick_as(&actor, "alpha").await;
        assert!(matches!(outcome, Ok(CommandResult::Ok)), "got {outcome:?}");
        let rows = b.hop_rows(by_call(&call_id), 2).await;
        assert!(rows.iter().all(|r| r.decision == "allow"), "{rows:?}");
    }
    b.stop().await;
}

/// A role grant narrows the delegation grant to the services it names;
/// the root's deny list refuses a hop whatever grants it, including on
/// an inner hop the first one led to.
#[tokio::test(flavor = "multi_thread")]
async fn role_grants_and_denies_follow_the_chain() {
    let b = Bouncers::start(&["alpha", "beta"]).await;
    b.set("alpha", "bounce_to", b.service("beta"));
    let base = Actor::api("tok-role", vec!["devices:read".into()]);

    // Named service: allowed on both hops.
    let actor = base.with_roles(vec![role(
        "scenes",
        vec![service_grant(&["example.service-*/bouncer"])],
        Vec::new(),
    )]);
    let (call_id, outcome) = b.kick_as(&actor, "alpha").await;
    assert!(matches!(outcome, Ok(CommandResult::Ok)), "got {outcome:?}");
    assert_eq!(b.hop_rows(by_call(&call_id), 2).await.len(), 2);

    // Another plugin's services only: refused with `no-permit`.
    let actor = base.with_roles(vec![role(
        "other",
        vec![service_grant(&["acme.notify"])],
        Vec::new(),
    )]);
    let (call_id, outcome) = b.kick_as(&actor, "alpha").await;
    assert!(
        matches!(outcome, Err(WitError::PermissionDenied(_))),
        "got {outcome:?}"
    );
    let rows = b.hop_rows(by_call(&call_id), 1).await;
    assert_eq!(rows[0].required_scope.as_deref(), Some("no-permit"));

    // The wildcard with a deny on the service: refused with `deny`.
    let policy = TokenPolicy {
        scopes: vec!["*".into()],
        deny: vec![DenyRule {
            actions: ActionSet::of(&[Action::ServiceCall]),
            categories: None,
            devices: None,
            services: Some(vec![format!("{PLUGIN}/bouncer")]),
        }],
        ..TokenPolicy::default()
    };
    let actor = Actor::from_token_policy("tok-deny", policy, false);
    let (call_id, outcome) = b.kick_as(&actor, "alpha").await;
    assert!(
        matches!(outcome, Err(WitError::PermissionDenied(_))),
        "got {outcome:?}"
    );
    let rows = b.hop_rows(by_call(&call_id), 1).await;
    assert_eq!(rows[0].required_scope.as_deref(), Some("deny"));

    // A deny that comes with a role refuses it too, even for the
    // wildcard.
    let actor = Actor::api("tok-role-deny", vec!["*".into()]).with_roles(vec![role(
        "no-bounce",
        Vec::new(),
        vec![DenyRule {
            actions: ActionSet::of(&[Action::ServiceCall]),
            categories: None,
            devices: None,
            services: None,
        }],
    )]);
    let (call_id, outcome) = b.kick_as(&actor, "alpha").await;
    assert!(
        matches!(outcome, Err(WitError::PermissionDenied(_))),
        "got {outcome:?}"
    );
    let rows = b.hop_rows(by_call(&call_id), 1).await;
    assert_eq!(rows[0].required_scope.as_deref(), Some("deny"));
    b.stop().await;
}

/// An event a request causes carries its call id, live and in history;
/// a subscriber's reaction runs host-rooted (its own grant decides,
/// the token's lack of `services:call` doesn't matter) and its hop row
/// names the request as `caused_by`.
#[tokio::test(flavor = "multi_thread")]
async fn reactions_record_what_caused_them() {
    let b = Bouncers::start(&["alpha", "beta", "gamma"]).await;
    // alpha announces; beta relays the announcement to gamma.
    b.set("alpha", "announce", "yes".into());
    b.set("beta", "relay_to", b.service("gamma"));

    let actor = Actor::api("tok-events", vec!["services:call".into()]);
    let (call_id, outcome) = b.kick_as(&actor, "alpha").await;
    assert!(matches!(outcome, Ok(CommandResult::Ok)), "got {outcome:?}");

    // The announcement is in history with the request's call id.
    let events = b
        .engine
        .event_log()
        .query(
            &EventQuery {
                instance_id: Some("alpha".into()),
                ..EventQuery::default()
            },
            10,
        )
        .expect("history");
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0].call_id.as_deref(), Some(call_id.as_str()));

    // beta's reaction: one hop to gamma, its own call id, caused by
    // the request, attributed to beta (host-rooted).
    let rows = b
        .hop_rows(
            AuditQuery {
                caused_by: Some(call_id.clone()),
                ..AuditQuery::default()
            },
            1,
        )
        .await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    let row = &rows[0];
    assert_eq!(row.decision, "allow");
    assert_eq!(row.caused_by.as_deref(), Some(call_id.as_str()));
    assert_ne!(row.call_id.as_deref(), Some(call_id.as_str()));
    assert_eq!(row.token_id, "beta");
    assert_eq!(row.actor_kind, "plugin");
    assert_eq!(
        row.path,
        "service.call/example.service-bouncer/gamma/bouncer/kick"
    );
    b.stop().await;
}

/// Work the host starts on its own stamps no call id, so a reaction to
/// it stays out of the ledger.
#[tokio::test(flavor = "multi_thread")]
async fn host_rooted_events_are_not_attributed() {
    let b = Bouncers::start(&["alpha", "beta", "gamma"]).await;
    b.set("alpha", "announce", "yes".into());
    b.set("beta", "relay_to", b.service("gamma"));
    let grants = [oxidhome_manifest::ServiceGrant {
        plugin: PLUGIN.into(),
        instance: "*".into(),
        service: "bouncer".into(),
        commands: vec!["kick".into()],
        caller_instance: "*".into(),
    }];
    let outcome = dispatcher::call_service_from_host(
        &b.engine,
        "test-driver",
        &grants,
        &grants,
        b.service("alpha"),
        "kick",
        Vec::new(),
    )
    .await;
    assert!(matches!(outcome, Ok(CommandResult::Ok)), "got {outcome:?}");
    let events = b
        .engine
        .event_log()
        .query(
            &EventQuery {
                instance_id: Some("alpha".into()),
                ..EventQuery::default()
            },
            10,
        )
        .expect("history");
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0].call_id, None);
    // Give beta's reaction time to run; it writes no row.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let rows: Vec<_> = b
        .engine
        .audit_log()
        .query(&AuditQuery::default(), 50)
        .expect("query")
        .into_iter()
        .filter(|r| r.method == dispatcher::SERVICE_CALL_AUDIT_METHOD)
        .collect();
    assert!(rows.is_empty(), "{rows:?}");
    b.stop().await;
}
