//! The `warn` audit row of an allowed sensitive action.
//!
//! [`crate::auth::authorize()`] stays a pure decision. An allow whose
//! [`Decision::sensitive`] names categories is recorded with one
//! completed row at `level = warn` before the action: `path`
//! `authz.<action>:<target>`, `decision = allow`, `required_scope` the
//! categories (`sensitive:lock`, or `owner:lock` for the owner token),
//! and the invocation's `call_id`, so `GET /api/v1/audit?call_id=…`
//! joins it to the request's own row.
//!
//! A device command's row is written by the supervisor once the
//! command has won `queued → started` and passed re-authorization,
//! durably, and the command doesn't run if it can't be written. Byte
//! releases inside reads (camera `bytes-val` in state, events and
//! command results) are recorded once per response or stream
//! (`api::bytes::BytesGate`), best-effort.

use super::authorize::{Action, Decision, Reason};
use super::invocation::InvocationContext;
use crate::state::audit_log::AUDIT_LEVEL_WARN;
use crate::state::{AuditEntry, AuditLog, AuditLogError};

/// Audit `method` of the `warn` row a sensitive allow writes.
pub const AUDIT_METHOD_AUTHZ: &str = "AUTHZ";

/// Write the `warn` row for `decision` (an allow on sensitive
/// categories) of `action` on `target`. A command's row commits at
/// `synchronous = FULL`: a lock that moved must not lose its record to
/// a power cut.
///
/// # Errors
///
/// The audit write failed.
pub fn record(
    audit: &AuditLog,
    ctx: &InvocationContext,
    action: Action,
    target: &str,
    decision: &Decision,
) -> Result<u64, AuditLogError> {
    let root = ctx.root();
    let prefix = if decision.reason == Reason::Owner {
        "owner"
    } else {
        "sensitive"
    };
    let label = format!("{prefix}:{}", decision.sensitive.to_csv());
    tracing::warn!(
        target: "auth.sensitive",
        token_id = root.audit_token_id(),
        transport = root.transport().as_str(),
        call_id = ctx.call_id(),
        action = action.as_str(),
        target = super::invocation::audit_cap(target),
        grant = %label,
        "sensitive action allowed",
    );
    let entry = AuditEntry {
        id: 0,
        intent_ms: 0,
        finalized_ms: None,
        token_id: root.audit_token_id().to_owned(),
        actor_kind: root.kind().as_str().to_owned(),
        method: AUDIT_METHOD_AUTHZ.to_owned(),
        path: format!(
            "authz.{}:{}",
            action.as_str(),
            super::invocation::audit_cap(target)
        ),
        status: 200,
        decision: "allow".to_owned(),
        required_scope: Some(label),
        execution_outcome: None,
        domain_error: None,
        credential_fp: None,
        call_id: Some(ctx.call_id().to_owned()),
        invocation: Some(ctx.audit_json()),
        command_id: None,
        command_outcome: None,
        level: Some(AUDIT_LEVEL_WARN.to_owned()),
        caused_by: None,
    };
    if action == Action::DeviceCommand {
        audit.record_completed_durable(&entry)
    } else {
        audit.record_completed(&entry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::role::RoleDef;
    use crate::auth::{
        Actor, ActorKind, DeviceCategory, DeviceClass, Principal, Resource, Transport, authorize,
    };
    use crate::state::{AuditQuery, Db};
    use std::sync::Arc;

    #[test]
    fn writes_a_warn_row_linked_by_call_id() {
        let audit = AuditLog::new(Arc::new(Db::open_in_memory().expect("db")));
        let role = RoleDef::parse(
            "locks",
            br#"[{"actions":["device.command"],"category":["lock"]}]"#,
        )
        .expect("role");
        let actor = Actor::api("tok-lock", vec![Arc::new(role)]);
        let ctx =
            InvocationContext::external(Principal::token(ActorKind::Api, &actor, Transport::Rest));
        let resource = Resource::device(
            "dev-0000000000000001",
            DeviceClass::of(DeviceCategory::Lock),
        );
        let decision = authorize(&ctx, Action::DeviceCommand, &resource);
        assert!(decision.allow);
        record(
            &audit,
            &ctx,
            Action::DeviceCommand,
            "dev-0000000000000001",
            &decision,
        )
        .expect("recorded");
        let rows = audit
            .query(
                &AuditQuery {
                    level: Some("warn".into()),
                    ..AuditQuery::default()
                },
                10,
            )
            .expect("query");
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row.token_id, "tok-lock");
        assert_eq!(row.method, AUDIT_METHOD_AUTHZ);
        assert_eq!(row.path, "authz.device.command:dev-0000000000000001");
        assert_eq!(row.decision, "allow");
        assert_eq!(row.required_scope.as_deref(), Some("sensitive:lock"));
        assert_eq!(row.call_id.as_deref(), Some(ctx.call_id()));
        assert_eq!(row.level.as_deref(), Some("warn"));
    }
}
