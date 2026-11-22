//! Host-only invocation context (architecture-review H6).
//!
//! An [`Actor`] answers "is this credential allowed to call this
//! route?". It says nothing about *what happens next*: before H6, once a
//! REST / Connect / MCP request entered a plugin's `execute-command`,
//! the initiating credential was gone, and any `call-service` the
//! plugin made was attributed only to the plugin instance.
//!
//! [`InvocationContext`] is the value that survives that boundary. It
//! is minted once per external entry point (one authenticated REST /
//! Connect request, one MCP `tools/call`) and carries:
//!
//! - a **call id** (`call-<32 hex>`) — written on the entry point's
//!   audit row and on every downstream audit row the invocation causes,
//!   so `GET /api/v1/audit?call_id=…` reconstructs the whole tree;
//! - the **root principal** ([`Principal`]) — subject, credential id
//!   and transport modelled as separate fields instead of being folded
//!   into `Actor.id`;
//! - the **current executing actor** — the plugin instance whose wasm
//!   is running on behalf of the root;
//! - a **deadline** — work that is still queued when it passes is
//!   refused instead of executed late, and nested `call-service` hops
//!   wait at most the remaining budget;
//! - the **delegation chain** — one [`DelegationHop`] per
//!   `call-service` hop, outermost first. The dispatcher's cycle
//!   detection reads the same chain.
//!
//! The context is host-only: it is never serialized into the WIT
//! surface, so a plugin can neither read nor forge it. It rides the
//! supervisor control messages across the task hop and is installed as
//! a `tokio::task_local` (`CURRENT`) while the instance's wasm runs,
//! so host imports executed on that task see it. The
//! `plugin.execute_command` / `plugin.execute_service_command` tracing
//! spans record its `call_id`.
//!
//! Work that starts inside the host (plugin `init`, `tick`, `on-event`,
//! and test drivers that call `InstanceHandle::execute_command`) runs
//! under a [`Transport::Host`] context rooted at the plugin instance
//! itself. Those invocations are not externally attributable, so the
//! dispatcher keeps them out of the audit ledger (they are traced
//! only), which keeps ledger volume proportional to external requests.

use std::sync::Arc;
use std::time::Duration;

use rand::TryRng;
use tokio::task_local;
use tokio::time::Instant;

use super::{Actor, ActorKind};

/// Deadline budget granted to an externally-rooted invocation. Bounds
/// how long a command may sit in a supervisor queue before it is
/// refused, and caps every nested `call-service` wait to what is left.
/// Deliberately larger than the per-hop `DISPATCH_TIMEOUT` (30 s) so a
/// single slow hop still gets its full window.
pub const EXTERNAL_INVOCATION_DEADLINE: Duration = Duration::from_mins(1);

/// How the root principal reached the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Transport {
    /// JSON REST surface (`/api/v1/*`).
    Rest,
    /// Connect RPC surface (Connect JSON, gRPC, gRPC-Web).
    Connect,
    /// MCP over streamable HTTP (`/api/v1/mcp`).
    McpHttp,
    /// MCP over stdio, authorized by the parent process.
    McpStdio,
    /// Started inside the host: plugin lifecycle (`init`, `tick`,
    /// `on-event`) or a host-side driver. Not externally attributable.
    Host,
}

impl Transport {
    /// Stable name for audit and tracing output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Transport::Rest => "rest",
            Transport::Connect => "connect",
            Transport::McpHttp => "mcp-http",
            Transport::McpStdio => "mcp-stdio",
            Transport::Host => "host",
        }
    }
}

/// The principal an invocation is attributed to. Separates the
/// *subject* (who), the *credential* that proved it (which token), and
/// the *transport* it arrived on — the three things `Actor.id` used to
/// stand in for at once.
///
/// There is no per-person identity yet, so for bearer tokens the
/// subject is the token id; a future user model changes the subject
/// without touching `credential_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    kind: ActorKind,
    subject: String,
    credential_id: Option<String>,
    transport: Transport,
}

impl Principal {
    /// Principal for a caller that authenticated with a bearer token.
    /// `kind` is the audit actor kind the transport records (`api` for
    /// REST / Connect, `mcp` for MCP tool calls).
    #[must_use]
    pub fn token(kind: ActorKind, actor: &Actor, transport: Transport) -> Self {
        Self {
            kind,
            subject: actor.id().to_owned(),
            credential_id: Some(actor.id().to_owned()),
            transport,
        }
    }

    /// Principal for a caller authorized by the local process boundary
    /// rather than a credential (MCP stdio).
    #[must_use]
    pub fn local_process(
        kind: ActorKind,
        subject: impl Into<String>,
        transport: Transport,
    ) -> Self {
        Self {
            kind,
            subject: subject.into(),
            credential_id: None,
            transport,
        }
    }

    /// Principal for work that starts inside the host on behalf of a
    /// plugin instance.
    #[must_use]
    pub fn host(instance_id: impl Into<String>) -> Self {
        Self {
            kind: ActorKind::Plugin,
            subject: instance_id.into(),
            credential_id: None,
            transport: Transport::Host,
        }
    }

    /// Actor kind recorded in audit rows.
    #[must_use]
    pub fn kind(&self) -> ActorKind {
        self.kind
    }

    /// Who the invocation is attributed to.
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// Credential (token id) that authenticated the subject, if any.
    #[must_use]
    pub fn credential_id(&self) -> Option<&str> {
        self.credential_id.as_deref()
    }

    /// Transport the root request arrived on.
    #[must_use]
    pub fn transport(&self) -> Transport {
        self.transport
    }

    /// `true` for principals that came from outside the host. Only
    /// these invocations produce downstream audit rows.
    #[must_use]
    pub fn is_external(&self) -> bool {
        self.transport != Transport::Host
    }

    /// Value for the audit ledger's `token_id` column: the credential
    /// id when there is one, otherwise the subject. Matches what the
    /// entry point's own row records, so a `token_id` filter finds the
    /// entry row and every downstream row together.
    #[must_use]
    pub fn audit_token_id(&self) -> &str {
        self.credential_id.as_deref().unwrap_or(&self.subject)
    }
}

/// One `call-service` hop on the delegation chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegationHop {
    /// Instance whose wasm issued the call. Also the unit of cycle
    /// detection: that supervisor is parked until the hop returns.
    pub caller_instance: String,
    /// Plugin id that owns the target service.
    pub target_plugin: String,
    /// Instance that owns the target service.
    pub target_instance: String,
    /// Immutable service `local-id` (not the per-run `svc-N`).
    pub target_service: String,
}

/// See the module docs. Cheap to clone (`Arc` inside); derived
/// contexts ([`Self::entering`], [`Self::delegate`]) copy the chain
/// rather than mutating a shared one, so a hop can never leak into a
/// sibling invocation.
#[derive(Debug, Clone)]
pub struct InvocationContext {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    call_id: String,
    root: Principal,
    current: Option<String>,
    deadline: Option<Instant>,
    chain: Vec<DelegationHop>,
}

task_local! {
    /// Context of the invocation whose wasm is running on this task.
    /// The supervisor scopes it around `execute-command` and
    /// `execute-service-command`; unset everywhere else (`init`,
    /// `tick`, `on-event`), where [`current_or_host`] synthesizes a
    /// host-origin context.
    pub(crate) static CURRENT: InvocationContext;
}

/// The context installed on the current task, if any.
#[must_use]
pub fn current() -> Option<InvocationContext> {
    CURRENT.try_with(Clone::clone).ok()
}

/// The installed context, or a fresh host-origin one rooted at
/// `instance_id` when the running wasm was not entered through a
/// context-carrying dispatch.
#[must_use]
pub fn current_or_host(instance_id: &str) -> InvocationContext {
    current().unwrap_or_else(|| InvocationContext::host_origin(instance_id))
}

impl InvocationContext {
    /// Context for an externally-rooted invocation: fresh call id and a
    /// deadline [`EXTERNAL_INVOCATION_DEADLINE`] from now.
    #[must_use]
    pub fn external(root: Principal) -> Self {
        Self::new(
            root,
            None,
            Some(Instant::now() + EXTERNAL_INVOCATION_DEADLINE),
        )
    }

    /// Context for work that starts inside the host on behalf of
    /// `instance_id`. No deadline — host-driven work keeps the
    /// per-hop dispatch timeout only.
    #[must_use]
    pub fn host_origin(instance_id: &str) -> Self {
        Self::new(
            Principal::host(instance_id),
            Some(instance_id.to_owned()),
            None,
        )
    }

    fn new(root: Principal, current: Option<String>, deadline: Option<Instant>) -> Self {
        Self {
            inner: Arc::new(Inner {
                call_id: mint_call_id(),
                root,
                current,
                deadline,
                chain: Vec::new(),
            }),
        }
    }

    /// Replace the deadline. `None` removes it.
    #[must_use]
    pub fn with_deadline(&self, deadline: Option<Instant>) -> Self {
        self.derive(|inner| inner.deadline = deadline)
    }

    /// Host-minted correlation id shared by every audit row this
    /// invocation produces.
    #[must_use]
    pub fn call_id(&self) -> &str {
        &self.inner.call_id
    }

    /// The principal the whole invocation is attributed to.
    #[must_use]
    pub fn root(&self) -> &Principal {
        &self.inner.root
    }

    /// Instance currently executing on behalf of the root; `None`
    /// while the request is still in a host handler.
    #[must_use]
    pub fn current_actor(&self) -> Option<&str> {
        self.inner.current.as_deref()
    }

    /// Absolute deadline, if any.
    #[must_use]
    pub fn deadline(&self) -> Option<Instant> {
        self.inner.deadline
    }

    /// Budget left before the deadline. `None` means unbounded;
    /// `Some(Duration::ZERO)` means expired.
    #[must_use]
    pub fn remaining(&self) -> Option<Duration> {
        self.inner
            .deadline
            .map(|d| d.saturating_duration_since(Instant::now()))
    }

    /// `true` once the deadline has passed.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.remaining().is_some_and(|r| r.is_zero())
    }

    /// `call-service` hops taken so far, outermost first.
    #[must_use]
    pub fn chain(&self) -> &[DelegationHop] {
        &self.inner.chain
    }

    /// Derived context with `instance_id` as the executing actor.
    #[must_use]
    pub fn entering(&self, instance_id: &str) -> Self {
        if self.current_actor() == Some(instance_id) {
            return self.clone();
        }
        self.derive(|inner| inner.current = Some(instance_id.to_owned()))
    }

    /// Derived context for the callee of `hop`: the hop is appended to
    /// the chain and the hop's target becomes the executing actor.
    #[must_use]
    pub fn delegate(&self, hop: DelegationHop) -> Self {
        self.derive(|inner| {
            inner.current = Some(hop.target_instance.clone());
            inner.chain.push(hop);
        })
    }

    fn derive(&self, f: impl FnOnce(&mut Inner)) -> Self {
        let mut inner = Inner {
            call_id: self.inner.call_id.clone(),
            root: self.inner.root.clone(),
            current: self.inner.current.clone(),
            deadline: self.inner.deadline,
            chain: self.inner.chain.clone(),
        };
        f(&mut inner);
        Self {
            inner: Arc::new(inner),
        }
    }

    /// JSON summary stored in the audit ledger's `invocation_json`
    /// column: root principal, executing actor, delegation chain. The
    /// call id has its own column and the deadline is a monotonic
    /// instant, so neither is repeated here.
    #[must_use]
    pub fn audit_json(&self) -> String {
        let root = &self.inner.root;
        let chain: Vec<serde_json::Value> = self
            .inner
            .chain
            .iter()
            .map(|h| {
                serde_json::json!({
                    "caller": audit_cap(&h.caller_instance),
                    "plugin": audit_cap(&h.target_plugin),
                    "instance": audit_cap(&h.target_instance),
                    "service": audit_cap(&h.target_service),
                })
            })
            .collect();
        serde_json::json!({
            "root": {
                "kind": root.kind.as_str(),
                "subject": root.subject,
                "credential_id": root.credential_id,
                "transport": root.transport.as_str(),
            },
            "current": self.inner.current.as_deref().map(audit_cap),
            "chain": chain,
        })
        .to_string()
    }
}

/// Longest identifier copied into an audit row. Service `local-id`s,
/// command names and test-driver caller ids come from plugins or
/// callers and are not otherwise length-bounded; capping keeps one hop
/// row small no matter what a plugin registers.
pub const MAX_AUDIT_IDENT_BYTES: usize = 128;

/// `s` truncated to at most [`MAX_AUDIT_IDENT_BYTES`] on a char
/// boundary.
#[must_use]
pub fn audit_cap(s: &str) -> &str {
    let mut cut = s.len().min(MAX_AUDIT_IDENT_BYTES);
    while !s.is_char_boundary(cut) {
        cut -= 1;
    }
    &s[..cut]
}

/// `call-<32 lowercase hex>` — 128 random bits, same shape as the
/// installation UUIDs.
fn mint_call_id() -> String {
    use std::fmt::Write as _;
    let mut bytes = [0u8; 16];
    rand::rngs::SysRng
        .try_fill_bytes(&mut bytes)
        .expect("system RNG must be available");
    let mut id = String::with_capacity(5 + 32);
    id.push_str("call-");
    for b in bytes {
        let _ = write!(id, "{b:02x}");
    }
    id
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hop(caller: &str, target: &str) -> DelegationHop {
        DelegationHop {
            caller_instance: caller.into(),
            target_plugin: "example.p".into(),
            target_instance: target.into(),
            target_service: "svc".into(),
        }
    }

    #[test]
    fn token_principal_separates_subject_credential_and_transport() {
        let actor = Actor::api("tok-1", vec!["*".into()]);
        let p = Principal::token(ActorKind::Mcp, &actor, Transport::McpHttp);
        assert_eq!(p.kind(), ActorKind::Mcp);
        assert_eq!(p.subject(), "tok-1");
        assert_eq!(p.credential_id(), Some("tok-1"));
        assert_eq!(p.transport(), Transport::McpHttp);
        assert!(p.is_external());
        assert_eq!(p.audit_token_id(), "tok-1");
    }

    #[test]
    fn local_process_principal_has_no_credential() {
        let p = Principal::local_process(ActorKind::Mcp, "parent", Transport::McpStdio);
        assert_eq!(p.credential_id(), None);
        assert_eq!(p.audit_token_id(), "parent");
        assert!(p.is_external());
    }

    #[test]
    fn host_origin_is_not_external_and_has_no_deadline() {
        let ctx = InvocationContext::host_origin("alpha");
        assert!(!ctx.root().is_external());
        assert_eq!(ctx.root().kind(), ActorKind::Plugin);
        assert_eq!(ctx.current_actor(), Some("alpha"));
        assert_eq!(ctx.remaining(), None);
        assert!(!ctx.is_expired());
    }

    #[test]
    fn call_ids_are_unique_and_well_formed() {
        let a = InvocationContext::host_origin("x");
        let b = InvocationContext::host_origin("x");
        assert_ne!(a.call_id(), b.call_id());
        assert!(a.call_id().starts_with("call-"));
        assert_eq!(a.call_id().len(), 5 + 32);
    }

    #[test]
    fn delegate_appends_hop_without_mutating_parent() {
        let actor = Actor::api("tok-1", vec![]);
        let root =
            InvocationContext::external(Principal::token(ActorKind::Api, &actor, Transport::Rest));
        let a = root.entering("alpha");
        let b = a.delegate(hop("alpha", "beta"));
        assert!(a.chain().is_empty());
        assert_eq!(b.chain(), &[hop("alpha", "beta")]);
        assert_eq!(b.current_actor(), Some("beta"));
        assert_eq!(b.call_id(), root.call_id());
        assert_eq!(b.root(), root.root());
        assert_eq!(b.deadline(), root.deadline());
    }

    #[test]
    fn entering_same_instance_reuses_context() {
        let ctx = InvocationContext::host_origin("alpha");
        let again = ctx.entering("alpha");
        assert!(Arc::ptr_eq(&ctx.inner, &again.inner));
    }

    #[test]
    fn deadline_expires() {
        let actor = Actor::api("tok-1", vec![]);
        let ctx = InvocationContext::external(Principal::token(
            ActorKind::Api,
            &actor,
            Transport::Connect,
        ));
        let remaining = ctx.remaining().expect("external contexts carry a deadline");
        assert!(remaining <= EXTERNAL_INVOCATION_DEADLINE);
        assert!(!ctx.is_expired());
        let expired = ctx.with_deadline(Some(Instant::now()));
        assert!(expired.is_expired());
        assert_eq!(expired.remaining(), Some(Duration::ZERO));
        assert!(!expired.with_deadline(None).is_expired());
    }

    #[test]
    fn audit_json_carries_root_current_and_chain() {
        let actor = Actor::api("tok-9", vec![]);
        let ctx =
            InvocationContext::external(Principal::token(ActorKind::Api, &actor, Transport::Rest))
                .entering("alpha")
                .delegate(hop("alpha", "beta"));
        let v: serde_json::Value = serde_json::from_str(&ctx.audit_json()).unwrap();
        assert_eq!(v["root"]["kind"], "api");
        assert_eq!(v["root"]["subject"], "tok-9");
        assert_eq!(v["root"]["credential_id"], "tok-9");
        assert_eq!(v["root"]["transport"], "rest");
        assert_eq!(v["current"], "beta");
        assert_eq!(v["chain"][0]["caller"], "alpha");
        assert_eq!(v["chain"][0]["instance"], "beta");
        assert_eq!(v["chain"][0]["service"], "svc");
    }

    #[test]
    fn audit_cap_bounds_identifiers_on_char_boundaries() {
        assert_eq!(audit_cap("short"), "short");
        let long = "é".repeat(MAX_AUDIT_IDENT_BYTES);
        let capped = audit_cap(&long);
        assert!(capped.len() <= MAX_AUDIT_IDENT_BYTES);
        assert!(capped.len() >= MAX_AUDIT_IDENT_BYTES - 1);
        let ctx = InvocationContext::host_origin("a").delegate(DelegationHop {
            caller_instance: "a".into(),
            target_plugin: "p".into(),
            target_instance: "b".into(),
            target_service: "x".repeat(10_000),
        });
        assert!(ctx.audit_json().len() < 1_000);
    }

    #[tokio::test]
    async fn current_reads_task_local_scope() {
        assert!(current().is_none());
        let ctx = InvocationContext::host_origin("alpha");
        let id = ctx.call_id().to_owned();
        let seen = CURRENT
            .scope(ctx, async { current().map(|c| c.call_id().to_owned()) })
            .await;
        assert_eq!(seen.as_deref(), Some(id.as_str()));
        assert_eq!(current_or_host("beta").current_actor(), Some("beta"));
    }
}
