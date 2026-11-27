# ADR-0011: Tokens hold roles; sensitive categories live in role grants

- **Status:** accepted
- **Date:** 2026-11-26
- **Deciders:** OxidHome maintainers
- **Supersedes:** none
- **Superseded by:** none
- **References:** PR #244; closed PRs #240 and #243 (not adopted)

## Context

The first permission model (H6) had grown several overlapping layers: a token held a raw scope list and roles, MCP
tokens carried 14.4 constraints, tokens and roles both carried deny lists, sensitive categories (lock, opener,
alarm, camera bytes) were granted per token or per role on a separate path, and allowed sensitive actions were rate
limited with a reserve / commit / refund charge. Each layer had its own CLI flags, wire fields and audit labels. A
household operator could not predict what a token may do, and every new surface had to thread all of it. There are
no users yet, so the model can be replaced outright.

## Decision

A token holds role names and an owner flag, nothing else. A role is a list of grants `{actions, category?,
devices?}`; access is absent unless a grant gives it, and there is no deny list. `*` names every action a role can
hold. A grant narrowed to device categories or device ids names only device and blob actions. Four roles are built
in code (`admin`, `member`, `guest`, `agent`) and can't be edited, deleted or shadowed; the owner adds custom roles,
stored by name. A role that live tokens hold can't be deleted.

A sensitive category is reached only by one grant whose `category` names every sensitive category of the target;
`*` never reaches one. `admin` and `member` hold them all. The owner token may do everything and alone holds
`token.manage` and `policy.manage`, which no role can grant.

An allowed sensitive action still leaves a `warn` audit row: a device command's row is written durably by the
supervisor at dequeue, after re-authorization, and the command doesn't run without it. A deny's audit label is the
refused action's name. The `service.call` hop check stays: an externally rooted `call-service` hop needs both the
calling plugin's `consumes_services` grant and the root's `service.call`.

## Rejected options

- **Keep scope lists beside roles.** Two ways to say the same thing, and the source of the deny and constraint
  layers.
- **Keep token or role deny lists.** "Absent unless granted" covers the cases seen so far; a deny list can return on
  roles only if a concrete need appears.
- **Keep per-token sensitive grants and rate limits.** A grant naming the category does the first; the `warn` row is
  the operator's signal, and limits are an admin and metrics concern.
- **Decide plugin permits inside `authorize()` with an owner-narrowing surface for each kind (#240, #243).** It adds
  far more than it removes; plugin grants stay approved at install and checked at their call sites.

## Consequences

REST, Connect, MCP and the CLI mint tokens by role name and edit roles as grant lists. `mcp-stdio` runs as one role
(`--role`, `agent` by default). Tokens are revoked one by one offline (`oxidhome token revoke`). Owner narrowing of
plugin grants other than `network` is an open question.
