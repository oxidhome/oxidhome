# ADR-0005: Connect RPC alongside the JSON/REST API

- **Status:** accepted
- **Date:** 2026-07-28
- **Deciders:** the maintainer
- **Supersedes:** none
- **Superseded by:** none
- **References:** Phase 15, PRs #49, #50, #67, #74, #75, #76

## Context

Phase 12 planned a JSON/REST + WebSocket API and deferred gRPC. Client SDKs need a typed, generated contract and
server streaming for event tails, and REST alone has neither.

## Decision

The daemon serves a Connect RPC surface from the same axum listener as the JSON/REST + WebSocket API. The
`connectrpc` router speaks Connect, gRPC and gRPC-Web from one set of handlers, generated from the `.proto` files in
`proto/` into `oxidhome-proto`. Every 0.1 API area (health, instances, devices, plugins, logs, events, including the
event tail as server streaming) exists on both surfaces. Both surfaces share the same authentication, scope checks
and audit ledger. Connect is the contract for SDKs; the JSON API stays for browsers and `curl`.

## Rejected options

- **REST only, gRPC deferred** (the Phase 12 plan). No generated clients and no typed streaming.
- **Dropping the JSON API.** Loses easy debugging from a browser or `curl`, for little gain while both share handlers
  and auth.
- **GraphQL.** Out of scope.

## Consequences

- Every API change lands on both surfaces.
- CI regenerates the Connect code with `buf` and fails if the committed code is stale.
