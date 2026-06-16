//! OxidHome Connect-RPC type surface.
//!
//! This crate is **entirely generated** by `buf generate` — the two
//! sub-trees below mirror the eliza example in `anthropics/connect-rust`:
//!
//! - [`proto`] — buffa-generated message types (`CheckRequest`,
//!   `CheckResponse`, …) and their owned/view shapes.
//! - [`connect`] — `protoc-gen-connect-rust`-generated service
//!   traits, client structs, and the `register()` extension that
//!   mounts a handler into a [`connectrpc::Router`].
//!
//! Downstream code (`oxidhome-core::api::connect_router`) implements
//! one of the service traits (e.g. `HealthService`) on a struct that
//! holds the [`Engine`](::connectrpc) handle it needs and calls
//! `.register(Router::new())` to get a Connect router it can mount
//! on the existing axum app via `into_axum_service()`.
//!
//! ## Regen
//!
//! See `scripts/install-buf-tools.sh` for the tool install + run
//! `buf generate` from the workspace root. The committed code under
//! `src/gen/` must match the regen output; CI's `buf-verify` job
//! enforces this via `git diff --exit-code`.

// Buffa message types. The `#[path]` aliases route the generated
// trees into stable Rust module names so the rest of the workspace
// can `use oxidhome_proto::proto::oxidhome::v1::CheckRequest` without
// caring about the on-disk codegen layout.
//
// The buffa-side `mod.rs` references its types via `crate::proto::...`
// (per `buffa_module=crate::proto` in `buf.gen.yaml`), so the
// alias name on the crate side has to be exactly `proto`.
#[path = "gen/buffa/mod.rs"]
pub mod proto;

// Connect service stubs (traits, handlers, clients).
#[path = "gen/connect/mod.rs"]
pub mod connect;
