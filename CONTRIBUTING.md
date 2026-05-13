# Contributing to OxidHome

Thanks for your interest in OxidHome. This document covers how to contribute to the core platform — the host runtime,
plugin SDK, WIT definitions, and tooling.

For first-party plugin contributions, see [`oxidhome/plugins`](https://github.com/oxidhome/plugins). For documentation
and articles, see [`oxidhome/docs`](https://github.com/oxidhome/docs).

## Project status

OxidHome is in **early development**. The architecture is settling but the implementation is not. Expect:

- Frequent breaking changes to internal APIs.
- The WIT interface (`wit/oxidhome.wit`) iterating until 1.0.
- Some areas being more welcoming to contributions than others — the architecture is documented in [
  `ARCHITECTURE.md`](ARCHITECTURE.md), and changes that diverge from it should be discussed before implementation.

If you're considering a non-trivial contribution, please open an issue or discussion first. This isn't a barrier to
entry — it's so we can give you useful feedback before you spend time on something that might not land.

## How to contribute

### Reporting bugs

Open an issue with:

- What you were doing
- What you expected to happen
- What actually happened
- Your environment (OS, Rust version, Wasmtime version if relevant)
- Minimal reproduction if possible

### Suggesting features or design changes

Open a GitHub Discussion (preferred) or an issue. Please read [`ARCHITECTURE.md`](ARCHITECTURE.md) first — most "why
doesn't OxidHome do X" questions are answered there, and proposals that conflict with the documented design need to
address why the existing reasoning should change.

For changes to the WIT interface specifically, expect a longer review cycle. The WIT is the contract plugin authors
depend on; we're cautious about changes pre-1.0 and very cautious post-1.0.

### Submitting code

1. **Fork and branch.** Branch from `main`. Use a descriptive branch name (`feat/event-bus-filtering`,
   `fix/wasmtime-config-leak`).
2. **Match the existing style.** Run `cargo fmt` and `cargo clippy --all-targets -- -D warnings` before pushing.
3. **Test what you change.** Unit tests for new logic, integration tests for new host/plugin interactions.
4. **Write meaningful commits.** Conventional Commits style is appreciated but not required (`feat:`, `fix:`, `docs:`,
   `refactor:`).
5. **Open a pull request** with a description of what changed and why. Link related issues.

PR reviews focus on correctness, design fit with the architecture, and code clarity. Expect requests for changes;
they're not personal.

## Development setup

You'll need:

- Rust — pinned to the version in [`rust-toolchain.toml`](rust-toolchain.toml) (1.95.0 at the moment, with `rustfmt`, `clippy`, `llvm-tools-preview`, and the `wasm32-wasip2` target). `rustup` reads that file automatically inside the workspace, so just having `rustup` installed is enough.
- The CI toolchain — `cargo install-tools` (alias defined in `.cargo/config.toml`) installs `cargo-deny`, `cargo-llvm-cov`, `cargo-machete`, `cargo-nextest`, `cargo-action-fmt`, `wit-deps-cli`, and `wasm-tools` with `--locked`. One command, same versions as CI.
- [`wit-bindgen-cli`](https://github.com/bytecodealliance/wit-bindgen): `cargo install wit-bindgen-cli` (separate; not yet in the install-tools alias).

To build and test:

```sh
cargo build --workspace
cargo nextest run --workspace
```

(CI runs `cargo llvm-cov nextest` under the hood; `cargo nextest run` matches that locally. `cargo test --workspace` also works on a default Rust setup if you'd rather not install `cargo-nextest`, but the output is less readable and isn't what CI sees.)

To validate the WIT file:

```sh
wasm-tools component wit wit/oxidhome.wit
```

## Code conventions

- **Edition:** Rust 2024 (or the latest stable edition the workspace declares).
- **Formatting:** `cargo fmt` enforced in CI.
- **Linting:** `cargo clippy --all-targets -- -D warnings` enforced in CI.
- **Unsafe code:** avoid it. The workspace sets `unsafe_code = "deny"` so it is forbidden by default everywhere. In rare,
  well-justified cases (e.g., FFI, performance-critical primitives with no safe alternative) a specific block may opt in
  with `#[allow(unsafe_code)]`. Every such use must carry a `// SAFETY:` comment that explains the invariants the caller
  must uphold and why they hold here. PRs introducing new unsafe code are reviewed with extra scrutiny.
- **Errors:** `thiserror` for libraries, `anyhow` for binaries. No `unwrap()` or `expect()` in non-test code without a
  good reason in a comment.
- **Async:** `tokio` runtime. Wasmtime async features enabled. No blocking calls inside async contexts.
- **Logging:** `tracing` (not `log`). Spans for cross-component flows.
- **Public API:** every public item gets a doc comment. `cargo doc --no-deps` should produce useful output.

## What kinds of contributions are most useful right now

Because the project is early-stage, some areas are higher-leverage than others:

- **Test infrastructure** — building out the test host, plugin testing harnesses, integration test patterns.
- **WIT review** — feedback from people who've worked with WIT and the Component Model elsewhere is genuinely valuable.
  The current WIT is a first cut.
- **Documentation gaps** — things that confused you when reading the code or trying to write a plugin.
- **Plugin SDK ergonomics** — making the Rust SDK pleasant to use for plugin authors.

Less urgent right now:

- New device capabilities (the existing set is small but intentionally so for 0.1).
- Performance optimization (correctness first).
- Additional language SDKs (the Rust SDK needs to be solid before others are worth building).

## Licensing of contributions

OxidHome is dual-licensed under [MIT](LICENSE-MIT) and [Apache-2.0](LICENSE-APACHE).

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as
defined in the Apache-2.0 license, shall be dual-licensed as above, without any additional terms or conditions.

This is the standard Rust ecosystem contribution clause. By opening a pull request you confirm you have the right to
submit your contribution under these terms.

## Code of conduct

Be respectful, be patient, assume good faith. Disagreements about technical decisions are normal and welcome; personal
attacks are not. The maintainers reserve the right to remove comments, close issues, or restrict participation if needed
to keep the project healthy.

## Questions

For implementation questions or design discussions, open a GitHub Discussion. For private concerns, contact the
maintainers listed in the repo settings.
