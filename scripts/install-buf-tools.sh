#!/usr/bin/env bash
# Install the Buf + Anthropic codegen plugins OxidHome's Connect RPC
# pipeline needs. Idempotent — re-runs are cheap (cargo / go skip
# already-installed versions).
#
# Usage:
#   ./scripts/install-buf-tools.sh
#
# Prerequisites: `go` and `cargo` on PATH.
#
# What it installs:
#   - buf CLI (Go) — protoc-equivalent parser + the `buf generate`
#     driver that fans out to the codegen plugins below.
#   - protoc-gen-buffa, protoc-gen-buffa-packaging (Rust) — buffa's
#     message + module-tree codegen plugins.
#   - protoc-gen-connect-rust (Rust, from `connectrpc-codegen`) —
#     Anthropic's Connect service-trait codegen plugin.
#
# After install, $GOPATH/bin and ~/.cargo/bin must be on PATH so
# `buf generate` can locate the plugins.
set -euo pipefail

# Versions pinned alongside the workspace `connectrpc` / `buffa`
# pins in Cargo.toml; bumping here without bumping the runtime
# crate version (or vice versa) will produce a codegen / runtime
# mismatch.
BUF_VERSION="${BUF_VERSION:-v1.55.0}"
BUFFA_VERSION="${BUFFA_VERSION:-0.7.1}"
CONNECTRPC_CODEGEN_VERSION="${CONNECTRPC_CODEGEN_VERSION:-0.7.0}"

step() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

step "buf ${BUF_VERSION} (go install)"
go install "github.com/bufbuild/buf/cmd/buf@${BUF_VERSION}"

step "protoc-gen-buffa ${BUFFA_VERSION} (cargo install)"
cargo install protoc-gen-buffa --version "${BUFFA_VERSION}" --locked

step "protoc-gen-buffa-packaging ${BUFFA_VERSION} (cargo install)"
cargo install protoc-gen-buffa-packaging --version "${BUFFA_VERSION}" --locked

step "protoc-gen-connect-rust ${CONNECTRPC_CODEGEN_VERSION} (cargo install connectrpc-codegen)"
cargo install connectrpc-codegen --version "${CONNECTRPC_CODEGEN_VERSION}" --locked

step "Versions"
"$(go env GOPATH)/bin/buf" --version
"${CARGO_HOME:-$HOME/.cargo}/bin/protoc-gen-buffa" --version 2>/dev/null || true
"${CARGO_HOME:-$HOME/.cargo}/bin/protoc-gen-buffa-packaging" --version 2>/dev/null || true
"${CARGO_HOME:-$HOME/.cargo}/bin/protoc-gen-connect-rust" --version 2>/dev/null || true

cat <<EOF

All Buf / Connect codegen tools installed.

Make sure both \$GOPATH/bin (\$(go env GOPATH)/bin) and
\$HOME/.cargo/bin are on your \$PATH so 'buf generate' can locate
the plugins. Then regenerate with:

    buf generate
    cargo fmt --all   # see note below

The committed code under crates/oxidhome-proto/src/gen/ must
match the post-fmt regen output; CI enforces this via
\`git diff --exit-code\` in the buf-verify job. The cargo fmt
step matters because rustfmt wraps buffa's long single-line
\`#![allow(...)]\` attributes — the CI buf-verify job runs the
same two commands in the same order.
EOF
