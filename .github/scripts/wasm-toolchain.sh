#!/usr/bin/env bash
# Bumps the exact-pinned wasm toolchain crates in the root Cargo.toml
# together, so the host and the guest bindings stay on one wasm-tools
# release. Used by .github/workflows/wasm-toolchain.yaml; Dependabot
# ignores these crates.
#
#   wasm-toolchain.sh plan    print the bump it would make (dry run)
#   wasm-toolchain.sh apply   make it: rewrite the pins, update the
#                             root and examples/*/Cargo.lock lockfiles
#
# The target is the newest wasmtime release (not older than the pin)
# for which a wit-bindgen release (not older than its pin) exists on
# the same wasm-tools line (the 0.N in wasmparser / wit-parser 0.N.x):
# wasmtime's `wasmparser` / `wit-parser` / `wasm-encoder` requirements
# give the line, wit-bindgen-core's `wit-parser` and wit-bindgen-rust's
# `wit-component` / `wasm-metadata` requirements give wit-bindgen's.
# Each pinned wasm-tools crate moves to its newest release on that
# line. With no in-sync pair nothing is bumped: a lone wasmtime or
# wit-bindgen bump would put a second wasm-tools copy in the build.
#
# Versions come from the crates.io sparse index (CRATES_INDEX
# overrides it, e.g. a file:// fixture directory). `apply` writes the
# PR title / body and `changed` to $GITHUB_OUTPUT when it is set, and
# the PR body to $PR_BODY_FILE (default: wasm-toolchain-pr.md in
# $RUNNER_TEMP or the system temp directory).
set -euo pipefail

INDEX="${CRATES_INDEX:-https://index.crates.io}"
ROOT="$(git rev-parse --show-toplevel)"
MANIFEST="$ROOT/Cargo.toml"
CACHE="$(mktemp -d)"
trap 'rm -rf "$CACHE"' EXIT

# Pinned in lockstep with wasmtime (same version number).
WASMTIME_CRATES="wasmtime wasmtime-wasi wasmtime-wasi-http"
# wasm-tools crates that may be pinned to wasmtime's line.
TOOLS_CRATES="wit-parser wit-component wasm-encoder wasm-metadata wasmparser"

die() { echo "error: $*" >&2; exit 1; }
log() { echo "$*" >&2; }

# Sparse-index path of a crate name.
index_path() {
  local c
  c="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
  case ${#c} in
    1) echo "1/$c" ;;
    2) echo "2/$c" ;;
    3) echo "3/${c:0:1}/$c" ;;
    *) echo "${c:0:2}/${c:2:2}/$c" ;;
  esac
}

# The crate's stable, non-yanked releases as a JSON array of
# {vers, deps}, newest first. Cached per run.
releases() {
  local file="$CACHE/$1.json"
  if [[ ! -s $file ]]; then
    curl -fsSL --retry 3 -A 'oxidhome-wasm-toolchain-bump' \
      "$INDEX/$(index_path "$1")" |
      jq -s '[.[] | select((.yanked | not) and (.vers | test("^[0-9]+\\.[0-9]+\\.[0-9]+$")))
              | {vers, deps: [.deps[] | select(.kind != "dev")
                              | {name: (.package // .name), req}]}]
             | sort_by(.vers | split(".") | map(tonumber)) | reverse' >"$file" ||
      die "cannot read the crates.io index entry for $1"
  fi
  cat "$file"
}

# jq prelude: semver ordering and the compatibility line of a version or
# a caret / exact requirement ("^0.263.0" and "0.263.1" -> "0.263",
# "^1.2" -> "1").
JQ_LIB='
def nums: split(".") | map(tonumber);
def line: if test("^[\\^=]?[0-9]+\\.[0-9]+(\\.[0-9]+)?$") | not
          then error("unsupported requirement \(.)") else . end
  | ltrimstr("^") | ltrimstr("=") | split(".")
  | if .[0] == "0" then "0." + .[1] else .[0] end;
'

# Versions of crate $1 not older than $2, newest first.
versions_from() {
  releases "$1" | jq -r --arg min "$2" "$JQ_LIB"'
    .[] | select((.vers | nums) >= ($min | nums)) | .vers'
}

# The line of crate $1 @ $2's requirement on $3 (empty if no such dep).
dep_line() {
  releases "$1" | jq -r --arg v "$2" --arg d "$3" "$JQ_LIB"'
    [.[] | select(.vers == $v) | .deps[] | select(.name == $d) | .req | line]
    | unique | if length > 1 then error("several lines") else (.[0] // "") end'
}

# Newest release of crate $1 on line $2 (empty if none).
newest_on_line() {
  releases "$1" | jq -r --arg l "$2" "$JQ_LIB"'
    [.[] | select(.vers | line == $l) | .vers][0] // ""'
}

# The exact pin of crate $1 in the root manifest (empty if not pinned).
current_pin() {
  sed -n -E "s/^$1 = (\\{ *version = )?\"=([0-9.]+)\".*/\\2/p" "$MANIFEST" | head -n 1
}

# The wasm-tools line wasmtime $1 is built on (empty if its
# requirements disagree).
wasmtime_line() {
  local l line=""
  for dep in wasmparser wit-parser wasm-encoder; do
    l="$(dep_line wasmtime "$1" "$dep")" || return 1
    [[ -z $l ]] && continue
    if [[ -z $line ]]; then line="$l"; elif [[ $l != "$line" ]]; then echo ""; return; fi
  done
  echo "$line"
}

# The wasm-tools line wit-bindgen $1 is built on (empty if its crates
# disagree).
bindgen_line() {
  local parser component metadata
  parser="$(dep_line wit-bindgen-core "$1" wit-parser)"
  component="$(dep_line wit-bindgen-rust "$1" wit-component)"
  metadata="$(dep_line wit-bindgen-rust "$1" wasm-metadata)"
  if [[ $parser == "$component" && $parser == "$metadata" ]]; then
    echo "$parser"
  else
    echo ""
  fi
}

# Prints the plan as "status <current|bump|none>", "line <0.N>", then
# one "pin <crate> <old> <new>" per pinned crate.
plan() {
  local cur_wt cur_wb wts wbs wt wb bl line="" target_wt="" target_wb="" c old new
  cur_wt="$(current_pin wasmtime)"
  cur_wb="$(current_pin wit-bindgen)"
  [[ -n $cur_wt && -n $cur_wb ]] || die "no exact wasmtime / wit-bindgen pin in $MANIFEST"

  # Fetch up front so a failed download stops the run here instead of
  # reading as "no release" inside a substitution below.
  for c in $WASMTIME_CRATES wit-bindgen wit-bindgen-core wit-bindgen-rust $TOOLS_CRATES; do
    releases "$c" >/dev/null
  done
  wts="$(versions_from wasmtime "$cur_wt")"
  wbs="$(versions_from wit-bindgen "$cur_wb")"

  for wt in $wts; do
    line="$(wasmtime_line "$wt")"
    if [[ -z $line ]]; then
      log "wasmtime $wt: its wasm-tools requirements disagree, skipped"
      continue
    fi
    for wb in $wbs; do
      bl="$(bindgen_line "$wb")"
      if [[ $bl == "$line" ]]; then
        target_wb="$wb"
        break
      fi
    done
    if [[ -n $target_wb ]]; then
      target_wt="$wt"
      break
    fi
    log "wasmtime $wt (wasm-tools $line): no wit-bindgen >= $cur_wb on that line"
  done

  if [[ -z $target_wt ]]; then
    echo "status none"
    return
  fi
  log "target: wasmtime $target_wt + wit-bindgen $target_wb on wasm-tools $line"

  local out="" changed=0
  for c in $WASMTIME_CRATES wit-bindgen $TOOLS_CRATES; do
    old="$(current_pin "$c")"
    [[ -z $old ]] && continue
    if [[ " $WASMTIME_CRATES " == *" $c "* ]]; then
      new="$target_wt"
      releases "$c" | jq -e --arg v "$new" 'any(.[]; .vers == $v)' >/dev/null ||
        die "$c $new is not published"
    elif [[ $c == wit-bindgen ]]; then
      new="$target_wb"
    else
      new="$(newest_on_line "$c" "$line")"
      [[ -n $new ]] || die "$c has no release on wasm-tools $line"
    fi
    [[ $old != "$new" ]] && changed=1
    out+="pin $c $old $new"$'\n'
  done
  if ((changed)); then echo "status bump"; else echo "status current"; fi
  echo "line $line"
  printf '%s' "$out"
}

apply() {
  local p status line c old new wt="" table=""
  p="$(plan)"
  printf '%s\n' "$p"
  status="$(awk '$1 == "status" { print $2 }' <<<"$p")"
  if [[ $status != bump ]]; then
    log "nothing to bump ($status)"
    [[ -n ${GITHUB_OUTPUT:-} ]] && echo "changed=false" >>"$GITHUB_OUTPUT"
    return
  fi
  line="$(awk '$1 == "line" { print $2 }' <<<"$p")"

  while read -r _ c old new; do
    [[ $c == wasmtime ]] && wt="$new"
    table+="| \`$c\` | $old | $new |"$'\n'
    [[ $old == "$new" ]] && continue
    sed -i.bak -E "s/^($c = (\\{ *version = )?\")=$old\"/\\1=$new\"/" "$MANIFEST"
    rm -f "$MANIFEST.bak"
    [[ "$(current_pin "$c")" == "$new" ]] || die "failed to rewrite the $c pin"
  done < <(grep '^pin ' <<<"$p")

  # Re-resolve only what the new pins require; the examples are
  # standalone workspaces whose lockfiles CI builds with --locked.
  (cd "$ROOT" && cargo update --workspace)
  for lock in "$ROOT"/examples/*/Cargo.lock; do
    (cd "$(dirname "$lock")" && cargo update --workspace)
  done

  local title="build(deps): bump wasm toolchain to wasmtime $wt"
  local body_file="${PR_BODY_FILE:-${RUNNER_TEMP:-${TMPDIR:-/tmp}}/wasm-toolchain-pr.md}"
  cat >"$body_file" <<EOF
Bumps the exact-pinned wasm toolchain together onto wasm-tools $line, the line wasmtime $wt is built on. wit-bindgen moves to its newest release on the same line, so the host and the guest bindings share one wasm-tools version.

| crate | from | to |
| --- | --- | --- |
${table}
The root and \`examples/*\` lockfiles were updated with \`cargo update --workspace\`. If the WIT contract baseline or the generated bindings change, fix them up in this PR before merging.

Opened by \`.github/workflows/wasm-toolchain.yaml\`.
EOF
  log "PR body written to $body_file"
  if [[ -n ${GITHUB_OUTPUT:-} ]]; then
    {
      echo "changed=true"
      echo "title=$title"
      echo "body-file=$body_file"
    } >>"$GITHUB_OUTPUT"
  fi
}

case "${1:-}" in
  plan) plan ;;
  apply) apply ;;
  *) die "usage: $0 plan|apply" ;;
esac
