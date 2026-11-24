#!/usr/bin/env bash
# Bumps the exact-pinned wasm toolchain crates in the root Cargo.toml
# together, so the host and the guest bindings stay on one wasm-tools
# release line. Used by .github/workflows/wasm-toolchain.yaml;
# Dependabot ignores these crates. Needs bash >= 4.4, curl and jq;
# `apply` also needs cargo and osv-scanner.
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
# Quarantine: only releases published at least QUARANTINE_DAYS (default
# 7, the same as Dependabot's cooldown) days ago count, for every crate
# involved; yanked releases never do. The publish time is the index's
# `pubtime`, crates.io's `created_at` for the version.
#
# Advisories: a release with an OSV advisory (api.osv.dev, crates.io
# ecosystem) is never picked; the next-newest clean one is. `apply` then
# runs osv-scanner over every lockfile before and after the update and
# opens no PR when the update adds a vulnerability. An unreachable OSV
# fails the run. A pin never moves backwards.
#
# Versions come from the crates.io sparse index (CRATES_INDEX
# overrides it, e.g. a file:// fixture directory). `apply` writes the
# PR title / body and `changed` to $GITHUB_OUTPUT when it is set, and
# the PR body to $PR_BODY_FILE (default: wasm-toolchain-pr.md in
# $RUNNER_TEMP or the system temp directory).
set -euo pipefail
if ((BASH_VERSINFO[0] * 100 + BASH_VERSINFO[1] < 404)); then
  echo "error: needs bash >= 4.4 (this is $BASH_VERSION)" >&2
  exit 1
fi
# Command substitutions below carry most of the logic; fail in them too.
shopt -s inherit_errexit

INDEX="${CRATES_INDEX:-https://index.crates.io}"
OSV_API="${OSV_API:-https://api.osv.dev}"
QUARANTINE_DAYS="${QUARANTINE_DAYS:-7}"
[[ $QUARANTINE_DAYS =~ ^[0-9]+$ ]] || { echo "error: QUARANTINE_DAYS must be a whole number of days" >&2; exit 1; }
# Releases published after this instant are still in quarantine.
CUTOFF="$(jq -nr --argjson d "$QUARANTINE_DAYS" 'now - $d * 86400 | floor | todate')"
ROOT="$(git rev-parse --show-toplevel)"
MANIFEST="$ROOT/Cargo.toml"
CACHE="$(mktemp -d)"
trap 'rm -rf "$CACHE"' EXIT

# Pinned in lockstep with wasmtime (same version number).
WASMTIME_CRATES="wasmtime wasmtime-wasi wasmtime-wasi-http"
# Released in lockstep with wit-bindgen.
BINDGEN_CRATES="wit-bindgen wit-bindgen-core wit-bindgen-rust wit-bindgen-rust-macro"
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

# The crate's stable, non-yanked releases published by $CUTOFF as a
# JSON array of {vers, deps}, newest first. Cached per run.
releases() {
  local file="$CACHE/$1.json"
  if [[ ! -s $file ]]; then
    curl -fsSL --retry 3 --max-time 60 -A 'oxidhome-wasm-toolchain-bump' \
      "$INDEX/$(index_path "$1")" |
      jq -s --arg cutoff "$CUTOFF" '[.[] | select((.yanked | not)
                     and (.vers | test("^[0-9]+\\.[0-9]+\\.[0-9]+$"))
                     and .pubtime != null and .pubtime <= $cutoff)
              | {vers, deps: [.deps[] | select(.kind != "dev")
                              | {name: (.package // .name), req}]}]
             | sort_by(.vers | split(".") | map(tonumber)) | reverse' >"$file" ||
      die "cannot read the crates.io index entry for $1"
  fi
  cat "$file"
}

# OSV advisory ids (space-separated, empty if none) for crate $1 @ $2.
# Withdrawn advisories don't count. Cached per run; fails the run when
# OSV can't be queried.
advisories() {
  local file="$CACHE/osv-$1@$2.txt"
  if [[ ! -e $file ]]; then
    jq -n --arg n "$1" --arg v "$2" '{package: {ecosystem: "crates.io", name: $n}, version: $v}' |
      curl -fsS --retry 3 --max-time 60 -A 'oxidhome-wasm-toolchain-bump' \
        -H 'Content-Type: application/json' --data-binary @- "$OSV_API/v1/query" |
      jq -r '[.vulns[]? | select(.withdrawn == null) | .id] | join(" ")' >"$file" ||
      { rm -f "$file"; die "cannot query OSV for $1 $2"; }
  fi
  cat "$file"
}

# Advisories of every crate in $2.. at version $1, as "crate version:
# ids" lines. Exits the run when OSV can't be queried: callers sit in
# conditions, where errexit doesn't reach, so a failed query must never
# read as "no advisories".
advisories_of() {
  local v="$1" c ids
  shift
  for c in "$@"; do
    ids="$(advisories "$c" "$v")" || die "cannot query OSV for $c $v"
    [[ -n $ids ]] && echo "$c $v: $ids"
  done
  return 0
}

# jq prelude: semver ordering and the compatibility line of a version or
# a caret requirement ("^0.263.0" and "0.263.1" -> "0.263", "^1.2" ->
# "1"). Any other requirement (exact, tilde, range) stops the run: the
# newest-release-on-the-line pick assumes caret semantics.
JQ_LIB='
def nums: split(".") | map(tonumber);
def line: if test("^\\^?[0-9]+\\.[0-9]+(\\.[0-9]+)?$") | not
          then error("unsupported requirement \(.)") else . end
  | ltrimstr("^") | split(".")
  | if .[0] == "0" then "0." + .[1] else .[0] end;
'

# $1 > $2 as versions.
newer() {
  jq -en --arg a "$1" --arg b "$2" "$JQ_LIB"'($a | nums) > ($b | nums)' >/dev/null
}

# Versions of crate $1 not older than $2, newest first.
versions_from() {
  releases "$1" | jq -r --arg min "$2" "$JQ_LIB"'
    .[] | select((.vers | nums) >= ($min | nums)) | .vers'
}

# Releases of crate $1 on line $2, newest first.
versions_on_line() {
  releases "$1" | jq -r --arg l "$2" "$JQ_LIB"'.[] | select(.vers | line == $l) | .vers'
}

# The line of crate $1 @ $2's requirement on $3 (empty if no such dep).
dep_line() {
  releases "$1" | jq -r --arg v "$2" --arg d "$3" "$JQ_LIB"'
    [.[] | select(.vers == $v) | .deps[] | select(.name == $d) | .req | line]
    | unique | if length > 1 then error("several lines") else (.[0] // "") end'
}

# Whether crate $1 has release $2 out of quarantine.
published() {
  releases "$1" | jq -e --arg v "$2" 'any(.[]; .vers == $v)' >/dev/null
}

# The exact pin of crate $1 in the root manifest (empty if not pinned).
current_pin() {
  sed -n -E "s/^$1 = (\\{ *version = )?\"=([0-9.]+)\".*/\\2/p" "$MANIFEST" | head -n 1
}

# The wasm-tools line wasmtime $1 is built on (empty if its
# requirements disagree).
wasmtime_line() {
  local dep l line=""
  for dep in wasmparser wit-parser wasm-encoder; do
    l="$(dep_line wasmtime "$1" "$dep")"
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

# Whether every crate in $2.. has release $1 out of quarantine and
# without advisories; logs why not.
clean_release() {
  local v="$1" c found l
  shift
  for c in "$@"; do
    published "$c" "$v" || { log "  $c $v: not published or still in quarantine"; return 1; }
  done
  found="$(advisories_of "$v" "$@")" || exit 1
  if [[ -n $found ]]; then
    while read -r l; do log "  advisory: $l"; done <<<"$found"
    return 1
  fi
}

# Prints the plan as "quarantine <days> <cutoff>", "status
# <current|bump|none>", "line <0.N>", then one "pin <crate> <old> <new>"
# per pinned crate.
plan() {
  local cur_wt cur_wb wts wbs wt wb bl line="" target_wt="" target_wb="" c old new v found
  local wasmtime_pinned="" tools_pinned="" pins=""
  cur_wt="$(current_pin wasmtime)"
  cur_wb="$(current_pin wit-bindgen)"
  [[ -n $cur_wt && -n $cur_wb ]] || die "no exact wasmtime / wit-bindgen pin in $MANIFEST"
  for c in $WASMTIME_CRATES; do [[ -n "$(current_pin "$c")" ]] && wasmtime_pinned+=" $c"; done
  for c in $TOOLS_CRATES; do [[ -n "$(current_pin "$c")" ]] && tools_pinned+=" $c"; done
  echo "quarantine $QUARANTINE_DAYS $CUTOFF"
  log "quarantine: $QUARANTINE_DAYS days, only releases published by $CUTOFF"

  # Fetch up front so a failed download stops the run here.
  for c in $WASMTIME_CRATES $BINDGEN_CRATES $TOOLS_CRATES; do
    releases "$c" >/dev/null
  done
  wts="$(versions_from wasmtime "$cur_wt")"
  wbs="$(versions_from wit-bindgen "$cur_wb")"
  [[ -n $wts ]] || log "no wasmtime >= $cur_wt out of quarantine"

  for wt in $wts; do
    line="$(wasmtime_line "$wt")"
    if [[ -z $line ]]; then
      log "wasmtime $wt: its wasm-tools requirements disagree, skipped"
      continue
    fi
    log "wasmtime $wt (wasm-tools $line):"
    # shellcheck disable=SC2086 # word-split crate lists
    clean_release "$wt" $wasmtime_pinned || continue

    target_wb=""
    for wb in $wbs; do
      bl="$(bindgen_line "$wb")"
      [[ $bl == "$line" ]] || continue
      # shellcheck disable=SC2086
      if clean_release "$wb" $BINDGEN_CRATES; then
        target_wb="$wb"
        break
      fi
    done
    if [[ -z $target_wb ]]; then
      log "  no clean wit-bindgen >= $cur_wb out of quarantine on that line"
      continue
    fi

    # Each pinned wasm-tools crate: newest clean release on the line,
    # never older than its pin.
    pins=""
    for c in $tools_pinned; do
      old="$(current_pin "$c")"
      new=""
      for v in $(versions_on_line "$c" "$line"); do
        if newer "$old" "$v"; then new="$old"; break; fi
        [[ $v == "$old" ]] && { new="$v"; break; }
        found="$(advisories_of "$v" "$c")"
        [[ -z $found ]] && { new="$v"; break; }
        log "  advisory: $found"
      done
      if [[ -z $new ]]; then
        log "  no clean $c on wasm-tools $line"
        pins=""
        break
      fi
      pins+="pin $c $old $new"$'\n'
    done
    if [[ -n $tools_pinned && -z $pins ]]; then
      continue
    fi
    target_wt="$wt"
    break
  done

  if [[ -z $target_wt ]]; then
    echo "status none"
    return 0
  fi
  log "target: wasmtime $target_wt + wit-bindgen $target_wb on wasm-tools $line, no OSV advisories"

  local out=""
  for c in $wasmtime_pinned; do out+="pin $c $(current_pin "$c") $target_wt"$'\n'; done
  out+="pin wit-bindgen $cur_wb $target_wb"$'\n'
  out+="$pins"
  if awk '$1 == "pin" && $3 != $4 { found = 1 } END { exit !found }' <<<"$out"; then
    echo "status bump"
  else
    echo "status current"
  fi
  echo "line $line"
  printf '%s' "$out"
}

# osv-scanner findings over every lockfile as sorted "package version id"
# lines. Fails the run unless the scan itself succeeded (exit 0: clean,
# 1: findings).
scan_lockfiles() {
  local args=() lock json rc=0
  for lock in "$ROOT"/Cargo.lock "$ROOT"/examples/*/Cargo.lock; do args+=(--lockfile "$lock"); done
  json="$CACHE/osv-scan.json"
  osv-scanner scan source --format json "${args[@]}" >"$json" || rc=$?
  ((rc == 0 || rc == 1)) || die "osv-scanner failed (exit $rc)"
  jq -r '.results[]?.packages[]? | .package as $p | .vulnerabilities[]?
         | "\($p.name) \($p.version) \(.id)"' "$json" | sort -u
}

# Re-resolves only what the new pins require; the examples are
# standalone workspaces whose lockfiles CI builds with --locked.
update_lockfiles() {
  local lock
  (cd "$ROOT" && cargo update --workspace) || return 1
  for lock in "$ROOT"/examples/*/Cargo.lock; do
    (cd "$(dirname "$lock")" && cargo update --workspace) || return 1
  done
}

apply() {
  local p status line days c old new wt="" wb="" table="" before after added
  command -v osv-scanner >/dev/null || die "osv-scanner is not on PATH"
  p="$(plan)"
  printf '%s\n' "$p"
  status="$(awk '$1 == "status" { print $2 }' <<<"$p")"
  if [[ $status != bump ]]; then
    log "nothing to bump ($status)"
    if [[ -n ${GITHUB_OUTPUT:-} ]]; then echo "changed=false" >>"$GITHUB_OUTPUT"; fi
    return 0
  fi
  line="$(awk '$1 == "line" { print $2 }' <<<"$p")"
  days="$(awk '$1 == "quarantine" { print $2 }' <<<"$p")"
  before="$(scan_lockfiles)"

  # Restore the manifest if the lockfile update fails, so a rerun sees
  # the old pins and tries again.
  cp "$MANIFEST" "$CACHE/Cargo.toml.orig"
  while read -r _ c old new; do
    [[ $c == wasmtime ]] && wt="$new"
    [[ $c == wit-bindgen ]] && wb="$new"
    table+="| \`$c\` | $old | $new |"$'\n'
    [[ $old == "$new" ]] && continue
    sed -i.bak -E "s/^($c = (\\{ *version = )?\")=$old\"/\\1=$new\"/" "$MANIFEST"
    rm -f "$MANIFEST.bak"
    [[ "$(current_pin "$c")" == "$new" ]] || die "failed to rewrite the $c pin"
  done < <(grep '^pin ' <<<"$p")

  if ! update_lockfiles; then
    cp "$CACHE/Cargo.toml.orig" "$MANIFEST"
    die "cargo update failed; Cargo.toml restored"
  fi

  after="$(scan_lockfiles)"
  added="$(comm -13 <(printf '%s\n' "$before") <(printf '%s\n' "$after") | sed '/^$/d')"
  if [[ -n $added ]]; then
    log "the bump adds vulnerabilities (package version advisory); no PR:"
    while read -r pkg ver id; do
      echo "::error title=wasm toolchain bump adds a vulnerability::$pkg $ver: $id"
    done <<<"$added"
    if [[ -n ${GITHUB_OUTPUT:-} ]]; then echo "changed=false" >>"$GITHUB_OUTPUT"; fi
    return 0
  fi

  local title="build(deps): bump wasm toolchain to wasmtime $wt, wit-bindgen $wb"
  local body_file="${PR_BODY_FILE:-${RUNNER_TEMP:-${TMPDIR:-/tmp}}/wasm-toolchain-pr.md}"
  cat >"$body_file" <<EOF
Bumps the exact-pinned wasm toolchain together onto wasm-tools $line, the line wasmtime $wt is built on. wit-bindgen moves to its newest release on the same line, so the host and the guest bindings share one wasm-tools release line.

| crate | from | to |
| --- | --- | --- |
${table}
Only releases published at least $days days ago were considered (the scheduled default, 7 days, matches Dependabot's cooldown for every other dependency). None of the new pins has an OSV advisory, and osv-scanner finds no vulnerability in the updated lockfiles that main doesn't already have. The root and \`examples/*\` lockfiles were updated with \`cargo update --workspace\`. If the WIT contract baseline or the generated bindings change, fix them up in this PR before merging.

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
