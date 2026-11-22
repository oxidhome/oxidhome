//! WIT contract baselines (architecture review M1).
//!
//! `baselines/oxidhome-plugin@<version>.wit` holds the normalized
//! (doc comments stripped, `wit-component`-printed) form of every
//! released `oxidhome:plugin` package version. These tests fail when:
//!
//! - `wit/` changes the contract without bumping the package version
//!   (the current version's baseline no longer matches);
//! - the current version has no baseline yet;
//! - a version bump that claims to be compatible (same `0.x` minor, or
//!   same major after 1.0) isn't, per `wit_component::semver_check`.
//!
//! Doc-comment and formatting edits never fail: they don't change the
//! normalized form.
//!
//! To change the contract: bump the version in `wit/oxidhome.wit`
//! (`0.1.0` → `0.2.0` for a breaking change while 0.x, `0.1.0` →
//! `0.1.1` for an additive one), then record the new baseline with
//!
//! ```sh
//! OXIDHOME_BLESS_WIT_BASELINE=1 cargo test -p oxidhome-wit --test contract_baseline
//! ```
//!
//! Blessing only ever creates a missing baseline; it refuses to rewrite
//! an existing one, because that version may already be in plugins'
//! hands. CI also rejects PRs that modify or delete an existing
//! baseline file.

use std::path::{Path, PathBuf};

use semver::Version;
use wit_component::WitPrinter;
use wit_parser::{PackageId, Resolve};

const BLESS_ENV: &str = "OXIDHOME_BLESS_WIT_BASELINE";
const FILE_PREFIX: &str = "oxidhome-plugin@";

fn wit_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../wit")
}

fn baselines_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("baselines")
}

fn baseline_path(version: &Version) -> PathBuf {
    baselines_dir().join(format!("{FILE_PREFIX}{version}.wit"))
}

/// `wit/` parsed, plus the id and version of its main package.
fn current() -> (Resolve, PackageId, Version) {
    let mut resolve = Resolve::default();
    let (pkg, _) = resolve.push_dir(wit_dir()).expect("wit/ parses");
    let name = &resolve.packages[pkg].name;
    assert_eq!(
        (name.namespace.as_str(), name.name.as_str()),
        ("oxidhome", "plugin")
    );
    let version = name
        .version
        .clone()
        .expect("oxidhome:plugin must carry a version");
    (resolve, pkg, version)
}

fn normalized(resolve: &Resolve, pkg: PackageId) -> String {
    let mut printer = WitPrinter::default();
    printer.emit_docs(false);
    printer
        .print(resolve, pkg, &[])
        .expect("printing oxidhome:plugin");
    let mut text = printer.output.to_string();
    if !text.ends_with('\n') {
        text.push('\n');
    }
    text
}

/// Every committed baseline version, ascending.
fn baseline_versions() -> Vec<Version> {
    let Ok(entries) = std::fs::read_dir(baselines_dir()) else {
        return Vec::new();
    };
    let mut versions: Vec<Version> = entries
        .map(|entry| entry.expect("baselines/ entry").file_name())
        .filter_map(|name| {
            let name = name.to_str()?.to_owned();
            let version = name.strip_prefix(FILE_PREFIX)?.strip_suffix(".wit")?;
            Some(
                version
                    .parse()
                    .unwrap_or_else(|e| panic!("baselines/{name}: bad version: {e}")),
            )
        })
        .collect();
    versions.sort();
    versions
}

/// Whether `prev` → `next` claims to be a compatible bump: same `0.x`
/// minor before 1.0, same major after. Mirrors the SDK rule in
/// `oxidhome_manifest::check_compatibility`.
fn claims_compatible(prev: &Version, next: &Version) -> bool {
    if prev.major == 0 {
        next.major == 0 && next.minor == prev.minor
    } else {
        next.major == prev.major
    }
}

/// First differing line, for a readable failure.
fn first_difference(expected: &str, actual: &str) -> String {
    for (i, (e, a)) in expected.lines().zip(actual.lines()).enumerate() {
        if e != a {
            return format!("line {}:\n  baseline: {e}\n  wit/:     {a}", i + 1);
        }
    }
    format!(
        "baseline has {} lines, wit/ has {}",
        expected.lines().count(),
        actual.lines().count()
    )
}

#[test]
fn wit_matches_committed_baseline() {
    let (resolve, pkg, version) = current();
    let actual = normalized(&resolve, pkg);
    let path = baseline_path(&version);
    let bless = std::env::var_os(BLESS_ENV).is_some();

    match std::fs::read_to_string(&path) {
        Ok(expected) if expected == actual => {}
        Ok(expected) => panic!(
            "wit/ changed the oxidhome:plugin@{version} contract, but {version} already has a \
             committed baseline ({}).\n{}\n\nA released contract version is immutable. Bump the \
             package version in wit/oxidhome.wit (breaking: next 0.x minor; additive: next patch), \
             then run `{BLESS_ENV}=1 cargo test -p oxidhome-wit --test contract_baseline` to record \
             the new version's baseline.",
            path.display(),
            first_difference(&expected, &actual),
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if bless {
                std::fs::write(&path, &actual)
                    .unwrap_or_else(|e| panic!("writing {}: {e}", path.display()));
                eprintln!("recorded {}", path.display());
            } else {
                panic!(
                    "no baseline for oxidhome:plugin@{version}. Run `{BLESS_ENV}=1 cargo test -p \
                     oxidhome-wit --test contract_baseline` and commit {}.",
                    path.display(),
                );
            }
        }
        Err(e) => panic!("reading {}: {e}", path.display()),
    }

    let newest = baseline_versions().pop().expect("at least one baseline");
    assert_eq!(
        newest, version,
        "wit/ is at oxidhome:plugin@{version}, but a newer baseline {newest} exists; the contract \
         version must never go backwards",
    );
}

#[test]
fn compatible_version_bumps_are_semver_compatible() {
    let (mut resolve, current_pkg, current_version) = current();
    let mut versions = baseline_versions();
    // The current version is `wit/` itself, with or without a baseline
    // on disk yet (`wit_matches_committed_baseline` proves the two are
    // equal), so a fresh bump is checked even before it's blessed.
    if !versions.contains(&current_version) {
        versions.push(current_version.clone());
        versions.sort();
    }
    // Load every other baseline next to `wit/`, whose `deps/` resolve
    // their WASI imports.
    let packages: Vec<(Version, PackageId)> = versions
        .iter()
        .map(|v| {
            if *v == current_version {
                return (v.clone(), current_pkg);
            }
            let path = baseline_path(v);
            let text = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
            let pkg = resolve
                .push_str(&path, &text)
                .unwrap_or_else(|e| panic!("parsing {}: {e:?}", path.display()));
            (v.clone(), pkg)
        })
        .collect();

    for pair in packages.windows(2) {
        let ((prev, prev_pkg), (next, next_pkg)) = (&pair[0], &pair[1]);
        if !claims_compatible(prev, next) {
            continue;
        }
        check_pair(&resolve, *prev_pkg, *next_pkg)
            .unwrap_or_else(|e| panic!("{prev} -> {next} is not a compatible bump: {e}"));
    }
}

/// Every world of `prev` must still exist in `next` and pass
/// `semver_check`.
fn check_pair(resolve: &Resolve, prev: PackageId, next: PackageId) -> Result<(), String> {
    for (name, prev_world) in &resolve.packages[prev].worlds {
        let Some(next_world) = resolve.packages[next].worlds.get(name) else {
            return Err(format!("world `{name}` was removed"));
        };
        wit_component::semver_check(resolve.clone(), *prev_world, *next_world)
            .map_err(|e| format!("world `{name}`: {e:#}"))?;
    }
    Ok(())
}

/// The semver gate itself catches breaking edits and lets additive ones
/// through, so `compatible_version_bumps_are_semver_compatible` means
/// something before a second baseline exists.
#[test]
fn semver_gate_detects_breaking_changes() {
    let base = "package t:p@0.1.0;
        interface api { f: func(a: u32) -> string; }
        world w { import api; export run: func(); }";
    let additive = "package t:p@0.1.1;
        interface api { f: func(a: u32) -> string; g: func(); }
        world w { import api; export run: func(); }";
    let breaking = "package t:p@0.1.2;
        interface api { f: func(a: u64) -> string; }
        world w { import api; export run: func(); }";
    let mut resolve = Resolve::default();
    let base = resolve.push_str("base.wit", base).unwrap();
    let additive = resolve.push_str("additive.wit", additive).unwrap();
    let breaking = resolve.push_str("breaking.wit", breaking).unwrap();

    check_pair(&resolve, base, base).expect("identical");
    check_pair(&resolve, base, additive).expect("adding a function is compatible");
    let err = check_pair(&resolve, base, breaking).expect_err("changing a param type is breaking");
    assert!(err.contains("world `w`"), "{err}");
}

#[test]
fn compatibility_claims_follow_semver() {
    let v = |s: &str| s.parse::<Version>().unwrap();
    assert!(claims_compatible(&v("0.1.0"), &v("0.1.1")));
    assert!(!claims_compatible(&v("0.1.3"), &v("0.2.0")));
    assert!(claims_compatible(&v("1.2.0"), &v("1.3.0")));
    assert!(!claims_compatible(&v("1.9.0"), &v("2.0.0")));
    assert!(!claims_compatible(&v("0.9.0"), &v("1.0.0")));
}
