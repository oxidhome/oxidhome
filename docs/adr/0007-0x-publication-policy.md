# ADR-0007: 0.x publication policy and the unpublished WIT baseline

- **Status:** accepted
- **Date:** 2026-11-22
- **Deciders:** the maintainer
- **Supersedes:** none
- **Superseded by:** none
- **References:** PRs #4, #174, #177, #180; `CONTRIBUTING.md` "Development setup"; `ARCHITECTURE.md` "Bindgen and publication"

## Context

The WIT contract and the crates built on it change often before 1.0. Publishing them would freeze contracts nobody
outside the repo depends on yet, and the crates cannot be packaged as they stand: path dependencies, and a `wit/`
directory at the workspace root that the bindgen crates read from outside their own crate roots.

## Decision

- Every workspace crate has `publish = false` through 0.x. All of them become publishable together at the first SDK
  release meant for external plugin authors. Versions live only in the root `Cargo.toml`.
- The WIT package is versioned with semver, and `contract_baseline` compares `wit/` with the committed baseline of
  the current version. A contract change needs a version bump and a new baseline.
- **Exception while unpublished:** until `oxidhome-sdk` is published, no released contract exists, so the current
  version's baseline may be changed in place (delete it and bless it again) instead of bumping the version. Once the
  SDK is published, baselines are immutable and compatible bumps must pass the semver check.

## Rejected options

- **Publishing crates during 0.x.** Freezes contracts early and needs packaging work for the WIT files first.
- **Bumping the WIT version on every change before publication.** Version churn with no consumer to protect.

## Consequences

- Breaking WIT changes before the first SDK release stay cheap, and plugins must be rebuilt after one.
- The compatibility guarantees (immutable baselines, semver checks) start at the first SDK release.
- A second-language SDK that needs a versioned WIT artifact would force this decision to be revisited sooner.
