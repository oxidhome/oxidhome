# Architecture Decision Records

Each ADR records one settled, cross-cutting decision: its context, the choice, the options we rejected, and the
consequences. Read them after [`ARCHITECTURE.md`](../../ARCHITECTURE.md), which describes the current accepted
architecture, and before the WIT contract in [`wit/oxidhome.wit`](../../wit/oxidhome.wit).

An accepted ADR is not rewritten when the decision changes. Instead a new ADR supersedes it, and the old one gets
`Status: superseded` and a `Superseded by` link. Start a new record from [`template.md`](template.md) and take the next
free number.

| ADR                                                     | Title                                                         | Status   | Date       |
|---------------------------------------------------------|---------------------------------------------------------------|----------|------------|
| [0001](0001-one-sandbox-per-script.md)                  | One sandbox per script for same-instance script calls (H1)    | accepted | 2026-11-22 |
| [0002](0002-in-process-native-media-and-inference.md)   | Native media and inference stay in-process, with strict limits (H7) | accepted | 2026-11-22 |
| [0003](0003-explicit-command-outcomes.md)               | Explicit command outcome states (H5)                          | accepted | 2026-11-22 |
| [0004](0004-scripts-as-services.md)                     | Scripts are services                                          | accepted | 2026-06-01 |
| [0005](0005-connect-rpc-alongside-rest.md)              | Connect RPC alongside the JSON/REST API                       | accepted | 2026-07-28 |
| [0006](0006-resource-ceilings.md)                       | Host resource ceilings replace "no compute limits" (C4)      | accepted | 2026-07-31 |
| [0007](0007-0x-publication-policy.md)                   | 0.x publication policy and the unpublished WIT baseline       | accepted | 2026-11-22 |
