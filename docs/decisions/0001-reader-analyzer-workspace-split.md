# 1. Split into `dar-core` (parser) + `dar-forensic` (analyzer) workspace

Date: 2026-07-24
Status: Accepted

## Context

`dar-forensic` began life (through 0.7.0) as a single crate holding both the
DAR-archive parser and the forensic layer (anomaly auditing, bodyfile export).
The SecurityRonin fleet standardises on a **reader/analyzer split** for every
format: a `core/` crate that reads *valid* data robustly, and a `forensic/`
crate that audits it for anomalies (constitution: *Crate-structure standard —
reader/analyzer split*, reference impl `ntfs-forensic`/`qcow2-forensic`). Two
forces drove adopting it here:

- A pure parser is reusable by third parties and by other fleet layers
  (`forensic-vfs`, an eventual `disk-forensic` container path) that want to read
  a DAR tree **without** pulling in `forensicnomicon` and the reporting model.
- The analyzer and the parser have different dependency footprints and different
  audiences (a Rust dev wiring an archive reader vs. an examiner grading
  findings); one crate forces both on everyone.

## Decision

Restructure into a Cargo workspace with two members (commit `8d292b6`,
`refactor!: split into dar-core (parser) + dar-forensic (analyzer)`):

- **`core/`** → package **`dar-core`** — the pure parser: slice/catalog/header/CRC
  decode, all six decompression codecs, and `Read + Seek` navigation
  (`DarReader`, `SliceReader`, `DarEntry`, `EntryKind`, `CrcStatus`, `DarError`).
  No `forensicnomicon` dependency.
- **`forensic/`** → package **`dar-forensic`** — the analyzer. Re-exports the
  full parser API (`pub use dar::{…}` in `forensic/src/lib.rs`) and adds the
  forensic layer: `findings.rs`, `bodyfile.rs`, and the `DarAudit`/`DarBodyfile`
  extension traits. **Depends on `dar-core`** (workspace dep `dar = { … package =
  "dar-core" }`).

Dependency direction is one-way: `dar-forensic → {dar-core, forensicnomicon}`.
`dar-core` depends on neither — it has **no `forensicnomicon` dependency** (see
ADR 0005) — while `dar-forensic` depends on `dar-core` *and*, directly and
separately, on `forensicnomicon` (the leaf) for the reporting model. The
analyzer builds on `dar-core`'s public reader API because that API already
exposes the raw catalogue the audit needs (`iter_entries`, `is_complete`,
`entry_count`); it does not currently need to drop below `-core`.

## Consequences

- The public surface of `dar-forensic` is unchanged from the pre-split crate:
  every previously-exported type still resolves as `dar_forensic::*`, so the
  re-export makes the analyzer crate alone sufficient for forensic work. This was
  a behaviour-preserving refactor (all tests stayed green).
- `dar-core` is independently publishable and linkable — a developer who only
  needs to read archives adds `dar-core` and never sees the reporting model.
- The two crates carry **independent versions** (core `0.7.0`, forensic `0.8.0`
  today) — a forensic-only change need not bump the parser, and vice-versa.
- Cost: two manifests, two READMEs, and a workspace to keep in DRY sync (handled
  via `[workspace.package]`/`[workspace.dependencies]` inheritance, commit
  `defc9f8`).
