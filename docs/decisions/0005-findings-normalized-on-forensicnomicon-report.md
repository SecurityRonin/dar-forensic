# 5. Normalize audit findings onto `forensicnomicon::report`

Date: 2026-07-24
Status: Accepted

## Context

Every analyzer in the fleet must emit findings as one shared model so that
ORCHESTRATION (issen, disk-forensic) and a future GUI render them uniformly,
rather than each analyzer inventing its own `XxxAnalysis` type (constitution:
*The Reporting Model — `forensicnomicon::report`*). The producer pattern is:
keep the analyzer's own typed anomaly enum (the domain knowledge), and convert
to the canonical `Finding` via `impl Observation` — `forensicnomicon` never
enumerates every anomaly kind.

## Decision

`dar-forensic` keeps a typed **`AnomalyKind`** enum (`forensic/src/findings.rs`)
carrying the evidence for each observation, and implements
**`forensicnomicon::report::Observation` for `Anomaly`** (`severity` / `code` /
`note`), so a DAR finding aggregates uniformly alongside partition- and
filesystem-layer findings (commits `d6c3dc1` RED / `0711a3a` GREEN,
`feat(dar-forensic)!: GREEN — normalize onto forensicnomicon::report`). Each
anomaly's `severity`, stable machine-readable **`code`** (a published contract,
e.g. `DAR-CATALOG-INCOMPLETE`, `DAR-PATH-TRAVERSAL`), and human note are
*derived* from the `AnomalyKind` so they cannot drift.

Conventions enforced (per the constitution's reporting model):

- Findings are **observations, never verdicts** — notes say "consistent with …";
  the examiner draws the conclusion (`forensic/src/lib.rs` and `findings.rs`
  module docs both state this).
- `audit()` reads the **catalogue metadata only** — no entry data is decoded —
  and returns anomalies sorted most-severe first.

## Consequences

- A disk-forensic orchestrator can merge DAR findings into a single `Report`
  with no bespoke adapter — the `Observation` impl is the whole seam.
- The `code` strings are a **stable external contract**: a shipped code is never
  changed; new variants get new codes (constitution rule).
- Adopting the shared model was a breaking API change (release bump), because
  the returned finding type changed — accepted once, for fleet uniformity.
- `dar-forensic` gains a dependency on `forensicnomicon`; `dar-core` deliberately
  does **not** (ADR 0001 keeps the parser free of the reporting model).
