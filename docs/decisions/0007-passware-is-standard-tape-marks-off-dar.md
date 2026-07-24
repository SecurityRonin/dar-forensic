# 7. Treat "Passware archives" as standard tape-marks-off DAR, not a vendor format

Date: 2026-07-24
Status: Accepted

## Context

Mobile-forensics tools (Passware Kit Mobile, Cellebrite) emit DAR archives for
full-filesystem extractions. These archives have **no `seqt_catalogue` escape**,
which at first looks like a vendor-specific dialect that would justify a
`if passware { … }` branch in the reader. The constitution's *No Special Cases*
law is explicit that such a branch is "a confession that the model is wrong": it
fixes one instance and leaves siblings broken, and it games the visible sample
instead of solving the general problem.

Investigation (recorded in `README.md`, *Note on the "Passware variant"*, and in
`core/src/lib.rs` around the `data_name`/`ref_data_name` handling) showed the
escape is **not** vendor-specific: it is an *optional sequential-read tape mark*.
Passware simply writes archives with tape marks **disabled** — equivalent to
`dar -at`. Official `dar` reads them too. The catalogue is still present at the
tail; only its escape marker is absent.

## Decision

Handle the two cases through the **general** structural rule, not a vendor
branch. The archive's `data_name` (TLV type `0x0003`, a 10-byte label) is the
identity the catalogue's `ref_data_name` points at:

- **Tape marks on:** locate the catalogue by the `SEQT_CATALOGUE` escape
  (`AD FD EA 77 21 43`).
- **Tape marks off (Passware, `dar -at`, `dar_xform`-resliced):** locate the
  catalogue by matching its `ref_data_name` label — a *real structural field*,
  the same 10 bytes as the slice label — via the same tail-anchored scan
  (`find_catalogue` in `core/src/lib.rs`; commit `f0ad5ff`
  `feat(green): read re-sliced (dar_xform) and format-11.1+ tape-off catalogues`).

There is no "Passware mode" and no product-name literal in the parser — the
reader keys off the presence/absence of the escape and the `ref_data_name`
label, which is the general rule that both cases are instances of.

## Consequences

- One code path reads tape-marked *and* tape-mark-free archives, including
  archives re-sliced by the reference `dar_xform` tool (validated against a
  `dar_xform` oracle, `docs/validation.md`).
- The reader would correctly handle any future tool that writes tape-marks-off
  DAR, not just the two vendors seen today — the No-Special-Cases test ("would
  this still be correct for an unseen member of the same class?") passes.
- The "Passware variant" framing is documented as a *misconception*, so a future
  maintainer is not tempted to re-introduce a vendor special-case.
