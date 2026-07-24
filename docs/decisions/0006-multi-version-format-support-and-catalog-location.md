# 6. Multi-version format decoding, big-endian, and tail-scan catalog location

Date: 2026-07-24
Status: Accepted

## Context

DAR is not one format but a family: the header `version_string` (each byte
`value + 48`) spans format 1 (dar 1.0.x) through format 11 (dar 2.7–2.8). The
grammars differ materially — formats ≤ 7 have no `seqt_catalogue` escape, `u16`
uid/gid, bare-seconds timestamps and a fixed 2-byte CRC; format 1 goes further
(no inode flag byte, a `size·offset`-only file record, no CRC); format 9+ adds
FSA and unit-prefixed timestamps; format 11.1 adds an in-place working-directory
path. On-disk integers are **big-endian**, and the pervasive length/count
encoding is libdar's variable-length **`infinint`**. All of this had to be
reverse-documented from the GPL `libdar` source rather than a published spec
(constitution: *Research-First* — locate the authoritative reference).

A forensic reader is also pointed at very large archives (a real **92 GiB**
Passware extraction is in the validation corpus). The DAR catalogue always lives
at the **tail** of the archive, so reading front-to-back to find it would read
tens of GiB needlessly.

## Decision

Decode the full multi-version grammar in one reader (`core/src/lib.rs`,
per-version layout documented in `docs/implementation-notes.md` §11–§12):
formats **7–11** are validated against real committed per-release fixtures
(`v7_hello.dar` … `v11_hello.dar`). Format **1** was validated during
development against a confidential dar-1.0.0 archive that is **not committed**,
so no in-repo fixture backs it (`docs/validation.md`, "Recommended
strengthening"). Formats 2–6 share the format-7 grammar and are parsed. Key
format choices, all grounded in the `libdar` layout:

- **Big-endian** throughout; magic is `00 00 00 7b` (`SAUV_MAGIC_NUMBER = 123`,
  big-endian `u32`, `DAR_MAGIC` in `lib.rs`).
- **`archive_offset` points directly at the raw file bytes**, not at the
  data-section header that precedes them — `seek(archive_origin +
  archive_offset)` then `read(stored_size)` (documented invariant, `lib.rs`
  module header).
- **Catalog located by a tail-anchored forward scan.** On archives larger than
  `TAIL_SCAN = 256 MiB` the scan starts that many bytes before EOF (the catalog
  is always at the tail), falling back to a full scan only if not found
  (`core/src/lib.rs` `TAIL_SCAN`, `find_catalogue`). This is what lets the reader
  open a 90+ GiB archive reading ≈107 MiB, not 99 GiB (README).
- **Multi-volume (sliced) archives** are read as one logical stream via
  `SliceReader`; file data spanning slices is transparent (commits `32d5afe`,
  `f0ad5ff`).

## Consequences

- One `DarReader` reads dar 1.0.0 through dar 2.8.5 archives, tape-marked or not,
  single- or multi-slice — the analyst does not pick a format.
- Large-archive triage is practical: catalogue location is bounded, not linear
  in archive size.
- The grammar knowledge is reverse-engineered from GPL source; the risk is a
  format quirk a fixture did not exercise. Mitigated for formats 7–11 by
  validating each against a committed real upstream-`dar`-written fixture
  (`docs/validation.md`) — an independent oracle, not self-authored bytes.
  Format 1 rests on the (uncommitted) development archive only; formats 2–6 are
  covered transitively via the shared format-7 grammar.
- `infinint` encodings wider than 64 bits are rejected as corrupt rather than
  truncated (see ADR 0008) — a correctness/robustness boundary of this decoder.
