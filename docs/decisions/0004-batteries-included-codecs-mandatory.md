# 4. Batteries-included — all six codecs are mandatory, not Cargo features

Date: 2026-07-24
Status: Accepted

## Context

Early versions made the heavier decoders (gzip/bzip2/xz) **optional Cargo
features** so a consumer could build a "lean reader" (commit `f1cbc3e`,
`feat: make gzip/bzip2/xz optional features`). That directly contradicts the
fleet's *Batteries-Included* law: a forensic tool in the field must do the whole
job from one artifact — an examiner on an evidence workstation cannot
`cargo build --features xz`, and a codec that is not compiled in is a capability
that is not there when the archive that needs it lands. `default-features =
false` as a way to slim a forensic reader is banned by the constitution.

## Decision

Compile **all six decompression codecs (gzip, bzip2, xz, zstd, lz4, lzo)
unconditionally** into `dar-core`; remove the per-codec features and the
`default-features = false` lean build (commit `7e76ca9`,
`feat(dar-forensic)!: codecs are mandatory, not optional`). The only optional
feature that remains is `serde` (structured `audit()`/entry export), plus the
`vfs` adapter feature (ADR 0010). `core/Cargo.toml` documents this in the
`[features]` block: "All six decompression codecs … are always compiled in — a
forensic reader must be able to read every variant it encounters, so they are
not optional."

A direct consequence, taken in the same commit: with every codec always
decodable, the "unsupported codec" state no longer exists for any archive `dar`
can produce, so `AnomalyKind::UnsupportedCodec` and its audit check were
**removed**. Malformed compressed data still surfaces loudly as a `Corrupt`
error from `extract()` — the failure is not silenced, it is relocated from a
static capability gap to a runtime data-integrity error.

## Consequences

- `dar-forensic` reads every codec `dar -z<algo>` produces out of the box, in
  both single-stream and per-block (`block_compressor`) modes, with zero build
  flags.
- CI simplifies: the `--no-default-features` build/coverage permutations were
  dropped, leaving a single `--all-features`-equivalent run with no feature
  divergence to union over (commit `7e76ca9`).
- This was a **breaking change** (features removed from the public manifest
  surface); it was released as a major bump.
- Cost: the dependency graph carries all six decoder crates always. Accepted —
  they are pure-Rust and small, and completeness is the whole point.
