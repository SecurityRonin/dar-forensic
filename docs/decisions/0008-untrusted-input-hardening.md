# 8. Harden the parser for untrusted input — panic-free, bounded, fuzzed

Date: 2026-07-24
Status: Accepted

## Context

A DAR archive handed to this reader is **evidence from a potentially hostile
source** — a crafted archive must not crash the tool, exhaust memory, or (worse)
silently emit wrong bytes. The fleet's *Paranoid Gatekeeper* standard is
mandatory for every `*-core`/`*-forensic` crate: never panic, never read out of
bounds, never trust a length field, cap allocations, and fuzz every parsed
structure.

## Decision

Enforce a panic-free, bounded posture across the workspace:

- **Panic-free by lint.** `unwrap_used` and `expect_used` are `deny` at the
  workspace root (`[workspace.lints.clippy]` in `Cargo.toml`); production code
  carries no `unwrap`/`expect`/`panic!`. Tests opt out via
  `#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]` plus the
  `allow-*-in-tests` keys in `clippy.toml`.
- **`infinint` decodes to `u64` or errors — never truncates.** Encodings wider
  than 64 bits are rejected as corrupt (`core/src/lib.rs` module header), so a
  lying length field fails loud instead of wrapping.
- **Explicit allocation/size caps against bombs** (`core/src/lib.rs` constants):
  `MAX_CATALOGUE_COMPRESSED` (512 MiB) and `MAX_CATALOGUE_INFLATED` (1 GiB) guard
  the tail read and inflation; `MAX_CRC_SIZE` (64 KiB) caps a declared CRC width;
  `MAX_BLOCK_SIZE` (256 MiB) caps a per-block uncompressed size; per-file streams
  are bounded by the entry's known size.
- **The catalog scan never seeks backwards** (`core/src/lib.rs`, "skip must never
  seek backwards") — a crafted offset cannot drive an infinite loop or a
  re-read.
- **Continuous fuzzing.** Three `cargo fuzz` targets — `fuzz_open`, `fuzz_read`
  over the parser, and `fuzz_forensic` over the full audit pipeline
  (`fuzz/fuzz_targets/`) — built and smoke-run by `.github/workflows/fuzz.yml`,
  run on nightly (`cargo +nightly fuzz`, commit `50bf0c1`, because the pinned
  stable toolchain rejects the `-Z` flags).
- **100% line coverage, CI-enforced** (`docs/validation.md`, CI coverage job).

## Consequences

- The differentiator claim is **"input-fuzzed"** (measured, tier-1) paired with
  **"panic-free by lint"** (the static posture) — not a bare "panic-free"
  absolute (constitution: *Robustness wording*).
- A malformed/truncated archive surfaces as a loud `DarError::Corrupt` (or an
  `IncompleteCatalog` audit finding) with context, never a panic or silent short
  listing — Fail-Loud honoured.
- The caps are deliberately generous (far beyond any real `dar` setting) so they
  reject only pathological input, not legitimate large archives.
