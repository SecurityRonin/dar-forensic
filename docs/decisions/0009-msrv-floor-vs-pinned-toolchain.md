# 9. Declared MSRV floor (1.85) separate from the pinned dev toolchain (1.96.0)

Date: 2026-07-24
Status: Accepted

## Context

The fleet policy (constitution: *Rust MSRV & Toolchain Policy*) separates two
things that must not be conflated:

- the **dev toolchain** — one pinned current-stable version every contributor and
  CI builds/fmts/clippies with, to end "which Rust am I on" drift;
- the **declared MSRV** (`rust-version`) — a downstream-facing compatibility
  promise, kept **low and CI-verified** for *published libraries* so a wide
  crates.io audience can depend on them.

`dar-core` and `dar-forensic` are published libraries (ADR 0001), so they must
keep a real, low MSRV floor rather than tracking the dev toolchain.

## Decision

- **Pin the dev toolchain** to the fleet's current stable in
  `rust-toolchain.toml` (`channel = "1.96.0"`, with `clippy`/`rustfmt`
  components declared in the toml so CI and local agree — commit `3fc4363`
  `chore: pin toolchain to 1.96.0`).
- **Declare a low MSRV floor** of `rust-version = "1.85"` once in
  `[workspace.package]` (`Cargo.toml`), inherited by both members via
  `rust-version.workspace = true` (commit `defc9f8`). This is deliberately far
  below the 1.96.0 dev pin — the two are decoupled by design.

## Consequences

- Downstream consumers can build `dar-core`/`dar-forensic` on Rust 1.85+, while
  contributors develop on the pinned 1.96.0 — the promise is wider than the
  build environment.
- The `1.85` figure is higher than the fleet's usual `1.75`/`1.80` library
  floor. **Rationale reconstructed from structure; original intent not recovered
  in available history** — the exact dependency that raised the floor to 1.85 is
  not pinned down by the commit record (edition is 2021, which does not itself
  require 1.85, so the driver is most likely one of the always-compiled
  pure-Rust decoder crates per ADR 0004). The floor should be treated as
  CI-verified fact and only lowered if a `cargo msrv`/CI check confirms a lower
  version builds.
- Keeping MSRV in `[workspace.package]` (not restated per-crate) means a
  deliberate fleet bump is one edit; a second copy would drift.
