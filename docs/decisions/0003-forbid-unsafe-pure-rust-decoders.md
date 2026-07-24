# 3. `unsafe_code = "forbid"` — pure-Rust decompressors, no C bindings, no GPL

Date: 2026-07-24
Status: Accepted

## Context

DAR is a C++ format; the reference implementation (`libdar`) is **GPL** and ships
as a **C library with FFI bindings**. A Rust reader could have wrapped `libdar`
or reached for `-sys` codec crates (zlib, bzip2, xz, lz4, lzo all have mature C
bindings). The constitution's *unsafe is an avoidable cost-benefit exception*
law makes `forbid(unsafe)` the default and goal for evidence parsers, and treats
a **C-FFI `-sys` dependency as a categorically worse liability** than pure-Rust
code — the compiler has zero visibility into C, and a malicious archive is
attacker-controlled input feeding those decoders. A GPL linkage would also be
incompatible with the fleet's Apache-2.0 licensing (ADR is out of scope here but
see `LICENSE`).

## Decision

Set **`unsafe_code = "forbid"`** at the workspace root (`[workspace.lints.rust]`
in `Cargo.toml`) — a *provable*, badge-able "zero places a crafted input can
corrupt memory", not the downgraded `deny` + bounded-allow that mmap readers
(`ewf`) use. There is no mmap or FFI site to justify a downgrade.

To hold `forbid`, every decompressor is a **pure-Rust, decompress-only** crate,
selected explicitly for that property (`[workspace.dependencies]` comments in
`Cargo.toml`):

- gzip → `flate2` with `rust_backend` (miniz_oxide), not the C zlib backend
- bzip2 → `bzip2-rs` (pure-Rust decoder)
- xz/lzma → `lzma-rs`
- zstd → `ruzstd`
- lz4 → `lz4_flex` with `safe-decode`
- lzo → `lzo` with `default-features = false` (itself `#![forbid(unsafe_code)]`)

## Consequences

- The whole workspace compiles with no `unsafe`, no C toolchain, and no GPL —
  it is a single pure-Rust artifact that cross-compiles cleanly and carries the
  `unsafe forbidden` trust posture the README advertises.
- Two production `char::from_digit(..).unwrap()` sites (hex encoding, name
  escaping) were replaced with bounds-checked lookup-table indexing at the split
  (commit `8d292b6`) so the code is panic-free *without* `unsafe` and without
  `unwrap` (see ADR 0008).
- Trade-off: pure-Rust decoders may be slower than their C equivalents and, for
  newer formats, less battle-tested — accepted deliberately, because for an
  evidence parser memory-safety-by-construction outweighs codec throughput.
- Note: the `README.md` comparison table currently labels the posture
  `unsafe_code = "deny"`; the shipped lint is the stricter `"forbid"` — the doc
  understates the guarantee and should be corrected to `"forbid"`.
