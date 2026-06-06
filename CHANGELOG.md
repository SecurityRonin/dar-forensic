# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] — 2026-06-06

### Added

- **Transparent decompression of gzip, bzip2 and xz archives.** `dar -z`
  compresses *both* the catalogue (a single codec stream after the
  `seqt_catalogue` escape) and each entry's data (an independent stream at its
  archive offset). The reader now inflates the catalogue, so compressed archives
  **list** their entries, and `extract()` inflates each entry's stream. Decoders
  are pure-Rust (`flate2` with the `miniz_oxide` backend, `bzip2-rs`, `lzma-rs`),
  keeping the crate free of C bindings and `unsafe`. Validated against real
  `dar 2.8.5` `-zgzip` / `-zbzip2` / `-zxz` fixtures.
- Decompression-bomb guards: the catalogue is capped by a constant, and each
  entry by its catalogue-declared uncompressed size — a forged stream cannot
  over-inflate.

### Changed

- `extract()` no longer rejects every compressed entry. It returns the
  decompressed bytes for gzip/bzip2/xz; lzo, zstd and lz4 are recognised but not
  yet decoded and still return a clear `Corrupt` error (never wrong bytes).

### Fixed

- CI: install `cargo-fuzz` **without** `--locked` — its pinned `rustix 0.36` no
  longer builds on current nightly (reserved `rustc_*` attributes).
- CI: pin the gitleaks version instead of querying `releases/latest`, which is
  rate-limited on shared runners (empty version → 404).

## [0.1.0] — 2026-06-05

### Added

- Initial release: pure-Rust, read-only reader for Denis Corbin DAR archives.
- DAR formats 7–11 validated against real `dar` fixtures (dar 2.3.12–2.8.5), plus
  the legacy ≤7 grammar via the end *terminateur* trailer.
- Catalogue enumeration and random-access (`Read + Seek`) extraction, with a
  tail-scan optimisation for 90+ GiB archives.
- Passware Kit Mobile (tape-marks-disabled) layout, located by `ref_data_name`.
- Hardened against malicious input (no panic / OOM / backward seek), continuous
  `cargo fuzz`, and 100% CI-enforced line coverage.

[0.2.0]: https://github.com/SecurityRonin/dar-forensic/releases/tag/v0.2.0
[0.1.0]: https://github.com/SecurityRonin/dar-forensic/releases/tag/v0.1.0
