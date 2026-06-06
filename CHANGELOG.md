# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **`DarReader::entry_count()` and `iter_entries()`.** `entry_count()` returns
  the number of catalogue entries in O(1) without cloning the list; `iter_entries()`
  yields one `DarEntry` at a time so a streaming consumer over a large archive
  (hundreds of thousands of entries) need not hold the whole `Vec<DarEntry>` in
  memory. `entries()` is unchanged.
- **Per-file CRC verification.** `DarReader::verify(path)` recomputes libdar's
  per-file CRC over the decompressed data and compares it to the value stored in
  the catalogue, returning `CrcStatus::Match`, `Mismatch { stored, computed }`
  (lowercase hex), or `NotStored` (edition-1 archives record none). It never
  withholds the bytes — data that fails its CRC can still be `extract`ed to
  examine the corruption. Validated against real dar fixtures (formats 7–11 and
  the gzip/bzip2/xz archives, confirming the CRC covers the decompressed
  plaintext). The catalogue CRC width is bounded against an allocation bomb.
- **Optional compression codecs (`gzip` / `bzip2` / `xz`), all on by default.**
  Build with `default-features = false` for a lean reader carrying zero codec
  dependencies — enough to list and extract *stored* archives (e.g. the
  uncompressed Passware Kit Mobile corpus) with a much smaller supply-chain
  surface. A codec left disabled is still recognised: such an entry is listed
  and flagged by `audit()`, and `extract()` returns a clear "not supported in
  this build" error rather than ever mis-reading compressed data as stored.
- **Sleuth Kit bodyfile export.** `DarEntry::bodyfile()` renders one TSK
  `mactime` line (`MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime`),
  and `DarReader::write_bodyfile(&mut writer)` streams a line per catalogue
  entry — so a DAR archive drops straight into a `mactime` timeline. The mode
  field uses TSK's `type/type+perms` form (with setuid/setgid/sticky), symlink
  targets are appended, and `|`/`\`/control bytes in names are escaped.
- **`DarReader::audit()` — forensic anomaly detection.** Walks the parsed
  catalogue (no archive data read) and returns severity-graded `Anomaly`
  findings, most-severe first: incomplete catalogue, entries using a
  recognised-but-undecodable codec (lzo/zstd/lz4), absolute paths, `..`
  parent-traversal, duplicate paths, implausibly-far-future timestamps (beyond
  the year-2100 ceiling), and control bytes in names. Each finding carries a
  stable `code`, a `Severity`, and a human-readable note framed as an
  observation ("consistent with …"), not a conclusion. Mirrors the sibling
  forensic crates' findings vocabulary.
- **Optional `serde` feature** derives `Serialize` on the entry types
  (`DarEntry`, `EntryKind`) and the `audit()` finding types (`Severity`,
  `AnomalyKind`, `Anomaly`) for JSON/structured export. Off by default — the
  core reader keeps zero serialization dependencies. In JSON, an entry's `path`
  and `symlink_target` are the lossy-UTF-8 display string (the byte-exact values
  remain on the typed fields).
- **`DarReader::extract_to<W: Write>(path, &mut out)`** streams an entry's
  (decompressed) bytes straight to any writer without buffering the whole file,
  returning the byte count; safe for multi-GiB entries. `extract()` now
  delegates to it.
- **`DarReader::is_complete()`** reports whether the catalogue parsed to a clean
  root end-of-directory; an unmodelled entry type or truncation marks the
  listing incomplete (loud, not a silently short listing).

### Changed

- **BREAKING: `DarEntry` now exposes full forensic metadata** — `path` is raw
  bytes (`Vec<u8>`, with `path_lossy()` for display; a non-UTF-8 filename no
  longer fails `open()`), plus `kind` (`EntryKind`), `uid`, `gid`, `mode`,
  `atime`, `mtime`, `ctime`, and `symlink_target`. `entries()` now lists every
  inode type (files, directories, symlinks, pipes, sockets), not just files.

## [0.3.0] — 2026-06-06

### Added

- **DAR format edition 1 (dar 1.0.x, 2002).** Reverse-engineered from a real
  edition-1 archive and implemented: the flagless inode (no EA flag byte, no
  ctime, no FSA), the `size·offset`-only `cat_file` (no `storage_size`, no CRC;
  `storage_size` synthesised), and the `"root"`-named root. Validated
  byte-for-byte against a real dar-1.0.0 archive.
- **Compressed pre-8 archives now list and extract.** Formats ≤ 7 carry no
  per-entry compression byte, so the archive-global codec governs both the
  terminateur-located catalogue and every entry. The pre-8 path now inflates a
  compressed catalogue (previously any compressed pre-8 archive silently listed
  zero entries), and `cat_file` parsing is format-aware across editions 1 / 2–7
  / 8+. A compressed format-1 entry (which has no `storage_size`) is decoded by
  streaming the codec to its natural end.
- **Named-pipe (`p`) and socket (`s`) inodes are skipped** rather than stopping
  the catalogue walk — real full-filesystem archives contain them (all formats).
- A second CI gate holds the public-API (`tests/`) suite to 100% line coverage,
  alongside the existing combined-coverage gate.

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

[0.3.0]: https://github.com/SecurityRonin/dar-forensic/releases/tag/v0.3.0
[0.2.0]: https://github.com/SecurityRonin/dar-forensic/releases/tag/v0.2.0
[0.1.0]: https://github.com/SecurityRonin/dar-forensic/releases/tag/v0.1.0
