# Validation

`dar-forensic` parses untrusted DAR (Disk ARchiver) archives from potentially
compromised or adversarial sources. Correctness is therefore established the way
forensic tooling must be: against **independent oracles** (a different tool, or a
different code path, that already produced or decodes the same bytes correctly)
on archives whose ground truth is known — never against fixtures we hand-encoded
and then graded ourselves, except for narrowly-scoped code-path coverage that is
labelled as such.

This page records exactly which oracle backs each capability, so the claim is
independently re-checkable. Per-file provenance (which `dar` release built each
fixture, contents, sizes) lives in
[`forensic/tests/data/README.md`](https://github.com/SecurityRonin/dar-forensic/blob/main/forensic/tests/data/README.md);
the fleet-wide machine index is `issen/docs/corpus-catalog.md`. This page
cross-references both rather than duplicating them.

## How to read the evidence tiers

Each validation below is tagged with the trustworthiness of its check, not
whether the data is "synthetic":

- **Tier 1** — an independent third party authored the artifact *and* the answer
  key, or it is real-world data decoded by an independent tool. The strongest claim.
- **Tier 2** — real engine output whose ground truth is derivable from the
  documented construction, or confirmed by an *independent code path* on real
  data. Genuinely checked, but we chose the scenario.
- **Tier 3** — fixture and expected answer both authored here, nothing
  independent vouching. Used only for per-branch coverage, never as a
  correctness claim: a self-consistent round trip proves internal consistency,
  not correctness against real-world bytes.

## Independent oracles

| Oracle | Independent of us? | Validates | Tier |
|---|---|---|---|
| **The `dar` CLI** (Denis Corbin's reference tool — dar 2.3.12, 2.4.24, 2.5.3, 2.6.16, 2.8.5) | Yes — separate C++ codebase (`libdar`) | Every committed `vN_hello.dar` and codec/per-block/slice fixture is *written by* the matching upstream `dar` release; the reader must list, seek-extract, and CRC-verify back to the exact bytes `dar` archived | 2 |
| **`dar_xform`** (reference re-slicing tool, dar 2.8) | Yes — same `libdar` codebase, different binary | The re-sliced tape-marks-off archive `xform_tapeoff.dar` — locating the catalogue by its preserved `data_name` after `dar_xform` regenerated the slice `internal_name` | 2 |
| **Pure-Rust codec crates** (`flate2`, `bzip2`, `xz`/`liblzma`, `zstd`, `lz4`, `lzo`) | Yes — vetted third-party decoders we reuse | The decompression of catalogues and entry streams that real `dar -z<algo>` produced — the codec output is matched against the known plaintext payload | 2 |

The committed fixtures are not round-trips we hand-encoded: an *independent* tool
(`dar` / `dar_xform`) wrote every archive, and the answer key is the file content
that was fed to `dar` at creation time (documented verbatim in each test's header
comment and in [`forensic/tests/data/README.md`](https://github.com/SecurityRonin/dar-forensic/blob/main/forensic/tests/data/README.md)).

## Independent test corpora

All committed fixtures are produced by the upstream `dar` reference tool from
documented inputs, so each carries an independently-established answer key. They
are tiny and committed so the real-archive tests run in CI and are reproducible.

| Corpus | Source | Used for | License / redistribution |
|---|---|---|---|
| **`v7_hello.dar` … `v11_hello.dar`** (one per format) | Built by dar 2.3.12 / 2.4.24 / 2.5.3 / 2.6.16 / 2.8.5 | Per-format open / list / extract / CRC-verify against the file content `dar` archived | Generated fixtures, committed (see `tests/data/README.md`) |
| **`v11_gzip/bzip2/xz/zstd/lzo.dar`, `pb_gzip/lz4/zstd.dar`, `v11_lz4.dar`** | Built by dar 2.8.5 (`-z<algo>`, single-stream and per-block) | Transparent decompression of catalogue + entry streams for all six codecs, in both stream and block modes | Generated fixtures, committed |
| **`ms_stored.{1..4}.dar`** | Built by dar 2.8.5 (`-s 1k`, multi-volume) | Multi-slice reassembly: a payload spanning slice boundaries | Generated fixtures, committed |
| **`xform_tapeoff.dar`** | Built by dar 2.8.5 (`dar -at`) then re-sliced by `dar_xform` | Tape-marks-off + `data_name`-based catalogue location after re-slicing | Generated fixtures, committed |

## Per-capability validation

### Open / list / extract per DAR format (7–11) — Tier 2

`forensic/tests/real_images.rs` opens each `vN_hello.dar` archive — every one
written by the matching upstream `dar` release — and asserts the entry path,
size, and extracted bytes against the content that release archived:
`v7` (`v7_extracts_hello_txt`, line 311), `v8` (`v8_extracts_hello_txt`, 189),
`v9` (`v9_extracts_hello_txt`, 132), `v10` (`v10_extracts_hello_txt`, 247),
`v11` (`v11_extracts_hello_txt`, 87). Because an independent tool produced the
archive and the answer key is the documented input content, this is real-engine
validation, not a self-encoded round trip. The structurally-different pre-8
layouts (no `seqt_catalogue` escape, `u16` uid/gid, bare-seconds timestamps,
fixed 2-byte CRC) are exercised by the `v7` / `v8` fixtures specifically.

### Transparent decompression — six codecs — Tier 2

`forensic/tests/real_images.rs` validates list + extract + CRC against real
`dar -z<algo>` output: gzip (`gzip_extracts_payload_roundtrip`, line 402),
bzip2 (`bzip2_lists_and_extracts`, 453), xz (`xz_lists_and_extracts`, 458),
zstd (`zstd_lists_and_extracts`, 465), lz4 (`lz4_default_block_lists_and_extracts`,
475 and `lz4_multiblock_lists_and_extracts`, 481), lzo (`lzo_default_block_lists_and_extracts`,
489). Per-block mode (`dar -z algo:lvl:blocksize`) is covered by `pb_gzip` /
`pb_zstd` (`gzip_block_mode_lists_and_extracts` 495, `zstd_block_mode_lists_and_extracts`
501). The compressed payload is the deterministic 136 000-byte text built at test
time (`expected_payload`, line 371), so the codec output is matched against a
known plaintext, and the decoders themselves are the vetted third-party crates.

### CRC verification — Tier 2

`forensic/tests/real_images.rs` recomputes libdar's per-file XOR-fold CRC over
the extracted plaintext and matches the value `dar` stored in the catalogue, for
each format (`verify_v7_hello_matches` … `verify_v11_hello_matches`, lines
579–617) and for the compressed fixtures, confirming the CRC covers the
*decompressed* plaintext (`verify_gzip_payload_matches_decompressed_plaintext`,
620; bzip2/xz at 625/631).

### Multi-volume (sliced) archives — Tier 2

`multislice_stored_lists_and_extracts` (`forensic/tests/real_images.rs`, line
643) opens the real `dar -s 1k` four-slice archive and asserts a payload that
spans slice boundaries reassembles byte-exact. `xform_resliced_tapeoff_lists_and_extracts`
(line 783) validates `data_name`-based catalogue location on an archive that
`dar_xform` re-sliced. Malformed-slice error paths (bad magic, unknown extension,
under-sized slice, seek bounds) are driven by hand-built slice headers
(`slicereader_*` tests, lines 701–777) — Tier 3 coverage of the rejection arms.

### Bodyfile / timeline export — Tier 2 structure

`write_bodyfile_emits_one_well_formed_line_per_entry` (`forensic/tests/real_images.rs`,
line 547) confirms one 11-field TSK bodyfile line per catalogue entry on the real
`v11` fixture, with the regular file typed `r/r…`. The field semantics follow the
Sleuth Kit bodyfile contract consumed by `mactime`.

### Anomaly audit (`audit()`) — Tier 3

The catalogue-anomaly detectors (`DAR-CATALOG-INCOMPLETE`, `DAR-PATH-ABSOLUTE`,
`DAR-PATH-TRAVERSAL`, `DAR-PATH-DUPLICATE`, `DAR-TIME-FUTURE`, `DAR-NAME-CONTROL`)
are exercised by hand-built byte archives in `forensic/tests/synthetic.rs`, which
splice the exact malformed catalogue entry each rule targets — code paths a
well-formed `dar`-written archive cannot reach. These are self-authored fixtures
graded against self-authored expectations: Tier 3, used for branch coverage of the
audit logic, not as a correctness claim against real-world adversarial archives.

### Robustness — never panic, never over-read

The parser, the read+extract path, and the audit pipeline are each fuzzed
(`fuzz_open`, `fuzz_read`, `fuzz_forensic`) with the invariant "must not panic."
Production code is `unsafe_code = "deny"` and denies `clippy::unwrap_used` /
`clippy::expect_used`; every attacker-controlled length and offset is
bounds-checked, a forged `stored_size` is validated against the real archive
length before any allocation, and a length that would cast to a negative `i64`
seek is rejected.

## Reproducing the validation

All committed fixtures and their tests are always-on — no large download or env
gate is required:

```bash
# Full suite (unit + synthetic + real-fixture integration)
cargo test

# Real-archive integration tests only
cargo test -p dar-forensic --test real_images

# Synthetic code-path / anomaly-audit tests only
cargo test -p dar-forensic --test synthetic

# Coverage gate (lcov; CI enforces 100% library line coverage)
cargo install cargo-llvm-cov && cargo llvm-cov --lcov --output-path lcov.info
```

To regenerate any fixture from the reference tool (the construction *is* the
oracle), follow the verbatim `dar` / `dar_xform` command in the corresponding
test-module header comment in `forensic/tests/real_images.rs` and in
[`forensic/tests/data/README.md`](https://github.com/SecurityRonin/dar-forensic/blob/main/forensic/tests/data/README.md).

## Recommended strengthening (gaps)

These are honest gaps where the validation could be raised toward Tier 1 — none
is currently wired as a test:

- **Differential extraction against `dar -x`.** The committed fixtures compare the
  reader's output to the *known input content*. A stronger, Tier-1-style check
  would extract the same fixtures with the upstream `dar -x` CLI and compare the
  two extractions byte-for-byte (an independent decode of the same archive bytes),
  guarding against a shared assumption between our writer-of-record (`dar -c`) and
  our reader. This is recommended as an env-gated test that runs when `dar` is on
  `PATH`.
- **Real third-party / large-corpus fixtures, env-gated.** Validation against a
  real dar-1.0.0 edition-1 archive, a large Passware Kit Mobile archive, and a
  large multi-volume Android extraction was performed during development and is
  described in `docs/implementation-notes.md`, but those archives are confidential
  / outsized and are **not committed**, so no reproducible in-repo test backs them
  today. The recommended form is an env-gated test (skipping cleanly when the path
  variable is unset, as the fleet does for large oracles) plus a provenance entry
  in `tests/data/README.md` for any redistributable sample.

## Coverage & fuzzing as backstops

100% library line coverage is enforced in CI (`cargo llvm-cov`, lcov gate), with
a second gate holding the public-API (`tests/`) suite to the same bar. Coverage
is a regression backstop that proves behaviour is exercised — it is not the
correctness claim. The oracles above are.
