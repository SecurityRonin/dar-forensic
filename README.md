# dar-forensic

[![Crates.io](https://img.shields.io/crates/v/dar-forensic.svg)](https://crates.io/crates/dar-forensic)
[![docs.rs](https://img.shields.io/docsrs/dar-forensic)](https://docs.rs/dar-forensic)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/SecurityRonin/dar-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/dar-forensic/actions)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

Pure-Rust reader for Denis Corbin **DAR (Disk ARchiver)** archives — the format mobile-forensics tools (Passware Kit Mobile, Cellebrite) use for full-filesystem extractions. Enumerates the catalog, seeks straight to any file for random-access extraction — transparently decompressing gzip, bzip2 and xz — and is hardened to be pointed safely at untrusted evidence. Zero `unsafe`, no GPL, no C bindings.

## Rust library

```toml
[dependencies]
dar-forensic = "0.3"
```

## Quick start

```rust
use std::fs::File;
use dar_forensic::DarReader;

// `open` takes anything Read + Seek — a File, or a Cursor over bytes.
let mut reader = DarReader::open(File::open("userdata.1.dar")?)?;

for entry in reader.entries() {
    println!("{} ({} bytes)", entry.path_lossy(), entry.size);
}

// Extract one file — a direct seek to its catalog offset, no scanning.
let data = reader.extract("root/etc/hostname")?;
println!("{}", String::from_utf8_lossy(&data));

// Integrity check — recompute the stored per-file CRC over the data.
println!("{}", reader.verify("root/etc/hostname")?); // CRC match | CRC mismatch: …

// Forensic audit — flag catalogue anomalies (metadata only, no data read).
for finding in reader.audit() {
    // e.g. [MEDIUM] DAR-PATH-TRAVERSAL: entry `../../etc/cron.d/x` contains a `..` …
    eprintln!("{finding}");
}

// Timeline export — write a Sleuth Kit bodyfile straight into `mactime`.
reader.write_bodyfile(&mut std::io::stdout())?;
# Ok::<(), dar_forensic::DarError>(())
```

## What makes this different

DAR is a C++ format; the reference implementation (`libdar`) is GPL with C bindings, and the `dar` name on crates.io is an empty placeholder. `dar-forensic` is the first standalone, dependency-light Rust reader — and it is built for forensic use, where the archive is *evidence from a potentially hostile source*:

| | libdar (C++) | `dar-forensic` |
|---|---|---|
| Language / linkage | C++, GPL, C FFI | pure Rust, MIT, `unsafe_code = "deny"` |
| Reads DAR formats 1–11 | ✅ | ✅ (1 + 7–11 validated against real archives) |
| Tape-marks-disabled archives (Passware / mobile) | ✅ | ✅ |
| Random-access extraction (`Read + Seek`) | ✅ | ✅ — composes with `ewf`, `vmdk`, … |
| Transparent gzip / bzip2 / xz / zstd / lz4 decompression | ✅ | ✅ — pure-Rust decoders, no C |
| Tail-scan for 90+ GiB archives (≈107 MiB read, not 99 GiB) | — | ✅ |
| Forensic anomaly audit (`audit()` → severity-graded findings) | — | ✅ — incomplete catalogue, path-traversal, undecodable codec, … (serde-exportable) |
| Timeline export (Sleuth Kit bodyfile → `mactime`) | — | ✅ — `write_bodyfile()` straight from the catalogue |
| Hardened against malicious input (no panic / OOM / backward seek) | — | ✅ |
| Continuous fuzzing | — | ✅ `cargo fuzz` |
| 100% line coverage, CI-enforced | — | ✅ |

### Note on the "Passware variant"

Archives written by Passware Kit Mobile have no `seqt_catalogue` escape, which once looked like a vendor-specific format. It isn't: the escape is an *optional sequential-read tape mark*, and Passware simply writes archives with tape marks **disabled** (equivalent to `dar -at`). They are **standard DAR** — official dar reads them too. `dar-forensic` locates the catalog by its `ref_data_name` label in that case (a real structural field, the same 10 bytes as the slice label), so it reads both tape-marked and tape-mark-free archives.

## Format support

| DAR format | `version_string` | Status |
|------------|------------------|--------|
| Format 11 (dar 2.7–2.8) | `"0;3"` (11.3) | Supported — validated against a dar 2.8.5 fixture |
| Format 10 (dar 2.6) | `"0:1"` | Supported — validated against a dar 2.6.16 fixture |
| Format 9 (dar 2.5) | `"090"` | Supported — validated against a dar 2.5.3 fixture **and a real 92 GiB Passware archive** |
| Format 8 (dar 2.4) | `"081"` | Supported — validated against a dar 2.4.24 fixture |
| Format 7 (dar 2.3) | `"07"` | Supported — validated against a dar 2.3.12 fixture |
| Formats 2–6 (dar 2.0–2.3) | `"02"`–`"06"` | Same legacy grammar as 7; parsed but not yet validated against a fixture |
| Format 1 (dar 1.0.x) | `"01"` | Supported — validated against a real dar 1.0.0 archive (flagless inode, `size·offset` cat_file, no CRC) |
| Tape marks on **or** off | — | both supported (e.g. Passware writes them off) |
| Archive creation / writing | — | Not supported (reader only) |

The format version is the header `version_string`, each byte `value + 48` (`"090"` → 9, `"0:1"` → 10.1). Formats ≤ 7 are structurally different — no `seqt_catalogue` escape (catalog located via the end *terminateur* trailer), `u16` uid/gid, bare-seconds timestamps, and a fixed 2-byte CRC; format 1 goes further still — no inode flag byte, and a `size·offset`-only file record with no CRC. Compressed pre-8 archives carry no per-entry codec byte, so the archive-global codec drives both the catalog and every entry. The full per-version layout, reverse-documented from the authoritative libdar source, is in [docs/implementation-notes.md](docs/implementation-notes.md) §11–§12.

### Scope and limits

- **Read-only** — does not create or modify archives.
- **Decompression: gzip, bzip2, xz, zstd, lz4** — these are transparently inflated for both the compressed catalog and extracted entry data (pure-Rust decoders, bounded against decompression bombs), in both dar's single-stream and per-block (`block_compressor`) modes. Archives using lzo are recognised but not decoded (no pure-Rust lzo decoder); encrypted entries are *listed* but `extract()` returns a clear error rather than wrong bytes — decryption is out of scope.
- **Lean build** — the five codecs are default-on Cargo features (`gzip`, `bzip2`, `xz`, `zstd`, `lz4`). For a reader of *stored* archives (e.g. the uncompressed Passware corpus) with zero codec dependencies, build with `default-features = false`. A codec you leave out is still recognised: its entries list and are flagged by `audit()`, and `extract()` refuses them rather than mis-decoding.
- **CRC verification** — `verify(path)` recomputes libdar's per-file CRC over the decompressed data and compares it to the value stored in the catalogue, returning `Match`, `Mismatch { stored, computed }`, or `NotStored` (edition-1 archives record no CRC). It never withholds the bytes: data that fails its CRC can still be `extract`ed for analysis of the corruption.

## Security

`dar-forensic` is designed to be run on archives from potentially compromised or adversarial sources:

- **No panics on malicious input** — every attacker-controlled length and offset is bounds- or overflow-checked.
- **No allocation bombs** — a forged `stored_size` is validated against the real archive length *before* any allocation.
- **No backward seeks** — a length that would cast to a negative `i64` seek is rejected.
- **Bounded decoding** — infinints are `u64`-or-`Corrupt` (never silently truncated); NUL-terminated names are length-capped; the terminateur scan is bounded.
- **Zero `unsafe`** and continuously fuzz-tested.

### Running the fuzz target

```bash
rustup install nightly
cargo install cargo-fuzz
cargo +nightly fuzz run fuzz_open
```

## Testing

117 tests — unit (private helpers + every error branch), synthetic-archive integration, and real-fixture integration — at **100% library line coverage, enforced in CI** (`cargo llvm-cov`, lcov gate), with a second gate that holds the public-API (`tests/`) suite to the same bar. Committed, reproducible fixtures cover formats 7–11 (one per dar release) and the three gzip/bzip2/xz `dar -z` codecs; parsing was additionally validated byte-for-byte against a real dar-1.0.0 edition-1 archive, and against a confidential 92 GiB Passware Kit Mobile archive (DAR format 9, 637,698 entries — not committed). The parser survives millions of `cargo fuzz` executions with zero crashes.

```bash
cargo test
cargo install cargo-llvm-cov && cargo llvm-cov --lcov --output-path lcov.info
```

> The `--summary-only` line percentage can read slightly under 100% because the generic, reader-agnostic functions are monomorphized once per reader type across the test binaries; the lcov merge (and `--show-missing-lines`) confirms no source line is left uncovered.

## Related crates

`dar-forensic` reads the files *inside* a DAR archive. When the archive itself is wrapped in a disk-image container, these crates provide the same `Read + Seek` interface to feed it:

| Crate | Format |
|-------|--------|
| [`ewf`](https://github.com/SecurityRonin/ewf) | E01 / Expert Witness Format (EnCase, FTK Imager) |
| [`aff4`](https://github.com/SecurityRonin/aff4) | AFF4 v1 (Evimetry) |
| [`vmdk`](https://github.com/SecurityRonin/vmdk) | VMware VMDK |
| [`vhdx`](https://github.com/SecurityRonin/vhdx) | Microsoft VHDX (Hyper-V, Azure) |
| [`vhd`](https://github.com/SecurityRonin/vhd) | Legacy VHD |
| [`qcow2`](https://github.com/SecurityRonin/qcow2) | QEMU / KVM QCOW2 |
| [`ufed`](https://github.com/SecurityRonin/ufed) | Cellebrite UFED |
| [`dd`](https://github.com/SecurityRonin/dd) | Raw / flat / dd images |
| [`iso9660-forensic`](https://github.com/SecurityRonin/iso9660-forensic) | ISO 9660 optical media |
| [`dmg`](https://github.com/SecurityRonin/dmg) | Apple DMG / UDIF |

For forensic integrity analysis of container formats:

| Crate | Format |
|-------|--------|
| [`ewf-forensic`](https://github.com/SecurityRonin/ewf-forensic) | E01 structural audit, Adler-32 / MD5 repair |
| [`vhdx-forensic`](https://github.com/SecurityRonin/vhdx-forensic) | VHDX integrity analysis |

---

[Privacy Policy](https://securityronin.github.io/dar-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/dar-forensic/terms/) · © 2026 Security Ronin Ltd
