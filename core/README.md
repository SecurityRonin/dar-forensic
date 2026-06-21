# dar-core

[![Crates.io](https://img.shields.io/crates/v/dar-core.svg)](https://crates.io/crates/dar-core)
[![docs.rs](https://img.shields.io/docsrs/dar-core)](https://docs.rs/dar-core)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/SecurityRonin/dar-forensic/blob/main/LICENSE)
[![CI](https://github.com/SecurityRonin/dar-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/dar-forensic/actions)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

**Pure-Rust, read-only parser for Denis Corbin DAR (Disk ARchiver) archives — the backup/extraction format mobile-forensics tools (Passware Kit Mobile, Cellebrite) write for full-filesystem dumps.** Enumerate the catalogue, seek straight to any file for random-access extraction, and verify per-file CRCs — transparently decompressing gzip, bzip2, xz, zstd, lz4 and lzo, across single-file and multi-volume (sliced) archives. Zero `unsafe`, no GPL, no C bindings.

## 30 seconds

```toml
[dependencies]
dar-core = "0.7"
```

```rust
use std::fs::File;
use dar::DarReader; // package is `dar-core`; the crate imports as `dar`

let mut reader = DarReader::open(File::open("userdata.1.dar")?)?;

// List the catalogue — one seek, no full-archive scan.
for entry in reader.entries() {
    println!("{} ({} bytes)", entry.path_lossy(), entry.size);
}

// Extract one file — direct seek to its catalog offset.
let data = reader.extract("root/etc/hostname")?;

// Integrity check — recompute libdar's per-file CRC over the decoded data.
println!("{}", reader.verify("root/etc/hostname")?); // CRC match | CRC mismatch: …
# Ok::<(), dar::DarError>(())
```

Multi-volume archives open the same way via `DarReader::open_slices(&[path0, path1, …])` (or `open_slices` from a basename); file data that spans slices is stitched together transparently.

## What it reads

| | dar-core |
|---|---|
| DAR formats 1–11 | ✅ (1 + 7–11 validated against real archives) |
| Tape-marks-disabled archives (Passware / mobile) | ✅ — standard DAR written with tape marks off |
| Random-access extraction (`Read + Seek`) | ✅ — composes with `ewf`, `vmdk`, `vhdx`, … |
| Transparent gzip / bzip2 / xz / zstd / lz4 / lzo | ✅ — pure-Rust decoders, no C, single-stream and per-block |
| Multi-volume (sliced) archives | ✅ — `open_slices()` |
| Tail-scan for 90+ GiB archives | ✅ — reads ≈107 MiB, not 99 GiB |
| Archive creation / writing | — (reader only) |

All six decompression codecs are always compiled in — a forensic reader must read every variant it encounters, so they are not optional features. The only optional feature is `serde` (derives `Serialize` on the public entry types). Encrypted entries are *listed* but `extract()` returns a clear error rather than wrong bytes — decryption is out of scope.

## Trust but verify

`dar-core` is built to be pointed at untrusted evidence:

- **No panics on malicious input** — every attacker-controlled length and offset is bounds- or overflow-checked through bounds-checked readers (no `unwrap`/`expect` in production code, enforced by the workspace lints).
- **No allocation bombs** — a forged `stored_size` is validated against the real archive length *before* any allocation.
- **No backward seeks** — a length that would cast to a negative `i64` seek is rejected.
- **Zero `unsafe`** (`unsafe_code = "deny"`) and continuously fuzz-tested (`fuzz_open`, `fuzz_read`).
- **187 tests at 100% library line coverage, CI-enforced** — the committed real-archive fixtures are written by the upstream **`dar` reference CLI** (dar 2.3.12 → 2.8.5) and `dar_xform` across formats 7–11, all six codecs, and multi-volume slices: the reader must list, seek-extract, and CRC-verify each back to the exact content `dar` archived. A real dar-1.0.0 archive, a large Passware Kit Mobile archive, and a large Android extraction were exercised during development but are **not committed**. See [docs/validation.md](https://securityronin.github.io/dar-forensic/validation/) for which oracle backs each capability and the recommended `dar -x` differential and env-gated large-corpus tests.

## The forensic layer

`dar-core` is the reader. For severity-graded anomaly auditing (path-traversal, incomplete catalogue, future timestamps, …) and Sleuth Kit bodyfile timeline export, add [`dar-forensic`](https://crates.io/crates/dar-forensic), which re-exports this reader and layers the `audit()` / `write_bodyfile()` analyzer on top.

---

[Privacy Policy](https://securityronin.github.io/dar-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/dar-forensic/terms/) · © 2026 Security Ronin Ltd
