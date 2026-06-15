# dar-forensic

Pure-Rust reader for Denis Corbin **DAR (Disk ARchiver)** archives — the format mobile-forensics tools (Passware Kit Mobile, Cellebrite) use for full-filesystem extractions. Enumerates the catalog, seeks straight to any file for random-access extraction — transparently decompressing gzip, bzip2, xz, zstd, lz4 and lzo, and reading multi-volume (sliced) archives — and is hardened to be pointed safely at untrusted evidence. Zero `unsafe`, no GPL, no C bindings.

## Two crates

| Crate | Role | crates.io |
|-------|------|-----------|
| **`dar-core`** | read-only parser — open, enumerate, seek-extract, CRC-verify | `cargo add dar-core` |
| **`dar-forensic`** | forensic-grade reader + anomaly auditor (`audit()` → graded findings, `write_bodyfile()`) | `cargo add dar-forensic` |

`dar-forensic` re-exports the full `dar-core` reader, so the analyzer crate alone is enough for forensic work:

```toml
[dependencies]
dar-forensic = "0.7"
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
| Transparent gzip / bzip2 / xz / zstd / lz4 / lzo decompression | ✅ | ✅ — pure-Rust decoders, no C |
| Multi-volume (sliced) archives | ✅ | ✅ — `open_slices()`; file data spans slices transparently |
| Tail-scan for 90+ GiB archives (≈107 MiB read, not 99 GiB) | — | ✅ |
| Forensic anomaly audit (`audit()` → severity-graded findings) | — | ✅ — incomplete catalogue, path-traversal, absolute path, … (serde-exportable) |
| Timeline export (Sleuth Kit bodyfile → `mactime`) | — | ✅ — `write_bodyfile()` straight from the catalogue |
| Hardened against malicious input (no panic / OOM / backward seek) | — | ✅ |
| Continuous fuzzing | — | ✅ `cargo fuzz` |
| 100% line coverage, CI-enforced | — | ✅ |

## Anomaly codes

`audit()` reads the catalogue only (no entry data) and returns severity-graded `Anomaly` values, most-severe first. Each carries a stable, machine-readable `code` (a published contract), a `severity`, and a human-readable note. Findings are **observations, not verdicts** — the analyst draws the conclusion.

| `code` | Severity | What it flags |
|--------|----------|---------------|
| `DAR-CATALOG-INCOMPLETE` | High | Catalogue ended early — fewer entries recovered than the archive claims (truncation or corruption) |
| `DAR-PATH-ABSOLUTE` | Medium | Entry path begins with `/` — extraction outside the intended root |
| `DAR-PATH-TRAVERSAL` | Medium | Entry path contains a `..` component — directory-traversal on extraction |
| `DAR-PATH-DUPLICATE` | Low | The same path appears more than once in the catalogue |
| `DAR-TIME-FUTURE` | Low | An `atime`/`mtime`/`ctime` is far in the future — possible timestamp tampering |
| `DAR-NAME-CONTROL` | Low | Entry name contains control characters (`< 0x20` or `0x7f`) — terminal-injection / concealment |

With the `serde` feature, `Anomaly` is `Serialize` for JSON/structured export.

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

The full per-version layout, reverse-documented from the authoritative libdar source, is in [Implementation Notes](implementation-notes.md) §11–§12.

## Security

`dar-forensic` is designed to be run on archives from potentially compromised or adversarial sources:

- **No panics on malicious input** — every attacker-controlled length and offset is bounds- or overflow-checked.
- **No allocation bombs** — a forged `stored_size` is validated against the real archive length *before* any allocation.
- **No backward seeks** — a length that would cast to a negative `i64` seek is rejected.
- **Bounded decoding** — infinints are `u64`-or-`Corrupt` (never silently truncated); NUL-terminated names are length-capped; the terminateur scan is bounded.
- **Zero `unsafe`** and continuously fuzz-tested.

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

---

[Privacy Policy](privacy.md) · [Terms of Service](terms.md) · © 2026 Security Ronin Ltd
