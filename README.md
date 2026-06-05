[![Crates.io](https://img.shields.io/crates/v/dar.svg)](https://crates.io/crates/dar)
[![Docs.rs](https://img.shields.io/docsrs/dar)](https://docs.rs/dar)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/SecurityRonin/dar/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/dar/actions/workflows/ci.yml)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

**Pure-Rust reader for Denis Corbin DAR (Disk ARchiver) archives — including the variant Passware Kit Mobile writes for mobile full-filesystem extractions.**

Parses the end-of-archive catalog to enumerate every stored file, then seeks straight to each entry for random-access extraction — no streaming through the whole archive. Hardened against malformed and malicious input (no panics, no unbounded allocation), so it is safe to point at untrusted evidence. Zero `unsafe`, no C bindings.

```toml
[dependencies]
dar = "0.1"
```

## Library quick start

```rust
use std::fs::File;
use dar::DarReader;

// `open` takes anything `Read + Seek` — a File, or a Cursor over bytes.
let mut reader = DarReader::open(File::open("backup.1.dar")?)?;

// List every archived file.
for entry in reader.entries() {
    println!("{} ({} bytes)", entry.path, entry.size);
}

// Extract one file — a direct seek to its catalog offset, no scanning.
let data = reader.extract("root/etc/hostname")?;
println!("{}", String::from_utf8_lossy(&data));
```

`DarReader::open` accepts any `Read + Seek` source, so it works equally over an on-disk `.dar` slice or an in-memory `Cursor<Vec<u8>>`.

## Library features

- **Catalog enumeration** — parses the `seqt_catalogue` section at the archive tail into a flat list of entries (path + uncompressed size).
- **Random-access extraction** — `extract()` seeks directly to `archive_origin + archive_offset` and reads the stored bytes; no need to walk preceding entries.
- **Full variable-length infinint decoding** — handles 4-byte (`0x80`) and 8-byte (`0x40`) groups; over-wide (>64-bit) encodings are rejected as corrupt rather than silently truncated.
- **Second- and nanosecond-precision inodes** — both timestamp layouts (`'s'` and `'n'`) are skipped correctly.
- **Passware Mobile variant** — locates the catalog by the archive label when the standard `seqt_catalogue` escape is absent (the form Passware Kit Mobile produces).
- **Tail-scan for large archives** — on multi-gigabyte forensic archives the catalog scan starts near EOF, falling back to a full scan only if needed (≈107 MiB read instead of the whole 90+ GiB archive).
- **Hardened against hostile input** — every attacker-controlled length and offset is bounds-checked: no arithmetic-overflow panics, no backward seeks, no unbounded allocation, no allocation bombs. Continuously fuzzed (`cargo fuzz`).
- **Zero `unsafe`** — `unsafe_code = "deny"` at the workspace level.
- **MIT licensed** — no GPL, safe for proprietary DFIR tooling.

### Scope and limits

- **Read-only.** dar does not create or modify archives.
- **Uncompressed, unencrypted entries.** Compressed (`gzip`/`bzip2`/`lzo`/`xz`) and encrypted entries are listed, but `extract()` returns a clear error rather than wrong bytes — decompression and decryption are out of scope.
- **CRC fields are parsed but not yet verified.** The stored per-file CRC is located and skipped; integrity verification against it is not implemented.

## Format support

| DAR format | `version_string` | Status |
|------------|------------------|--------|
| Format 11 (dar 2.7–2.8) | e.g. `"0;3"` (11.3) | Supported — validated against a dar 2.8.5 fixture |
| Format 10 (dar 2.6) | `"0:1"` | Supported — validated against a dar 2.6.16 fixture |
| Format 9 (dar 2.5) | `"090"` | Supported — validated against a dar 2.5.3 fixture and a real Passware archive |
| Passware Mobile variant | `"090"`, no `seqt_catalogue` escape | Supported — label-scan catalog location |
| Format 8 (dar 2.4) | `"081"` | Supported — validated against a dar 2.4.24 fixture |
| Format 7 (dar 2.3) | `"07"` | Supported — validated against a dar 2.3.12 fixture |
| Formats 2–6 (dar 2.0–2.3) | `"02"`–`"06"` | Same legacy grammar as 7; parsed but not yet validated against a fixture |
| Format 1 (dar 1.x) | `"01"` | Best-effort; unvalidated (no buildable dar 1.x) |
| Archive creation / writing | — | Not supported (reader only) |

The DAR format version is encoded in the header `version_string`, where each byte is `value + 48` (so `"090"` → format 9, `"0:1"` → format 10.1). Formats ≤ 7 are structurally different — no `seqt_catalogue` escape (the catalog is located via the end *terminateur* trailer), `u16` uid/gid, bare-seconds timestamps, and a fixed 2-byte CRC. The full per-version layout (reverse-documented from the authoritative libdar source) is in [docs/implementation-notes.md](docs/implementation-notes.md) §11–§12.

## Archive format

DAR archives use magic `00 00 00 7b` (`SAUV_MAGIC_NUMBER`, big-endian u32 — **not** an ASCII string), the variable-length **infinint** integer encoding, and a catalog located at the tail via the `AD FD EA 77 21 43` (`seqt_catalogue`) escape. Each file's catalog entry stores an `archive_offset` measured from `archive_origin` (the byte after the slice-header TLV block), pointing directly at the raw bytes. Full details — infinint encoding, inode layout, FSA blocks, catalog termination — are in [docs/implementation-notes.md](docs/implementation-notes.md).

## Testing

- **92 tests at 100% library line coverage** (enforced in CI via `cargo llvm-cov`) — unit, synthetic-archive integration, and real-fixture integration — plus a continuously-run `cargo fuzz` target over `DarReader::open` + `extract` (3.4M executions/min, zero crashes).
- **Public fixtures committed to the repo, one per format** — `v7_hello.dar` (dar 2.3.12), `v8_hello.dar` (dar 2.4.24), `v9_hello.dar` (dar 2.5.3), `v10_hello.dar` (dar 2.6.16) and `v11_hello.dar` (dar 2.8.5) — so every validated format is exercised in CI and is independently reproducible.
- **Real-world validation:** parsing was confirmed against a 92 GiB archive produced by Passware Kit Mobile 2026 v3.0 (DAR format 9, 637,698 entries). That archive is confidential and is **not** committed; only the public fixtures ship with the repo.
- **Fuzzing:** the hardened parser survives ≈1.5 million libFuzzer executions per 45 s with zero crashes.

See [docs/implementation-notes.md](docs/implementation-notes.md) for the format reference and the validated-corpus table.

## Related crates

### Container readers

| Crate | Format | Notes |
|-------|--------|-------|
| [`ewf`](https://github.com/SecurityRonin/ewf) | E01 / EWF / Ex01 | Dominant professional forensic acquisition format |
| [`aff4`](https://github.com/SecurityRonin/aff4) | AFF4 v1 | Evimetry / aff4-imager forensic disk images with Map streams |
| [`vmdk`](https://github.com/SecurityRonin/vmdk) | VMware VMDK | Monolithic sparse disk images from VMware Workstation / ESXi |
| [`vhdx`](https://github.com/SecurityRonin/vhdx) | Microsoft VHDX | Hyper-V, Windows 8+, WSL2, Azure disk container |
| [`vhd`](https://github.com/SecurityRonin/vhd) | Legacy VHD | Virtual PC / Hyper-V Generation-1 fixed and dynamic disk images |
| [`qcow2`](https://github.com/SecurityRonin/qcow2) | QCOW2 v2/v3 | QEMU / KVM / libvirt disk images |
| [`ufed`](https://github.com/SecurityRonin/ufed) | Cellebrite UFED | Physical mobile device dumps with UFD XML segment mapping |
| [`dd`](https://github.com/SecurityRonin/dd) | Raw / flat / gz | dd, dcfldd, and gzip-wrapped raw images |
| [`iso9660-forensic`](https://github.com/SecurityRonin/iso9660-forensic) | ISO 9660 | Optical disc images: multi-session, UDF bridge, Rock Ridge, Joliet, El Torito |
| [`dmg`](https://github.com/SecurityRonin/dmg) | Apple DMG / UDIF | macOS disk images with koly trailer, mish block tables, zlib decompression |

### Forensic analysers

| Crate | Format | Notes |
|-------|--------|-------|
| [`ewf-forensic`](https://github.com/SecurityRonin/ewf-forensic) | E01 | Structural integrity audit, Adler-32 / MD5 hash verification, and in-memory repair |
| [`vhdx-forensic`](https://github.com/SecurityRonin/vhdx-forensic) | VHDX | Forensic integrity analyser and in-memory repair tool for VHDX containers |

---

[Privacy Policy](https://securityronin.github.io/dar/privacy/) · [Terms of Service](https://securityronin.github.io/dar/terms/) · © 2026 Security Ronin Ltd
