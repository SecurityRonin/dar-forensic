[![Crates.io](https://img.shields.io/crates/v/dar.svg)](https://crates.io/crates/dar)
[![Docs.rs](https://img.shields.io/docsrs/dar)](https://docs.rs/dar)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/SecurityRonin/dar/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/dar/actions/workflows/ci.yml)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

**Pure-Rust DAR (Disk ARchiver) archive reader — catalog index, random-access extraction, CRC32 validation.**

Reads DAR archives: parses the end-of-archive catalog to enumerate all stored files, then seeks directly to each entry for O(1) random-access extraction without streaming through the whole archive. CRC32 is verified on every extracted file. Zero unsafe code, no C bindings.

```toml
[dependencies]
dar = "0.1"
```

---

## Usage

### List and extract files from a DAR archive

```rust
use dar::DarReader;

let mut reader = DarReader::open("backup.dar")?;

// List all archived files
for entry in reader.entries() {
    println!("{} ({} bytes)", entry.path, entry.size);
}

// Extract a specific file — seeks directly, no streaming required
let data = reader.extract("etc/passwd")?;
println!("{}", String::from_utf8_lossy(&data));
```

---

## Archive format

```text
[4]  magic = b"DAR\x00"
[4]  version = 1 (u32 LE)
[4]  entry_count (u32 LE)
For each entry:
  [4]        name_len (u32 LE)
  [name_len] path (UTF-8)
  [8]        data_len (u64 LE)
  [data_len] raw data
  [4]        CRC32 of data (u32 LE, IEEE polynomial)
[4]  catalog magic = b"CATL"
[4]  catalog entry count (u32 LE)
For each catalog entry:
  [4]  name_len
  [name_len]  path (UTF-8)
  [8]  data_offset (u64 LE) — absolute byte position in archive
  [8]  data_len (u64 LE)
```

The catalog at the end of the archive maps each path to its absolute file offset, enabling direct seeks for extraction without reading preceding entries.

---

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
| [`iso`](https://github.com/SecurityRonin/iso) | ISO 9660 | Optical disc images: multi-session, UDF bridge, Rock Ridge, Joliet, El Torito |
| [`dmg`](https://github.com/SecurityRonin/dmg) | Apple DMG / UDIF | macOS disk images with koly trailer, mish block tables, zlib decompression |

### Forensic analysers

| Crate | Format | Notes |
|-------|--------|-------|
| [`ewf-forensic`](https://github.com/SecurityRonin/ewf-forensic) | E01 | Structural integrity audit, Adler-32 / MD5 hash verification, and in-memory repair |
| [`vhdx-forensic`](https://github.com/SecurityRonin/vhdx-forensic) | VHDX | Forensic integrity analyser and in-memory repair tool for VHDX containers |

---

[Privacy Policy](https://securityronin.github.io/dar/privacy/) · [Terms of Service](https://securityronin.github.io/dar/terms/) · © 2026 Security Ronin Ltd
