# dar-forensic

[![Crates.io](https://img.shields.io/crates/v/dar-forensic.svg)](https://crates.io/crates/dar-forensic)
[![docs.rs](https://img.shields.io/docsrs/dar-forensic)](https://docs.rs/dar-forensic)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/SecurityRonin/dar-forensic/blob/main/LICENSE)
[![CI](https://github.com/SecurityRonin/dar-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/dar-forensic/actions)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

**Forensic-grade reader and anomaly auditor for Denis Corbin DAR (Disk ARchiver) archives — point it at a Passware Kit Mobile or Cellebrite extraction and get severity-graded findings straight from the catalogue.** It re-exports the full `dar-core` reader (open, enumerate, seek-extract, CRC-verify, transparent gzip/bzip2/xz/zstd/lz4/lzo, multi-volume) and layers a metadata-only `audit()` plus Sleuth Kit bodyfile timeline export on top. Zero `unsafe`, no GPL, no C bindings.

## 30 seconds

```toml
[dependencies]
dar-forensic = "0.7"
```

```rust
use std::fs::File;
use dar_forensic::{DarReader, DarAudit, DarBodyfile};

let mut reader = DarReader::open(File::open("userdata.1.dar")?)?;

// Forensic audit — flags catalogue anomalies, most-severe first.
// Reads metadata only; no entry data is decompressed.
for finding in reader.audit() {
    // e.g. [MEDIUM] DAR-PATH-TRAVERSAL: entry `../../etc/cron.d/x` contains a `..` …
    eprintln!("{finding}");
}

// Timeline export — write a Sleuth Kit bodyfile straight into `mactime`.
reader.write_bodyfile(&mut std::io::stdout())?;
# Ok::<(), dar_forensic::DarError>(())
```

The reader API is the same as `dar-core`: `reader.entries()`, `reader.extract(path)`, `reader.verify(path)`, `DarReader::open_slices(...)`. Adding `dar-forensic` alone is enough — you do not also need `dar-core`.

## Anomaly codes

`audit()` returns severity-graded `Anomaly` values, each carrying a stable, machine-readable `code` (a published contract), a `severity`, and a human-readable note. Findings are **observations, not verdicts** — the analyst draws the conclusion.

| `code` | Severity | What it flags |
|--------|----------|---------------|
| `DAR-CATALOG-INCOMPLETE` | High | Catalogue ended early — fewer entries recovered than the archive claims (truncation or corruption) |
| `DAR-PATH-ABSOLUTE` | Medium | Entry path begins with `/` — extraction outside the intended root |
| `DAR-PATH-TRAVERSAL` | Medium | Entry path contains a `..` component — directory-traversal on extraction |
| `DAR-PATH-DUPLICATE` | Low | The same path appears more than once in the catalogue |
| `DAR-TIME-FUTURE` | Low | An `atime`/`mtime`/`ctime` is far in the future — possible timestamp tampering |
| `DAR-NAME-CONTROL` | Low | Entry name contains control characters (`< 0x20` or `0x7f`) — terminal-injection / concealment |

Each `Anomaly`'s `severity`, `code`, and `note` are *derived* from its `AnomalyKind`, so they cannot drift. With the `serde` feature, `Anomaly` and the parser entry types are `Serialize` for JSON/structured export.

## The reader/analyzer split

| Crate | Role |
|-------|------|
| [`dar-core`](https://crates.io/crates/dar-core) | the raw read-only parser — open, enumerate, seek-extract, CRC-verify, decompress |
| **`dar-forensic`** | re-exports the reader + adds `audit()` (anomaly findings) and `write_bodyfile()` (timeline) |

## Trust but verify

`dar-forensic` is built to be run on archives from potentially compromised or adversarial sources:

- **No panics on malicious input** — every attacker-controlled length and offset is bounds- or overflow-checked (no `unwrap`/`expect` in production code, enforced by the workspace lints).
- **No allocation bombs** — a forged `stored_size` is validated against the real archive length *before* any allocation.
- **No backward seeks** — a length that would cast to a negative `i64` seek is rejected.
- **Zero `unsafe`** (`unsafe_code = "deny"`) and continuously fuzz-tested — `fuzz_open` (parser), `fuzz_read` (read + extract), and `fuzz_forensic` (the audit pipeline).
- **187 tests at 100% library line coverage, CI-enforced** — validated not only against synthetic fixtures for formats 7–11 and all six codecs, but byte-for-byte against a real dar-1.0.0 archive, a 92 GiB Passware Kit Mobile archive (637,698 entries), and a 52 GB Android extraction re-sliced into 13 volumes (every extraction byte-identical to the single-file reader).

The full per-version DAR layout, the Passware tape-marks-off explanation, and the real-archive validation log are in the [repository README](https://github.com/SecurityRonin/dar-forensic) and `docs/implementation-notes.md`.

---

[Privacy Policy](https://securityronin.github.io/dar-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/dar-forensic/terms/) · © 2026 Security Ronin Ltd
