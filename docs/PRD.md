# dar-forensic — Purpose & Scope

**Why this exists.** `libdar` (Denis Corbin's reference DAR implementation) is
GPL C++ with C FFI bindings, and the bare `dar` name on crates.io is an empty
placeholder — so there was no pure-Rust way to read a DAR archive, let alone one
built for forensic use. Mobile-forensics tools (Passware Kit Mobile, Cellebrite)
write full-filesystem extractions as DAR, and an examiner needs to enumerate and
extract from those archives *as evidence from a potentially hostile source*, on
an evidence workstation, without a C toolchain or a GPL dependency.

**Who uses it.** Two audiences: a forensic analyst who wants to list, extract,
CRC-verify, audit, and timeline a DAR archive; and a Rust developer who wants a
dependency-light, `Read + Seek` DAR reader that composes with other container
crates (`ewf`, `vmdk`, `forensic-vfs`).

**What it does.** Opens single- and multi-volume DAR archives (formats 1 and
7–11, tape-marks on or off), enumerates the catalogue, seeks straight to any
entry for random-access extraction, transparently decompresses all six codecs
(gzip, bzip2, xz, zstd, lz4, lzo), recomputes libdar's per-file CRC, flags
catalogue anomalies (`audit()` → severity-graded findings on the shared
`forensicnomicon::report` model), and exports a Sleuth Kit bodyfile for
`mactime`. See [`docs/decisions/`](docs/decisions/) for the load-bearing design
decisions and [`docs/validation.md`](docs/validation.md) for the oracle-backed
evidence.

**In scope:** read-only parsing, decompression, CRC verification, catalogue
anomaly auditing, bodyfile/timeline export, and an optional `forensic-vfs`
`FileSystem` adapter (`vfs` feature).

**Out of scope (non-goals):** creating or modifying archives (reader only);
decrypting encrypted entries (they are *listed*, but `extract()` returns a clear
error rather than wrong bytes); and, for now, carving orphaned catalogue entries
or enumerating archive free space (the VFS adapter reports these as empty rather
than fabricating them). The **In scope** and **Out of scope** paragraphs above
are the detailed boundaries.
