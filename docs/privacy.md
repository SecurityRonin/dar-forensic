# Privacy Policy

**Effective date:** 2026-06-03  
**Product:** dar (Rust library)  
**Operator:** Security Ronin Ltd

---

## What dar collects

dar is a local Rust library. It does not operate a server, does not have a backend, and does not transmit data to Security Ronin or any third party.

dar opens and reads DAR archive bytes from a `Read + Seek` source you provide (a file, an in-memory buffer, or any seekable stream). It makes no network connections of any kind.

---

## File data

dar reads archive bytes to enumerate the catalog and extract stored files. Extracted bytes are returned to your own code and never uploaded, cached off-machine, or shared. Nothing leaves your process.

---

## Telemetry

dar has no telemetry, no crash reporting, no analytics, and no update checks. It never phones home.

---

## Open source

dar is fully open source under the MIT licence. You can audit every line — including the fact that there are no network calls — at [github.com/SecurityRonin/dar](https://github.com/SecurityRonin/dar).

---

## Changes

If this policy changes materially, the effective date above will be updated and a note will appear in the release changelog.

---

## Contact

Security Ronin Ltd — [github.com/SecurityRonin](https://github.com/SecurityRonin)
