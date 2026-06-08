//! Forensic-grade reader and anomaly auditor for Denis Corbin DAR (Disk
//! ARchiver) archives.
//!
//! Built on the pure-Rust [`dar`] parser core: this crate re-exports the
//! reader API and adds the forensic layer — catalogue anomaly detection
//! ([`DarAudit::audit`]) and Sleuth Kit bodyfile export
//! ([`DarBodyfile::bodyfile`] / [`DarAudit::write_bodyfile`]) — graded onto the
//! shared [`forensicnomicon::report`] model.
//!
//! Every anomaly is an *observation*, never an assertion of intent: the notes
//! say "consistent with …", and the examiner draws the conclusions.
//!
//! ```no_run
//! use dar_forensic::{DarReader, DarAudit};
//! use std::io::Cursor;
//!
//! # fn demo(bytes: Vec<u8>) -> Result<(), dar_forensic::DarError> {
//! let reader = DarReader::open(Cursor::new(bytes))?;
//! for anomaly in reader.audit() {
//!     println!("{anomaly}");
//! }
//! # Ok(())
//! # }
//! ```

// Production code is panic-free (no unwrap/expect, enforced by the workspace
// lints); tests legitimately use them.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

mod bodyfile;
mod findings;

use std::io::{Read, Seek, Write};

// Re-export the full parser API so `dar_forensic::*` resolves exactly as the
// single-crate library did (DarReader, SliceReader, DarEntry, EntryKind,
// CrcStatus, DarError, and the entry-projection helpers).
pub use dar::{CrcStatus, DarEntry, DarError, DarReader, EntryKind, SliceReader};

pub use findings::{Anomaly, AnomalyKind, Severity};

/// Epoch seconds for 2100-01-01T00:00:00Z. [`DarAudit::audit`] flags entry
/// timestamps beyond this as implausibly far in the future (clock error or
/// tampering) — a deterministic ceiling, not a comparison against wall-clock.
const FAR_FUTURE_EPOCH_SECS: i64 = 4_102_444_800;

/// Sleuth Kit [`bodyfile`](https://wiki.sleuthkit.org/index.php?title=Body_file)
/// formatting for a parsed [`DarEntry`].
pub trait DarBodyfile {
    /// One Sleuth Kit bodyfile line for this entry (no trailing newline) — the
    /// input format for TSK's `mactime` timeline tool.
    ///
    /// Fields: `MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime`. DAR
    /// records no content hash, inode address, or birth time, so those are `0`;
    /// `mode` uses TSK's `type/type+perms` form (e.g. `r/rrwxr-xr-x`); a
    /// symlink's target is appended as ` -> target`; and `|`, `\`, and control
    /// bytes in names are backslash-escaped so one entry stays one line.
    fn bodyfile(&self) -> String;
}

impl DarBodyfile for DarEntry {
    fn bodyfile(&self) -> String {
        bodyfile::line(self)
    }
}

/// Forensic analysis over a parsed DAR catalogue: anomaly auditing and bodyfile
/// export. Pure metadata over the already-parsed catalogue — no archive data is
/// read or decoded.
pub trait DarAudit {
    /// Audit the loaded catalogue for forensic anomalies, returning them sorted
    /// most-severe first. See [`AnomalyKind`] for what is detected; each
    /// [`Anomaly`] is an observation, not a conclusion.
    fn audit(&self) -> Vec<Anomaly>;

    /// Write a Sleuth Kit [bodyfile](DarBodyfile::bodyfile) — one line per
    /// catalogue entry, newline-terminated — to `out`, for feeding TSK's
    /// `mactime` timeline tool. Pure metadata over the parsed catalogue; no
    /// archive data is read.
    ///
    /// # Errors
    /// Returns any I/O error produced while writing to `out`.
    fn write_bodyfile<W: Write>(&self, out: &mut W) -> std::io::Result<()>;
}

impl<R: Read + Seek> DarAudit for DarReader<R> {
    fn audit(&self) -> Vec<Anomaly> {
        let mut anomalies = Vec::new();

        if !self.is_complete() {
            anomalies.push(Anomaly::new(AnomalyKind::IncompleteCatalog {
                entries_recovered: self.entry_count(),
            }));
        }

        let mut seen: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
        let mut dup_seen: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
        for e in self.iter_entries() {
            let path = String::from_utf8_lossy(&e.path).into_owned();

            if e.path.first() == Some(&b'/') {
                anomalies.push(Anomaly::new(AnomalyKind::AbsolutePath {
                    path: path.clone(),
                }));
            }
            if e.path.split(|&b| b == b'/').any(|c| c == b"..") {
                anomalies.push(Anomaly::new(AnomalyKind::ParentTraversal {
                    path: path.clone(),
                }));
            }
            if e.path.iter().any(|&b| b < 0x20 || b == 0x7f) {
                anomalies.push(Anomaly::new(AnomalyKind::ControlCharsInName {
                    path: path.clone(),
                }));
            }
            for (field, t) in [("atime", e.atime), ("mtime", e.mtime)]
                .into_iter()
                .chain(e.ctime.map(|c| ("ctime", c)))
            {
                if t > FAR_FUTURE_EPOCH_SECS {
                    anomalies.push(Anomaly::new(AnomalyKind::FutureTimestamp {
                        path: path.clone(),
                        field,
                        epoch_secs: t,
                    }));
                }
            }
            // Report a duplicated path once, on its second sighting.
            if !seen.insert(e.path.clone()) && dup_seen.insert(e.path.clone()) {
                anomalies.push(Anomaly::new(AnomalyKind::DuplicatePath { path }));
            }
        }

        // Most-severe first; stable, so equal severities keep catalogue order.
        anomalies.sort_by_key(|a| std::cmp::Reverse(a.severity));
        anomalies
    }

    fn write_bodyfile<W: Write>(&self, out: &mut W) -> std::io::Result<()> {
        for entry in self.iter_entries() {
            writeln!(out, "{}", entry.bodyfile())?;
        }
        Ok(())
    }
}
