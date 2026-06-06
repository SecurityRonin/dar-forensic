//! Pure-Rust reader for Denis Corbin DAR (Disk ARchiver) archives.
//!
//! Supports DAR formats 7–11 (produced by dar 2.3–2.8) and the legacy ≤7 grammar.
//! Passware Kit Mobile produces format-9 archives; dar 2.8.5 produces 11.3.
//! Entries and the catalogue compressed with gzip, bzip2 or xz are transparently
//! decompressed (pure-Rust); lzo, zstd, lz4 and encryption are not decoded.
//!
//! ## Format sketch
//!
//! ```text
//! Slice header:
//!   [4]  magic = 00 00 00 7b  (SAUV_MAGIC_NUMBER = 123, big-endian u32)
//!   [10] internal_name label
//!   [1]  flag  [1]  ext_char
//!   TLV list:  infinint(count) + count × (u16 type + infinint len + data)
//!   ← archive_origin: all catalog archive_offset values are relative to here
//!
//! Archive body:
//!   escaped sequences (seqt_file, seqt_saved, …) + raw file bytes
//!
//! Catalog  (located by seqt_catalogue escape: AD FD EA 77 21 43):
//!   [10] label  +  (NUL working-dir path, format 11.1+ only)  +  entries
//!
//!   Each entry: cat_sig byte where (cat_sig & 0x1f | 0x60) gives type
//!     'd' directory  → NUL-name + inode [+ FSA]  (push to dir stack)
//!     'f' file       → NUL-name + inode [+ FSA] + file-specific fields
//!     'z' EOD        → pop dir stack; depth=0 → done
//! ```
//!
//! ## Key non-obvious invariants
//!
//! - **Infinint**: variable-length. The common form is 5 bytes
//!   (`0x80 XX XX XX XX`, a big-endian u32); timestamps past 2^32 use the
//!   9-byte `0x40` form (big-endian u64). Encodings wider than 64 bits are
//!   rejected as corrupt — this reader decodes to `u64` or errors, never
//!   truncates.
//! - **Permissions**: 2-byte big-endian u16, *not* an infinint.
//! - **Timestamps**: format 8 stores a bare seconds infinint; format 9+ prefix
//!   a unit byte (`'s'`/`'u'`/`'n'`) and add a sub-second infinint for `'u'`/`'n'`.
//! - **FSA** (format 9+ only): inode flag bit `0x10` (FSA-full) adds inode
//!   infinints and an FSA block; format 8 has no FSA.
//! - **archive_offset**: points *directly* to the raw file bytes, not to the
//!   data-section header that precedes them in the body stream.
//!   `seek(archive_origin + archive_offset)` then `read(stored_size)`.
//!
//! Full format notes: `docs/implementation-notes.md`.

use std::io::{Cursor, Read, Seek, SeekFrom, Write};

use thiserror::Error;

mod bodyfile;
mod findings;
pub use findings::{Anomaly, AnomalyKind, Severity};

/// `00 00 00 7b` — DAR magic (SAUV_MAGIC_NUMBER = 123, big-endian u32).
const DAR_MAGIC: [u8; 4] = [0x00, 0x00, 0x00, 0x7b];

/// Upper bound on the compressed catalogue bytes read from the archive tail and
/// on the inflated catalogue, guarding against a decompression bomb (per-file
/// streams need no such constant — they are bounded by the entry's known size).
const MAX_CATALOGUE_COMPRESSED: u64 = 512 * 1024 * 1024;
const MAX_CATALOGUE_INFLATED: u64 = 1024 * 1024 * 1024;

/// Epoch seconds for 2100-01-01T00:00:00Z. [`DarReader::audit`] flags entry
/// timestamps beyond this as implausibly far in the future (clock error or
/// tampering) — a deterministic ceiling, not a comparison against wall-clock.
const FAR_FUTURE_EPOCH_SECS: i64 = 4_102_444_800;

/// Escape sequence marking the catalog: `AD FD EA 77 21 43`.
const SEQT_CATALOGUE: [u8; 6] = [0xAD, 0xFD, 0xEA, 0x77, 0x21, 0x43];

/// First archive format with an in-place (working-directory) path in the
/// catalog header — `archive_version(11,1)` → `value() = 11*256 + 1`.
/// Formats 8, 9, 10 and 11.0 have no such field.
const FORMAT_11_1: u32 = 11 * 256 + 1;

/// Errors returned by [`DarReader`].
#[derive(Debug, Error)]
pub enum DarError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("not a DAR archive")]
    NotADar,
    #[error("corrupt archive: {0}")]
    Corrupt(String),
    #[error("entry not found: '{0}'")]
    EntryNotFound(String),
}

/// The kind of filesystem object a catalog entry describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    File,
    Directory,
    Symlink,
    NamedPipe,
    Socket,
    CharDevice,
    BlockDevice,
    Hardlink,
    /// A catalog entry type this reader does not model (the raw `cat_sig` letter).
    Unknown(char),
}

/// Metadata about one archived filesystem object.
///
/// Paths and symlink targets are exposed as raw bytes — DAR (like the
/// filesystems it archives) does not guarantee UTF-8, and a forensic reader
/// must never lose or reject a byte-exact name. Use [`DarEntry::path_lossy`] for
/// display.
#[derive(Debug, Clone)]
pub struct DarEntry {
    /// Path as stored, raw bytes — may not be valid UTF-8.
    pub path: Vec<u8>,
    /// What kind of filesystem object this entry describes.
    pub kind: EntryKind,
    /// Uncompressed size in bytes (0 for entries with no data).
    pub size: u64,
    /// Owner user id.
    pub uid: u64,
    /// Owner group id.
    pub gid: u64,
    /// Permission bits (the low bits of the mode).
    pub mode: u16,
    /// Access time, seconds since the Unix epoch.
    pub atime: i64,
    /// Modification time, seconds since the Unix epoch.
    pub mtime: i64,
    /// Status-change time, seconds since the Unix epoch; `None` for formats
    /// before 8, which do not record it.
    pub ctime: Option<i64>,
    /// Target of a symbolic link, raw bytes; `None` for non-symlinks.
    pub symlink_target: Option<Vec<u8>>,
}

impl DarEntry {
    /// The path decoded as lossy UTF-8 (invalid byte sequences become U+FFFD).
    #[must_use]
    pub fn path_lossy(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(&self.path)
    }

    /// One Sleuth Kit [`bodyfile`](https://wiki.sleuthkit.org/index.php?title=Body_file)
    /// line for this entry (no trailing newline) — the input format for TSK's
    /// `mactime` timeline tool.
    ///
    /// Fields: `MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime`. DAR
    /// records no content hash, inode address, or birth time, so those are `0`;
    /// `mode` uses TSK's `type/type+perms` form (e.g. `r/rrwxr-xr-x`); a
    /// symlink's target is appended as ` -> target`; and `|`, `\`, and control
    /// bytes in names are backslash-escaped so one entry stays one line.
    #[must_use]
    pub fn bodyfile(&self) -> String {
        bodyfile::line(self)
    }
}

#[derive(Debug, Clone)]
struct EntryRef {
    path: Vec<u8>,
    kind: EntryKind,
    size: u64,
    uid: u64,
    gid: u64,
    mode: u16,
    atime: i64,
    mtime: i64,
    ctime: Option<i64>,
    symlink_target: Option<Vec<u8>>,
    archive_offset: u64,
    stored_size: u64,
    compression: u8,
}

/// Read-only DAR archive reader.
pub struct DarReader<R: Read + Seek> {
    inner: R,
    /// Byte position immediately after the slice header TLV block.
    /// `archive_origin + archive_offset` = absolute position of raw file bytes.
    archive_origin: u64,
    /// Archive format major version (`value() >> 8`). Format 1 stores no
    /// per-entry `storage_size`, so a compressed format-1 entry is decoded by
    /// streaming the codec to its natural end rather than reading a fixed length.
    format_major: u32,
    /// Whether the catalog parsed to a clean root EOD (see [`DarReader::is_complete`]).
    complete: bool,
    entries: Vec<EntryRef>,
}

impl<R: Read + Seek> DarReader<R> {
    /// Open a DAR archive, validating the magic and loading the catalog.
    pub fn open(mut reader: R) -> Result<Self, DarError> {
        let mut magic = [0u8; 4];
        reader
            .read_exact(&mut magic)
            .map_err(|_| DarError::NotADar)?;
        if magic != DAR_MAGIC {
            return Err(DarError::NotADar);
        }

        let mut label = [0u8; 10];
        reader.read_exact(&mut label)?; // internal_name label
        let _flag = read_u8(&mut reader)?; // slice flag ('T' terminal / 'N' / 'E')
        let extension = read_u8(&mut reader)?; // 'T' = TLV (format 8+); 'N'/'S' = legacy (<= 7)

        // Format 8+ carries a TLV list and a `seqt_catalogue` escape; format <= 7
        // has neither — its catalogue is located via the end `terminateur` trailer
        // (libdar header.cpp extension handling; terminateur.cpp).
        let entries;
        let archive_origin;
        let format_major;
        let complete;
        if extension == b'T' {
            // TLV list: infinint(count) then count × (u16 type + infinint len + data)
            let tlv_count = read_infinint(&mut reader).map_err(|e| match e {
                DarError::Io(_) => DarError::Corrupt("truncated TLV block".into()),
                other => other,
            })?;
            for _ in 0..tlv_count {
                skip(&mut reader, 2)?;
                let len = read_infinint(&mut reader)?;
                skip(&mut reader, len)?;
            }

            archive_origin = reader.stream_position()?;
            let format_value = read_format_value(&mut reader);
            // The archive's global compression algorithm is the byte immediately
            // after the version string; it tells us whether (and how) the
            // catalogue stream is compressed. Unreadable → treat as stored.
            let global_comp = read_u8(&mut reader).unwrap_or(b'n');
            reader.seek(SeekFrom::Start(archive_origin))?;

            // true → seqt_catalogue tape mark found (catalog has label + maybe path);
            // false → located by its ref_data_name label (tape marks off, e.g. Passware).
            let via_escape = find_catalogue(&mut reader, &label)?;
            format_major = format_value >> 8;
            if via_escape && is_compressed(global_comp) {
                // The catalogue is a single stream compressed with the archive
                // codec, beginning right after the seqt_catalogue escape and
                // running to the trailer. Inflate it, then parse from the
                // plaintext buffer — which begins with the in-catalog label and
                // optional in-place path, exactly like the uncompressed case.
                let mut compressed = Vec::new();
                reader
                    .by_ref()
                    .take(MAX_CATALOGUE_COMPRESSED)
                    .read_to_end(&mut compressed)?;
                let inflated = inflate_catalogue(&compressed, global_comp)?;
                let mut cur = Cursor::new(inflated);
                skip(&mut cur, 10)?; // catalog label
                if format_value >= FORMAT_11_1 {
                    skip_nul_string(&mut cur)?;
                }
                (entries, complete) = parse_catalog(&mut cur, format_major, global_comp)?;
            } else {
                if via_escape {
                    skip(&mut reader, 10)?; // catalog label
                                            // The in-place path exists only from format 11.1
                                            // (catalogue.cpp:157). Formats 8/9/10/11.0 have none.
                    if format_value >= FORMAT_11_1 {
                        skip_nul_string(&mut reader)?;
                    }
                }
                (entries, complete) = parse_catalog(&mut reader, format_major, global_comp)?;
            }
        } else if extension == b'N' || extension == b'S' {
            if extension == b'S' {
                read_infinint(&mut reader)?; // slice size (multi-slice header); unused
            }
            archive_origin = reader.stream_position()?;
            let format_value = read_format_value(&mut reader); // 3-byte edition: value = major*256
            format_major = format_value >> 8;
            // The global compression char follows the version string (same as
            // format 8+). Formats <= 7 carry no per-entry compression byte, so
            // this single char governs both the catalogue and every entry's data.
            let global_comp = read_u8(&mut reader).unwrap_or(b'n');
            let cat_offset = read_terminateur(&mut reader)?;
            let cat_start = archive_origin
                .checked_add(cat_offset)
                .ok_or_else(|| DarError::Corrupt("catalogue offset overflows".into()))?;
            let end = reader.seek(SeekFrom::End(0))?;
            if cat_start >= end {
                return Err(DarError::Corrupt(format!(
                    "catalogue start {cat_start} past archive end {end}"
                )));
            }
            reader.seek(SeekFrom::Start(cat_start))?;
            // Legacy catalogue: no 10-byte label, no path — entries begin here.
            // When the archive is compressed, the catalogue is a single codec
            // stream (the terminateur addresses its start); inflate it first.
            if is_compressed(global_comp) {
                let mut compressed = Vec::new();
                reader
                    .by_ref()
                    .take(MAX_CATALOGUE_COMPRESSED)
                    .read_to_end(&mut compressed)?;
                let inflated = inflate_catalogue(&compressed, global_comp)?;
                (entries, complete) =
                    parse_catalog(&mut Cursor::new(inflated), format_major, global_comp)?;
            } else {
                (entries, complete) = parse_catalog(&mut reader, format_major, global_comp)?;
            }
        } else {
            return Err(DarError::Corrupt(format!(
                "unknown slice-header extension {extension:#04x}"
            )));
        }

        Ok(Self {
            inner: reader,
            archive_origin,
            format_major,
            complete,
            entries,
        })
    }

    /// List all archived file entries (path and uncompressed size).
    pub fn entries(&self) -> Vec<DarEntry> {
        self.entries
            .iter()
            .map(|e| DarEntry {
                path: e.path.clone(),
                kind: e.kind,
                size: e.size,
                uid: e.uid,
                gid: e.gid,
                mode: e.mode,
                atime: e.atime,
                mtime: e.mtime,
                ctime: e.ctime,
                symlink_target: e.symlink_target.clone(),
            })
            .collect()
    }

    /// Whether the catalog was parsed to a clean end.
    ///
    /// `false` means parsing stopped early — typically at a catalog entry type
    /// this reader does not model (e.g. a hardlink or device node) or at
    /// corruption — so [`entries`](Self::entries) may be an *incomplete* listing.
    /// A forensic caller should treat an incomplete listing as "more may exist".
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.complete
    }

    /// Audit the loaded catalogue for forensic anomalies, returning them sorted
    /// most-severe first. Pure metadata analysis over the already-parsed
    /// catalogue — no archive data is read or decoded. See [`AnomalyKind`] for
    /// what is detected; each [`Anomaly`] is an observation, not a conclusion.
    #[must_use]
    pub fn audit(&self) -> Vec<Anomaly> {
        let mut anomalies = Vec::new();

        if !self.complete {
            anomalies.push(Anomaly::new(AnomalyKind::IncompleteCatalog {
                entries_recovered: self.entries.len(),
            }));
        }

        let mut seen: std::collections::HashSet<&[u8]> = std::collections::HashSet::new();
        let mut dup_seen: std::collections::HashSet<&[u8]> = std::collections::HashSet::new();
        for e in &self.entries {
            let path = String::from_utf8_lossy(&e.path).into_owned();

            if let Some(codec) = unsupported_codec(e.compression) {
                anomalies.push(Anomaly::new(AnomalyKind::UnsupportedCodec {
                    path: path.clone(),
                    codec,
                }));
            }
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
            if !seen.insert(e.path.as_slice()) && dup_seen.insert(e.path.as_slice()) {
                anomalies.push(Anomaly::new(AnomalyKind::DuplicatePath { path }));
            }
        }

        // Most-severe first; stable, so equal severities keep catalogue order.
        anomalies.sort_by_key(|a| std::cmp::Reverse(a.severity));
        anomalies
    }

    /// Write a Sleuth Kit [bodyfile](DarEntry::bodyfile) — one line per catalogue
    /// entry, newline-terminated — to `out`, for feeding TSK's `mactime` timeline
    /// tool. Pure metadata over the parsed catalogue; no archive data is read.
    pub fn write_bodyfile<W: Write>(&self, out: &mut W) -> std::io::Result<()> {
        for entry in self.entries() {
            writeln!(out, "{}", entry.bodyfile())?;
        }
        Ok(())
    }

    /// Extract a file by path, streaming its (decompressed) bytes to `out` and
    /// returning the number of bytes written. Unlike [`extract`](Self::extract),
    /// this never holds the whole file in memory, so it is safe for multi-GiB
    /// entries (and composes with hashing, scanning, or writing to disk).
    pub fn extract_to<P: AsRef<[u8]>, W: Write>(
        &mut self,
        path: P,
        out: &mut W,
    ) -> Result<u64, DarError> {
        let path = path.as_ref();
        let name = String::from_utf8_lossy(path);
        let entry = self
            .entries
            .iter()
            .find(|e| e.path.as_slice() == path)
            .ok_or_else(|| DarError::EntryNotFound(name.clone().into_owned()))?
            .clone();

        // The raw bytes live at archive_origin + archive_offset. Both fields are
        // attacker-controlled, so the sum is checked and the claimed length
        // validated against the bytes that actually exist before reading.
        let start = self
            .archive_origin
            .checked_add(entry.archive_offset)
            .ok_or_else(|| {
                DarError::Corrupt(format!("'{name}' archive offset overflows file position"))
            })?;
        let end = self.inner.seek(SeekFrom::End(0))?;
        if start > end {
            return Err(DarError::Corrupt(format!(
                "'{name}' starts at {start}, past archive end {end}"
            )));
        }
        let available = end - start;
        self.inner.seek(SeekFrom::Start(start))?;

        // Stored: stream the raw bytes straight through, no buffering.
        if !is_compressed(entry.compression) {
            if entry.stored_size > available {
                return Err(DarError::Corrupt(format!(
                    "'{name}' claims {} stored bytes but only {available} remain",
                    entry.stored_size
                )));
            }
            return Ok(std::io::copy(
                &mut self.inner.by_ref().take(entry.stored_size),
                out,
            )?);
        }

        // Compressed: decode straight to `out`, capped at the declared size so a
        // forged stream cannot over-inflate (streaming decompression-bomb guard).
        let mut cap = CapWriter {
            inner: out,
            written: 0,
            max: entry.size,
        };
        if self.format_major == 1 {
            // Format 1 stores no storage_size; the codec stream (dar 1.x is
            // gzip/zlib-only) runs from the offset to its own natural end.
            decode_stream(self.inner.by_ref(), entry.compression, &mut cap)?;
        } else {
            // 8+/2-7: exactly stored_size compressed bytes on disk.
            if entry.stored_size > available {
                return Err(DarError::Corrupt(format!(
                    "'{name}' claims {} stored bytes but only {available} remain",
                    entry.stored_size
                )));
            }
            let mut data = vec![0u8; entry.stored_size as usize];
            self.inner.read_exact(&mut data)?;
            decode_stream(&data[..], entry.compression, &mut cap)?;
        }
        if cap.written != entry.size {
            return Err(DarError::Corrupt(format!(
                "'{name}' decompressed to {} bytes but catalog declares {}",
                cap.written, entry.size
            )));
        }
        Ok(cap.written)
    }

    /// Extract a file by path, returning its raw bytes. Buffers the whole entry
    /// in memory; prefer [`extract_to`](Self::extract_to) for large files.
    pub fn extract<P: AsRef<[u8]>>(&mut self, path: P) -> Result<Vec<u8>, DarError> {
        let mut buf = Vec::new();
        self.extract_to(path, &mut buf)?;
        Ok(buf)
    }
}

// ── Catalog parser ────────────────────────────────────────────────────────────

/// On archives larger than this, the catalog scan starts this many bytes
/// before EOF (the catalog always lives at the tail), avoiding a full read of
/// a multi-gigabyte forensic archive before falling back to a full scan.
const TAIL_SCAN: u64 = 256 * 1024 * 1024;

const CHUNK: usize = 4 * 1024 * 1024;
// OVERLAP = max(SEQT_CATALOGUE.len(), label.len()) - 1; carries bytes across chunk boundaries.
const OVERLAP: usize = 9;

/// Scan forward from the current reader position searching for either the
/// `seqt_catalogue` escape or the archive `label`.
///
/// Returns `Some(true)` if the escape was found (reader positioned just after it),
/// `Some(false)` if the label was found (reader positioned just after it),
/// `None` if EOF was reached without a match.
fn scan_window<R: Read + Seek>(
    r: &mut R,
    label: &[u8; 10],
    use_label: bool,
) -> Result<Option<bool>, DarError> {
    let mut buf = vec![0u8; CHUNK + OVERLAP];
    let mut overlap_len: usize = 0;
    loop {
        let chunk_file_pos = r.stream_position()?;
        let n = r.read(&mut buf[overlap_len..overlap_len + CHUNK])?;
        if n == 0 {
            break;
        }
        let total = overlap_len + n;
        // buf[0..overlap_len]  → tail of previous chunk (file pos: chunk_file_pos - overlap_len)
        // buf[overlap_len..total] → newly read bytes
        let buf_base = chunk_file_pos - overlap_len as u64;

        if let Some(i) = buf[..total]
            .windows(SEQT_CATALOGUE.len())
            .position(|w| w == SEQT_CATALOGUE)
        {
            r.seek(SeekFrom::Start(
                buf_base + i as u64 + SEQT_CATALOGUE.len() as u64,
            ))?;
            return Ok(Some(true));
        }
        if use_label {
            if let Some(i) = buf[..total]
                .windows(label.len())
                .position(|w| w == label.as_ref())
            {
                r.seek(SeekFrom::Start(buf_base + i as u64 + label.len() as u64))?;
                return Ok(Some(false));
            }
        }

        let keep = OVERLAP.min(total);
        buf.copy_within(total - keep..total, 0);
        overlap_len = keep;
    }
    Ok(None)
}

/// Locate the catalog section and position the reader at its first entry.
///
/// Returns `true` when the `seqt_catalogue` escape is found — the caller then
/// skips the 10-byte in-catalog label and (format 11.1+) the path NUL string.
/// The escape is a *sequential-read tape mark*; it is present only when the
/// archive was written with tape marks (libdar's default).
///
/// Returns `false` when the catalog is located by its `ref_data_name` label
/// directly. Archives written with tape marks disabled (e.g. by Passware Kit
/// Mobile, equivalent to `dar -at`) omit the escape; their catalog still begins
/// with the 10-byte `ref_data_name`, which equals the slice `label`, so scanning
/// for `label` in the tail finds it — a structural marker, not a heuristic.
///
/// Returns `Err(Corrupt)` when neither marker is found.
///
/// Strategy: DAR catalogs always live at the tail of the archive.  On forensic
/// archives ≥ 256 MiB we jump straight to the last 256 MiB and scan forward
/// from there, then fall back to a full forward scan from `archive_origin` if
/// needed.  This reduces the I/O for a 92 GiB archive from ~99 GiB to ~107 MiB.
fn find_catalogue<R: Read + Seek>(r: &mut R, label: &[u8; 10]) -> Result<bool, DarError> {
    find_catalogue_within(r, label, TAIL_SCAN)
}

/// Implementation of [`find_catalogue`] with the tail-scan window size as a
/// parameter so the full-scan fallback can be exercised without a 256 MiB
/// fixture.
fn find_catalogue_within<R: Read + Seek>(
    r: &mut R,
    label: &[u8; 10],
    tail_scan: u64,
) -> Result<bool, DarError> {
    // All-zero labels cannot be used as a reliable catalog marker (too common
    // in zero-padded archive bodies).
    let use_label = !label.iter().all(|&b| b == 0);

    let archive_origin = r.stream_position()?;
    let file_end = r.seek(SeekFrom::End(0))?;

    if file_end <= archive_origin {
        return Err(DarError::Corrupt("archive body too short".into()));
    }

    // Jump to at most tail_scan bytes before end; for small files this equals archive_origin.
    let tail_start = archive_origin.max(file_end.saturating_sub(tail_scan));
    r.seek(SeekFrom::Start(tail_start))?;

    if let Some(result) = scan_window(r, label, use_label)? {
        return Ok(result);
    }

    // Tail scan missed.  Fall back to a full scan from archive_origin.
    if tail_start > archive_origin {
        r.seek(SeekFrom::Start(archive_origin))?;
        if let Some(result) = scan_window(r, label, use_label)? {
            return Ok(result);
        }
    }

    Err(DarError::Corrupt("seqt_catalogue not found".into()))
}

/// Read the NUL-terminated `version_string` at the current position and return
/// `archive_version::value()` = `major*256 + fix`, where `major = b0*256 + b1`
/// and each byte is `value + 48`. Format <= 7 stores only `"NN"` (fix implicitly
/// 0); format 8+ stores `"NNf"`. Returns `u32::MAX` for an unreadable string so
/// an unknown future format is treated as newest.
fn read_format_value<R: Read>(r: &mut R) -> u32 {
    let b = read_nul_bytes(r).unwrap_or_default();
    if b.len() >= 2 {
        let major = u32::from(b[0].saturating_sub(48)) * 256 + u32::from(b[1].saturating_sub(48));
        let fix = if b.len() >= 3 {
            u32::from(b[2].saturating_sub(48))
        } else {
            0
        };
        major * 256 + fix
    } else {
        u32::MAX
    }
}

/// True when a libdar compression char names a known compression algorithm.
/// `compression2char` emits the algorithm letter in lowercase for streamed mode
/// and uppercase for per-block mode (`z`=gzip, `y`=bzip2, `x`=xz, `l`/`j`/`k`=lzo
/// variants, `d`=zstd, `q`=lz4); `n` is stored. Any other byte — e.g. a header
/// placeholder in a non-dar-produced archive — is treated as not compressed, so
/// the catalogue/entry is read verbatim rather than mis-decoded.
fn is_compressed(algo: u8) -> bool {
    matches!(
        algo.to_ascii_lowercase(),
        b'z' | b'y' | b'x' | b'l' | b'j' | b'k' | b'd' | b'q'
    )
}

/// The codec character if `algo` names a compression this reader recognises but
/// cannot decode — lzo (`l`/`j`/`k`), zstd (`d`), or lz4 (`q`). Returns `None`
/// for the decodable codecs (`z`/`y`/`x`) and for stored entries. The original
/// case is preserved (uppercase = per-block) as evidence.
fn unsupported_codec(algo: u8) -> Option<char> {
    matches!(algo.to_ascii_lowercase(), b'l' | b'j' | b'k' | b'd' | b'q').then_some(algo as char)
}

/// Inflate a compressed catalogue into a single buffer, routing through the same
/// [`decode_stream`]/[`CapWriter`] path the per-file extractor uses and capping
/// output at `MAX_CATALOGUE_INFLATED` (decompression-bomb guard). Trailing bytes
/// after the codec stream (the archive trailer) are ignored by the decoder.
fn inflate_catalogue(compressed: &[u8], algo: u8) -> Result<Vec<u8>, DarError> {
    let mut out = Vec::new();
    let mut cap = CapWriter {
        inner: &mut out,
        written: 0,
        max: MAX_CATALOGUE_INFLATED,
    };
    decode_stream(compressed, algo, &mut cap)?;
    Ok(out)
}

/// A `Write` adapter that forwards to `inner`, counting bytes written and failing
/// once more than `max` would be written — the streaming decompression-bomb
/// guard used by [`DarReader::extract_to`].
struct CapWriter<'a, W: Write> {
    inner: &'a mut W,
    written: u64,
    max: u64,
}

impl<W: Write> Write for CapWriter<'_, W> {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if self.written + data.len() as u64 > self.max {
            return Err(std::io::Error::other("decompressed data exceeds bound"));
        }
        self.inner.write_all(data)?;
        self.written += data.len() as u64;
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Stream-decode a compressed input to `out`, dispatching on the libdar codec
/// char. The Read decoders stop at the codec stream's end (ignoring trailing
/// bytes); lzma-rs rejects trailing bytes only after fully validating the
/// stream, so that one error is treated as success.
fn decode_stream<R: Read, W: Write>(input: R, algo: u8, out: &mut W) -> Result<(), DarError> {
    match algo.to_ascii_lowercase() {
        b'z' => {
            std::io::copy(&mut flate2::read::ZlibDecoder::new(input), out)
                .map_err(|e| DarError::Corrupt(format!("zlib decode failed: {e}")))?;
        }
        b'y' => {
            std::io::copy(&mut bzip2_rs::DecoderReader::new(input), out)
                .map_err(|e| DarError::Corrupt(format!("bzip2 decode failed: {e}")))?;
        }
        b'x' => {
            let mut br = std::io::BufReader::new(input);
            match lzma_rs::xz_decompress(&mut br, out) {
                Ok(()) => {}
                Err(lzma_rs::error::Error::XzError(ref m))
                    if m == "Unexpected data after last XZ block" => {}
                Err(e) => return Err(DarError::Corrupt(format!("xz decode failed: {e}"))),
            }
        }
        other => {
            return Err(DarError::Corrupt(format!(
                "unsupported compression '{}'",
                other as char
            )))
        }
    }
    Ok(())
}

/// Locate the catalogue in a pre-format-8 archive via the end `terminateur`
/// trailer (libdar terminateur.cpp:95-138), returning the catalogue start offset
/// relative to `archive_origin`.
///
/// From EOF, count trailing `0xFF` padding bytes (8 bits each); the first
/// non-`0xFF` byte encodes the remaining count in unary as its set high bits.
/// `byte_offset = total_bits * 4` is the distance back from that byte to the
/// catalogue-position infinint. The `0xFF` run is bounded so a hostile all-`0xFF`
/// tail cannot spin or overflow.
fn read_terminateur<R: Read + Seek>(r: &mut R) -> Result<u64, DarError> {
    const BLOCK_SIZE: u64 = 4;
    const MAX_BITS: u64 = 4096; // far beyond any real terminator

    let mut pos = r.seek(SeekFrom::End(0))?;
    let mut bits: u64 = 0;
    let terminal = loop {
        if pos == 0 {
            return Err(DarError::Corrupt("terminator underflows archive".into()));
        }
        pos -= 1;
        r.seek(SeekFrom::Start(pos))?;
        let b = read_u8(r)?;
        if b == 0xFF {
            bits += 8;
            if bits > MAX_BITS {
                return Err(DarError::Corrupt("terminator padding too long".into()));
            }
        } else {
            break b;
        }
    };
    // The terminator byte must have its top bit set; count consecutive set MSBs.
    if terminal & 0x80 == 0 {
        return Err(DarError::Corrupt(format!(
            "invalid terminator byte {terminal:#04x}"
        )));
    }
    let mut x = terminal;
    while x != 0 {
        if x & 0x80 == 0 {
            return Err(DarError::Corrupt("malformed terminator bit run".into()));
        }
        bits += 1;
        x <<= 1;
    }
    let byte_offset = bits * BLOCK_SIZE;
    let infinint_start = pos
        .checked_sub(byte_offset)
        .ok_or_else(|| DarError::Corrupt("terminator offset underflows".into()))?;
    r.seek(SeekFrom::Start(infinint_start))?;
    read_infinint(r)
}

/// Parse all catalog entries, returning file entries with their extraction info.
///
/// Stops when the root directory is closed (depth reaches zero) or an unknown
/// entry type is encountered (slice trailer).
fn parse_catalog<R: Read + Seek>(
    r: &mut R,
    format_major: u32,
    global_comp: u8,
) -> Result<(Vec<EntryRef>, bool), DarError> {
    let mut entries = Vec::new();
    let mut dir_stack: Vec<Vec<u8>> = Vec::new();
    let mut depth: u32 = 0;
    // True once the catalog is walked to its closing root EOD; left false if we
    // stop early (unknown entry type or a truncated stream).
    let mut complete = false;

    loop {
        let mut buf = [0u8; 1];
        match r.read_exact(&mut buf) {
            Ok(()) => {}
            Err(_) => break,
        }

        // Lower 5 bits of cat_sig + 0x60 gives the ASCII type letter.
        let entry_type = ((buf[0] & 0x1f) | 0x60) as char;

        match entry_type {
            'z' => {
                // End of directory
                depth = depth.saturating_sub(1);
                dir_stack.pop();
                if depth == 0 {
                    complete = true; // reached the closing root EOD — clean end
                    break;
                }
            }
            'd' => {
                let name = read_nul_bytes(r)?;
                let inode = read_inode_base(r, format_major)?;
                if format_major >= 9 && (inode.flags >> 4) & 1 != 0 {
                    skip_fsa(r)?;
                }
                let is_root = depth == 0;
                depth += 1;
                // The archive root (`<ROOT>`, or `"root"` in formats 1/9) is a
                // virtual node: `<ROOT>` is dropped entirely; a named root becomes
                // the path prefix. Neither is listed as an entry. Real
                // sub-directories are listed with their full path.
                if name != b"<ROOT>" {
                    let path = join_path(&dir_stack, &name);
                    if !is_root {
                        entries.push(meta_entry(path, EntryKind::Directory, &inode, None));
                    }
                    dir_stack.push(name);
                }
            }
            'f' => {
                let name = read_nul_bytes(r)?;
                let inode = read_inode_base(r, format_major)?;
                if format_major >= 9 && (inode.flags >> 4) & 1 != 0 {
                    skip_fsa(r)?;
                }

                let (size, archive_offset, stored_size, compression) =
                    read_file_fields(r, format_major, global_comp)?;

                entries.push(EntryRef {
                    path: join_path(&dir_stack, &name),
                    kind: EntryKind::File,
                    size,
                    uid: inode.uid,
                    gid: inode.gid,
                    mode: inode.mode,
                    atime: inode.atime,
                    mtime: inode.mtime,
                    ctime: inode.ctime,
                    symlink_target: None,
                    archive_offset,
                    stored_size,
                    compression,
                });
            }
            'l' => {
                // Symbolic link: inode + NUL-terminated target path.
                let name = read_nul_bytes(r)?;
                let inode = read_inode_base(r, format_major)?;
                if format_major >= 9 && (inode.flags >> 4) & 1 != 0 {
                    skip_fsa(r)?;
                }
                let target = read_nul_bytes(r)?;
                let path = join_path(&dir_stack, &name);
                entries.push(meta_entry(path, EntryKind::Symlink, &inode, Some(target)));
            }
            'p' | 's' => {
                // Named pipe (FIFO) / unix socket: a bare inode, no data and no
                // type-specific fields.
                let name = read_nul_bytes(r)?;
                let inode = read_inode_base(r, format_major)?;
                if format_major >= 9 && (inode.flags >> 4) & 1 != 0 {
                    skip_fsa(r)?;
                }
                let kind = if entry_type == 'p' {
                    EntryKind::NamedPipe
                } else {
                    EntryKind::Socket
                };
                entries.push(meta_entry(join_path(&dir_stack, &name), kind, &inode, None));
            }
            _ => break, // unknown type = slice trailer or unhandled entry
        }
    }

    Ok((entries, complete))
}

/// Read the file-specific catalog fields after the inode and return
/// `(size, archive_offset, stored_size, compression)`. Layout differs by format
/// (libdar cat_file.cpp / crc.cpp):
/// - 8+: storage_size · file_data_status(1) · comp(1) · length-prefixed CRC.
/// - 2-7: storage_size · fixed 2-byte CRC; no status/comp byte — the
///   archive-global codec applies.
/// - 1: size · offset only; storage_size synthesised, global codec applies.
fn read_file_fields<R: Read + Seek>(
    r: &mut R,
    format_major: u32,
    global_comp: u8,
) -> Result<(u64, u64, u64, u8), DarError> {
    let size = read_infinint(r)?;
    let archive_offset = read_infinint(r)?;
    let (mut stored_size, compression) = if format_major >= 8 {
        let ss = read_infinint(r)?;
        let _file_data_status = read_u8(r)?;
        let comp = read_u8(r)?;
        let crc_size = read_infinint(r)?;
        skip(r, crc_size)?;
        (ss, comp)
    } else if format_major >= 2 {
        let ss = read_infinint(r)?;
        skip(r, 2)?; // fixed 2-byte CRC
        (ss, global_comp)
    } else {
        (size, global_comp) // format 1: storage_size synthesised
    };
    // Pre-8: storage_size 0 means the data is stored uncompressed.
    if format_major <= 7 && stored_size == 0 {
        stored_size = size;
    }
    Ok((size, archive_offset, stored_size, compression))
}

/// Join a directory stack and a leaf name into a `/`-separated raw-byte path.
fn join_path(stack: &[Vec<u8>], name: &[u8]) -> Vec<u8> {
    let mut path = Vec::new();
    for component in stack {
        path.extend_from_slice(component);
        path.push(b'/');
    }
    path.extend_from_slice(name);
    path
}

/// Build an `EntryRef` for a non-file inode (dir/symlink/pipe/socket): it carries
/// metadata but no archive data.
fn meta_entry(
    path: Vec<u8>,
    kind: EntryKind,
    inode: &Inode,
    symlink_target: Option<Vec<u8>>,
) -> EntryRef {
    EntryRef {
        path,
        kind,
        size: 0,
        uid: inode.uid,
        gid: inode.gid,
        mode: inode.mode,
        atime: inode.atime,
        mtime: inode.mtime,
        ctime: inode.ctime,
        symlink_target,
        archive_offset: 0,
        stored_size: 0,
        compression: b'n',
    }
}

// ── Low-level I/O helpers ─────────────────────────────────────────────────────

/// Read a DAR variable-length infinint, decoded to `u64`.
///
/// Format (TG=4): optional leading `0x00` skip-bytes, then a terminal byte
/// with exactly one bit set; `pos = terminal.leading_zeros()` and the value
/// occupies `(skip_count * 8 + pos + 1) * 4` big-endian bytes.
///
/// A `u64` holds at most 8 data bytes.  Any encoding wider than that — i.e.
/// *any* leading `0x00` (which alone implies ≥ 36 bytes) or a terminal below
/// `0x40` (`pos > 1`) — cannot be represented and is rejected as `Corrupt`
/// rather than silently truncated.  This single bound also removes the
/// `(skip * 8 …)` arithmetic-overflow panic and caps the leading-zero scan, so
/// a malicious all-zero run can never spin or overflow the skip counter.
fn read_infinint<R: Read>(r: &mut R) -> Result<u64, DarError> {
    let terminal = read_u8(r)?;
    if terminal == 0x00 {
        // A skip-byte group is at least 36 data bytes — far beyond u64.
        return Err(DarError::Corrupt(
            "infinint exceeds 64-bit range (multi-group encoding)".into(),
        ));
    }
    if terminal.count_ones() != 1 {
        return Err(DarError::Corrupt(format!(
            "invalid infinint terminal: {terminal:#04x}"
        )));
    }
    let pos = terminal.leading_zeros(); // 0 ..= 7
    if pos > 1 {
        // data_bytes = (pos + 1) * 4 > 8 → does not fit in u64.
        return Err(DarError::Corrupt(format!(
            "infinint exceeds 64-bit range: terminal {terminal:#04x} implies {} bytes",
            (pos + 1) * 4
        )));
    }
    let data_bytes = (pos + 1) * 4; // 4 (terminal 0x80) or 8 (terminal 0x40)
    let mut val: u64 = 0;
    for _ in 0..data_bytes {
        val = (val << 8) | u64::from(read_u8(r)?);
    }
    Ok(val)
}

fn read_u8<R: Read>(r: &mut R) -> Result<u8, DarError> {
    let mut b = [0u8; 1];
    r.read_exact(&mut b)?;
    Ok(b[0])
}

/// Upper bound on a NUL-terminated path/name field.  Real DAR entries stay
/// well under this; the cap stops a NUL-free region of a hostile archive from
/// growing the buffer until EOF (or OOM on a multi-GiB stream).
const MAX_NUL_STRING: usize = 64 * 1024;

/// Read a NUL-terminated byte string (raw, not UTF-8 validated), consuming the
/// NUL. Length-capped at `MAX_NUL_STRING` so a NUL-free hostile region can't grow
/// the buffer to EOF.
fn read_nul_bytes<R: Read>(r: &mut R) -> Result<Vec<u8>, DarError> {
    let mut bytes = Vec::new();
    loop {
        let b = read_u8(r)?;
        if b == 0 {
            break;
        }
        if bytes.len() >= MAX_NUL_STRING {
            return Err(DarError::Corrupt(format!(
                "NUL-terminated string exceeds {MAX_NUL_STRING} bytes"
            )));
        }
        bytes.push(b);
    }
    Ok(bytes)
}

/// Skip a NUL-terminated string without collecting the bytes.
fn skip_nul_string<R: Read>(r: &mut R) -> Result<(), DarError> {
    let mut len: usize = 0;
    loop {
        if read_u8(r)? == 0 {
            return Ok(());
        }
        len += 1;
        if len > MAX_NUL_STRING {
            return Err(DarError::Corrupt(format!(
                "NUL-terminated string exceeds {MAX_NUL_STRING} bytes"
            )));
        }
    }
}

/// Seek past `n` bytes.
fn skip<R: Seek>(r: &mut R, n: u64) -> Result<(), DarError> {
    if n > 0 {
        // `SeekFrom::Current` takes an i64; a value above i64::MAX would cast to
        // a negative offset and seek *backwards* (re-reading earlier bytes on a
        // File).  No real DAR field is that large — reject it outright.
        let off = i64::try_from(n)
            .map_err(|_| DarError::Corrupt(format!("skip length {n} exceeds seekable range")))?;
        r.seek(SeekFrom::Current(off)).map_err(DarError::Io)?;
    }
    Ok(())
}

/// Skip one DAR timestamp field.
///
/// Timestamps are prefixed with a type byte:
/// - `'s'` (0x73) and others: seconds only — one infinint follows
/// - `'n'` (0x6e): nanosecond precision — two infinints follow (seconds + nanoseconds)
fn read_timestamp<R: Read + Seek>(r: &mut R, format_major: u32) -> Result<i64, DarError> {
    // Format 8 and earlier store a bare seconds infinint with NO precision byte
    // (libdar datetime.cpp:372). Format 9+ prefix a unit byte ('s' seconds,
    // 'u' microsecond, 'n' nanosecond); sub-second units add a second infinint,
    // which we read and discard (seconds resolution is what we expose).
    if format_major < 9 {
        return Ok(read_infinint(r)? as i64);
    }
    let ts_type = read_u8(r)?;
    let secs = read_infinint(r)? as i64;
    if ts_type == b'n' || ts_type == b'u' {
        read_infinint(r)?;
    }
    Ok(secs)
}

/// Read a 2-byte big-endian `u16` (uid/gid for format <= 7, and permission bits).
fn read_u16<R: Read>(r: &mut R) -> Result<u16, DarError> {
    let mut b = [0u8; 2];
    r.read_exact(&mut b)?;
    Ok(u16::from_be_bytes(b))
}

/// Decoded inode metadata shared by every catalog entry type.
struct Inode {
    flags: u8,
    uid: u64,
    gid: u64,
    mode: u16,
    atime: i64,
    mtime: i64,
    ctime: Option<i64>,
}

/// Read one inode's base fields and return them. Layout in order: an optional
/// flags byte (format 2+), uid, gid, a `u16` perms field, atime, mtime, and a
/// ctime for format 8+. uid/gid are a 2-byte `u16` for format `<= 7` and an
/// infinint for 8+; each timestamp is decoded by [`read_timestamp`]. FSA inode
/// fields (format 9+, when flag bit `0x10` is set) are consumed and discarded.
fn read_inode_base<R: Read + Seek>(r: &mut R, format_major: u32) -> Result<Inode, DarError> {
    // Format 1 predates extended attributes and has NO leading flag byte
    // (libdar cat_inode.cpp); formats 2+ store it. Synthesise 0 for format 1.
    let flags = if format_major >= 2 { read_u8(r)? } else { 0 };
    // uid/gid: 2-byte u16 for format <= 7 (libdar cat_inode.cpp:171), infinint for 8+.
    let (uid, gid) = if format_major <= 7 {
        (u64::from(read_u16(r)?), u64::from(read_u16(r)?))
    } else {
        (read_infinint(r)?, read_infinint(r)?)
    };
    let mode = read_u16(r)?; // perms: a 2-byte big-endian u16, never an infinint
    let atime = read_timestamp(r, format_major)?;
    let mtime = read_timestamp(r, format_major)?;
    // ctime (last_cha) exists only from format 8 (libdar cat_inode.cpp:197).
    let ctime = if format_major >= 8 {
        Some(read_timestamp(r, format_major)?)
    } else {
        None
    };
    // FSA inode fields exist only from format 9 (libdar cat_inode.cpp:264); bit
    // 0x10 is the FSA-full status. Formats <= 8 have no FSA.
    if format_major >= 9 && (flags >> 4) & 1 != 0 {
        read_infinint(r)?;
        read_infinint(r)?;
    }
    Ok(Inode {
        flags,
        uid,
        gid,
        mode,
        atime,
        mtime,
        ctime,
    })
}

/// Skip one FSA (filesystem attributes) block.
///
/// Format: infinint(family_tag) + infinint(data_size) + data_size bytes.
fn skip_fsa<R: Read + Seek>(r: &mut R) -> Result<(), DarError> {
    let _tag = read_infinint(r)?;
    let size = read_infinint(r)?;
    skip(r, size)
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    // ── read_infinint ─────────────────────────────────────────────────────────

    #[test]
    fn infinint_decodes_value() {
        let data = [0x80u8, 0x00, 0x00, 0x00, 0x0d];
        assert_eq!(read_infinint(&mut Cursor::new(&data[..])).unwrap(), 13);
    }

    #[test]
    fn infinint_bad_preamble_returns_corrupt() {
        // 0x03 = two bits set — not a valid infinint terminal.
        let data = [0x03u8, 0x00, 0x00, 0x00, 0x00];
        let err = read_infinint(&mut Cursor::new(&data[..])).unwrap_err();
        assert!(matches!(&err, DarError::Corrupt(_)));
    }

    #[test]
    fn infinint_truncated_returns_io() {
        // Only 2 bytes — read_exact needs 5.
        let err = read_infinint(&mut Cursor::new(&[0x80u8, 0x00][..])).unwrap_err();
        assert!(matches!(err, DarError::Io(_)));
    }

    #[test]
    fn infinint_0x40_preamble_reads_8_data_bytes() {
        // 0x40 terminal: leading_zeros=1, pos=1, data_bytes=(0*8+1+1)*4=8
        // Encodes the value 0x5d15_9331 in 8 big-endian bytes.
        let mut data = vec![0x40u8];
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x5d, 0x15, 0x93, 0x31]);
        assert_eq!(
            read_infinint(&mut Cursor::new(data)).unwrap(),
            0x5d15_9331u64
        );
    }

    #[test]
    fn infinint_multi_bit_terminal_returns_corrupt() {
        // 0x60 = 0110_0000 — two bits set, not a valid terminal.
        let data = [0x60u8, 0x00, 0x00, 0x00, 0x00];
        let err = read_infinint(&mut Cursor::new(&data[..])).unwrap_err();
        assert!(matches!(&err, DarError::Corrupt(_)));
    }

    // ── read_u8 ───────────────────────────────────────────────────────────────

    #[test]
    fn read_u8_reads_single_byte() {
        assert_eq!(read_u8(&mut Cursor::new(&[0x42u8][..])).unwrap(), 0x42);
    }

    #[test]
    fn read_u8_eof_returns_io() {
        let err = read_u8(&mut Cursor::new(&[][..])).unwrap_err();
        assert!(matches!(err, DarError::Io(_)));
    }

    // ── read_nul_bytes ──────────────────────────────────────────────────────

    #[test]
    fn nul_bytes_reads_until_nul() {
        let data = b"hello\x00world";
        assert_eq!(
            read_nul_bytes(&mut Cursor::new(&data[..])).unwrap(),
            b"hello"
        );
    }

    #[test]
    fn nul_bytes_preserves_non_utf8() {
        // Raw bytes are kept verbatim — a non-UTF-8 name must NOT be rejected.
        let data = [0xFF, 0x80, 0x00];
        assert_eq!(
            read_nul_bytes(&mut Cursor::new(&data[..])).unwrap(),
            vec![0xFF, 0x80]
        );
    }

    #[test]
    fn nul_bytes_eof_before_nul_returns_io() {
        let err = read_nul_bytes(&mut Cursor::new(b"no-nul".to_vec())).unwrap_err();
        assert!(matches!(err, DarError::Io(_)));
    }

    // ── skip_nul_string ───────────────────────────────────────────────────────

    #[test]
    fn skip_nul_string_advances_past_nul() {
        let data = b"skip\x00rest";
        let mut c = Cursor::new(data.to_vec());
        skip_nul_string(&mut c).unwrap();
        assert_eq!(c.position(), 5); // "skip\0" = 5 bytes consumed
    }

    #[test]
    fn skip_nul_string_eof_returns_io() {
        let err = skip_nul_string(&mut Cursor::new(b"no-nul".to_vec())).unwrap_err();
        assert!(matches!(err, DarError::Io(_)));
    }

    // ── find_catalogue ────────────────────────────────────────────────────────

    #[test]
    fn find_catalogue_body_too_short() {
        // Fewer than 6 bytes — can't fill the initial window; label also too short.
        let label = [0u8; 10];
        let err = find_catalogue(&mut Cursor::new(&[0x01u8, 0x02, 0x03][..]), &label).unwrap_err();
        assert!(
            matches!(&err, DarError::Corrupt(s) if s == "archive body too short"
            || s == "seqt_catalogue not found")
        );
    }

    #[test]
    fn find_catalogue_escape_at_start() {
        let mut data = [0xAD, 0xFD, 0xEA, 0x77, 0x21, 0x43, 0xFF];
        let mut c = Cursor::new(&mut data[..]);
        let via_escape = find_catalogue(&mut c, &[0u8; 10]).unwrap();
        assert!(via_escape);
        assert_eq!(c.position(), 6);
    }

    #[test]
    fn find_catalogue_escape_not_found() {
        // 10 bytes of zeros, label is 0xFF×10 so label scan also fails.
        let label = [0xFFu8; 10];
        let err = find_catalogue(&mut Cursor::new(&[0u8; 10][..]), &label).unwrap_err();
        assert!(matches!(&err, DarError::Corrupt(s) if s == "seqt_catalogue not found"));
    }

    #[test]
    fn find_catalogue_label_fallback() {
        let label: [u8; 10] = [0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18, 0x29, 0x3A];
        // Prefix junk (no escape) followed by the label bytes.
        let mut data = vec![0x00u8; 5];
        data.extend_from_slice(&label);
        let mut c = Cursor::new(data);
        let via_escape = find_catalogue(&mut c, &label).unwrap();
        assert!(!via_escape);
        assert_eq!(c.position(), 15); // 5 junk + 10 label consumed
    }

    // ── skip ──────────────────────────────────────────────────────────────────

    #[test]
    fn skip_zero_does_not_move_cursor() {
        let mut c = Cursor::new(vec![0xFFu8; 10]);
        skip(&mut c, 0).unwrap();
        assert_eq!(c.position(), 0);
    }

    #[test]
    fn skip_n_advances_cursor() {
        let mut c = Cursor::new(vec![0xFFu8; 10]);
        skip(&mut c, 7).unwrap();
        assert_eq!(c.position(), 7);
    }

    // ── read_inode_base ───────────────────────────────────────────────────────

    #[test]
    fn inode_base_bit4_clear_reads_31_bytes() {
        // flags(1) + uid(5) + gid(5) + perms(2) + 3×[type(1)+secs(5)] = 31 bytes
        let mut data = vec![0x00u8]; // flags (bit4=0)
        data.extend_from_slice(&[0x80, 0x00, 0x00, 0x00, 0x00]); // uid
        data.extend_from_slice(&[0x80, 0x00, 0x00, 0x00, 0x00]); // gid
        data.extend_from_slice(&[0x00, 0x00]); // perms
        for _ in 0..3 {
            data.push(b's'); // timestamp type
            data.extend_from_slice(&[0x80, 0x00, 0x00, 0x00, 0x00]); // seconds
        }
        data.push(0xFF); // sentinel — must not be consumed
        let mut c = Cursor::new(data);
        assert_eq!(read_inode_base(&mut c, 11).unwrap().flags, 0x00);
        assert_eq!(c.position(), 31);
    }

    #[test]
    fn inode_base_bit4_set_reads_41_bytes() {
        // flags(1) + uid(5) + gid(5) + perms(2) + 3×[type(1)+secs(5)] + nlink(5) + field9(5) = 41
        let mut data = vec![0x10u8]; // flags (bit4=1)
        data.extend_from_slice(&[0x80, 0x00, 0x00, 0x00, 0x00]); // uid
        data.extend_from_slice(&[0x80, 0x00, 0x00, 0x00, 0x00]); // gid
        data.extend_from_slice(&[0x00, 0x00]); // perms
        for _ in 0..3 {
            data.push(b's');
            data.extend_from_slice(&[0x80, 0x00, 0x00, 0x00, 0x00]);
        }
        data.extend_from_slice(&[0x80, 0x00, 0x00, 0x00, 0x00]); // nlink
        data.extend_from_slice(&[0x80, 0x00, 0x00, 0x00, 0x00]); // field9
        data.push(0xFF); // sentinel
        let mut c = Cursor::new(data);
        assert_eq!(read_inode_base(&mut c, 11).unwrap().flags, 0x10);
        assert_eq!(c.position(), 41);
    }

    // ── skip_fsa ─────────────────────────────────────────────────────────────

    #[test]
    fn skip_fsa_consumes_tag_size_and_data() {
        // tag=infinint(5) + size=infinint(3) + 3 data bytes
        let mut data = Vec::new();
        data.extend_from_slice(&[0x80, 0x00, 0x00, 0x00, 0x05]); // tag
        data.extend_from_slice(&[0x80, 0x00, 0x00, 0x00, 0x03]); // size=3
        data.extend_from_slice(&[0xAA, 0xBB, 0xCC]); // data
        data.push(0xFF); // sentinel
        let mut c = Cursor::new(data);
        skip_fsa(&mut c).unwrap();
        assert_eq!(c.position(), 13); // 5 + 5 + 3 = 13
    }

    // ── hardening: malicious / corrupted infinint encodings ───────────────────
    //
    // A `u64` holds at most 8 data bytes.  The reader's contract is "decode to
    // u64 or return Corrupt" — it must never silently truncate an over-wide
    // value, overflow while computing the byte count, or loop on a zero run.

    #[test]
    fn infinint_leading_zero_byte_returns_corrupt() {
        // A leading 0x00 skip-byte implies a ≥36-byte group — far beyond u64.
        // Must be rejected as Corrupt, not mislabelled as an I/O shortage.
        let data = [0x00u8, 0x80, 0x00, 0x00, 0x00, 0x00];
        let err = read_infinint(&mut Cursor::new(&data[..])).unwrap_err();
        assert!(matches!(err, DarError::Corrupt(_)), "got {err:?}");
    }

    #[test]
    fn infinint_12_byte_group_exceeds_u64_returns_corrupt() {
        // 0x20 terminal → pos=2 → 12 data bytes → cannot fit in u64.
        // Must error rather than silently truncate to a wrong value.
        let mut data = vec![0x20u8];
        data.extend_from_slice(&[0x11; 12]);
        let err = read_infinint(&mut Cursor::new(data)).unwrap_err();
        assert!(matches!(err, DarError::Corrupt(_)), "got {err:?}");
    }

    #[test]
    fn infinint_all_zero_run_returns_corrupt_without_hanging() {
        // A run of zero bytes must terminate promptly with Corrupt, never spin
        // consuming the whole stream (and never overflow-panic the skip count).
        let data = vec![0u8; 4096];
        let err = read_infinint(&mut Cursor::new(data)).unwrap_err();
        assert!(matches!(err, DarError::Corrupt(_)), "got {err:?}");
    }

    // ── hardening: unbounded NUL-terminated strings ───────────────────────────

    #[test]
    fn nul_bytes_without_terminator_is_length_bounded() {
        // No NUL in 200 KiB of data: must be rejected once the path cap is hit,
        // not grow the buffer until EOF (or OOM on a multi-GiB stream).
        let data = vec![b'A'; 200_000];
        let err = read_nul_bytes(&mut Cursor::new(data)).unwrap_err();
        assert!(matches!(err, DarError::Corrupt(_)), "got {err:?}");
    }

    #[test]
    fn skip_nul_string_without_terminator_is_length_bounded() {
        let data = vec![b'A'; 200_000];
        let err = skip_nul_string(&mut Cursor::new(data)).unwrap_err();
        assert!(matches!(err, DarError::Corrupt(_)), "got {err:?}");
    }

    // ── hardening: skip must never seek backwards ─────────────────────────────

    #[test]
    fn skip_value_above_i64_max_returns_corrupt() {
        // n > i64::MAX casts to a negative i64 → SeekFrom::Current would seek
        // *backwards* on a File (re-reading earlier bytes).  Must be rejected,
        // and the stream position must not move.
        let mut c = Cursor::new(vec![0u8; 64]);
        c.set_position(32);
        let err = skip(&mut c, 0x8000_0000_0000_0000).unwrap_err();
        assert!(matches!(err, DarError::Corrupt(_)), "got {err:?}");
        assert_eq!(c.position(), 32); // unchanged on a rejected skip
    }

    // ── terminateur trailer (pre-8 catalog locator) ───────────────────────────

    #[test]
    fn terminateur_reads_catalogue_offset() {
        // pos infinint 0x18 = 24; terminator 0xc0 → two leading ones → 2*4 = 8
        // bytes back to the infinint.
        let data = vec![0x80u8, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0xc0];
        assert_eq!(read_terminateur(&mut Cursor::new(data)).unwrap(), 24);
    }

    #[test]
    fn terminateur_all_ff_underflows_returns_corrupt() {
        let err = read_terminateur(&mut Cursor::new(vec![0xFFu8; 4])).unwrap_err();
        assert!(matches!(err, DarError::Corrupt(_)), "got {err:?}");
    }

    #[test]
    fn terminateur_excessive_ff_padding_returns_corrupt() {
        let err = read_terminateur(&mut Cursor::new(vec![0xFFu8; 600])).unwrap_err();
        assert!(matches!(err, DarError::Corrupt(_)), "got {err:?}");
    }

    #[test]
    fn terminateur_low_terminator_byte_returns_corrupt() {
        // Terminator byte 0x01 has no top bit set.
        let data = vec![0x80u8, 0x00, 0x00, 0x00, 0x18, 0x01];
        let err = read_terminateur(&mut Cursor::new(data)).unwrap_err();
        assert!(matches!(err, DarError::Corrupt(_)), "got {err:?}");
    }

    #[test]
    fn terminateur_noncontiguous_high_bits_returns_corrupt() {
        // 0xA0 = 1010_0000: top bit set but the high-bit run is not contiguous.
        let data = vec![0x80u8, 0x00, 0x00, 0x00, 0x18, 0xA0];
        let err = read_terminateur(&mut Cursor::new(data)).unwrap_err();
        assert!(matches!(err, DarError::Corrupt(_)), "got {err:?}");
    }

    // ── find_catalogue: full-scan fallback + body-too-short ────────────────────

    #[test]
    fn find_catalogue_falls_back_to_full_scan() {
        // Escape near the start; a tiny tail window misses it, forcing the
        // archive_origin full-scan fallback.
        let mut data = vec![0x11u8, 0x22]; // junk before the escape
        data.extend_from_slice(&SEQT_CATALOGUE);
        data.extend_from_slice(&[0x33u8; 12]); // trailing bytes beyond the tail window
        let mut c = Cursor::new(data);
        let via_escape = find_catalogue_within(&mut c, &[0u8; 10], 4).unwrap();
        assert!(via_escape);
        assert_eq!(c.position(), 2 + SEQT_CATALOGUE.len() as u64);
    }

    #[test]
    fn find_catalogue_full_scan_miss_returns_not_found() {
        // No escape and no matching label anywhere; a tiny tail window forces
        // the full-scan fallback, which also misses → "not found".
        let mut c = Cursor::new(vec![0x11u8; 16]);
        let err = find_catalogue_within(&mut c, &[0xABu8; 10], 4).unwrap_err();
        assert!(matches!(&err, DarError::Corrupt(s) if s == "seqt_catalogue not found"));
    }

    #[test]
    fn find_catalogue_body_too_short_when_origin_at_eof() {
        let mut c = Cursor::new(vec![0u8; 6]);
        c.seek(SeekFrom::Start(6)).unwrap();
        let err = find_catalogue(&mut c, &[0u8; 10]).unwrap_err();
        assert!(matches!(&err, DarError::Corrupt(s) if s == "archive body too short"));
    }

    // ── decode_stream / CapWriter ────────────────────────────────────────────

    #[test]
    fn decode_stream_caps_decompression_bomb() {
        use flate2::{write::ZlibEncoder, Compression};
        use std::io::Write;
        let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
        enc.write_all(&[0u8; 4096]).unwrap();
        let blob = enc.finish().unwrap();
        // Inflates to 4096 bytes but the CapWriter caps output at 16.
        let mut sink = Vec::new();
        let mut cap = CapWriter {
            inner: &mut sink,
            written: 0,
            max: 16,
        };
        let err = decode_stream(&blob[..], b'z', &mut cap).unwrap_err();
        assert!(matches!(&err, DarError::Corrupt(s) if s.contains("exceeds bound")));
    }

    #[test]
    fn decode_stream_rejects_malformed_zlib() {
        let err = decode_stream(
            b"not a zlib stream at all".as_slice(),
            b'z',
            &mut Vec::new(),
        )
        .unwrap_err();
        assert!(matches!(&err, DarError::Corrupt(s) if s.contains("zlib decode failed")));
    }

    #[test]
    fn decode_stream_rejects_malformed_bzip2() {
        let err =
            decode_stream(b"not a bzip2 stream".as_slice(), b'y', &mut Vec::new()).unwrap_err();
        assert!(matches!(&err, DarError::Corrupt(s) if s.contains("bzip2 decode failed")));
    }

    #[test]
    fn decode_stream_rejects_malformed_xz() {
        let err = decode_stream(
            b"this is not an xz stream".as_slice(),
            b'x',
            &mut Vec::new(),
        )
        .unwrap_err();
        assert!(matches!(&err, DarError::Corrupt(s) if s.contains("xz decode failed")));
    }

    #[test]
    fn cap_writer_forwards_within_bound_and_fails_over() {
        use std::io::Write;
        let mut sink = Vec::new();
        let mut w = CapWriter {
            inner: &mut sink,
            written: 0,
            max: 4,
        };
        assert_eq!(w.write(b"ab").unwrap(), 2); // within bound
        w.flush().unwrap();
        let err = w.write(b"cde").unwrap_err(); // 2 + 3 > 4
        assert_eq!(err.to_string(), "decompressed data exceeds bound");
        assert_eq!(sink, b"ab");
    }
}
