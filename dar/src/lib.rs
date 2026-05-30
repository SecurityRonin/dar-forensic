//! Pure-Rust reader for Denis Corbin DAR (Disk ARchiver) archives.
//!
//! Supports DAR format versions 8, 9, and 11 (produced by dar 2.x).
//! Passware Mobile produces v8/v9 archives; dar 2.8.5 produces v11.
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
//!   [10] label  +  NUL-terminated path  +  entries
//!
//!   Each entry: cat_sig byte where (cat_sig & 0x1f | 0x60) gives type
//!     'd' directory  → NUL-name + inode [+ FSA]  (push to dir stack)
//!     'f' file       → NUL-name + inode [+ FSA] + file-specific fields
//!     'z' EOD        → pop dir stack; depth=0 → done
//! ```
//!
//! ## Key non-obvious invariants
//!
//! - **Infinint**: always 5 bytes — `0x80 XX XX XX XX`, value = last 4 as
//!   big-endian u32.
//! - **Permissions**: 2-byte big-endian u16, *not* an infinint.
//! - **Inode bit 4**: when set the inode is 41 bytes (includes nlink+field9)
//!   and an FSA block follows; when clear the inode is 31 bytes, no FSA.
//! - **archive_offset**: points *directly* to the raw file bytes, not to the
//!   data-section header that precedes them in the body stream.
//!   `seek(archive_origin + archive_offset)` then `read(stored_size)`.
//!
//! Full format notes: `docs/implementation-notes.md`.

use std::io::{Read, Seek, SeekFrom};

use thiserror::Error;

/// `00 00 00 7b` — DAR magic (SAUV_MAGIC_NUMBER = 123, big-endian u32).
const DAR_MAGIC: [u8; 4] = [0x00, 0x00, 0x00, 0x7b];

/// Escape sequence marking the catalog: `AD FD EA 77 21 43`.
const SEQT_CATALOGUE: [u8; 6] = [0xAD, 0xFD, 0xEA, 0x77, 0x21, 0x43];

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

/// Metadata about one archived file.
#[derive(Debug, Clone)]
pub struct DarEntry {
    pub path: String,
    pub size: u64,
}

#[derive(Debug, Clone)]
struct EntryRef {
    path: String,
    size: u64,
    archive_offset: u64,
    stored_size: u64,
    compression: u8,
    encrypted: bool,
}

/// Read-only DAR archive reader.
pub struct DarReader<R: Read + Seek> {
    inner: R,
    /// Byte position immediately after the slice header TLV block.
    /// `archive_origin + archive_offset` = absolute position of raw file bytes.
    archive_origin: u64,
    entries: Vec<EntryRef>,
}

impl<R: Read + Seek> DarReader<R> {
    /// Open a DAR archive, validating the magic and loading the catalog.
    pub fn open(mut reader: R) -> Result<Self, DarError> {
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic).map_err(|_| DarError::NotADar)?;
        if magic != DAR_MAGIC {
            return Err(DarError::NotADar);
        }

        let mut label = [0u8; 10];
        reader.read_exact(&mut label)?; // internal_name label
        skip(&mut reader, 2)?;  // flag + ext_char

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

        // Everything after the TLV block is addressed by archive_offset.
        let archive_origin = reader.stream_position()?;

        // Returns true if the standard escape was found (catalog has label + path prefix),
        // false if catalog was located via the archive label directly (no prefix to skip).
        let via_escape = find_catalogue(&mut reader, &label)?;
        if via_escape {
            skip(&mut reader, 10)?;      // catalog label
            skip_nul_string(&mut reader)?; // catalog working-directory path
        }

        let entries = parse_catalog(&mut reader)?;

        Ok(Self { inner: reader, archive_origin, entries })
    }

    /// List all archived file entries (path and uncompressed size).
    pub fn entries(&self) -> Vec<DarEntry> {
        self.entries
            .iter()
            .map(|e| DarEntry { path: e.path.clone(), size: e.size })
            .collect()
    }

    /// Extract a file by path, returning its raw bytes.
    pub fn extract(&mut self, path: &str) -> Result<Vec<u8>, DarError> {
        let entry = self
            .entries
            .iter()
            .find(|e| e.path == path)
            .ok_or_else(|| DarError::EntryNotFound(path.to_string()))?
            .clone();

        if entry.encrypted {
            return Err(DarError::Corrupt(format!("'{}' is encrypted", path)));
        }
        if entry.compression != b'n' {
            return Err(DarError::Corrupt(format!(
                "'{}' uses unsupported compression '{}'",
                path, entry.compression as char
            )));
        }

        self.inner
            .seek(SeekFrom::Start(self.archive_origin + entry.archive_offset))?;
        let mut data = vec![0u8; entry.stored_size as usize];
        self.inner.read_exact(&mut data)?;
        Ok(data)
    }
}

// ── Catalog parser ────────────────────────────────────────────────────────────

/// Locate the catalog section and position the reader at its first entry.
///
/// Returns `true` when the standard `seqt_catalogue` escape is found — the
/// caller must then skip the 10-byte in-catalog label and path NUL string.
///
/// Returns `false` when the catalog is located via the archive `label` directly
/// (Passware Mobile format: no escape, no path NUL between label and entries).
///
/// Returns `Err(Corrupt)` when neither marker is found.
fn find_catalogue<R: Read + Seek>(r: &mut R, label: &[u8; 10]) -> Result<bool, DarError> {
    let start_pos = r.stream_position()?;

    // ── pass 1: escape scan ───────────────────────────────────────────────────
    let n = SEQT_CATALOGUE.len();
    let mut window = [0u8; 6];
    if r.read_exact(&mut window)
        .map_err(|_| DarError::Corrupt("archive body too short".into()))
        .is_ok()
    {
        loop {
            if window == SEQT_CATALOGUE {
                return Ok(true);
            }
            window.copy_within(1.., 0);
            if r.read_exact(&mut window[n - 1..]).is_err() {
                break; // exhausted — fall through to label scan
            }
        }
    }

    // ── pass 2: label-scan fallback ───────────────────────────────────────────
    // Only useful when the label is non-trivial (all-zero labels are too common
    // in zero-filled archive bodies to be reliable markers).
    if label.iter().all(|&b| b == 0) {
        return Err(DarError::Corrupt("seqt_catalogue not found".into()));
    }

    r.seek(SeekFrom::Start(start_pos))?;
    let mut lwindow = [0u8; 10];
    r.read_exact(&mut lwindow)
        .map_err(|_| DarError::Corrupt("seqt_catalogue not found".into()))?;

    loop {
        if &lwindow == label {
            return Ok(false); // reader is now positioned at the first catalog entry
        }
        lwindow.copy_within(1.., 0);
        if r.read_exact(&mut lwindow[9..]).is_err() {
            break;
        }
    }

    Err(DarError::Corrupt("seqt_catalogue not found".into()))
}

/// Parse all catalog entries, returning file entries with their extraction info.
///
/// Stops when the root directory is closed (depth reaches zero) or an unknown
/// entry type is encountered (slice trailer).
fn parse_catalog<R: Read + Seek>(r: &mut R) -> Result<Vec<EntryRef>, DarError> {
    let mut entries = Vec::new();
    let mut dir_stack: Vec<String> = Vec::new();
    let mut depth: u32 = 0;

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
                    break;
                }
            }
            'd' => {
                let name = read_nul_string(r)?;
                let flags = read_inode_base(r)?;
                if (flags >> 4) & 1 != 0 {
                    skip_fsa(r)?;
                }
                depth += 1;
                // <ROOT> is a virtual root; don't include it in file paths.
                if name != "<ROOT>" {
                    dir_stack.push(name);
                }
            }
            'f' => {
                let name = read_nul_string(r)?;
                let flags = read_inode_base(r)?;
                if (flags >> 4) & 1 != 0 {
                    skip_fsa(r)?;
                }

                let size = read_infinint(r)?;
                let archive_offset = read_infinint(r)?;
                let stored_size = read_infinint(r)?;
                let encryption_flag = read_u8(r)?;
                let compression = read_u8(r)?;
                let crc_size = read_infinint(r)?;
                skip(r, crc_size)?;

                let path = if dir_stack.is_empty() {
                    name
                } else {
                    format!("{}/{}", dir_stack.join("/"), name)
                };

                entries.push(EntryRef {
                    path,
                    size,
                    archive_offset,
                    stored_size,
                    compression,
                    encrypted: encryption_flag != 0,
                });
            }
            _ => break, // unknown type = slice trailer boundary
        }
    }

    Ok(entries)
}

// ── Low-level I/O helpers ─────────────────────────────────────────────────────

/// Read a 5-byte DAR infinint: `0x80 XX XX XX XX` → big-endian u32.
fn read_infinint<R: Read>(r: &mut R) -> Result<u64, DarError> {
    let mut buf = [0u8; 5];
    r.read_exact(&mut buf)?;
    if buf[0] != 0x80 {
        return Err(DarError::Corrupt(format!(
            "invalid infinint preamble: 0x{:02x}",
            buf[0]
        )));
    }
    Ok(u32::from_be_bytes(buf[1..5].try_into().unwrap()) as u64)
}

fn read_u8<R: Read>(r: &mut R) -> Result<u8, DarError> {
    let mut b = [0u8; 1];
    r.read_exact(&mut b)?;
    Ok(b[0])
}

/// Read a NUL-terminated UTF-8 string, consuming the NUL byte.
fn read_nul_string<R: Read>(r: &mut R) -> Result<String, DarError> {
    let mut bytes = Vec::new();
    loop {
        let b = read_u8(r)?;
        if b == 0 {
            break;
        }
        bytes.push(b);
    }
    String::from_utf8(bytes).map_err(|e| DarError::Corrupt(e.to_string()))
}

/// Skip a NUL-terminated string without collecting the bytes.
fn skip_nul_string<R: Read>(r: &mut R) -> Result<(), DarError> {
    loop {
        if read_u8(r)? == 0 {
            return Ok(());
        }
    }
}

/// Seek past `n` bytes.
fn skip<R: Seek>(r: &mut R, n: u64) -> Result<(), DarError> {
    if n > 0 {
        r.seek(SeekFrom::Current(n as i64))
            .map(|_| ())
            .map_err(DarError::Io)?;
    }
    Ok(())
}

/// Read the inode flags byte and seek past the remaining fixed-size fields.
///
/// Base layout (31 bytes when bit 4 clear, 41 bytes when bit 4 set):
///   flags(1) + uid(5) + gid(5) + perms(2) + ctime(6) + mtime(6) + atime(6)
///   [+ nlink(5) + field9(5) only when (flags >> 4) & 1 == 1]
fn read_inode_base<R: Read + Seek>(r: &mut R) -> Result<u8, DarError> {
    let flags = read_u8(r)?;
    // uid(5)+gid(5)+perms(2)+ctime(6)+mtime(6)+atime(6) = 30 bytes always present
    skip(r, 30)?;
    // nlink and field9 only present when bit 4 is set
    if (flags >> 4) & 1 != 0 {
        skip(r, 10)?;
    }
    Ok(flags)
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
        let data = [0x01u8, 0x00, 0x00, 0x00, 0x00];
        let err = read_infinint(&mut Cursor::new(&data[..])).unwrap_err();
        assert!(matches!(&err, DarError::Corrupt(s) if s.contains("preamble")));
    }

    #[test]
    fn infinint_truncated_returns_io() {
        // Only 2 bytes — read_exact needs 5.
        let err = read_infinint(&mut Cursor::new(&[0x80u8, 0x00][..])).unwrap_err();
        assert!(matches!(err, DarError::Io(_)));
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

    // ── read_nul_string ───────────────────────────────────────────────────────

    #[test]
    fn nul_string_reads_until_nul() {
        let data = b"hello\x00world";
        assert_eq!(read_nul_string(&mut Cursor::new(&data[..])).unwrap(), "hello");
    }

    #[test]
    fn nul_string_invalid_utf8_returns_corrupt() {
        // 0xFF 0x80 is not valid UTF-8; 0x00 terminates.
        let data = [0xFF, 0x80, 0x00];
        let err = read_nul_string(&mut Cursor::new(&data[..])).unwrap_err();
        assert!(matches!(err, DarError::Corrupt(_)));
    }

    #[test]
    fn nul_string_eof_before_nul_returns_io() {
        let err = read_nul_string(&mut Cursor::new(b"no-nul".to_vec())).unwrap_err();
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
        let err = find_catalogue(&mut Cursor::new(&[0x01u8, 0x02, 0x03][..]), &label)
            .unwrap_err();
        assert!(matches!(&err, DarError::Corrupt(s) if s == "archive body too short"
            || s == "seqt_catalogue not found"));
    }

    #[test]
    fn find_catalogue_escape_at_start() {
        let mut data = vec![0xAD, 0xFD, 0xEA, 0x77, 0x21, 0x43, 0xFF];
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
        // flags=0x00 (bit4 clear) + 30 bytes
        let mut data = vec![0x00u8]; // flags
        data.extend_from_slice(&[0xAA; 30]);
        data.push(0xFF); // sentinel
        let mut c = Cursor::new(data);
        assert_eq!(read_inode_base(&mut c).unwrap(), 0x00);
        assert_eq!(c.position(), 31);
    }

    #[test]
    fn inode_base_bit4_set_reads_41_bytes() {
        // flags=0x10 (bit4 set) + 30 bytes + 10 bytes
        let mut data = vec![0x10u8]; // flags
        data.extend_from_slice(&[0xAA; 40]);
        data.push(0xFF); // sentinel
        let mut c = Cursor::new(data);
        assert_eq!(read_inode_base(&mut c).unwrap(), 0x10);
        assert_eq!(c.position(), 41);
    }

    // ── skip_fsa ─────────────────────────────────────────────────────────────

    #[test]
    fn skip_fsa_consumes_tag_size_and_data() {
        // tag=infinint(5) + size=infinint(3) + 3 data bytes
        let mut data = Vec::new();
        data.extend_from_slice(&[0x80, 0x00, 0x00, 0x00, 0x05]); // tag
        data.extend_from_slice(&[0x80, 0x00, 0x00, 0x00, 0x03]); // size=3
        data.extend_from_slice(&[0xAA, 0xBB, 0xCC]);               // data
        data.push(0xFF);                                             // sentinel
        let mut c = Cursor::new(data);
        skip_fsa(&mut c).unwrap();
        assert_eq!(c.position(), 13); // 5 + 5 + 3 = 13
    }
}
