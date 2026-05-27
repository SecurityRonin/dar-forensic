//! Pure-Rust reader for Denis Corbin DAR (Disk ARchiver) archives.
//!
//! Supports DAR format versions 8, 9, and 11 (produced by dar 2.x).
//!
//! Format overview:
//!   Slice header: magic(4) + label(10) + flag(1) + ext_char(1) + TLV_list
//!   Archive body: version_string + escapes + file_data
//!   Catalog:      seqt_catalogue_escape + label(10) + path + entries
//!   Slice trailer: version + offsets

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

        skip(&mut reader, 10)?; // internal_name label
        skip(&mut reader, 2)?;  // flag + ext_char

        // TLV list: infinint(count) then count × (u16 type + infinint len + data)
        let tlv_count = read_infinint(&mut reader)
            .map_err(|_| DarError::Corrupt("truncated TLV block".into()))?;
        for _ in 0..tlv_count {
            skip(&mut reader, 2)?;
            let len = read_infinint(&mut reader)?;
            skip(&mut reader, len)?;
        }

        // Everything after the TLV block is addressed by archive_offset.
        let archive_origin = reader.stream_position()?;

        find_catalogue(&mut reader)?;

        skip(&mut reader, 10)?;      // catalog label
        skip_nul_string(&mut reader)?; // catalog working-directory path

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

/// Scan forward until the seqt_catalogue escape is found and consumed.
///
/// After return the reader is positioned immediately after the 6-byte escape,
/// at the first byte of the catalog payload.
fn find_catalogue<R: Read + Seek>(r: &mut R) -> Result<(), DarError> {
    let n = SEQT_CATALOGUE.len();
    let mut window = [0u8; 6];
    r.read_exact(&mut window)
        .map_err(|_| DarError::Corrupt("archive body too short".into()))?;

    loop {
        if window == SEQT_CATALOGUE {
            return Ok(());
        }
        window.copy_within(1.., 0);
        r.read_exact(&mut window[n - 1..])
            .map_err(|_| DarError::Corrupt("seqt_catalogue not found".into()))?;
    }
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
