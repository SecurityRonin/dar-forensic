//! Pure-Rust DAR (Disk ARchiver) archive reader.
//!
//! Reads archives in the SecurityRonin DAR format:
//!
//! ```text
//! [4]  magic = b"DAR\x00"
//! [4]  version = 1u32 LE
//! [4]  entry_count (u32 LE)
//! For each entry:
//!   [4]  name_len (u32 LE)
//!   [name_len]  path (UTF-8)
//!   [8]  data_len (u64 LE)
//!   [data_len]  raw data
//!   [4]  crc32 of data (u32 LE)
//! [4]  catalog magic = b"CATL"
//! [4]  catalog entry count (u32 LE)
//! For each catalog entry:
//!   [4]  name_len
//!   [name_len]  path (UTF-8)
//!   [8]  data_offset (u64 LE) — byte position in the archive file
//!   [8]  data_len (u64 LE)
//! ```

use std::io::{Read, Seek, SeekFrom};

use thiserror::Error;

const MAGIC: &[u8; 4] = b"DAR\x00";
const VERSION: u32 = 1;
const CATALOG_MAGIC: &[u8; 4] = b"CATL";

/// Errors returned by `DarReader`.
#[derive(Debug, Error)]
pub enum DarError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("not a DAR archive: bad magic")]
    NotADar,
    #[error("corrupt catalog: {0}")]
    CorruptCatalog(String),
    #[error("CRC32 mismatch for '{path}': expected {expected:#010x}, got {got:#010x}")]
    BadChecksum { path: String, expected: u32, got: u32 },
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
    data_offset: u64,
    data_len: u64,
}

/// Read-only DAR archive reader.
pub struct DarReader<R: Read + Seek> {
    inner: R,
    entries: Vec<EntryRef>,
}

impl<R: Read + Seek> DarReader<R> {
    /// Open a DAR archive, validating the magic and loading the catalog.
    pub fn open(mut reader: R) -> Result<Self, DarError> {
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic).map_err(|_| DarError::NotADar)?;
        if &magic != MAGIC {
            return Err(DarError::NotADar);
        }
        let version = read_u32le(&mut reader).map_err(|_| DarError::NotADar)?;
        if version != VERSION {
            return Err(DarError::NotADar);
        }
        let entry_count = read_u32le(&mut reader).map_err(|_| DarError::NotADar)?;

        // Skip past all file data to find the catalog.
        for _ in 0..entry_count {
            let name_len = read_u32le(&mut reader)
                .map_err(|e| DarError::CorruptCatalog(e.to_string()))?;
            reader
                .seek(SeekFrom::Current(name_len as i64))
                .map_err(|e| DarError::CorruptCatalog(e.to_string()))?;
            let data_len = read_u64le(&mut reader)
                .map_err(|e| DarError::CorruptCatalog(e.to_string()))?;
            // Skip data + CRC
            reader
                .seek(SeekFrom::Current(data_len as i64 + 4))
                .map_err(|e| DarError::CorruptCatalog(e.to_string()))?;
        }

        // Read catalog magic
        let mut cat_magic = [0u8; 4];
        reader
            .read_exact(&mut cat_magic)
            .map_err(|e| DarError::CorruptCatalog(e.to_string()))?;
        if &cat_magic != CATALOG_MAGIC {
            return Err(DarError::CorruptCatalog("missing CATL marker".into()));
        }

        let cat_count = read_u32le(&mut reader)
            .map_err(|e| DarError::CorruptCatalog(e.to_string()))?;
        let mut entries = Vec::with_capacity(cat_count as usize);
        for _ in 0..cat_count {
            let name_len = read_u32le(&mut reader)
                .map_err(|e| DarError::CorruptCatalog(e.to_string()))?;
            let mut name_bytes = vec![0u8; name_len as usize];
            reader
                .read_exact(&mut name_bytes)
                .map_err(|e| DarError::CorruptCatalog(e.to_string()))?;
            let path = String::from_utf8(name_bytes)
                .map_err(|e| DarError::CorruptCatalog(e.to_string()))?;
            let data_offset = read_u64le(&mut reader)
                .map_err(|e| DarError::CorruptCatalog(e.to_string()))?;
            let data_len = read_u64le(&mut reader)
                .map_err(|e| DarError::CorruptCatalog(e.to_string()))?;
            entries.push(EntryRef { path, data_offset, data_len });
        }

        Ok(Self { inner: reader, entries })
    }

    /// List all archived entries (path and size).
    pub fn entries(&self) -> Vec<DarEntry> {
        self.entries
            .iter()
            .map(|e| DarEntry { path: e.path.clone(), size: e.data_len })
            .collect()
    }

    /// Extract a file by path, verifying its CRC32.
    pub fn extract(&mut self, path: &str) -> Result<Vec<u8>, DarError> {
        let entry = self
            .entries
            .iter()
            .find(|e| e.path == path)
            .ok_or_else(|| DarError::EntryNotFound(path.to_string()))?
            .clone();

        self.inner.seek(SeekFrom::Start(entry.data_offset))?;
        let mut data = vec![0u8; entry.data_len as usize];
        self.inner.read_exact(&mut data)?;

        // CRC32 is stored immediately after the data in the archive.
        let stored_crc = read_u32le(&mut self.inner)?;
        let computed = crc32(&data);
        if stored_crc != computed {
            return Err(DarError::BadChecksum {
                path: path.to_string(),
                expected: stored_crc,
                got: computed,
            });
        }
        Ok(data)
    }
}

fn read_u32le<R: Read>(r: &mut R) -> std::io::Result<u32> {
    let mut b = [0u8; 4];
    r.read_exact(&mut b)?;
    Ok(u32::from_le_bytes(b))
}

fn read_u64le<R: Read>(r: &mut R) -> std::io::Result<u64> {
    let mut b = [0u8; 8];
    r.read_exact(&mut b)?;
    Ok(u64::from_le_bytes(b))
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            if crc & 1 == 1 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    // ── Test helper ────────────────────────────────────────────────────────────

    fn make_dar(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        // Header
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&VERSION.to_le_bytes());
        out.extend_from_slice(&(files.len() as u32).to_le_bytes());

        // Track where each file's data begins (after name_len + name + data_len)
        let mut data_offsets: Vec<u64> = Vec::new();

        // File entries
        for (name, data) in files {
            let name_bytes = name.as_bytes();
            let pos_before_data = out.len() as u64
                + 4 // name_len field
                + name_bytes.len() as u64
                + 8; // data_len field
            data_offsets.push(pos_before_data);
            out.extend_from_slice(&(name_bytes.len() as u32).to_le_bytes());
            out.extend_from_slice(name_bytes);
            out.extend_from_slice(&(data.len() as u64).to_le_bytes());
            out.extend_from_slice(data);
            out.extend_from_slice(&crc32(data).to_le_bytes());
        }

        // Catalog
        out.extend_from_slice(CATALOG_MAGIC);
        out.extend_from_slice(&(files.len() as u32).to_le_bytes());
        for ((name, data), offset) in files.iter().zip(data_offsets.iter()) {
            let name_bytes = name.as_bytes();
            out.extend_from_slice(&(name_bytes.len() as u32).to_le_bytes());
            out.extend_from_slice(name_bytes);
            out.extend_from_slice(&offset.to_le_bytes());
            out.extend_from_slice(&(data.len() as u64).to_le_bytes());
        }
        out
    }

    // ── Tests ──────────────────────────────────────────────────────────────────

    #[test]
    fn not_a_dar_returns_err() {
        let data = b"this is not a DAR archive at all";
        let result = DarReader::open(Cursor::new(data));
        assert!(matches!(result, Err(DarError::NotADar)));
    }

    #[test]
    fn empty_archive_has_no_entries() {
        let archive = make_dar(&[]);
        let reader = DarReader::open(Cursor::new(archive)).expect("open failed");
        assert!(reader.entries().is_empty());
    }

    #[test]
    fn single_file_listed_in_entries() {
        let archive = make_dar(&[("readme.txt", b"hello")]);
        let reader = DarReader::open(Cursor::new(archive)).expect("open failed");
        let entries = reader.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, "readme.txt");
        assert_eq!(entries[0].size, 5);
    }

    #[test]
    fn multiple_files_listed() {
        let archive = make_dar(&[("a.bin", b"aaa"), ("b.bin", b"bbb"), ("c.bin", b"ccc")]);
        let reader = DarReader::open(Cursor::new(archive)).expect("open failed");
        let entries = reader.entries();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].path, "a.bin");
        assert_eq!(entries[1].path, "b.bin");
        assert_eq!(entries[2].path, "c.bin");
    }

    #[test]
    fn extract_returns_correct_bytes() {
        let payload = b"forensic evidence content";
        let archive = make_dar(&[("evidence.bin", payload)]);
        let mut reader = DarReader::open(Cursor::new(archive)).expect("open failed");
        let extracted = reader.extract("evidence.bin").expect("extract failed");
        assert_eq!(extracted, payload);
    }

    #[test]
    fn bad_checksum_returns_err() {
        let mut archive = make_dar(&[("data.bin", b"original content")]);
        // Data starts at: 4(magic)+4(ver)+4(cnt) + 4(namelen)+8("data.bin")+8(datalen) = 32
        // Corrupt first byte of the actual payload; the CRC should then mismatch.
        archive[32] ^= 0xFF;
        let mut reader = DarReader::open(Cursor::new(archive)).expect("open failed");
        let result = reader.extract("data.bin");
        assert!(matches!(result, Err(DarError::BadChecksum { .. })));
    }

    #[test]
    fn extract_not_found_returns_err() {
        let archive = make_dar(&[("present.txt", b"here")]);
        let mut reader = DarReader::open(Cursor::new(archive)).expect("open failed");
        let result = reader.extract("missing.txt");
        assert!(matches!(result, Err(DarError::EntryNotFound(_))));
    }

    #[test]
    fn extract_multiple_files_independently() {
        let archive = make_dar(&[("alpha.bin", b"ALPHA"), ("beta.bin", b"BETA DATA")]);
        let mut reader = DarReader::open(Cursor::new(archive)).expect("open failed");
        let alpha = reader.extract("alpha.bin").expect("extract alpha");
        let beta = reader.extract("beta.bin").expect("extract beta");
        assert_eq!(alpha, b"ALPHA");
        assert_eq!(beta, b"BETA DATA");
    }

    #[test]
    fn extract_nested_path() {
        let archive = make_dar(&[("subdir/file.bin", b"nested data")]);
        let mut reader = DarReader::open(Cursor::new(archive)).expect("open failed");
        let data = reader.extract("subdir/file.bin").expect("extract failed");
        assert_eq!(data, b"nested data");
    }
}
