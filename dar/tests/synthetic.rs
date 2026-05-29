//! Synthetic-byte integration tests.
//!
//! Each test constructs a minimal DAR archive from raw bytes to exercise a
//! specific code path that real archive fixtures cannot reach.  No on-disk
//! files are required.

use std::io::Cursor;
use dar::{DarError, DarReader};

// ── helpers ───────────────────────────────────────────────────────────────────

fn inf(n: u32) -> [u8; 5] {
    let b = n.to_be_bytes();
    [0x80, b[0], b[1], b[2], b[3]]
}

fn inode_base(bit4: bool) -> Vec<u8> {
    let flags = if bit4 { 0x10u8 } else { 0x00 };
    let mut v = vec![flags];
    v.extend_from_slice(&[0u8; 30]);
    if bit4 {
        v.extend_from_slice(&[0u8; 10]); // nlink + field9
    }
    v
}

/// Builds a valid 21-byte DAR header with TLV count = 0.
/// After this, `archive_origin` == 21.
fn header() -> Vec<u8> {
    let mut v = vec![0x00u8, 0x00, 0x00, 0x7b]; // magic
    v.extend_from_slice(&[0u8; 10]);              // internal_name
    v.extend_from_slice(&[0x00, 0x00]);           // flag + ext_char
    v.extend_from_slice(&inf(0));                 // TLV count = 0
    v
}

/// Catalog escape + 10-byte label + NUL path.
fn catalog_open() -> Vec<u8> {
    let mut v = vec![0xAD, 0xFD, 0xEA, 0x77, 0x21, 0x43]; // seqt_catalogue
    v.extend_from_slice(&[0u8; 10]);                        // label
    v.push(0x00);                                           // path NUL
    v
}

/// A `<ROOT>` directory entry (no FSA).
fn root_dir() -> Vec<u8> {
    let mut v = vec![0x04u8]; // cat_sig → 'd'
    v.extend_from_slice(b"<ROOT>\x00");
    v.extend(inode_base(false));
    v
}

/// A named directory entry (no FSA).
fn subdir(name: &str) -> Vec<u8> {
    let mut v = vec![0x04u8];
    v.extend_from_slice(name.as_bytes());
    v.push(0x00);
    v.extend(inode_base(false));
    v
}

/// A file catalog entry.
fn file_entry(name: &str, enc: u8, comp: u8, archive_offset: u32, size: u32) -> Vec<u8> {
    let mut v = vec![0x06u8]; // cat_sig → 'f'
    v.extend_from_slice(name.as_bytes());
    v.push(0x00);
    v.extend(inode_base(false));
    v.extend_from_slice(&inf(size));           // logical size
    v.extend_from_slice(&inf(archive_offset)); // archive_offset
    v.extend_from_slice(&inf(size));           // stored_size
    v.push(enc);
    v.push(comp);
    v.extend_from_slice(&inf(0)); // crc_size = 0
    v
}

const EOD: u8 = 0x1a; // cat_sig → 'z'

/// Minimal archive: header → catalog immediately at archive_origin → ROOT →
/// file entries → EOD.  File data is not embedded; use for tests that don't
/// call extract().
fn minimal_dar(files: Vec<Vec<u8>>) -> Vec<u8> {
    let mut v = header();
    v.extend(catalog_open());
    v.extend(root_dir());
    for f in files {
        v.extend(f);
    }
    v.push(EOD);
    v
}

// ── RED test: corrupt infinint preserves cause ────────────────────────────────

/// A bad preamble byte (0x01 ≠ 0x80) in the TLV-count infinint field.
///
/// The error must identify the root cause ("preamble" or "infinint"), not be
/// relabelled as "truncated TLV block" which implies an I/O shortage rather
/// than a corrupt byte.
#[test]
fn corrupt_infinint_in_header_preserves_cause() {
    let mut buf = vec![0x00u8, 0x00, 0x00, 0x7b]; // magic
    buf.extend_from_slice(&[0u8; 10]);              // label
    buf.extend_from_slice(&[0x00, 0x00]);           // flag + ext_char
    buf.push(0x01);                                 // bad preamble — not 0x80
    buf.extend_from_slice(&[0x00u8; 4]);

    let err = match DarReader::open(Cursor::new(buf)) {
        Err(e) => e,
        Ok(_) => panic!("expected Err, got Ok"),
    };
    assert!(
        matches!(&err, DarError::Corrupt(s) if s.contains("preamble") || s.contains("infinint")),
        "expected Corrupt mentioning preamble/infinint, got: {err}"
    );
}
