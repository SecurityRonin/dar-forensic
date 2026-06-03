//! Synthetic-byte integration tests.
//!
//! Each test constructs a minimal DAR archive from raw bytes to exercise a
//! specific code path that real archive fixtures cannot reach.  No on-disk
//! files are required.

use dar::{DarError, DarReader};
use std::io::Cursor;

// ── helpers ───────────────────────────────────────────────────────────────────

fn inf(n: u32) -> [u8; 5] {
    let b = n.to_be_bytes();
    [0x80, b[0], b[1], b[2], b[3]]
}

fn inode_base(bit4: bool) -> Vec<u8> {
    let flags = if bit4 { 0x10u8 } else { 0x00 };
    let mut v = vec![flags];
    v.extend_from_slice(&[0x80, 0x00, 0x00, 0x00, 0x00]); // uid
    v.extend_from_slice(&[0x80, 0x00, 0x00, 0x00, 0x00]); // gid
    v.extend_from_slice(&[0x00, 0x00]); // perms
    for _ in 0..3 {
        v.push(b's'); // timestamp type
        v.extend_from_slice(&[0x80, 0x00, 0x00, 0x00, 0x00]); // seconds
    }
    if bit4 {
        v.extend_from_slice(&[0x80, 0x00, 0x00, 0x00, 0x00]); // nlink
        v.extend_from_slice(&[0x80, 0x00, 0x00, 0x00, 0x00]); // field9
    }
    v
}

/// Builds a valid 21-byte DAR header with TLV count = 0.
/// After this, `archive_origin` == 21.
fn header() -> Vec<u8> {
    let mut v = vec![0x00u8, 0x00, 0x00, 0x7b]; // magic
    v.extend_from_slice(&[0u8; 10]); // internal_name
    v.extend_from_slice(&[0x00, 0x00]); // flag + ext_char
    v.extend_from_slice(&inf(0)); // TLV count = 0
    v
}

/// Catalog escape + 10-byte label + NUL path.
fn catalog_open() -> Vec<u8> {
    let mut v = vec![0xAD, 0xFD, 0xEA, 0x77, 0x21, 0x43]; // seqt_catalogue
    v.extend_from_slice(&[0u8; 10]); // label
    v.push(0x00); // path NUL
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

/// Inode with 'n'-type (nanosecond-precision) timestamps.
///
/// Produces 46 bytes for bit4=false:
///   flags(1) + uid(5) + gid(5) + perms(2)
///   + [type('n') + sec(5) + ns(5)] × 3 = 13 + 33 = 46
fn inode_ns(bit4: bool) -> Vec<u8> {
    let flags = if bit4 { 0x10u8 } else { 0x00 };
    let mut v = vec![flags];
    v.extend_from_slice(&[0x80, 0x00, 0x00, 0x00, 0x00]); // uid
    v.extend_from_slice(&[0x80, 0x00, 0x00, 0x00, 0x00]); // gid
    v.extend_from_slice(&[0x00, 0x00]); // perms
    for _ in 0..3 {
        v.push(b'n'); // type 'n'
        v.extend_from_slice(&[0x80, 0x00, 0x00, 0x00, 0x00]); // seconds
        v.extend_from_slice(&[0x80, 0x00, 0x00, 0x00, 0x00]); // nanoseconds
    }
    if bit4 {
        v.extend_from_slice(&[0x80, 0x00, 0x00, 0x00, 0x00]); // nlink
        v.extend_from_slice(&[0x80, 0x00, 0x00, 0x00, 0x00]); // field9
    }
    v
}

/// A file catalog entry with nanosecond-precision timestamps (Passware Mobile format).
fn file_entry_ns(name: &str, enc: u8, comp: u8, archive_offset: u32, size: u32) -> Vec<u8> {
    let mut v = vec![0x06u8]; // cat_sig → 'f'
    v.extend_from_slice(name.as_bytes());
    v.push(0x00);
    v.extend(inode_ns(false));
    v.extend_from_slice(&inf(size));
    v.extend_from_slice(&inf(archive_offset));
    v.extend_from_slice(&inf(size));
    v.push(enc);
    v.push(comp);
    v.extend_from_slice(&inf(0)); // crc_size = 0
    v
}

/// A file catalog entry.
fn file_entry(name: &str, enc: u8, comp: u8, archive_offset: u32, size: u32) -> Vec<u8> {
    let mut v = vec![0x06u8]; // cat_sig → 'f'
    v.extend_from_slice(name.as_bytes());
    v.push(0x00);
    v.extend(inode_base(false));
    v.extend_from_slice(&inf(size)); // logical size
    v.extend_from_slice(&inf(archive_offset)); // archive_offset
    v.extend_from_slice(&inf(size)); // stored_size
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

// ── corrupt infinint preserves cause ─────────────────────────────────────────

/// A bad preamble byte (0x01 ≠ 0x80) in the TLV-count infinint field.
///
/// The error must identify the root cause ("preamble" or "infinint"), not be
/// relabelled as "truncated TLV block" which implies an I/O shortage rather
/// than a corrupt byte.
#[test]
fn corrupt_infinint_in_header_preserves_cause() {
    let mut buf = vec![0x00u8, 0x00, 0x00, 0x7b]; // magic
    buf.extend_from_slice(&[0u8; 10]); // label
    buf.extend_from_slice(&[0x00, 0x00]); // flag + ext_char
    buf.push(0x03); // invalid terminal — two bits set
    buf.extend_from_slice(&[0x00u8; 4]);

    let Err(err) = DarReader::open(Cursor::new(buf)) else {
        panic!("expected Err, got Ok");
    };
    assert!(
        matches!(&err, DarError::Corrupt(s) if s.contains("terminal") || s.contains("infinint")),
        "expected Corrupt mentioning terminal/infinint, got: {err}"
    );
}

// ── no catalog escape ─────────────────────────────────────────────────────────

#[test]
fn no_catalog_escape_returns_corrupt() {
    let mut buf = header();
    buf.extend_from_slice(&[0u8; 64]); // body with no seqt_catalogue escape
    assert!(matches!(
        DarReader::open(Cursor::new(buf)),
        Err(DarError::Corrupt(_))
    ));
}

// ── extract: encrypted ────────────────────────────────────────────────────────

#[test]
fn extract_encrypted_entry_returns_corrupt() {
    let dar = minimal_dar(vec![file_entry("secret.bin", 1, b'n', 0, 0)]);
    let mut r = DarReader::open(Cursor::new(dar)).expect("open");
    assert!(matches!(r.extract("secret.bin"), Err(DarError::Corrupt(_))));
}

// ── extract: compressed ───────────────────────────────────────────────────────

#[test]
fn extract_compressed_entry_returns_corrupt() {
    let dar = minimal_dar(vec![file_entry("data.lzo", 0, b'z', 0, 0)]);
    let mut r = DarReader::open(Cursor::new(dar)).expect("open");
    assert!(matches!(r.extract("data.lzo"), Err(DarError::Corrupt(_))));
}

// ── multiple files ────────────────────────────────────────────────────────────

#[test]
fn two_files_both_listed() {
    let dar = minimal_dar(vec![
        file_entry("a.txt", 0, b'n', 0, 0),
        file_entry("b.txt", 0, b'n', 0, 0),
    ]);
    let r = DarReader::open(Cursor::new(dar)).expect("open");
    let paths: Vec<_> = r.entries().into_iter().map(|e| e.path).collect();
    assert_eq!(paths, ["a.txt", "b.txt"]);
}

// ── nested directory path ─────────────────────────────────────────────────────

#[test]
fn nested_directory_path_is_correct() {
    // ROOT > sub/ > file.txt > EOD(sub) > EOD(ROOT)
    let mut buf = header();
    buf.extend(catalog_open());
    buf.extend(root_dir());
    buf.extend(subdir("sub"));
    buf.extend(file_entry("file.txt", 0, b'n', 0, 0));
    buf.push(EOD); // close sub
    buf.push(EOD); // close ROOT
    let r = DarReader::open(Cursor::new(buf)).expect("open");
    assert_eq!(r.entries()[0].path, "sub/file.txt");
}

// ── catalog: EOF without EOD ──────────────────────────────────────────────────

/// Archive whose catalog ends at EOF before the 'z' EOD entry.
///
/// `parse_catalog` must break cleanly on `Err(_)` from `read_exact` rather
/// than returning an error — partial catalogs are valid output.
#[test]
fn catalog_eof_without_eod_returns_entries() {
    let mut buf = header();
    buf.extend(catalog_open());
    buf.extend(root_dir());
    buf.extend(file_entry("lone.txt", 0, b'n', 0, 0));
    // deliberately omit the EOD byte
    let r = DarReader::open(Cursor::new(buf)).expect("open");
    let paths: Vec<_> = r.entries().into_iter().map(|e| e.path).collect();
    assert_eq!(paths, ["lone.txt"]);
}

// ── catalog: unknown entry type ────────────────────────────────────────────────

/// An unrecognised cat_sig type must terminate parsing without error,
/// returning whatever entries were collected before it.
#[test]
fn catalog_unknown_entry_type_stops_parsing() {
    let mut buf = header();
    buf.extend(catalog_open());
    buf.extend(root_dir());
    buf.extend(file_entry("before.txt", 0, b'n', 0, 0));
    buf.push(0x01); // cat_sig → 'a' (0x61), unknown type
    buf.push(EOD); // never reached
    let r = DarReader::open(Cursor::new(buf)).expect("open");
    let paths: Vec<_> = r.entries().into_iter().map(|e| e.path).collect();
    assert_eq!(paths, ["before.txt"]);
}

// ── catalog: invalid UTF-8 filename ───────────────────────────────────────────

/// A file entry whose name contains invalid UTF-8 must cause `open` to fail
/// with `DarError::Corrupt`, not a panic or silent data loss.
#[test]
fn catalog_invalid_utf8_filename_returns_corrupt() {
    let mut buf = header();
    buf.extend(catalog_open());
    buf.extend(root_dir());
    // Manually build a file entry with a non-UTF8 name: [0xFF, 0x80, NUL]
    buf.push(0x06); // cat_sig 'f'
    buf.extend_from_slice(&[0xFF, 0x80, 0x00]); // invalid UTF-8 name + NUL
    buf.extend(inode_base(false));
    buf.extend_from_slice(&inf(0)); // size
    buf.extend_from_slice(&inf(0)); // archive_offset
    buf.extend_from_slice(&inf(0)); // stored_size
    buf.push(0x00); // enc
    buf.push(b'n'); // comp
    buf.extend_from_slice(&inf(0)); // crc_size
    buf.push(EOD);
    assert!(matches!(
        DarReader::open(Cursor::new(buf)),
        Err(DarError::Corrupt(_))
    ));
}

// ── catalog: label-only marker (no seqt_catalogue escape) ─────────────────────

/// A DAR archive whose catalog begins with the 10-byte archive label and has no
/// seqt_catalogue escape sequence.  The parser must fall back to a label scan.
///
/// This is the format produced by Passware Mobile.
#[test]
fn catalog_without_escape_lists_entries() {
    const LABEL: [u8; 10] = [0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18, 0x29, 0x3A];

    let mut buf = vec![0x00u8, 0x00, 0x00, 0x7b]; // magic
    buf.extend_from_slice(&LABEL); // internal_name
    buf.extend_from_slice(&[0x00, 0x00]); // flag + ext_char
    buf.extend_from_slice(&inf(0)); // TLV count = 0 → archive_origin = 21

    // File data — use non-zero bytes so the label won't false-match in the body.
    buf.extend_from_slice(b"FFFFFFFFFFFFFFFF"); // 16 distinct bytes

    // Catalog header: label only, no escape, no path NUL.
    buf.extend_from_slice(&LABEL);
    buf.extend(root_dir());
    buf.extend(file_entry("a.txt", 0, b'n', 0, 16));
    buf.push(EOD);

    let r = DarReader::open(Cursor::new(buf)).expect("open with label-only catalog");
    let paths: Vec<_> = r.entries().into_iter().map(|e| e.path).collect();
    assert_eq!(paths, ["a.txt"]);
}

/// Same setup as above but also verifies `extract()` can seek back to the
/// file data using the catalog's archive_offset.
#[test]
fn catalog_without_escape_extracts_correctly() {
    const LABEL: [u8; 10] = [0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18, 0x29, 0x3A];

    let mut buf = vec![0x00u8, 0x00, 0x00, 0x7b];
    buf.extend_from_slice(&LABEL);
    buf.extend_from_slice(&[0x00, 0x00]);
    buf.extend_from_slice(&inf(0)); // archive_origin = 21

    buf.extend_from_slice(b"HELLOWORLD"); // 10 bytes of payload at archive_origin

    // Catalog: label only marker.
    buf.extend_from_slice(&LABEL);
    buf.extend(root_dir());
    buf.extend(file_entry("f.bin", 0, b'n', 0, 10));
    buf.push(EOD);

    let mut r = DarReader::open(Cursor::new(buf)).expect("open");
    assert_eq!(r.extract("f.bin").expect("extract"), b"HELLOWORLD");
}

// ── extract correct bytes ─────────────────────────────────────────────────────

/// Verifies archive_origin + archive_offset arithmetic end-to-end.
///
/// Layout: header(21) | payload(4) | catalog_escape | … | file entry
/// archive_origin = 21; archive_offset = 0; stored_size = 4
/// → extract must seek to byte 21 and read exactly b"test"
#[test]
fn extract_returns_correct_bytes() {
    const PAYLOAD: &[u8] = b"test";

    let mut buf = header(); // 21 bytes; archive_origin = 21
    buf.extend_from_slice(PAYLOAD); // bytes 21-24
    buf.extend(catalog_open()); // escape at byte 25
    buf.extend(root_dir());
    buf.extend(file_entry("out.bin", 0, b'n', 0, PAYLOAD.len() as u32));
    buf.push(EOD);

    let mut r = DarReader::open(Cursor::new(buf)).expect("open");
    assert_eq!(r.extract("out.bin").expect("extract"), PAYLOAD);
}

// ── nanosecond-precision ('n') timestamps ─────────────────────────────────────

/// File entries using 'n'-type (nanosecond-precision) timestamps must be listed.
///
/// This is the inode format used by Passware Mobile DAR archives.  The inode
/// is 46 bytes (not 31), because each of the three timestamps stores both
/// seconds and nanoseconds as separate infinints after the type byte.
#[test]
fn nanosecond_timestamp_inode_lists_entry() {
    let dar = minimal_dar(vec![file_entry_ns("hi.bin", 0, b'n', 0, 0)]);
    let r = DarReader::open(Cursor::new(dar)).expect("open");
    assert_eq!(r.entries().len(), 1);
    assert_eq!(r.entries()[0].path, "hi.bin");
}

/// Same as above, but also verifies that extract() seeks to the correct offset.
///
/// If the inode is mis-parsed (too few bytes consumed), archive_offset is read
/// from the wrong position and extract() returns garbage or panics.
#[test]
fn nanosecond_timestamp_inode_extracts_correctly() {
    const PAYLOAD: &[u8] = b"ns_payload";

    let mut buf = header();
    buf.extend_from_slice(PAYLOAD); // at archive_origin (byte 21)
    buf.extend(catalog_open());
    buf.extend(root_dir());
    buf.extend(file_entry_ns("p.bin", 0, b'n', 0, PAYLOAD.len() as u32));
    buf.push(EOD);

    let mut r = DarReader::open(Cursor::new(buf)).expect("open");
    assert_eq!(r.extract("p.bin").expect("extract"), PAYLOAD);
}

// ── symlink entries ───────────────────────────────────────────────────────────

/// A symlink catalog entry (cat_sig → 'l').
fn symlink_entry(name: &str, target: &str) -> Vec<u8> {
    let mut v = vec![0x0cu8]; // cat_sig → 'l'
    v.extend_from_slice(name.as_bytes());
    v.push(0x00);
    v.extend(inode_base(false));
    v.extend_from_slice(target.as_bytes());
    v.push(0x00);
    v
}

// ── catalog: no NUL path after seqt_catalogue (format 9 style) ───────────────

/// seqt_catalogue + label, but no NUL-terminated path before entries.
///
/// DAR format 9 archives omit the working-directory path field from the
/// catalog header.  Format 11 uses an empty NUL-terminated path `"\0"`.
fn catalog_open_no_path() -> Vec<u8> {
    let mut v = vec![0xAD, 0xFD, 0xEA, 0x77, 0x21, 0x43]; // seqt_catalogue
    v.extend_from_slice(&[0u8; 10]); // label (no path NUL follows)
    v
}

/// A DAR archive whose catalog header has no NUL path (format 9 style) must
/// still list its entries correctly.
#[test]
fn catalog_without_nul_path_lists_entries() {
    let mut buf = header();
    // Format-9 version string (each byte = value+48): '0'=0×256, '9'=9, '0'=fix 0
    buf.extend_from_slice(b"090\x00");
    buf.extend(catalog_open_no_path());
    buf.extend(root_dir());
    buf.extend(file_entry("f9.txt", 0, b'n', 0, 0));
    buf.push(EOD);
    let r = DarReader::open(Cursor::new(buf)).expect("open");
    assert_eq!(r.entries().len(), 1);
    assert_eq!(r.entries()[0].path, "f9.txt");
}

// ── large infinint timestamps (0x40 encoding) ────────────────────────────────

/// Inode where ctime uses a 0x40-encoded 8-byte infinint for the seconds value.
///
/// This is the real-world encoding seen in Passware Mobile archives when the
/// timestamp epoch value exceeds 32 bits and DAR chooses the next-larger
/// infinint group (0x40 terminal → 8 data bytes instead of the usual 4).
fn inode_large_ctime_ts() -> Vec<u8> {
    let mut v = vec![0x00u8]; // flags (bit4=0)
    v.extend_from_slice(&[0x80, 0x00, 0x00, 0x00, 0x00]); // uid = 0
    v.extend_from_slice(&[0x80, 0x00, 0x00, 0x00, 0x00]); // gid = 0
    v.extend_from_slice(&[0x00, 0x00]); // perms = 0
                                        // ctime: 'n' type, seconds via 0x40 (8 bytes), nanoseconds via 0x80 (4 bytes)
    v.push(b'n');
    v.push(0x40);
    v.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x5d, 0x15, 0x93, 0x31]); // seconds
    v.extend_from_slice(&[0x80, 0x00, 0x00, 0x00, 0x00]); // nanoseconds
                                                          // mtime: 's' type, seconds via 0x80
    v.push(b's');
    v.extend_from_slice(&[0x80, 0x00, 0x00, 0x00, 0x00]);
    // atime: 's' type
    v.push(b's');
    v.extend_from_slice(&[0x80, 0x00, 0x00, 0x00, 0x00]);
    v
}

fn file_entry_large_ts(name: &str) -> Vec<u8> {
    let mut v = vec![0x06u8]; // cat_sig → 'f'
    v.extend_from_slice(name.as_bytes());
    v.push(0x00);
    v.extend(inode_large_ctime_ts());
    v.extend_from_slice(&inf(0)); // data_size
    v.extend_from_slice(&inf(0)); // archive_offset
    v.extend_from_slice(&inf(0)); // stored_size
    v.push(0x00); // enc = none
    v.push(b'n'); // comp = none
    v.extend_from_slice(&inf(0)); // crc_size = 0
    v
}

/// A file entry whose ctime seconds field uses the 0x40 infinint preamble
/// (8 data bytes) must be listed without error.
///
/// This matches the Passware Mobile format where large epoch timestamps require
/// more than 4 bytes, triggering the next infinint encoding group.
#[test]
fn file_with_large_timestamp_infinint_is_parseable() {
    let dar = minimal_dar(vec![file_entry_large_ts("big_ts.bin")]);
    let r = DarReader::open(Cursor::new(dar)).expect("open");
    assert_eq!(r.entries().len(), 1);
    assert_eq!(r.entries()[0].path, "big_ts.bin");
}

/// A symlink between two regular files must not stop catalog parsing.
///
/// Symlinks are leaf nodes (not extractable) so they must be silently skipped
/// while parsing continues to the entries that follow.
#[test]
fn symlink_entry_does_not_stop_parsing() {
    let dar = minimal_dar(vec![
        file_entry("before.txt", 0, b'n', 0, 0),
        symlink_entry("link.txt", "/etc/target"),
        file_entry("after.txt", 0, b'n', 0, 0),
    ]);
    let r = DarReader::open(Cursor::new(dar)).expect("open");
    let paths: Vec<_> = r.entries().into_iter().map(|e| e.path).collect();
    assert_eq!(paths, ["before.txt", "after.txt"]);
}

// ── hardening: malicious / corrupted catalog fields ──────────────────────────
//
// Every length and offset in a catalog entry is attacker-controlled: a forensic
// tool must treat a `.dar` as hostile input.  These tests feed deliberately
// malicious entries and require a graceful `Err`, never a panic, a backward
// seek, or an out-of-memory abort.

/// Encode a `u64` as an 8-byte (`0x40`-terminal) infinint — the widest value
/// that still fits the reader's 64-bit contract.
fn inf64(n: u64) -> Vec<u8> {
    let mut v = vec![0x40u8];
    v.extend_from_slice(&n.to_be_bytes());
    v
}

/// A file entry with caller-controlled 64-bit `archive_offset` and
/// `stored_size`, for exercising extraction bounds checks.  Logical size,
/// encryption, compression and CRC are all benign so `open()` succeeds and the
/// entry is listed; only the extraction-path fields are weaponised.
fn file_entry_raw_sizes(name: &str, archive_offset: u64, stored_size: u64) -> Vec<u8> {
    let mut v = vec![0x06u8]; // cat_sig → 'f'
    v.extend_from_slice(name.as_bytes());
    v.push(0x00);
    v.extend(inode_base(false));
    v.extend_from_slice(&inf(0)); // logical size = 0
    v.extend(inf64(archive_offset)); // archive_offset (64-bit)
    v.extend(inf64(stored_size)); // stored_size (64-bit)
    v.push(0x00); // encryption = none
    v.push(b'n'); // compression = none
    v.extend_from_slice(&inf(0)); // crc_size = 0
    v
}

/// `archive_origin + archive_offset` must not overflow-panic; an offset of
/// `u64::MAX` must be rejected as corrupt.
#[test]
fn extract_archive_offset_overflow_returns_corrupt() {
    let mut buf = header();
    buf.extend(catalog_open());
    buf.extend(root_dir());
    buf.extend(file_entry_raw_sizes("evil.bin", u64::MAX, 0));
    buf.push(EOD);

    let mut r = DarReader::open(Cursor::new(buf)).expect("open");
    let err = r.extract("evil.bin").unwrap_err();
    assert!(matches!(err, DarError::Corrupt(_)), "got {err:?}");
}

/// A `stored_size` larger than the bytes actually present must be rejected as
/// corrupt — not surface as an I/O short-read after a needless allocation.
#[test]
fn extract_stored_size_beyond_archive_returns_corrupt() {
    let mut buf = header();
    buf.extend(catalog_open());
    buf.extend(root_dir());
    // Valid offset, but claims 1 MiB of stored bytes that do not exist.
    buf.extend(file_entry_raw_sizes("toobig.bin", 0, 1 << 20));
    buf.push(EOD);

    let mut r = DarReader::open(Cursor::new(buf)).expect("open");
    let err = r.extract("toobig.bin").unwrap_err();
    assert!(matches!(err, DarError::Corrupt(_)), "got {err:?}");
}

/// A `stored_size` of `u64::MAX` must be rejected *before* allocating — the
/// classic decompression/extraction bomb.  Without a bounds check the
/// `vec![0u8; stored_size]` request aborts the process; with one it returns
/// `Corrupt` having allocated nothing.
#[test]
fn extract_gigantic_stored_size_does_not_allocate() {
    let mut buf = header();
    buf.extend(catalog_open());
    buf.extend(root_dir());
    buf.extend(file_entry_raw_sizes("bomb.bin", 0, u64::MAX));
    buf.push(EOD);

    let mut r = DarReader::open(Cursor::new(buf)).expect("open");
    let err = r.extract("bomb.bin").unwrap_err();
    assert!(matches!(err, DarError::Corrupt(_)), "got {err:?}");
}
