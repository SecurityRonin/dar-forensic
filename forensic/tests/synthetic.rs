//! Synthetic-byte integration tests.
//!
//! Each test constructs a minimal DAR archive from raw bytes to exercise a
//! specific code path that real archive fixtures cannot reach.  No on-disk
//! files are required.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use dar_forensic::{
    Anomaly, AnomalyKind, CrcStatus, DarAudit, DarBodyfile, DarEntry, DarError, DarReader,
    EntryKind, Severity,
};
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
    v.extend_from_slice(&[0x00, b'T']); // flag + extension ('T' = TLV / format 8+)
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
    buf.extend_from_slice(&[0x00, b'T']); // flag + extension ('T' = TLV / format 8+)
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

#[test]
fn extract_compressed_size_mismatch_returns_corrupt() {
    // A real zlib stream of b"hello" (decodes to 5 bytes) embedded at
    // archive_origin, but the catalog declares size = 10. extract() must reject
    // the mismatch rather than return a short buffer.
    const ZLIB_HELLO: [u8; 13] = [
        0x78, 0xda, 0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00, 0x06, 0x2c, 0x02, 0x15,
    ];
    let mut buf = header(); // archive_origin = 21
    buf.extend_from_slice(&ZLIB_HELLO); // file data at offset 0
    buf.extend(catalog_open());
    buf.extend(root_dir());
    // file entry: gzip ('z'), archive_offset 0, stored_size 13, declared size 10.
    let mut entry = vec![0x06u8]; // cat_sig → 'f'
    entry.extend_from_slice(b"z.bin\x00");
    entry.extend(inode_base(false));
    entry.extend_from_slice(&inf(10)); // logical size (wrong on purpose)
    entry.extend_from_slice(&inf(0)); // archive_offset
    entry.extend_from_slice(&inf(ZLIB_HELLO.len() as u32)); // stored_size
    entry.push(0x00); // not encrypted
    entry.push(b'z'); // gzip
    entry.extend_from_slice(&inf(0)); // crc_size
    buf.extend(entry);
    buf.push(EOD);

    let mut r = DarReader::open(Cursor::new(buf)).expect("open");
    let err = r.extract("z.bin").expect_err("size mismatch must error");
    assert!(matches!(&err, DarError::Corrupt(s) if s.contains("declares")));
}

#[test]
fn format_10_compressed_catalogue_lists_entries() {
    use flate2::{write::ZlibEncoder, Compression};
    use std::io::Write;

    // A format-10 ("0:0") archive whose catalogue is gzip-compressed. Unlike the
    // 11.3 fixtures this exercises the pre-11.1 branch (no in-place path after
    // the catalog label) of the compressed-catalogue path.
    const LBL: [u8; 10] = [0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA];

    let mut cat = Vec::new();
    cat.extend_from_slice(&LBL); // in-catalog label
    cat.extend(root_dir());
    cat.extend(file_entry("c.txt", 0, b'n', 0, 5));
    cat.push(EOD);
    let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
    enc.write_all(&cat).unwrap();
    let zcat = enc.finish().unwrap();

    let mut buf = vec![0x00u8, 0x00, 0x00, 0x7b]; // magic
    buf.extend_from_slice(&LBL); // internal_name
    buf.extend_from_slice(&[0x00, b'T']); // flag + TLV extension
    buf.extend_from_slice(&inf(0)); // TLV count 0 → archive_origin
    buf.extend_from_slice(b"0:0\x00"); // version string → format 10
    buf.push(b'z'); // global compression = gzip
    buf.extend_from_slice(&[0xAD, 0xFD, 0xEA, 0x77, 0x21, 0x43]); // seqt_catalogue
    buf.extend_from_slice(&zcat); // compressed catalogue

    let r = DarReader::open(Cursor::new(buf)).expect("open format-10 compressed");
    let paths: Vec<_> = r
        .entries()
        .into_iter()
        .map(|e| e.path_lossy().into_owned())
        .collect();
    assert_eq!(paths, ["c.txt"]);
}

// ── multiple files ────────────────────────────────────────────────────────────

#[test]
fn two_files_both_listed() {
    let dar = minimal_dar(vec![
        file_entry("a.txt", 0, b'n', 0, 0),
        file_entry("b.txt", 0, b'n', 0, 0),
    ]);
    let r = DarReader::open(Cursor::new(dar)).expect("open");
    let paths: Vec<_> = r
        .entries()
        .into_iter()
        .map(|e| e.path_lossy().into_owned())
        .collect();
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
    let entries = r.entries();
    let paths: Vec<_> = entries
        .iter()
        .map(|e| e.path_lossy().into_owned())
        .collect();
    assert_eq!(paths, ["sub", "sub/file.txt"]);
    assert_eq!(entries[0].kind, EntryKind::Directory);
    assert_eq!(entries[1].kind, EntryKind::File);
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
    let paths: Vec<_> = r
        .entries()
        .into_iter()
        .map(|e| e.path_lossy().into_owned())
        .collect();
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
    let paths: Vec<_> = r
        .entries()
        .into_iter()
        .map(|e| e.path_lossy().into_owned())
        .collect();
    assert_eq!(paths, ["before.txt"]);
}

// ── catalog: invalid UTF-8 filename ───────────────────────────────────────────

/// A file entry whose name is not valid UTF-8 must be preserved byte-for-byte,
/// NOT rejected — forensic filenames are arbitrary bytes.
#[test]
fn catalog_non_utf8_filename_is_preserved() {
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
    buf.push(0x00); // file_data_status
    buf.push(b'n'); // comp
    buf.extend_from_slice(&inf(0)); // crc_size
    buf.push(EOD);
    let r = DarReader::open(Cursor::new(buf)).expect("non-UTF-8 name must not fail open");
    let entries = r.entries();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].path, vec![0xFF, 0x80]);
    assert_eq!(entries[0].path_lossy(), "\u{FFFD}\u{FFFD}");
}

// ── catalog: label-only marker (no seqt_catalogue escape) ─────────────────────

/// A DAR archive written with tape marks disabled (`dar -at`, as Passware Kit
/// Mobile does): no `seqt_catalogue` escape, so the catalog is located by its
/// `ref_data_name` label (= the slice label) instead. Standard DAR, not a
/// variant — the escape is an optional sequential-read tape mark.
#[test]
fn catalog_without_escape_lists_entries() {
    const LABEL: [u8; 10] = [0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18, 0x29, 0x3A];

    let mut buf = vec![0x00u8, 0x00, 0x00, 0x7b]; // magic
    buf.extend_from_slice(&LABEL); // internal_name
    buf.extend_from_slice(&[0x00, b'T']); // flag + extension ('T' = TLV / format 8+)
    buf.extend_from_slice(&inf(0)); // TLV count = 0 → archive_origin = 21

    // File data — use non-zero bytes so the label won't false-match in the body.
    buf.extend_from_slice(b"FFFFFFFFFFFFFFFF"); // 16 distinct bytes

    // Catalog: label + empty in-place path (format 11.1+), no escape.
    buf.extend_from_slice(&LABEL);
    buf.push(0x00); // empty in-place path NUL-string (format 11.1+, as real dar writes)
    buf.extend(root_dir());
    buf.extend(file_entry("a.txt", 0, b'n', 0, 16));
    buf.push(EOD);

    let r = DarReader::open(Cursor::new(buf)).expect("open with label-only catalog");
    let paths: Vec<_> = r
        .entries()
        .into_iter()
        .map(|e| e.path_lossy().into_owned())
        .collect();
    assert_eq!(paths, ["a.txt"]);
}

/// Same setup as above but also verifies `extract()` can seek back to the
/// file data using the catalog's archive_offset.
#[test]
fn catalog_without_escape_extracts_correctly() {
    const LABEL: [u8; 10] = [0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18, 0x29, 0x3A];

    let mut buf = vec![0x00u8, 0x00, 0x00, 0x7b];
    buf.extend_from_slice(&LABEL);
    buf.extend_from_slice(&[0x00, b'T']); // flag + extension ('T' = TLV / format 8+)
    buf.extend_from_slice(&inf(0)); // archive_origin = 21

    buf.extend_from_slice(b"HELLOWORLD"); // 10 bytes of payload at archive_origin

    // Catalog: label + empty in-place path (format 11.1+).
    buf.extend_from_slice(&LABEL);
    buf.push(0x00); // empty in-place path NUL-string (format 11.1+, as real dar writes)
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
    assert_eq!(r.entries()[0].path_lossy(), "hi.bin");
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
    assert_eq!(r.entries()[0].path_lossy(), "f9.txt");
}

/// Format 10 (and 11.0) also have NO in-place path in the catalog header — per
/// libdar that field begins only at archive format 11.1 (`catalogue.cpp:157`,
/// gate `>= archive_version(11,1)`).  A reader that skips a path for any
/// `format >= 10` consumes the first entry's bytes and mis-parses.
#[test]
fn catalog_format_10_has_no_inplace_path() {
    let mut buf = header();
    // Format-10 version string: ':' = 58 = 10 + 48 → major 10, fix 0.
    buf.extend_from_slice(b"0:0\x00");
    buf.extend(catalog_open_no_path());
    buf.extend(root_dir());
    buf.extend(file_entry("f10.txt", 0, b'n', 0, 0));
    buf.push(EOD);
    let r = DarReader::open(Cursor::new(buf)).expect("open");
    assert_eq!(r.entries().len(), 1);
    assert_eq!(r.entries()[0].path_lossy(), "f10.txt");
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
    assert_eq!(r.entries()[0].path_lossy(), "big_ts.bin");
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
    let entries = r.entries();
    let paths: Vec<_> = entries
        .iter()
        .map(|e| e.path_lossy().into_owned())
        .collect();
    assert_eq!(paths, ["before.txt", "link.txt", "after.txt"]);
    assert_eq!(entries[1].kind, EntryKind::Symlink);
    assert_eq!(
        entries[1].symlink_target.as_deref(),
        Some(&b"/etc/target"[..])
    );
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

/// The compressed extraction path enforces the same stored-bytes bounds check as
/// the stored path: a codec entry claiming more on-disk bytes than the archive
/// holds is rejected as corrupt before any decode is attempted.
#[test]
fn extract_compressed_stored_size_beyond_archive_returns_corrupt() {
    let mut buf = header();
    buf.extend(catalog_open());
    buf.extend(root_dir());
    // comp='z' (gzip) but claims 1 MiB of stored bytes that do not exist.
    let mut entry = vec![0x06u8]; // cat_sig → 'f'
    entry.extend_from_slice(b"toobig.z");
    entry.push(0x00);
    entry.extend(inode_base(false));
    entry.extend_from_slice(&inf(0)); // logical size = 0
    entry.extend(inf64(0)); // archive_offset
    entry.extend(inf64(1 << 20)); // stored_size = 1 MiB (absent)
    entry.push(0x00); // encryption = none
    entry.push(b'z'); // compression = gzip
    entry.extend_from_slice(&inf(0)); // crc_size = 0
    buf.extend(entry);
    buf.push(EOD);

    let mut r = DarReader::open(Cursor::new(buf)).expect("open");
    let err = r.extract("toobig.z").unwrap_err();
    assert!(matches!(err, DarError::Corrupt(_)), "got {err:?}");
}

/// A failing output writer must surface as an error, never be silently
/// swallowed: the stored-path `io::copy` result is propagated to the caller.
#[test]
fn extract_to_stored_propagates_writer_error() {
    struct FailingWriter;
    impl std::io::Write for FailingWriter {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("sink is full"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    const PAYLOAD: &[u8] = b"test";
    let mut buf = header();
    buf.extend_from_slice(PAYLOAD);
    buf.extend(catalog_open());
    buf.extend(root_dir());
    buf.extend(file_entry("out.bin", 0, b'n', 0, PAYLOAD.len() as u32));
    buf.push(EOD);

    let mut r = DarReader::open(Cursor::new(buf)).expect("open");
    let err = r.extract_to("out.bin", &mut FailingWriter).unwrap_err();
    assert!(matches!(err, DarError::Io(_)), "got {err:?}");
}

// ── slice-header extension branches ──────────────────────────────────────────

/// A format-8+ header ('T' extension) truncated before the TLV count must map
/// the I/O shortage to a clear "truncated TLV block" Corrupt error.
#[test]
fn truncated_tlv_block_returns_corrupt() {
    let mut buf = vec![0x00u8, 0x00, 0x00, 0x7b]; // magic
    buf.extend_from_slice(&[0u8; 10]); // label
    buf.push(0x00); // flag
    buf.push(b'T'); // extension = TLV — but no TLV count byte follows
    let Err(err) = DarReader::open(Cursor::new(buf)) else {
        panic!("expected Err, got Ok");
    };
    assert!(matches!(&err, DarError::Corrupt(s) if s.contains("truncated TLV")));
}

/// An unrecognised slice-header extension byte must be rejected as corrupt.
#[test]
fn unknown_extension_returns_corrupt() {
    let mut buf = vec![0x00u8, 0x00, 0x00, 0x7b];
    buf.extend_from_slice(&[0u8; 10]);
    buf.push(0x00); // flag
    buf.push(0x00); // extension — not 'T'/'N'/'S'
    let Err(err) = DarReader::open(Cursor::new(buf)) else {
        panic!("expected Err, got Ok");
    };
    assert!(matches!(&err, DarError::Corrupt(s) if s.contains("unknown slice-header extension")));
}

/// The 'S' (size) extension stores a slice-size infinint before the data layer;
/// a reader must consume it (then locate the catalog via the terminateur).
#[test]
fn size_extension_consumes_slice_size() {
    let mut buf = vec![0x00u8, 0x00, 0x00, 0x7b];
    buf.extend_from_slice(&[0u8; 10]);
    buf.push(0x00); // flag
    buf.push(b'S'); // extension = size
    buf.extend_from_slice(&inf(0)); // slice-size infinint (consumed)
    buf.extend_from_slice(b"07\x00"); // archive_version (format 7)
                                      // No valid terminateur follows → open fails, but the slice-size path ran.
    let Err(err) = DarReader::open(Cursor::new(buf)) else {
        panic!("expected Err, got Ok");
    };
    assert!(matches!(err, DarError::Corrupt(_)), "got {err:?}");
}

/// A pre-8 ('N') archive whose terminateur points beyond the archive end must be
/// rejected, not seek out of bounds.
#[test]
fn legacy_catalogue_past_end_returns_corrupt() {
    let mut buf = vec![0x00u8, 0x00, 0x00, 0x7b];
    buf.extend_from_slice(&[0u8; 10]);
    buf.push(0x00); // flag
    buf.push(b'N'); // extension = none (legacy)
    buf.extend_from_slice(b"07\x00"); // archive_version (format 7)
                                      // terminateur: pos infinint = 10_000 (far past EOF) + "00 00 00 c0" marker
                                      // (two leading 1-bits → 2*4 = 8 bytes back to the 5-byte infinint).
    buf.extend_from_slice(&inf(10_000));
    buf.extend_from_slice(&[0x00, 0x00, 0x00, 0xc0]);
    let Err(err) = DarReader::open(Cursor::new(buf)) else {
        panic!("expected Err, got Ok");
    };
    assert!(matches!(&err, DarError::Corrupt(s) if s.contains("past archive end")));
}

// ── extract: offset beyond archive end (no overflow) ─────────────────────────

/// An archive_offset that lands past EOF (without overflowing) must be rejected.
#[test]
fn extract_offset_past_archive_end_returns_corrupt() {
    let dar = minimal_dar(vec![file_entry("x.bin", 0, b'n', 100_000, 0)]);
    let mut r = DarReader::open(Cursor::new(dar)).expect("open");
    let err = r.extract("x.bin").unwrap_err();
    assert!(matches!(&err, DarError::Corrupt(s) if s.contains("past archive end")));
}

// ── FSA block is skipped (format 9+ inode with the FSA-full bit) ─────────────

/// A file entry with the inode FSA-full bit (0x10) set, followed by an FSA
/// block (family tag + size + data), must be parsed by skipping the block.
#[test]
fn entry_with_fsa_block_is_listed() {
    let mut entry = vec![0x06u8]; // 'f'
    entry.extend_from_slice(b"fsa.txt\x00");
    entry.extend(inode_base(true)); // flags 0x10 + the two FSA inode infinints
    entry.extend_from_slice(&inf(264)); // FSA family tag
    entry.extend_from_slice(&inf(2)); // FSA data size
    entry.extend_from_slice(&[0xAA, 0xBB]); // FSA data
    entry.extend_from_slice(&inf(0)); // size
    entry.extend_from_slice(&inf(0)); // archive_offset
    entry.extend_from_slice(&inf(0)); // stored_size
    entry.push(0x00); // encryption = none
    entry.push(b'n'); // compression = none
    entry.extend_from_slice(&inf(0)); // crc_size
    let dar = minimal_dar(vec![entry]);
    let r = DarReader::open(Cursor::new(dar)).expect("open");
    assert_eq!(r.entries()[0].path_lossy(), "fsa.txt");
}

/// A symlink entry carrying an FSA block (FSA-full inode bit) must be skipped
/// in full so the following entry still parses.
#[test]
fn symlink_with_fsa_block_is_skipped() {
    let mut sym = vec![0x0cu8]; // cat_sig → 'l'
    sym.extend_from_slice(b"link\x00");
    sym.extend(inode_base(true)); // flags 0x10 + the two FSA inode infinints
    sym.extend_from_slice(&inf(264)); // FSA family tag
    sym.extend_from_slice(&inf(2)); // FSA data size
    sym.extend_from_slice(&[0xAA, 0xBB]); // FSA data
    sym.extend_from_slice(b"/target\x00"); // symlink target
    let dar = minimal_dar(vec![sym, file_entry("after.txt", 0, b'n', 0, 0)]);
    let r = DarReader::open(Cursor::new(dar)).expect("open");
    let entries = r.entries();
    let paths: Vec<_> = entries
        .iter()
        .map(|e| e.path_lossy().into_owned())
        .collect();
    // The symlink (with its FSA block correctly skipped) and the file both list.
    assert_eq!(paths, ["link", "after.txt"]);
    assert_eq!(entries[0].symlink_target.as_deref(), Some(&b"/target"[..]));
}

// ── e2e coverage of helper guards through the public API ──────────────────────
//
// These feed crafted malicious archives to open()/extract() so the deep
// defensive guards in the parsing helpers fire end-to-end (not only via the
// lib.rs unit tests). A handful of guards are unreachable through the public API
// and remain covered by the unit suite only: the >256 MiB tail-scan fallback,
// BoundedWriter::flush (lzma-rs never flushes the writer), and the all-0xFF
// terminator underflow (the DAR magic forbids an all-0xFF file).

/// `DarReader` is intentionally not `Debug`, so `.unwrap_err()` won't compile on
/// `open()`; this returns the error or panics on an unexpected `Ok`.
fn open_err(buf: Vec<u8>) -> DarError {
    match DarReader::open(Cursor::new(buf)) {
        Err(e) => e,
        Ok(_) => panic!("expected Err, got Ok"),
    }
}

#[test]
fn e2e_archive_with_no_body_is_too_short() {
    // header() ends exactly at archive_origin → find_catalogue: body too short.
    let err = open_err(header());
    assert!(matches!(&err, DarError::Corrupt(s) if s.contains("too short")));
}

/// header + escape + ROOT + a file entry whose `size` infinint is `size_bytes`.
fn dar_with_first_file_size(size_bytes: &[u8]) -> Vec<u8> {
    let mut buf = header();
    buf.extend(catalog_open());
    buf.extend(root_dir());
    let mut e = vec![0x06u8]; // 'f'
    e.extend_from_slice(b"f\x00");
    e.extend(inode_base(false));
    e.extend_from_slice(size_bytes); // read by read_infinint
    buf.extend(e);
    buf.push(EOD);
    buf
}

#[test]
fn e2e_infinint_skip_byte_size_returns_corrupt() {
    // size infinint leads with 0x00 (a >36-byte skip group) → rejected.
    let err = open_err(dar_with_first_file_size(&[0x00]));
    assert!(matches!(&err, DarError::Corrupt(s) if s.contains("multi-group")));
}

#[test]
fn e2e_infinint_wide_terminal_size_returns_corrupt() {
    // terminal 0x20 → (2+1)*4 = 12 data bytes, beyond u64.
    let err = open_err(dar_with_first_file_size(&[0x20]));
    assert!(matches!(&err, DarError::Corrupt(s) if s.contains("exceeds 64-bit")));
}

#[test]
fn e2e_filename_without_nul_is_length_capped() {
    let mut buf = header();
    buf.extend(catalog_open());
    buf.extend(root_dir());
    buf.push(0x06u8); // 'f'
    buf.extend(std::iter::repeat_n(b'A', 64 * 1024 + 8)); // name, no NUL
    let err = open_err(buf);
    assert!(matches!(&err, DarError::Corrupt(s) if s.contains("exceeds")));
}

#[test]
fn e2e_inplace_path_without_nul_is_length_capped() {
    // format 11.1 → open() skips the in-place path after the catalog label.
    let mut buf = vec![0x00u8, 0x00, 0x00, 0x7b];
    buf.extend_from_slice(&[0u8; 10]); // label (all-zero → located via escape)
    buf.extend_from_slice(&[0x00, b'T']);
    buf.extend_from_slice(&inf(0)); // archive_origin
    buf.extend_from_slice(b"0;1\x00"); // version 11.1
    buf.push(b'n'); // stored → plaintext catalogue
    buf.extend_from_slice(&[0xAD, 0xFD, 0xEA, 0x77, 0x21, 0x43]); // seqt_catalogue
    buf.extend_from_slice(&[0u8; 10]); // in-catalog label
    buf.extend(std::iter::repeat_n(b'P', 64 * 1024 + 8)); // path, no NUL
    let err = open_err(buf);
    assert!(matches!(&err, DarError::Corrupt(s) if s.contains("exceeds")));
}

/// A format-11.3 archive with a stored ('n') catalogue (so it lists) holding one
/// entry whose data is the caller's `blob`, compressed with `comp`, declaring
/// `declared_size` uncompressed bytes.
fn dar_with_compressed_entry(comp: u8, blob: &[u8], declared_size: u32) -> Vec<u8> {
    let mut buf = vec![0x00u8, 0x00, 0x00, 0x7b];
    buf.extend_from_slice(&[0u8; 10]); // label
    buf.extend_from_slice(&[0x00, b'T']);
    buf.extend_from_slice(&inf(0)); // archive_origin = 21
    buf.extend_from_slice(b"0;3\x00"); // version 11.3
    buf.push(b'n'); // GLOBAL compression stored → plaintext catalogue
    let data_off = (buf.len() - 21) as u32; // blob offset from archive_origin
    buf.extend_from_slice(blob);
    buf.extend_from_slice(&[0xAD, 0xFD, 0xEA, 0x77, 0x21, 0x43]); // seqt_catalogue
    buf.extend_from_slice(&[0u8; 10]); // in-catalog label
    buf.push(0x00); // in-place path NUL (format 11.1+)
    buf.extend(root_dir());
    let mut e = vec![0x06u8]; // 'f'
    e.extend_from_slice(b"c\x00");
    e.extend(inode_base(false));
    e.extend_from_slice(&inf(declared_size)); // size
    e.extend_from_slice(&inf(data_off)); // archive_offset
    e.extend_from_slice(&inf(blob.len() as u32)); // stored_size
    e.push(0x00); // not encrypted
    e.push(comp); // per-file codec
    e.extend_from_slice(&inf(0)); // crc_size
    buf.extend(e);
    buf.push(EOD);
    buf
}

#[test]
fn e2e_gzip_entry_exceeding_declared_size_is_rejected() {
    use flate2::{write::ZlibEncoder, Compression};
    use std::io::Write;
    let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
    enc.write_all(&[b'X'; 100]).unwrap();
    let blob = enc.finish().unwrap(); // inflates to 100, declared 5
    let dar = dar_with_compressed_entry(b'z', &blob, 5);
    let mut r = DarReader::open(Cursor::new(dar)).expect("open");
    let err = r.extract("c").unwrap_err();
    assert!(matches!(&err, DarError::Corrupt(s) if s.contains("exceeds bound")));
}

#[test]
fn e2e_xz_entry_exceeding_declared_size_is_rejected() {
    // Real xz stream of 200 'A' bytes; declared size 5 → BoundedWriter overflow.
    const XZ_200A: [u8; 72] = [
        0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, 0x00, 0x04, 0xe6, 0xd6, 0xb4, 0x46, 0x02, 0x00, 0x21,
        0x01, 0x16, 0x00, 0x00, 0x00, 0x74, 0x2f, 0xe5, 0xa3, 0xe0, 0x00, 0xc7, 0x00, 0x06, 0x5d,
        0x00, 0x20, 0xef, 0x66, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd5, 0xfd, 0x97, 0x6e, 0x23,
        0x68, 0x20, 0xa1, 0x00, 0x01, 0x22, 0xc8, 0x01, 0x00, 0x00, 0x00, 0x9f, 0xb4, 0xe8, 0xe8,
        0xb1, 0xc4, 0x67, 0xfb, 0x02, 0x00, 0x00, 0x00, 0x00, 0x04, 0x59, 0x5a,
    ];
    let dar = dar_with_compressed_entry(b'x', &XZ_200A, 5);
    let mut r = DarReader::open(Cursor::new(dar)).expect("open");
    let err = r.extract("c").unwrap_err();
    assert!(matches!(&err, DarError::Corrupt(s) if s.contains("xz decode failed")));
}

/// A legacy ('N' extension, format 7) header followed by `tail`, whose end is
/// scanned by read_terminateur.
fn legacy_with_terminator_tail(tail: &[u8]) -> Vec<u8> {
    let mut buf = vec![0x00u8, 0x00, 0x00, 0x7b];
    buf.extend_from_slice(&[0u8; 10]); // label
    buf.push(0x00); // flag
    buf.push(b'N'); // extension = none (legacy)
    buf.extend_from_slice(b"07\x00"); // archive_version (format 7)
    buf.extend_from_slice(tail);
    buf
}

#[test]
fn e2e_legacy_terminator_padding_too_long_returns_corrupt() {
    // 513 trailing 0xFF bytes → >4096 padding bits before any terminator byte.
    let dar = legacy_with_terminator_tail(&[0xFFu8; 513]);
    let err = open_err(dar);
    assert!(matches!(&err, DarError::Corrupt(s) if s.contains("padding too long")));
}

#[test]
fn e2e_legacy_terminator_malformed_bit_run_returns_corrupt() {
    // Terminal byte 0xA0 = 1010_0000: top bit set but the set MSBs aren't
    // contiguous → "malformed terminator bit run".
    let dar = legacy_with_terminator_tail(&[0xA0]);
    let err = open_err(dar);
    assert!(matches!(&err, DarError::Corrupt(s) if s.contains("malformed terminator")));
}

// ── DAR format edition 1 (dar 1.0.x, 2002) ────────────────────────────────────
//
// Clean-room synthetic edition-1 archives, byte-built from the layout
// reverse-engineered from a real dar 1.0.0 archive (see the dar-format-1-layout
// note). Edition 1 differs from formats 2–7: the inode has NO leading flag byte,
// no ctime, no FSA; cat_file is just size·offset (no storage_size, no CRC); the
// root dir is named "root"; dar 1.x is gzip-only and (with -z) compresses the
// terminateur-located catalogue as a single zlib stream.

/// A format-1 inode body: uid(u16) · gid(u16) · perm(u16) · atime · mtime.
fn inode_v1() -> Vec<u8> {
    let mut v = vec![0x03, 0xe8, 0x03, 0xe8, 0x01, 0xa4]; // uid 1000, gid 1000, perm 0o644
    v.extend_from_slice(&inf(1_600_000_000)); // atime
    v.extend_from_slice(&inf(1_600_000_000)); // mtime
    v
}

/// Build a single-file edition-1 archive (`root/hello.txt`). `comp` is `b'n'`
/// (stored) or `b'z'` (gzip — both the file data and the catalogue are zlib
/// streams). The payload is chosen to compress smaller than its size.
fn edition1(comp: u8) -> (Vec<u8>, Vec<u8>) {
    use flate2::{write::ZlibEncoder, Compression};
    use std::io::Write;
    let zlib = |raw: &[u8]| {
        let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
        e.write_all(raw).unwrap();
        e.finish().unwrap()
    };
    let content: Vec<u8> = if comp == b'z' {
        std::iter::repeat_n(b"edition-1 payload 0123456789 ", 40)
            .flatten()
            .copied()
            .collect()
    } else {
        b"hello format 1\n".to_vec()
    };
    let size = content.len() as u32;
    let data = if comp == b'z' {
        zlib(&content)
    } else {
        content.clone()
    };

    let data_off: u32 = 4; // after "01\0" + comp byte, relative to archive_origin
    let mut cat = Vec::new();
    cat.push(0x04); // 'd'
    cat.extend_from_slice(b"root\x00");
    cat.extend(inode_v1());
    cat.push(0x06); // 'f'
    cat.extend_from_slice(b"hello.txt\x00");
    cat.extend(inode_v1());
    cat.extend_from_slice(&inf(size)); // size
    cat.extend_from_slice(&inf(data_off)); // archive_offset (no storage_size/CRC)
    cat.push(EOD);
    let cat_on_disk = if comp == b'z' { zlib(&cat) } else { cat };

    let mut buf = vec![0x00u8, 0x00, 0x00, 0x7b]; // magic
    buf.extend_from_slice(b"0000000001"); // internal_name (10 bytes)
    buf.push(0x00); // flag
    buf.push(b'N'); // ext = legacy (pre-8)
                    // archive_origin = 16
    buf.extend_from_slice(b"01\x00"); // version_string → format 1
    buf.push(comp); // global compression char
    buf.extend_from_slice(&data); // file data at offset 4
    let cat_off = (4 + data.len()) as u32; // catalogue offset relative to origin
    buf.extend_from_slice(&cat_on_disk);
    // terminateur: inf(cat_off) then 3 pad bytes + 0xc0 (2 high bits → 8 = 5+3 back)
    buf.extend_from_slice(&inf(cat_off));
    buf.extend_from_slice(&[0x00, 0x00, 0x00, 0xc0]);
    (buf, content)
}

#[test]
fn v1_stored_lists_and_extracts() {
    let (dar, content) = edition1(b'n');
    let mut r = DarReader::open(Cursor::new(dar)).expect("open edition-1 stored");
    let entries = r.entries();
    assert_eq!(
        entries
            .iter()
            .map(|e| e.path_lossy().into_owned())
            .collect::<Vec<_>>(),
        ["root/hello.txt"]
    );
    assert_eq!(entries[0].size, content.len() as u64);
    // Metadata is exposed (inode_v1: uid/gid 1000, mode 0o644, ts 1_600_000_000;
    // format 1 records no ctime).
    let f = &entries[0];
    assert_eq!(f.kind, EntryKind::File);
    assert_eq!(f.uid, 1000);
    assert_eq!(f.gid, 1000);
    assert_eq!(f.mode, 0o644);
    assert_eq!(f.atime, 1_600_000_000);
    assert_eq!(f.mtime, 1_600_000_000);
    assert_eq!(f.ctime, None);
    assert_eq!(f.symlink_target, None);
    assert_eq!(r.extract("root/hello.txt").expect("extract"), content);
}

#[test]
fn v1_gzip_catalogue_lists_and_extracts() {
    let (dar, content) = edition1(b'z');
    let mut r = DarReader::open(Cursor::new(dar)).expect("open edition-1 gzip");
    let entries = r.entries();
    assert_eq!(
        entries
            .iter()
            .map(|e| e.path_lossy().into_owned())
            .collect::<Vec<_>>(),
        ["root/hello.txt"]
    );
    assert_eq!(r.extract("root/hello.txt").expect("extract"), content);
}

/// A format-1 archive (gzip-global) whose single file `f` has the caller's
/// on-disk `data` and declares uncompressed `size`. Catalogue + entry are both
/// under the gzip global codec, so the entry decodes via the streaming path.
fn edition1_compressed_entry(data: &[u8], size: u32) -> Vec<u8> {
    use flate2::{write::ZlibEncoder, Compression};
    use std::io::Write;
    let zlib = |raw: &[u8]| {
        let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
        e.write_all(raw).unwrap();
        e.finish().unwrap()
    };
    let mut cat = Vec::new();
    cat.push(0x04);
    cat.extend_from_slice(b"root\x00");
    cat.extend(inode_v1());
    cat.push(0x06);
    cat.extend_from_slice(b"f\x00");
    cat.extend(inode_v1());
    cat.extend_from_slice(&inf(size));
    cat.extend_from_slice(&inf(4)); // archive_offset
    cat.push(EOD);
    let cat_z = zlib(&cat);

    let mut buf = vec![0x00u8, 0x00, 0x00, 0x7b];
    buf.extend_from_slice(b"0000000001");
    buf.push(0x00);
    buf.push(b'N');
    buf.extend_from_slice(b"01\x00");
    buf.push(b'z'); // global compression = gzip
    buf.extend_from_slice(data); // entry data at offset 4
    let cat_off = (4 + data.len()) as u32;
    buf.extend_from_slice(&cat_z);
    buf.extend_from_slice(&inf(cat_off));
    buf.extend_from_slice(&[0x00, 0x00, 0x00, 0xc0]);
    buf
}

#[test]
fn v1_compressed_entry_malformed_returns_corrupt() {
    let dar = edition1_compressed_entry(b"this is not a zlib stream!!", 100);
    let mut r = DarReader::open(Cursor::new(dar)).expect("open");
    let err = r.extract("root/f").unwrap_err();
    assert!(matches!(&err, DarError::Corrupt(s) if s.contains("zlib decode failed")));
}

#[test]
fn v1_compressed_entry_size_mismatch_returns_corrupt() {
    use flate2::{write::ZlibEncoder, Compression};
    use std::io::Write;
    let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
    e.write_all(b"short").unwrap(); // decodes to 5 bytes
    let blob = e.finish().unwrap();
    let dar = edition1_compressed_entry(&blob, 100); // catalog claims 100
    let mut r = DarReader::open(Cursor::new(dar)).expect("open");
    let err = r.extract("root/f").unwrap_err();
    assert!(matches!(&err, DarError::Corrupt(s) if s.contains("declares")));
}

// ── special inode types (named pipe / socket) ─────────────────────────────────

#[test]
fn pipe_and_socket_entries_do_not_stop_parsing() {
    // Real full-filesystem archives contain FIFOs ('p') and sockets ('s') — bare
    // inodes with no data. The parser must skip them and keep reading later files
    // rather than treating them as an unknown type and stopping. The pipe carries
    // an FSA block (flag bit 0x10) to exercise the FSA skip in this arm.
    let mut pipe = vec![0x10u8]; // cat_sig low5 0x10 → 'p'
    pipe.extend_from_slice(b"fifo\x00");
    pipe.extend(inode_base(true)); // FSA-full inode fields
    pipe.extend_from_slice(&inf(264)); // FSA family tag
    pipe.extend_from_slice(&inf(2)); // FSA data size
    pipe.extend_from_slice(&[0xAA, 0xBB]); // FSA data
    let mut sock = vec![0x13u8]; // cat_sig low5 0x13 → 's'
    sock.extend_from_slice(b"sock\x00");
    sock.extend(inode_base(false));

    let dar = minimal_dar(vec![pipe, sock, file_entry("after.txt", 0, b'n', 0, 0)]);
    let r = DarReader::open(Cursor::new(dar)).expect("open");
    let entries = r.entries();
    let paths: Vec<_> = entries
        .iter()
        .map(|e| e.path_lossy().into_owned())
        .collect();
    assert_eq!(paths, ["fifo", "sock", "after.txt"]);
    assert_eq!(entries[0].kind, EntryKind::NamedPipe);
    assert_eq!(entries[1].kind, EntryKind::Socket);
    assert_eq!(entries[2].kind, EntryKind::File);
}

// ── loud-not-silent on unknown entry types ───────────────────────────────────

#[test]
fn unknown_entry_type_marks_listing_incomplete() {
    // A hardlink ('m', cat_sig 0x0d) is a type this reader does not model.
    // Hitting it must flag the listing as incomplete, not silently look done —
    // a forensic listing that silently drops everything after it is dangerous.
    let dar = minimal_dar(vec![file_entry("a.txt", 0, b'n', 0, 0), vec![0x0d]]);
    let r = DarReader::open(Cursor::new(dar)).expect("open");
    assert!(
        !r.is_complete(),
        "an unmodelled entry type must mark the listing incomplete"
    );
    // entries parsed before the unknown type are still returned.
    let paths: Vec<_> = r
        .entries()
        .iter()
        .map(|e| e.path_lossy().into_owned())
        .collect();
    assert_eq!(paths, ["a.txt"]);
}

#[test]
fn well_formed_archive_is_complete() {
    let dar = minimal_dar(vec![file_entry("a.txt", 0, b'n', 0, 0)]);
    let r = DarReader::open(Cursor::new(dar)).expect("open");
    assert!(r.is_complete());
}

// ── audit() forensic anomaly detection ────────────────────────────────────────

/// A file entry whose mtime is implausibly far in the future (~year 2103),
/// encoded with the 32-bit infinint form (the value stays below `u32::MAX`).
fn file_entry_future_mtime(name: &str) -> Vec<u8> {
    let mut v = vec![0x06u8]; // cat_sig → 'f'
    v.extend_from_slice(name.as_bytes());
    v.push(0x00);
    v.push(0x00); // inode flags
    v.extend_from_slice(&inf(0)); // uid
    v.extend_from_slice(&inf(0)); // gid
    v.extend_from_slice(&[0x00, 0x00]); // perms
    v.push(b's');
    v.extend_from_slice(&inf(0)); // atime
    v.push(b's');
    v.extend_from_slice(&inf(4_200_000_000)); // mtime ~2103 (> year-2100 ceiling)
    v.push(b's');
    v.extend_from_slice(&inf(0)); // ctime
    v.extend_from_slice(&inf(0)); // data_size
    v.extend_from_slice(&inf(0)); // archive_offset
    v.extend_from_slice(&inf(0)); // stored_size
    v.push(0x00); // enc = none
    v.push(b'n'); // comp = none
    v.extend_from_slice(&inf(0)); // crc_size = 0
    v
}

fn codes(anomalies: &[Anomaly]) -> Vec<&'static str> {
    anomalies.iter().map(|a| a.code).collect()
}

#[test]
fn audit_clean_archive_reports_no_anomalies() {
    let dar = minimal_dar(vec![file_entry("notes.txt", 0, b'n', 0, 0)]);
    let r = DarReader::open(Cursor::new(dar)).expect("open");
    assert!(r.audit().is_empty());
}

#[test]
fn audit_flags_incomplete_catalog() {
    // A hardlink ('m', 0x0d) is an unmodelled type → parsing stops → incomplete.
    let dar = minimal_dar(vec![file_entry("a.txt", 0, b'n', 0, 0), vec![0x0d]]);
    let r = DarReader::open(Cursor::new(dar)).expect("open");
    let anomalies = r.audit();
    let a = anomalies
        .iter()
        .find(|a| a.code == "DAR-CATALOG-INCOMPLETE")
        .expect("incomplete-catalog anomaly");
    assert_eq!(a.severity, Severity::High);
    assert!(matches!(
        a.kind,
        AnomalyKind::IncompleteCatalog {
            entries_recovered: 1
        }
    ));
}

#[test]
fn audit_flags_absolute_path() {
    let dar = minimal_dar(vec![file_entry("/etc/shadow", 0, b'n', 0, 0)]);
    let r = DarReader::open(Cursor::new(dar)).expect("open");
    assert!(codes(&r.audit()).contains(&"DAR-PATH-ABSOLUTE"));
}

#[test]
fn audit_flags_parent_traversal() {
    let dar = minimal_dar(vec![file_entry("../../escape", 0, b'n', 0, 0)]);
    let r = DarReader::open(Cursor::new(dar)).expect("open");
    assert!(codes(&r.audit()).contains(&"DAR-PATH-TRAVERSAL"));
}

#[test]
fn audit_flags_duplicate_path_once() {
    let dar = minimal_dar(vec![
        file_entry("dup.bin", 0, b'n', 0, 0),
        file_entry("dup.bin", 0, b'n', 0, 0),
    ]);
    let r = DarReader::open(Cursor::new(dar)).expect("open");
    let dups: Vec<_> = r
        .audit()
        .into_iter()
        .filter(|a| a.code == "DAR-PATH-DUPLICATE")
        .collect();
    assert_eq!(dups.len(), 1, "a duplicated path is reported exactly once");
}

#[test]
fn audit_flags_future_timestamp() {
    let dar = minimal_dar(vec![file_entry_future_mtime("backdated.bin")]);
    let r = DarReader::open(Cursor::new(dar)).expect("open");
    let a = r
        .audit()
        .into_iter()
        .find(|a| a.code == "DAR-TIME-FUTURE")
        .expect("future-timestamp anomaly");
    assert_eq!(a.severity, Severity::Low);
    assert!(matches!(
        a.kind,
        AnomalyKind::FutureTimestamp { field: "mtime", .. }
    ));
}

#[test]
fn audit_flags_control_chars_in_name() {
    let dar = minimal_dar(vec![file_entry("inv\x1bisible", 0, b'n', 0, 0)]);
    let r = DarReader::open(Cursor::new(dar)).expect("open");
    assert!(codes(&r.audit()).contains(&"DAR-NAME-CONTROL"));
}

#[test]
fn severity_orders_and_displays() {
    assert!(Severity::Info < Severity::Low);
    assert!(Severity::Low < Severity::Medium);
    assert!(Severity::Medium < Severity::High);
    assert!(Severity::High < Severity::Critical);
    assert_eq!(Severity::Info.to_string(), "INFO");
    assert_eq!(Severity::Low.to_string(), "LOW");
    assert_eq!(Severity::Medium.to_string(), "MEDIUM");
    assert_eq!(Severity::High.to_string(), "HIGH");
    assert_eq!(Severity::Critical.to_string(), "CRITICAL");
}

#[test]
fn anomaly_display_is_bracketed_severity_code_note() {
    let a = Anomaly::new(AnomalyKind::AbsolutePath {
        path: "/etc/shadow".into(),
    });
    let s = a.to_string();
    assert!(s.starts_with("[MEDIUM] DAR-PATH-ABSOLUTE: "));
    assert!(s.contains("/etc/shadow"));
}

#[cfg(feature = "serde")]
#[test]
fn audit_anomaly_serializes_to_json() {
    let a = Anomaly::new(AnomalyKind::AbsolutePath {
        path: "/etc/shadow".into(),
    });
    let json = serde_json::to_string(&a).expect("serialize");
    assert!(json.contains("\"severity\":\"Medium\""), "{json}");
    assert!(json.contains("\"code\":\"DAR-PATH-ABSOLUTE\""), "{json}");
    assert!(json.contains("AbsolutePath"), "{json}");
}

// ── bodyfile (Sleuth Kit mactime) export ──────────────────────────────────────

fn mk_entry(path: &[u8], kind: EntryKind, mode: u16) -> DarEntry {
    DarEntry {
        path: path.to_vec(),
        kind,
        size: 0,
        uid: 0,
        gid: 0,
        mode,
        atime: 0,
        mtime: 0,
        ctime: None,
        symlink_target: None,
    }
}

#[test]
fn bodyfile_basic_file_line() {
    let e = mk_entry(b"notes.txt", EntryKind::File, 0);
    assert_eq!(e.bodyfile(), "0|notes.txt|0|r/r---------|0|0|0|0|0|0|0");
}

#[test]
fn bodyfile_includes_ids_size_and_times() {
    let e = DarEntry {
        path: b"f".to_vec(),
        kind: EntryKind::File,
        size: 4096,
        uid: 1000,
        gid: 1001,
        mode: 0o644,
        atime: 111,
        mtime: 222,
        ctime: Some(333),
        symlink_target: None,
    };
    assert_eq!(
        e.bodyfile(),
        "0|f|0|r/rrw-r--r--|1000|1001|4096|111|222|333|0"
    );
}

#[test]
fn bodyfile_renders_permission_and_special_bits() {
    let mode_str = |mode: u16| {
        mk_entry(b"x", EntryKind::File, mode)
            .bodyfile()
            .split('|')
            .nth(3)
            .unwrap()
            .to_string()
    };
    assert_eq!(mode_str(0o0755), "r/rrwxr-xr-x");
    assert_eq!(mode_str(0o0644), "r/rrw-r--r--");
    assert_eq!(mode_str(0o4755), "r/rrwsr-xr-x"); // setuid + owner exec → s
    assert_eq!(mode_str(0o4644), "r/rrwSr--r--"); // setuid, no owner exec → S
    assert_eq!(mode_str(0o2755), "r/rrwxr-sr-x"); // setgid + group exec → s
    assert_eq!(mode_str(0o2745), "r/rrwxr-Sr-x"); // setgid, no group exec → S
    assert_eq!(mode_str(0o1707), "r/rrwx---rwt"); // sticky + other exec → t
    assert_eq!(mode_str(0o1706), "r/rrwx---rwT"); // sticky, no other exec → T
}

#[test]
fn bodyfile_type_letter_per_kind() {
    let tletter = |kind| {
        mk_entry(b"x", kind, 0)
            .bodyfile()
            .split('|')
            .nth(3)
            .unwrap()
            .chars()
            .next()
            .unwrap()
    };
    assert_eq!(tletter(EntryKind::File), 'r');
    assert_eq!(tletter(EntryKind::Directory), 'd');
    assert_eq!(tletter(EntryKind::Symlink), 'l');
    assert_eq!(tletter(EntryKind::NamedPipe), 'p');
    assert_eq!(tletter(EntryKind::Socket), 's');
    assert_eq!(tletter(EntryKind::CharDevice), 'c');
    assert_eq!(tletter(EntryKind::BlockDevice), 'b');
    assert_eq!(tletter(EntryKind::Hardlink), 'r');
    assert_eq!(tletter(EntryKind::Unknown('q')), '-');
}

#[test]
fn bodyfile_escapes_pipe_backslash_and_control_bytes() {
    // name bytes: a | b \ c <TAB> d <LF>
    let line = mk_entry(b"a|b\\c\td\n", EntryKind::File, 0).bodyfile();
    assert!(line.starts_with("0|a\\|b\\\\c\\x09d\\x0a|0|r/r"), "{line}");
}

#[test]
fn bodyfile_appends_symlink_target() {
    let mut e = mk_entry(b"link", EntryKind::Symlink, 0o777);
    e.symlink_target = Some(b"/etc/passwd".to_vec());
    let line = e.bodyfile();
    assert!(line.contains("|link -> /etc/passwd|"), "{line}");
    assert!(line.split('|').nth(3).unwrap().starts_with("l/l"), "{line}");
}

// ── entry JSON export (feature = "serde") ─────────────────────────────────────

#[cfg(feature = "serde")]
#[test]
fn entry_serializes_to_json_with_string_path() {
    let e = DarEntry {
        path: b"files/hello.txt".to_vec(),
        kind: EntryKind::File,
        size: 13,
        uid: 1000,
        gid: 1000,
        mode: 0o644,
        atime: 100,
        mtime: 200,
        ctime: Some(300),
        symlink_target: None,
    };
    let json = serde_json::to_string(&e).expect("serialize");
    // path is a readable string, not a raw byte array.
    assert!(json.contains("\"path\":\"files/hello.txt\""), "{json}");
    assert!(json.contains("\"kind\":\"File\""), "{json}");
    assert!(json.contains("\"size\":13"), "{json}");
    assert!(json.contains("\"ctime\":300"), "{json}");
    assert!(json.contains("\"symlink_target\":null"), "{json}");
}

#[cfg(feature = "serde")]
#[test]
fn entry_serializes_symlink_target_as_string() {
    let e = DarEntry {
        path: b"link".to_vec(),
        kind: EntryKind::Symlink,
        size: 0,
        uid: 0,
        gid: 0,
        mode: 0o777,
        atime: 0,
        mtime: 0,
        ctime: None,
        symlink_target: Some(b"/etc/passwd".to_vec()),
    };
    let json = serde_json::to_string(&e).expect("serialize");
    assert!(
        json.contains("\"symlink_target\":\"/etc/passwd\""),
        "{json}"
    );
    assert!(json.contains("\"kind\":\"Symlink\""), "{json}");
    assert!(json.contains("\"ctime\":null"), "{json}");
}

// ── CRC verification ──────────────────────────────────────────────────────────

/// A format-8+ stored ('n') file entry named `name` declaring `size` bytes at
/// archive_offset 0, carrying the caller's `crc` (length-prefixed).
fn file_entry_with_crc(name: &str, size: u32, crc: &[u8]) -> Vec<u8> {
    let mut v = vec![0x06u8]; // cat_sig → 'f'
    v.extend_from_slice(name.as_bytes());
    v.push(0x00);
    v.extend(inode_base(false));
    v.extend_from_slice(&inf(size)); // logical size
    v.extend_from_slice(&inf(0)); // archive_offset
    v.extend_from_slice(&inf(size)); // stored_size
    v.push(0x00); // enc = none
    v.push(b'n'); // comp = none (stored)
    v.extend_from_slice(&inf(crc.len() as u32)); // crc width
    v.extend_from_slice(crc); // crc bytes
    v
}

#[test]
fn verify_matches_correct_crc() {
    const DATA: &[u8] = b"AB"; // XOR-fold width 2 → [0x41, 0x42]
    let mut buf = header();
    buf.extend_from_slice(DATA); // data at archive_offset 0
    buf.extend(catalog_open());
    buf.extend(root_dir());
    buf.extend(file_entry_with_crc("f", DATA.len() as u32, &[0x41, 0x42]));
    buf.push(EOD);
    let mut r = DarReader::open(Cursor::new(buf)).expect("open");
    assert_eq!(r.verify("f").expect("verify"), CrcStatus::Match);
}

#[test]
fn verify_detects_mismatch() {
    const DATA: &[u8] = b"AB";
    let mut buf = header();
    buf.extend_from_slice(DATA);
    buf.extend(catalog_open());
    buf.extend(root_dir());
    buf.extend(file_entry_with_crc("f", DATA.len() as u32, &[0xff, 0xff]));
    buf.push(EOD);
    let mut r = DarReader::open(Cursor::new(buf)).expect("open");
    match r.verify("f").expect("verify") {
        CrcStatus::Mismatch { stored, computed } => {
            assert_eq!(stored, "ffff");
            assert_eq!(computed, "4142");
        }
        other => panic!("expected Mismatch, got {other:?}"),
    }
}

#[test]
fn verify_not_stored_when_crc_absent() {
    // file_entry writes a zero-width CRC, so no CRC is recorded.
    let dar = minimal_dar(vec![file_entry("f", 0, b'n', 0, 0)]);
    let mut r = DarReader::open(Cursor::new(dar)).expect("open");
    assert_eq!(r.verify("f").expect("verify"), CrcStatus::NotStored);
}

#[test]
fn verify_unknown_path_errors() {
    let dar = minimal_dar(vec![file_entry("f", 0, b'n', 0, 0)]);
    let mut r = DarReader::open(Cursor::new(dar)).expect("open");
    assert!(matches!(r.verify("nope"), Err(DarError::EntryNotFound(_))));
}

#[test]
fn oversized_crc_width_is_rejected() {
    // A hostile catalogue declaring a 70_000-byte CRC width must be rejected
    // (allocation-bomb guard), not allocated.
    let mut buf = header();
    buf.extend(catalog_open());
    buf.extend(root_dir());
    let mut entry = vec![0x06u8]; // cat_sig → 'f'
    entry.extend_from_slice(b"big.crc");
    entry.push(0x00);
    entry.extend(inode_base(false));
    entry.extend_from_slice(&inf(0)); // size
    entry.extend_from_slice(&inf(0)); // archive_offset
    entry.extend_from_slice(&inf(0)); // stored_size
    entry.push(0x00); // enc = none
    entry.push(b'n'); // comp = none
    entry.extend_from_slice(&inf(70_000)); // CRC width > MAX_CRC_SIZE (64 KiB)
    buf.extend(entry);
    buf.push(EOD);
    let Err(err) = DarReader::open(Cursor::new(buf)) else {
        panic!("expected Err, got Ok");
    };
    assert!(
        matches!(&err, DarError::Corrupt(s) if s.contains("CRC width")),
        "{err:?}"
    );
}

#[test]
fn crc_status_display() {
    assert_eq!(CrcStatus::Match.to_string(), "CRC match");
    assert_eq!(CrcStatus::NotStored.to_string(), "no CRC stored");
    assert_eq!(
        CrcStatus::Mismatch {
            stored: "ab".into(),
            computed: "cd".into(),
        }
        .to_string(),
        "CRC mismatch: stored ab, computed cd"
    );
}

// ── O(1) count + lazy entry iteration ─────────────────────────────────────────

#[test]
fn entry_count_matches_entries_len() {
    let dar = minimal_dar(vec![
        file_entry("a.txt", 0, b'n', 0, 0),
        file_entry("b.txt", 0, b'n', 0, 0),
    ]);
    let r = DarReader::open(Cursor::new(dar)).expect("open");
    assert_eq!(r.entry_count(), r.entries().len());
    assert_eq!(r.entry_count(), 2);
}

#[test]
fn iter_entries_matches_collected_entries() {
    let dar = minimal_dar(vec![
        file_entry("a.txt", 0, b'n', 0, 0),
        file_entry("b.txt", 0, b'n', 0, 0),
    ]);
    let r = DarReader::open(Cursor::new(dar)).expect("open");
    let lazy: Vec<_> = r
        .iter_entries()
        .map(|e| e.path_lossy().into_owned())
        .collect();
    let eager: Vec<_> = r
        .entries()
        .iter()
        .map(|e| e.path_lossy().into_owned())
        .collect();
    assert_eq!(lazy, eager);
    assert_eq!(lazy, ["a.txt", "b.txt"]);
}

// ── zstd decode ────────────────────────────────────────────

/// A real standard zstd frame (zstd CLI v1.5.6) of the line below repeated 6×.
/// dar's streamed zstd writes exactly this format (ZSTD_compressStream produces
/// a standard frame — see compressor_zstd.cpp), so this is byte-faithful.
const ZSTD_FRAME: &[u8] = &[
    0x28, 0xb5, 0x2f, 0xfd, 0x24, 0xf0, 0x8d, 0x01, 0x00, 0x84, 0x02, 0x64, 0x61, 0x72, 0x2d, 0x66,
    0x6f, 0x72, 0x65, 0x6e, 0x73, 0x69, 0x63, 0x20, 0x7a, 0x73, 0x74, 0x64, 0x20, 0x64, 0x65, 0x63,
    0x6f, 0x64, 0x65, 0x20, 0x72, 0x6f, 0x75, 0x6e, 0x64, 0x74, 0x72, 0x69, 0x70, 0x20, 0x6c, 0x69,
    0x6e, 0x65, 0x0a, 0x01, 0x00, 0x28, 0x2e, 0x4a, 0x95, 0x01, 0x0a, 0x07, 0x45, 0x88,
];

#[test]
fn zstd_entry_extracts_to_plaintext() {
    let expected = b"dar-forensic zstd decode roundtrip line\n".repeat(6);
    let dar = dar_with_compressed_entry(b'd', ZSTD_FRAME, expected.len() as u32);
    let mut r = DarReader::open(Cursor::new(dar)).expect("open");
    assert_eq!(r.extract("c").expect("extract zstd entry"), expected);
}

// ── block_compressor decode guards ────────────────────────────────────────────
// A 'q' (lz4) or 'l' (lzo) codec forces per-block framing, so a crafted block
// stream as entry data exercises decode_blocks' corruption guards via extract().

fn extract_block_entry(block_stream: &[u8], comp: u8) -> DarError {
    let dar = dar_with_compressed_entry(comp, block_stream, 64);
    DarReader::open(Cursor::new(dar))
        .expect("open")
        .extract("c")
        .unwrap_err()
}

#[test]
fn block_eof_with_nonzero_size_is_corrupt() {
    // H_EOF (type 2) must carry size 0.
    let err = extract_block_entry(&[0x02, 0x80, 0x00, 0x00, 0x00, 0x05], b'q');
    assert!(
        matches!(&err, DarError::Corrupt(s) if s.contains("end-of-blocks")),
        "{err:?}"
    );
}

#[test]
fn block_zero_size_data_is_corrupt() {
    // H_DATA (type 1) with size 0.
    let err = extract_block_entry(&[0x01, 0x80, 0x00, 0x00, 0x00, 0x00], b'q');
    assert!(
        matches!(&err, DarError::Corrupt(s) if s.contains("zero-size")),
        "{err:?}"
    );
}

#[test]
fn block_size_exceeding_input_is_corrupt() {
    // H_DATA claiming 1000 bytes with none remaining.
    let err = extract_block_entry(&[0x01, 0x80, 0x00, 0x00, 0x03, 0xE8], b'q');
    assert!(
        matches!(&err, DarError::Corrupt(s) if s.contains("exceeds remaining input")),
        "{err:?}"
    );
}

#[test]
fn block_unknown_type_is_corrupt() {
    let err = extract_block_entry(&[0x63, 0x80, 0x00, 0x00, 0x00, 0x00], b'q');
    assert!(
        matches!(&err, DarError::Corrupt(s) if s.contains("unknown compressed block type")),
        "{err:?}"
    );
}

#[test]
fn block_lzo_malformed_is_corrupt() {
    // A well-formed H_DATA frame whose 2-byte payload is not a valid lzo1x block
    // (lzo1x needs >= 3 bytes): the bounds-checked decoder surfaces a typed error
    // as Corrupt rather than panicking.
    let err = extract_block_entry(&[0x01, 0x80, 0x00, 0x00, 0x00, 0x02, 0xAA, 0xBB], b'l');
    assert!(
        matches!(&err, DarError::Corrupt(s) if s.contains("lzo")),
        "{err:?}"
    );
}
