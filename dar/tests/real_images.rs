//! Integration tests against real DAR corpus fixtures.
//!
//! ## v11_hello.dar  (DAR format 11.3, version_string "0;3")
//!
//! Created with dar 2.8.5 on macOS Apple Silicon:
//!
//!   mkdir -p /tmp/dar_test/files
//!   printf 'hello corpus\n' > /tmp/dar_test/files/hello.txt
//!   dar -c /tmp/archive -R /tmp/dar_test -g files/hello.txt
//!   cp /tmp/archive.1.dar v11_hello.dar
//!
//! Contents: files/hello.txt — 13 bytes: "hello corpus\n"
//!
//! ## v9_hello.dar  (DAR format 9, version_string "090")
//!
//! Created with dar 2.5.3 on macOS Apple Silicon:
//!
//!   mkdir -p /tmp/v9_corpus/files
//!   printf 'hello format 9\n' > /tmp/v9_corpus/files/hello.txt
//!   /path/to/dar253/bin/dar -c /tmp/v9_archive -R /tmp/v9_corpus -g files/hello.txt
//!   cp /tmp/v9_archive.1.dar v9_hello.dar
//!
//! dar 2.5.3 source: <https://sourceforge.net/projects/dar/files/dar/2.5.3/>
//! Contents: files/hello.txt — 15 bytes: "hello format 9\n"

use dar::DarReader;
use std::io::Cursor;
use std::path::Path;

const DATA_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data");

fn open_v11() -> DarReader<Cursor<Vec<u8>>> {
    let path = format!("{DATA_DIR}/v11_hello.dar");
    let data =
        std::fs::read(Path::new(&path)).unwrap_or_else(|e| panic!("read v11_hello.dar: {e}"));
    DarReader::open(Cursor::new(data))
        .unwrap_or_else(|e| panic!("DarReader::open v11_hello.dar: {e}"))
}

// ── open ─────────────────────────────────────────────────────────────────────

#[test]
fn v11_opens() {
    let _ = open_v11();
}

// ── entries ───────────────────────────────────────────────────────────────────

#[test]
fn v11_lists_one_entry() {
    assert_eq!(open_v11().entries().len(), 1);
}

#[test]
fn v11_entry_path() {
    let r = open_v11();
    let entries = r.entries();
    assert_eq!(entries[0].path, "files/hello.txt");
}

#[test]
fn v11_entry_size_is_13() {
    let r = open_v11();
    let entries = r.entries();
    assert_eq!(entries[0].size, 13);
}

// ── extract ───────────────────────────────────────────────────────────────────

#[test]
fn v11_extracts_hello_txt() {
    let mut r = open_v11();
    let data = r
        .extract("files/hello.txt")
        .expect("extract files/hello.txt");
    assert_eq!(data, b"hello corpus\n");
}

// ── v9_hello.dar ─────────────────────────────────────────────────────────────

fn open_v9() -> DarReader<Cursor<Vec<u8>>> {
    let path = format!("{DATA_DIR}/v9_hello.dar");
    let data = std::fs::read(Path::new(&path)).unwrap_or_else(|e| panic!("read v9_hello.dar: {e}"));
    DarReader::open(Cursor::new(data))
        .unwrap_or_else(|e| panic!("DarReader::open v9_hello.dar: {e}"))
}

#[test]
fn v9_opens() {
    let _ = open_v9();
}

#[test]
fn v9_lists_one_entry() {
    assert_eq!(open_v9().entries().len(), 1);
}

#[test]
fn v9_entry_path() {
    assert_eq!(open_v9().entries()[0].path, "root/files/hello.txt");
}

#[test]
fn v9_entry_size_is_15() {
    assert_eq!(open_v9().entries()[0].size, 15);
}

#[test]
fn v9_extracts_hello_txt() {
    let mut r = open_v9();
    let data = r.extract("root/files/hello.txt").expect("extract");
    assert_eq!(data, b"hello format 9\n");
}

// ── v8_hello.dar (DAR format 8.1, version_string "081") ──────────────────────
//
// Created with dar 2.4.24 (built from the SourceForge release tarball):
//
//   mkdir -p /tmp/v8_corpus/files
//   printf 'hello format 8\n' > /tmp/v8_corpus/files/hello.txt
//   /path/to/dar-2.4.24/dar -Q -c /tmp/v8_archive -R /tmp/v8_corpus -g files/hello.txt
//   cp /tmp/v8_archive.1.dar v8_hello.dar
//
// Format 8 timestamps are bare seconds infinints (no 's'/'n' type byte) and the
// inode carries no FSA — see docs/implementation-notes.md §11.
// dar 2.4.24 source: <https://sourceforge.net/projects/dar/files/dar/2.4.24/>

fn open_v8() -> DarReader<Cursor<Vec<u8>>> {
    let path = format!("{DATA_DIR}/v8_hello.dar");
    let data = std::fs::read(Path::new(&path)).unwrap_or_else(|e| panic!("read v8_hello.dar: {e}"));
    DarReader::open(Cursor::new(data))
        .unwrap_or_else(|e| panic!("DarReader::open v8_hello.dar: {e}"))
}

#[test]
fn v8_opens() {
    let _ = open_v8();
}

#[test]
fn v8_lists_one_entry() {
    assert_eq!(open_v8().entries().len(), 1);
}

#[test]
fn v8_entry_path_ends_with_hello_txt() {
    assert!(open_v8().entries()[0].path.ends_with("files/hello.txt"));
}

#[test]
fn v8_entry_size_is_15() {
    assert_eq!(open_v8().entries()[0].size, 15);
}

#[test]
fn v8_extracts_hello_txt() {
    let mut r = open_v8();
    let path = r.entries()[0].path.clone(); // virtual-root prefix is data-determined
    let data = r.extract(&path).expect("extract");
    assert_eq!(data, b"hello format 8\n");
}

// ── v10_hello.dar (DAR format 10.1, version_string "0:1") ────────────────────
//
// Created with dar 2.6.16 (built from the SourceForge release tarball,
// --disable-nodump-flag).  Validates that the format >= 11.1 path-boundary fix
// correctly treats format 10 as having NO catalog in-place path, and that the
// format-9 inode/timestamp layout applies unchanged at format 10.
//
//   printf 'hello format 10\n' > /tmp/v10_corpus/files/hello.txt
//   /path/to/dar-2.6.16/dar -Q -c /tmp/v10_archive -R /tmp/v10_corpus -g files/hello.txt
//   cp /tmp/v10_archive.1.dar v10_hello.dar
//
// dar 2.6.16 source: <https://sourceforge.net/projects/dar/files/dar/2.6.16/>

fn open_v10() -> DarReader<Cursor<Vec<u8>>> {
    let path = format!("{DATA_DIR}/v10_hello.dar");
    let data =
        std::fs::read(Path::new(&path)).unwrap_or_else(|e| panic!("read v10_hello.dar: {e}"));
    DarReader::open(Cursor::new(data))
        .unwrap_or_else(|e| panic!("DarReader::open v10_hello.dar: {e}"))
}

#[test]
fn v10_opens() {
    let _ = open_v10();
}

#[test]
fn v10_lists_one_entry() {
    assert_eq!(open_v10().entries().len(), 1);
}

#[test]
fn v10_entry_path_ends_with_hello_txt() {
    assert!(open_v10().entries()[0].path.ends_with("files/hello.txt"));
}

#[test]
fn v10_entry_size_is_16() {
    assert_eq!(open_v10().entries()[0].size, 16);
}

#[test]
fn v10_extracts_hello_txt() {
    let mut r = open_v10();
    let path = r.entries()[0].path.clone();
    let data = r.extract(&path).expect("extract");
    assert_eq!(data, b"hello format 10\n");
}

// ── v7_hello.dar (DAR format 7, version_string "07") ─────────────────────────
//
// Created with dar 2.3.12 (built from the SourceForge release tarball in a
// gcc:4.9 container — pre-2.4 C++ won't compile on a modern toolchain).
//
// Pre-format-8 archives are structurally different (see implementation-notes
// §12): no `seqt_catalogue` escape — the catalog is located via the end
// `terminateur` trailer; slice-header extension is 'N' (no TLV), so
// archive_origin = 16; inode uid/gid are 2-byte u16 (not infinint); timestamps
// are bare seconds infinints with no ctime; the per-file CRC is a fixed 2 bytes
// (no length prefix); and there is no catalog label / no path field.
//
//   printf 'hello format 7\n' > /src/files/hello.txt
//   /path/to/dar-2.3.12/dar -Q -c /work/v7 -R /src -g files/hello.txt
//   cp /work/v7.1.dar v7_hello.dar
//
// dar 2.3.12 source: <https://sourceforge.net/projects/dar/files/dar/2.3.12/>

fn open_v7() -> DarReader<Cursor<Vec<u8>>> {
    let path = format!("{DATA_DIR}/v7_hello.dar");
    let data = std::fs::read(Path::new(&path)).unwrap_or_else(|e| panic!("read v7_hello.dar: {e}"));
    DarReader::open(Cursor::new(data)).unwrap_or_else(|e| panic!("DarReader::open v7_hello.dar: {e}"))
}

#[test]
fn v7_opens() {
    let _ = open_v7();
}

#[test]
fn v7_lists_one_entry() {
    assert_eq!(open_v7().entries().len(), 1);
}

#[test]
fn v7_entry_path_ends_with_hello_txt() {
    assert!(open_v7().entries()[0].path.ends_with("files/hello.txt"));
}

#[test]
fn v7_entry_size_is_15() {
    assert_eq!(open_v7().entries()[0].size, 15);
}

#[test]
fn v7_extracts_hello_txt() {
    let mut r = open_v7();
    let path = r.entries()[0].path.clone();
    let data = r.extract(&path).expect("extract");
    assert_eq!(data, b"hello format 7\n");
}

// ── error cases ───────────────────────────────────────────────────────────────

#[test]
fn open_empty_returns_err() {
    let result = DarReader::open(Cursor::new(vec![]));
    assert!(result.is_err(), "opening empty bytes must return Err");
}

#[test]
fn open_truncated_returns_err() {
    // 4 valid magic bytes then nothing — incomplete header
    let result = DarReader::open(Cursor::new(vec![0x00, 0x00, 0x00, 0x7b]));
    assert!(result.is_err(), "truncated archive must return Err");
}

#[test]
fn open_wrong_magic_returns_err() {
    // Old SecurityRonin format magic — must be rejected
    let result = DarReader::open(Cursor::new(
        b"DAR\x00\x01\x00\x00\x00\x00\x00\x00\x00".to_vec(),
    ));
    assert!(result.is_err(), "wrong magic must return Err");
}

#[test]
fn extract_missing_path_returns_err() {
    let mut r = open_v11();
    assert!(
        r.extract("no/such/file").is_err(),
        "extracting non-existent path must return Err"
    );
}
