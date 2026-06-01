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
//! dar 2.5.3 source: https://sourceforge.net/projects/dar/files/dar/2.5.3/
//! Contents: files/hello.txt — 15 bytes: "hello format 9\n"

use std::io::Cursor;
use std::path::Path;
use dar::DarReader;

const DATA_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data");

fn open_v11() -> DarReader<Cursor<Vec<u8>>> {
    let path = format!("{DATA_DIR}/v11_hello.dar");
    let data = std::fs::read(Path::new(&path))
        .unwrap_or_else(|e| panic!("read v11_hello.dar: {e}"));
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
    let data = r.extract("files/hello.txt").expect("extract files/hello.txt");
    assert_eq!(data, b"hello corpus\n");
}

// ── v9_hello.dar ─────────────────────────────────────────────────────────────

fn open_v9() -> DarReader<Cursor<Vec<u8>>> {
    let path = format!("{DATA_DIR}/v9_hello.dar");
    let data = std::fs::read(Path::new(&path))
        .unwrap_or_else(|e| panic!("read v9_hello.dar: {e}"));
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
    assert_eq!(open_v9().entries()[0].path, "files/hello.txt");
}

#[test]
fn v9_entry_size_is_15() {
    assert_eq!(open_v9().entries()[0].size, 15);
}

#[test]
fn v9_extracts_hello_txt() {
    let mut r = open_v9();
    let data = r.extract("files/hello.txt").expect("extract");
    assert_eq!(data, b"hello format 9\n");
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
    let result = DarReader::open(Cursor::new(b"DAR\x00\x01\x00\x00\x00\x00\x00\x00\x00".to_vec()));
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
