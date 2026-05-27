//! Integration tests against the real Denis Corbin DAR v11 corpus.
//!
//! `v11_hello.dar` was created with dar 2.8.5 (format 11.3) on a real system:
//!
//!   cd /tmp && mkdir dar_test && echo -n "hello corpus" > dar_test/files/hello.txt
//!   printf '\n' >> dar_test/files/hello.txt
//!   dar -c /tmp/archive -R /tmp/dar_test -g files/hello.txt
//!   cp /tmp/archive.1.dar v11_hello.dar
//!
//! Archive contents:
//!   files/hello.txt  — 13 bytes: "hello corpus\n"

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
