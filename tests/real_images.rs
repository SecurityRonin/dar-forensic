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

use dar_forensic::{DarEntry, DarReader, EntryKind};
use std::io::Cursor;
use std::path::Path;

const DATA_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data");

/// The single regular-file entry in an archive (entries() now also lists the
/// containing directory, so we can't assume index 0 is the file).
fn sole_file(r: &DarReader<Cursor<Vec<u8>>>) -> DarEntry {
    let files: Vec<DarEntry> = r
        .entries()
        .into_iter()
        .filter(|e| e.kind == EntryKind::File)
        .collect();
    assert_eq!(files.len(), 1, "expected exactly one file entry");
    files.into_iter().next().unwrap()
}

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
fn v11_lists_one_file() {
    assert_eq!(
        open_v11()
            .entries()
            .iter()
            .filter(|e| e.kind == EntryKind::File)
            .count(),
        1
    );
}

#[test]
fn v11_entry_path() {
    assert_eq!(sole_file(&open_v11()).path_lossy(), "files/hello.txt");
}

#[test]
fn v11_entry_size_is_13() {
    assert_eq!(sole_file(&open_v11()).size, 13);
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
fn v9_lists_one_file() {
    assert_eq!(
        open_v9()
            .entries()
            .iter()
            .filter(|e| e.kind == EntryKind::File)
            .count(),
        1
    );
}

#[test]
fn v9_entry_path() {
    assert_eq!(sole_file(&open_v9()).path_lossy(), "root/files/hello.txt");
}

#[test]
fn v9_entry_size_is_15() {
    assert_eq!(sole_file(&open_v9()).size, 15);
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
fn v8_lists_one_file() {
    assert_eq!(
        open_v8()
            .entries()
            .iter()
            .filter(|e| e.kind == EntryKind::File)
            .count(),
        1
    );
}

#[test]
fn v8_entry_path_ends_with_hello_txt() {
    assert!(sole_file(&open_v8())
        .path_lossy()
        .ends_with("files/hello.txt"));
}

#[test]
fn v8_entry_size_is_15() {
    assert_eq!(sole_file(&open_v8()).size, 15);
}

#[test]
fn v8_extracts_hello_txt() {
    let r = open_v8();
    let path = sole_file(&r).path; // virtual-root prefix is data-determined
    let mut r = r;
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
fn v10_lists_one_file() {
    assert_eq!(
        open_v10()
            .entries()
            .iter()
            .filter(|e| e.kind == EntryKind::File)
            .count(),
        1
    );
}

#[test]
fn v10_entry_path_ends_with_hello_txt() {
    assert!(sole_file(&open_v10())
        .path_lossy()
        .ends_with("files/hello.txt"));
}

#[test]
fn v10_entry_size_is_16() {
    assert_eq!(sole_file(&open_v10()).size, 16);
}

#[test]
fn v10_extracts_hello_txt() {
    let r = open_v10();
    let path = sole_file(&r).path;
    let mut r = r;
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
    DarReader::open(Cursor::new(data))
        .unwrap_or_else(|e| panic!("DarReader::open v7_hello.dar: {e}"))
}

#[test]
fn v7_opens() {
    let _ = open_v7();
}

#[test]
fn v7_lists_one_file() {
    assert_eq!(
        open_v7()
            .entries()
            .iter()
            .filter(|e| e.kind == EntryKind::File)
            .count(),
        1
    );
}

#[test]
fn v7_entry_path_ends_with_hello_txt() {
    assert!(sole_file(&open_v7())
        .path_lossy()
        .ends_with("files/hello.txt"));
}

#[test]
fn v7_entry_size_is_15() {
    assert_eq!(sole_file(&open_v7()).size, 15);
}

#[test]
fn v7_extracts_hello_txt() {
    let r = open_v7();
    let path = sole_file(&r).path;
    let mut r = r;
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

// ── compressed fixtures ──────────────────────────────────────────────────────
//
// All three are DAR format 11.3 archives built with dar 2.8.5 on macOS, each
// holding the same two files compressed with a different codec:
//
//   yes 'dar-forensic gzip bzip2 xz roundtrip corpus line padding 0123456789' \
//       | head -2000 > corpus/payload.txt      # 2000 * 68 = 136000 bytes
//   printf 'tiny\n' > corpus/small.txt
//   dar -c arch_<algo> -R corpus -z<algo> -g payload.txt -g small.txt
//
//   v11_gzip.dar   dar … -zgzip    (per-file compression char 'z')
//   v11_bzip2.dar  dar … -zbzip2   (char 'y')
//   v11_xz.dar     dar … -zxz      (char 'x')
//
// payload.txt (136000 bytes, 99% compressible) is stored compressed; small.txt
// (5 bytes) is too small to benefit and is stored uncompressed.

const PAYLOAD_LINE: &str = "dar-forensic gzip bzip2 xz roundtrip corpus line padding 0123456789\n";

fn expected_payload() -> Vec<u8> {
    PAYLOAD_LINE.repeat(2000).into_bytes()
}

fn open_fixture(name: &str) -> DarReader<Cursor<Vec<u8>>> {
    let path = format!("{DATA_DIR}/{name}");
    let data = std::fs::read(Path::new(&path)).unwrap_or_else(|e| panic!("read {name}: {e}"));
    DarReader::open(Cursor::new(data)).unwrap_or_else(|e| panic!("DarReader::open {name}: {e}"))
}

// The catalogue of a -z archive is itself compressed with the archive codec, so
// listing requires decompressing it; extraction additionally decompresses each
// entry's own stream (small.txt stays stored, so it exercises the 'n' path too).

#[test]
fn gzip_lists_both_entries() {
    let r = open_fixture("v11_gzip.dar");
    let entries = r.entries();
    assert_eq!(entries.len(), 2, "gzip archive must list both files");
    let payload = entries
        .iter()
        .find(|e| e.path_lossy() == "payload.txt")
        .expect("payload.txt present");
    assert_eq!(payload.size, 136_000);
    let small = entries
        .iter()
        .find(|e| e.path_lossy() == "small.txt")
        .expect("small.txt present");
    assert_eq!(small.size, 5);
}

#[test]
fn gzip_extracts_payload_roundtrip() {
    let mut r = open_fixture("v11_gzip.dar");
    let data = r
        .extract("payload.txt")
        .expect("extract gzip-compressed payload.txt");
    assert_eq!(data, expected_payload());
}

#[test]
fn gzip_extracts_stored_small_file() {
    let mut r = open_fixture("v11_gzip.dar");
    let data = r.extract("small.txt").expect("extract stored small.txt");
    assert_eq!(data, b"tiny\n");
}

/// Full round-trip for a compressed fixture: list both entries, then extract the
/// compressed payload and the stored small file.
fn assert_compressed_fixture(name: &str) {
    let r = open_fixture(name);
    let entries = r.entries();
    assert_eq!(entries.len(), 2, "{name} must list both files");
    assert_eq!(
        entries
            .iter()
            .find(|e| e.path_lossy() == "payload.txt")
            .expect("payload.txt present")
            .size,
        136_000
    );
    assert_eq!(
        entries
            .iter()
            .find(|e| e.path_lossy() == "small.txt")
            .expect("small.txt present")
            .size,
        5
    );

    let mut r = open_fixture(name);
    assert_eq!(
        r.extract("payload.txt")
            .expect("extract compressed payload"),
        expected_payload()
    );
    assert_eq!(
        r.extract("small.txt").expect("extract stored small"),
        b"tiny\n"
    );
}

#[test]
fn bzip2_lists_and_extracts() {
    assert_compressed_fixture("v11_bzip2.dar");
}

#[test]
fn xz_lists_and_extracts() {
    assert_compressed_fixture("v11_xz.dar");
}

// ── entry metadata (real fixtures) ────────────────────────────────────────────

#[test]
fn v11_file_exposes_timestamps_and_ctime() {
    // Format 11 (>= 8) records ctime; the dar-created fixture has real mtimes.
    let f = sole_file(&open_v11());
    assert_eq!(f.kind, EntryKind::File);
    assert!(f.ctime.is_some(), "format 11 records a ctime");
    assert!(f.mtime > 0, "fixture has a real modification time");
}

#[test]
fn v7_file_has_no_ctime() {
    // Pre-8 formats do not record ctime, so it must be None.
    assert_eq!(sole_file(&open_v7()).ctime, None);
}

// ── extract_to (streaming) ────────────────────────────────────────────────────

#[test]
fn extract_to_streams_stored_file() {
    let mut r = open_v11();
    let mut out = Vec::new();
    let n = r
        .extract_to("files/hello.txt", &mut out)
        .expect("extract_to");
    assert_eq!(out, b"hello corpus\n");
    assert_eq!(n as usize, out.len());
}

#[test]
fn extract_to_streams_decompressed() {
    let mut r = open_fixture("v11_gzip.dar");
    let mut out = Vec::new();
    let n = r
        .extract_to("payload.txt", &mut out)
        .expect("extract_to gzip");
    assert_eq!(out, expected_payload());
    assert_eq!(n as usize, out.len());
}
