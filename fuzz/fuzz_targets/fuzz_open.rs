//! Fuzz target: feed arbitrary bytes to the parser core's `DarReader::open` and
//! extract every catalogue entry.
//!
//! Invariant: must never panic; may return Ok or Err.
//!
//! Run with:
//!   cargo +nightly fuzz run fuzz_open
#![no_main]

use dar::DarReader;
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    // DarReader accepts any Read+Seek — use an in-memory cursor, no tempfile.
    let cursor = Cursor::new(data);
    if let Ok(mut reader) = DarReader::open(cursor) {
        for entry in reader.entries() {
            let _ = reader.extract(&entry.path);
        }
    }
});
