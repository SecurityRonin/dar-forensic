//! Fuzz target: full open + audit + bodyfile pipeline on arbitrary bytes.
//! Invariant: never panics; produces a (possibly empty) anomaly list and a
//! bodyfile, or an Err from open.
#![no_main]

use dar_forensic::{DarAudit, DarBodyfile, DarReader};
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    let cursor = Cursor::new(data);
    if let Ok(reader) = DarReader::open(cursor) {
        // Catalogue anomaly audit — pure metadata, must never panic.
        let _ = reader.audit();
        // Per-entry bodyfile rendering (escaping, permission/timestamp format).
        for entry in reader.entries() {
            let _ = entry.bodyfile();
        }
        // Whole-archive bodyfile export to an in-memory buffer.
        let mut out = Vec::new();
        let _ = reader.write_bodyfile(&mut out);
    }
});
