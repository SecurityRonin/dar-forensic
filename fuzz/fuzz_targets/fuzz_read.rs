//! Fuzz target: open arbitrary bytes as a DAR archive and stream every entry's
//! (decompressed) data through `extract_to`, exercising the codec decoders.
//!
//! Invariant: never panics; reads return Ok/Err but never out-of-bounds.
#![no_main]

use dar::DarReader;
use libfuzzer_sys::fuzz_target;
use std::io::{Cursor, Sink};

fuzz_target!(|data: &[u8]| {
    let cursor = Cursor::new(data);
    if let Ok(mut reader) = DarReader::open(cursor) {
        let entries = reader.entries();
        let mut sink: Sink = std::io::sink();
        for entry in entries {
            // Bounded by the per-entry decompression-bomb guard inside the
            // reader; a decode error is a normal outcome, never a panic.
            let _ = reader.extract_to(&entry.path, &mut sink);
        }
    }
});
