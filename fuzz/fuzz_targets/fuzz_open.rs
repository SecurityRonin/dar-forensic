#![no_main]

use dar_forensic::DarReader;
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    // DarReader accepts any Read+Seek — use in-memory cursor, no tempfile
    let cursor = Cursor::new(data);
    if let Ok(mut reader) = DarReader::open(cursor) {
        for entry in reader.entries() {
            let _ = reader.extract(&entry.path);
        }
    }
});
