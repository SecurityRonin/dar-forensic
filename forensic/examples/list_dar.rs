// A runnable demo, not library production code: it prints a usage error and
// exits via `expect`/`panic` rather than threading a Result through `main`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use dar_forensic::DarReader;
use std::env;
use std::fs::File;
use std::io::BufReader;

fn main() {
    let path = env::args().nth(1).expect("usage: list_dar <file.dar>");
    let file = File::open(&path).unwrap_or_else(|e| panic!("open {path}: {e}"));
    let reader = BufReader::new(file);
    let dar = DarReader::open(reader).unwrap_or_else(|e| panic!("DarReader::open: {e}"));
    let entries = dar.entries();
    println!("{} entries", entries.len());
    for e in entries.iter().take(10) {
        println!("  {:?}  {}  ({} bytes)", e.kind, e.path_lossy(), e.size);
    }
    if entries.len() > 10 {
        println!("  ... ({} more)", entries.len() - 10);
    }
}
