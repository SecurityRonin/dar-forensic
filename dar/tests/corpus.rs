use std::io::Cursor;
use std::path::PathBuf;
use dar::DarReader;

fn corpus_dir() -> Option<PathBuf> {
    std::env::var("CORPUS_DIR").ok().map(PathBuf::from)
}

#[test]
fn corpus_test_dar_opens_and_has_entries() {
    let Some(dir) = corpus_dir() else { return };
    let path = dir.join("test.dar");
    if !path.exists() {
        return;
    }
    let data = std::fs::read(&path).expect("read test.dar");
    let reader = DarReader::open(Cursor::new(&data)).expect("open");
    let entries = reader.entries();
    assert!(!entries.is_empty(), "corpus DAR must contain at least one entry");
}

#[test]
fn corpus_test_dar_extract_all_entries() {
    let Some(dir) = corpus_dir() else { return };
    let path = dir.join("test.dar");
    if !path.exists() {
        return;
    }
    let data = std::fs::read(&path).expect("read test.dar");
    let reader = DarReader::open(Cursor::new(&data)).expect("open");
    for entry in reader.entries() {
        let result = reader.extract(&entry.path);
        assert!(result.is_ok(), "extract({}) must succeed", entry.path);
    }
}
