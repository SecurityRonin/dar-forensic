# tests/data — DAR Corpus

Real DAR archive fixtures, built with the `dar` tool on macOS (Apple Silicon).
Both carry the genuine DAR magic `00 00 00 7b` and are exercised by
`tests/real_images.rs`. They are tiny and committed so the real-archive tests
run in CI and are independently reproducible.

## Files

| File | Size | DAR format | Contents |
|------|------|-----------|----------|
| `v9_hello.dar` | 578 B | format 9 (`version_string` `"090"`) | `files/hello.txt` = `"hello format 9\n"` (15 B) |
| `v11_hello.dar` | 628 B | format 11.3 (`version_string` `"0;3"`) | `files/hello.txt` = `"hello corpus\n"` (13 B) |

## Generating v11_hello.dar (dar 2.8.5)

```bash
mkdir -p /tmp/dar_test/files
printf 'hello corpus\n' > /tmp/dar_test/files/hello.txt
dar -c /tmp/archive -R /tmp/dar_test -g files/hello.txt
cp /tmp/archive.1.dar v11_hello.dar
```

## Generating v9_hello.dar (dar 2.5.3, built from source)

```bash
mkdir -p /tmp/v9_corpus/files
printf 'hello format 9\n' > /tmp/v9_corpus/files/hello.txt
/path/to/dar253/bin/dar -c /tmp/v9_archive -R /tmp/v9_corpus -g files/hello.txt
cp /tmp/v9_archive.1.dar v9_hello.dar
```

dar 2.5.3 source: <https://sourceforge.net/projects/dar/files/dar/2.5.3/>

---

Format quirks and parser implementation notes: [`docs/implementation-notes.md`](../../../docs/implementation-notes.md)
