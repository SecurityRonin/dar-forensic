# tests/data — DAR Corpus

Real DAR archive fixtures, each built with the matching upstream `dar` release.
All carry the genuine DAR magic `00 00 00 7b` and are exercised by
`tests/real_images.rs`. They are tiny and committed so the real-archive tests
run in CI and are independently reproducible.

## Files

| File | Size | DAR format | Built with | Contents |
|------|------|-----------|------------|----------|
| `v7_hello.dar`  | 143 B | format 7 (`"07"`)   | dar 2.3.12 | `files/hello.txt` = `"hello format 7\n"` (15 B) |
| `v8_hello.dar`  | 425 B | format 8.1 (`"081"`) | dar 2.4.24 | `files/hello.txt` = `"hello format 8\n"` (15 B) |
| `v9_hello.dar`  | 578 B | format 9 (`"090"`)   | dar 2.5.3  | `files/hello.txt` = `"hello format 9\n"` (15 B) |
| `v10_hello.dar` | 579 B | format 10.1 (`"0:1"`) | dar 2.6.16 | `files/hello.txt` = `"hello format 10\n"` (16 B) |
| `v11_hello.dar` | 628 B | format 11.3 (`"0;3"`) | dar 2.8.5  | `files/hello.txt` = `"hello corpus\n"` (13 B) |

The format version is the header `version_string`, each byte = `value + 48`
(`"081"` → 8.1, `"0:1"` → 10.1 since `:` = 58 = 10 + 48, `"0;3"` → 11.3).

## Generating the fixtures

dar 2.8.5 was already installed; 2.4.24, 2.5.3 and 2.6.16 were built from their
SourceForge release tarballs (the older builds use
`--disable-nodump-flag`/`--disable-*-linking` to avoid optional deps). dar
2.3.12 (format 7) does not compile on a modern toolchain, so it was built in a
`gcc:4.9` container. For each:

```bash
mkdir -p /tmp/corpus/files
printf 'hello ...\n' > /tmp/corpus/files/hello.txt
<dar-X.Y.Z>/dar -Q -c /tmp/archive -R /tmp/corpus -g files/hello.txt
cp /tmp/archive.1.dar vN_hello.dar
```

Sources: <https://sourceforge.net/projects/dar/files/dar/>

---

Format quirks and the per-version layout (from libdar): [`docs/implementation-notes.md`](../../../docs/implementation-notes.md) §11.
