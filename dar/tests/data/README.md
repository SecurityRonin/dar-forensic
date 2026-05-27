# tests/data — DAR Corpus

Integration test fixtures produced by `dar 2.8.5` on macOS (Apple Silicon).

## Files

| File | Size | Description |
|------|------|-------------|
| `v11_hello.dar` | 628 B | dar format 11.3, single file `files/hello.txt` |
| `test.dar` | 4.7 KB | Old custom format — kept as wrong-magic fixture only |

## Generating v11_hello.dar

```bash
mkdir -p /tmp/dar_test/files
printf 'hello corpus\n' > /tmp/dar_test/files/hello.txt
dar -c /tmp/archive -R /tmp/dar_test -g files/hello.txt
cp /tmp/archive.1.dar v11_hello.dar
```

Verified contents: `files/hello.txt` = `"hello corpus\n"` (13 bytes).

---

Format quirks and parser implementation notes: [`docs/implementation-notes.md`](../../../docs/implementation-notes.md)
