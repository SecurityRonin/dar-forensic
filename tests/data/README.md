# tests/data — DAR Corpus

Real DAR archive fixtures, each built with the matching upstream `dar` (or
`dar_xform`) release. All carry the genuine DAR magic `00 00 00 7b` and are
exercised by [`../../forensic/tests/real_images.rs`](../../forensic/tests/real_images.rs).
They are tiny and committed so the real-archive tests run in CI and are
independently reproducible.

This is the single repo-root `tests/data/` for the whole workspace (`core/` +
`forensic/`). Workspace members reach these fixtures with a relative path from
their own `tests/` directory — `forensic/tests/real_images.rs` resolves the dir
via `concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data")`.

Fleet machine-index cross-reference: [`issen/docs/corpus-catalog.md`](../../../issen/docs/corpus-catalog.md).

`dar`/`dar_xform` versions used: 2.3.12 (format 7), 2.4.24 (format 8.1),
2.5.3 (format 9), 2.6.16 (format 10.1), 2.8.5 (format 11.3 + all codec/multislice
/xform fixtures), all on macOS Apple Silicon. 2.8.5 was already installed;
2.4.24 / 2.5.3 / 2.6.16 were built from their SourceForge release tarballs (with
`--disable-nodump-flag` / `--disable-*-linking` to avoid optional deps); 2.3.12
does not compile on a modern toolchain and was built in a `gcc:4.9` container.
Sources: <https://sourceforge.net/projects/dar/files/dar/>.

The format version is the header `version_string`, each byte = `value + 48`
(`"081"` → 8.1, `"0:1"` → 10.1 since `:` = 58 = 10 + 48, `"0;3"` → 11.3).

## Single-file version fixtures

Each holds one `hello.txt` and validates a distinct on-disk format generation.

| File | MD5 | DAR format | Built with | Contents |
|------|-----|-----------|------------|----------|
| `v7_hello.dar`  | `0d3e7daf50418e62b56dead2f4e59fd1` | format 7 (`"07"`)    | dar 2.3.12 | `files/hello.txt` = `"hello format 7\n"` (15 B) |
| `v8_hello.dar`  | `d1b1d737dbf27fe8af5a4a15c08e7fee` | format 8.1 (`"081"`) | dar 2.4.24 | `files/hello.txt` = `"hello format 8\n"` (15 B) |
| `v9_hello.dar`  | `0bc5e93f4370dbe39cb1410c10e35d1c` | format 9 (`"090"`)   | dar 2.5.3  | `files/hello.txt` = `"hello format 9\n"` (15 B) |
| `v10_hello.dar` | `e27dbfffff0a13377b3f9674f2b79e21` | format 10.1 (`"0:1"`) | dar 2.6.16 | `files/hello.txt` = `"hello format 10\n"` (16 B) |
| `v11_hello.dar` | `cd01c1a72e8831a8bb7aed0593123801` | format 11.3 (`"0;3"`) | dar 2.8.5  | `files/hello.txt` = `"hello corpus\n"` (13 B) |

Generator (substitute the version-specific binary and payload string):

```bash
# v11_hello.dar  (dar 2.8.5)
mkdir -p /tmp/dar_test/files
printf 'hello corpus\n' > /tmp/dar_test/files/hello.txt
dar -c /tmp/archive -R /tmp/dar_test -g files/hello.txt
cp /tmp/archive.1.dar v11_hello.dar

# v9_hello.dar  (dar 2.5.3)
printf 'hello format 9\n' > /tmp/v9_corpus/files/hello.txt
<dar-2.5.3>/bin/dar -c /tmp/v9_archive -R /tmp/v9_corpus -g files/hello.txt
cp /tmp/v9_archive.1.dar v9_hello.dar

# v8_hello.dar  (dar 2.4.24)
printf 'hello format 8\n' > /tmp/v8_corpus/files/hello.txt
<dar-2.4.24>/dar -Q -c /tmp/v8_archive -R /tmp/v8_corpus -g files/hello.txt
cp /tmp/v8_archive.1.dar v8_hello.dar

# v10_hello.dar  (dar 2.6.16, built --disable-nodump-flag)
printf 'hello format 10\n' > /tmp/v10_corpus/files/hello.txt
<dar-2.6.16>/dar -Q -c /tmp/v10_archive -R /tmp/v10_corpus -g files/hello.txt
cp /tmp/v10_archive.1.dar v10_hello.dar

# v7_hello.dar  (dar 2.3.12, gcc:4.9 container)
printf 'hello format 7\n' > /src/files/hello.txt
<dar-2.3.12>/dar -Q -c /work/v7 -R /src -g files/hello.txt
cp /work/v7.1.dar v7_hello.dar
```

Format quirks per generation (format 7 = `terminateur`-located catalog, 2-byte
uid/gid, no ctime; format 8 = bare-seconds timestamps, no FSA; format 10 = no
in-place catalog path): see
[`docs/implementation-notes.md`](../../docs/implementation-notes.md) §§11–12.

## Codec fixtures (format 11.3, dar 2.8.5)

Each holds the same two files — `payload.txt` (136 000 B, 99 % compressible,
stored compressed) and `small.txt` (5 B `"tiny\n"`, too small to benefit, stored
uncompressed) — under a different compression codec. The single-stream codecs
(`-zgzip` / `-zbzip2` / `-zxz` / `-zzstd`) compress the catalogue + each entry as
one stream; lz4 and lzo are always per-block framed.

| File | MD5 | dar flag | Codec mode |
|------|-----|----------|------------|
| `v11_gzip.dar`  | `206dd07a2b71fdcaad9da20c25d98907` | `-zgzip`  | single-stream (per-file char `z`) |
| `v11_bzip2.dar` | `11d58b213484710f1f8dcb82b3cfb2d7` | `-zbzip2` | single-stream (char `y`) |
| `v11_xz.dar`    | `8b7ab7b6416e52f5eb5f2b7204539731` | `-zxz`    | single-stream (char `x`) |
| `v11_zstd.dar`  | `69781af0db25ba02ba4496874429c6a5` | `-zzstd`  | single-stream |
| `v11_lz4.dar`   | `8e0489d06e6ca6110952486c517a63a4` | `-zlz4`   | per-block (default 240 kio block; payload fits one) |
| `v11_lzo.dar`   | `1ac6cb7f2b7481743d89fcdb248a245b` | `-zlzo`   | per-block (raw lzo1x blocks) |
| `pb_gzip.dar`   | `76f908e890d2557b36aaf71c278307f1` | `-zgzip:6:1024` | per-block gzip, 1 KiB blocks |
| `pb_zstd.dar`   | `af6fd268130b50dd2c3b1c916d538729` | `-zzstd:6:1024` | per-block zstd, 1 KiB blocks |
| `pb_lz4.dar`    | `76fdb4e3ca516671121a97cb41f62635` | `-zlz4:9:1024`  | per-block lz4, 1 KiB blocks (~133 blocks) |

Generator (all dar 2.8.5; the same corpus feeds every codec):

```bash
mkdir -p corpus
yes 'dar-forensic gzip bzip2 xz roundtrip corpus line padding 0123456789' \
    | head -2000 > corpus/payload.txt          # 2000 * 68 = 136000 bytes
printf 'tiny\n' > corpus/small.txt

# single-stream codecs
dar -c arch_gzip  -R corpus -zgzip  -g payload.txt -g small.txt && cp arch_gzip.1.dar  v11_gzip.dar
dar -c arch_bzip2 -R corpus -zbzip2 -g payload.txt -g small.txt && cp arch_bzip2.1.dar v11_bzip2.dar
dar -c arch_xz    -R corpus -zxz    -g payload.txt -g small.txt && cp arch_xz.1.dar    v11_xz.dar
dar -c arch_zstd  -R corpus -zzstd  -g payload.txt -g small.txt && cp arch_zstd.1.dar  v11_zstd.dar
dar -c arch_lz4   -R corpus -zlz4   -g payload.txt -g small.txt && cp arch_lz4.1.dar   v11_lz4.dar
dar -c arch_lzo   -R corpus -zlzo   -g payload.txt -g small.txt && cp arch_lzo.1.dar   v11_lzo.dar

# explicit per-block (algo:level:blocksize-in-kiB)
dar -c arch_pbgz  -R corpus -zgzip:6:1024 -g payload.txt -g small.txt && cp arch_pbgz.1.dar  pb_gzip.dar
dar -c arch_pbzs  -R corpus -zzstd:6:1024 -g payload.txt -g small.txt && cp arch_pbzs.1.dar  pb_zstd.dar
dar -c arch_pblz4 -R corpus -zlz4:9:1024  -g payload.txt -g small.txt && cp arch_pblz4.1.dar pb_lz4.dar
```

## Multi-slice fixture (format 11.3, dar 2.8.5)

A real `dar -s 1k` STORED archive split into four 1 KiB slices, where `big.bin`
(2600 B, deterministic pattern `i % 251`) spans slice boundaries. Listing needs
the catalogue in the last slice; extraction reassembles `big.bin` across slices.

| File | MD5 |
|------|-----|
| `ms_stored.1.dar` | `d6e71a4b34cefb4a603bcd56a26465ba` |
| `ms_stored.2.dar` | `efb5234e8d869e6c2caab96637d11dd7` |
| `ms_stored.3.dar` | `dff6507bce57c6adcf415d9d43e8d977` |
| `ms_stored.4.dar` | `a35ccfb98ea9952e155ab1055c53ed4e` |

Contents: `big.bin` (2600 B, byte *i* = `i % 251`) and `note.txt` =
`"multi-slice corpus\n"`.

```bash
mkdir -p ms_corpus
# big.bin: 2600 bytes, byte i = i % 251
python3 -c 'import sys; sys.stdout.buffer.write(bytes(i%251 for i in range(2600)))' > ms_corpus/big.bin
printf 'multi-slice corpus\n' > ms_corpus/note.txt
dar -c ms_stored -R ms_corpus -s 1k -g big.bin -g note.txt   # -> ms_stored.{1,2,3,4}.dar
```

## dar_xform re-slice fixture (dar 2.8.5)

`xform_tapeoff.dar` (MD5 `e2156373a111882ddbaa269c35dd04a5`) is a `dar -at`
(tape-marks-off) archive re-wrapped by `dar_xform`, which regenerates the slice
`internal_name`. The catalogue still references the archive's preserved
`data_name`, so locating it requires matching the `data_name` (slice-header TLV
type `0x0003`), not the slice's `internal_name` label.

Contents: `hello.txt` = `"tape-marks-off then dar_xform\n"` and `data.bin`
(800 B, byte *i* = `i % 251`).

```bash
mkdir -p xf_corpus
printf 'tape-marks-off then dar_xform\n' > xf_corpus/hello.txt
python3 -c 'import sys; sys.stdout.buffer.write(bytes(i%251 for i in range(800)))' > xf_corpus/data.bin
dar      -at -c xf_src   -R xf_corpus -g hello.txt -g data.bin   # tape marks off
dar_xform xf_src xform_tapeoff                                   # re-wrap -> xform_tapeoff.1.dar
cp xform_tapeoff.1.dar xform_tapeoff.dar
```
