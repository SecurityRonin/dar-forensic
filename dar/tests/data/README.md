# tests/data — DAR Corpus

Real archives produced by `dar 2.8.5` on macOS, used as an independent
doer-checker corpus for the Rust parser.

## Files

| File | Size | Description |
|------|------|-------------|
| `v11_hello.dar` | 628 B | dar format 11.3, single file: `files/hello.txt` |
| `test.dar` | 4.7 KB | Old SecurityRonin custom format — kept as wrong-magic fixture only |

## Generating v11_hello.dar

```bash
mkdir -p /tmp/dar_test/files
printf 'hello corpus\n' > /tmp/dar_test/files/hello.txt
dar -c /tmp/archive -R /tmp/dar_test -g files/hello.txt
cp /tmp/archive.1.dar v11_hello.dar
```

Verified contents: `files/hello.txt` = `"hello corpus\n"` (13 bytes).

---

## DAR Format Notes (v11.3 — reverse-engineered from v11_hello.dar)

These notes capture non-obvious findings from byte-level analysis. The
authoritative source is the dar source tree; these notes record the
discoveries needed to write a correct parser without it.

### Magic

```
00 00 00 7b   # SAUV_MAGIC_NUMBER = 123, big-endian u32
```

### Infinint encoding

Always exactly **5 bytes**: `0x80 XX XX XX XX`

- Preamble byte must be `0x80`.
- Value = last 4 bytes as big-endian u32.

```
80 00 00 00 00  →  0
80 00 00 00 0d  →  13
80 00 00 01 f5  →  501
```

### Slice header layout

```
[4]   magic = 00 00 00 7b
[10]  internal_name label (opaque)
[1]   flag = 0x54
[1]   ext_char = 0x54 ('T')
[5]   TLV count (infinint)
  For each TLV:
    [2]  type (big-endian u16)   — type 3 = tlv_data_name
    [5]  data length (infinint)
    [N]  data
```

**archive_origin** = byte position immediately after the TLV block (i.e. the
first byte after the last TLV entry). All `archive_offset` values in the
catalog are relative to this position.

For `v11_hello.dar`: one TLV (type 3, 10 bytes), so header = 4+10+1+1+5+2+5+10 = **38 bytes**.

What follows the TLV block (archive_version string, cmd_line, etc.) is **part
of the addressed space**, not the header. The parser does not need to parse
these fields; it scans for `seqt_catalogue` instead.

### Escape sequences

6-byte markers embedded in the archive body:

```
AD FD EA 77 21 XX   — escape type XX:
  0x44  'D'  seqt_data_name    → skip 10-byte label
  0x50  'P'  seqt_in_place     → skip NUL-terminated path
  0x46  'F'  seqt_file         → followed by cat_sig + NUL-name + inode
  0x53  'S'  seqt_saved
  0x52  'R'  seqt_real_data    → followed by infinint(crc_size) + CRC
  0x43  'C'  seqt_catalogue    → start of catalog
  0x73  's'  (undocumented)
```

### Permissions field

Stored as a **2-byte big-endian u16**, **not** an infinint.

```
01 ed  →  493  →  0o755
01 a4  →  420  →  0o644
```

### Inode structure

First byte is the **flags** byte. Bit 4 (`0x10`) is the critical bit:

```
flags & 0x10 == 0  →  31-byte inode  (virtual entries like <ROOT>)
flags & 0x10 != 0  →  41-byte inode  (real filesystem entries)
```

Fixed layout:

```
[1]   flags
[5]   uid     (infinint)
[5]   gid     (infinint)
[2]   perms   (big-endian u16)
[1]   ctime precision ('s' = seconds)
[5]   ctime   (infinint, epoch seconds)
[1]   mtime precision
[5]   mtime
[1]   atime precision
[5]   atime
                         ← inode ends here when bit 4 clear (31 bytes)
[5]   nlink   (infinint) ← only when bit 4 set
[5]   field9  (infinint) ← only when bit 4 set
                         ← inode ends here when bit 4 set (41 bytes)
```

After the inode, **if bit 4 is set**, one FSA block follows:

```
[5]   family_tag  (infinint — value varies per filesystem; ignore for parsing)
[5]   data_size   (infinint)
[N]   data        (data_size bytes)
```

Bit 4 therefore governs three things simultaneously: presence of
nlink/field9, presence of the FSA block, and apparently marks real vs.
virtual catalog entries.

### archive_offset and extraction

The `archive_offset` in each file's catalog entry is a byte offset **from
`archive_origin`** pointing **directly at the raw file bytes** — not at the
data-section header.

```
raw_data_position = archive_origin + archive_offset
```

For `v11_hello.dar`:
- `archive_origin` = 38 (0x0026)
- `archive_offset` = 230 (0xe6)
- raw data at 38 + 230 = 268 (0x010c) ✓ — first byte of `"hello corpus\n"`

The data-section header in the archive body (`infinint(data_size) + encryption
+ compression + infinint(crc_size) + CRC`) precedes the raw bytes in the body
stream but is **not used during extraction** — the catalog supplies all sizes
directly.

### File-specific catalog fields (after inode + optional FSA)

```
[5]   data_size       (infinint) — uncompressed byte count
[5]   archive_offset  (infinint) — from archive_origin to raw bytes
[5]   stored_size     (infinint) — bytes in archive (= data_size if uncompressed)
[1]   encryption_flag            — 0x00 = none
[1]   compression_char           — 'n' = none, 'z' = zlib, etc.
[5]   crc_size        (infinint)
[N]   crc_data        (crc_size bytes)
```

### Catalog structure

Located by scanning for the `seqt_catalogue` escape (`AD FD EA 77 21 43`).
After the 6-byte escape:

```
[10]  catalog label (opaque)
[NUL] working-directory path (NUL-terminated string)
      catalog entries...
```

Each entry begins with a **cat_sig** byte:

```
entry_type = (cat_sig & 0x1f) | 0x60
  'd'  directory — NUL-name + inode [+ FSA] ; push to dir stack
  'f'  file      — NUL-name + inode [+ FSA] + file-specific fields
  'z'  EOD       — pop dir stack; stop when depth reaches 0
```

Catalog termination uses a **depth counter** (not a length prefix):
every directory entry (including `<ROOT>`) increments depth; every EOD
decrements it. When depth hits zero the root is closed and parsing stops.
The virtual `<ROOT>` entry has name `"<ROOT>"` and is excluded from file paths.
