# DAR Implementation Notes

Developer notes capturing format quirks and empirically verified behaviour.
Derived from byte-level analysis of a real `dar 2.8.5` v11.3 archive;
authoritative source is the dar source tree.

---

## 1. Magic and infinint encoding

DAR magic is `00 00 00 7b` (big-endian u32 = 123 = `SAUV_MAGIC_NUMBER`), **not**
an ASCII string.

All variable-length integers use the **infinint** encoding: always exactly
5 bytes, preamble `0x80` followed by a big-endian u32.

```
80 00 00 00 00  →  0
80 00 00 00 0d  →  13
80 00 00 01 f5  →  501
```

Anything other than `0x80` in the first byte is a format error.

---

## 2. archive_origin — where offsets are measured from

The `archive_offset` stored in each file's catalog entry is **not** measured
from byte 0. It is measured from the byte immediately after the TLV block
in the slice header, called `archive_origin` in the parser.

Slice header layout:

```
[4]   magic
[10]  internal_name label (opaque bytes)
[1]   flag
[1]   ext_char
[5]   TLV count (infinint)
  ↻ for each TLV:
    [2]  type  (big-endian u16)  — type 3 = tlv_data_name
    [5]  len   (infinint)
    [N]  data
← archive_origin
```

The fields that follow in the file (archive_version string, cmd_line,
flag2, …) are **inside the addressed space**, not part of the header.
The parser does not parse them; it scans forward for `seqt_catalogue`.

Empirical verification with `v11_hello.dar`:
- One TLV (type 3, 10 bytes) → `archive_origin` = 38 (0x0026)
- Catalog reports `archive_offset` = 230 (0xe6) for `hello.txt`
- Raw data at 38 + 230 = 268 (0x010c) ✓ — first byte of `"hello corpus\n"`

---

## 3. archive_offset points at raw bytes, not the data-section header

The archive body contains a data-section header just before each file's raw
bytes:

```
infinint(data_size) + byte(encryption) + byte(compression) +
infinint(crc_size) + crc_bytes + <raw file bytes>
```

`archive_offset` skips this header and points **directly at the raw bytes**.
Extraction is therefore:

```
seek(archive_origin + archive_offset)
read(stored_size bytes)
decompress if compression_char != 'n'
```

The catalog already supplies `data_size`, `stored_size`, and
`compression_char` — the body data-section header is redundant for
extraction purposes and is not re-parsed.

---

## 4. Inode bit 4 governs layout size AND FSA presence

The first byte of every inode is a **flags** byte. Bit 4 (`0x10`) controls
three things simultaneously:

| bit 4 | inode size | nlink / field9 | FSA block |
|-------|-----------|----------------|-----------|
| 0     | 31 bytes  | absent         | absent    |
| 1     | 41 bytes  | present        | follows   |

Fixed inode layout:

```
[1]   flags
[5]   uid     (infinint)
[5]   gid     (infinint)
[2]   perms   (big-endian u16 — NOT an infinint)
[1]   ctime precision  ('s' = seconds)
[5]   ctime            (infinint, epoch seconds)
[1]   mtime precision
[5]   mtime
[1]   atime precision
[5]   atime
                          ← ends here when (flags & 0x10) == 0  (31 bytes)
[5]   nlink   (infinint)  ← only when (flags & 0x10) != 0
[5]   field9  (infinint)  ← only when (flags & 0x10) != 0
                          ← ends here when (flags & 0x10) != 0  (41 bytes)
```

The virtual `<ROOT>` catalog entry uses `flags = 0x03` (bit 4 clear) and
produces a 31-byte inode. Real filesystem entries use `flags = 0x13`
(bit 4 set) and produce 41-byte inodes.

**Permissions** are stored as a 2-byte big-endian u16, not an infinint:

```
01 ed  →  493  →  0o755
01 a4  →  420  →  0o644
```

---

## 5. FSA block format

When `(flags & 0x10) != 0`, one FSA block follows the inode:

```
[5]   family_tag  (infinint — varies per filesystem type; skip it)
[5]   data_size   (infinint)
[N]   data        (data_size bytes)
```

The `family_tag` value differs between real filesystem entries (129 for a
directory, 264 for a regular file in the observed corpus) and has no
meaning for extraction. Only `data_size` is needed to skip past the block.

---

## 6. Catalog structure and termination

The catalog is located by scanning for the 6-byte escape:

```
AD FD EA 77 21 43   (seqt_catalogue)
```

Immediately after the escape:

```
[10]  catalog label (opaque)
[NUL] working-directory path (NUL-terminated)
      entries...
```

Each entry starts with a **cat_sig** byte. Entry type:

```
entry_type = (cat_sig & 0x1f) | 0x60
  'd'  directory — NUL-name + inode [+ FSA]  → push dir to stack
  'f'  file      — NUL-name + inode [+ FSA] + file-specific fields
  'z'  EOD       → pop dir from stack
  other          → slice trailer boundary; stop parsing
```

Termination uses a **depth counter**, not a length prefix. Every directory
entry (including `<ROOT>`) increments depth; every EOD decrements it.
When depth reaches zero the root is closed and catalog parsing is complete.
The first non-`d/f/z` byte (slice trailer begins with `0x80` = infinint
preamble) is reliably distinguishable and acts as a hard stop.

File-specific catalog fields (after inode + optional FSA):

```
[5]   data_size       (infinint) — uncompressed byte count
[5]   archive_offset  (infinint) — from archive_origin to raw bytes
[5]   stored_size     (infinint) — bytes in archive; = data_size if uncompressed
[1]   encryption_flag            — 0x00 = none
[1]   compression_char           — 'n' = none
[5]   crc_size        (infinint)
[N]   crc_data        (crc_size bytes)
```
