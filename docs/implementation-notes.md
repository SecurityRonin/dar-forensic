# DAR Implementation Notes

Developer notes capturing format quirks and empirically verified behaviour.
Derived from byte-level analysis of a real `dar 2.8.5` v11.3 archive;
authoritative source is the dar source tree.

---

## 1. Magic and infinint encoding

DAR magic is `00 00 00 7b` (big-endian u32 = 123 = `SAUV_MAGIC_NUMBER`), **not**
an ASCII string.

Variable-length integers use the **infinint** encoding. The most common form
is 5 bytes — preamble `0x80` followed by a big-endian u32:

```
80 00 00 00 00  →  0
80 00 00 00 0d  →  13
80 00 00 01 f5  →  501
```

Larger values use a wider group (see §7). This reader targets `u64`, so it
accepts only the 4-byte (`0x80`) and 8-byte (`0x40`) groups; a leading `0x00`
skip-byte or a terminal below `0x40` denotes a >64-bit value and is rejected as
corrupt rather than truncated. A first byte that is `0x00`, or has more than
one bit set, is a format error.

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

---

## 7. Infinint encoding — full variable-length spec

The 5-byte `0x80 XX XX XX XX` form described in §1 is only the most common
case.  DAR uses a general TG=4 variable-length encoding:

1. Consume leading `0x00` **skip bytes** (each adds 8 to the group count).
2. The first non-zero byte is the **terminal**.  It must have exactly one bit
   set; any other value is a format error.
3. `pos = terminal.leading_zeros()` (0-indexed from MSB).
4. `data_bytes = (skip_count × 8 + pos + 1) × 4`
5. Read `data_bytes` big-endian bytes as the integer value.

Common cases:

```
terminal  skip  pos  data_bytes  typical use
0x80       0    0        4       small values (uid, gid, size < 2^32)
0x40       0    1        8       timestamps with epoch > 2^32
0x20       0    2       12       very large sizes (rare)
0x00 0x80  1    0       36       theoretical maximum for 1 skip byte
```

The `0x80` case coincides with the §1 description: terminal `0x80`,
`data_bytes = 4`, value is a big-endian u32.

**Reader contract (u64 or error).** `read_infinint` decodes to `u64`, which
holds at most 8 data bytes. Only the `0x80` (4-byte) and `0x40` (8-byte) groups
fit. Any leading `0x00` skip-byte (≥ 36 bytes) or a terminal below `0x40`
(`pos > 1`, ≥ 12 bytes) denotes a value too large for `u64` and is rejected as
`Corrupt` — never silently truncated. Rejecting the skip-byte form on the first
byte also removes the leading-zero-run DoS and the `(skip × 8 …)` overflow that
the general formula would otherwise allow. No real DAR field (size, offset,
uid/gid, timestamp) exceeds 64 bits, so this loses no legitimate archive.

**Empirically confirmed:** Passware Kit Mobile 2026 v3.0 produces DAR v9
archives (`version_string = "090"`) where `ctime` seconds fields use the
`0x40` terminal (8 data bytes) for timestamps with epoch values that exceed
32 bits.  Parsing fails if only `0x80` is accepted.

---

## 8. `version_string` encoding

Every byte in the `version_string` field is stored as `raw_value + 48` (an
ASCII offset, not a text digit).  The 3-byte (+ NUL) layout is:

```
byte 0 = (version / 256) + 48
byte 1 = (version % 256) + 48
byte 2 = fix              + 48
NUL
```

`version` is a single monotonically-increasing integer (not major.minor).
`fix` is a sub-revision for bug-fix-only format changes.

Decoding examples:

| On-disk bytes | Decode | DAR format |
|---------------|--------|------------|
| `"090"`       | `0×256 + (57−48) = 9`, fix `0` | **format 9** |
| `"0;3"`       | `0×256 + (59−48) = 11`, fix `3` | **format 11.3** |
| `"080"`       | `0×256 + (56−48) = 8`, fix `0` | format 8 |

The semicolon in `"0;3"` is incidental — ASCII 59 = 11 + 48, not a
separator.  The format is purely numeric.

---

## 9. Validated corpus

| File | `version_string` | DAR format | Created by | Entries |
|------|-----------------|-----------|------------|---------|
| `dar/tests/data/v11_hello.dar` | `"0;3"` | **11.3** | dar 2.8.5 on macOS (Apple Silicon) | 1 |
| `userdata.1.dar` (confidential) | `"090"` | **9** | Passware Kit Mobile 2026 v3.0 | 637,698 |

`v11_hello.dar`: standard `seqt_catalogue` escape; used for offset arithmetic
verification.

`userdata.1.dar`: no `seqt_catalogue` escape; catalog located via archive
label scan; timestamps use `0x40` infinint encoding; `cmd_line` field = "N/A".

Both archives share DAR magic `0x0000007b` and the same cat_sig encoding.

---

## 10. Hardening against malicious / corrupted input

Every length and offset in a catalog is attacker-controlled. The reader treats
a `.dar` as hostile and turns each malformed field into a graceful `Corrupt`
error — never a panic, backward seek, or out-of-memory abort. The invariants:

| Field / path | Risk if unchecked | Guard |
|---|---|---|
| infinint width | `(skip×8+pos+1)×4` overflow panic; >64-bit silent truncation | reject leading `0x00` and terminals `< 0x40` (§7) |
| infinint zero-run | unbounded read / skip-count overflow | rejected on the first `0x00` byte |
| `skip(n)` (TLV/FSA/CRC lengths) | `n > i64::MAX` casts negative → backward seek on a File | `i64::try_from(n)` → `Corrupt` |
| `archive_origin + archive_offset` | u64 overflow panic | `checked_add` → `Corrupt` |
| `stored_size` | `vec![0u8; huge]` allocation bomb / OOM abort | bounds-check against actual archive length **before** allocating |
| NUL-terminated path/name | unbounded buffer growth on a NUL-free region | capped at `MAX_NUL_STRING` (64 KiB) |

These are covered by dedicated red/green tests (`tests/synthetic.rs`,
`src/lib.rs` unit tests) and a `cargo fuzz` target (`fuzz/fuzz_targets/fuzz_open.rs`)
exercising `open` + `extract` over arbitrary bytes.
```
