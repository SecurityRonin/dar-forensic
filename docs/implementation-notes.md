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

> Empirical notes from a v11.3 archive. The two "nlink/field9" infinints are
> actually the FSA-status inode fields, and the layout is version-dependent —
> see §11 (formats 8–11) and §12 (legacy ≤7) for the authoritative, libdar-cited
> per-version field map.

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

> The NUL working-directory path shown below exists only from format 11.1 (§11),
> and the `seqt_catalogue` escape only from format 8 — pre-8 archives are located
> via the end terminateur trailer (§12).

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

`userdata.1.dar`: standard DAR written with sequential tape marks **disabled**
(equivalent to `dar -at`), so the `seqt_catalogue` escape is absent and the
catalog is located by its `ref_data_name` label (= the slice label); timestamps
use the `0x40` infinint encoding; `cmd_line` = "N/A". This is **not** a vendor
format variant — official dar reads such archives via the terminateur trailer.

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

---

## 11. Per-format-version layout (from the authoritative libdar source)

Reverse-documented from libdar at tag `v2.8.5` (its reader handles every older
format, so its `if (reading_ver >= …)` guards are the layout boundaries). File
citations are `src/libdar/<file>:<line>`. This is an independent
description of the on-disk format — no GPL code is reproduced.

**Format version value.** `archive_version::value() = major*256 + fix`
(`archive_version.hpp`), where `major = byte0*256 + byte1` and each header byte
is de-obfuscated as `value = byte - 48` (`archive_version.cpp:55-139`). All
version gates below compare against this `value()`.

**infinint is version-independent** (`real_infinint.cpp:56-114`, `TG = 4`):
`data_bytes = (skip*8 + pos) * 4`. No format changes it, so the u64-or-`Corrupt`
reader (§7) is correct for every format.

**Catalog working-directory ("in_place") path — gated on `>= 11.1`, NOT `>= 10`.**
After the `seqt_catalogue` escape and 10-byte catalog label, a NUL-terminated
path is present only when `reading_ver >= archive_version(11,1)`
(`catalogue.cpp:157`; sequential: `seqt_in_place` mark, `escape_catalogue.cpp:116`).
Formats 8, 9, 10 and **11.0** have no path. (Earlier this reader used `>= 10`,
which would mis-parse the first entry of a format-10 or 11.0 archive.)

**Inode** (`cat_inode.cpp:121-330`), field order for formats ≥ 8:
`flag(1) · uid(inf) · gid(inf) · perm(u16) · atime · mtime · ctime`, then
EA fields if EA-status (`flag & 0x07`) is "full", then FSA fields if
`reading_ver >= 9` and FSA-status (`flag & 0x18`) is set. There is **no
nlink/field9** — hardlinks are separate `cat_mirage`/`cat_etoile` (`'m'`)
entries. `flag & 0x18` is the FSA-status field (`0x10` = full), not a
nlink-present bit.

**Timestamps** (`datetime.cpp:368-387`):
- format **< 9**: a bare seconds infinint (no type byte).
- format **>= 9**: `type_byte('s'|'u'|'n') · seconds(inf) [· sub-second(inf) if 'u'/'n']`.

**FSA** introduced at format **9** (`cat_inode.cpp:264`). In the inode only
`fsa_families(inf)` + `fsa_size(inf)` (+ `fsa_offset(inf)` + `fsa_crc` on a
sealed read) appear; the payload lives at `fsa_offset`. Absent in format 8.

**cat_file** (`cat_file.cpp:108-321`) for a saved file: `size(inf) ·
offset(inf) · storage_size(inf) · file_data_status(1) · compression(1) ·
data_crc`. Since format **10**, a `file_data_status` byte is present even for
**not-saved** files (`cat_file.cpp:222`). CRCs are length-prefixed infinints
since format 8 (`crc.cpp:460`). For `compression == none` the `storage_size`
bytes at `archive_origin + offset` are the raw file content.

**Header (`header_version.cpp:87-444`):** for an unencrypted archive a reader
sees `edition · algo_zip(1) · cmd_line(NUL) · flags(var)` then optional
flag-gated blocks; the crypto-algo byte under `FLAG_SCRAMBLED` exists only for
`edition >= 9` (`header_version.cpp:221`), and the format-10 KDF block
(salt/iteration/hash) is gated on `FLAG_HAS_KDF_PARAM`, not the edition — so it
is invisible when reading unencrypted archives.

### What a format-8 / format-10 reader must do differently

- **Format 8:** timestamps are bare seconds infinints (no type byte); no FSA;
  no crypto byte under SCRAMBLED; no not-saved `file_data_status` byte.
- **Format 10:** like 9 for extraction (tagged timestamps, FSA present), plus a
  not-saved `file_data_status` byte; **still no catalog in_place path** (that
  starts at 11.1).
```

---

## 12. Pre-format-8 (legacy ≤7) layout

Reverse-documented from libdar v2.8.5 read guards (`reading_ver < 8` / `<= 7` /
`> 1`) and validated byte-for-byte against a real dar-2.3.12 format-7 archive
(`dar/tests/data/v7_hello.dar`). Formats ≤7 differ structurally from 8+:

**Slice header & extension** (`header.cpp`): after magic + 10-byte label come a
flag byte and an *extension* byte. `'T'` (format 8+) introduces a TLV list;
`'N'` (none) / `'S'` (size — followed by a slice-size infinint) are pre-8 and
have **no TLV list**, so `archive_origin` = the byte after the extension (16
for a single-TLV-less header). `header_version` for <8 stores a 3-byte
`version_string` (`"NN"` + NUL, no fix byte, no header CRC).

**Catalogue location — the `terminateur` trailer** (`terminateur.cpp:95-138`):
pre-8 archives have **no `seqt_catalogue` escape**. The catalogue is found from
the archive end: count trailing `0xFF` padding (×8 bits), then the first
non-`0xFF` byte contributes its set high bits; `byte_offset = total_bits × 4` is
the distance back to the catalogue-position infinint, which gives the catalogue
start relative to `archive_origin`. (This trailer also exists in 8–11 as a
universal locator; this reader uses it only for ≤7 and the escape scan for 8+.)

**Catalogue framing**: pre-8 has **no 10-byte ref label, no in-place path, no
trailing catalogue CRC** (all gated `reading_ver > 7` in `catalogue.cpp`). The
root entry is named `"root"` (kept in paths, like the format-9 fixtures).

**cat_inode** (`cat_inode.cpp`): `flag(1) · uid(u16) · gid(u16) · perm(u16) ·
atime · mtime`. uid/gid are 2-byte `ntohs` (not infinint) for ≤7; timestamps
are bare seconds infinints (no unit byte, <9); **no ctime** (added at 8); no
FSA (added at 9).

**cat_file** (`cat_file.cpp`, `crc.cpp`): `size · offset · storage_size`, then
**no encryption/compression bytes** and a **fixed 2-byte CRC** (no length
prefix). `storage_size == 0` means the data is stored uncompressed (= logical
size). Data at `archive_origin + offset` is the raw file content.

**Distinct legacy profiles**: formats 2–7 share the above grammar (the only
intra-range split is `reading_ver > 1` for `storage_size`); **format 1** (dar
1.x) additionally omits the EA flag byte and the file CRC and synthesises
storage_size. Format 1 is unvalidated (no dar 1.x binary builds on a modern
toolchain) and treated as best-effort.
