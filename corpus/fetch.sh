#!/usr/bin/env bash
# Synthesise a minimal valid DAR (Disk ARchiver, SecurityRonin format) corpus archive.
# Format: magic DAR\x00, version 1, entries, then CATL catalog.
# No external tools required — uses only Python 3.
set -euo pipefail

DEST="$(cd "$(dirname "$0")" && pwd)"

python3 - "${DEST}/test.dar" <<'PY'
import struct, sys, zlib

files = [
    ("boot/mbr.bin", bytes(range(256)) * 2),        # 512 B
    ("etc/hostname",  b"corpus-host\n"),
    ("data/pattern",  bytes(range(256)) * 16),       # 4 KiB
]

hdr   = b"DAR\x00" + struct.pack("<II", 1, len(files))
body  = b""
catalog_entries = []
offset = len(hdr)

for (name, data) in files:
    name_b = name.encode()
    crc    = zlib.crc32(data) & 0xFFFFFFFF
    chunk  = struct.pack("<I", len(name_b)) + name_b + struct.pack("<Q", len(data)) + data + struct.pack("<I", crc)
    data_offset = offset + 4 + len(name_b) + 8   # skip name_len, name, data_len
    catalog_entries.append((name_b, data_offset, len(data)))
    body  += chunk
    offset += len(chunk)

catalog  = b"CATL" + struct.pack("<I", len(files))
for (name_b, data_offset, data_len) in catalog_entries:
    catalog += struct.pack("<I", len(name_b)) + name_b
    catalog += struct.pack("<QQ", data_offset, data_len)

with open(sys.argv[1], "wb") as f:
    f.write(hdr + body + catalog)

print(f"wrote {len(hdr + body + catalog)} bytes → {sys.argv[1]}")
PY
