#!/usr/bin/env python3
"""Static triage helpers for the supplied EX5 artifact.

This script never loads or executes the artifact as code.
"""

from __future__ import annotations

import collections
import math
import struct
import sys
from pathlib import Path


MAGICS = {
    b"MZ": "PE/DOS",
    b"\x7fELF": "ELF",
    b"PK\x03\x04": "ZIP",
    b"\x1f\x8b": "gzip",
    b"7z\xbc\xaf\x27\x1c": "7-Zip",
    b"Rar!\x1a\x07": "RAR",
    b"%PDF": "PDF",
}


def entropy(chunk: bytes) -> float:
    counts = collections.Counter(chunk)
    size = len(chunk)
    return -sum((n / size) * math.log2(n / size) for n in counts.values()) if size else 0.0


def find_all(blob: bytes, needle: bytes) -> list[int]:
    return [i for i in range(len(blob)) if blob.startswith(needle, i)]


def main() -> int:
    path = Path(sys.argv[1] if len(sys.argv) > 1 else "Rick36.ex5")
    blob = path.read_bytes()
    print(f"file={path} size={len(blob)} sha256={__import__('hashlib').sha256(blob).hexdigest()}")
    print(f"unique_bytes={len(set(blob))} common={collections.Counter(blob).most_common(12)}")

    print("header_words_le:")
    for offset in range(0, min(0x100, len(blob)), 4):
        word = struct.unpack_from("<I", blob, offset)[0]
        print(f"  0x{offset:04x}: 0x{word:08x} ({word})")

    print("magic_hits:")
    for magic, name in MAGICS.items():
        hits = find_all(blob, magic)
        if hits:
            print(f"  {name}: {', '.join(hex(i) for i in hits[:32])}")

    print("utf16le_strings:")
    raw = blob.decode("utf-16le", errors="ignore")
    for item in raw.split("\x00"):
        if len(item) >= 2 and any(ch.isalpha() for ch in item):
            print(f"  {item!r}")

    print("entropy_256_byte_chunks:")
    for offset in range(0, len(blob), 0x100):
        chunk = blob[offset : offset + 0x100]
        print(f"  0x{offset:04x}: {entropy(chunk):.4f}")

    print("flag_markers:")
    lowered = blob.lower()
    for marker in (b"flag{", b"ctf{", b"kma", b"kmactf", b"virus", b"http", b"powershell"):
        hits = find_all(lowered, marker)
        if hits:
            print(f"  {marker!r}: {', '.join(hex(i) for i in hits)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
