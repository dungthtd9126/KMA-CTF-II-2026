#!/usr/bin/env python3
"""Find embedded standard streams without executing the EX5 artifact."""

from __future__ import annotations

import base64
import bz2
import gzip
import lzma
import re
import zlib
from pathlib import Path


def try_streams(blob: bytes) -> None:
    decoders = {
        "zlib": lambda x: zlib.decompress(x),
        "deflate-raw": lambda x: zlib.decompress(x, -15),
        "gzip": gzip.decompress,
        "bz2": bz2.decompress,
        "lzma": lzma.decompress,
    }
    for offset in range(len(blob)):
        tail = blob[offset:]
        for name, decoder in decoders.items():
            try:
                plain = decoder(tail)
            except Exception:
                continue
            if len(plain) >= 16:
                print(f"stream={name} offset=0x{offset:x} size={len(plain)} head={plain[:32].hex()}")


def try_xor_signatures(blob: bytes) -> None:
    signatures = {
        b"PK\x03\x04": "zip",
        b"\x7fELF": "elf",
        b"MZ": "pe",
        b"\x1f\x8b": "gzip",
        b"\x78\x9c": "zlib",
        b"\x78\xda": "zlib",
        b"flag{": "flag",
        b"CTF{": "ctf",
    }
    for key in range(256):
        decoded = bytes(value ^ key for value in blob)
        for signature, name in signatures.items():
            if signature in decoded:
                print(f"xor8 key=0x{key:02x} signature={name} offset=0x{decoded.index(signature):x}")


def main() -> None:
    blob = Path("Rick36.ex5").read_bytes()
    try_streams(blob)
    try_xor_signatures(blob)
    for match in re.finditer(rb"(?:[A-Za-z0-9+/]{32,}={0,2})", blob):
        try:
            decoded = base64.b64decode(match.group(), validate=True)
        except Exception:
            continue
        if len(decoded) >= 16:
            print(f"base64 offset=0x{match.start():x} encoded={len(match.group())} decoded={len(decoded)}")


if __name__ == "__main__":
    main()
