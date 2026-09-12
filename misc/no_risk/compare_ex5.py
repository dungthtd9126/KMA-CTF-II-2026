#!/usr/bin/env python3
"""Compare EX5 container metadata and payload statistics without executing it."""

from __future__ import annotations

import collections
import hashlib
import math
import struct
import sys
from pathlib import Path


def entropy(data: bytes) -> float:
    counts = collections.Counter(data)
    return -sum((n / len(data)) * math.log2(n / len(data)) for n in counts.values())


def u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def main() -> int:
    paths = [Path(arg) for arg in sys.argv[1:]] or [Path("Rick36.ex5")]
    for path in paths:
        data = path.read_bytes()
        body = data[0x2F4:]
        blocks = [body[i : i + 16] for i in range(0, len(body) - 15, 16)]
        repeats = [(block.hex(), count) for block, count in collections.Counter(blocks).most_common() if count > 1]
        print(f"=== {path} ===")
        print(f"size={len(data):#x} sha256={hashlib.sha256(data).hexdigest()}")
        print("header:", " ".join(f"{off:#x}={u32(data, off):#x}" for off in range(0, 0xA4, 4) if u32(data, off)))
        print(f"body={len(body):#x} entropy={entropy(body):.5f} unique={len(set(body))} zero={body.count(0)}")
        print(f"body_head={body[:32].hex()} body_tail={body[-32:].hex()}")
        print(f"repeat16={repeats[:8]}")
        print("chunk_entropy:", " ".join(f"{i:#x}:{entropy(body[i:i+0x100]):.3f}" for i in range(0, len(body), 0x100)))


if __name__ == "__main__":
    raise SystemExit(main())
