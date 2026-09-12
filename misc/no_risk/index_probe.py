#!/usr/bin/env python3
"""Probe position-derived byte transforms without executing the EX5 file."""

from __future__ import annotations

import re
import sys
from pathlib import Path


MARKERS = (b"flag{", b"ctf{", b"kmactf{", b"KMACTF{", b"MeePwn")


def runs(data: bytes, minimum: int = 10) -> list[tuple[int, bytes]]:
    return [(m.start(), m.group()) for m in re.finditer(rb"[ -~]{%d,}" % minimum, data)]


def report(label: str, data: bytes) -> None:
    lowered = data.lower()
    hits = [(marker.decode("ascii", "replace"), lowered.find(marker.lower())) for marker in MARKERS]
    found = [(name, pos) for name, pos in hits if pos >= 0]
    text_runs = runs(data)
    ranked = sorted(text_runs, key=lambda item: len(item[1]), reverse=True)[:3]
    if found or ranked and len(ranked[0][1]) >= 24:
        print(label, "hits=", found, "runs=", [(hex(p), r[:160]) for p, r in ranked])


def decode(data: bytes, mode: str, shift: int = 0, period: int | None = None) -> bytes:
    out = bytearray(len(data))
    for i, value in enumerate(data):
        index = i + shift
        if period is not None:
            index %= period
        key = index & 0xFF
        if mode == "xor":
            out[i] = value ^ key
        elif mode == "add":
            out[i] = (value + key) & 0xFF
        else:
            out[i] = (value - key) & 0xFF
    return bytes(out)


def main() -> int:
    path = Path(sys.argv[1] if len(sys.argv) > 1 else "Rick36.ex5")
    blob = path.read_bytes()
    regions = {"body": blob[0x2F4:], "tail": blob[0x2E8:]}

    for region_name, region in regions.items():
        for mode in ("xor", "add", "sub"):
            for shift in range(256):
                report(f"{region_name} {mode} shift={shift}", decode(region, mode, shift))

        for period in (2, 4, 8, 16, 32, 64, 128, 256, 512, 1024):
            report(f"{region_name} xor period={period}", decode(region, "xor", period=period))

        for scale in (2, 4, 8, 16, 32, 64):
            data = bytes(value ^ (((i * scale) & 0xFF)) for i, value in enumerate(region))
            report(f"{region_name} xor scale={scale}", data)

        for offset in range(8):
            data = bytes(value ^ (((i // 2 + offset) & 0xFF)) for i, value in enumerate(region))
            report(f"{region_name} xor half-index offset={offset}", data)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
