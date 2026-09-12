#!/usr/bin/env python3
"""Probe simple bit-plane encodings; never executes the artifact."""

from pathlib import Path


def printable_runs(data: bytes, minimum: int = 8) -> list[str]:
    out: list[str] = []
    current = bytearray()
    for value in data:
        if 32 <= value < 127:
            current.append(value)
        else:
            if len(current) >= minimum:
                out.append(current.decode("ascii"))
            current.clear()
    if len(current) >= minimum:
        out.append(current.decode("ascii"))
    return out


def bits_to_bytes(bits: list[int], reverse: bool) -> bytes:
    result = bytearray()
    for offset in range(0, len(bits) - 7, 8):
        value = 0
        group = bits[offset : offset + 8]
        for bit in group:
            value = (value << 1) | bit if not reverse else (value >> 1) | (bit << 7)
        result.append(value)
    return bytes(result)


def main() -> None:
    blob = Path("Rick36.ex5").read_bytes()[0x2E8:]
    for bit in range(8):
        values = [(value >> bit) & 1 for value in blob]
        for reverse in (False, True):
            decoded = bits_to_bytes(values, reverse)
            runs = printable_runs(decoded)
            hits = [run for run in runs if "flag" in run.lower() or "ctf" in run.lower()]
            if hits:
                print(f"bit={bit} reverse={reverse} hits={hits[:10]}")
            if runs:
                longest = max(runs, key=len)
                if len(longest) >= 16:
                    print(f"bit={bit} reverse={reverse} longest={longest[:120]!r}")

    for shift in range(1, 8):
        decoded = bytes(((a << shift) | (b >> (8 - shift))) & 0xFF for a, b in zip(blob, blob[1:]))
        for label, candidate in ((f"left{shift}", decoded), (f"right{shift}", bytes(reversed(decoded)))):
            hits = [run for run in printable_runs(candidate) if "flag" in run.lower() or "ctf" in run.lower()]
            if hits:
                print(f"shift={label} hits={hits[:10]}")


if __name__ == "__main__":
    main()
