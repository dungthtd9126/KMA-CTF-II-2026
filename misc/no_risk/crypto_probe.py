#!/usr/bin/env python3
"""Probe common metadata-derived decryptions; never executes EX5 content."""

from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path

from Crypto.Cipher import AES, ARC4


def candidates(blob: bytes) -> dict[str, bytes]:
    fields = {
        "h20": blob[0x20:0x30],
        "h80": blob[0x80:0x90],
        "h90": blob[0x90:0xA0],
        "h80+h90": blob[0x80:0xA0],
        "nonce": blob[0x2E8:0x2F4],
        "body0": blob[0x2F4:0x304],
        "text": "Clean-room behavioral reconstruction".encode(),
        "version": "1.004".encode(),
    }
    values = dict(fields)
    for label, value in fields.items():
        for name, fn in (("md5", hashlib.md5), ("sha1", hashlib.sha1), ("sha256", hashlib.sha256)):
            values[f"{name}({label})"] = fn(value).digest()
    for a, av in fields.items():
        for b, bv in fields.items():
            if a < b:
                value = av + bv
                for name, fn in (("md5", hashlib.md5), ("sha256", hashlib.sha256)):
                    values[f"{name}({a}+{b})"] = fn(value).digest()
    return {label: value for label, value in values.items() if len(value) in (16, 24, 32)}


def printable_runs(data: bytes, minimum: int = 8) -> list[tuple[int, str]]:
    out: list[tuple[int, str]] = []
    for match in re.finditer(rb"[ -~]{%d,}" % minimum, data):
        out.append((match.start(), match.group().decode("ascii", "replace")))
    return out


def report(label: str, data: bytes) -> None:
    low = data.lower()
    hits = [(mark, low.find(mark.lower())) for mark in (b"flag{", b"kmactf", b"ctf{", b"http", b"MQL", b"EX5", b"PK\x03\x04", b"\x78\x9c")]
    runs = printable_runs(data)
    if any(pos >= 0 for _, pos in hits) or runs:
        print(label, "hits=", hits, "runs=", runs[:12], "head=", data[:24].hex())


def xtea_decrypt(data: bytes, key: bytes) -> bytes:
    key_words = [int.from_bytes(key[i : i + 4], "little") for i in range(0, 16, 4)]
    out = bytearray()
    for off in range(0, len(data) - 7, 8):
        v0 = int.from_bytes(data[off : off + 4], "little")
        v1 = int.from_bytes(data[off + 4 : off + 8], "little")
        total = (0x9E3779B9 * 32) & 0xFFFFFFFF
        for _ in range(32):
            v1 = (v1 - ((((v0 << 4 ^ v0 >> 5) + v0) ^ (total + key_words[(total >> 11) & 3]))) & 0xFFFFFFFF) & 0xFFFFFFFF
            total = (total - 0x9E3779B9) & 0xFFFFFFFF
            v0 = (v0 - ((((v1 << 4 ^ v1 >> 5) + v1) ^ (total + key_words[total & 3]))) & 0xFFFFFFFF) & 0xFFFFFFFF
        out += v0.to_bytes(4, "little") + v1.to_bytes(4, "little")
    return bytes(out)


def main() -> int:
    path = Path(sys.argv[1] if len(sys.argv) > 1 else "Rick36.ex5")
    blob = path.read_bytes()
    data = blob[0x2F4:]
    keys = candidates(blob)
    ivs = {
        "zero": bytes(16),
        "h20": blob[0x20:0x30],
        "h80": blob[0x80:0x90],
        "h90": blob[0x90:0xA0],
        "body0": data[:16],
        "nonce0": blob[0x2E8:0x2F4] + bytes(4),
    }
    for key_label, key in keys.items():
        for iv_label, iv in ivs.items():
            for mode_name, mode in (("CBC", AES.MODE_CBC), ("CFB", AES.MODE_CFB), ("OFB", AES.MODE_OFB)):
                try:
                    plain = AES.new(key, mode, iv=iv).decrypt(data)
                except ValueError:
                    continue
                report(f"AES-{mode_name} key={key_label} iv={iv_label}", plain)
        try:
            report(f"RC4 key={key_label}", ARC4.new(key).decrypt(data))
        except ValueError:
            pass
        if len(key) == 16:
            report(f"XTEA key={key_label}", xtea_decrypt(data, key))
        for period in range(1, min(65, len(key) + 1)):
            plain = bytes(value ^ key[offset % period] for offset, value in enumerate(data))
            report(f"XOR key={key_label} period={period}", plain)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
