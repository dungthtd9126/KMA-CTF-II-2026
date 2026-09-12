#!/usr/bin/env python3
"""Try conservative, metadata-derived decryptions of the EX5 payload.

No sample code is executed. Candidates are scored for recognizable structure.
"""

from __future__ import annotations

import hashlib
import math
import re
import sys
from pathlib import Path

from Crypto.Cipher import AES, ChaCha20, ChaCha20_Poly1305


def entropy(data: bytes) -> float:
    counts = [0] * 256
    for value in data:
        counts[value] += 1
    size = len(data)
    return -sum((n / size) * math.log2(n / size) for n in counts if n) if size else 0.0


def score(data: bytes) -> tuple[float, str]:
    head = data[:512]
    printable = sum(32 <= x < 127 or x in (9, 10, 13) for x in head) / max(1, len(head))
    markers = [b"flag", b"ctf", b"MQL", b"EX5", b"PK\x03\x04", b"\x78\x9c", b"\x78\xda", b"\x1f\x8b"]
    hits = sum(head.lower().find(marker.lower()) >= 0 for marker in markers)
    utf16 = len(re.findall(rb"(?:[ -~]\x00){4,}", data[:4096]))
    # Plain code/data usually has lower entropy than the encrypted payload.
    value = printable * 10 + hits * 20 + utf16 * 8 + max(0.0, 7.5 - entropy(head))
    desc = f"entropy={entropy(head):.3f} printable={printable:.3f} markers={hits} utf16={utf16} head={head[:16].hex()}"
    return value, desc


def add_candidate(candidates: dict[str, bytes], label: str, value: bytes) -> None:
    if len(value) in (16, 24, 32):
        candidates.setdefault(label, value)


def main() -> int:
    path = Path(sys.argv[1] if len(sys.argv) > 1 else "Rick36.ex5")
    blob = path.read_bytes()
    nonce = blob[0x2E8:0x2F4]
    ciphertext = blob[0x2F4:]
    if len(ciphertext) % 16:
        raise SystemExit(f"ciphertext is not block aligned: {len(ciphertext)}")

    candidates: dict[str, bytes] = {}
    fields = {
        "header20": blob[0x20:0x30],
        "header80": blob[0x80:0x90],
        "header90": blob[0x90:0xA0],
        "nonce": nonce,
        "nonce_padded": nonce + b"\x00" * 4,
        "header80_100": blob[0x80:0xA0],
        "header20_40": blob[0x20:0x40],
    }
    for label, value in fields.items():
        add_candidate(candidates, label, value)
        for name, func in (("md5", hashlib.md5), ("sha1", hashlib.sha1), ("sha256", hashlib.sha256)):
            digest = func(value).digest()
            add_candidate(candidates, f"{name}({label})", digest)

    texts = [
        path.name,
        path.stem,
        path.name.lower(),
        path.stem.lower(),
        "no_risk",
        "Rick36.ex5",
        "Clean-room behavioral reconstruction",
        "1.004",
        "Rick36.ex5\x001.004",
        "Rick36\x001.004",
    ]
    raw_inputs = [(f"text:{text!r}", text.encode()) for text in texts]
    raw_inputs += [(f"raw:{label}", value) for label, value in fields.items()]
    raw_inputs += [
        ("raw:header", blob[:0x2E8]),
        ("raw:header+nonce", blob[:0x2F4]),
        ("raw:file", blob),
        ("raw:ciphertext", ciphertext),
    ]
    for label, value in raw_inputs:
        for name, func in (("md5", hashlib.md5), ("sha1", hashlib.sha1), ("sha256", hashlib.sha256)):
            digest = func(value).digest()
            add_candidate(candidates, f"{name}({label})", digest)

    results: list[tuple[float, str, str, bytes]] = []
    for key_label, key in candidates.items():
        modes = [("ECB", AES.MODE_ECB), ("CBC", AES.MODE_CBC), ("CTR", AES.MODE_CTR)]
        for mode_name, mode in modes:
            try:
                if mode == AES.MODE_CBC:
                    cipher = AES.new(key, mode, iv=nonce + b"\x00" * 4)
                    plain = cipher.decrypt(ciphertext)
                elif mode == AES.MODE_CTR:
                    cipher = AES.new(key, mode, nonce=nonce)
                    plain = cipher.decrypt(ciphertext)
                else:
                    cipher = AES.new(key, mode)
                    plain = cipher.decrypt(ciphertext)
            except ValueError:
                continue
            value, desc = score(plain)
            results.append((value, key_label, mode_name, plain))
            if value >= 100:
                print(f"candidate {value:.2f} {key_label} {mode_name} {desc}")
                print(f"  ascii={plain[:128]!r}")

        if len(key) in (16, 32):
            for nonce_len in (8, 12):
                try:
                    chacha_nonce = nonce[:nonce_len]
                    plain = ChaCha20.new(key=key, nonce=chacha_nonce).decrypt(ciphertext)
                except ValueError:
                    continue
                value, desc = score(plain)
                results.append((value, key_label, f"ChaCha20-{nonce_len}", plain))
                if value >= 100:
                    print(f"candidate {value:.2f} {key_label} ChaCha20-{nonce_len} {desc}")
                    print(f"  ascii={plain[:128]!r}")

        if len(key) in (16, 24, 32) and len(ciphertext) >= 32:
            for scheme_name, factory in (("AES-GCM", AES), ("ChaCha20-Poly1305", ChaCha20_Poly1305)):
                for aad_label, aad in (("none", None), ("header", blob[:0x2E8]), ("header+nonce", blob[:0x2F4])):
                    try:
                        if scheme_name == "AES-GCM":
                            cipher = factory.new(key, factory.MODE_GCM, nonce=nonce)
                        else:
                            cipher = factory.new(key=key, nonce=nonce)
                        if aad is not None:
                            cipher.update(aad)
                        plain = cipher.decrypt_and_verify(ciphertext[:-16], ciphertext[-16:])
                    except (ValueError, KeyError):
                        continue
                    print(f"AUTHENTICATED {key_label} {scheme_name} aad={aad_label} head={plain[:32].hex()}")
                    (path.parent / f"{path.name}.{scheme_name.lower().replace('-', '_')}.plain").write_bytes(plain)

    print(f"tested={len(results)} candidates={len(candidates)}")
    for value, key_label, mode_name, plain in sorted(results, reverse=True)[:20]:
        print(f"top {value:.2f} {key_label} {mode_name} entropy={entropy(plain[:512]):.3f} head={plain[:16].hex()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
