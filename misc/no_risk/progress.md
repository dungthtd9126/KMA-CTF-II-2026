# Progress Handoff

## Objective

Recover the flag from `Rick36.ex5`; produce the required CTF write-up. Treat the artifact as potentially unsafe; static analysis only.

## Confirmed facts

- Category: reverse engineering; MQL5/EX5 container.
- Target size: 50,100 bytes.
- SHA-256: `dfa4af63918c1bf12e5994f647a571e311b274a5551931e83740901dede973f6`.
- Header: `EX5\x02`; metadata includes UTF-16LE `Clean-room behavioral reconstruction` and `1.004`.
- Header/payload boundary: `0x2f4`; payload length `0xc0c0`.
- Payload entropy: approximately 7.997 bits/byte; no direct flag marker, PE/ELF/archive signature, URL, or import found.
- `clamscan --no-summary Rick36.ex5` returned `OK`; this does not prove safety.
- Artifact never executed.
- Public Meepwn EX5 research indicates runtime UTF-16 strings and index-XOR obfuscation, but direct position-XOR variants over this payload found no flag.
- Repeated 16-byte blocks cluster in the payload tail; public comparison samples do not show the same pattern. Custom/structured payload remains likely.

## Files and commands

- `solve.py`, `decrypt.py`, `extract.py`, `crypto_probe.py`, `stego_probe.py`, `compare_ex5.py`: existing static probes.
- `index_probe.py`: position-derived XOR/add/subtraction probes.
- `solve.md`: detailed local notes.
- `.ctf-knowledge/working-note.md`: research checkpoint.
- Useful commands: `rtk python3 compare_ex5.py Rick36.ex5 /tmp/cezlsma.ex5 /tmp/mt5r.ex5`; `rtk python3 index_probe.py Rick36.ex5`; `rtk xxd` around payload offsets.

## Attempts/results

- Direct ASCII/UTF-16 strings: only metadata.
- Common AES/ChaCha/RC4/XTEA/XOR, compression, Base64, and bit-plane probes: no validated plaintext.
- Public EX5 write-up retrieved through GitHub; methodology recorded in `solve.md`.
- Public samples `/tmp/cezlsma.ex5` and `/tmp/mt5r.ex5` available for structural comparison.

## Blocker

The flag encoding/key or custom payload format is not yet identified. No local MetaTrader/Wine runtime.

## Next steps

1. Inspect the repeated tail region and compare repeated chunks, not only 16-byte blocks.
2. Analyze header fields and payload generation for a custom PRNG/stream or embedded structure.
3. Validate any decoded candidate, then create `write_up_train/no_risk/wu.md` and sanitized reusable knowledge.
