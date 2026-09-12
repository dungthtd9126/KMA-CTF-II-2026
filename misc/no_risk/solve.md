# no_risk - Rick36.ex5

## Classification

- Category: reverse engineering / MQL5 EX5 artifact.
- Scope: authorized local CTF artifact; static analysis only.
- Target: `Rick36.ex5`, 50,100 bytes.
- SHA-256: `dfa4af63918c1bf12e5994f647a571e311b274a5551931e83740901dede973f6`.

## Confirmed

- Header starts with `EX5\x02`.
- Fixed metadata/header region ends at `0x2f4`.
- UTF-16LE metadata includes `Clean-room behavioral reconstruction` and `1.004`.
- Payload length is `0xc0c0`; entropy is approximately 7.997 bits/byte.
- No direct flag marker, PE/ELF/archive signature, URL, import, or useful ASCII payload found.
- `clamscan --no-summary Rick36.ex5` reported `OK`; this is not a safety guarantee.
- Artifact has not been executed.

## Reference

The public Meepwn EX5 write-up shows that MQL5 strings can materialize as UTF-16 in the MetaTrader process, with an encoded string recovered by XORing each byte with its index. The same family of transforms is being tested statically here.

## Current hypotheses

1. Flag is encoded in the EX5 payload with an index-derived byte transform.
2. Payload is a custom stream/cipher whose key or seed is present in metadata.
3. Flag requires EX5 runtime behavior; no local MetaTrader/Wine runtime is available.

## Files

- `solve.py`: initial static triage.
- `decrypt.py`: conservative crypto probes.
- `extract.py`: compression/Base64/XOR signature probes.
- `compare_ex5.py`: metadata and payload comparison.
- `crypto_probe.py`: broader common-cipher probes.
- `stego_probe.py`: bit-plane probes.

## Next tests

- Probe index XOR, affine/index variants, and UTF-16 reconstruction over body and file.
- Compare target payload against public EX5 samples for generated-region structure.
- Inspect EX5 decoder/research references if simple transforms fail.
