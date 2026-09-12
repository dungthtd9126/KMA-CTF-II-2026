# Working Note: no_risk

- Objective: recover the flag from `Rick36.ex5` and document the validated solution.
- Mode: resume.
- Safety: static-only; do not execute the EX5 artifact.
- Confirmed target identity: 50,100 bytes; SHA-256 `dfa4af63918c1bf12e5994f647a571e311b274a5551931e83740901dede973f6`.
- Confirmed structure: `EX5\x02` header; metadata/header through `0x2f4`; `0xc0c0` high-entropy payload.
- Killed paths so far: direct strings, common compression signatures, Base64, simple common-cipher candidates, basic bit-plane extraction.
- Active hypotheses: index-derived XOR; metadata-seeded custom stream; runtime-only string materialization.
- Best next tests: index/affine transforms; byte-structure comparison; EX5 format research.
