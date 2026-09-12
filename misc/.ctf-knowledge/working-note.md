# Working note - the-cube-lost-its-memory-twice

- **Challenge:** The Cube Lost Its Memory Twice
- **Started:** 2026-09-12
- **Memory mode:** normal
- **Authorization/scope:** Organizer-provided KMA CTF HTTP service only

## Fingerprint

- Category: web
- Architecture/runtime: React 19.3.0 client bundle; server unknown
- Suspected bug surface: start response discloses scramble; finish accepts move list
- Known primitives: inverse scramble; Stage 1 pass token

## Confirmed Observations

- Bundle exposes `/api/stages/{stage}/start` and `/api/stages/{stage}/finish`.
- Both fresh inverse sequences were accepted remotely.
- Manual delayed Stage 2 submission returned generic invalid-run error; fresh automation passed.

## Current Decision

- **Best path:** Keep `solve.py` as the reproducible dynamic solver.
- **Killed paths under current conditions:** Reusing delayed run IDs.

## Evidence Index

- `solve.py`
- `solve.md`
- `write_up_train/the-cube-lost-its-memory-twice/wu.md`

## Redaction / Leakage Queue

- Pass tokens and run IDs omitted from persistent notes and generalized datasets.
