# Session checkpoint - return

- Updated: 2026-09-12
- Memory mode: normal

## Objective and authorization

Solve the supplied local pwn challenge and validate the intended flag-read path.

## Artifact / environment identity

`bin/broker` and `bin/sandboxee`, amd64 PIE, Chromium Mojo/ipcz embedded; Docker runs broker as root and sandboxee as nobody.

## Confirmed facts

1. Stale `FileEntry::size` enables a controlled over-copy in `Connection::DoRead`.
2. Mojo/ipcz has a supplied patch removing an array bounds check; shared-memory parcel data is disabled.
3. Local broker/sandboxee startup and normal registration work.

## Active hypotheses

1. The overflow provides a sandboxee control-flow or memory primitive that must be combined with malformed Mojo traffic to affect the root broker.

## Current files / scripts

- `src/sandboxee.cc`, `src/broker.cc`, `src/ctf.mojom`: inspected.
- `patches/*.patch`: inspected.
- `solve.py`: local protocol probe.

## Resume point

- Best next bounded test: trigger `CREATE` with a small file, `WRITE` with 1000 bytes, `READ`, inspect crash/canary/layout under gdb.

## Next steps

1. Capture exact overflow offsets and available stack/heap control.
2. Trace Mojo serialization and malformed-array reachability.
3. Build and validate the final pwntools exploit.

## Unknowns / blockers / redaction

- No blocker. Do not copy the flag into generalized knowledge.
