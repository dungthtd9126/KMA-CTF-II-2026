# Working note - return

- Challenge: return
- Started: 2026-09-12
- Memory mode: normal
- Scope: local, organizer-provided pwn challenge

## Fingerprint

- Category: userland pwn / privilege-boundary IPC
- Architecture/runtime: amd64 PIE ELF; Chromium Mojo/ipcz statically linked
- Mitigations: full RELRO, stack canary, NX, PIE
- Input: line protocol through `sandboxee`; broker root, sandboxee drops to nobody in Docker
- Suspected bug surface: stale `FileEntry::size` used as destination capacity in `DoRead`; patched ipcz array bounds validation
- Known primitives: controlled file contents; read-back length can exceed recorded size
- Unknowns: reliable control-flow primitive and broker-side escalation chain

## Confirmed observations

- `CREATE` records initial data length in `FileEntry::size`; `WRITE` does not update it — `src/sandboxee.cc:303-312`, `320-346`.
- `READ` copies broker-returned data using `result->data.size()` into `preview[32]` or `malloc(entry->size)` — `src/sandboxee.cc:370-384`.
- Broker authenticates tokens and grants unrestricted path handling only to `assmin`; flag is root-only in the container — `src/broker.cc:292-371`, `Dockerfile`.
- Local `CTF_STDIO=1 ./bin/broker` works; child launches and protocol responds.
- Binary modes were adjusted executable locally to reproduce the supplied launch layout.

## Meaningful attempts

- Basic `REGISTER alice` / `QUIT`: confirmed local broker-sandboxee IPC and protocol.

## Current decision

- Best path: characterize the overflow under gdb, then identify how the ipcz patch is reached from attacker-controlled Mojo traffic.
- Killed paths: none.

## Redaction

- Keep flag out of generalized knowledge and datasets.
