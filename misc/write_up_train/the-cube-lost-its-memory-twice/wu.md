# The Cube Lost Its Memory Twice

## Metadata

- **Challenge ID:** the-cube-lost-its-memory-twice
- **Category:** web
- **Event/source:** KMA CTF II 2026
- **Date solved:** 2026-09-12
- **Memory mode:** normal
- **Architecture/runtime:** Browser JavaScript client; React 19.3.0 bundle; server runtime unknown
- **Mitigations/constraints:** Remote server deadlines; 3-second queued start; Stage 1 pass token required for Stage 2
- **Files:** `solve.py`, `solve.md`
- **Remote:** `http://42.112.213.93:18081/`
- **Final result:** Both stages accepted; flag returned by Stage 2
- **Solution reuse:** false

## Challenge Summary

The page presents two Rubik cube stages. The browser starts a run, receives the server's scramble, submits a move list, and receives the flag only after both server checks pass.

## Environment and Fingerprint

### Artifact identity

The root page served the Vite-style bundle `/assets/index-CO3YbkAX.js` with 425322 bytes. No source, Dockerfile, or local backend was provided.

### Runtime / version boundary

The bundle identifies React 19.3.0. The server implementation and exact cube library version are unknown.

### Important constraints

Stage 1 is a 2x2x2 run with a 60-second deadline. Stage 2 is a 3x3x3 run with a 180-second deadline. Each run waits about three seconds before accepting moves. Stage 2 requires the fresh Stage 1 pass token.

## Root Cause

The start response discloses the complete scramble. The finish endpoint accepts a client-controlled move array and checks the resulting cube state, so the challenge contains no hidden solving secret: every face move is reversible. Reversing the disclosed scramble produces the solved state directly.

## Derived Primitives

| Primitive | How obtained | Verification signal | Scope/limitations |
| --- | --- | --- | --- |
| Complete scramble | Read the JSON returned by `/api/stages/{stage}/start` | `scramble` field present | Run-specific and time-limited |
| Inverse move list | Reverse tokens; invert prime/non-prime suffixes; preserve `2` moves | Finish returns `ok: true` | Requires supported move notation |
| Stage 2 authorization | Use Stage 1's returned pass token | Stage 2 start returns a run | Token is short-lived and must not be reused after expiry |

## Key Observations

- The bundle defines `POST /api/stages/${stage}/start` and `POST /api/stages/${stage}/finish`.
- The UI text explicitly suggests inspecting the start response and rewinding its moves.
- Fresh dynamically reversed move lists passed both server stages.

## Decision Trace

### ATT-001 - Inspect the client protocol

- **Observation/state:** The root page is a static React application with a Rubik UI and server-authoritative verification text.
- **Hypothesis:** The JavaScript bundle contains the challenge protocol and may reveal the intended state transition.
- **Why plausible:** A browser client must know how to start and finish runs.
- **Smallest discriminating test:** Fetch the bundle and search its literals for HTTP calls, stage fields, and success conditions.
- **Why this test first:** It is cheaper and more decisive than manually solving a cube.
- **Expected signal:** Start/finish endpoints plus a returned scramble or token.
- **Actual signal:** Both endpoints, `scramble`, `runId`, `startsAt`, `deadlineAt`, and `stagePassToken` were present.
- **Outcome:** supported
- **Interpretation:** The server protocol is directly reproducible.
- **Decision/pivot:** Request Stage 1 and invert its returned scramble.
- **Retry/transfer condition:** Apply to puzzle clients that expose full reversible state in start responses.
- **Evidence:** `/assets/index-CO3YbkAX.js`, functions `Ge` and `Ke` in the fetched bundle

### ATT-002 - Reverse Stage 1

- **Observation/state:** Stage 1 returned an 11-move 2x2x2 scramble and a queued run.
- **Hypothesis:** The reverse/inverse sequence will solve the server's stored scramble.
- **Why plausible:** Cube face turns are invertible and the server receives the move list from the client.
- **Smallest discriminating test:** Submit only the reversed scramble after the advertised start time.
- **Why this test first:** It tests the core logic with the minimum legal move sequence.
- **Expected signal:** HTTP 200 with `ok: true` and a Stage 2 pass token.
- **Actual signal:** HTTP 200; Stage 1 accepted 11 moves and returned a pass token.
- **Outcome:** successful_stage
- **Interpretation:** The inverse transformation and finish schema are correct.
- **Decision/pivot:** Start Stage 2 with the returned token.
- **Retry/transfer condition:** Fresh Stage 1 run required if the pass token expires.
- **Evidence:** `solve.py`, `POST /api/stages/1/start`, `POST /api/stages/1/finish`

### ATT-003 - Delayed manual Stage 2 submission

- **Observation/state:** A Stage 2 run had been started, but the manually issued finish request reached the service much later.
- **Hypothesis:** The run was no longer valid because of its short lifetime or service-side invalidation, rather than because the inverse was wrong.
- **Why plausible:** The response exposes queue/deadline timestamps and the request was delayed during manual debugging.
- **Smallest discriminating test:** Use a fresh Stage 1 pass and automate Stage 2 start, queue wait, and finish as one sequence.
- **Why this test first:** It changes run freshness while keeping the move algorithm unchanged.
- **Expected signal:** A fresh run accepts the same inversion method.
- **Actual signal:** The delayed request returned `400 {"error":"Invalid run request"}`; the fresh automated run passed.
- **Outcome:** partially_supported
- **Interpretation:** Stale-run timing was the likely failure; the response alone did not isolate expiry from other server invalidation.
- **Decision/pivot:** Automate each start-to-finish segment and avoid stale run IDs.
- **Retry/transfer condition:** Retry with a fresh authorized chain when a run is outside its queue/deadline window.
- **Evidence:** Stage 2 finish response; `solve.py`

### ATT-004 - Dynamic two-stage solver

- **Observation/state:** The protocol and inverse operation were confirmed, but Stage 2 runs were time-sensitive.
- **Hypothesis:** A dynamic solver can complete both stages before their deadlines without hardcoded scrambles.
- **Why plausible:** Start responses provide all run-specific data needed by the client.
- **Smallest discriminating test:** Start each stage, wait for `startsAt - serverNow`, compute the inverse, and finish immediately.
- **Why this test first:** It removes stale data and minimizes manual delay.
- **Expected signal:** Both finish responses return `ok: true`; Stage 2 includes a flag field.
- **Actual signal:** Both stages returned `ok: true`; the flag field was returned.
- **Outcome:** successful_stage
- **Interpretation:** The complete exploit/reproduction is validated remotely.
- **Decision/pivot:** Finalize the script and sanitized knowledge capture.
- **Retry/transfer condition:** Use the same script against a compatible instance of the provided service.
- **Evidence:** `solve.py` remote run output

## Exploitation / Solution Strategy

```text
start response discloses scramble
  |
reverse tokens and invert each move
  |
finish Stage 1 and obtain pass token
  |
repeat for Stage 2
  |
server returns flag
```

## Detailed Solution

### Stage 1 - 2x2x2

Send `{}` to `POST /api/stages/1/start`. Split the returned scramble into tokens, reverse the token order, and invert each token: an unprimed move gains `'`, a primed move loses `'`, and a `2` move is unchanged. Wait until the advertised start time, then send the resulting array with the returned `runId` to `POST /api/stages/1/finish`.

**Intermediate verification:** The judge returned `ok: true` and a Stage 2 pass token.

### Stage 2 - 3x3x3

Send the Stage 1 pass token to `POST /api/stages/2/start`. Apply the same inverse operation to its fresh scramble, wait for the queue, and finish with `{runId,moves}`.

**Intermediate verification:** The judge returned `ok: true` and the flag field.

## Meaningful Failed Paths and Pivots

### Stale Stage 2 run

- **Context:** Remote two-stage protocol with queued starts and finite deadlines.
- **Expected:** The manually prepared inverse would be accepted.
- **Observed:** `400 {"error":"Invalid run request"}` after a delayed finish request.
- **Root cause/unknown:** The run was likely expired or invalidated before the request arrived; exact server-side reason was not exposed.
- **This does not prove:** The inverse move sequence is invalid; a fresh automated run accepted it.
- **Do not retry when:** The run or pass token is stale or outside its advertised time window.
- **Retry when:** A fresh Stage 1 pass starts a new Stage 2 run and submission is automated.
- **Lesson:** Treat start, queue wait, inversion, and finish as one short-lived transaction.

## Final Exploit / Reproduction

- **Exploit/script:** `solve.py`
- **Usage:** `rtk python3 solve.py`
- **Reliability notes:** Scrambles and run IDs are dynamic. The script waits from server-provided timestamps and submits immediately; network delay can still require a fresh run.

## Validation

- **Local:** `rtk python3 -m py_compile solve.py` passed.
- **Remote:** Both stages returned `ok: true`.
- **Success signal:** Stage 2 returned a flag-shaped success value.

## Research Findings

No external research was needed. The bundled client and remote responses were sufficient.

## New Knowledge

### Challenge-specific

- The exact target URL, run IDs, scrambles, timestamps, pass tokens, and flag are challenge-specific.

### Reusable candidates

- Inspect puzzle/challenge start responses before implementing a full solver; a disclosed reversible state may reduce the task to an inverse transformation.
- Automate short-lived start-to-finish protocols using server-provided timing fields.

## General Bugs and Debugging Lessons

- Manual analysis can make a valid staged run stale. Preserve the protocol logic, but start a fresh run before retesting.

## Transfer to Future Challenges

### Recognition cues

- A client-side puzzle UI calls a start endpoint and receives a complete scramble, state, or seed.
- A finish endpoint accepts a client-supplied action sequence and returns a state-check result.

### Preconditions

- The disclosed state fully determines the target state.
- Actions have known inverses, and the server checks the resulting state rather than a hidden human-solving process.

### Fast checks

- Search the bundle for `/start`, `/finish`, `scramble`, `runId`, and `flag`; issue one start request and inspect its JSON.

### Negative cues / stop conditions

- The server keeps a hidden commitment, rejects replayed sequences, enforces an unknown optimality rule, or does not disclose enough state.

### Version/mitigation boundary

- This solve was verified only against the provided 2026 service and its observed face-move notation.

## Dataset / Evaluation Notes

- **Suggested split:** unassigned
- **Exact prior solution used:** false
- **Potential near-duplicate family:** reversible puzzle/protocol challenges
- **Safe for generalized training export:** yes, with flag/token omission

## Evidence

- `solve.py`
- `solve.md`
- `POST /api/stages/1/start` and `POST /api/stages/1/finish`
- `POST /api/stages/2/start` and `POST /api/stages/2/finish`

## Flag

`KMACTF{tw1st_th3_cl0ck_b4ck}`
