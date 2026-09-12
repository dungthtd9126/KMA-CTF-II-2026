# The Cube Lost Its Memory Twice

Category: web
Target: http://42.112.213.93:18081/

## Confirmed protocol

- `POST /api/stages/1/start` returns a run, puzzle, complete scramble, queue time, and deadline.
- `POST /api/stages/1/finish` accepts `{runId,moves}` and returns a short-lived Stage 2 pass token.
- Stage 2 uses the pass token at `/api/stages/2/start`; its finish endpoint has the same move format.
- The client bundle explicitly exposes these endpoints and the UI hint says to rewind the returned scramble.

## Solve

For each scramble, reverse the token order and invert each move:

- `R` becomes `R'`
- `R'` becomes `R`
- `R2` remains `R2`

`solve.py` performs both stages dynamically, waits for each server queue, and submits immediately.

## Validation

```text
rtk python3 -m py_compile solve.py
rtk python3 solve.py
```

Remote validation returned `ok: true` for both stages.

Flag: `KMACTF{tw1st_th3_cl0ck_b4ck}`
