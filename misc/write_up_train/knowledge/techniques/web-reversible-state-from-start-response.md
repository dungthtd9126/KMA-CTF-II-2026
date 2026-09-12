---
schema_version: "1.0"
kind: technique
id: "web-reversible-state-from-start-response"
category: "web"
status: draft
claim_state: "confirmed"
evidence_scope: ["single_challenge", "implementation_verified"]
tested_versions: []
source_challenges: ["the-cube-lost-its-memory-twice"]
---

# Reverse client-visible puzzle state

## Trigger

### Recognition cues

- A browser puzzle calls a start endpoint and receives a complete scramble, state, or seed.
- A finish endpoint accepts a client-supplied action sequence and checks the resulting state.

### Decision rule

Inspect the start JSON and client protocol first. If the disclosed state fully determines the target and actions have known inverses, submit the inverse sequence before implementing a domain-specific solver.

## Preconditions

- The returned state is complete enough to reconstruct the target.
- Each action has a deterministic inverse.
- The server validates the final state rather than an unknown human-solving property.
- The run ID remains valid through submission.

## Fast discriminating checks

1. Search the bundle for `/start`, `/finish`, `scramble`, `runId`, and `flag`; issue one start request and inspect its JSON.

## Procedure

1. Capture the complete start response and its timing/token fields.
2. Reverse the action tokens and replace each action with its inverse.
3. Submit the resulting sequence with the returned run ID before the deadline.
4. Repeat the same check for any gated stage using the fresh authorization token.

### Verification points

- Start response contains the full state and run metadata.
- Finish returns an explicit success value for the inverse sequence.

## Expected observations

- A minimal inverse sequence reaches the solved/accepted state.
- No manual domain solver is required.

## Counterexamples / Negative cues

### Do not apply blindly when

- The server keeps a hidden commitment, rejects replayed sequences, enforces unknown optimality, or discloses insufficient state.

### Known failure modes

- The run or authorization token expires while the payload is being prepared.
- The action notation has inverses that are not handled by the simple parser.

### Retry / transfer boundary

- Retry with a fresh run when timing is the only failed prerequisite. Abandon this path if a fresh inverse is rejected for a state or policy reason.

## Version / Mitigation Boundary

Verified against the provided 2026 web service and face-move notation with optional prime and `2` suffixes. Broader puzzle grammars were not tested.

## Retrieval Cues

- web CTF
- start response scramble
- reversible state
- inverse move list
- client-controlled finish sequence

## Evidence

- `solve.py`
- `write_up_train/the-cube-lost-its-memory-twice/wu.md`
