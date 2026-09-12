---
schema_version: "1.0"
kind: failure
id: "web-short-lived-run-expiry"
category: "web"
status: draft
claim_state: "confirmed"
evidence_scope: ["single_challenge"]
tested_versions: []
source_challenges: ["the-cube-lost-its-memory-twice"]
---

# Delayed submission invalidates staged web runs

## Hypothesis

A previously started staged run can be reused after manual analysis and a delayed finish request.

### Why It Was Reasonable

The run ID and scramble remain visible, so reusing them appears deterministic.

## Context

- Architecture/runtime: Remote browser-backed HTTP service
- Version: Unknown
- Mitigations: Queue and finite server deadlines
- Relevant primitive/state: Run ID, scramble, Stage 1 pass token
- Required prerequisite: Finish must arrive while the run remains valid

## Attempt

### Bounded Procedure

Start Stage 2, prepare the inverse manually, and submit finish after a debugging delay.

### Expected Signal

The inverse sequence is accepted for the existing run.

### Cost

medium

## Observed Result

The delayed finish returned `400 Invalid run request`. A fresh automated Stage 1-to-Stage 2 chain accepted the same inversion method.

### Discriminating Value

The stale-run direction is a timing failure candidate; it does not invalidate the inverse algorithm.

## Root Cause / Missing Assumption

The run was likely expired or invalidated before finish; the service did not expose which condition caused the generic error.

### This Result Does Not Prove

That every `Invalid run request` is caused by expiry, or that all staged web protocols use the same timing window.

## Retry Conditions

### Do Not Retry When

- The current run or pass token is outside its advertised queue/deadline window.

### Retry When

- A fresh authorized chain can start and submit without manual delay.

### Where This Direction Can Succeed

- Protocols with explicit timing fields and deterministic run state, when start, wait, compute, and finish are automated.

## Debugging Recognition Cues

- Generic invalid-run responses after a long gap between start and finish.
- A fresh run succeeds without changing the payload algorithm.

## Retrieval Cues

- web CTF
- run ID expiry
- staged endpoint
- deadline
- invalid run request

## Evidence

- `write_up_train/the-cube-lost-its-memory-twice/wu.md`
- `solve.py`
