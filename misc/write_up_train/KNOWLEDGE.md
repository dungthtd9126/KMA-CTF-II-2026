# Reusable Knowledge

### Client-exposed reversible puzzle state

When a puzzle client receives a complete scramble/state from a start endpoint and a finish endpoint accepts a client action list, test the inverse transformation before building a full solver. See `knowledge/techniques/web-reversible-state-from-start-response.md`.

### Short-lived staged web runs

Queue times, deadlines, run IDs, and pass tokens make manual retries unreliable. Automate each fresh start-to-finish segment, and restart the authorized chain after stale-run errors. See `knowledge/failures/web-short-lived-run-expiry.md`.
