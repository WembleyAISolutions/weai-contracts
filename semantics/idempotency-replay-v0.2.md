# Idempotency and replay (v0.2)

These rules are public contract semantics. They do not specify storage, clocks, or enforcement internals.

## Idempotency key

`idempotency_key` is supplied by the submitting consumer on the execution-request request wire.

- Same `idempotency_key` and the same request self-digest (`verification`) identify the same request. Bound objects MUST share the same `request_ref`.
- Same `idempotency_key` and a different request self-digest is not a duplicate. The public reason code is `idempotency_conflict`.
- The request digest covers the complete request wire, including `submitted_at` when present. A different timestamp is a different digest.

## Nonce / replay

`nonce` is required on the v0.2 execution-request request wire.

- Same `nonce` and the same request self-digest is the idempotent duplicate case, not a new request.
- Same `nonce` and a different request self-digest is replay and MUST NOT be treated as a new accepted request. The public reason code is `replay_rejected`.
- A new governed request requires a new `request_ref` and a new request self-digest.

## What this contract does not say

- How a service stores keys or nonces
- How long a key or nonce remains comparable
- Any private checking algorithm

Holding matching idempotency fields does not grant authority.
