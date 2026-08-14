# Integrity binding (v0.2)

Public integrity binds a wire object’s exact contents to a digest so an interoperable consumer can detect tampering. It is integrity only. It does not grant authority.

## Public fields

### `verification` (self-integrity)

Present on the execution-request request, execution-request response, status-result result, and error-denial wire objects.

- `scheme` — `sha-256`
- `canonicalization` — `rfc8785`
- `value` — lowercase hex SHA-256 of this object’s canonical form

`verification` binds the exact contents of **this** wire object.

### `request_verification` (request binding)

Present on the execution-request response, status-result result, and error-denial objects when the originating request can be identified.

It is the digest identity (`scheme`, `canonicalization`, `value`) of the originating execution-request **request**. It binds this object to that request. It is not this object’s self-integrity.

Do not copy the request digest into `verification.value` on downstream objects.

## RFC 8785 + SHA-256 digest rule

1. Take the complete wire object as transmitted, including `submitted_at` when present.
2. Omit only `verification.value` (the self-referential digest). Keep `verification.scheme` and `verification.canonicalization`. Keep `request_verification` in full when present, including its `value`.
3. Canonicalize that object with RFC 8785 JSON Canonicalization Scheme (JCS):
   - object keys sorted by UTF-16 code-unit order
   - array order preserved
   - no insignificant whitespace
   - UTF-8
4. Hash the canonical UTF-8 bytes with SHA-256.
5. Encode as lowercase hexadecimal. That string is `verification.value`.

A consumer recomputes this digest and compares it to `verification.value`. A mismatch means the transmitted contents were modified.

A consumer binds a response, status result, or error-denial to a request by comparing `request_verification` to that request’s `verification`. A mismatch means it is not bound to that request.

## Payload

`payload` is part of the request wire, so changing payload bytes changes the request digest.

`payload` is operation-specific input only. It cannot replace or override envelope `actor_refs`, `authority_refs`, `evidence_refs`, `resource_revision_refs`, `scope`, `verification`, or `request_verification`. Payload data does not become authority by being present.

## What public integrity MUST NOT be read as

A matching digest does not mean:

- a governance check succeeded
- authority was granted
- approval was given
- any service decision was made
- a private signing or trust implementation was applied
- admission or execution permission was granted

Schema validity does not grant authority.

## What remains out of scope

- Private keys
- Signatures and signing infrastructure
- Trust-model implementation
- Admission or enforcement internals
- Governance decision logic
- Internal authority implementation
