# weai-contracts

Public contract schemas and examples for third-party systems that exchange structured requests, results, status records, and capability-use declarations with WEAI-compatible services.

## What this repository is

- public contract vocabulary
- request / result / status examples
- capability-use contract examples
- non-authority declarations
- executable public schemas and conformance fixtures for published versions

## Contract families

This repository defines public-safe contract shapes in five families:

1. **Execution Request Contracts** — a consumer submits a structured request; the service returns an accepted/denied outcome with a verifiable result reference.
2. **Capability Consumption Contracts** — a consumer requests use of a named capability under an agreed scope.
3. **Status / Result Contracts** — a consumer queries or receives the outcome of a prior request: final state plus a verifiable result reference.
4. **Error / Denial Contracts** — every request may be denied or fail; denial and error are first-class, contracted outcomes.
5. **Professional Authority Evidence Contracts** — a professional portal or credential-record system publishes one immutable, integrity-bound observation of one professional credential revision; evidence is not authority, admission, or execution permission.

v0.2 publishes executable wire objects for families 1, 3, and 4. Capability consumption remains at the frozen v0.1 baseline; no v0.2 of that family is published here.

## Versions

Contract shapes are versioned. A published version is a compatibility reference, not a guarantee of service availability.

- **v0.1** is a published loose baseline and is frozen. v0.1 schemas and examples are unchanged. They remain documentation-wrapper documents (illustration fields may sit beside request and response in one file). That wrapper is the v0.1 compatibility reference, not the v0.2 wire contract.
- **v0.2** is a new public wire grammar. Implementations select it explicitly with `contract_family` and `contract_version`. v0.2 does not silently migrate v0.1.

See `semantics/versioning-v0.2.md`.

## v0.2 wire objects

v0.2 conformance targets are wire objects. Documentation wrappers do not define the v0.2 contract. Published v0.2 examples are wire objects.

Request and result are separate objects.

| Family | Wire object | Schema |
| --- | --- | --- |
| execution-request | request only | `contracts/execution-request/v0.2/request.schema.json` |
| execution-request | response only | `contracts/execution-request/v0.2/response.schema.json` |
| status-result | query only | `contracts/status-result/v0.2/query.schema.json` |
| status-result | result only | `contracts/status-result/v0.2/result.schema.json` |
| error-denial | denial or error | `contracts/error-denial/v0.2/schema.json` |

The execution-request **request** wire does not contain `outcome`, `accepted`, `denied`, `result_ref`, or any decision result. Intake `accepted` / `denied` belongs on the execution-request **response**. Later state belongs on status-result. Denial and error also have a dedicated error-denial shape.

On the execution-request **response**:

- `accepted` means the contract request was accepted into its defined processing path. It does not mean a governance allow-decision, that authority was granted, or that execution is permitted.
- `denied` is an intake outcome on this response wire. It is not a governance decision object and is not a substitute for one.

`payload` on the request is operation-specific input only. It cannot replace or override envelope `actor_refs`, `authority_refs`, `evidence_refs`, `resource_revision_refs`, `scope`, `verification`, or `request_verification`. Payload data does not become authority by being present.

Shared public definitions live in `contracts/common/v0.2/defs.schema.json`.

## v1.0 wire objects

v1.0 publishes Professional Authority Evidence as a standalone evidence wire object.

| Family | Wire object | Schema |
| --- | --- | --- |
| professional-authority-evidence | evidence only | `contracts/professional-authority-evidence/v1.0/evidence.schema.json` |

Shared public definitions for this family live in `contracts/common/v1.0/defs.schema.json`. Evidence is not authority, admission, or execution permission.

## Identity model (v0.2)

- `consumer_ref` is the submitting consumer or service identity. It is not the complete actor model.
- `actor_refs` is a generic array of opaque acting identities.
- `authority_refs`, `evidence_refs`, and `resource_revision_refs` are independent opaque reference collections.

References are opaque strings. This repository does not define resolution, roles, or product-specific actor types. Presence of a reference does not grant authority.

## Integrity binding (v0.2)

Public integrity uses RFC 8785 (JCS) and SHA-256:

- `verification` — self-integrity of **this** wire object (`scheme`, `canonicalization`, `value`)
- `request_verification` — digest identity of the originating execution-request request (on response, status result, and error-denial)

Published v0.2 tokens: `scheme` `sha-256`, `canonicalization` `rfc8785`.

A matching `verification` digest means this object’s contents are unmodified. A matching `request_verification` binds a downstream object to a request. Neither means a governance check succeeded, that authority or approval was granted, or that any service decision was made. Private keys, signatures, and trust implementation are out of scope.

See `semantics/integrity-binding-v0.2.md`.

## Idempotency and replay (v0.2)

v0.2 execution requests require `idempotency_key` and `nonce`. Duplicate and replay comparison rules are public field-equality rules, not a private implementation.

See `semantics/idempotency-replay-v0.2.md`.

## Reason codes (v0.2)

Public reason codes are generic only. The catalog is documentation; `reason_code` remains an open string on the wire.

See `vocab/reason-codes-v0.2.json`.

## What this repository is not

- not an implementation
- not an API service
- not an authorization system
- not a billing or settlement system
- not a runtime
- not a platform onboarding record

## Authority rule

A valid contract shape does not by itself create permission to call any service.
Conformance to a contract does not imply execution authority, runtime admission, or access entitlement.

## Public boundary

Only public-safe contract schemas, examples, vocabulary, versioning notes, and conformance fixtures belong here.
Internal implementation, enforcement logic, and service topology are out of scope and are not published in this repository.

## Conformance

```
npm test
```

This command validates frozen v0.1 examples against v0.1 schemas and v0.2 wire fixtures against v0.2 schemas.
