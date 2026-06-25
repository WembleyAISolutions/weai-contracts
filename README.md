# weai-contracts

Public contract schemas and examples for third-party systems that exchange structured requests, results, status records, and capability-use declarations with WEAI-compatible services.

## What this repository is

- public contract vocabulary
- request / result / status examples
- capability-use contract examples
- non-authority declarations

## Contract families

This repository defines public-safe contract shapes in four families:

1. **Execution Request Contracts** — a consumer submits a structured request; the service returns an accepted/denied outcome with a verifiable result reference.
2. **Capability Consumption Contracts** — a consumer requests use of a named capability under an agreed scope.
3. **Status / Result Contracts** — a consumer queries or receives the outcome of a prior request: final state plus a verifiable result reference.
4. **Error / Denial Contracts** — every request may be denied or fail; denial and error are first-class, contracted outcomes.

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

Only public-safe contract schemas, examples, and compatibility notes belong here.
Internal implementation, enforcement logic, and service topology are out of scope and are not published in this repository.

## Versioning

Contract shapes are versioned. A published version is a compatibility reference, not a guarantee of service availability.
