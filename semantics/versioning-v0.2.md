# Versioning (v0.2)

Contract shapes are versioned. A published version is a compatibility reference, not a guarantee of service availability.

## Frozen v0.1

v0.1 is a published loose baseline. It is frozen.

- Do not rewrite, rename, or silently migrate v0.1 schemas or examples.
- v0.1 documents remain valid against v0.1 schemas only.
- v0.1 documents are documentation-wrapper objects (request and response may appear in one file). That wrapper is not the v0.2 wire contract.

## v0.2

v0.2 is a new public wire grammar for:

- execution-request request
- execution-request response
- status-result query
- status-result result
- error-denial

Capability-consumption has no v0.2 in this version.

v0.2 wire objects are selected explicitly by `contract_family` and `contract_version`. Sending a v0.1 document as v0.2, or the reverse, is a different contract.

## Compatibility rules

Within one published version:

- Adding an optional field is additive.
- Removing a required field, renaming a field, changing a public enum, or changing a family constant is breaking and requires a new version.

Across versions:

- Implementations MUST read `contract_version` and MUST NOT assume a later version is a drop-in replacement for an earlier one.
- Schema validity does not grant authority, runtime admission, or access entitlement.
