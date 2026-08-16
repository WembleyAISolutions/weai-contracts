# Professional Authority Evidence v1.0 — Normative Requirements

Status: Interface 1 normative baseline  
Contract family: `professional-authority-evidence`  
Contract version: `v1.0`  
Public baseline: `weai-contracts` v0.2 at `00b401877dd2a802105e5c2202eac73c35b9598f`

## 1. Purpose

Professional Authority Evidence v1.0 is a public-safe, profession-neutral wire contract for publishing one immutable observation of one professional credential revision.

It lets a professional portal or credential-record system produce portable evidence that a downstream domain platform can pin and evaluate under its own admission policy. It supports individual practitioners and organisations across multiple professional domains without embedding any product, regulator, profession, jurisdiction, customer, case, payment, or execution-system topology.

This contract is evidence only. A conforming object does not grant authority, approve work, admit an operation, create an engagement, or authorize execution.

## 2. Direction and ownership

The only contract direction is:

`evidence producer -> Professional Authority Evidence v1.0 -> evidence consumer`

The evidence producer owns the professional record, credential revisions, verification records, and immutable supporting-resource revisions it publishes. An external issuer may remain the real-world source of a credential.

The evidence consumer owns all domain-specific policy and operational decisions. It decides whether a pinned evidence object is trusted, fresh, applicable, and sufficient for a particular operation.

Multiple evidence producers or multiple evidence objects may support one operation. They MUST converge into one execution request and, downstream, no more than one governance decision for that operation. Evidence producers MUST NOT emit independent `ALLOW` or `DENY` decisions for the same operation.

## 3. Conformance language

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, and MAY are normative.

Conformance has four separate gates:

1. schema validity;
2. RFC 8785 plus SHA-256 self-integrity;
3. semantic invariants in this document;
4. consumer-local trust, freshness, scope, and operation policy.

Passing gates 1–3 means only that the evidence object conforms to this public contract. It does not predetermine gate 4.

## 4. Wire object

The published wire object MUST be a JSON object with `additionalProperties: false` at the top level and on every closed nested object.

### 4.1 Required shape

```json
{
  "contract_family": "professional-authority-evidence",
  "contract_version": "v1.0",
  "evidence_type": "professional_authority",
  "evidence_ref": "opaque-evidence-ref",
  "producer_ref": "opaque-producer-ref",
  "subject_ref": "opaque-subject-ref",
  "subject_kind": "individual",
  "professional_domain_ref": "opaque-domain-ref",
  "jurisdiction_ref": "opaque-jurisdiction-ref",
  "credential": {
    "credential_ref": "opaque-credential-ref",
    "credential_revision_ref": "opaque-credential-revision-ref",
    "credential_type_ref": "opaque-credential-type-ref",
    "issuer_ref": "opaque-issuer-ref",
    "status": "active",
    "status_as_of": "2026-08-15T00:00:00Z",
    "authority_scope_refs": [
      "opaque-scope-ref"
    ]
  },
  "credential_verification": {
    "verification_state": "verified",
    "verification_record_ref": "opaque-verification-record-ref",
    "verification_record_revision_ref": "opaque-verification-revision-ref",
    "verification_method_ref": "opaque-method-ref",
    "verifier_ref": "opaque-verifier-ref",
    "verified_at": "2026-08-15T00:01:00Z",
    "evidence_refs": [
      "opaque-source-evidence-ref"
    ],
    "resource_revision_refs": [
      "opaque-locked-resource-revision-ref"
    ]
  },
  "issued_at": "2026-08-15T00:02:00Z",
  "verification": {
    "scheme": "sha-256",
    "canonicalization": "rfc8785",
    "value": "0000000000000000000000000000000000000000000000000000000000000000"
  }
}
```

The digest value above is a shape illustration only. A published example MUST contain the correctly computed digest.

### 4.2 Top-level fields

| Field | Required | Constraint | Meaning |
| --- | --- | --- | --- |
| `contract_family` | yes | constant `professional-authority-evidence` | Selects this contract family. |
| `contract_version` | yes | constant `v1.0` | Selects this exact wire version. |
| `evidence_type` | yes | constant `professional_authority` | Distinguishes this evidence purpose without naming a profession. |
| `evidence_ref` | yes | opaque non-empty string | Immutable identity of this published evidence object. |
| `supersedes_evidence_ref` | no | opaque non-empty string | Immediate predecessor when this publication replaces prior evidence in the same credential lineage. |
| `producer_ref` | yes | opaque non-empty string | Identity of the evidence-producing system or organisation. |
| `subject_ref` | yes | opaque non-empty string | Individual or organisation described by the credential. |
| `subject_kind` | yes | `individual` or `organisation` | Generic subject category only. |
| `professional_domain_ref` | yes | opaque non-empty string | Profession or domain reference; vocabulary resolution is outside this contract. |
| `jurisdiction_ref` | yes | opaque non-empty string | Jurisdiction to which the assertion applies. |
| `credential` | yes | closed object | One credential and exactly one immutable credential revision. |
| `credential_verification` | yes | closed object | One immutable verification-record revision and its supporting references. |
| `issued_at` | yes | canonical UTC timestamp | Time this immutable evidence object was published. |
| `verification` | yes | RFC 8785 plus SHA-256 object | Self-integrity of this wire object. |

### 4.3 `credential`

| Field | Required | Constraint | Meaning |
| --- | --- | --- | --- |
| `credential_ref` | yes | opaque non-empty string | Stable credential lineage identity. |
| `credential_revision_ref` | yes | opaque non-empty string | Exact immutable revision being asserted. |
| `credential_type_ref` | yes | opaque non-empty string | Credential type without embedding a regulator-specific enum. |
| `issuer_ref` | yes | opaque non-empty string | External issuer or authoritative source reference. |
| `status` | yes | `active`, `inactive`, `expired`, `suspended`, `revoked`, or `unknown` | Normalized observed credential status. It is not a governance decision. |
| `status_as_of` | yes | canonical UTC timestamp | Time at which `status` was observed to apply. |
| `valid_from` | no | canonical UTC timestamp | Start of the credential-validity interval when known. |
| `valid_until` | no | canonical UTC timestamp | End of the credential-validity interval when known. |
| `authority_scope_refs` | yes | non-empty unique opaque-reference array | Producer-observed professional scopes. Presence does not grant operation authority. |

One wire object MUST describe exactly one credential revision for exactly one subject. A producer MUST publish separate evidence objects for separate credential lineages, subjects, or jurisdictions.

### 4.4 `credential_verification`

| Field | Required | Constraint | Meaning |
| --- | --- | --- | --- |
| `verification_state` | yes | constant `verified` | The producer completed its declared verification process for this record revision. This is not operation approval. |
| `verification_record_ref` | yes | opaque non-empty string | Stable verification-record lineage identity. |
| `verification_record_revision_ref` | yes | opaque non-empty string | Exact immutable verification-record revision. |
| `verification_method_ref` | yes | opaque non-empty string | Method reference; public vocabulary and resolution remain out of scope. |
| `verifier_ref` | yes | opaque non-empty string | Human, service, or organisation that performed the recorded verification. |
| `verified_at` | yes | canonical UTC timestamp | Time the producer completed verification. |
| `evidence_refs` | yes | non-empty unique opaque-reference array | Source observations or evidence records supporting verification. |
| `resource_revision_refs` | yes | non-empty unique opaque-reference array | Immutable locked attachment, snapshot, or source-resource revisions. |

Raw attachment bodies, access tokens, private URLs, secret material, and personally identifying profile fields MUST NOT appear in this wire object. Resolution and access control for all opaque references are out of scope.

## 5. Identifier and timestamp grammar

All fields ending in `_ref` and all items in fields ending in `_refs` use the repository's opaque-reference rule: JSON string with `minLength: 1`. This contract MUST NOT impose prefixes, dotted tokens, UUIDs, product names, URLs, database keys, or another identifier grammar.

Opaque references are compared by exact string equality only. Format, lookup, storage, and lifecycle implementation remain outside the public contract.

All timestamp fields MUST be valid RFC 3339 UTC values matching the admitted grammar: UTC `Z` only; calendar-valid dates and times; hours `00–23`; minutes and seconds `00–59`; optional fractional seconds of one or more digits; no numeric offsets; no leap-second `60`. The schema grammar is `^\\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\\d|3[01])T([01]\\d|2[0-3]):[0-5]\\d:[0-5]\\d(\\.\\d+)?Z$`. Calendar validity (real month/day, leap-year February 29) is a conformance-enforced semantic requirement. Producers MUST normalize timestamps before construction and MUST inject them into a pure builder; builders MUST NOT read a clock internally.

Reference arrays MUST:

- contain at least one item where this document marks them non-empty;
- contain no duplicates;
- be sorted in ascending UTF-16 code-unit order before integrity calculation; and
- retain that order on the wire.

## 6. Revision, locking, and replay rules

1. `credential_revision_ref`, `verification_record_revision_ref`, and every item in `resource_revision_refs` MUST identify immutable, locked revisions.
2. An evidence producer MUST NOT publish from an editable credential or verification draft.
3. A change to credential identity, status, validity, scope, supporting evidence, locked resources, or verification facts MUST create a new relevant revision and a new `evidence_ref`.
4. The new evidence object MUST set `supersedes_evidence_ref` to the immediate prior publication for that credential lineage.
5. A published evidence object MUST never be mutated in place.
6. Re-delivery of the same `evidence_ref` with the same integrity digest is an identical replay and MAY be processed idempotently.
7. Re-delivery of the same `evidence_ref` with different bytes or a different digest is a conflict and MUST be rejected.
8. A new `evidence_ref` carrying the same credential revision and verification-record revision as an existing publication MUST be rejected as an ambiguous duplicate. An identical replay reuses the original `evidence_ref`.

## 7. Semantic invariants

In addition to schema validity, conforming implementations MUST enforce:

- `status_as_of <= verified_at <= issued_at`;
- if both are present, `valid_from <= valid_until`;
- if `status` is `active` and `valid_from` is present, `valid_from <= status_as_of`;
- if `status` is `active` and `valid_until` is present, `status_as_of <= valid_until`;
- if `status` is `expired`, `valid_until` is required and `valid_until <= status_as_of`;
- `supersedes_evidence_ref`, when present, is different from `evidence_ref` and names the immediate prior object in the same `producer_ref` plus `credential_ref` lineage; and
- identical semantic input, including injected timestamps and ordered arrays, produces identical wire bytes after RFC 8785 canonicalization and the same digest.

Statuses `inactive`, `expired`, `suspended`, `revoked`, and `unknown` are structurally valid evidence states. Their validity MUST NOT be interpreted as permission to perform an operation.

## 8. Integrity

`verification` MUST use the existing public integrity tokens:

- `scheme`: `sha-256`
- `canonicalization`: `rfc8785`
- `value`: exactly 64 lowercase hexadecimal characters

The digest algorithm is the v0.2 public rule:

1. take the complete wire object as transmitted;
2. omit only `verification.value`;
3. retain `verification.scheme` and `verification.canonicalization`;
4. canonicalize with RFC 8785;
5. hash the canonical UTF-8 bytes with SHA-256; and
6. encode as lowercase hexadecimal.

A matching digest means only that this evidence object is unmodified. It is not a signature, producer-trust proof, credential issuance, governance result, admission result, or execution permission.

## 9. Producer obligations

A conforming producer MUST:

- own or be authorized to publish the referenced professional record;
- export only locked credential, verification, and supporting-resource revisions;
- preserve old revisions and published evidence objects;
- record the external issuer separately from the producer when they differ;
- normalize source status into the closed public status enum without discarding its own source record;
- construct the wire object deterministically from injected inputs;
- compute and verify the digest before publication; and
- expose no customer, case, order, settlement, payment, commission, or operation-decision data through this family.

The producer MUST NOT claim that `verification_state: verified` means the subject is permitted to perform any specific downstream operation.

## 10. Consumer obligations

A conforming consumer MUST, in order:

1. select the exact `contract_family` and `contract_version`;
2. validate the JSON Schema;
3. recompute and compare self-integrity;
4. enforce the semantic invariants;
5. pin the exact `evidence_ref`, digest, credential revision, verification-record revision, and resource revisions used;
6. evaluate producer trust, freshness, credential status, jurisdiction, professional scope, subject relationship, and operation applicability under consumer-local policy; and
7. retain the evidence-to-operation audit link.

A consumer MUST NOT:

- treat schema validity, digest equality, `verification_state`, or `status: active` as automatic authority;
- silently refresh a pinned evidence object during an operation;
- rewrite producer-owned credential facts;
- create an independently editable copy that competes with the producer's credential authority; or
- split one operation into separate producer-specific governance decisions.

## 11. Binding to execution-request v0.2

When this evidence supports an `execution-request` v0.2 object:

- its `evidence_ref` MUST appear in the request envelope `evidence_refs`;
- its `credential_revision_ref`, `verification_record_revision_ref`, and all supporting `resource_revision_refs` MUST appear in the request envelope `resource_revision_refs`;
- its `subject_ref` MAY appear in `actor_refs` only when that subject is an actual actor in the requested operation;
- no evidence field may override the request envelope, operation profile, binding result, consumer policy, or governance result; and
- any number of evidence objects MUST converge into one request for one governed operation.

This contract defines no automatic mapping into `authority_refs`. Such mapping is consumer-specific and MUST be explicit outside this public family.

## 12. Forbidden fields and semantics

The schema and conformance suite MUST reject additional top-level or nested properties. In particular, this family MUST NOT carry:

- `allow`, `deny`, `allowed`, `denied`, `decision`, `outcome`, `approved`, or equivalent operation-decision fields;
- customer, domain-subject, case, domain-artifact, declaration, review, submission, or execution payloads;
- engagement, assignment, workflow, or case-state mutation fields;
- price, fee, commission, revenue share, payout, wallet, settlement, invoice, or payment data;
- raw credential attachments or attachment contents;
- authentication secrets, session tokens, or private signing keys;
- product, portal, repository, internal service, database, regulator, or professional-domain-specific constants; or
- private topology, admission, enforcement, orchestration, or governance implementation semantics.

## 13. Versioning

`v1.0` is selected explicitly by `contract_family` plus `contract_version`.

After publication:

- removing or renaming a field, changing requiredness, changing a constant or enum, weakening integrity, changing identifier meaning, or changing a semantic invariant is breaking and requires a new contract version;
- an optional additive field requires explicit review for public safety and interoperability before admission;
- producer-specific extensions are forbidden inside the v1.0 wire object; and
- private implementation metadata MUST remain outside the public object.

## 14. Repository responsibility and publication artifacts

The canonical public standard belongs only in `WembleyAISolutions/weai-contracts`.

Publication requires this complete artifact set:

| Responsibility | Required repository path |
| --- | --- |
| Normative requirements | `semantics/professional-authority-evidence-v1.0.md` |
| Shared v1.0 public definitions | `contracts/common/v1.0/defs.schema.json` |
| Executable wire schema | `contracts/professional-authority-evidence/v1.0/evidence.schema.json` |
| Published valid example | `contracts/professional-authority-evidence/v1.0/evidence.example.json` |
| Positive fixtures | `tests/conformance/v1.0/positive/professional-authority-evidence.*.json` |
| Negative fixtures | `tests/conformance/v1.0/negative/professional-authority-evidence.*.json` |
| Semantic fixtures | `tests/conformance/v1.0/semantic/professional-authority-evidence.*.json` |
| Conformance registration | `tests/conformance/manifest.json` and `tests/conformance/run.mjs` |
| Public family index | `README.md` |

Existing v0.1 and v0.2 schemas, examples, semantics, fixtures, reason codes, and wire behavior MUST remain unchanged.

Product connectors, producer adapters, consumer adapters, resolver logic, trust configuration, domain policy, and governance implementation MUST NOT be added to this public repository.

## 15. Minimum conformance matrix

### Positive

- active individual credential;
- active organisation credential;
- structurally valid inactive, expired, suspended, revoked, and unknown observations;
- valid optional validity interval;
- valid superseding evidence with a new credential or verification revision;
- exact byte-identical replay; and
- multiple sorted, unique scope, evidence, and resource-revision references.

### Schema-negative

- every missing required field, independently;
- wrong family, version, type, or subject-kind constant;
- unknown credential status;
- empty opaque reference;
- empty required reference array;
- duplicate reference-array item;
- unknown additional top-level property;
- unknown additional nested property;
- malformed timestamp;
- malformed integrity object; and
- digest that is short, uppercase, or non-hexadecimal.

### Semantic-negative

- integrity mismatch;
- unsorted reference array;
- `status_as_of > verified_at`;
- `verified_at > issued_at`;
- inverted validity interval;
- active status outside a supplied validity interval;
- expired status without an elapsed `valid_until`;
- self-supersession or predecessor from a different credential lineage;
- same `evidence_ref` with different bytes;
- new `evidence_ref` with unchanged credential and verification revisions; and
- any prohibited governance, execution, customer, case, or financial field.

Producer implementations MUST independently test that editable or unresolved revisions cannot be published. The public schema cannot resolve this condition because reference resolution and storage are outside this contract.

## 16. Publication gate

The family is publishable only when:

1. all required artifacts in section 14 exist;
2. `npm test` passes with the complete v0.1, v0.2, and v1.0 corpus;
3. all published example digests recompute exactly;
4. public-boundary scans find no product names, private topology, financial semantics, or internal implementation details;
5. a producer fixture and a consumer fixture independently agree on the same canonical bytes and digest; and
6. architecture review confirms the invariant: evidence is not authority, binding, governance, admission, or execution.
