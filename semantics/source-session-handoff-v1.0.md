# Source Session Handoff v1.0 — Normative Requirements

Status: public compatibility baseline  
Contract family: `source-session-handoff`  
Contract version: `v1.0`  
Profile: `oauth2-authorization-code-pkce-s256-v1`

## 1. Purpose

Source Session Handoff v1.0 is a public-safe wire contract for one handoff attempt from an issuing source to a receiving party.

The profile is OAuth 2.0 Authorization Code with PKCE S256 only. This repository publishes the initiation, the issuer-attested context, and the closed failure. It does not publish an OAuth endpoint, a token response schema, or a receiver session.

A conforming object does not authenticate identity. It does not grant permission, role, membership, runtime admission, or access.

## 2. Protocol semantics

The only contract direction is:

`receiver initiation -> issuer attestation -> authenticated context or failure`

Three wire objects are distinct:

1. `initiation` — the receiver's server-side request to start one handoff.
2. `authenticated-context` — the issuer-attested bound produced only after server-side redemption.
3. `failure` — a closed outcome when the attempt does not produce a usable source context.

Normative rules:

1. Browser-authored identity, organisation, role, and scope are never trusted. Schema-valid JSON presented by the browser is not an issuer attestation.
2. Integrity or hash equality is not authenticated identity. PKCE S256 proves verifier possession only inside the referenced OAuth profile. It does not identify a person or organisation and does not grant receiver access. Equality of opaque references is not identity either.
3. Source references do not create receiver roles or permissions. `source_role_ref` and `source_permission_refs` are source-attested bounds only.
4. Missing, empty, wildcard, ambiguous, expired, revoked, or mismatched context fails closed.
5. Effective receiver access is determined later by both the source bounds and the receiver's current authority. This family does not perform that decision. Using source bounds alone is `permission_denied`.
6. `dependency_unavailable` is never converted into success, an empty context, or an unscoped redirect.

The authorization code is opaque and single-use. It becomes unusable at the start of successful atomic redemption. An uncertain exchange may be queried or reconciled. Reconciliation MUST NOT create a second receiver session. This contract does not itself issue a receiver session.

No identity, organisation, role, scope, authorization code, PKCE verifier, or token material is placed in redirect URLs or in persistent browser storage. The browser may retain only the opaque transaction correlation needed to match `transaction_ref`.

Standard OAuth token responses are referenced by this profile and are not redefined here. The authenticated-context object is not an access token, refresh token, or identity token.

## 3. Wire objects

Each v1.0 wire object MUST be a JSON object with `additionalProperties: false`. Ad-hoc extension fields are forbidden. A future field requires a separately published compatible revision.

Unsupported `contract_family`, `contract_version`, or `profile` values fail closed as `unsupported_version`. The failure object that reports that outcome is itself `source-session-handoff` / `v1.0` / `oauth2-authorization-code-pkce-s256-v1`.

### 3.1 Initiation

Required fields: `contract_family`, `contract_version`, `profile`, `handoff_ref`, `issuer`, `receiver_ref`, `client_ref`, `destination_uri`, `transaction_ref`, `nonce_ref`, `requested_record_scope_refs`, `initiated_at`, `expires_at`, `correlation_ref`.

`requested_record_scope_refs` MUST be a non-empty array of unique bounds. A wildcard asterisk, whitespace, and duplicates are schema-invalid. A bound that is a proper UTF-16 prefix of another bound in the same array is ambiguous and fails closed as `scope_invalid` even when the schema accepts the strings.

`expires_at` MUST be strictly later than `initiated_at`, and the duration MUST be no greater than 60 seconds. That window is the authorization-code lifetime for the attempt.

### 3.2 Authenticated context

Required fields: `contract_family`, `contract_version`, `profile`, `handoff_ref`, `transaction_ref`, `issuer`, `audience`, `receiver_ref`, `client_ref`, `subject_ref`, `source_session_ref`, `source_context_ref`, `organisation_ref`, `account_ref`, `record_scope_refs`, `source_role_ref`, `source_permission_refs`, `destination_uri`, `issued_at`, `expires_at`, `correlation_ref`.

`subject_ref` is issuer-scoped. `organisation_ref` and `account_ref` are issuer-scoped references. `source_session_ref` and `source_context_ref` are opaque source references and MUST be distinct.

`record_scope_refs` and `source_permission_refs` use the same non-empty, unique, no-wildcard rule as initiation scopes. On the wire they MUST be sorted in ascending UTF-16 code-unit order.

`expires_at` MUST be strictly later than `issued_at`, and the duration MUST be no greater than 5 minutes. No refresh token exists in v1.0.

A bound pair with an initiation MUST satisfy all of the following by exact string equality:

- `contract_family`, `contract_version`, and `profile`;
- `handoff_ref`, `transaction_ref`, `issuer`, `receiver_ref`, `client_ref`, `destination_uri`, and `correlation_ref`;
- `audience` equals the initiation `receiver_ref`;
- every `record_scope_refs` item is a member of `requested_record_scope_refs`;
- `initiated_at <= issued_at <= initiation.expires_at`.

A context issued inside the code window remains eligible until its own `expires_at`. Elapse of the code window does not truncate that context lifetime.

Issuer mismatch is an issuer mix-up and is `unverified`. Audience, receiver, client, and destination mismatches are `unverified`.

### 3.3 Failure

Required fields: `contract_family`, `contract_version`, `profile`, `outcome`, `retryable`, `correlation_ref`, `occurred_at`.

`handoff_ref` is optional. `correlation_ref` remains required when no handoff reference has been assigned.

The object MUST NOT carry passwords, bearer tokens, authorization codes, PKCE verifiers, customer or order records, commercial amounts, signing secrets, diagnostic text, or membership and grant assertions. `additionalProperties: false` is the structural enforcement.

## 4. Field and ownership mapping

| Field | Objects | Owner | Comparison | Does not mean |
| --- | --- | --- | --- | --- |
| `contract_family` | all | contract | constant `source-session-handoff` | a product or deployment |
| `contract_version` | all | contract | constant `v1.0` | compatibility with any other family |
| `profile` | all | contract | constant `oauth2-authorization-code-pkce-s256-v1` | a token response schema |
| `handoff_ref` | all, optional on failure | receiver, then shared | exact string | a receiver session |
| `issuer` | initiation, context | issuer identifier | exact string against the initiation | a fetched metadata document |
| `audience` | context | issuer, naming the receiver | exact string against initiation `receiver_ref` | authenticated identity or access |
| `receiver_ref` | initiation, context | agreed receiving party | exact string | a receiver role |
| `client_ref` | initiation, context | receiver client registration | exact string | a client secret or access grant |
| `destination_uri` | initiation, context | pre-registered redirect | exact string, https, no query, fragment, or asterisk | a browser-rewritten location |
| `transaction_ref` | initiation, context | receiver correlation | exact string against browser-bound state | the raw state value |
| `nonce_ref` | initiation | receiver correlation | opaque reference | the raw nonce |
| `requested_record_scope_refs` | initiation | receiver request | non-empty unique explicit bounds | receiver authorization |
| `subject_ref` | context | issuer-scoped subject | exact string against the issuer attestation | a receiver account |
| `source_session_ref` | context | issuer | exact string; distinct from `source_context_ref` | a receiver session |
| `source_context_ref` | context | issuer | exact string | a receiver context store |
| `organisation_ref` | context | issuer | exact string against the issuer attestation | receiver membership |
| `account_ref` | context | issuer | exact string against the issuer attestation | a receiver account grant |
| `record_scope_refs` | context | issuer | non-empty subset of the initiation request | receiver authorization |
| `source_role_ref` | context | issuer | source-attested bound only | a receiver role |
| `source_permission_refs` | context | issuer | source-attested bounds only | receiver permissions |
| `initiated_at` | initiation | receiver clock input | start of the 60-second code window | a refresh lifetime |
| `issued_at` | context | issuer clock input | inside the initiation code window | a receiver session start |
| `expires_at` | initiation, context | window end | 60 seconds for the code; 5 minutes for the context | a refresh token |
| `correlation_ref` | all | receiver | exact string across the attempt | a credential |
| `outcome` | failure | receiver classification | closed vocabulary | success |
| `retryable` | failure | matrix | true only for `dependency_unavailable` | a second redemption |
| `occurred_at` | failure | receiver clock input | canonical UTC | a diagnostic payload |

Opaque references are JSON strings with `minLength: 1`. This contract MUST NOT impose prefixes, UUIDs, product names, or hostnames. Resolution is out of scope.

Timestamps use the v1.0 UTC grammar: `Z` only, no numeric offset, no leap-second `60`. Calendar validity is a conformance requirement.

## 5. Profile sequence

Profile `oauth2-authorization-code-pkce-s256-v1` proceeds in this order.

1. The receiver registers one exact destination URI for `client_ref`. Wildcard redirect URIs are not part of this profile.
2. The receiver builds one initiation object. The code window is at most 60 seconds. The initiation object is not placed in the browser redirect or in persistent browser storage.
3. The browser is sent to the issuer authorization interaction with the registered client, PKCE S256 only, the exact destination URI, and opaque state bound to `transaction_ref`. The raw PKCE verifier is not included. Identity, organisation, role, and scope payloads are not included.
4. The issuer authenticates the subject under its own rules. That authentication is not defined here.
5. The issuer returns the browser to the exact `destination_uri` with an opaque single-use authorization code and the state value. The code lifetime is at most 60 seconds. This contract does not redefine that OAuth redirect.
6. The receiver's server compares the returned state with `transaction_ref` and the expected issuer with `issuer` before redemption. A mismatch is `unverified`.
7. The receiver's server redeems the code. Redemption is server-side only. PKCE `plain` is unsupported and fails closed. The verifier is not written to these wire objects, to the redirect, or to persistent browser storage.
8. At the start of successful atomic redemption the code becomes unusable. The issuer's standard token response is consumed as defined by the referenced OAuth specification and is not stored as this family's wire object. The receiver then holds at most one authenticated-context object. Its lifetime is at most 5 minutes. v1.0 has no refresh token.
9. If the exchange result is uncertain, the receiver may query or reconcile with `handoff_ref` and `transaction_ref`. Reconciliation MUST return the original context or a failure. It MUST NOT redeem again in a way that creates a second receiver session.
10. Any failed check emits one failure object. `dependency_unavailable` may be retried for reconciliation of the same attempt only.

## 6. Frozen transport rules

This profile freezes the following. A different transport requires a separately published profile or contract revision.

- OAuth 2.0 Authorization Code;
- PKCE S256 only;
- exact registered redirect URI;
- browser-bound state and transaction correlation;
- issuer mix-up defence by exact issuer equality;
- opaque single-use authorization code;
- code lifetime no greater than 60 seconds;
- server-side redemption only;
- access and context lifetime no greater than 5 minutes;
- no refresh token in v1.0;
- the code becomes unusable at the start of successful atomic redemption;
- uncertain exchange may be queried or reconciled and MUST NOT create a second receiver session;
- no identity or scope payload in redirect URLs or persistent browser storage;
- standard OAuth token responses are referenced, not redefined.

## 7. Semantic invariants and precedence

Schema validity is necessary and not sufficient. Conforming evaluation MUST apply the first matching rule:

1. If a required dependency cannot be reached, the outcome is `dependency_unavailable`, `retryable` true, with no accepted context, no empty scope, no unscoped redirect, and no receiver session.
2. If the peer `contract_family`, `contract_version`, or `profile` is not this published triple, the outcome is `unsupported_version`.
3. If a record-scope array or `source_permission_refs` is empty, duplicated, wildcarded, not in ascending UTF-16 code-unit order, or contains a bound that is a proper prefix of another, or if context record scopes are not a subset of the initiation request, the outcome is `scope_invalid`.
4. If the peer object otherwise fails schema validation, the outcome is `malformed`.
5. If the code was already consumed, the outcome is `replayed`. An uncertain exchange may reconcile only the same complete authenticated context that was redeemed. A difference in any normative field fails closed as `replayed` and MUST NOT mint another receiver session.
6. If a lifetime is inverted, non-positive, or over the profile maximum, if context `issued_at` falls outside the initiation code window, or if the evaluation instant is at or after the context `expires_at`, the outcome is `expired`. An evaluation instant before `issued_at` fails closed as `unverified`. Elapse of the code window after a timely `issued_at` does not by itself expire the context. Lifetime comparison retains the full fractional-second precision of each timestamp and does not round. Exactly 60 seconds is within the code maximum, and exactly 300 seconds is within the context maximum. Any greater duration is expired.
7. If issuer, audience, receiver, client, destination, handoff, transaction, or correlation binding does not match, or the issuer attestation is revoked, the outcome is `unverified`.
8. If the presentation channel is not server-side redemption, the issuer attestation is absent, subject, organisation, account, role, permission bounds, `source_session_ref`, or `source_context_ref` differ from that attestation, or the two source references are not distinct, the outcome is `identity_not_bound`.
9. If a caller treats the source role or source permission bounds as receiver access, the outcome is `permission_denied`.

A source context that passes rules 1–8 is still not receiver access. Receiver current authority is a later decision. This family does not mint a receiver session on acceptance, replay, reconciliation, or dependency failure.

## 8. Failure and retry matrix

The executable matrix is `vocab/source-session-handoff-failure-v1.0.json`. The schema enum and `retryable` constants MUST match it.

| Outcome | Retryable | Required result |
| --- | --- | --- |
| `malformed` | false | Reject the same bytes. Do not infer a context. |
| `unverified` | false | Do not accept the mismatched or revoked binding. |
| `expired` | false | Do not extend the window. A later attempt is a new handoff. |
| `replayed` | false | Do not create a second receiver session. |
| `identity_not_bound` | false | Do not trust browser-authored or forged identity fields. |
| `scope_invalid` | false | Do not substitute an empty, wildcard, or broader scope. |
| `permission_denied` | false | Do not convert source bounds into receiver access. |
| `unsupported_version` | false | Do not negotiate an unpublished version or profile. |
| `dependency_unavailable` | true | Reconcile the same attempt only. Never success, empty context, or an unscoped redirect. |

Every failure carries `correlation_ref` and `occurred_at`. `handoff_ref` is included only when the attempt already has one. No sensitive diagnostic material is permitted.

## 9. Compatibility note

Source Session Handoff v1.0 is additive. It does not revise frozen v0.1, frozen v0.2, or professional-authority-evidence v1.0.

Selection is explicit:

- `contract_family` = `source-session-handoff`
- `contract_version` = `v1.0`
- `profile` = `oauth2-authorization-code-pkce-s256-v1`

`v1.0` on another family is a different contract. A missing, unknown, or newer version or profile fails closed as `unsupported_version`. Implementations MUST NOT treat a later revision as a silent replacement.

Within this published triple:

- `additionalProperties` is false on every wire object;
- ad-hoc extension fields are forbidden;
- removing, renaming, or redefining a field, constant, outcome, or lifetime maximum is breaking and requires a new published revision;
- an additional field, outcome, or profile requires a separately published compatible revision before use.

This family is not an execution request, a status result, an error-denial object, or a professional-authority evidence object. It MUST NOT be wrapped into those shapes to simulate compatibility.

A valid schema does not authenticate identity and does not grant permission, role, membership, runtime admission, or access.

## 10. Out of scope

This repository does not implement cryptographic verification, OAuth endpoints, token issuance, session issuance, storage, HTTP services, or product adapters.

Private topology, internal trust configuration, private keys, secrets, hostnames, and enforcement implementation are out of scope.

The wire objects MUST NOT carry passwords, native source bearer tokens, authorization codes, the PKCE verifier, raw customer or order records, commercial amounts, or source signing secrets.

## 11. Conformance

`npm test` validates this family together with frozen v0.1, v0.2, and professional-authority-evidence v1.0.

Minimum coverage:

- valid initiation and authenticated context;
- missing required fields;
- additional unknown fields;
- empty, duplicate, and wildcard scopes;
- issuer, audience, receiver, and destination mismatch;
- expired and inverted lifetimes, including the 60-second and 5-minute maxima;
- unsupported contract version and profile;
- forged and browser-authored context rejection;
- replay and `dependency_unavailable`, including the ban on a second receiver session and on converting dependency failure into success.

## 12. Publication artifacts

| Responsibility | Path |
| --- | --- |
| Protocol semantics, ownership, sequence, matrix, compatibility | `semantics/source-session-handoff-v1.0.md` |
| Executable failure and retry matrix | `vocab/source-session-handoff-failure-v1.0.json` |
| Shared structural definitions | `contracts/source-session-handoff/v1.0/defs.schema.json` |
| Initiation schema and example | `contracts/source-session-handoff/v1.0/initiation.schema.json` |
| Authenticated-context schema and example | `contracts/source-session-handoff/v1.0/authenticated-context.schema.json` |
| Failure schema and example | `contracts/source-session-handoff/v1.0/failure.schema.json` |
| Conformance fixtures | `tests/conformance/source-session-handoff/v1.0/` |
| Runner registration | `tests/conformance/manifest.json` and `tests/conformance/run.mjs` |
| Public family index | `README.md` |
