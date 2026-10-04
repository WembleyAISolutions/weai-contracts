# Source Session Handoff v1.0 — Normative Requirements

Status: public implementation baseline  
Contract family: `source-session-handoff`  
Contract version: `v1.0`  
Profile: `oauth2-authorization-code-pkce-s256-v1`  
Redemption success shape: public option A, compact JWS authenticated context

## 1. Parties and planes

This family is the user-entry session handoff. The issuing source authenticates the user and attests the source context. The handoff runtime carries the protocol. The receiving party resolves its own identity, authority, and session after the context is issued.

Two planes are distinct.

A. User-entry session handoff. The receiver or runtime initiates OAuth 2.0 Authorization Code with PKCE S256. This document freezes that plane.

B. Source data plane. Programme, resource, claim, commercial, and event APIs, and any other machine-to-machine operational integration, are not this contract.

`source-session-handoff` v1.0 does not define the Business Growth operational data gateway. It does not absorb any Business Growth operational API.

`AgentBusinessLoadRequest` and `AgentBusinessLoadResult` are a distinct post-session receiver companion and loading contract. They are not initiation, authenticated context, OAuth authorization, receiver identity proof, or receiver authority. They MUST NOT establish source identity, establish receiver identity, replace this OAuth handoff, create a receiver session, or turn a source role into a receiver role. They may execute only after the receiving party has established receiver identity, authority, and session.

## 2. Direction

The only normative sequence is:

1. Receiver or runtime initiation.
2. Source authorization endpoint.
3. Source session authentication or reuse.
4. Authorization code.
5. Server-side redemption and PKCE S256.
6. Issuer-attested authenticated context.
7. Receiver identity resolution.
8. Receiver authority resolution.
9. Receiver session establishment.

The source MUST NOT create a receiver session. Source role, permission, and membership values MUST NOT become receiver authority directly.

A conforming object does not authenticate receiver identity. It does not grant permission, role, membership, runtime admission, or access.

## 3. Wire objects

Each v1.0 JSON object except the authorization callback is a closed object with `additionalProperties: false`. The authorization callback is two closed alternatives, success and denial, each with `additionalProperties: false`. Ad-hoc extension fields are forbidden.

Published objects:

1. `initiation` — server-side start of one handoff. It MUST NOT be copied wholesale into browser-visible parameters.
2. `authorization-request` — closed request sent toward the source authorization endpoint.
3. `authorization-response` — browser callback of `code` and `state`, or one safe OAuth error and `state`.
4. `redemption-request` — server-to-server redemption. It is not a browser object.
5. `redemption-response` — closed success body. Public option A. Failure uses the public failure object.
6. `authenticated-context` — the JSON payload of the compact JWS. It is the only claim vocabulary.
7. `trusted-source-registration` — public verification material.
8. `failure` — closed machine failure. It is not placed in the browser URL.

Unsupported `contract_family`, `contract_version`, or `profile` values fail closed as `unsupported_version`. The failure object that reports that outcome is itself `source-session-handoff` / `v1.0` / `oauth2-authorization-code-pkce-s256-v1`.

Browser-authored identity, organisation, role, and scope are never trusted. Integrity or hash equality is not authenticated identity. PKCE S256 proves verifier possession only. It does not identify a person or organisation and does not grant receiver access.

## 4. Initiation

Required fields: `contract_family`, `contract_version`, `profile`, `purpose`, `handoff_ref`, `issuer`, `receiver_ref`, `client_ref`, `destination_uri`, `transaction_ref`, `nonce_ref`, `requested_record_scope_refs`, `initiated_at`, `expires_at`, `correlation_ref`.

`purpose` is an opaque string compared by exact equality across initiation, authorization request, redemption request, authenticated context, and trusted-source registration.

`requested_record_scope_refs` MUST be a non-empty array of unique bounds. A wildcard asterisk, whitespace, and duplicates are schema-invalid. A bound that is a proper UTF-16 prefix of another bound in the same array is ambiguous and fails closed as `scope_invalid` even when the schema accepts the strings. An empty array is the empty-set case and is `scope_invalid`. A numeric, empty-string, or other structurally illegal element is `malformed`, not `scope_invalid`.

`expires_at` MUST be strictly later than `initiated_at`, and the duration MUST be no greater than 60 seconds. That window is the authorization-code lifetime. The code window maximum remains 60 seconds.

`initiated_at` and `expires_at` MUST each be a calendar-valid instant in the proleptic Gregorian calendar for years 0000 through 9999. Comparison uses the whole-second civil day count and the exact fractional digit string. It does not use a host date library, does not apply a 0–99 year offset, and does not truncate or round fractional seconds.

`destination_uri` MUST satisfy section 8. The structural schema pattern is only a screen.

## 5. Authorization request and response

### 5.1 Authorization request

Required fields: `contract_family`, `contract_version`, `profile`, `response_type` = `code`, `client_ref`, `receiver_ref`, `destination_uri`, `state`, `code_challenge`, `code_challenge_method` = `S256`, `handoff_ref`, `transaction_ref`, `correlation_ref`, `purpose`.

On the authorization redirect, query parameter names are these field names. This profile does not rename `destination_uri`.

`state` is an independent high-entropy opaque browser correlation. The runtime binds it server-side to `transaction_ref`. `state` MUST NOT be required to equal `transaction_ref`.

The PKCE verifier uses the RFC 7636 verifier grammar: ASCII unreserved characters, 43 to 128 characters. The challenge is `BASE64URL(SHA256(ASCII(verifier)))` with no padding. `plain` is rejected.

The authorization request MUST NOT carry, and the browser MUST NOT be shown:

- subject identity
- organisation or account identity
- source session or source context references
- source role or source permissions
- record scopes
- receiver role, membership, or grant
- the PKCE verifier
- tokens or assertions

### 5.2 Authorization response

Success fields are only `code` and `state`. Denial fields are only one safe OAuth error and `state`.

The safe error enum is `invalid_request`, `unauthorized_client`, `access_denied`, `unsupported_response_type`, `server_error`, `temporarily_unavailable`.

The callback carries no identity, role, scope, context, destination, or verifier fields.

The authorization code is opaque, drawn from a cryptographically secure generator with at least 128 bits of entropy, single-use, and limited to a maximum lifetime of 60 seconds.

If the client or the destination is not trusted, do not redirect the browser to the supplied destination. When a safe registered redirect is already established, browser denial may use only a safe OAuth error and `state`. Do not expose internal machine diagnostics or identity state in URL parameters.

## 6. Redemption

### 6.1 Redemption request

This object is server-to-server only. Required fields: `contract_family`, `contract_version`, `profile`, `grant_type` = `authorization_code`, `client_ref`, `destination_uri`, `authorization_code`, `code_verifier`, `handoff_ref`, `transaction_ref`, `correlation_ref`, `purpose`.

The issuer MUST atomically validate the authorization-code record against the client, the exact destination, the S256 challenge, the handoff, the transaction, the correlation, the purpose, expiry, one-time-use status, and the bound source session and context. The code record is source-server internal state. It binds the authenticated source user, session, and context established at authorization time. The code becomes unusable at the start of successful atomic redemption.

### 6.2 Redemption response — public option A

The closed success response is:

- `contract_family`, `contract_version`, `profile`
- `status` = `issued`
- `token_type` = `Bearer`
- `assertion_format` = `compact-jws-authenticated-context-v1`
- `assertion`
- `expires_in`

`assertion` is a compact JWS. Its payload is exactly one public authenticated-context v1.0 JSON object. v1.0 does not define a second claim vocabulary. It does not require duplicate private runtime claims such as simultaneous `iss` and `issuer`, `aud` and `audience`, `sub` and `subject_ref`, or `client_id` and `client_ref`.

The protected header requires `alg` and `kid` and no other members. `alg` MUST be one of `RS256`, `RS384`, `RS512`, `ES256`, `ES384`, `ES512`, `EdDSA` and MUST be permitted by the trusted-source registration. Reject `alg` = `none`, a caller-controlled `jku`, an embedded caller `jwk`, `x5u`, `x5c`, and any critical header.

`expires_in` is the exact whole-second authenticated-context lifetime, an integer from 1 through 300. If the context timestamps do not describe an integral-second lifetime matching `expires_in`, the redemption response is invalid.

Failure uses the public failure object. It does not use an alternate private token-error object. `refresh_token` is forbidden in v1.0. Unknown fields are rejected.

## 7. Authenticated context

Required fields: `contract_family`, `contract_version`, `profile`, `purpose`, `handoff_ref`, `transaction_ref`, `correlation_ref`, `issuer`, `audience`, `receiver_ref`, `client_ref`, `subject_ref`, `source_session_ref`, `source_context_ref`, `organisation_ref`, `account_ref`, `record_scope_refs`, `source_role_ref`, `source_permission_refs`, `destination_uri`, `issued_at`, `expires_at`.

`subject_ref` is issuer-scoped. `source_session_ref` and `source_context_ref` MUST be distinct. The context MUST NOT outlive the source session from which it was issued.

`source_role_ref` and `source_permission_refs` are source bounds only. They do not grant receiver role, membership, grant, permission, tenant authority, admission, or session.

The maximum lifetime is 5 minutes. Allowed clock skew in v1.0 is 0 seconds. An evaluation instant before `issued_at` is `unverified`. An evaluation instant at or after `expires_at` is `expired`.

`record_scope_refs` and `source_permission_refs` use the same non-empty, unique, no-wildcard rule as initiation scopes. On the wire they MUST be sorted in ascending UTF-16 code-unit order.

`issued_at` and `expires_at` use the same calendar-valid UTC instant rules as initiation. No refresh token exists in v1.0.

A bound pair with an initiation MUST satisfy all of the following by exact string equality:

- `contract_family`, `contract_version`, `profile`, and `purpose`;
- `handoff_ref`, `transaction_ref`, `issuer`, `receiver_ref`, `client_ref`, `destination_uri`, and `correlation_ref`;
- `audience` equals the initiation `receiver_ref`;
- every `record_scope_refs` item is a member of `requested_record_scope_refs`;
- `initiated_at <= issued_at <= initiation.expires_at`.

A context issued inside the code window remains eligible until its own `expires_at`. Elapse of the code window does not truncate that context lifetime.

Issuer mismatch is `unverified` and machine code `ISSUER_MISMATCH`. Audience mismatch is `unverified` and machine code `AUDIENCE_MISMATCH`. Receiver, client, and destination mismatches are `unverified`. Purpose mismatch is `unverified` and machine code `PURPOSE_MISMATCH`.

## 8. Destination and redirect

A destination is validated in two steps. First, reject the original string when it contains whitespace, a control character, a backslash, an asterisk, a query, or a fragment, or when the authority has user information, an empty port, a non-canonical port, or a non-canonical IPv4 literal. Second, parse that same original string with a standards-compliant URL parser. The parser accepts a nonempty host and a well-formed IPv6 literal. An embedded IPv4 is accepted only in the legal final 32-bit position; any other embedded IPv4 is rejected by the parser. A path the parser would rewrite, including dot segments, is rejected. A path with empty segments, including `/a//callback`, is valid. A legitimate port, including an explicit port that a parser would omit from its serialized form, is valid.

IPv6 syntax is the parser's syntax. This contract does not publish a partial IPv6 grammar.

After syntactic validation, registered destination matching is byte-for-byte equality of the original strings. No canonicalisation is applied before that comparison. Host case, an explicit port, and IPv6 spelling are significant.

The same syntax applies to `authorization_endpoint` and `token_endpoint`.

## 9. Browser persistence

The browser MUST NOT persist:

- subject, organisation, or account identity
- source role or source permissions
- record scope
- source session or source context references
- the PKCE verifier
- the authenticated-context assertion or token
- receiver authority

These values MUST NOT be written to `localStorage` or any equivalent durable browser state.

The authorization code may appear transiently in the OAuth callback query only. The receiver callback flow MUST consume it on the server immediately and remove it from the user-visible URL. The PKCE verifier remains server-side.

## 10. Trusted-source registration

Required public fields: `registration_version`, `issuer`, `client_ref`, `receiver_ref`, `purpose`, `allowed_contract_versions`, `allowed_profiles`, `authorization_endpoint`, `token_endpoint`, `destination_uris`, `status` (`enabled`, `disabled`, or `revoked`), `algorithms`, and public `jwks`. `environment` is optional.

The permitted algorithm set is `RS256`, `RS384`, `RS512`, `ES256`, `ES384`, `ES512`, and `EdDSA`. Registration MUST NOT allow any other algorithm.

Registration contains public verification material only. It MUST NOT contain receiver role, receiver membership, grant, permission, receiver session authority, private JWK material, or a source or client secret. Caller-supplied key URLs are not trust. `jku`, `x5u`, and embedded private parameters are rejected.

`status` `disabled` is machine code `CLIENT_DISABLED`. `revoked` is `CLIENT_REVOKED`. A client that is not the registered client is `UNKNOWN_CLIENT`. Each of those results forbids redirect to the supplied destination.

## 11. Failure object

Required fields: `contract_family`, `contract_version`, `profile`, `outcome`, `code`, `retryable`, `correlation_ref`, `occurred_at`. `handoff_ref` is optional.

`outcome` remains the high-level class. `code` is the stable machine code and determines `outcome` and `retryable`. The executable matrix is `vocab/source-session-handoff-failure-v1.0.json`.

`occurred_at` MUST be a calendar-valid UTC timestamp. An impossible date, including 30 February and 29 February in a non-leap year, makes the failure object non-conformant even when the timestamp pattern matches.

The object MUST NOT carry passwords, bearer tokens, authorization codes, PKCE verifiers, customer or order records, commercial amounts, signing secrets, diagnostic text, or membership and grant assertions.

## 12. Field ownership

| Field | Objects | Comparison | Does not mean |
| --- | --- | --- | --- |
| `purpose` | initiation, authorization request, redemption request, context, registration | exact string | an operational data API |
| `state` | authorization request and response | server-side binding to `transaction_ref` | equality with `transaction_ref` |
| `code_challenge` | authorization request | S256 of the server-side verifier | the verifier itself |
| `code_verifier` | redemption request | RFC 7636, server-side only | a browser parameter |
| `authorization_code` / `code` | redemption request / callback | opaque, single-use, at least 128 bits, at most 60 seconds | a receiver session |
| `assertion` | redemption response | compact JWS of one authenticated context | a second claim set or a refresh token |
| `expires_in` | redemption response | exact integral seconds, 1 through 300 | a lifetime with clock skew |
| `source_role_ref` | context | source bound only | a receiver role |
| `source_permission_refs` | context | source bounds only | receiver permissions |
| `destination_uri` | initiation, authorization, redemption, context, registration | byte-for-byte after syntax validation | a canonicalized URL |

Opaque references are JSON strings with `minLength: 1`. This contract MUST NOT impose prefixes, UUIDs, product names, or hostnames.

Timestamps use the v1.0 UTC grammar: `Z` only, no numeric offset, no leap-second `60`, years 0000 through 9999. Instant order and duration use integer whole seconds plus the exact fractional digit string.

## 13. Semantic invariants and precedence

Schema validity is necessary and not sufficient. Conforming evaluation of a bound initiation and authenticated context MUST apply the first matching rule:

1. If a required dependency cannot be reached, the outcome is `dependency_unavailable`, `retryable` true, with no accepted context, no empty scope, no unscoped redirect, and no receiver session. Issuer unavailability uses machine code `ISSUER_UNAVAILABLE`. Any other such dependency uses `DEPENDENCY_UNAVAILABLE`.
2. If the peer `contract_family`, `contract_version`, or `profile` is not this published triple, the outcome is `unsupported_version`. Machine code `UNSUPPORTED_PROFILE` or `UNSUPPORTED_CONTRACT_VERSION` applies when that is the defect.
3. If a scope or permission element is structurally illegal — not a string, an empty string, or whitespace — the outcome is `malformed`. This classification precedes semantic scope classification.
4. If a record-scope array or `source_permission_refs` is an empty set, duplicated, wildcarded, not in ascending UTF-16 code-unit order, or contains a bound that is a proper prefix of another, or if context record scopes are not a subset of the initiation request, the outcome is `scope_invalid` and the machine code is `RECORD_SCOPE_INVALID`.
5. If the peer object otherwise fails schema validation, a timestamp is not a calendar-valid UTC instant, or `destination_uri` fails section 8, the outcome is `malformed`.
6. If the code was already consumed and this attempt is not an uncertain reconciliation of the same complete authenticated context, the outcome is `replayed`. Reconciliation MUST still pass the lifetime, revocation, binding, presentation, attestation, and source-bound rules below. A difference in any normative field fails closed as `replayed` and MUST NOT mint another receiver session.
7. If a lifetime is inverted, non-positive, or over the profile maximum, if context `issued_at` falls outside the initiation code window, if the context outlives the source session, or if the evaluation instant is at or after the context `expires_at`, the outcome is `expired`. Allowed clock skew is 0 seconds. An evaluation instant before `issued_at` is `unverified`. Elapse of the code window after a timely `issued_at` does not by itself expire the context. Lifetime comparison retains full fractional-second precision. Exactly 60 seconds is within the code maximum. Exactly 300 seconds is within the context maximum. Any greater duration is expired.
8. If issuer, audience, receiver, client, destination, handoff, transaction, correlation, or purpose binding does not match, or the issuer attestation is revoked, the outcome is `unverified`.
9. If the presentation channel is not server-side redemption, the issuer attestation is absent, subject, organisation, account, role, permission bounds, `source_session_ref`, or `source_context_ref` differ from that attestation, or the two source references are not distinct, the outcome is `identity_not_bound`.
10. If a caller treats the source role or source permission bounds as receiver access, the outcome is `permission_denied`.

A source context that passes these rules is still not receiver access. This family does not mint a receiver session on acceptance, replay, reconciliation, or dependency failure.

Redemption of an authorization code applies the first matching machine code:

1. `ISSUER_UNAVAILABLE` or `DEPENDENCY_UNAVAILABLE`
2. `UNSUPPORTED_PROFILE` or `UNSUPPORTED_CONTRACT_VERSION`
3. `MALFORMED_REQUEST`
4. `INVALID_PKCE_METHOD`
5. `UNKNOWN_CLIENT`, `CLIENT_DISABLED`, or `CLIENT_REVOKED`
6. `DESTINATION_MISMATCH`
7. `CODE_UNKNOWN`
8. `CODE_EXPIRED`
9. `CODE_REPLAYED`
10. `PKCE_MISMATCH`
11. `PURPOSE_MISMATCH`, `HANDOFF_MISMATCH`, `TRANSACTION_MISMATCH`, or `CORRELATION_MISMATCH`
12. `SOURCE_ROLE_CONTEXT_INVALID` when the code record has no distinct bound source session and source context

Only a record that passes every atomic check is consumed. Consumption is single-use.

## 14. Failure and retry matrix

Only `ISSUER_UNAVAILABLE` and `DEPENDENCY_UNAVAILABLE` are automatic-machine retryable. `SOURCE_AUTHENTICATION_REQUIRED` needs user action and is not automatic-machine retryable.

`safe_browser_behavior` `do_not_redirect` means the browser is not sent to the supplied destination. `safe_oauth_error_and_state` is allowed only after a safe registered redirect is already established, and the query is only the safe OAuth error plus `state`. `user_action_required` is source authentication, not a machine retry. `retry_same_attempt_no_unscoped_redirect` reconciles the same attempt and never becomes success, an empty context, or an unscoped redirect.

| Code | Outcome | Retryable | Browser |
| --- | --- | --- | --- |
| `SOURCE_AUTHENTICATION_REQUIRED` | `identity_not_bound` | false | user action |
| `UNKNOWN_CLIENT` | `unverified` | false | do not redirect |
| `CLIENT_DISABLED` | `unverified` | false | do not redirect |
| `CLIENT_REVOKED` | `unverified` | false | do not redirect |
| `DESTINATION_MISMATCH` | `unverified` | false | do not redirect |
| `UNSUPPORTED_PROFILE` | `unsupported_version` | false | safe OAuth error and state |
| `UNSUPPORTED_CONTRACT_VERSION` | `unsupported_version` | false | safe OAuth error and state |
| `INVALID_PKCE_METHOD` | `malformed` | false | safe OAuth error and state |
| `PKCE_MISMATCH` | `unverified` | false | safe OAuth error and state |
| `CODE_EXPIRED` | `expired` | false | safe OAuth error and state |
| `CODE_REPLAYED` | `replayed` | false | safe OAuth error and state |
| `CODE_UNKNOWN` | `unverified` | false | safe OAuth error and state |
| `SOURCE_ACCOUNT_DISABLED` | `permission_denied` | false | safe OAuth error and state |
| `ORGANISATION_MISMATCH` | `unverified` | false | safe OAuth error and state |
| `RECORD_SCOPE_INVALID` | `scope_invalid` | false | safe OAuth error and state |
| `SOURCE_ROLE_CONTEXT_INVALID` | `identity_not_bound` | false | safe OAuth error and state |
| `MALFORMED_REQUEST` | `malformed` | false | safe OAuth error and state |
| `MALFORMED_REDEMPTION_RESPONSE` | `malformed` | false | safe OAuth error and state |
| `MALFORMED_AUTHENTICATED_CONTEXT` | `malformed` | false | safe OAuth error and state |
| `ISSUER_MISMATCH` | `unverified` | false | safe OAuth error and state |
| `AUDIENCE_MISMATCH` | `unverified` | false | safe OAuth error and state |
| `CONTEXT_EXPIRED` | `expired` | false | safe OAuth error and state |
| `PURPOSE_MISMATCH` | `unverified` | false | safe OAuth error and state |
| `HANDOFF_MISMATCH` | `unverified` | false | safe OAuth error and state |
| `TRANSACTION_MISMATCH` | `unverified` | false | safe OAuth error and state |
| `CORRELATION_MISMATCH` | `unverified` | false | safe OAuth error and state |
| `ISSUER_UNAVAILABLE` | `dependency_unavailable` | true | retry the same attempt, no unscoped redirect |
| `DEPENDENCY_UNAVAILABLE` | `dependency_unavailable` | true | retry the same attempt, no unscoped redirect |

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

## 15. Companion load boundary

`AgentBusinessLoadRequest` / `AgentBusinessLoadResult` is not source-session-handoff initiation, not an authorization request, and not an authenticated context. It is a receiver post-session companion and loading contract. It MUST NOT establish source identity, establish receiver identity, replace OAuth handoff, create a receiver session, or turn a source role into a receiver role. It may execute only after receiver identity, authority, and session have been established by the receiver.

## 16. Compatibility

Source Session Handoff v1.0 is additive. It does not revise frozen v0.1, frozen v0.2, or professional-authority-evidence v1.0.

Selection is explicit:

- `contract_family` = `source-session-handoff`
- `contract_version` = `v1.0`
- `profile` = `oauth2-authorization-code-pkce-s256-v1`

Within this published triple, `additionalProperties` is false on every wire object. Removing, renaming, or redefining a field, constant, outcome, machine code, or lifetime maximum is breaking and requires a new published revision.

This family is not an execution request, a status result, an error-denial object, a professional-authority evidence object, or a Business Growth operational API.

A valid schema does not authenticate identity and does not grant permission, role, membership, runtime admission, or access.

## 17. Out of scope

This repository does not implement OAuth endpoints, token issuance, session issuance, storage, HTTP services, or product adapters. Cryptographic verification uses the public JWKS in trusted-source registration; private keys are not published.

The wire objects MUST NOT carry passwords, native source bearer tokens other than the option A assertion on the server-side redemption response, the PKCE verifier on any browser object, raw customer or order records, commercial amounts, or source signing secrets.

## 18. Conformance

`npm test` validates this family together with frozen v0.1, v0.2, and professional-authority-evidence v1.0.

Minimum coverage includes valid initiation, authorization request, authorization callback, redemption request, redemption response, signed authenticated-context payload structure, trusted-source registration, exact destination matching, a double-slash path, malformed IPv6 and illegal embedded IPv4, PKCE S256, PKCE plain rejection, PKCE mismatch, one-time, expired, replayed, and unknown codes, wrong, disabled, and revoked clients, wrong issuer, audience, purpose, profile, and contract version, malformed request, redemption response, and authenticated context, context lifetime over 5 minutes, refresh token rejection, unknown fields on every closed object, source role distinct from receiver role, browser-sensitive field prohibition, a callback of only safe fields, structurally illegal scope classified as `malformed`, scope escalation classified as `scope_invalid`, and replay or reconciliation that never creates a second receiver session.

Calendar and fractional timestamp tests remain in force.

## 19. Publication artifacts

| Responsibility | Path |
| --- | --- |
| Protocol semantics | `semantics/source-session-handoff-v1.0.md` |
| Failure and machine-code matrix | `vocab/source-session-handoff-failure-v1.0.json` |
| Shared definitions | `contracts/source-session-handoff/v1.0/defs.schema.json` |
| Initiation | `contracts/source-session-handoff/v1.0/initiation.schema.json` |
| Authorization request | `contracts/source-session-handoff/v1.0/authorization-request.schema.json` |
| Authorization response | `contracts/source-session-handoff/v1.0/authorization-response.schema.json` |
| Redemption request | `contracts/source-session-handoff/v1.0/redemption-request.schema.json` |
| Redemption response | `contracts/source-session-handoff/v1.0/redemption-response.schema.json` |
| Authenticated context | `contracts/source-session-handoff/v1.0/authenticated-context.schema.json` |
| Trusted-source registration | `contracts/source-session-handoff/v1.0/trusted-source-registration.schema.json` |
| Failure | `contracts/source-session-handoff/v1.0/failure.schema.json` |
| Conformance fixtures | `tests/conformance/source-session-handoff/v1.0/` |
| Runner registration | `tests/conformance/manifest.json` and `tests/conformance/run.mjs` |
| Public family index | `README.md` |
