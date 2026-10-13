import assert from "node:assert/strict";
import { createPublicKey, generateKeyPairSync, sign, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import Ajv2020 from "ajv/dist/2020.js";
import {
  assessAuthorizationRequest,
  assessRedemption,
  assessSourceSessionHandoff,
  authorizationRequestDestinationAccepted,
  browserCallbackQueryAllowed,
  browserProhibitedFields,
  compareInstants,
  contextSemanticsHold,
  destinationUriValid,
  destinationsExactMatch,
  durationWithin,
  failureObjectConforms,
  initiationSemanticsHold,
  inspectCompactJws,
  integralSecondLifetime,
  jwsHeaderAccepted,
  pkceChallengeCanonical,
  pkceChallengeFor,
  pkceVerifierValid,
  prefixScanEvidence,
  redemptionResponseMatchesContext,
  registrationEndpointsAccepted,
  registrationPermitsRedirect,
  parseUtc,
  retryableFor,
  sameCompleteAuthenticatedContext,
  scopeArrayInvalid,
} from "./source-session-handoff/semantics.mjs";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "../..");
const manifest = JSON.parse(
  readFileSync(join(repoRoot, "tests/conformance/manifest.json"), "utf8"),
);

const FAMILY = "source-session-handoff";
const VERSION = "v1.0";
const PROFILE = "oauth2-authorization-code-pkce-s256-v1";
const CODE_WINDOW_SECONDS = 60n;
const CONTEXT_WINDOW_SECONDS = 300n;
const EVALUATION_AT = "2026-08-15T00:00:30Z";

const INITIATION_SCHEMA = "contracts/source-session-handoff/v1.0/initiation.schema.json";
const AUTHZ_REQUEST_SCHEMA = "contracts/source-session-handoff/v1.0/authorization-request.schema.json";
const AUTHZ_RESPONSE_SCHEMA = "contracts/source-session-handoff/v1.0/authorization-response.schema.json";
const REDEMPTION_REQUEST_SCHEMA = "contracts/source-session-handoff/v1.0/redemption-request.schema.json";
const REDEMPTION_RESPONSE_SCHEMA = "contracts/source-session-handoff/v1.0/redemption-response.schema.json";
const CONTEXT_SCHEMA = "contracts/source-session-handoff/v1.0/authenticated-context.schema.json";
const REGISTRATION_SCHEMA = "contracts/source-session-handoff/v1.0/trusted-source-registration.schema.json";
const FAILURE_SCHEMA = "contracts/source-session-handoff/v1.0/failure.schema.json";
const INITIATION_EXAMPLE = "contracts/source-session-handoff/v1.0/initiation.example.json";
const AUTHZ_REQUEST_EXAMPLE = "contracts/source-session-handoff/v1.0/authorization-request.example.json";
const AUTHZ_SUCCESS_EXAMPLE = "contracts/source-session-handoff/v1.0/authorization-response.success.example.json";
const AUTHZ_DENIAL_EXAMPLE = "contracts/source-session-handoff/v1.0/authorization-response.denial.example.json";
const REDEMPTION_REQUEST_EXAMPLE = "contracts/source-session-handoff/v1.0/redemption-request.example.json";
const REDEMPTION_RESPONSE_EXAMPLE = "contracts/source-session-handoff/v1.0/redemption-response.example.json";
const CONTEXT_EXAMPLE = "contracts/source-session-handoff/v1.0/authenticated-context.example.json";
const REGISTRATION_EXAMPLE = "contracts/source-session-handoff/v1.0/trusted-source-registration.example.json";
const FAILURE_EXAMPLE = "contracts/source-session-handoff/v1.0/failure.example.json";
const FAILURE_MATRIX = "vocab/source-session-handoff-failure-v1.0.json";
const SEMANTICS = "semantics/source-session-handoff-v1.0.md";

const PROHIBITED_FIELDS = [
  "password",
  "access_token",
  "refresh_token",
  "id_token",
  "authorization_code",
  "code_verifier",
  "bearer_token",
  "client_secret",
  "jwt_secret",
  "customer_record",
  "order_record",
  "amount",
  "membership",
  "grant",
  "detail",
  "error_description",
  "diagnostic",
];

const ajv = new Ajv2020({
  allErrors: true,
  strict: true,
  strictRequired: false,
});
ajv.addSchema(loadJson("contracts/common/v0.2/defs.schema.json"));
ajv.addSchema(loadJson("contracts/common/v1.0/defs.schema.json"));
ajv.addSchema(loadJson("contracts/source-session-handoff/v1.0/defs.schema.json"));

const validators = new Map();

function loadJson(relPath) {
  return JSON.parse(readFileSync(join(repoRoot, relPath), "utf8"));
}

function validatorFor(schemaRelPath) {
  let validate = validators.get(schemaRelPath);
  if (!validate) {
    const schema = loadJson(schemaRelPath);
    validate = schema.$id ? ajv.getSchema(schema.$id) : undefined;
    if (!validate) {
      validate = ajv.compile(schema);
    }
    validators.set(schemaRelPath, validate);
  }
  return validate;
}

function formatErrors(validate) {
  return JSON.stringify(validate.errors, null, 2);
}

function schemaForFixture(relPath) {
  const name = relPath.split("/").pop();
  if (name.startsWith("initiation.")) {
    return INITIATION_SCHEMA;
  }
  if (name.startsWith("authorization-request.")) {
    return AUTHZ_REQUEST_SCHEMA;
  }
  if (name.startsWith("authorization-response.")) {
    return AUTHZ_RESPONSE_SCHEMA;
  }
  if (name.startsWith("redemption-request.")) {
    return REDEMPTION_REQUEST_SCHEMA;
  }
  if (name.startsWith("redemption-response.")) {
    return REDEMPTION_RESPONSE_SCHEMA;
  }
  if (name.startsWith("authenticated-context.")) {
    return CONTEXT_SCHEMA;
  }
  if (name.startsWith("trusted-source-registration.")) {
    return REGISTRATION_SCHEMA;
  }
  if (name.startsWith("failure.")) {
    return FAILURE_SCHEMA;
  }
  throw new Error(`no schema for ${relPath}`);
}

function attestedFrom(context) {
  return {
    subject_ref: context.subject_ref,
    organisation_ref: context.organisation_ref,
    account_ref: context.account_ref,
    source_role_ref: context.source_role_ref,
    source_session_ref: context.source_session_ref,
    source_context_ref: context.source_context_ref,
    source_permission_refs: [...context.source_permission_refs],
    record_scope_refs: [...context.record_scope_refs],
  };
}

function presentationOf(overrides = {}) {
  const initiation = overrides.initiation ?? loadJson(INITIATION_EXAMPLE);
  const context = overrides.context ?? loadJson(CONTEXT_EXAMPLE);
  return {
    initiation,
    context,
    presentation: overrides.presentation ?? "server_redemption",
    attested: Object.hasOwn(overrides, "attested") ? overrides.attested : attestedFrom(context),
    revoked: overrides.revoked ?? false,
    dependencyAvailable: overrides.dependencyAvailable ?? true,
    codeConsumed: overrides.codeConsumed ?? false,
    uncertain: overrides.uncertain ?? false,
    redeemedContext: overrides.redeemedContext ?? null,
    at: Object.hasOwn(overrides, "at") ? overrides.at : EVALUATION_AT,
    sourceSessionExpiresAt: Object.hasOwn(overrides, "sourceSessionExpiresAt")
      ? overrides.sourceSessionExpiresAt
      : "2026-08-15T00:05:00Z",
    requestReceiverAccess: overrides.requestReceiverAccess ?? false,
    schemaValidInitiation: validatorFor(INITIATION_SCHEMA)(initiation),
    schemaValidContext: validatorFor(CONTEXT_SCHEMA)(context),
  };
}

function assertNoSession(result) {
  assert.equal(result.mintsReceiverSession, false);
  assert.equal(result.mintsAdditionalReceiverSession, false);
  assert.equal(result.synthesizedUnscopedRedirect, false);
  assert.equal(result.synthesizedEmptyContext, false);
  assert.equal(result.grantsReceiverAccess, false);
}

test("source-session-handoff positive wire fixtures validate", async (t) => {
  for (const item of manifest.source_session_handoff_v1_positive) {
    await t.test(item.name, () => {
      const validate = validatorFor(item.schema);
      const fixture = loadJson(item.fixture);
      assert.equal(schemaForFixture(item.fixture), item.schema);
      assert.equal(Object.hasOwn(fixture, "example_id"), false);
      assert.equal(Object.hasOwn(fixture, "notes"), false);
      assert.equal(validate(fixture), true, formatErrors(validate));
      if (item.schema === INITIATION_SCHEMA) {
        assert.equal(initiationSemanticsHold(fixture), true, item.fixture);
      }
      if (item.schema === CONTEXT_SCHEMA) {
        assert.equal(contextSemanticsHold(fixture), true, item.fixture);
      }
      if (item.schema === FAILURE_SCHEMA) {
        assert.equal(failureObjectConforms(fixture, true), true, item.fixture);
      }
    });
  }
});

test("source-session-handoff negative wire fixtures are rejected", async (t) => {
  for (const item of manifest.source_session_handoff_v1_negative) {
    await t.test(item.name, () => {
      const validate = validatorFor(item.schema);
      const fixture = loadJson(item.fixture);
      assert.equal(schemaForFixture(item.fixture), item.schema);
      assert.equal(validate(fixture), false, `${item.fixture} unexpectedly validated`);
      if (item.schema === FAILURE_SCHEMA) {
        assert.equal(failureObjectConforms(fixture, false), false, item.fixture);
      }
    });
  }
});

test("source-session-handoff semantic fixtures remain schema-valid", async (t) => {
  for (const item of manifest.source_session_handoff_v1_semantic) {
    await t.test(item.name, () => {
      const validate = validatorFor(item.schema);
      const fixture = loadJson(item.fixture);
      assert.equal(schemaForFixture(item.fixture), item.schema);
      assert.equal(validate(fixture), true, formatErrors(validate));
      if (item.schema === INITIATION_SCHEMA) {
        assert.equal(initiationSemanticsHold(fixture), true, item.fixture);
      }
      if (item.schema === CONTEXT_SCHEMA) {
        assert.equal(contextSemanticsHold(fixture), true, item.fixture);
      }
    });
  }
});

test("source-session-handoff published examples are a bound source context and not access", () => {
  const result = assessSourceSessionHandoff(presentationOf());
  assert.equal(result.failure, null);
  assert.equal(result.contextAccepted, true);
  assert.equal(result.reconciled, false);
  assertNoSession(result);
  const initiation = loadJson(INITIATION_EXAMPLE);
  const context = loadJson(CONTEXT_EXAMPLE);
  assert.equal(context.audience, initiation.receiver_ref);
  assert.equal(context.issuer, initiation.issuer);
  assert.equal(context.destination_uri, initiation.destination_uri);
  assert.notEqual(context.source_session_ref, context.source_context_ref);
});

test("source-session-handoff multiple explicit scopes and a proper subset are usable source bounds", () => {
  const initiation = loadJson(
    "tests/conformance/source-session-handoff/v1.0/positive/initiation.multiple-scopes.json",
  );
  const full = loadJson(
    "tests/conformance/source-session-handoff/v1.0/positive/authenticated-context.multiple-bounds.json",
  );
  const subset = loadJson(
    "tests/conformance/source-session-handoff/v1.0/positive/authenticated-context.scope-subset.json",
  );
  const fullResult = assessSourceSessionHandoff(presentationOf({
    initiation,
    context: full,
    attested: attestedFrom(full),
  }));
  assert.equal(fullResult.failure, null);
  assert.equal(fullResult.contextAccepted, true);
  assertNoSession(fullResult);
  const subsetResult = assessSourceSessionHandoff(presentationOf({
    initiation,
    context: subset,
    attested: attestedFrom(subset),
  }));
  assert.equal(subsetResult.failure, null);
  assert.equal(subsetResult.contextAccepted, true);
  assertNoSession(subsetResult);
});

test("source-session-handoff missing required fields are rejected", async (t) => {
  const cases = [
    [INITIATION_SCHEMA, INITIATION_EXAMPLE],
    [AUTHZ_REQUEST_SCHEMA, AUTHZ_REQUEST_EXAMPLE],
    [REDEMPTION_REQUEST_SCHEMA, REDEMPTION_REQUEST_EXAMPLE],
    [REDEMPTION_RESPONSE_SCHEMA, REDEMPTION_RESPONSE_EXAMPLE],
    [CONTEXT_SCHEMA, CONTEXT_EXAMPLE],
    [REGISTRATION_SCHEMA, REGISTRATION_EXAMPLE],
    [FAILURE_SCHEMA, FAILURE_EXAMPLE],
  ];
  for (const [schemaRel, exampleRel] of cases) {
    const schema = loadJson(schemaRel);
    const example = loadJson(exampleRel);
    const validate = validatorFor(schemaRel);
    assert.ok(schema.required.length > 0);
    for (const field of schema.required) {
      await t.test(`${exampleRel} missing ${field}`, () => {
        const clone = structuredClone(example);
        delete clone[field];
        assert.equal(validate(clone), false, `${field} unexpectedly remained valid`);
      });
    }
  }
});

test("source-session-handoff unknown and prohibited fields are rejected", async (t) => {
  const cases = [
    [INITIATION_SCHEMA, INITIATION_EXAMPLE],
    [AUTHZ_REQUEST_SCHEMA, AUTHZ_REQUEST_EXAMPLE],
    [AUTHZ_RESPONSE_SCHEMA, AUTHZ_SUCCESS_EXAMPLE],
    [AUTHZ_RESPONSE_SCHEMA, AUTHZ_DENIAL_EXAMPLE],
    [REDEMPTION_REQUEST_SCHEMA, REDEMPTION_REQUEST_EXAMPLE],
    [REDEMPTION_RESPONSE_SCHEMA, REDEMPTION_RESPONSE_EXAMPLE],
    [CONTEXT_SCHEMA, CONTEXT_EXAMPLE],
    [REGISTRATION_SCHEMA, REGISTRATION_EXAMPLE],
    [FAILURE_SCHEMA, FAILURE_EXAMPLE],
  ];
  for (const [schemaRel, exampleRel] of cases) {
    const validate = validatorFor(schemaRel);
    const example = loadJson(exampleRel);
    await t.test(`${exampleRel} extension_field`, () => {
      const clone = structuredClone(example);
      clone.extension_field = "not-admitted";
      assert.equal(validate(clone), false);
    });
    for (const field of PROHIBITED_FIELDS) {
      await t.test(`${exampleRel} prohibits ${field}`, () => {
        const clone = structuredClone(example);
        clone[field] = "not-admitted";
        assert.equal(validate(clone), false, `${field} unexpectedly remained valid`);
      });
    }
  }
});

test("source-session-handoff failure matrix matches the schema and semantics", () => {
  const matrix = loadJson(FAILURE_MATRIX);
  const schema = loadJson(FAILURE_SCHEMA);
  const semantics = readFileSync(join(repoRoot, SEMANTICS), "utf8");
  assert.deepEqual(matrix.outcomes.map((entry) => entry.outcome), schema.properties.outcome.enum);
  assert.equal(matrix.contract_family, FAMILY);
  assert.equal(matrix.contract_version, VERSION);
  assert.equal(matrix.profile, PROFILE);
  const validate = validatorFor(FAILURE_SCHEMA);
  const representative = new Map();
  for (const entry of matrix.codes) {
    assert.equal(typeof entry.code, "string");
    assert.equal(typeof entry.safe_browser_behavior, "string");
    assert.ok(Array.isArray(entry.phase) && entry.phase.length > 0, entry.code);
    assert.equal(entry.retryable, retryableFor(entry.outcome), entry.code);
    assert.equal(semantics.includes(`\`${entry.code}\``), true, entry.code);
    if (!representative.has(entry.outcome)) {
      representative.set(entry.outcome, entry.code);
    }
    const automatic = entry.code === "ISSUER_UNAVAILABLE" || entry.code === "DEPENDENCY_UNAVAILABLE";
    assert.equal(entry.retryable, automatic, entry.code);
  }
  assert.equal(
    matrix.codes.find((entry) => entry.code === "SOURCE_AUTHENTICATION_REQUIRED").safe_browser_behavior,
    "user_action_required",
  );
  for (const entry of matrix.outcomes) {
    assert.equal(entry.retryable, retryableFor(entry.outcome));
    assert.equal(semantics.includes(`\`${entry.outcome}\``), true, entry.outcome);
    const wire = {
      contract_family: FAMILY,
      contract_version: VERSION,
      profile: PROFILE,
      outcome: entry.outcome,
      code: representative.get(entry.outcome),
      retryable: entry.retryable,
      correlation_ref: "correlation-placeholder-001",
      occurred_at: "2026-08-15T00:00:10Z",
    };
    assert.equal(validate(wire), true, formatErrors(validate));
    assert.equal(failureObjectConforms(wire, true), true, entry.outcome);
    wire.retryable = !entry.retryable;
    assert.equal(validate(wire), false, `${entry.outcome} accepted the wrong retryable flag`);
  }
  assert.equal(semantics.includes(PROFILE), true);
  assert.equal(semantics.includes("60 seconds"), true);
  assert.equal(semantics.includes("5 minutes"), true);
  assert.equal(semantics.includes("additionalProperties"), true);
  const dependency = loadJson(
    "tests/conformance/source-session-handoff/v1.0/positive/failure.dependency-unavailable.json",
  );
  assert.equal(dependency.retryable, true);
  assert.equal(Object.hasOwn(dependency, "handoff_ref"), false);
  assert.equal(validate(dependency), true, formatErrors(validate));
});

test("source-session-handoff issuer audience receiver and destination mismatches fail closed", async (t) => {
  const cases = [
    ["tests/conformance/source-session-handoff/v1.0/semantic/authenticated-context.issuer-mismatch.json", "unverified"],
    ["tests/conformance/source-session-handoff/v1.0/semantic/authenticated-context.audience-mismatch.json", "unverified"],
    ["tests/conformance/source-session-handoff/v1.0/semantic/authenticated-context.receiver-mismatch.json", "unverified"],
    ["tests/conformance/source-session-handoff/v1.0/semantic/authenticated-context.destination-mismatch.json", "unverified"],
    ["tests/conformance/source-session-handoff/v1.0/semantic/authenticated-context.client-mismatch.json", "unverified"],
  ];
  for (const [rel, outcome] of cases) {
    await t.test(outcome + " " + rel.split("/").pop(), () => {
      const result = assessSourceSessionHandoff(presentationOf({ context: loadJson(rel) }));
      assert.equal(result.failure, outcome);
      assert.equal(result.retryable, false);
      assert.equal(result.contextAccepted, false);
      assertNoSession(result);
    });
  }
});

test("source-session-handoff expired and inverted lifetimes fail closed", async (t) => {
  const initiationCases = [
    "tests/conformance/source-session-handoff/v1.0/semantic/initiation.inverted-lifetime.json",
    "tests/conformance/source-session-handoff/v1.0/semantic/initiation.lifetime-over-60s.json",
  ];
  for (const rel of initiationCases) {
    await t.test(rel.split("/").pop(), () => {
      const result = assessSourceSessionHandoff(presentationOf({ initiation: loadJson(rel) }));
      assert.equal(result.failure, "expired");
      assert.equal(result.retryable, false);
      assertNoSession(result);
    });
  }
  const contextCases = [
    "tests/conformance/source-session-handoff/v1.0/semantic/authenticated-context.inverted-lifetime.json",
    "tests/conformance/source-session-handoff/v1.0/semantic/authenticated-context.lifetime-over-5m.json",
    "tests/conformance/source-session-handoff/v1.0/semantic/authenticated-context.issued-after-code-window.json",
  ];
  for (const rel of contextCases) {
    await t.test(rel.split("/").pop(), () => {
      const result = assessSourceSessionHandoff(presentationOf({ context: loadJson(rel) }));
      assert.equal(result.failure, "expired");
      assert.equal(result.retryable, false);
      assertNoSession(result);
    });
  }
  await t.test("elapsed context expiry", () => {
    const result = assessSourceSessionHandoff(presentationOf({ at: "2026-08-15T00:04:20Z" }));
    assert.equal(result.failure, "expired");
  });
  await t.test("context remains usable after the code window", () => {
    const result = assessSourceSessionHandoff(presentationOf({ at: "2026-08-15T00:02:00Z" }));
    assert.equal(result.failure, null);
    assert.equal(result.contextAccepted, true);
    assertNoSession(result);
  });
  await t.test("evaluation before issued_at", () => {
    const result = assessSourceSessionHandoff(presentationOf({ at: "2026-08-15T00:00:10Z" }));
    assert.equal(result.failure, "unverified");
    assert.equal(result.retryable, false);
  });
  await t.test("exact 60 second code window remains usable", () => {
    const initiation = structuredClone(loadJson(INITIATION_EXAMPLE));
    initiation.expires_at = "2026-08-15T00:01:00Z";
    const result = assessSourceSessionHandoff(presentationOf({ initiation }));
    assert.equal(result.failure, null);
    assert.equal(result.contextAccepted, true);
  });
  await t.test("61 second code window is expired", () => {
    const initiation = structuredClone(loadJson(INITIATION_EXAMPLE));
    initiation.expires_at = "2026-08-15T00:01:01Z";
    const result = assessSourceSessionHandoff(presentationOf({ initiation }));
    assert.equal(result.failure, "expired");
  });
  await t.test("exact 5 minute context remains usable", () => {
    const context = structuredClone(loadJson(CONTEXT_EXAMPLE));
    context.expires_at = "2026-08-15T00:05:20Z";
    const result = assessSourceSessionHandoff(presentationOf({
      context,
      sourceSessionExpiresAt: context.expires_at,
    }));
    assert.equal(result.failure, null);
    assert.equal(result.contextAccepted, true);
  });
  await t.test("301 second context is expired", () => {
    const context = structuredClone(loadJson(CONTEXT_EXAMPLE));
    context.expires_at = "2026-08-15T00:05:21Z";
    const result = assessSourceSessionHandoff(presentationOf({ context }));
    assert.equal(result.failure, "expired");
  });
  await t.test("60.0000000001 second code window is expired", () => {
    const initiation = structuredClone(loadJson(INITIATION_EXAMPLE));
    initiation.expires_at = "2026-08-15T00:01:00.0000000001Z";
    assert.equal(validatorFor(INITIATION_SCHEMA)(initiation), true);
    const result = assessSourceSessionHandoff(presentationOf({ initiation }));
    assert.equal(result.failure, "expired");
    assert.equal(result.contextAccepted, false);
  });
  await t.test("fractional excess on both ends is not rounded back to 60 seconds", () => {
    const initiation = structuredClone(loadJson(INITIATION_EXAMPLE));
    initiation.initiated_at = "2026-08-15T00:00:00.0000000001Z";
    initiation.expires_at = "2026-08-15T00:01:00.0000000002Z";
    assert.equal(validatorFor(INITIATION_SCHEMA)(initiation), true);
    const result = assessSourceSessionHandoff(presentationOf({ initiation }));
    assert.equal(result.failure, "expired");
  });
  await t.test("300.0000000001 second context is expired", () => {
    const context = structuredClone(loadJson(CONTEXT_EXAMPLE));
    context.expires_at = "2026-08-15T00:05:20.0000000001Z";
    assert.equal(validatorFor(CONTEXT_SCHEMA)(context), true);
    const result = assessSourceSessionHandoff(presentationOf({ context }));
    assert.equal(result.failure, "expired");
    assert.equal(result.contextAccepted, false);
  });
});

test("source-session-handoff requires an external source-session expiry bound", async (t) => {
  await t.test("missing source-session expiry fails closed", () => {
    const result = assessSourceSessionHandoff(presentationOf({ sourceSessionExpiresAt: undefined }));
    assert.equal(result.failure, "unverified");
    assert.equal(result.contextAccepted, false);
    assertNoSession(result);
  });
  await t.test("context outliving the source session is expired", () => {
    const result = assessSourceSessionHandoff(presentationOf({
      sourceSessionExpiresAt: "2026-08-15T00:04:19Z",
    }));
    assert.equal(result.failure, "expired");
    assert.equal(result.contextAccepted, false);
    assertNoSession(result);
  });
  await t.test("context not outliving the source session remains eligible", () => {
    const result = assessSourceSessionHandoff(presentationOf({
      sourceSessionExpiresAt: "2026-08-15T00:04:20Z",
    }));
    assert.equal(result.failure, null);
    assert.equal(result.contextAccepted, true);
    assertNoSession(result);
  });
});

test("source-session-handoff empty duplicate wildcard and ambiguous scopes fail closed", async (t) => {
  const schemaCases = [
    ["tests/conformance/source-session-handoff/v1.0/negative/initiation.empty-scope.json", "scope_invalid"],
    ["tests/conformance/source-session-handoff/v1.0/negative/initiation.duplicate-scope.json", "scope_invalid"],
    ["tests/conformance/source-session-handoff/v1.0/negative/initiation.wildcard-scope.json", "scope_invalid"],
    ["tests/conformance/source-session-handoff/v1.0/negative/initiation.wildcard-embedded.json", "scope_invalid"],
    ["tests/conformance/source-session-handoff/v1.0/negative/authenticated-context.empty-scope.json", "scope_invalid"],
    ["tests/conformance/source-session-handoff/v1.0/negative/authenticated-context.duplicate-scope.json", "scope_invalid"],
    ["tests/conformance/source-session-handoff/v1.0/negative/authenticated-context.wildcard-scope.json", "scope_invalid"],
  ];
  for (const [rel, outcome] of schemaCases) {
    await t.test(rel.split("/").pop(), () => {
      const schema = schemaForFixture(rel);
      const fixture = loadJson(rel);
      assert.equal(validatorFor(schema)(fixture), false);
      const input = schema === INITIATION_SCHEMA
        ? presentationOf({ initiation: fixture })
        : presentationOf({ context: fixture });
      const result = assessSourceSessionHandoff(input);
      assert.equal(result.failure, outcome);
      assert.equal(result.retryable, false);
      assertNoSession(result);
    });
  }
  await t.test("ambiguous prefix", () => {
    const initiation = loadJson(
      "tests/conformance/source-session-handoff/v1.0/semantic/initiation.ambiguous-scope.json",
    );
    assert.equal(validatorFor(INITIATION_SCHEMA)(initiation), true);
    const result = assessSourceSessionHandoff(presentationOf({ initiation }));
    assert.equal(result.failure, "scope_invalid");
  });
  await t.test("unsorted scopes", () => {
    const initiation = loadJson(
      "tests/conformance/source-session-handoff/v1.0/semantic/initiation.unsorted-scopes.json",
    );
    assert.equal(validatorFor(INITIATION_SCHEMA)(initiation), true);
    const result = assessSourceSessionHandoff(presentationOf({ initiation }));
    assert.equal(result.failure, "scope_invalid");
  });
  await t.test("unsorted source_permission_refs", () => {
    const context = structuredClone(loadJson(CONTEXT_EXAMPLE));
    context.source_permission_refs = ["permission-b", "permission-a"];
    assert.equal(validatorFor(CONTEXT_SCHEMA)(context), true);
    const result = assessSourceSessionHandoff(presentationOf({
      context,
      attested: attestedFrom(context),
    }));
    assert.equal(result.failure, "scope_invalid");
    assert.equal(result.retryable, false);
    assert.equal(result.contextAccepted, false);
    assertNoSession(result);
  });
  await t.test("duplicate source_permission_refs", () => {
    const context = structuredClone(loadJson(CONTEXT_EXAMPLE));
    context.source_permission_refs = [
      "source-permission-placeholder-001",
      "source-permission-placeholder-001",
    ];
    assert.equal(validatorFor(CONTEXT_SCHEMA)(context), false);
    const result = assessSourceSessionHandoff(presentationOf({ context }));
    assert.equal(result.failure, "scope_invalid");
    assert.equal(result.contextAccepted, false);
  });
  await t.test("ascending source_permission_refs", () => {
    const context = structuredClone(loadJson(CONTEXT_EXAMPLE));
    context.source_permission_refs = ["permission-a", "permission-b"];
    assert.equal(validatorFor(CONTEXT_SCHEMA)(context), true);
    const result = assessSourceSessionHandoff(presentationOf({
      context,
      attested: attestedFrom(context),
    }));
    assert.equal(result.failure, null);
    assert.equal(result.contextAccepted, true);
    assertNoSession(result);
  });
  await t.test("scope outside the initiation request", () => {
    const context = loadJson(
      "tests/conformance/source-session-handoff/v1.0/semantic/authenticated-context.scope-not-subset.json",
    );
    assert.equal(validatorFor(CONTEXT_SCHEMA)(context), true);
    const result = assessSourceSessionHandoff(presentationOf({ context }));
    assert.equal(result.failure, "scope_invalid");
    assert.equal(result.synthesizedEmptyContext, false);
  });
});

test("source-session-handoff unsupported contract and profile versions fail closed", async (t) => {
  const cases = [
    "tests/conformance/source-session-handoff/v1.0/negative/initiation.unsupported-version.json",
    "tests/conformance/source-session-handoff/v1.0/negative/initiation.unsupported-profile.json",
    "tests/conformance/source-session-handoff/v1.0/negative/initiation.unsupported-family.json",
    "tests/conformance/source-session-handoff/v1.0/negative/authenticated-context.unsupported-version.json",
    "tests/conformance/source-session-handoff/v1.0/negative/authenticated-context.unsupported-profile.json",
  ];
  for (const rel of cases) {
    await t.test(rel.split("/").pop(), () => {
      const schema = schemaForFixture(rel);
      const fixture = loadJson(rel);
      assert.equal(validatorFor(schema)(fixture), false);
      const input = schema === INITIATION_SCHEMA
        ? presentationOf({ initiation: fixture })
        : presentationOf({ context: fixture });
      const result = assessSourceSessionHandoff(input);
      assert.equal(result.failure, "unsupported_version");
      assert.equal(result.retryable, false);
      assert.equal(result.contextAccepted, false);
      assertNoSession(result);
    });
  }
});

test("source-session-handoff forged and browser-authored context is not trusted", async (t) => {
  const original = loadJson(CONTEXT_EXAMPLE);
  const cases = [
    "tests/conformance/source-session-handoff/v1.0/semantic/authenticated-context.forged-subject.json",
    "tests/conformance/source-session-handoff/v1.0/semantic/authenticated-context.forged-organisation.json",
    "tests/conformance/source-session-handoff/v1.0/semantic/authenticated-context.forged-role.json",
    "tests/conformance/source-session-handoff/v1.0/semantic/authenticated-context.same-session-and-context-ref.json",
  ];
  for (const rel of cases) {
    await t.test(rel.split("/").pop(), () => {
      const context = loadJson(rel);
      assert.equal(validatorFor(CONTEXT_SCHEMA)(context), true);
      const result = assessSourceSessionHandoff(presentationOf({
        context,
        attested: attestedFrom(original),
      }));
      assert.equal(result.failure, "identity_not_bound");
      assert.equal(result.retryable, false);
      assert.equal(result.contextAccepted, false);
      assertNoSession(result);
    });
  }
  await t.test("browser presentation of a byte-matching context", () => {
    const result = assessSourceSessionHandoff(presentationOf({ presentation: "browser" }));
    assert.equal(result.failure, "identity_not_bound");
    assert.equal(result.contextAccepted, false);
    assertNoSession(result);
  });
  await t.test("missing issuer attestation", () => {
    const result = assessSourceSessionHandoff(presentationOf({ attested: null }));
    assert.equal(result.failure, "identity_not_bound");
    assertNoSession(result);
  });
  await t.test("revoked source attestation", () => {
    const result = assessSourceSessionHandoff(presentationOf({ revoked: true }));
    assert.equal(result.failure, "unverified");
    assert.equal(result.retryable, false);
    assertNoSession(result);
  });
});

test("source-session-handoff source bounds do not grant receiver access", () => {
  const result = assessSourceSessionHandoff(presentationOf({ requestReceiverAccess: true }));
  assert.equal(result.failure, "permission_denied");
  assert.equal(result.retryable, false);
  assert.equal(result.contextAccepted, false);
  assertNoSession(result);
});

test("source-session-handoff replay and uncertain reconcile do not create a second session", () => {
  const original = loadJson(CONTEXT_EXAMPLE);
  const first = assessSourceSessionHandoff(presentationOf());
  assert.equal(first.failure, null);
  assert.equal(first.contextAccepted, true);
  assertNoSession(first);

  const replayed = assessSourceSessionHandoff(presentationOf({ codeConsumed: true }));
  assert.equal(replayed.failure, "replayed");
  assert.equal(replayed.retryable, false);
  assert.equal(replayed.contextAccepted, false);
  assertNoSession(replayed);

  const secondSession = loadJson(
    "tests/conformance/source-session-handoff/v1.0/semantic/authenticated-context.replay-second-session.json",
  );
  const other = assessSourceSessionHandoff(presentationOf({
    context: secondSession,
    codeConsumed: true,
    redeemedContext: original,
  }));
  assert.equal(other.failure, "replayed");
  assertNoSession(other);

  const reconciled = assessSourceSessionHandoff(presentationOf({
    uncertain: true,
    codeConsumed: true,
    redeemedContext: original,
  }));
  assert.equal(reconciled.failure, null);
  assert.equal(reconciled.reconciled, true);
  assert.equal(reconciled.contextAccepted, true);
  assertNoSession(reconciled);

  const reconciledOther = assessSourceSessionHandoff(presentationOf({
    context: secondSession,
    uncertain: true,
    codeConsumed: true,
    redeemedContext: original,
    attested: attestedFrom(original),
  }));
  assert.equal(reconciledOther.failure, "replayed");
  assert.equal(reconciledOther.contextAccepted, false);
  assertNoSession(reconciledOther);
});

test("source-session-handoff reconciliation requires the complete authenticated context", async (t) => {
  const redeemed = loadJson(CONTEXT_EXAMPLE);
  assert.equal(sameCompleteAuthenticatedContext(redeemed, structuredClone(redeemed)), true);

  const scalarMutations = [
    ["issuer", "issuer-placeholder-999"],
    ["audience", "receiver-placeholder-999"],
    ["receiver_ref", "receiver-placeholder-999"],
    ["client_ref", "client-placeholder-999"],
    ["destination_uri", "https://receiver.example/session-handoff/other"],
    ["handoff_ref", "handoff-placeholder-999"],
    ["transaction_ref", "transaction-placeholder-999"],
    ["correlation_ref", "correlation-placeholder-999"],
    ["source_session_ref", "source-session-placeholder-999"],
    ["source_context_ref", "source-context-placeholder-999"],
    ["subject_ref", "subject-placeholder-999"],
    ["organisation_ref", "organisation-placeholder-999"],
    ["account_ref", "account-placeholder-999"],
    ["source_role_ref", "source-role-placeholder-999"],
    ["purpose", "purpose-placeholder-999"],
    ["issued_at", "2026-08-15T00:00:21Z"],
    ["expires_at", "2026-08-15T00:04:21Z"],
    ["contract_version", "v1.1"],
    ["profile", "oauth2-authorization-code-pkce-plain-v1"],
    ["contract_family", "execution-request"],
  ];
  const arrayMutations = [
    ["source_permission_refs", ["source-permission-placeholder-002"]],
    ["record_scope_refs", ["record-scope-placeholder-001", "record-scope-placeholder-002"]],
  ];

  function assertRejected(label, candidate, initiation) {
    assert.equal(sameCompleteAuthenticatedContext(candidate, redeemed), false, label);
    const result = assessSourceSessionHandoff(presentationOf({
      initiation,
      context: candidate,
      uncertain: true,
      codeConsumed: true,
      redeemedContext: redeemed,
      attested: attestedFrom(redeemed),
    }));
    assert.equal(result.reconciled, false, label);
    assert.equal(result.contextAccepted, false, label);
    assert.equal(result.failure === null, false, label);
    assertNoSession(result);
  }

  for (const [field, value] of scalarMutations) {
    await t.test(field, () => {
      const candidate = structuredClone(redeemed);
      candidate[field] = value;
      assertRejected(field, candidate, loadJson(INITIATION_EXAMPLE));
    });
  }
  for (const [field, value] of arrayMutations) {
    await t.test(field, () => {
      const candidate = structuredClone(redeemed);
      candidate[field] = value;
      assertRejected(field, candidate, loadJson(INITIATION_EXAMPLE));
    });
  }
  await t.test("record scope that remains a requested subset", () => {
    const initiation = loadJson(
      "tests/conformance/source-session-handoff/v1.0/positive/initiation.multiple-scopes.json",
    );
    const full = loadJson(
      "tests/conformance/source-session-handoff/v1.0/positive/authenticated-context.multiple-bounds.json",
    );
    const narrowed = structuredClone(full);
    narrowed.record_scope_refs = ["record-scope-placeholder-001"];
    assert.equal(validatorFor(CONTEXT_SCHEMA)(narrowed), true);
    assert.equal(sameCompleteAuthenticatedContext(narrowed, full), false);
    const result = assessSourceSessionHandoff(presentationOf({
      initiation,
      context: narrowed,
      uncertain: true,
      codeConsumed: true,
      redeemedContext: full,
      attested: attestedFrom(full),
    }));
    assert.equal(result.failure, "replayed");
    assert.equal(result.reconciled, false);
    assert.equal(result.contextAccepted, false);
    assertNoSession(result);
  });
});

test("source-session-handoff reconciliation still runs semantic validation", async (t) => {
  const redeemed = loadJson(CONTEXT_EXAMPLE);
  function reconcile(overrides) {
    return assessSourceSessionHandoff(presentationOf({
      context: redeemed,
      uncertain: true,
      codeConsumed: true,
      redeemedContext: structuredClone(redeemed),
      attested: attestedFrom(redeemed),
      ...overrides,
    }));
  }

  await t.test("valid reconciliation does not mint a second session", () => {
    const result = reconcile({});
    assert.equal(result.failure, null);
    assert.equal(result.reconciled, true);
    assert.equal(result.contextAccepted, true);
    assertNoSession(result);
  });
  await t.test("exact context at expiry is rejected", () => {
    const result = reconcile({ at: redeemed.expires_at });
    assert.equal(result.failure, "expired");
    assert.equal(result.reconciled, false);
    assert.equal(result.contextAccepted, false);
    assertNoSession(result);
  });
  await t.test("revoked attestation is rejected", () => {
    const result = reconcile({ revoked: true });
    assert.equal(result.failure, "unverified");
    assert.equal(result.reconciled, false);
    assert.equal(result.contextAccepted, false);
    assertNoSession(result);
  });
  await t.test("browser presentation is rejected", () => {
    const result = reconcile({ presentation: "browser" });
    assert.equal(result.failure, "identity_not_bound");
    assert.equal(result.reconciled, false);
    assert.equal(result.contextAccepted, false);
    assertNoSession(result);
  });
  await t.test("source permission bounds do not grant receiver access", () => {
    const result = reconcile({ requestReceiverAccess: true });
    assert.equal(result.failure, "permission_denied");
    assert.equal(result.reconciled, false);
    assert.equal(result.contextAccepted, false);
    assertNoSession(result);
  });
  await t.test("mismatched source permission attestation is rejected", () => {
    const attested = attestedFrom(redeemed);
    attested.source_permission_refs = ["source-permission-placeholder-999"];
    const result = reconcile({ attested });
    assert.equal(result.failure, "identity_not_bound");
    assert.equal(result.reconciled, false);
    assert.equal(result.contextAccepted, false);
    assertNoSession(result);
  });
});

test("source-session-handoff failure occurred_at must be a real UTC calendar day", async (t) => {
  const validate = validatorFor(FAILURE_SCHEMA);
  const base = loadJson(FAILURE_EXAMPLE);
  assert.notEqual(parseUtc(base.occurred_at), null);
  for (const item of manifest.source_session_handoff_v1_positive) {
    if (!item.fixture.split("/").pop().startsWith("failure.")) {
      continue;
    }
    const failure = loadJson(item.fixture);
    assert.notEqual(parseUtc(failure.occurred_at), null, item.fixture);
  }

  function withOccurredAt(value) {
    const failure = structuredClone(base);
    failure.occurred_at = value;
    return failure;
  }

  const cases = [
    ["published example remains calendar-valid", base.occurred_at, true],
    ["leap day 2024-02-29", "2024-02-29T00:00:00Z", true],
    ["leap century 2000-02-29", "2000-02-29T23:59:59Z", true],
    ["leap day 2028-02-29", "2028-02-29T00:00:00.1Z", true],
    ["impossible 2026-02-30", "2026-02-30T00:00:00Z", false],
    ["non-leap 2026-02-29", "2026-02-29T00:00:00Z", false],
    ["non-leap century 1900-02-29", "1900-02-29T00:00:00Z", false],
    ["impossible 2026-04-31", "2026-04-31T00:00:00Z", false],
  ];
  for (const [name, occurredAt, calendarValid] of cases) {
    await t.test(name, () => {
      const failure = withOccurredAt(occurredAt);
      assert.equal(validate(failure), true, formatErrors(validate));
      assert.equal(parseUtc(failure.occurred_at) !== null, calendarValid);
      assert.equal(failureObjectConforms(failure, true), calendarValid, name);
    });
  }
});

test("source-session-handoff dependency_unavailable never becomes success or an unscoped redirect", () => {
  const result = assessSourceSessionHandoff(presentationOf({ dependencyAvailable: false }));
  assert.equal(result.failure, "dependency_unavailable");
  assert.equal(result.retryable, true);
  assert.equal(result.contextAccepted, false);
  assertNoSession(result);
  const wire = {
    contract_family: FAMILY,
    contract_version: VERSION,
    profile: PROFILE,
    outcome: result.failure,
    code: "DEPENDENCY_UNAVAILABLE",
    retryable: result.retryable,
    correlation_ref: "correlation-placeholder-001",
    occurred_at: EVALUATION_AT,
  };
  const validate = validatorFor(FAILURE_SCHEMA);
  assert.equal(validate(wire), true, formatErrors(validate));
  assert.equal(Object.hasOwn(wire, "record_scope_refs"), false);
  assert.equal(Object.hasOwn(wire, "destination_uri"), false);
  const duringReplay = assessSourceSessionHandoff(presentationOf({
    dependencyAvailable: false,
    codeConsumed: true,
  }));
  assert.equal(duringReplay.failure, "dependency_unavailable");
  assert.equal(duringReplay.mintsAdditionalReceiverSession, false);
  assert.equal(duringReplay.contextAccepted, false);
});

test("source-session-handoff missing and unknown fields classify as malformed", () => {
  const missing = loadJson(
    "tests/conformance/source-session-handoff/v1.0/negative/initiation.missing-handoff-ref.json",
  );
  const missingResult = assessSourceSessionHandoff(presentationOf({ initiation: missing }));
  assert.equal(missingResult.failure, "malformed");
  assert.equal(missingResult.retryable, false);
  assertNoSession(missingResult);

  const unknown = loadJson(
    "tests/conformance/source-session-handoff/v1.0/negative/authenticated-context.unknown-property.json",
  );
  const unknownResult = assessSourceSessionHandoff(presentationOf({ context: unknown }));
  assert.equal(unknownResult.failure, "malformed");
  assert.equal(unknownResult.retryable, false);
  assertNoSession(unknownResult);
});

test("source-session-handoff wire schemas stay closed", () => {
  const closed = [
    INITIATION_SCHEMA,
    AUTHZ_REQUEST_SCHEMA,
    REDEMPTION_REQUEST_SCHEMA,
    REDEMPTION_RESPONSE_SCHEMA,
    CONTEXT_SCHEMA,
    FAILURE_SCHEMA,
  ];
  for (const rel of closed) {
    const schema = loadJson(rel);
    assert.equal(schema.additionalProperties, false, rel);
    assert.equal(schema.unevaluatedProperties, false, rel);
    assert.equal(schema.properties.contract_family.const, FAMILY);
    assert.equal(schema.properties.contract_version.const, VERSION);
    assert.equal(schema.properties.profile.const, PROFILE);
  }
  const registration = loadJson(REGISTRATION_SCHEMA);
  assert.equal(registration.additionalProperties, false);
  assert.equal(registration.unevaluatedProperties, false);
  assert.equal(registration.properties.registration_version.const, "v1");
  assert.equal(Object.hasOwn(registration.properties, "receiver_role"), false);
  const callback = loadJson(AUTHZ_RESPONSE_SCHEMA);
  assert.equal(callback.oneOf.length, 2);
  for (const branch of callback.oneOf) {
    assert.equal(branch.additionalProperties, false);
    assert.equal(branch.unevaluatedProperties, false);
  }
});

test("source-session-handoff utc instants keep calendar and fractional precision", async (t) => {
  const engine = readFileSync(
    join(repoRoot, "tests/conformance/source-session-handoff/semantics.mjs"),
    "utf8",
  );
  assert.equal(/\bDate\s*\./.test(engine), false);
  assert.equal(/new\s+Date\s*\(/.test(engine), false);
  assert.equal(engine.includes("Date.parse"), false);
  assert.equal(engine.includes("10n **"), false);
  assert.equal(engine.includes("padEnd"), false);

  const legacyStart = Date.UTC(99, 11, 31, 23, 59, 30);
  const legacyEnd = Date.UTC(100, 0, 1, 0, 0, 0);
  assert.ok(legacyStart > legacyEnd);

  await t.test("0099-12-31 to 0100-01-01 is 30 seconds", () => {
    assert.equal(compareInstants("0099-12-31T23:59:30Z", "0100-01-01T00:00:00Z"), -1);
    assert.equal(durationWithin("0099-12-31T23:59:30Z", "0100-01-01T00:00:00Z", CODE_WINDOW_SECONDS), true);
    assert.equal(durationWithin("0099-12-31T23:59:30Z", "0100-01-01T00:00:00Z", 29n), false);
  });
  await t.test("year 0000 leap day and the following new year", () => {
    assert.notEqual(parseUtc("0000-02-29T00:00:00Z"), null);
    assert.equal(parseUtc("0000-02-30T00:00:00Z"), null);
    assert.equal(durationWithin("0000-12-31T23:59:30Z", "0001-01-01T00:00:00Z", CODE_WINDOW_SECONDS), true);
    assert.equal(compareInstants("0001-01-01T00:00:00Z", "0099-12-31T23:59:30Z"), -1);
  });
  await t.test("leap and non-leap February boundaries", () => {
    assert.notEqual(parseUtc("2000-02-29T12:00:00Z"), null);
    assert.equal(parseUtc("1900-02-29T12:00:00Z"), null);
    assert.equal(parseUtc("2026-02-29T12:00:00Z"), null);
    assert.notEqual(parseUtc("2026-02-28T23:59:30Z"), null);
    assert.equal(parseUtc("2026-04-31T00:00:00Z"), null);
    assert.notEqual(parseUtc("2026-04-30T23:59:59.5Z"), null);
    assert.equal(durationWithin("2024-02-29T23:59:30Z", "2024-03-01T00:00:00Z", CODE_WINDOW_SECONDS), true);
    assert.equal(durationWithin("2026-02-28T23:59:30Z", "2026-03-01T00:00:00Z", CODE_WINDOW_SECONDS), true);
    assert.equal(durationWithin("2026-12-31T23:59:30Z", "2027-01-01T00:00:00Z", CODE_WINDOW_SECONDS), true);
  });
  await t.test("fractional seconds are not truncated", () => {
    assert.equal(compareInstants("2026-08-15T00:00:00.1Z", "2026-08-15T00:00:00.10Z"), 0);
    assert.equal(compareInstants("2026-08-15T00:00:00.1Z", "2026-08-15T00:00:00.1000000001Z"), -1);
    assert.equal(durationWithin("2026-08-15T00:00:00Z", "2026-08-15T00:01:00Z", CODE_WINDOW_SECONDS), true);
    assert.equal(
      durationWithin("2026-08-15T00:00:00Z", "2026-08-15T00:01:00.0000000001Z", CODE_WINDOW_SECONDS),
      false,
    );
    assert.equal(durationWithin("2026-08-15T00:00:20Z", "2026-08-15T00:05:20Z", CONTEXT_WINDOW_SECONDS), true);
    assert.equal(
      durationWithin("2026-08-15T00:00:20Z", "2026-08-15T00:05:20.0000000001Z", CONTEXT_WINDOW_SECONDS),
      false,
    );
    assert.equal(
      durationWithin("2026-08-15T00:00:00.900Z", "2026-08-15T00:00:01.100Z", CODE_WINDOW_SECONDS),
      true,
    );
    assert.equal(
      integralSecondLifetime("2026-08-15T00:00:00.900Z", "2026-08-15T00:00:01.100Z"),
      null,
    );
    assert.equal(
      integralSecondLifetime("2026-08-15T00:00:00.0001Z", "2026-08-15T00:01:00.0001Z"),
      60n,
    );
    assert.equal(
      integralSecondLifetime("2026-08-15T00:00:00.0001Z", "2026-08-15T00:01:00.0002Z"),
      null,
    );
  });
  await t.test("long fractional digits stay exact without scaled integers", () => {
    const digits = "1".repeat(10000);
    const lastDiffers = `${"1".repeat(9999)}2`;
    const equalStart = `2026-08-15T00:00:00.${digits}Z`;
    const equalSame = `2026-08-15T00:00:00.${digits}Z`;
    const greater = `2026-08-15T00:00:00.${lastDiffers}Z`;
    assert.equal(compareInstants(equalStart, equalSame), 0);
    assert.equal(compareInstants(equalStart, greater), -1);
    assert.equal(compareInstants(greater, equalStart), 1);

    const codeExact = `2026-08-15T00:01:00.${digits}Z`;
    const codeEpsilon = `2026-08-15T00:01:00.${lastDiffers}Z`;
    assert.equal(durationWithin(equalStart, codeExact, CODE_WINDOW_SECONDS), true);
    assert.equal(integralSecondLifetime(equalStart, codeExact), 60n);
    assert.equal(durationWithin(equalStart, codeEpsilon, CODE_WINDOW_SECONDS), false);
    assert.equal(integralSecondLifetime(equalStart, codeEpsilon), null);
    const exactCode = redemptionOf({
      record: { issued_at: equalStart, expires_at: codeExact },
      now: "2026-08-15T00:00:30Z",
    });
    assert.equal(exactCode.failure, null);
    assert.equal(exactCode.codeConsumed, true);
    const overCode = redemptionOf({
      record: { issued_at: equalStart, expires_at: codeEpsilon },
      now: "2026-08-15T00:00:30Z",
    });
    assert.equal(overCode.code, "CODE_EXPIRED");
    assert.equal(overCode.failure, "expired");
    assert.equal(overCode.codeConsumed, false);

    const contextStart = `2026-08-15T00:00:20.${digits}Z`;
    const contextExact = `2026-08-15T00:05:20.${digits}Z`;
    const contextEpsilon = `2026-08-15T00:05:20.${lastDiffers}Z`;
    assert.equal(durationWithin(contextStart, contextExact, CONTEXT_WINDOW_SECONDS), true);
    assert.equal(integralSecondLifetime(contextStart, contextExact), 300n);
    assert.equal(durationWithin(contextStart, contextEpsilon, CONTEXT_WINDOW_SECONDS), false);
    assert.equal(integralSecondLifetime(contextStart, contextEpsilon), null);
  });
  await t.test("low-year code window is accepted by the handoff oracle", () => {
    const initiation = structuredClone(loadJson(INITIATION_EXAMPLE));
    initiation.initiated_at = "0099-12-31T23:59:30Z";
    initiation.expires_at = "0100-01-01T00:00:00Z";
    const context = structuredClone(loadJson(CONTEXT_EXAMPLE));
    context.issued_at = "0099-12-31T23:59:40Z";
    context.expires_at = "0100-01-01T00:04:40Z";
    assert.equal(validatorFor(INITIATION_SCHEMA)(initiation), true);
    assert.equal(validatorFor(CONTEXT_SCHEMA)(context), true);
    assert.equal(initiationSemanticsHold(initiation), true);
    assert.equal(contextSemanticsHold(context), true);
    const result = assessSourceSessionHandoff(presentationOf({
      initiation,
      context,
      at: "0099-12-31T23:59:50Z",
    }));
    assert.equal(result.failure, null);
    assert.equal(result.contextAccepted, true);
    assertNoSession(result);
  });
});

test("source-session-handoff impossible timestamps fail object conformance", async (t) => {
  const cases = [
    ["initiation initiated_at", "initiated_at", "2026-02-30T00:00:00Z"],
    ["initiation expires_at", "expires_at", "1900-02-29T00:00:00Z"],
    ["context issued_at", "issued_at", "2026-04-31T00:00:00.1Z"],
    ["context expires_at", "expires_at", "2026-02-30T00:00:00Z"],
  ];
  for (const [name, field, value] of cases) {
    await t.test(name, () => {
      const initiation = structuredClone(loadJson(INITIATION_EXAMPLE));
      const context = structuredClone(loadJson(CONTEXT_EXAMPLE));
      if (field === "initiated_at" || field === "expires_at" && name.startsWith("initiation")) {
        initiation[field] = value;
      }
      if (name.startsWith("context")) {
        context[field] = value;
      }
      const schemaValidInitiation = validatorFor(INITIATION_SCHEMA)(initiation);
      const schemaValidContext = validatorFor(CONTEXT_SCHEMA)(context);
      assert.equal(schemaValidInitiation, true);
      assert.equal(schemaValidContext, true);
      if (name.startsWith("initiation")) {
        assert.equal(initiationSemanticsHold(initiation), false);
      } else {
        assert.equal(contextSemanticsHold(context), false);
      }
      const result = assessSourceSessionHandoff(presentationOf({ initiation, context }));
      assert.equal(result.failure, "malformed");
      assert.equal(result.contextAccepted, false);
      assert.equal(result.reconciled, false);
      assertNoSession(result);
    });
  }
  await t.test("failure occurred_at 2026-02-30 is non-conformant", () => {
    const failure = structuredClone(loadJson(FAILURE_EXAMPLE));
    failure.occurred_at = "2026-02-30T00:00:00Z";
    assert.equal(validatorFor(FAILURE_SCHEMA)(failure), true);
    assert.equal(failureObjectConforms(failure, true), false);
  });
  await t.test("invalid evaluation instant is malformed", () => {
    const result = assessSourceSessionHandoff(presentationOf({ at: "2026-02-30T00:00:00Z" }));
    assert.equal(result.failure, "malformed");
    assert.equal(result.contextAccepted, false);
  });
});

test("source-session-handoff destination uris require a real https authority", async (t) => {
  const accepted = [
    "https://receiver.example/session-handoff/callback",
    "https://receiver.example:443/session-handoff/callback",
    "https://[2001:db8::1]/session-handoff/callback",
    "https://[::1]:8443/callback",
    "https://192.0.2.10/callback",
    "https://3com/callback",
    "https://service.3com/callback",
    "https://[::ffff:192.0.2.1]/callback",
    "https://[0:0:0:0:0:0:0:1]/callback",
    "https://receiver.example/a//callback",
    "https://[2001:db8::1]/a//callback",
  ];
  for (const uri of accepted) {
    await t.test(`accepts ${uri}`, () => {
      const initiation = structuredClone(loadJson(INITIATION_EXAMPLE));
      initiation.destination_uri = uri;
      assert.equal(validatorFor(INITIATION_SCHEMA)(initiation), true, uri);
      assert.equal(destinationUriValid(uri), true, uri);
    });
  }

  const schemaValidRejects = [
    "https://[:::1]/callback",
    "https://[gggg::1]/callback",
    "https://[2001:db8:192.0.2.1::1]/callback",
    "https://receiver.example/foo/../callback",
    "https://receiver.example/%2e%2e/callback",
  ];
  const schemaInvalidRejects = [
    "https://:",
    "https:///",
    "https://user:pw@receiver.example/callback",
    "https://receiver.example:65536/callback",
    "https://receiver.example:/callback",
    "https://[::1",
    "https://receiver.example/foo\\bar",
    "https://receiver.example\\other.example/callback",
    "https://192.0.2.010/callback",
    "https://192.0.2/callback",
    "https://0x7f.0.0.1/callback",
    "https://0x7f000001/callback",
    "https://0X7F000001/callback",
    "https://2130706433/callback",
    "https://127.1/callback",
    "https://0177.0.0.1/callback",
    "http://receiver.example/callback",
    "https://receiver.example/callback?code=1",
    "https://receiver.example/callback#fragment",
    "https://receiver.example/*/callback",
    "https://receiver.example/call back",
  ];

  function pair(uri) {
    const initiation = structuredClone(loadJson(INITIATION_EXAMPLE));
    const context = structuredClone(loadJson(CONTEXT_EXAMPLE));
    initiation.destination_uri = uri;
    context.destination_uri = uri;
    return { initiation, context };
  }

  for (const uri of schemaValidRejects) {
    await t.test(`rejects schema-valid ${uri}`, () => {
      const { initiation, context } = pair(uri);
      assert.equal(validatorFor(INITIATION_SCHEMA)(initiation), true, uri);
      assert.equal(destinationUriValid(uri), false, uri);
      assert.equal(initiationSemanticsHold(initiation), false, uri);
      const result = assessSourceSessionHandoff(presentationOf({ initiation, context }));
      assert.equal(result.failure, "malformed", uri);
      assert.equal(result.contextAccepted, false, uri);
      assertNoSession(result);
    });
  }
  for (const uri of schemaInvalidRejects) {
    await t.test(`rejects ${uri}`, () => {
      const { initiation, context } = pair(uri);
      assert.equal(validatorFor(INITIATION_SCHEMA)(initiation), false, uri);
      assert.equal(destinationUriValid(uri), false, uri);
      const result = assessSourceSessionHandoff(presentationOf({ initiation, context }));
      assert.equal(result.failure, "malformed", uri);
      assert.equal(result.contextAccepted, false, uri);
      assertNoSession(result);
    });
  }
  await t.test("host case is not canonicalized", () => {
    const context = structuredClone(loadJson(CONTEXT_EXAMPLE));
    context.destination_uri = "https://Receiver.example/session-handoff/callback";
    assert.equal(destinationUriValid(context.destination_uri), true);
    const result = assessSourceSessionHandoff(presentationOf({ context }));
    assert.equal(result.failure, "unverified");
    assert.equal(result.contextAccepted, false);
  });
  await t.test("exact port spelling is not canonicalized", () => {
    const initiation = loadJson(INITIATION_EXAMPLE);
    const context = structuredClone(loadJson(CONTEXT_EXAMPLE));
    context.destination_uri = "https://receiver.example:443/session-handoff/callback";
    assert.equal(destinationUriValid(initiation.destination_uri), true);
    assert.equal(destinationUriValid(context.destination_uri), true);
    const result = assessSourceSessionHandoff(presentationOf({ context }));
    assert.equal(result.failure, "unverified");
    assert.equal(result.contextAccepted, false);
  });
  await t.test("reconciled invalid destination is still malformed", () => {
    const { initiation, context } = pair("https://:");
    const result = assessSourceSessionHandoff(presentationOf({
      initiation,
      context,
      uncertain: true,
      codeConsumed: true,
      redeemedContext: context,
    }));
    assert.equal(result.failure, "malformed");
    assert.equal(result.reconciled, false);
    assert.equal(result.contextAccepted, false);
    assertNoSession(result);
  });
  await t.test("non-canonical ipv4 does not consume an authorization code", () => {
    for (const uri of [
      "https://0x7f.0.0.1/callback",
      "https://0x7f000001/callback",
      "https://2130706433/callback",
      "https://0177.0.0.1/callback",
    ]) {
      const request = structuredClone(publishedRedemptionRequest());
      request.destination_uri = uri;
      const result = redemptionOf({ request, schemaValidRequest: true });
      assert.equal(result.code, "MALFORMED_REQUEST", uri);
      assert.equal(result.codeConsumed, false, uri);
      assertNoSession(result);
    }
  });
  await t.test("double-slash path matches only the original bytes", () => {
    const left = "https://receiver.example/a//callback";
    const right = "https://receiver.example/a/callback";
    assert.equal(destinationUriValid(left), true);
    assert.equal(destinationUriValid(right), true);
    assert.equal(destinationsExactMatch(left, left), true);
    assert.equal(destinationsExactMatch(left, right), false);
  });
});

function publishedRegistration() {
  return loadJson(REGISTRATION_EXAMPLE);
}

function publishedRedemptionRequest() {
  return loadJson(REDEMPTION_REQUEST_EXAMPLE);
}

function codeRecordFor(request, overrides = {}) {
  return {
    client_ref: request.client_ref,
    destination_uri: request.destination_uri,
    code_challenge: pkceChallengeFor(request.code_verifier),
    code_challenge_method: "S256",
    handoff_ref: request.handoff_ref,
    transaction_ref: request.transaction_ref,
    correlation_ref: request.correlation_ref,
    purpose: request.purpose,
    authorization_code: request.authorization_code,
    issued_at: "2026-08-15T00:00:00Z",
    expires_at: "2026-08-15T00:01:00Z",
    consumed: false,
    source_session_ref: "source-session-placeholder-001",
    source_context_ref: "source-context-placeholder-001",
    ...overrides,
  };
}

function publicJwk(publicKey, kid, alg) {
  const jwk = publicKey.export({ format: "jwk" });
  jwk.kid = kid;
  jwk.alg = alg;
  jwk.use = "sig";
  return jwk;
}

function registrationWithKeys(keys, algorithms) {
  return {
    ...publishedRegistration(),
    jwks: { keys },
    algorithms,
  };
}

function signedAssertion(header, payload, privateKey) {
  const encodedHeader = Buffer.from(JSON.stringify(header)).toString("base64url");
  const encodedPayload = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signingInput = Buffer.from(`${encodedHeader}.${encodedPayload}`);
  let signature;
  if (header.alg === "EdDSA") {
    signature = sign(null, signingInput, privateKey);
  } else if (header.alg === "ES256" || header.alg === "ES384" || header.alg === "ES512") {
    const hash = header.alg === "ES256" ? "sha256" : header.alg === "ES384" ? "sha384" : "sha512";
    signature = sign(hash, signingInput, { key: privateKey, dsaEncoding: "ieee-p1363" });
  } else if (header.alg === "RS256" || header.alg === "RS384" || header.alg === "RS512") {
    const nodeAlg = header.alg === "RS256" ? "RSA-SHA256" : header.alg === "RS384" ? "RSA-SHA384" : "RSA-SHA512";
    signature = sign(nodeAlg, signingInput, privateKey);
  } else {
    throw new Error(`unsupported test algorithm ${header.alg}`);
  }
  return `${encodedHeader}.${encodedPayload}.${signature.toString("base64url")}`;
}

function corruptSignature(assertion) {
  const parts = assertion.split(".");
  const bytes = Buffer.from(parts[2], "base64url");
  bytes[0] ^= 0xff;
  parts[2] = bytes.toString("base64url");
  return parts.join(".");
}

function compactWithHeader(header, payload) {
  const encodedHeader = Buffer.from(JSON.stringify(header)).toString("base64url");
  const encodedPayload = Buffer.from(JSON.stringify(payload)).toString("base64url");
  return `${encodedHeader}.${encodedPayload}.AA`;
}

function redemptionOf(overrides = {}) {
  const request = overrides.request ?? publishedRedemptionRequest();
  return assessRedemption({
    request,
    schemaValidRequest: Object.hasOwn(overrides, "schemaValidRequest")
      ? overrides.schemaValidRequest
      : validatorFor(REDEMPTION_REQUEST_SCHEMA)(request),
    registration: Object.hasOwn(overrides, "registration") ? overrides.registration : publishedRegistration(),
    codeRecord: Object.hasOwn(overrides, "codeRecord") ? overrides.codeRecord : codeRecordFor(request, overrides.record),
    codeChallengeMethod: overrides.codeChallengeMethod ?? "S256",
    now: overrides.now ?? "2026-08-15T00:00:30Z",
    issuerUnavailable: overrides.issuerUnavailable ?? false,
    dependencyAvailable: overrides.dependencyAvailable ?? true,
  });
}

test("source-session-handoff authorization callback and pkce shapes are closed", async (t) => {
  const request = loadJson(AUTHZ_REQUEST_EXAMPLE);
  const success = loadJson(AUTHZ_SUCCESS_EXAMPLE);
  const denial = loadJson(AUTHZ_DENIAL_EXAMPLE);
  const validateRequest = validatorFor(AUTHZ_REQUEST_SCHEMA);
  const validateCallback = validatorFor(AUTHZ_RESPONSE_SCHEMA);
  assert.equal(validateRequest(request), true, formatErrors(validateRequest));
  assert.equal(validateCallback(success), true, formatErrors(validateCallback));
  assert.equal(validateCallback(denial), true, formatErrors(validateCallback));
  assert.notEqual(request.state, request.transaction_ref);
  assert.equal(pkceVerifierValid("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"), true);
  assert.equal(
    pkceChallengeFor("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
    request.code_challenge,
  );

  await t.test("authorization response required fields", () => {
    const missingCode = structuredClone(success);
    delete missingCode.code;
    assert.equal(validateCallback(missingCode), false);
    const missingError = structuredClone(denial);
    delete missingError.error;
    assert.equal(validateCallback(missingError), false);
  });
  await t.test("pkce plain is rejected", () => {
    const plain = structuredClone(request);
    plain.code_challenge_method = "plain";
    assert.equal(validateRequest(plain), false);
    const redeemed = redemptionOf({ codeChallengeMethod: "plain" });
    assert.equal(redeemed.code, "INVALID_PKCE_METHOD");
    assert.equal(redeemed.failure, "malformed");
    assert.equal(redeemed.retryable, false);
    assertNoSession(redeemed);
  });
  await t.test("browser callback contains only safe fields bound to the request state", () => {
    assert.equal(browserCallbackQueryAllowed(success, request.state), true);
    assert.equal(browserCallbackQueryAllowed(denial, request.state), true);
    assert.equal(browserCallbackQueryAllowed(success), false);
    assert.equal(browserCallbackQueryAllowed(success, "state-from-another-handoff"), false);
    assert.equal(browserCallbackQueryAllowed({ ...success, state: "state-from-another-handoff" }, request.state), false);
    assert.equal(browserCallbackQueryAllowed({ ...success, subject_ref: "subject-placeholder-001" }, request.state), false);
    assert.equal(browserCallbackQueryAllowed({ error: "invalid_scope", state: success.state }, request.state), false);
    assert.equal(browserCallbackQueryAllowed({ error: "access_denied", state: success.state, error_description: "no" }, request.state), false);
    assert.equal(browserCallbackQueryAllowed({ ...success, code: "" }, request.state), false);
    assert.equal(browserCallbackQueryAllowed({ ...success, code: null }, request.state), false);
    assert.equal(browserCallbackQueryAllowed({ ...success, code: { value: success.code } }, request.state), false);
    assert.equal(browserCallbackQueryAllowed({ ...success, code: "short-code" }, request.state), false);
  });
  await t.test("authorization request destination is semantically validated", () => {
    assert.equal(authorizationRequestDestinationAccepted(request), true);
    const malformedIpv6 = structuredClone(request);
    malformedIpv6.destination_uri = "https://[:::1]/callback";
    assert.equal(validateRequest(malformedIpv6), true);
    assert.equal(destinationUriValid(malformedIpv6.destination_uri), false);
    assert.equal(authorizationRequestDestinationAccepted(malformedIpv6), false);
    const digitLeading = structuredClone(request);
    digitLeading.destination_uri = "https://service.3com/callback";
    assert.equal(validateRequest(digitLeading), true);
    assert.equal(authorizationRequestDestinationAccepted(digitLeading), true);
  });
  await t.test("browser-sensitive fields are absent from the authorization request", () => {
    const schema = loadJson(AUTHZ_REQUEST_SCHEMA);
    for (const field of browserProhibitedFields()) {
      assert.equal(Object.hasOwn(schema.properties, field), false, field);
      assert.equal(Object.hasOwn(request, field), false, field);
      assert.equal(Object.hasOwn(success, field), false, field);
      assert.equal(Object.hasOwn(denial, field), false, field);
    }
  });
});

test("source-session-handoff redemption issues one context and consumes the code once", async (t) => {
  const response = loadJson(REDEMPTION_RESPONSE_EXAMPLE);
  const context = loadJson(CONTEXT_EXAMPLE);
  const registration = publishedRegistration();
  const validateResponse = validatorFor(REDEMPTION_RESPONSE_SCHEMA);
  assert.equal(validateResponse(response), true, formatErrors(validateResponse));
  assert.equal(validatorFor(REGISTRATION_SCHEMA)(registration), true);
  assert.equal(redemptionResponseMatchesContext(response, context, registration), true);
  const inspected = inspectCompactJws(response.assertion);
  assert.equal(jwsHeaderAccepted(inspected.header, registration.algorithms), true);
  assert.equal(integralSecondLifetime(context.issued_at, context.expires_at), 240n);
  const key = createPublicKey({ key: registration.jwks.keys[0], format: "jwk" });
  const [header, payload, signature] = response.assertion.split(".");
  assert.equal(
    verify(null, Buffer.from(`${header}.${payload}`), key, Buffer.from(signature, "base64url")),
    true,
  );

  await t.test("valid redemption consumes the code and does not mint a receiver session", () => {
    const first = redemptionOf();
    assert.equal(first.failure, null);
    assert.equal(first.codeConsumed, true);
    assertNoSession(first);
    const replay = redemptionOf({ record: { consumed: true } });
    assert.equal(replay.code, "CODE_REPLAYED");
    assert.equal(replay.failure, "replayed");
    assert.equal(replay.mintsAdditionalReceiverSession, false);
    assertNoSession(replay);
  });
  await t.test("expired unknown and mismatched codes fail closed", () => {
    const expired = redemptionOf({ now: "2026-08-15T00:01:00Z" });
    assert.equal(expired.code, "CODE_EXPIRED");
    assert.equal(expired.retryable, false);
    assertNoSession(expired);
    const unknown = redemptionOf({ codeRecord: null });
    assert.equal(unknown.code, "CODE_UNKNOWN");
    assertNoSession(unknown);
    const mismatch = redemptionOf({ record: { code_challenge: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" } });
    assert.equal(mismatch.code, "PKCE_MISMATCH");
    assert.equal(mismatch.failure, "unverified");
    assertNoSession(mismatch);
  });
  await t.test("client destination purpose profile and version failures", () => {
    const wrongClient = structuredClone(publishedRedemptionRequest());
    wrongClient.client_ref = "client-placeholder-002";
    assert.equal(redemptionOf({ request: wrongClient }).code, "UNKNOWN_CLIENT");
    const disabled = structuredClone(publishedRegistration());
    disabled.status = "disabled";
    assert.equal(redemptionOf({ registration: disabled }).code, "CLIENT_DISABLED");
    assert.equal(registrationPermitsRedirect(disabled, disabled.client_ref, disabled.destination_uris[0]), false);
    const revoked = structuredClone(publishedRegistration());
    revoked.status = "revoked";
    assert.equal(redemptionOf({ registration: revoked }).code, "CLIENT_REVOKED");
    assert.equal(registrationPermitsRedirect(revoked, revoked.client_ref, revoked.destination_uris[0]), false);
    const otherDestination = structuredClone(publishedRedemptionRequest());
    otherDestination.destination_uri = "https://receiver.example/session-handoff/other";
    const destination = redemptionOf({ request: otherDestination });
    assert.equal(destination.code, "DESTINATION_MISMATCH");
    assert.equal(destination.redirectPermitted, false);
    const recordPurpose = redemptionOf({ record: { purpose: "other-purpose" } });
    assert.equal(recordPurpose.code, "PURPOSE_MISMATCH");
    assert.equal(recordPurpose.codeConsumed, false);
    assertNoSession(recordPurpose);
    const wrongProfile = structuredClone(publishedRedemptionRequest());
    wrongProfile.profile = "oauth2-authorization-code-pkce-plain-v1";
    assert.equal(redemptionOf({ request: wrongProfile, schemaValidRequest: false }).code, "UNSUPPORTED_PROFILE");
    const wrongVersion = structuredClone(publishedRedemptionRequest());
    wrongVersion.contract_version = "v9.9";
    assert.equal(redemptionOf({ request: wrongVersion, schemaValidRequest: false }).code, "UNSUPPORTED_CONTRACT_VERSION");
    const wrongFamily = structuredClone(publishedRedemptionRequest());
    wrongFamily.contract_family = "other-family";
    const unsupportedFamily = redemptionOf({ request: wrongFamily, schemaValidRequest: false });
    assert.equal(unsupportedFamily.code, "UNSUPPORTED_CONTRACT_VERSION");
    assert.equal(unsupportedFamily.failure, "unsupported_version");
    assert.equal(unsupportedFamily.codeConsumed, false);
    assertNoSession(unsupportedFamily);
  });
  await t.test("redemption response is closed and registration-bound", () => {
    const wrongConstants = [
      ["contract_family", "other-family"],
      ["contract_version", "v9.9"],
      ["profile", "other-profile"],
      ["status", "pending"],
      ["token_type", "DPoP"],
      ["assertion_format", "other-format"],
    ];
    for (const [field, value] of wrongConstants) {
      const candidate = structuredClone(response);
      candidate[field] = value;
      assert.equal(redemptionResponseMatchesContext(candidate, context, registration), false, field);
    }
    const extra = { ...structuredClone(response), access_token: "forbidden" };
    assert.equal(redemptionResponseMatchesContext(extra, context, registration), false);
    const missing = structuredClone(response);
    delete missing.status;
    assert.equal(redemptionResponseMatchesContext(missing, context, registration), false);

    for (const [field, value] of [
      ["issuer", "issuer-placeholder-002"],
      ["client_ref", "client-placeholder-002"],
      ["receiver_ref", "receiver-placeholder-002"],
      ["purpose", "other-purpose"],
    ]) {
      const wrongRegistration = structuredClone(registration);
      wrongRegistration[field] = value;
      assert.equal(redemptionResponseMatchesContext(response, context, wrongRegistration), false, field);
    }
    const wrongAudienceRegistration = structuredClone(registration);
    wrongAudienceRegistration.receiver_ref = "audience-placeholder-002";
    assert.equal(redemptionResponseMatchesContext(response, context, wrongAudienceRegistration), false);
    const wrongDestinationRegistration = structuredClone(registration);
    wrongDestinationRegistration.destination_uris = ["https://receiver.example/session-handoff/other"];
    assert.equal(redemptionResponseMatchesContext(response, context, wrongDestinationRegistration), false);
    const disabledRegistration = structuredClone(registration);
    disabledRegistration.status = "disabled";
    assert.equal(redemptionResponseMatchesContext(response, context, disabledRegistration), false);
    const wrongAllowedVersion = structuredClone(registration);
    wrongAllowedVersion.allowed_contract_versions = [];
    assert.equal(redemptionResponseMatchesContext(response, context, wrongAllowedVersion), false);
    const wrongAllowedProfile = structuredClone(registration);
    wrongAllowedProfile.allowed_profiles = [];
    assert.equal(redemptionResponseMatchesContext(response, context, wrongAllowedProfile), false);
  });

  await t.test("malformed redemption response and refresh token are rejected", () => {
    const refresh = structuredClone(response);
    refresh.refresh_token = "not-admitted";
    assert.equal(validateResponse(refresh), false);
    assert.equal(redemptionResponseMatchesContext(refresh, context, registration), false);
    const skewed = structuredClone(context);
    skewed.expires_at = "2026-08-15T00:04:20.5Z";
    assert.equal(integralSecondLifetime(skewed.issued_at, skewed.expires_at), null);
    assert.equal(redemptionResponseMatchesContext(response, skewed, registration), false);
    const headerWithJku = { ...inspected.header, jku: "https://caller.example/jwks" };
    assert.equal(jwsHeaderAccepted(headerWithJku, registration.algorithms), false);
    assert.equal(jwsHeaderAccepted({ alg: "none", kid: "source-key-placeholder-001" }, registration.algorithms), false);
    assert.equal(jwsHeaderAccepted({ alg: "EdDSA", kid: "source-key-placeholder-001", crit: ["bork"] }, registration.algorithms), false);
    const withIssuerClaim = { ...context, iss: context.issuer };
    assert.equal(validatorFor(CONTEXT_SCHEMA)(withIssuerClaim), false);
    assert.equal(redemptionResponseMatchesContext(response, withIssuerClaim, registration), false);
  });
  await t.test("purpose must match the request, code record, and registration", () => {
    const accepted = redemptionOf();
    assert.equal(accepted.failure, null);
    assert.equal(accepted.codeConsumed, true);
    assertNoSession(accepted);

    const otherRegistration = structuredClone(registration);
    otherRegistration.purpose = "other-purpose";
    const registrationDiffers = redemptionOf({ registration: otherRegistration });
    assert.equal(registrationDiffers.code, "PURPOSE_MISMATCH");
    assert.equal(registrationDiffers.failure, "unverified");
    assert.equal(registrationDiffers.codeConsumed, false);
    assert.equal(registrationDiffers.contextAccepted, false);
    assertNoSession(registrationDiffers);

    const otherRequest = structuredClone(publishedRedemptionRequest());
    otherRequest.purpose = "other-purpose";
    const requestDiffers = redemptionOf({ request: otherRequest });
    assert.equal(requestDiffers.code, "PURPOSE_MISMATCH");
    assert.equal(requestDiffers.codeConsumed, false);
    assertNoSession(requestDiffers);

    const recordDiffers = redemptionOf({ record: { purpose: "other-purpose" } });
    assert.equal(recordDiffers.code, "PURPOSE_MISMATCH");
    assert.equal(recordDiffers.codeConsumed, false);
    assertNoSession(recordDiffers);

    const stillValid = redemptionOf();
    assert.equal(stillValid.failure, null);
    assert.equal(stillValid.codeConsumed, true);
    const replay = redemptionOf({ record: { consumed: true } });
    assert.equal(replay.code, "CODE_REPLAYED");
    assert.equal(replay.codeConsumed, false);
    assert.equal(replay.mintsAdditionalReceiverSession, false);
    assertNoSession(replay);
  });
  await t.test("redemption assertion signature is verified against the registration jwks", () => {
    const ed = generateKeyPairSync("ed25519");
    const otherEd = generateKeyPairSync("ed25519");
    const ec = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const kid = "source-key-placeholder-001";
    const edJwk = publicJwk(ed.publicKey, kid, "EdDSA");
    const otherJwk = publicJwk(otherEd.publicKey, "other-key-001", "EdDSA");
    const ecJwk = publicJwk(ec.publicKey, "ec-key-001", "ES256");
    const rsaJwk = publicJwk(rsa.publicKey, "rsa-key-001", "RS256");
    const edRegistration = registrationWithKeys([edJwk], ["EdDSA"]);
    const header = { alg: "EdDSA", kid };
    const signed = signedAssertion(header, context, ed.privateKey);
    const issued = { ...structuredClone(response), assertion: signed };
    assert.equal(redemptionResponseMatchesContext(issued, context, edRegistration), true);

    const corrupted = corruptSignature(signed);
    assert.notEqual(corrupted, signed);
    assert.equal(redemptionResponseMatchesContext({ ...issued, assertion: corrupted }, context, edRegistration), false);
    const oneByte = signed.split(".");
    oneByte[2] = Buffer.from([1]).toString("base64url");
    assert.equal(redemptionResponseMatchesContext({ ...issued, assertion: oneByte.join(".") }, context, edRegistration), false);
    assert.equal(redemptionResponseMatchesContext({ ...issued, assertion: signed.split(".").slice(0, 2).join(".") }, context, edRegistration), false);
    assert.equal(redemptionResponseMatchesContext({ ...issued, assertion: `${signed}=` }, context, edRegistration), false);

    const unknownHeader = { alg: "EdDSA", kid: "unknown-key" };
    const unknown = signedAssertion(unknownHeader, context, ed.privateKey);
    assert.equal(redemptionResponseMatchesContext({ ...issued, assertion: unknown }, context, edRegistration), false);

    const wrongKey = signedAssertion(header, context, otherEd.privateKey);
    assert.equal(redemptionResponseMatchesContext({ ...issued, assertion: wrongKey }, context, edRegistration), false);
    const bothKeys = registrationWithKeys([edJwk, otherJwk], ["EdDSA"]);
    const signedByOther = signedAssertion({ alg: "EdDSA", kid: edJwk.kid }, context, otherEd.privateKey);
    assert.equal(redemptionResponseMatchesContext({ ...issued, assertion: signedByOther }, context, bothKeys), false);
    const signedByRegisteredOther = signedAssertion({ alg: "EdDSA", kid: otherJwk.kid }, context, otherEd.privateKey);
    assert.equal(redemptionResponseMatchesContext({ ...issued, assertion: signedByRegisteredOther }, context, bothKeys), true);

    assert.equal(redemptionResponseMatchesContext({ ...issued, assertion: compactWithHeader({ alg: "none", kid }, context) }, context, edRegistration), false);
    assert.equal(redemptionResponseMatchesContext({ ...issued, assertion: compactWithHeader({ alg: "HS256", kid }, context) }, context, edRegistration), false);
    const inconsistent = registrationWithKeys([edJwk], ["EdDSA", "RS256"]);
    assert.equal(
      redemptionResponseMatchesContext({ ...issued, assertion: compactWithHeader({ alg: "RS256", kid }, context) }, context, inconsistent),
      false,
    );
    const omitted = registrationWithKeys([edJwk], ["RS256"]);
    assert.equal(redemptionResponseMatchesContext(issued, context, omitted), false);

    for (const injected of ["jku", "jwk", "x5u", "x5c"]) {
      const injectedHeader = { alg: "EdDSA", kid, [injected]: "https://caller.example/keys" };
      const injectedAssertion = signedAssertion(injectedHeader, context, ed.privateKey);
      assert.equal(redemptionResponseMatchesContext({ ...issued, assertion: injectedAssertion }, context, edRegistration), false, injected);
    }

    const altered = structuredClone(context);
    altered.purpose = "other-purpose";
    const parts = signed.split(".");
    parts[1] = Buffer.from(JSON.stringify(altered)).toString("base64url");
    assert.equal(redemptionResponseMatchesContext({ ...issued, assertion: parts.join(".") }, context, edRegistration), false);
    const resigned = signedAssertion(header, altered, ed.privateKey);
    assert.equal(redemptionResponseMatchesContext({ ...issued, assertion: resigned }, context, edRegistration), false);

    const ambiguous = registrationWithKeys([edJwk, structuredClone(edJwk)], ["EdDSA"]);
    assert.equal(redemptionResponseMatchesContext(issued, context, ambiguous), false);
    const privateMaterial = structuredClone(edJwk);
    privateMaterial.d = "AA";
    assert.equal(redemptionResponseMatchesContext(issued, context, registrationWithKeys([privateMaterial], ["EdDSA"])), false);

    const ecRegistration = registrationWithKeys([ecJwk], ["ES256"]);
    const ecSigned = signedAssertion({ alg: "ES256", kid: ecJwk.kid }, context, ec.privateKey);
    assert.equal(redemptionResponseMatchesContext({ ...issued, assertion: ecSigned }, context, ecRegistration), true);
    const rsaRegistration = registrationWithKeys([rsaJwk], ["RS256"]);
    const rsaSigned = signedAssertion({ alg: "RS256", kid: rsaJwk.kid }, context, rsa.privateKey);
    assert.equal(redemptionResponseMatchesContext({ ...issued, assertion: rsaSigned }, context, rsaRegistration), true);
    const multiPrime = structuredClone(rsaJwk);
    multiPrime.oth = [{ r: "AA", d: "AA", t: "AA" }];
    assert.equal(
      redemptionResponseMatchesContext(
        { ...issued, assertion: rsaSigned },
        context,
        registrationWithKeys([multiPrime], ["RS256"]),
      ),
      false,
    );
    const ecAsRsa = registrationWithKeys([ecJwk], ["ES256", "RS256"]);
    assert.equal(
      redemptionResponseMatchesContext({ ...issued, assertion: compactWithHeader({ alg: "RS256", kid: ecJwk.kid }, context) }, context, ecAsRsa),
      false,
    );
  });
  await t.test("a correctly signed payload must still be one closed authenticated context", () => {
    const ed = generateKeyPairSync("ed25519");
    const kid = "source-key-placeholder-001";
    const edRegistration = registrationWithKeys([publicJwk(ed.publicKey, kid, "EdDSA")], ["EdDSA"]);
    const header = { alg: "EdDSA", kid };
    const accept = (payload, expiresIn = response.expires_in) => {
      const assertion = signedAssertion(header, payload, ed.privateKey);
      return redemptionResponseMatchesContext(
        { ...structuredClone(response), assertion, expires_in: expiresIn },
        payload,
        edRegistration,
      );
    };
    assert.equal(accept(context), true);
    assert.equal(accept({ ...structuredClone(context), iss: context.issuer }), false);
    assert.equal(accept({ ...structuredClone(context), aud: context.audience }), false);
    assert.equal(accept({ ...structuredClone(context), client_id: context.client_ref }), false);
    assert.equal(accept({ ...structuredClone(context), extension_field: "not-admitted" }), false);
    const sameKeyWrongIssuer = structuredClone(edRegistration);
    sameKeyWrongIssuer.issuer = "issuer-placeholder-002";
    assert.equal(
      redemptionResponseMatchesContext(
        { ...structuredClone(response), assertion: signedAssertion(header, context, ed.privateKey) },
        context,
        sameKeyWrongIssuer,
      ),
      false,
    );
    for (const field of ["subject_ref", "source_session_ref", "source_context_ref"]) {
      const missing = structuredClone(context);
      delete missing[field];
      assert.equal(accept(missing), false, field);
    }
    const sameRefs = structuredClone(context);
    sameRefs.source_context_ref = sameRefs.source_session_ref;
    assert.equal(accept(sameRefs), false);
    const wildcard = structuredClone(context);
    wildcard.record_scope_refs = ["*"];
    assert.equal(accept(wildcard), false);
    const malformedScope = structuredClone(context);
    malformedScope.record_scope_refs = [1];
    assert.equal(accept(malformedScope), false);
    const unsorted = structuredClone(context);
    unsorted.source_permission_refs = [
      "source-permission-placeholder-002",
      "source-permission-placeholder-001",
    ];
    assert.equal(accept(unsorted), false);
    const badDestination = structuredClone(context);
    badDestination.destination_uri = "https://:";
    assert.equal(accept(badDestination), false);
    const badDay = structuredClone(context);
    badDay.issued_at = "2026-02-30T00:00:00Z";
    assert.equal(accept(badDay), false);
    const tooLong = structuredClone(context);
    tooLong.expires_at = "2026-08-15T00:05:21Z";
    assert.equal(accept(tooLong, 300), false);
    const wrongFamily = structuredClone(context);
    wrongFamily.contract_family = "other-family";
    assert.equal(accept(wrongFamily), false);
    const wrongVersion = structuredClone(context);
    wrongVersion.contract_version = "v9.9";
    assert.equal(accept(wrongVersion), false);
    const wrongProfile = structuredClone(context);
    wrongProfile.profile = "other-profile";
    assert.equal(accept(wrongProfile), false);
  });
  await t.test("authorization code lifetime is a 60 second window from issued_at", () => {
    const judge = (record, now = "2026-08-15T00:00:30Z") => redemptionOf({ record, now });
    const exact = judge({
      issued_at: "2026-08-15T00:00:00.0000000000Z",
      expires_at: "2026-08-15T00:01:00.0000000000Z",
    });
    assert.equal(exact.failure, null);
    assert.equal(exact.codeConsumed, true);
    assertNoSession(exact);

    const shorter = judge({
      issued_at: "2026-08-15T00:00:00Z",
      expires_at: "2026-08-15T00:00:30Z",
    }, "2026-08-15T00:00:15Z");
    assert.equal(shorter.failure, null);
    assert.equal(shorter.codeConsumed, true);
    assertNoSession(shorter);

    const exactFraction = judge({
      issued_at: "2026-08-15T00:00:00.0000000001Z",
      expires_at: "2026-08-15T00:01:00.0000000001Z",
    });
    assert.equal(exactFraction.failure, null);
    assert.equal(exactFraction.codeConsumed, true);
    assertNoSession(exactFraction);

    const fractional = judge({
      issued_at: "2026-08-15T00:00:00.0000000000Z",
      expires_at: "2026-08-15T00:01:00.0000000001Z",
    });
    assert.equal(fractional.code, "CODE_EXPIRED");
    assert.equal(fractional.codeConsumed, false);
    assertNoSession(fractional);

    const sixtyOne = judge({
      issued_at: "2026-08-15T00:00:00Z",
      expires_at: "2026-08-15T00:01:01Z",
    });
    assert.equal(sixtyOne.code, "CODE_EXPIRED");
    assert.equal(sixtyOne.codeConsumed, false);
    assertNoSession(sixtyOne);

    const fiveMinutes = judge({
      issued_at: "2026-08-15T00:00:00Z",
      expires_at: "2026-08-15T00:05:00Z",
    }, "2026-08-15T00:01:00Z");
    assert.equal(fiveMinutes.code, "CODE_EXPIRED");
    assert.equal(fiveMinutes.failure, "expired");
    assert.equal(fiveMinutes.codeConsumed, false);
    assertNoSession(fiveMinutes);

    const hours = judge({
      issued_at: "2026-08-15T00:00:00Z",
      expires_at: "2026-08-15T02:00:00Z",
    });
    assert.equal(hours.code, "CODE_EXPIRED");
    assert.equal(hours.failure, "expired");
    assert.equal(hours.codeConsumed, false);
    assertNoSession(hours);

    const oneYear = judge({
      issued_at: "2026-08-15T00:00:00Z",
      expires_at: "2027-08-15T00:00:00Z",
    });
    assert.equal(oneYear.code, "CODE_EXPIRED");
    assert.equal(oneYear.codeConsumed, false);
    assertNoSession(oneYear);

    const missingRecord = codeRecordFor(publishedRedemptionRequest());
    delete missingRecord.issued_at;
    const missing = redemptionOf({ codeRecord: missingRecord });
    assert.equal(missing.code, "MALFORMED_REQUEST");
    assert.equal(missing.codeConsumed, false);
    assertNoSession(missing);

    const malformed = judge({ issued_at: "2026-02-30T00:00:00Z" });
    assert.equal(malformed.code, "MALFORMED_REQUEST");
    assert.equal(malformed.failure, "malformed");
    assert.equal(malformed.codeConsumed, false);
    assertNoSession(malformed);

    const malformedExpiry = judge({ expires_at: "2026-02-30T00:01:00Z" });
    assert.equal(malformedExpiry.code, "MALFORMED_REQUEST");
    assert.equal(malformedExpiry.failure, "malformed");
    assert.equal(malformedExpiry.codeConsumed, false);
    assertNoSession(malformedExpiry);

    const equalBounds = judge({
      issued_at: "2026-08-15T00:00:30Z",
      expires_at: "2026-08-15T00:00:30Z",
    });
    assert.equal(equalBounds.code, "CODE_EXPIRED");
    assert.equal(equalBounds.codeConsumed, false);
    assertNoSession(equalBounds);

    const inverted = judge({
      issued_at: "2026-08-15T00:01:00Z",
      expires_at: "2026-08-15T00:00:00Z",
    });
    assert.equal(inverted.code, "CODE_EXPIRED");
    assert.equal(inverted.codeConsumed, false);
    assertNoSession(inverted);

    const beforeStart = judge({
      issued_at: "2026-08-15T00:00:40Z",
      expires_at: "2026-08-15T00:01:40Z",
    });
    assert.equal(beforeStart.code, "CODE_EXPIRED");
    assert.equal(beforeStart.codeConsumed, false);
    assertNoSession(beforeStart);

    const atStart = judge({
      issued_at: "2026-08-15T00:00:30Z",
      expires_at: "2026-08-15T00:01:30Z",
    });
    assert.equal(atStart.failure, null);
    assert.equal(atStart.codeConsumed, true);

    const beforeEnd = judge({
      issued_at: "2026-08-15T00:00:00Z",
      expires_at: "2026-08-15T00:01:00Z",
    }, "2026-08-15T00:00:59Z");
    assert.equal(beforeEnd.failure, null);
    assert.equal(beforeEnd.codeConsumed, true);

    const atEnd = judge({
      issued_at: "2026-08-15T00:00:00Z",
      expires_at: "2026-08-15T00:01:00Z",
    }, "2026-08-15T00:01:00Z");
    assert.equal(atEnd.code, "CODE_EXPIRED");
    assert.equal(atEnd.failure, "expired");
    assert.equal(atEnd.codeConsumed, false);
    assertNoSession(atEnd);

    const afterEnd = judge({
      issued_at: "2026-08-15T00:00:00Z",
      expires_at: "2026-08-15T00:01:00Z",
    }, "2026-08-15T00:01:01Z");
    assert.equal(afterEnd.code, "CODE_EXPIRED");
    assert.equal(afterEnd.failure, "expired");
    assert.equal(afterEnd.codeConsumed, false);
    assertNoSession(afterEnd);

    const lowYear = judge({
      issued_at: "0099-12-31T23:59:30Z",
      expires_at: "0100-01-01T00:00:00Z",
    }, "0099-12-31T23:59:45Z");
    assert.equal(lowYear.failure, null);
    assert.equal(lowYear.codeConsumed, true);
    assertNoSession(lowYear);

    const once = redemptionOf();
    assert.equal(once.failure, null);
    assert.equal(once.codeConsumed, true);
    const replay = redemptionOf({ record: { consumed: true } });
    assert.equal(replay.code, "CODE_REPLAYED");
    assert.equal(replay.codeConsumed, false);
    assertNoSession(replay);
  });
  await t.test("issuer unavailability is the only automatic retry besides dependency failure", () => {
    const issuerDown = redemptionOf({ issuerUnavailable: true });
    assert.equal(issuerDown.code, "ISSUER_UNAVAILABLE");
    assert.equal(issuerDown.retryable, true);
    assertNoSession(issuerDown);
    const dependency = redemptionOf({ dependencyAvailable: false, issuerUnavailable: false });
    assert.equal(dependency.code, "DEPENDENCY_UNAVAILABLE");
    assert.equal(dependency.retryable, true);
    assert.equal(dependency.synthesizedUnscopedRedirect, false);
    assertNoSession(dependency);
  });
});

test("source-session-handoff structural scope defects are malformed before scope_invalid", () => {
  const numeric = structuredClone(loadJson(INITIATION_EXAMPLE));
  numeric.requested_record_scope_refs = [1];
  assert.equal(validatorFor(INITIATION_SCHEMA)(numeric), false);
  const numericResult = assessSourceSessionHandoff(presentationOf({ initiation: numeric }));
  assert.equal(numericResult.failure, "malformed");
  assert.notEqual(numericResult.failure, "scope_invalid");
  assertNoSession(numericResult);

  const emptyString = structuredClone(loadJson(INITIATION_EXAMPLE));
  emptyString.requested_record_scope_refs = [""];
  assert.equal(validatorFor(INITIATION_SCHEMA)(emptyString), false);
  const emptyResult = assessSourceSessionHandoff(presentationOf({ initiation: emptyString }));
  assert.equal(emptyResult.failure, "malformed");
  assertNoSession(emptyResult);
});

test("source-session-handoff context lifetime cannot use skew or outlive the source session", () => {
  const before = assessSourceSessionHandoff(presentationOf({ at: "2026-08-15T00:00:19.999Z" }));
  assert.equal(before.failure, "unverified");
  assert.equal(before.retryable, false);
  const outlives = assessSourceSessionHandoff(presentationOf({
    sourceSessionExpiresAt: "2026-08-15T00:04:00Z",
  }));
  assert.equal(outlives.failure, "expired");
  assertNoSession(outlives);
  const equalEnd = assessSourceSessionHandoff(presentationOf({
    sourceSessionExpiresAt: "2026-08-15T00:04:20Z",
  }));
  assert.equal(equalEnd.failure, null);
  assert.equal(equalEnd.contextAccepted, true);
  assertNoSession(equalEnd);
});

test("source-session-handoff redemption schema validity must be affirmative", () => {
  const request = publishedRedemptionRequest();
  const input = {
    request,
    registration: publishedRegistration(),
    codeRecord: codeRecordFor(request),
    codeChallengeMethod: "S256",
    now: "2026-08-15T00:00:30Z",
    issuerUnavailable: false,
    dependencyAvailable: true,
  };
  const omitted = assessRedemption(input);
  assert.equal(omitted.code, "MALFORMED_REQUEST");
  assert.equal(omitted.failure, "malformed");
  assert.equal(omitted.codeConsumed, false);
  assertNoSession(omitted);
  const undefinedFlag = assessRedemption({ ...input, schemaValidRequest: undefined });
  assert.equal(undefinedFlag.code, "MALFORMED_REQUEST");
  assert.equal(undefinedFlag.codeConsumed, false);
  const extra = { ...structuredClone(request), extension_field: "not-admitted" };
  const unknown = assessRedemption({ ...input, request: extra });
  assert.equal(unknown.code, "MALFORMED_REQUEST");
  assert.equal(unknown.codeConsumed, false);
  const missingGrant = structuredClone(request);
  delete missingGrant.grant_type;
  const droppedGrant = assessRedemption({ ...input, request: missingGrant });
  assert.equal(droppedGrant.code, "MALFORMED_REQUEST");
  assert.equal(droppedGrant.codeConsumed, false);
  const missingCode = structuredClone(request);
  delete missingCode.authorization_code;
  const droppedCode = assessRedemption({ ...input, request: missingCode });
  assert.equal(droppedCode.code, "MALFORMED_REQUEST");
  assert.equal(droppedCode.codeConsumed, false);
  const wrongFamily = structuredClone(request);
  wrongFamily.contract_family = "other-family";
  const family = assessRedemption({ ...input, request: wrongFamily });
  assert.equal(family.code, "UNSUPPORTED_CONTRACT_VERSION");
  assert.equal(family.codeConsumed, false);
  const accepted = redemptionOf();
  assert.equal(accepted.failure, null);
  assert.equal(accepted.codeConsumed, true);
});

test("source-session-handoff schema validity must be affirmative", () => {
  const base = presentationOf();
  const omitted = { ...base };
  delete omitted.schemaValidInitiation;
  delete omitted.schemaValidContext;
  const omittedResult = assessSourceSessionHandoff(omitted);
  assert.equal(omittedResult.failure, "malformed");
  assert.equal(omittedResult.contextAccepted, false);
  assertNoSession(omittedResult);
  for (const flags of [
    { schemaValidInitiation: undefined, schemaValidContext: undefined },
    { schemaValidInitiation: true, schemaValidContext: undefined },
    { schemaValidInitiation: undefined, schemaValidContext: true },
  ]) {
    const result = assessSourceSessionHandoff({ ...base, ...flags });
    assert.equal(result.failure, "malformed");
    assert.equal(result.contextAccepted, false);
    assertNoSession(result);
  }
  const accepted = assessSourceSessionHandoff(base);
  assert.equal(accepted.failure, null);
  assert.equal(accepted.contextAccepted, true);
});

test("source-session-handoff registration is public verification material only", () => {
  const registration = publishedRegistration();
  const schema = loadJson(REGISTRATION_SCHEMA);
  for (const field of ["receiver_role", "membership", "grant", "permission", "client_secret", "d"]) {
    assert.equal(Object.hasOwn(schema.properties, field), false, field);
  }
  const withPrivate = structuredClone(registration);
  withPrivate.jwks.keys[0].d = "not-a-public-parameter";
  assert.equal(validatorFor(REGISTRATION_SCHEMA)(withPrivate), false);
  assert.equal(registrationEndpointsAccepted(registration), true);
  assert.equal(
    registrationPermitsRedirect(
      registration,
      registration.client_ref,
      registration.destination_uris[0],
    ),
    true,
  );
  const validateRegistration = validatorFor(REGISTRATION_SCHEMA);
  for (const field of ["authorization_endpoint", "token_endpoint"]) {
    const malformed = structuredClone(registration);
    malformed[field] = "https://[:::1]/callback";
    assert.equal(validateRegistration(malformed), true, field);
    assert.equal(destinationUriValid(malformed[field]), false, field);
    assert.equal(registrationEndpointsAccepted(malformed), false, field);
    assert.equal(
      registrationPermitsRedirect(malformed, malformed.client_ref, malformed.destination_uris[0]),
      false,
      field,
    );
    assert.equal(
      redemptionResponseMatchesContext(
        loadJson(REDEMPTION_RESPONSE_EXAMPLE),
        loadJson(CONTEXT_EXAMPLE),
        malformed,
      ),
      false,
      field,
    );
  }
  assert.equal(
    registrationPermitsRedirect(
      registration,
      registration.client_ref,
      "https://receiver.example:443/session-handoff/callback",
    ),
    false,
  );
});

test("source-session-handoff redemption requires canonical registration endpoints", () => {
  const accepted = redemptionOf();
  assert.equal(accepted.failure, null);
  assert.equal(accepted.codeConsumed, true);
  const replay = redemptionOf({ record: { consumed: true } });
  assert.equal(replay.code, "CODE_REPLAYED");
  assert.equal(replay.codeConsumed, false);

  for (const [authorizationEndpoint, tokenEndpoint] of [
    ["https://issuer.example/oauth/authorize", "https://issuer.example/oauth/token"],
    ["https://issuer.example/oauth//authorize", "https://issuer.example/oauth/token"],
    ["https://issuer.example:8443/oauth/authorize", "https://issuer.example/oauth/token"],
    ["https://[2001:db8::1]/oauth/authorize", "https://[2001:db8::1]/oauth/token"],
  ]) {
    const registration = publishedRegistration();
    registration.authorization_endpoint = authorizationEndpoint;
    registration.token_endpoint = tokenEndpoint;
    const result = redemptionOf({ registration });
    assert.equal(result.failure, null, `${authorizationEndpoint} ${tokenEndpoint}`);
    assert.equal(result.codeConsumed, true, `${authorizationEndpoint} ${tokenEndpoint}`);
    assertNoSession(result);
  }

  const rejected = [
    "https://[:::1]/callback",
    "https://0x7f.0.0.1/callback",
    "https://issuer.example/oauth/authorize?x=1",
    "https://issuer.example/oauth/authorize#fragment",
    "https://user:pw@issuer.example/oauth/authorize",
    "https://issuer.example/oauth\\authorize",
    "https://issuer.example/oauth/authorize ",
    "https://issuer.example/oauth/authorize\u0000",
    "https://issuer.example:/oauth/authorize",
    "https://issuer.example:65536/oauth/authorize",
    "https://issuer.example/foo/../callback",
  ];
  for (const field of ["authorization_endpoint", "token_endpoint"]) {
    for (const endpoint of rejected) {
      const registration = publishedRegistration();
      registration[field] = endpoint;
      const result = redemptionOf({ registration });
      assert.equal(result.code, "UNKNOWN_CLIENT", `${field} ${endpoint}`);
      assert.equal(result.failure, "unverified", `${field} ${endpoint}`);
      assert.equal(result.codeConsumed, false, `${field} ${endpoint}`);
      assertNoSession(result);
      const replayed = redemptionOf({ registration, record: { consumed: true } });
      assert.equal(replayed.code, "UNKNOWN_CLIENT", `${field} ${endpoint}`);
      assert.equal(replayed.codeConsumed, false, `${field} ${endpoint}`);
    }
  }
});

function pairwisePrefixReference(values) {
  const sorted = [...values].sort();
  for (let i = 0; i < sorted.length; i += 1) {
    for (let j = i + 1; j < sorted.length; j += 1) {
      if (sorted[j].startsWith(sorted[i])) {
        return true;
      }
    }
  }
  return false;
}

function signedRawSegments(headerBytes, payloadBytes, privateKey) {
  const encodedHeader = Buffer.from(headerBytes).toString("base64url");
  const encodedPayload = Buffer.from(payloadBytes).toString("base64url");
  const signingInput = Buffer.from(`${encodedHeader}.${encodedPayload}`);
  const signature = sign(null, signingInput, privateKey);
  return {
    assertion: `${encodedHeader}.${encodedPayload}.${signature.toString("base64url")}`,
    signingInput,
    signature,
  };
}

test("source-session-handoff code identity is bound before record state", () => {
  const requestA = publishedRedemptionRequest();
  const recordA = codeRecordFor(requestA);
  const otherCode = "bbbbbbbbbbbbbbbbbbbbbb";
  const matched = redemptionOf({ request: requestA, codeRecord: recordA });
  assert.equal(matched.failure, null);
  assert.equal(matched.codeConsumed, true);
  assertNoSession(matched);

  const requestB = structuredClone(requestA);
  requestB.authorization_code = otherCode;
  const unknown = redemptionOf({ request: requestB, codeRecord: recordA });
  assert.equal(unknown.code, "CODE_UNKNOWN");
  assert.equal(unknown.failure, "unverified");
  assert.equal(unknown.retryable, false);
  assert.equal(unknown.codeConsumed, false);
  assertNoSession(unknown);

  const missingIdentity = codeRecordFor(requestA);
  delete missingIdentity.authorization_code;
  assert.equal(redemptionOf({ codeRecord: missingIdentity }).code, "CODE_UNKNOWN");
  const nullIdentity = codeRecordFor(requestA);
  nullIdentity.authorization_code = null;
  assert.equal(redemptionOf({ codeRecord: nullIdentity }).code, "CODE_UNKNOWN");
  const numericIdentity = codeRecordFor(requestA);
  numericIdentity.authorization_code = 1234567890123456789012;
  assert.equal(redemptionOf({ codeRecord: numericIdentity }).code, "CODE_UNKNOWN");
  const shortIdentity = codeRecordFor(requestA);
  shortIdentity.authorization_code = "short-code";
  assert.equal(redemptionOf({ codeRecord: shortIdentity }).code, "CODE_UNKNOWN");
  const caseIdentity = codeRecordFor(requestA);
  caseIdentity.authorization_code = `Q${requestA.authorization_code.slice(1)}`;
  const caseResult = redemptionOf({ codeRecord: caseIdentity });
  assert.equal(caseResult.code, "CODE_UNKNOWN");
  assert.equal(caseResult.codeConsumed, false);
  assert.equal(redemptionOf({ codeRecord: ["not-a-record"] }).code, "CODE_UNKNOWN");

  const consumedMatch = codeRecordFor(requestA, { consumed: true });
  const replay = redemptionOf({ codeRecord: consumedMatch });
  assert.equal(replay.code, "CODE_REPLAYED");
  assert.equal(replay.codeConsumed, false);
  assertNoSession(replay);
  const consumedOther = codeRecordFor(requestA, { consumed: true });
  const hiddenReplay = redemptionOf({ request: requestB, codeRecord: consumedOther });
  assert.equal(hiddenReplay.code, "CODE_UNKNOWN");
  assert.equal(hiddenReplay.codeConsumed, false);

  const malformedRequest = structuredClone(requestA);
  malformedRequest.authorization_code = "short";
  const malformed = redemptionOf({
    request: malformedRequest,
    codeRecord: recordA,
    schemaValidRequest: true,
  });
  assert.equal(malformed.code, "MALFORMED_REQUEST");
  assert.equal(malformed.codeConsumed, false);
  assertNoSession(malformed);

  const missingConsumed = codeRecordFor(requestA);
  delete missingConsumed.consumed;
  const missingFlag = redemptionOf({ codeRecord: missingConsumed });
  assert.equal(missingFlag.code, "MALFORMED_REQUEST");
  assert.equal(missingFlag.codeConsumed, false);
  const stringConsumed = codeRecordFor(requestA, { consumed: "false" });
  assert.equal(redemptionOf({ codeRecord: stringConsumed }).code, "MALFORMED_REQUEST");

  const wrongClient = structuredClone(requestA);
  wrongClient.client_ref = "client-placeholder-002";
  assert.equal(redemptionOf({ request: wrongClient, codeRecord: recordA }).code, "UNKNOWN_CLIENT");
  const otherDestination = "https://receiver.example/session-handoff/other";
  const registration = publishedRegistration();
  registration.destination_uris = [...registration.destination_uris, otherDestination];
  const wrongDestination = structuredClone(requestA);
  wrongDestination.destination_uri = otherDestination;
  const destination = redemptionOf({
    request: wrongDestination,
    registration,
    codeRecord: recordA,
  });
  assert.equal(destination.code, "DESTINATION_MISMATCH");
  assert.equal(destination.codeConsumed, false);
  const wrongVerifier = structuredClone(requestA);
  wrongVerifier.code_verifier = "a".repeat(43);
  const pkce = redemptionOf({ request: wrongVerifier, codeRecord: recordA });
  assert.equal(pkce.code, "PKCE_MISMATCH");
  assert.equal(pkce.codeConsumed, false);
  for (const [field, value, code] of [
    ["purpose", "other-purpose", "PURPOSE_MISMATCH"],
    ["handoff_ref", "handoff-placeholder-002", "HANDOFF_MISMATCH"],
    ["transaction_ref", "transaction-placeholder-002", "TRANSACTION_MISMATCH"],
    ["correlation_ref", "correlation-placeholder-002", "CORRELATION_MISMATCH"],
  ]) {
    const request = structuredClone(requestA);
    request[field] = value;
    const result = redemptionOf({ request, codeRecord: recordA });
    assert.equal(result.code, code, field);
    assert.equal(result.codeConsumed, false, field);
    assertNoSession(result);
  }
});

test("source-session-handoff issuance window is half-open", () => {
  const initiation = loadJson(INITIATION_EXAMPLE);
  const baseContext = loadJson(CONTEXT_EXAMPLE);
  const judge = (issuedAt, expiresAt, at, sourceSessionExpiresAt, extra = {}) => assessSourceSessionHandoff(presentationOf({
    initiation,
    context: { ...structuredClone(baseContext), issued_at: issuedAt, expires_at: expiresAt },
    at,
    sourceSessionExpiresAt,
    ...extra,
  }));

  const exactStart = judge(
    initiation.initiated_at,
    "2026-08-15T00:04:00Z",
    "2026-08-15T00:00:30Z",
    "2026-08-15T00:04:00Z",
  );
  assert.equal(exactStart.failure, null);
  assert.equal(exactStart.contextAccepted, true);

  const deepBeforeEnd = "2026-08-15T00:00:44.999999999999999999999999999999Z";
  const deepExpiry = "2026-08-15T00:04:44.999999999999999999999999999999Z";
  const justBefore = judge(deepBeforeEnd, deepExpiry, deepBeforeEnd, deepExpiry);
  assert.equal(justBefore.failure, null);
  assert.equal(justBefore.contextAccepted, true);

  const exactEnd = judge(
    initiation.expires_at,
    "2026-08-15T00:04:45Z",
    initiation.expires_at,
    "2026-08-15T00:04:45Z",
  );
  assert.equal(exactEnd.failure, "expired");
  assert.equal(exactEnd.reconciled, false);
  assertNoSession(exactEnd);

  const afterEnd = judge(
    "2026-08-15T00:00:45.0000000001Z",
    "2026-08-15T00:04:45.0000000001Z",
    "2026-08-15T00:00:45.0000000001Z",
    "2026-08-15T00:04:45.0000000001Z",
  );
  assert.equal(afterEnd.failure, "expired");

  const zeroWindow = structuredClone(initiation);
  zeroWindow.expires_at = zeroWindow.initiated_at;
  const zero = assessSourceSessionHandoff(presentationOf({
    initiation: zeroWindow,
    sourceSessionExpiresAt: baseContext.expires_at,
  }));
  assert.equal(zero.failure, "expired");
  const inverted = structuredClone(initiation);
  inverted.expires_at = "2026-08-15T00:00:00Z";
  inverted.initiated_at = "2026-08-15T00:00:45Z";
  assert.equal(assessSourceSessionHandoff(presentationOf({ initiation: inverted })).failure, "expired");

  const legalCode = structuredClone(initiation);
  legalCode.expires_at = "2026-08-15T00:01:00Z";
  const legalContext = structuredClone(baseContext);
  legalContext.issued_at = "2026-08-15T00:00:30Z";
  legalContext.expires_at = "2026-08-15T00:05:30Z";
  const legal = assessSourceSessionHandoff(presentationOf({
    initiation: legalCode,
    context: legalContext,
    at: legalContext.issued_at,
    sourceSessionExpiresAt: legalContext.expires_at,
  }));
  assert.equal(legal.failure, null);
  assert.equal(durationWithin(legalCode.initiated_at, legalCode.expires_at, 60n), true);
  assert.equal(durationWithin(legalContext.issued_at, legalContext.expires_at, 300n), true);

  const afterCode = assessSourceSessionHandoff(presentationOf({
    at: "2026-08-15T00:01:00Z",
    sourceSessionExpiresAt: baseContext.expires_at,
  }));
  assert.equal(afterCode.failure, null);
  assert.equal(afterCode.contextAccepted, true);

  const atContextEnd = assessSourceSessionHandoff(presentationOf({
    at: baseContext.expires_at,
    sourceSessionExpiresAt: baseContext.expires_at,
  }));
  assert.equal(atContextEnd.failure, "expired");
  const missingSession = assessSourceSessionHandoff(presentationOf({ sourceSessionExpiresAt: undefined }));
  assert.equal(missingSession.failure, "unverified");
  const exceedsSession = assessSourceSessionHandoff(presentationOf({
    sourceSessionExpiresAt: "2026-08-15T00:04:00Z",
  }));
  assert.equal(exceedsSession.failure, "expired");

  const reconciledEnd = judge(
    initiation.expires_at,
    "2026-08-15T00:04:45Z",
    initiation.expires_at,
    "2026-08-15T00:04:45Z",
    {
      uncertain: true,
      codeConsumed: true,
      redeemedContext: {
        ...structuredClone(baseContext),
        issued_at: initiation.expires_at,
        expires_at: "2026-08-15T00:04:45Z",
      },
    },
  );
  assert.equal(reconciledEnd.failure, "expired");
  assert.equal(reconciledEnd.reconciled, false);
  assertNoSession(reconciledEnd);

  const lowInitiation = structuredClone(initiation);
  lowInitiation.initiated_at = "0099-12-31T23:59:30Z";
  lowInitiation.expires_at = "0100-01-01T00:00:00Z";
  const lowContext = structuredClone(baseContext);
  lowContext.issued_at = "0099-12-31T23:59:59Z";
  lowContext.expires_at = "0100-01-01T00:04:59Z";
  const lowOk = assessSourceSessionHandoff(presentationOf({
    initiation: lowInitiation,
    context: lowContext,
    at: lowContext.issued_at,
    sourceSessionExpiresAt: lowContext.expires_at,
  }));
  assert.equal(lowOk.failure, null);
  const lowEnd = structuredClone(lowContext);
  lowEnd.issued_at = "0100-01-01T00:00:00Z";
  lowEnd.expires_at = "0100-01-01T00:05:00Z";
  const lowExpired = assessSourceSessionHandoff(presentationOf({
    initiation: lowInitiation,
    context: lowEnd,
    at: lowEnd.issued_at,
    sourceSessionExpiresAt: lowEnd.expires_at,
  }));
  assert.equal(lowExpired.failure, "expired");
});

test("source-session-handoff prefix checks compare adjacent sorted bounds", () => {
  const cases = [
    ["aa", "zz", "bb"],
    ["scope-001", "scope-001-extra", "scope-002"],
    ["m-prefix", "a-prefix", "z-prefix"],
    ["aa", "aa"],
    ["abc", "abd"],
    ["scope-prefix-001", "scope-prefix-002"],
    ["aa", "aaa"],
    ["\uD83D\uDE00", "\uD83D\uDE00b", "b"],
  ];
  for (const values of cases) {
    const evidence = prefixScanEvidence(values);
    assert.equal(evidence.ambiguous, pairwisePrefixReference(values), values.join(","));
    assert.ok(evidence.comparisons <= Math.max(values.length - 1, 0));
  }
  assert.equal(prefixScanEvidence(["aa", "zz", "aaa"]).ambiguous, true);
  assert.equal(scopeArrayInvalid(["scope-002", "scope-001"]), true);
  assert.equal(scopeArrayInvalid(["scope-001", "scope-002"]), false);
  const frozen = Object.freeze(["b", "a"]);
  const snapshot = [...frozen];
  assert.equal(scopeArrayInvalid(frozen), true);
  assert.deepEqual([...frozen], snapshot);
  const many = Array.from({ length: 10000 }, (_item, index) => `v${String(index).padStart(5, "0")}`);
  const scan = prefixScanEvidence(many);
  assert.equal(scan.ambiguous, false);
  assert.equal(scan.comparisons, many.length - 1);
  assert.equal(many[0], "v00000");
  assert.equal(many[9999], "v09999");
});

test("source-session-handoff JWS decoding rejects invalid UTF-8", () => {
  const ed = generateKeyPairSync("ed25519");
  const kid = "source-key-placeholder-001";
  const registration = registrationWithKeys([publicJwk(ed.publicKey, kid, "EdDSA")], ["EdDSA"]);
  const context = loadJson(CONTEXT_EXAMPLE);
  const header = { alg: "EdDSA", kid };
  const headerBytes = Buffer.from(JSON.stringify(header));
  const response = loadJson(REDEMPTION_RESPONSE_EXAMPLE);
  const multibyte = structuredClone(context);
  multibyte.subject_ref = `${context.subject_ref}-caf\u00e9`;
  const multibyteSigned = signedAssertion(header, multibyte, ed.privateKey);
  assert.equal(inspectCompactJws(multibyteSigned).payload.subject_ref, multibyte.subject_ref);
  assert.equal(
    redemptionResponseMatchesContext(
      { ...structuredClone(response), assertion: multibyteSigned },
      multibyte,
      registration,
    ),
    true,
  );

  const marker = Buffer.from('"subject_ref":"');
  const json = Buffer.from(JSON.stringify(context));
  const at = json.indexOf(marker);
  assert.ok(at > 0);
  const replacements = {
    "invalid payload": Buffer.from([0xff]),
    "continuation byte": Buffer.from([0x80]),
    "truncated sequence": Buffer.from([0xc3]),
    "overlong sequence": Buffer.from([0xc0, 0x80]),
  };
  for (const [name, bytes] of Object.entries(replacements)) {
    const payloadBytes = Buffer.concat([
      json.subarray(0, at + marker.length),
      bytes,
      json.subarray(at + marker.length),
    ]);
    const signed = signedRawSegments(headerBytes, payloadBytes, ed.privateKey);
    assert.equal(verify(null, signed.signingInput, ed.publicKey, signed.signature), true, name);
    const laundered = structuredClone(context);
    laundered.subject_ref = `\uFFFD${context.subject_ref}`;
    assert.equal(inspectCompactJws(signed.assertion), null, name);
    assert.equal(
      redemptionResponseMatchesContext(
        { ...structuredClone(response), assertion: signed.assertion },
        laundered,
        registration,
      ),
      false,
      name,
    );
  }

  const literalReplacement = structuredClone(context);
  literalReplacement.subject_ref = `\uFFFD${context.subject_ref}`;
  const literalSigned = signedAssertion(header, literalReplacement, ed.privateKey);
  assert.equal(inspectCompactJws(literalSigned).payload.subject_ref, literalReplacement.subject_ref);
  assert.equal(
    redemptionResponseMatchesContext(
      { ...structuredClone(response), assertion: literalSigned },
      literalReplacement,
      registration,
    ),
    true,
  );

  const bom = signedRawSegments(
    headerBytes,
    Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(JSON.stringify(context))]),
    ed.privateKey,
  );
  assert.equal(verify(null, bom.signingInput, ed.publicKey, bom.signature), true);
  assert.equal(inspectCompactJws(bom.assertion), null);
  assert.equal(
    redemptionResponseMatchesContext(
      { ...structuredClone(response), assertion: bom.assertion },
      context,
      registration,
    ),
    false,
  );
  const headerBom = signedRawSegments(
    Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), headerBytes]),
    Buffer.from(JSON.stringify(context)),
    ed.privateKey,
  );
  assert.equal(inspectCompactJws(headerBom.assertion), null);

  const badHeader = signedRawSegments(Buffer.from([0xff, 0x7b, 0x7d]), Buffer.from(JSON.stringify(context)), ed.privateKey);
  assert.equal(inspectCompactJws(badHeader.assertion), null);
  for (const payload of ["{", "null", "[]"]) {
    const parsed = signedRawSegments(headerBytes, Buffer.from(payload), ed.privateKey);
    assert.equal(inspectCompactJws(parsed.assertion), null, payload);
  }
  assert.equal(inspectCompactJws(multibyteSigned.split(".").slice(0, 2).join(".")), null);
  const tampered = corruptSignature(multibyteSigned);
  assert.equal(
    redemptionResponseMatchesContext(
      { ...structuredClone(response), assertion: tampered },
      multibyte,
      registration,
    ),
    false,
  );
  const unknown = signedAssertion({ alg: "EdDSA", kid: "unknown-key" }, context, ed.privateKey);
  assert.equal(
    redemptionResponseMatchesContext(
      { ...structuredClone(response), assertion: unknown },
      context,
      registration,
    ),
    false,
  );
});

test("source-session-handoff rejects hexadecimal integer DNS labels on every URI path", () => {
  const rejected = [
    "https://0xdead.example/callback",
    "https://api.0xdead.example/callback",
    "https://0XDEAD.example/callback",
    "https://%30xdead.example/callback",
    "https://0x7f.0.0.1/callback",
    "https://2130706433/callback",
    "https://127.1/callback",
    "https://0177.0.0.1/callback",
  ];
  const accepted = [
    "https://3com/callback",
    "https://service.3com/callback",
    "https://3receiver.example/callback",
    "https://0xdeadbeefish.example/callback",
    "https://receiver.example/a//callback",
    "https://192.0.2.10/callback",
    "https://[2001:db8::192.0.2.1]/callback",
  ];
  const validateInitiation = validatorFor(INITIATION_SCHEMA);
  const validateContext = validatorFor(CONTEXT_SCHEMA);
  const validateRequest = validatorFor(AUTHZ_REQUEST_SCHEMA);
  const validateRegistration = validatorFor(REGISTRATION_SCHEMA);
  for (const uri of rejected) {
    assert.equal(destinationUriValid(uri), false, uri);
    const initiation = loadJson(INITIATION_EXAMPLE);
    initiation.destination_uri = uri;
    assert.equal(validateInitiation(initiation), false, uri);
    assert.equal(initiationSemanticsHold(initiation), false, uri);
    const context = loadJson(CONTEXT_EXAMPLE);
    context.destination_uri = uri;
    assert.equal(validateContext(context), false, uri);
    assert.equal(contextSemanticsHold(context), false, uri);
    const request = loadJson(AUTHZ_REQUEST_EXAMPLE);
    request.destination_uri = uri;
    assert.equal(validateRequest(request), false, uri);
    assert.equal(authorizationRequestDestinationAccepted(request), false, uri);
    const registration = publishedRegistration();
    registration.authorization_endpoint = uri;
    registration.token_endpoint = uri;
    assert.equal(validateRegistration(registration), false, uri);
    assert.equal(registrationEndpointsAccepted(registration), false, uri);
    assert.equal(registrationPermitsRedirect(registration, registration.client_ref, uri), false, uri);
    const redemption = redemptionOf({
      request: { ...publishedRedemptionRequest(), destination_uri: uri },
      schemaValidRequest: true,
    });
    assert.equal(redemption.code, "MALFORMED_REQUEST", uri);
    assert.equal(redemption.codeConsumed, false, uri);
    assertNoSession(redemption);
  }
  for (const uri of accepted) {
    assert.equal(destinationUriValid(uri), true, uri);
    const initiation = loadJson(INITIATION_EXAMPLE);
    initiation.destination_uri = uri;
    assert.equal(validateInitiation(initiation), true, uri);
    assert.equal(initiationSemanticsHold(initiation), true, uri);
    const context = loadJson(CONTEXT_EXAMPLE);
    context.destination_uri = uri;
    assert.equal(validateContext(context), true, uri);
    assert.equal(contextSemanticsHold(context), true, uri);
    const request = loadJson(AUTHZ_REQUEST_EXAMPLE);
    request.destination_uri = uri;
    assert.equal(validateRequest(request), true, uri);
    assert.equal(authorizationRequestDestinationAccepted(request), true, uri);
  }
  const forbidden = "https://0xdead.example/callback";
  const allowListed = publishedRegistration();
  allowListed.destination_uris = [forbidden];
  assert.equal(validatorFor(REGISTRATION_SCHEMA)(allowListed), false);
  assert.equal(
    registrationPermitsRedirect(allowListed, allowListed.client_ref, forbidden),
    false,
  );
  const mismatch = redemptionOf({ registration: allowListed });
  assert.equal(mismatch.code, "UNKNOWN_CLIENT");
  assert.equal(mismatch.codeConsumed, false);
  const badEndpoint = publishedRegistration();
  badEndpoint.authorization_endpoint = "https://api.0xdead.example/callback";
  const endpoint = redemptionOf({ registration: badEndpoint });
  assert.equal(endpoint.code, "UNKNOWN_CLIENT");
  assert.equal(endpoint.codeConsumed, false);
});

test("source-session-handoff oracle integration keeps one failing invariant closed", () => {
  const request = publishedRedemptionRequest();
  const record = codeRecordFor(request);
  const registration = publishedRegistration();
  const context = loadJson(CONTEXT_EXAMPLE);
  const initiation = loadJson(INITIATION_EXAMPLE);
  const callback = loadJson(AUTHZ_SUCCESS_EXAMPLE);
  const authz = loadJson(AUTHZ_REQUEST_EXAMPLE);
  assert.equal(authorizationRequestDestinationAccepted(authz), true);
  assert.equal(browserCallbackQueryAllowed(callback, authz.state), true);
  const redeemed = redemptionOf({ request, codeRecord: record, registration });
  assert.equal(redeemed.codeConsumed, true);
  assert.equal(redemptionResponseMatchesContext(
    loadJson(REDEMPTION_RESPONSE_EXAMPLE),
    context,
    registration,
  ), true);
  const accepted = assessSourceSessionHandoff(presentationOf({
    initiation,
    context,
    sourceSessionExpiresAt: context.expires_at,
  }));
  assert.equal(accepted.contextAccepted, true);
  assert.equal(accepted.mintsReceiverSession, false);

  const otherCode = structuredClone(request);
  otherCode.authorization_code = "cccccccccccccccccccccc";
  const wrongCode = redemptionOf({ request: otherCode, codeRecord: record, registration });
  assert.equal(wrongCode.code, "CODE_UNKNOWN");
  assert.equal(wrongCode.codeConsumed, false);
  assert.equal(wrongCode.contextAccepted, false);
  assertNoSession(wrongCode);
});

function unusedBitAlias(segment) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  const decoded = Buffer.from(segment, "base64url");
  const last = segment[segment.length - 1];
  for (const character of alphabet) {
    if (character === last) {
      continue;
    }
    const candidate = `${segment.slice(0, -1)}${character}`;
    if (Buffer.from(candidate, "base64url").equals(decoded)) {
      return candidate;
    }
  }
  return null;
}

test("source-session-handoff compact JWS segments must be canonical base64url", () => {
  const response = loadJson(REDEMPTION_RESPONSE_EXAMPLE);
  const context = loadJson(CONTEXT_EXAMPLE);
  const registration = publishedRegistration();
  const [header, payload, signature] = response.assertion.split(".");
  assert.equal(inspectCompactJws(response.assertion) !== null, true);
  assert.equal(redemptionResponseMatchesContext(response, context, registration), true);
  assert.equal(Buffer.from(signature, "base64url").toString("base64url"), signature);

  const signatureAlias = `${signature.slice(0, -1)}x`;
  assert.equal(signature.endsWith("w"), true);
  assert.notEqual(signatureAlias, signature);
  assert.equal(
    Buffer.from(signatureAlias, "base64url").equals(Buffer.from(signature, "base64url")),
    true,
  );
  const aliased = `${header}.${payload}.${signatureAlias}`;
  const key = createPublicKey({ key: registration.jwks.keys[0], format: "jwk" });
  assert.equal(
    verify(null, Buffer.from(`${header}.${payload}`), key, Buffer.from(signatureAlias, "base64url")),
    true,
  );
  assert.equal(inspectCompactJws(aliased), null);
  assert.equal(
    redemptionResponseMatchesContext({ ...structuredClone(response), assertion: aliased }, context, registration),
    false,
  );

  const ed = generateKeyPairSync("ed25519");
  const kid = "source-key-placeholder-001";
  const edRegistration = registrationWithKeys([publicJwk(ed.publicKey, kid, "EdDSA")], ["EdDSA"]);
  const headerObject = { alg: "EdDSA", kid };
  const headerSegment = Buffer.from(JSON.stringify(headerObject)).toString("base64url");
  const payloadSegment = Buffer.from(JSON.stringify(context)).toString("base64url");
  const headerAlias = unusedBitAlias(headerSegment);
  const payloadAlias = unusedBitAlias(payloadSegment);
  assert.notEqual(headerAlias, null);
  assert.notEqual(payloadAlias, null);
  for (const [name, encodedHeader, encodedPayload] of [
    ["header alias", headerAlias, payloadSegment],
    ["payload alias", headerSegment, payloadAlias],
  ]) {
    const signingInput = Buffer.from(`${encodedHeader}.${encodedPayload}`);
    const signed = sign(null, signingInput, ed.privateKey);
    const assertion = `${encodedHeader}.${encodedPayload}.${signed.toString("base64url")}`;
    assert.equal(verify(null, signingInput, ed.publicKey, signed), true, name);
    assert.equal(inspectCompactJws(assertion), null, name);
    assert.equal(
      redemptionResponseMatchesContext(
        { ...structuredClone(response), assertion },
        context,
        edRegistration,
      ),
      false,
      name,
    );
  }

  const canonical = signedAssertion(headerObject, context, ed.privateKey);
  assert.equal(
    redemptionResponseMatchesContext(
      { ...structuredClone(response), assertion: canonical },
      context,
      edRegistration,
    ),
    true,
  );
  const ec = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 });
  for (const [alg, pair, curveKid] of [
    ["ES256", ec, "ec-key-001"],
    ["RS256", rsa, "rsa-key-001"],
  ]) {
    const jwk = publicJwk(pair.publicKey, curveKid, alg);
    const accepted = signedAssertion({ alg, kid: curveKid }, context, pair.privateKey);
    assert.equal(
      redemptionResponseMatchesContext(
        { ...structuredClone(response), assertion: accepted },
        context,
        registrationWithKeys([jwk], [alg]),
      ),
      true,
      alg,
    );
  }

  assert.equal(inspectCompactJws(`${header}.${payload}`), null);
  assert.equal(inspectCompactJws(`${header}..${signature}`), null);
  assert.equal(inspectCompactJws(`${header}.${payload}.${signature}.`), null);
  assert.equal(inspectCompactJws(`${header}.${payload}.${signature}=`), null);
  assert.equal(inspectCompactJws(`${header}.${payload}.${signature} `), null);
  assert.equal(inspectCompactJws(`${header}.${payload}.+${signature.slice(1)}`), null);
  assert.equal(inspectCompactJws(canonical.split(".").slice(0, 2).join(".")), null);
});

test("source-session-handoff rejects a trailing DNS root dot", () => {
  const uri = "https://receiver.example./callback";
  assert.equal(destinationUriValid(uri), false);
  const initiation = loadJson(INITIATION_EXAMPLE);
  initiation.destination_uri = uri;
  assert.equal(validatorFor(INITIATION_SCHEMA)(initiation), false);
  assert.equal(initiationSemanticsHold(initiation), false);
  const context = loadJson(CONTEXT_EXAMPLE);
  context.destination_uri = uri;
  assert.equal(validatorFor(CONTEXT_SCHEMA)(context), false);
  assert.equal(contextSemanticsHold(context), false);
  const request = loadJson(AUTHZ_REQUEST_EXAMPLE);
  request.destination_uri = uri;
  assert.equal(validatorFor(AUTHZ_REQUEST_SCHEMA)(request), false);
  assert.equal(authorizationRequestDestinationAccepted(request), false);
  const registration = publishedRegistration();
  registration.authorization_endpoint = uri;
  registration.token_endpoint = uri;
  assert.equal(validatorFor(REGISTRATION_SCHEMA)(registration), false);
  assert.equal(registrationEndpointsAccepted(registration), false);
  assert.equal(registrationPermitsRedirect(registration, registration.client_ref, uri), false);
  const redeemed = redemptionOf({
    request: { ...publishedRedemptionRequest(), destination_uri: uri },
    schemaValidRequest: true,
  });
  assert.equal(redeemed.code, "MALFORMED_REQUEST");
  assert.equal(redeemed.codeConsumed, false);
  assertNoSession(redeemed);
  const allowListed = publishedRegistration();
  allowListed.destination_uris = [uri];
  const mismatch = redemptionOf({ registration: allowListed });
  assert.equal(mismatch.code, "UNKNOWN_CLIENT");
  assert.equal(mismatch.codeConsumed, false);
  assert.equal(destinationUriValid("https://receiver.example/callback"), true);
  assert.equal(destinationUriValid("https://[::1]/callback"), true);
});

test("a registration is trusted only when the closed registration schema holds", () => {
  const response = loadJson(REDEMPTION_RESPONSE_EXAMPLE);
  const context = loadJson(CONTEXT_EXAMPLE);
  const registration = publishedRegistration();
  assert.equal(validatorFor(REGISTRATION_SCHEMA)(registration), true);
  assert.equal(redemptionResponseMatchesContext(response, context, registration), true);
  registration.client_secret = "not-public-verification-material";
  assert.equal(validatorFor(REGISTRATION_SCHEMA)(registration), false);
  assert.equal(redemptionResponseMatchesContext(response, context, registration), false);
  assert.equal(registrationPermitsRedirect(registration, registration.client_ref, registration.destination_uris[0]), false);
  const redeemed = redemptionOf({ registration });
  assert.equal(redeemed.code, "UNKNOWN_CLIENT");
  assert.equal(redeemed.codeConsumed, false);
  assertNoSession(redeemed);
  const disabled = publishedRegistration();
  disabled.status = "disabled";
  assert.equal(redemptionOf({ registration: disabled }).code, "CLIENT_DISABLED");
});

test("browser callback state matches the published grammar before equality", () => {
  const success = loadJson(AUTHZ_SUCCESS_EXAMPLE);
  const denial = loadJson(AUTHZ_DENIAL_EXAMPLE);
  const minimum = "a".repeat(22);
  const representative = success.state;
  const maximum = "b".repeat(128);
  for (const state of [minimum, representative, maximum]) {
    assert.equal(browserCallbackQueryAllowed({ ...success, state }, state), true);
    assert.equal(browserCallbackQueryAllowed({ ...denial, state }, state), true);
  }
  assert.equal(browserCallbackQueryAllowed({ state: "x", code: success.code }, "x"), false);
  const overlong = "c".repeat(129);
  assert.equal(browserCallbackQueryAllowed({ state: overlong, code: success.code }, overlong), false);
  const whitespace = `${minimum} `;
  assert.equal(browserCallbackQueryAllowed({ state: whitespace, code: success.code }, whitespace), false);
  assert.equal(browserCallbackQueryAllowed({ ...success, state: "x" }, representative), false);
  assert.equal(browserCallbackQueryAllowed({ ...success, state: representative }, "x"), false);
  assert.equal(browserCallbackQueryAllowed({ ...success, state: minimum }, maximum), false);
  assert.equal(browserCallbackQueryAllowed({ ...denial, state: minimum }, maximum), false);
});

test("an s256 challenge is the canonical encoding of exactly 32 bytes", () => {
  const request = loadJson(AUTHZ_REQUEST_EXAMPLE);
  const challenge = request.code_challenge;
  const alias = `${challenge.slice(0, -1)}N`;
  assert.equal(validatorFor(AUTHZ_REQUEST_SCHEMA)(request), true);
  assert.equal(pkceChallengeCanonical(challenge), true);
  assert.equal(pkceChallengeCanonical(pkceChallengeFor("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")), true);
  assert.equal(pkceChallengeFor("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"), challenge);
  assert.equal(Buffer.from(alias, "base64url").equals(Buffer.from(challenge, "base64url")), true);
  request.code_challenge = alias;
  assert.equal(validatorFor(AUTHZ_REQUEST_SCHEMA)(request), false);
  assert.equal(pkceChallengeCanonical(alias), false);
  assert.equal(pkceChallengeCanonical(`${challenge}A`), false);
  assert.equal(pkceChallengeCanonical(challenge.slice(0, -1)), false);
  assert.equal(pkceChallengeCanonical(`${challenge.slice(0, -1)}*`), false);
  const record = codeRecordFor(publishedRedemptionRequest());
  record.code_challenge = alias;
  const redeemed = redemptionOf({ record });
  assert.equal(redeemed.code, "PKCE_MISMATCH");
  assert.equal(redeemed.codeConsumed, false);
  assertNoSession(redeemed);
});

const PUBLISHED_DESTINATION = "https://receiver.example/session-handoff/callback";
const PARSER_INVALID_DESTINATION = "https://[:::1]/callback";
const SECOND_VALID_DESTINATION = "https://receiver.example/a//callback";

function registrationWithDestinations(uris, status = "enabled") {
  const registration = publishedRegistration();
  registration.status = status;
  registration.destination_uris = uris;
  return registration;
}

function publishedSignatureHolds(response, registration) {
  const inspected = inspectCompactJws(response.assertion);
  if (inspected === null) {
    return false;
  }
  const key = createPublicKey({ key: registration.jwks.keys[0], format: "jwk" });
  return verify(null, inspected.signingInput, key, inspected.signature);
}

function assertClosedRejection(result, code, label) {
  assert.equal(result.code, code, label);
  assert.equal(result.failure, "unverified", label);
  assert.equal(result.retryable, false, label);
  assert.equal(result.contextAccepted, false, label);
  assert.equal(result.redirectPermitted, false, label);
  assert.equal(result.reconciled, false, label);
  assert.equal(result.codeConsumed, false, label);
  assertNoSession(result);
}

function assertRegistrationTrustRejected(registration, code, label) {
  const response = loadJson(REDEMPTION_RESPONSE_EXAMPLE);
  const context = loadJson(CONTEXT_EXAMPLE);
  const request = publishedRedemptionRequest();
  const record = codeRecordFor(request);
  const registrationBefore = structuredClone(registration);
  const recordBefore = structuredClone(record);
  const responseBefore = structuredClone(response);
  const contextBefore = structuredClone(context);
  assert.equal(publishedSignatureHolds(response, registration), true, `${label} signature`);
  assert.equal(
    registrationPermitsRedirect(registration, registration.client_ref, PUBLISHED_DESTINATION),
    false,
    `${label} redirect`,
  );
  assert.equal(
    redemptionResponseMatchesContext(response, context, registration),
    false,
    `${label} signed context`,
  );
  const redeemed = redemptionOf({ registration, request, codeRecord: record });
  assertClosedRejection(redeemed, code, `${label} redemption`);
  assert.deepEqual(registration, registrationBefore, `${label} registration unchanged`);
  assert.deepEqual(record, recordBefore, `${label} code record unchanged`);
  assert.equal(record.consumed, false, `${label} code unconsumed`);
  assert.deepEqual(response, responseBefore, `${label} response unchanged`);
  assert.deepEqual(context, contextBefore, `${label} context unchanged`);
}

test("source-session-handoff validates every registered destination before trusting a registration", async (t) => {
  const validateRegistration = validatorFor(REGISTRATION_SCHEMA);
  const response = loadJson(REDEMPTION_RESPONSE_EXAMPLE);
  const context = loadJson(CONTEXT_EXAMPLE);

  await t.test("multiple valid destinations remain eligible on every trust path", () => {
    const destinations = [
      PUBLISHED_DESTINATION,
      "https://192.0.2.10/callback",
      "https://[2001:db8::1]/callback",
      "https://[2001:db8::192.0.2.1]/callback",
      "https://3receiver.example/callback",
      "https://receiver.example:8443/callback",
      SECOND_VALID_DESTINATION,
    ];
    const registration = registrationWithDestinations(destinations);
    const registrationBefore = structuredClone(registration);
    assert.equal(validateRegistration(registration), true);
    for (const uri of destinations) {
      assert.equal(destinationUriValid(uri), true, uri);
      assert.equal(
        registrationPermitsRedirect(registration, registration.client_ref, uri),
        true,
        uri,
      );
    }
    assert.equal(
      registrationPermitsRedirect(
        registration,
        registration.client_ref,
        "https://receiver.example:443/session-handoff/callback",
      ),
      false,
    );
    assert.equal(redemptionResponseMatchesContext(response, context, registration), true);
    const redeemed = redemptionOf({ registration });
    assert.equal(redeemed.failure, null);
    assert.equal(redeemed.codeConsumed, true);
    assert.equal(redeemed.contextAccepted, false);
    assertNoSession(redeemed);
    for (const uri of destinations.slice(1)) {
      const request = publishedRedemptionRequest();
      request.destination_uri = uri;
      const record = codeRecordFor(request);
      const recordBefore = structuredClone(record);
      const result = redemptionOf({ request, registration, codeRecord: record });
      assert.equal(result.failure, null, uri);
      assert.equal(result.codeConsumed, true, uri);
      assert.deepEqual(record, recordBefore, uri);
    }
    assert.deepEqual(registration, registrationBefore);
  });

  const positions = [
    ["invalid destination first and requested destination last", [PARSER_INVALID_DESTINATION, SECOND_VALID_DESTINATION, PUBLISHED_DESTINATION]],
    ["invalid destination middle and requested destination first", [PUBLISHED_DESTINATION, PARSER_INVALID_DESTINATION, SECOND_VALID_DESTINATION]],
    ["invalid destination last and requested destination middle", [SECOND_VALID_DESTINATION, PUBLISHED_DESTINATION, PARSER_INVALID_DESTINATION]],
    ["invalid destination first and requested destination middle", [PARSER_INVALID_DESTINATION, PUBLISHED_DESTINATION, SECOND_VALID_DESTINATION]],
    ["invalid destination middle and requested destination last", [SECOND_VALID_DESTINATION, PARSER_INVALID_DESTINATION, PUBLISHED_DESTINATION]],
    ["invalid destination last and requested destination first", [PUBLISHED_DESTINATION, SECOND_VALID_DESTINATION, PARSER_INVALID_DESTINATION]],
  ];
  for (const [name, uris] of positions) {
    await t.test(name, () => {
      const registration = registrationWithDestinations(uris);
      assert.equal(validateRegistration(registration), true, name);
      assert.equal(destinationUriValid(PARSER_INVALID_DESTINATION), false);
      assert.equal(destinationUriValid(PUBLISHED_DESTINATION), true);
      assert.deepEqual(registration.destination_uris, uris);
      assertRegistrationTrustRejected(registration, "UNKNOWN_CLIENT", name);
      assert.deepEqual(registration.destination_uris, uris, name);
    });
  }

  await t.test("schema-valid parser-invalid destinations reject the whole registration", () => {
    const invalidDestinations = [
      PARSER_INVALID_DESTINATION,
      "https://[192.0.2.1::1]/callback",
      "https://receiver.example/foo/../callback",
    ];
    for (const uri of invalidDestinations) {
      assert.equal(destinationUriValid(uri), false, uri);
      const only = registrationWithDestinations([uri]);
      assert.equal(validateRegistration(only), true, uri);
      assertRegistrationTrustRejected(only, "UNKNOWN_CLIENT", `only ${uri}`);
      const unused = registrationWithDestinations([PUBLISHED_DESTINATION, uri]);
      assert.equal(validateRegistration(unused), true, uri);
      assertRegistrationTrustRejected(unused, "UNKNOWN_CLIENT", `unused ${uri}`);
    }
  });

  await t.test("structural allow-list failures fail closed", () => {
    const missing = publishedRegistration();
    delete missing.destination_uris;
    const sparse = registrationWithDestinations([PUBLISHED_DESTINATION]);
    sparse.destination_uris.length = 2;
    const cases = [
      ["missing", missing],
      ["null", registrationWithDestinations(null)],
      ["non-array", registrationWithDestinations(PUBLISHED_DESTINATION)],
      ["empty", registrationWithDestinations([])],
      ["duplicate", registrationWithDestinations([PUBLISHED_DESTINATION, PUBLISHED_DESTINATION])],
      ["non-string", registrationWithDestinations([PUBLISHED_DESTINATION, 1])],
      ["sparse", sparse],
    ];
    for (const [name, registration] of cases) {
      assert.equal(validateRegistration(registration), false, name);
      let redirected = null;
      assert.doesNotThrow(() => {
        redirected = registrationPermitsRedirect(
          registration,
          registration.client_ref,
          PUBLISHED_DESTINATION,
        );
      }, name);
      assert.equal(redirected, false, name);
      assert.doesNotThrow(() => {
        assert.equal(redemptionResponseMatchesContext(response, context, registration), false, name);
      }, name);
      const request = publishedRedemptionRequest();
      const record = codeRecordFor(request);
      const recordBefore = structuredClone(record);
      let redeemed = null;
      assert.doesNotThrow(() => {
        redeemed = redemptionOf({ registration, request, codeRecord: record });
      }, name);
      assertClosedRejection(redeemed, "UNKNOWN_CLIENT", name);
      assert.deepEqual(record, recordBefore, name);
      if (name === "sparse") {
        assert.equal(registration.destination_uris.length, 2);
        assert.equal(Object.hasOwn(registration.destination_uris, 1), false);
        assert.equal(registration.destination_uris[0], PUBLISHED_DESTINATION);
      }
    }
  });

  await t.test("invalid authorization endpoint with valid destinations", () => {
    const registration = publishedRegistration();
    registration.authorization_endpoint = PARSER_INVALID_DESTINATION;
    assert.equal(validateRegistration(registration), true);
    assert.equal(destinationUriValid(registration.destination_uris[0]), true);
    assert.equal(registrationEndpointsAccepted(registration), false);
    assertRegistrationTrustRejected(registration, "UNKNOWN_CLIENT", "authorization endpoint");
  });

  await t.test("invalid token endpoint with valid destinations", () => {
    const registration = publishedRegistration();
    registration.token_endpoint = PARSER_INVALID_DESTINATION;
    assert.equal(validateRegistration(registration), true);
    assert.equal(destinationUriValid(registration.destination_uris[0]), true);
    assert.equal(registrationEndpointsAccepted(registration), false);
    assertRegistrationTrustRejected(registration, "UNKNOWN_CLIENT", "token endpoint");
  });

  await t.test("omitted valid destination remains DESTINATION_MISMATCH", () => {
    const registration = registrationWithDestinations([SECOND_VALID_DESTINATION]);
    const registrationBefore = structuredClone(registration);
    const request = publishedRedemptionRequest();
    const record = codeRecordFor(request);
    const recordBefore = structuredClone(record);
    assert.equal(validateRegistration(registration), true);
    assert.equal(destinationUriValid(SECOND_VALID_DESTINATION), true);
    assert.equal(destinationUriValid(PUBLISHED_DESTINATION), true);
    assert.equal(
      registrationPermitsRedirect(registration, registration.client_ref, SECOND_VALID_DESTINATION),
      true,
    );
    assert.equal(
      registrationPermitsRedirect(registration, registration.client_ref, PUBLISHED_DESTINATION),
      false,
    );
    assert.equal(publishedSignatureHolds(response, registration), true);
    assert.equal(redemptionResponseMatchesContext(response, context, registration), false);
    const redeemed = redemptionOf({ registration, request, codeRecord: record });
    assertClosedRejection(redeemed, "DESTINATION_MISMATCH", "omitted destination");
    assert.deepEqual(registration, registrationBefore);
    assert.deepEqual(record, recordBefore);
    assert.equal(record.consumed, false);
  });

  await t.test("disabled malformed registration preserves CLIENT_DISABLED", () => {
    const registration = registrationWithDestinations(
      [PUBLISHED_DESTINATION, PARSER_INVALID_DESTINATION],
      "disabled",
    );
    assert.equal(validateRegistration(registration), true);
    assertRegistrationTrustRejected(registration, "CLIENT_DISABLED", "disabled");
    const replayed = redemptionOf({ registration, record: { consumed: true } });
    assertClosedRejection(replayed, "CLIENT_DISABLED", "disabled consumed record");
  });

  await t.test("revoked malformed registration preserves CLIENT_REVOKED", () => {
    const registration = registrationWithDestinations(
      [PUBLISHED_DESTINATION, PARSER_INVALID_DESTINATION],
      "revoked",
    );
    assert.equal(validateRegistration(registration), true);
    assertRegistrationTrustRejected(registration, "CLIENT_REVOKED", "revoked");
    const replayed = redemptionOf({ registration, record: { consumed: true } });
    assertClosedRejection(replayed, "CLIENT_REVOKED", "revoked consumed record");
  });

  await t.test("historical negative destinations fail closed", () => {
    const negatives = [
      "https://0x7f.0.0.1/callback",
      "https://0xdead.example/callback",
      "https://receiver.example./callback",
      "https://user:pw@receiver.example/callback",
      "https://receiver.example/callback?x=1",
      "https://receiver.example/callback#fragment",
      "https://*.receiver.example/callback",
      "https://receiver.example/callback ",
      "https://receiver.example/callback\u0000",
      "https://receiver.example/a\\b",
      "https://receiver.example:/callback",
      "https://receiver.example:65536/callback",
    ];
    for (const uri of negatives) {
      assert.equal(destinationUriValid(uri), false, uri);
      const registration = registrationWithDestinations([PUBLISHED_DESTINATION, uri]);
      assert.equal(validateRegistration(registration), false, uri);
      assertRegistrationTrustRejected(registration, "UNKNOWN_CLIENT", uri);
    }
  });

  await t.test("in-place addition of an unused invalid URI rejects the same registration", () => {
    const registration = publishedRegistration();
    const record = codeRecordFor(publishedRedemptionRequest());
    assert.equal(validateRegistration(registration), true);
    assert.equal(registrationPermitsRedirect(registration, registration.client_ref, PUBLISHED_DESTINATION), true);
    assert.equal(redemptionResponseMatchesContext(response, context, registration), true);
    const accepted = redemptionOf({ registration, codeRecord: record });
    assert.equal(accepted.failure, null);
    assert.equal(accepted.codeConsumed, true);
    assert.equal(record.consumed, false);
    registration.destination_uris.push(PARSER_INVALID_DESTINATION);
    const registrationBefore = structuredClone(registration);
    const rejectedRecord = codeRecordFor(publishedRedemptionRequest());
    const rejectedRecordBefore = structuredClone(rejectedRecord);
    assert.equal(validateRegistration(registration), true);
    assert.equal(destinationUriValid(registration.destination_uris[0]), true);
    assert.equal(destinationUriValid(registration.destination_uris[1]), false);
    assert.equal(publishedSignatureHolds(response, registration), true);
    assert.equal(
      registrationPermitsRedirect(registration, registration.client_ref, PUBLISHED_DESTINATION),
      false,
    );
    assert.equal(redemptionResponseMatchesContext(response, context, registration), false);
    const rejected = redemptionOf({ registration, codeRecord: rejectedRecord });
    assertClosedRejection(rejected, "UNKNOWN_CLIENT", "mutated registration");
    assert.deepEqual(registration, registrationBefore);
    assert.deepEqual(registration.destination_uris, [PUBLISHED_DESTINATION, PARSER_INVALID_DESTINATION]);
    assert.deepEqual(rejectedRecord, rejectedRecordBefore);
    assert.equal(rejectedRecord.consumed, false);
  });
});

function assessPublishedAuthorization(overrides = {}) {
  const request = overrides.request ?? loadJson(AUTHZ_REQUEST_EXAMPLE);
  const initiation = overrides.initiation ?? loadJson(INITIATION_EXAMPLE);
  const registration = Object.hasOwn(overrides, "registration") ? overrides.registration : publishedRegistration();
  const stored = loadJson(AUTHZ_REQUEST_EXAMPLE);
  return assessAuthorizationRequest({
    request,
    schemaValidRequest: Object.hasOwn(overrides, "schemaValidRequest")
      ? overrides.schemaValidRequest
      : validatorFor(AUTHZ_REQUEST_SCHEMA)(request),
    initiation,
    registration,
    expectedState: Object.hasOwn(overrides, "expectedState") ? overrides.expectedState : stored.state,
    expectedCodeChallenge: Object.hasOwn(overrides, "expectedCodeChallenge")
      ? overrides.expectedCodeChallenge
      : stored.code_challenge,
    issuerUnavailable: overrides.issuerUnavailable ?? false,
    dependencyAvailable: overrides.dependencyAvailable ?? true,
  });
}

function rsaMaterial(bits, alg = "RS256", kid = `rsa-${alg}-${bits}`) {
  const pair = generateKeyPairSync("rsa", { modulusLength: bits });
  return { ...pair, jwk: publicJwk(pair.publicKey, kid, alg) };
}

function rsaSignatureHolds(assertion, jwk) {
  const [header, payload, signature] = assertion.split(".");
  const nodeAlg = jwk.alg === "RS384" ? "RSA-SHA384" : jwk.alg === "RS512" ? "RSA-SHA512" : "RSA-SHA256";
  const key = createPublicKey({ key: jwk, format: "jwk" });
  return verify(nodeAlg, Buffer.from(`${header}.${payload}`), key, Buffer.from(signature, "base64url"));
}

function signedContextResponse(jwk, privateKey, alg) {
  const response = loadJson(REDEMPTION_RESPONSE_EXAMPLE);
  const context = loadJson(CONTEXT_EXAMPLE);
  response.assertion = signedAssertion({ alg, kid: jwk.kid }, context, privateKey);
  return { response, context };
}

function assertWeakRegistrationRejected(registration, label) {
  const record = codeRecordFor(publishedRedemptionRequest());
  const recordBefore = structuredClone(record);
  const registrationBefore = structuredClone(registration);
  assert.equal(
    registrationPermitsRedirect(registration, registration.client_ref, registration.destination_uris[0]),
    false,
    label,
  );
  assert.equal(
    redemptionResponseMatchesContext(
      loadJson(REDEMPTION_RESPONSE_EXAMPLE),
      loadJson(CONTEXT_EXAMPLE),
      registration,
    ),
    false,
    label,
  );
  const redeemed = redemptionOf({ registration, codeRecord: record });
  assertClosedRejection(redeemed, "UNKNOWN_CLIENT", label);
  assert.deepEqual(record, recordBefore, label);
  assert.equal(record.consumed, false, label);
  const authorized = assessPublishedAuthorization({ registration });
  assert.equal(authorized.authorizationAccepted, false, label);
  assert.equal(authorized.codeIssued, false, label);
  assert.equal(authorized.code, "UNKNOWN_CLIENT", label);
  assertNoSession(authorized);
  assert.deepEqual(registration, registrationBefore, label);
}

test("source-session-handoff rejects RSA moduli below 2048 bits", async (t) => {
  const validateRegistration = validatorFor(REGISTRATION_SCHEMA);

  await t.test("2048, 3072, and 4096 bit RSA keys and EC and EdDSA keys still verify", () => {
    for (const bits of [2048, 3072, 4096]) {
      const key = rsaMaterial(bits);
      const modulus = Buffer.from(key.jwk.n, "base64url");
      assert.equal(modulus.length * 8, bits, `${bits} byte length`);
      assert.ok(modulus[0] >= 0x80, `${bits} top bit`);
      const registration = registrationWithKeys([key.jwk], ["RS256"]);
      assert.equal(validateRegistration(registration), true, `${bits} schema`);
      const { response, context } = signedContextResponse(key.jwk, key.privateKey, "RS256");
      assert.equal(rsaSignatureHolds(response.assertion, key.jwk), true, `${bits} node verify`);
      assert.equal(redemptionResponseMatchesContext(response, context, registration), true, bits);
      assert.equal(
        registrationPermitsRedirect(registration, registration.client_ref, registration.destination_uris[0]),
        true,
        bits,
      );
      const redeemed = redemptionOf({ registration });
      assert.equal(redeemed.failure, null, bits);
      assert.equal(redeemed.codeConsumed, true, bits);
      const authorized = assessPublishedAuthorization({ registration });
      assert.equal(authorized.authorizationAccepted, true, bits);
      assert.equal(authorized.codeIssued, false, bits);
      assertNoSession(authorized);
    }
    for (const alg of ["RS384", "RS512"]) {
      const key = rsaMaterial(2048, alg, `rsa-${alg}-2048`);
      const registration = registrationWithKeys([key.jwk], [alg]);
      const { response, context } = signedContextResponse(key.jwk, key.privateKey, alg);
      assert.equal(rsaSignatureHolds(response.assertion, key.jwk), true, alg);
      assert.equal(redemptionResponseMatchesContext(response, context, registration), true, alg);
    }
    const context = loadJson(CONTEXT_EXAMPLE);
    const response = loadJson(REDEMPTION_RESPONSE_EXAMPLE);
    const ed = generateKeyPairSync("ed25519");
    const edJwk = publicJwk(ed.publicKey, "ed-keep-001", "EdDSA");
    const edRegistration = registrationWithKeys([edJwk], ["EdDSA"]);
    const edAssertion = signedAssertion({ alg: "EdDSA", kid: edJwk.kid }, context, ed.privateKey);
    assert.equal(
      redemptionResponseMatchesContext({ ...response, assertion: edAssertion }, context, edRegistration),
      true,
    );
    const ec = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    const ecJwk = publicJwk(ec.publicKey, "ec-keep-001", "ES256");
    const ecRegistration = registrationWithKeys([ecJwk], ["ES256"]);
    const ecAssertion = signedAssertion({ alg: "ES256", kid: ecJwk.kid }, context, ec.privateKey);
    assert.equal(
      redemptionResponseMatchesContext({ ...response, assertion: ecAssertion }, context, ecRegistration),
      true,
    );
  });

  await t.test("512, 1024, and 2047 bit RSA keys are rejected before trust or consumption", () => {
    for (const bits of [512, 1024, 2047]) {
      const key = rsaMaterial(bits, "RS256", `rsa-short-${bits}`);
      const modulus = Buffer.from(key.jwk.n, "base64url");
      if (bits === 2047) {
        assert.equal(modulus.length, 256);
        assert.ok(modulus[0] < 0x80);
      } else {
        assert.equal(modulus.length * 8, bits);
        assert.ok(modulus[0] >= 0x80);
      }
      const registration = registrationWithKeys([key.jwk], ["RS256"]);
      assert.equal(validateRegistration(registration), true, `${bits} schema`);
      const { response, context } = signedContextResponse(key.jwk, key.privateKey, "RS256");
      assert.equal(rsaSignatureHolds(response.assertion, key.jwk), true, `${bits} node would verify`);
      assert.equal(redemptionResponseMatchesContext(response, context, registration), false, bits);
      assertWeakRegistrationRejected(registration, `${bits} registration`);
    }
  });

  await t.test("a leading-zero padded short modulus is not a 2048 bit key", () => {
    const key = rsaMaterial(1024, "RS256", "rsa-padded-1024");
    const raw = Buffer.from(key.jwk.n, "base64url");
    const padded = Buffer.concat([Buffer.alloc(256 - raw.length), raw]);
    assert.equal(padded.length * 8, 2048);
    assert.equal(padded[0], 0);
    const disguised = structuredClone(key.jwk);
    disguised.n = padded.toString("base64url");
    const registration = registrationWithKeys([disguised], ["RS256"]);
    assert.equal(validateRegistration(registration), true);
    assertWeakRegistrationRejected(registration, "padded modulus");
  });

  await t.test("an unused weak RSA key rejects the whole registration", () => {
    const strong = rsaMaterial(2048, "RS256", "rsa-strong-2048");
    const weak = rsaMaterial(512, "RS256", "rsa-unused-512");
    const registration = registrationWithKeys([strong.jwk, weak.jwk], ["RS256"]);
    assert.equal(validateRegistration(registration), true);
    const { response, context } = signedContextResponse(strong.jwk, strong.privateKey, "RS256");
    assert.equal(rsaSignatureHolds(response.assertion, strong.jwk), true);
    assert.equal(redemptionResponseMatchesContext(response, context, registration), false);
    assertWeakRegistrationRejected(registration, "unused weak key");
  });

  await t.test("non-canonical modulus, weak exponent, ambiguous kid, and tampered alg fail closed", () => {
    const strong = rsaMaterial(2048, "RS256", "rsa-canonical-2048");
    const alias = unusedBitAlias(strong.jwk.n);
    assert.notEqual(alias, null);
    assert.equal(Buffer.from(alias, "base64url").equals(Buffer.from(strong.jwk.n, "base64url")), true);
    const nonCanonical = structuredClone(strong.jwk);
    nonCanonical.n = alias;
    const nonCanonicalRegistration = registrationWithKeys([nonCanonical], ["RS256"]);
    assert.equal(validateRegistration(nonCanonicalRegistration), true);
    assertWeakRegistrationRejected(nonCanonicalRegistration, "non-canonical modulus");
    for (const exponent of ["AQ", "Ag"]) {
      const weakExponent = structuredClone(strong.jwk);
      weakExponent.kid = `rsa-exponent-${exponent}`;
      weakExponent.e = exponent;
      const registration = registrationWithKeys([weakExponent], ["RS256"]);
      assert.equal(validateRegistration(registration), true, exponent);
      assertWeakRegistrationRejected(registration, `exponent ${exponent}`);
    }
    const other = rsaMaterial(2048, "RS256", "rsa-canonical-2048");
    const ambiguous = registrationWithKeys([strong.jwk, other.jwk], ["RS256"]);
    const signed = signedContextResponse(strong.jwk, strong.privateKey, "RS256");
    assert.equal(rsaSignatureHolds(signed.response.assertion, strong.jwk), true);
    assert.equal(redemptionResponseMatchesContext(signed.response, signed.context, ambiguous), false);
    const tampered = signedContextResponse(strong.jwk, strong.privateKey, "RS256");
    tampered.response.assertion = signedAssertion(
      { alg: "RS384", kid: strong.jwk.kid },
      tampered.context,
      strong.privateKey,
    );
    assert.equal(
      redemptionResponseMatchesContext(tampered.response, tampered.context, registrationWithKeys([strong.jwk], ["RS256"])),
      false,
    );
  });

  await t.test("disabled and revoked weak keys keep status precedence", () => {
    for (const [status, code] of [["disabled", "CLIENT_DISABLED"], ["revoked", "CLIENT_REVOKED"]]) {
      const key = rsaMaterial(512, "RS256", `rsa-${status}`);
      const registration = registrationWithKeys([key.jwk], ["RS256"]);
      registration.status = status;
      const redeemed = redemptionOf({ registration });
      assertClosedRejection(redeemed, code, status);
      const authorized = assessPublishedAuthorization({ registration });
      assert.equal(authorized.code, code, status);
      assert.equal(authorized.authorizationAccepted, false, status);
      assert.equal(authorized.codeIssued, false, status);
      assertNoSession(authorized);
    }
  });
});

test("source-session-handoff binds authorization purpose before issuing a code", async (t) => {
  const validateRequest = validatorFor(AUTHZ_REQUEST_SCHEMA);

  function deny(overrides, code, label) {
    const result = assessPublishedAuthorization(overrides);
    assert.equal(result.authorizationAccepted, false, label);
    assert.equal(result.codeIssued, false, label);
    assert.equal(result.code, code, label);
    assert.equal(result.contextAccepted, false, label);
    assertNoSession(result);
    return result;
  }

  await t.test("the published authorization request is accepted and does not issue a code", () => {
    const result = assessPublishedAuthorization();
    assert.equal(result.failure, null);
    assert.equal(result.authorizationAccepted, true);
    assert.equal(result.codeIssued, false);
    assert.equal(result.contextAccepted, false);
    assertNoSession(result);
  });

  await t.test("request purpose mismatch is denied while the destination stays valid", () => {
    const request = loadJson(AUTHZ_REQUEST_EXAMPLE);
    request.purpose = "other-purpose";
    assert.equal(validateRequest(request), true);
    assert.equal(destinationUriValid(request.destination_uri), true);
    assert.equal(authorizationRequestDestinationAccepted(request), true);
    deny({ request }, "PURPOSE_MISMATCH", "request purpose");
  });

  await t.test("registration purpose mismatch is denied independently", () => {
    const registration = publishedRegistration();
    registration.purpose = "other-purpose";
    deny({ registration }, "PURPOSE_MISMATCH", "registration purpose");
  });

  await t.test("initiation purpose mismatch is denied independently", () => {
    const initiation = loadJson(INITIATION_EXAMPLE);
    initiation.purpose = "other-purpose";
    deny({ initiation }, "PURPOSE_MISMATCH", "initiation purpose");
  });

  await t.test("handoff transaction client receiver destination state and pkce mismatches are denied", () => {
    const request = loadJson(AUTHZ_REQUEST_EXAMPLE);
    const cases = [
      ["handoff_ref", "handoff-placeholder-002", "HANDOFF_MISMATCH"],
      ["transaction_ref", "transaction-placeholder-002", "TRANSACTION_MISMATCH"],
      ["correlation_ref", "correlation-placeholder-002", "CORRELATION_MISMATCH"],
      ["client_ref", "client-placeholder-002", "UNKNOWN_CLIENT"],
      ["receiver_ref", "receiver-placeholder-002", "UNKNOWN_CLIENT"],
      ["destination_uri", "https://receiver.example/a//callback", "DESTINATION_MISMATCH"],
      ["state", "b".repeat(22), "MALFORMED_REQUEST"],
      ["code_challenge", pkceChallengeFor("a".repeat(43)), "MALFORMED_REQUEST"],
      ["code_challenge_method", "plain", "INVALID_PKCE_METHOD"],
    ];
    for (const [field, value, code] of cases) {
      const candidate = structuredClone(request);
      candidate[field] = value;
      deny({ request: candidate }, code, field);
    }
    const initiation = loadJson(INITIATION_EXAMPLE);
    initiation.issuer = "issuer-placeholder-002";
    deny({ initiation }, "UNKNOWN_CLIENT", "issuer");
    const omitted = assessAuthorizationRequest({
      request,
      initiation: loadJson(INITIATION_EXAMPLE),
      registration: publishedRegistration(),
      expectedState: request.state,
      expectedCodeChallenge: request.code_challenge,
    });
    assert.equal(omitted.code, "MALFORMED_REQUEST");
    assert.equal(omitted.codeIssued, false);
  });
});

test("source-session-handoff authorization rejects an invalid complete stored initiation", async (t) => {
  const cases = [
    ["zero lifetime", { expires_at: "2026-08-15T00:00:00Z" }],
    ["inverted lifetime", { expires_at: "2026-08-14T23:59:59Z" }],
    ["overlong lifetime", { expires_at: "2026-08-15T00:01:01Z" }],
    ["fractional excess", { expires_at: "2026-08-15T00:01:00.0000000001Z" }],
    ["impossible calendar date", { initiated_at: "2026-02-30T00:00:00Z" }],
    ["empty scopes", { requested_record_scope_refs: [] }],
    ["duplicate scopes", { requested_record_scope_refs: ["scope-a", "scope-a"] }],
    ["unsorted scopes", { requested_record_scope_refs: ["scope-b", "scope-a"] }],
    ["ambiguous scopes", { requested_record_scope_refs: ["scope-a", "scope-ab"] }],
    ["wildcard scopes", { requested_record_scope_refs: ["scope-*"] }],
    ["non-string scopes", { requested_record_scope_refs: [1] }],
    ["empty string scopes", { requested_record_scope_refs: [""] }],
    ["whitespace scopes", { requested_record_scope_refs: ["scope a"] }],
    ["non-array scopes", { requested_record_scope_refs: "scope-a" }],
    ["unknown field", { extension_field: "not-admitted" }],
    ["unsupported family", { contract_family: "other" }],
    ["unsupported version", { contract_version: "v99" }],
    ["unsupported profile", { profile: "other" }],
  ];
  for (const [name, change] of cases) {
    await t.test(name, () => {
      const initiation = { ...loadJson(INITIATION_EXAMPLE), ...change };
      const before = structuredClone(initiation);
      const result = assessPublishedAuthorization({ initiation });
      assert.equal(result.code, "MALFORMED_REQUEST", name);
      assert.equal(result.authorizationAccepted, false, name);
      assert.equal(result.codeIssued, false, name);
      assert.equal(result.contextAccepted, false, name);
      assertNoSession(result);
      assert.deepEqual(initiation, before, name);
    });
  }
  await t.test("every missing required initiation field fails closed", () => {
    for (const field of loadJson(INITIATION_SCHEMA).required) {
      const initiation = loadJson(INITIATION_EXAMPLE);
      delete initiation[field];
      const result = assessPublishedAuthorization({ initiation });
      assert.equal(result.code, "MALFORMED_REQUEST", field);
      assert.equal(result.authorizationAccepted, false, field);
      assert.equal(result.codeIssued, false, field);
      assertNoSession(result);
    }
  });
  await t.test("valid exact and fractional windows and sorted scopes remain accepted", () => {
    for (const expires_at of ["2026-08-15T00:00:00.0000000001Z", "2026-08-15T00:01:00Z"]) {
      const initiation = loadJson(INITIATION_EXAMPLE);
      initiation.expires_at = expires_at;
      initiation.requested_record_scope_refs = ["scope-a", "scope-b"];
      const result = assessPublishedAuthorization({ initiation });
      assert.equal(result.authorizationAccepted, true);
      assert.equal(result.codeIssued, false);
      assertNoSession(result);
    }
  });
  await t.test("historical semantic-invalid initiation fixtures deny authorization", () => {
    for (const item of manifest.source_session_handoff_v1_semantic.filter((item) => item.schema === INITIATION_SCHEMA)) {
      const result = assessPublishedAuthorization({ initiation: loadJson(item.fixture) });
      assert.equal(result.authorizationAccepted, false, item.fixture);
      assert.equal(result.code, "MALFORMED_REQUEST", item.fixture);
      assert.equal(result.codeIssued, false);
      assertNoSession(result);
    }
  });
});

test("source-session-handoff validates all EC and OKP public key material", async (t) => {
  const validateRegistration = validatorFor(REGISTRATION_SCHEMA);
  const materials = [
    ["P-256", "ES256", "prime256v1", 32],
    ["P-384", "ES384", "secp384r1", 48],
    ["P-521", "ES512", "secp521r1", 66],
    ["Ed25519", "EdDSA", null, 32],
  ];
  for (const [curve, alg, namedCurve, length] of materials) {
    const pair = namedCurve === null ? generateKeyPairSync("ed25519") : generateKeyPairSync("ec", { namedCurve });
    const jwk = publicJwk(pair.publicKey, `valid-${curve}`, alg);
    await t.test(`${curve} genuine generated key accepts on every trust path`, () => {
      const registration = registrationWithKeys([jwk], [alg]);
      const { response, context } = signedContextResponse(jwk, pair.privateKey, alg);
      assert.equal(validateRegistration(registration), true);
      assert.equal(redemptionResponseMatchesContext(response, context, registration), true);
      assert.equal(registrationPermitsRedirect(registration, registration.client_ref, registration.destination_uris[0]), true);
      assert.equal(assessPublishedAuthorization({ registration }).authorizationAccepted, true);
      const redeemed = redemptionOf({ registration });
      assert.equal(redeemed.codeConsumed, true);
      assertNoSession(redeemed);
    });
    const fields = namedCurve === null ? ["x"] : ["x", "y"];
    for (const field of fields) {
      for (const size of [1, length - 1, length + 1]) {
        await t.test(`${curve} ${field} length ${size} rejects used and unused keys`, () => {
          const invalid = { ...jwk, [field]: Buffer.alloc(size, 1).toString("base64url") };
          const only = registrationWithKeys([invalid], [alg]);
          assert.equal(validateRegistration(only), true);
          assertWeakRegistrationRejected(only, `${curve} ${field} ${size}`);
          const original = publishedRegistration();
          const mixed = registrationWithKeys([...original.jwks.keys, invalid], [...new Set([...original.algorithms, alg])]);
          assert.equal(validateRegistration(mixed), true);
          assertWeakRegistrationRejected(mixed, `unused ${curve} ${field} ${size}`);
        });
      }
    }
    await t.test(`${curve} malformed full-length curve material rejects the registration`, () => {
      const invalid = { ...jwk, x: Buffer.alloc(length, 0xff).toString("base64url") };
      if (namedCurve !== null) invalid.y = Buffer.alloc(length).toString("base64url");
      const original = publishedRegistration();
      const registration = registrationWithKeys([...original.jwks.keys, invalid], [...new Set([...original.algorithms, alg])]);
      assert.equal(validateRegistration(registration), true);
      assertWeakRegistrationRejected(registration, `${curve} curve material`);
    });
    await t.test(`${curve} algorithm/curve mismatch fails closed`, () => {
      const invalid = { ...jwk, alg: alg === "ES256" ? "ES384" : "ES256" };
      assertWeakRegistrationRejected(registrationWithKeys([invalid], [invalid.alg]), `${curve} mismatched algorithm`);
    });
    if (length % 3 !== 0) {
      await t.test(`${curve} noncanonical coordinate pad bits reject unused keys`, () => {
        const alias = unusedBitAlias(jwk.x);
        assert.notEqual(alias, null);
        const invalid = { ...jwk, x: alias };
        const original = publishedRegistration();
        const registration = registrationWithKeys([...original.jwks.keys, invalid], [...new Set([...original.algorithms, alg])]);
        assert.equal(validateRegistration(registration), true);
        assertWeakRegistrationRejected(registration, `${curve} pad bits`);
      });
    }
  }
  await t.test("Ed25519 import alone does not establish a valid curve point", () => {
    const original = publishedRegistration();
    // y=2 has no recovered x; y=1 with sign=1 is noncanonical; zero and
    // identity are small-order points; y=p is outside the field.
    const fieldPrime = Buffer.from(`ed${"ff".repeat(30)}7f`, "hex");
    const badPoints = [Buffer.alloc(32), Buffer.from(`01${"00".repeat(31)}`, "hex"),
      Buffer.from(`02${"00".repeat(31)}`, "hex"), Buffer.from(`01${"00".repeat(30)}80`, "hex"), fieldPrime];
    for (const bytes of badPoints) {
      const invalid = { ...original.jwks.keys[0], kid: "bad-ed-point", x: bytes.toString("base64url") };
      assert.doesNotThrow(() => createPublicKey({ key: invalid, format: "jwk" }));
      const registration = registrationWithKeys([...original.jwks.keys, invalid], original.algorithms);
      assert.equal(validateRegistration(registration), true);
      assertWeakRegistrationRejected(registration, `Ed25519 ${bytes.toString("hex")}`);
    }
  });
});

test("source-session-handoff RSA unsigned integers must be minimally encoded", async (t) => {
  const key = rsaMaterial(2048, "RS256", "rsa-minimal-2048");
  const { response, context } = signedContextResponse(key.jwk, key.privateKey, "RS256");
  const valid = registrationWithKeys([key.jwk], ["RS256"]);
  assert.equal(redemptionResponseMatchesContext(response, context, valid), true);
  for (const field of ["n", "e"]) {
    for (const zeroBytes of [1, 2]) {
      await t.test(`${field} with ${zeroBytes} leading zero octets rejects used and unused keys`, () => {
        const padded = { ...key.jwk, [field]: Buffer.concat([Buffer.alloc(zeroBytes), Buffer.from(key.jwk[field], "base64url")]).toString("base64url") };
        assert.equal(Buffer.from(padded[field], "base64url").toString("base64url"), padded[field]);
        assert.equal(rsaSignatureHolds(response.assertion, padded), true, "Node accepts the alias");
        const only = registrationWithKeys([padded], ["RS256"]);
        assert.equal(validatorFor(REGISTRATION_SCHEMA)(only), true);
        assert.equal(redemptionResponseMatchesContext(response, context, only), false);
        assertWeakRegistrationRejected(only, `${field} padded used key`);
        const original = publishedRegistration();
        const mixed = registrationWithKeys([...original.jwks.keys, padded], [...original.algorithms, "RS256"]);
        assertWeakRegistrationRejected(mixed, `${field} padded unused key`);
      });
    }
  }
});
