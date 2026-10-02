import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import Ajv2020 from "ajv/dist/2020.js";

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
const CONTEXT_SCHEMA = "contracts/source-session-handoff/v1.0/authenticated-context.schema.json";
const FAILURE_SCHEMA = "contracts/source-session-handoff/v1.0/failure.schema.json";
const INITIATION_EXAMPLE = "contracts/source-session-handoff/v1.0/initiation.example.json";
const CONTEXT_EXAMPLE = "contracts/source-session-handoff/v1.0/authenticated-context.example.json";
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
  if (name.startsWith("authenticated-context.")) {
    return CONTEXT_SCHEMA;
  }
  if (name.startsWith("failure.")) {
    return FAILURE_SCHEMA;
  }
  throw new Error(`no schema for ${relPath}`);
}

function retryableFor(outcome) {
  switch (outcome) {
    case "malformed":
    case "unverified":
    case "expired":
    case "replayed":
    case "identity_not_bound":
    case "scope_invalid":
    case "permission_denied":
    case "unsupported_version":
      return false;
    case "dependency_unavailable":
      return true;
    default: {
      const unknown = outcome;
      throw new Error(`unsupported outcome ${unknown}`);
    }
  }
}

function closedResult(failure) {
  return {
    failure,
    retryable: failure === null ? false : retryableFor(failure),
    contextAccepted: false,
    grantsReceiverAccess: false,
    mintsReceiverSession: false,
    mintsAdditionalReceiverSession: false,
    synthesizedUnscopedRedirect: false,
    synthesizedEmptyContext: false,
    reconciled: false,
  };
}

function acceptedResult() {
  return {
    failure: null,
    retryable: false,
    contextAccepted: true,
    grantsReceiverAccess: false,
    mintsReceiverSession: false,
    mintsAdditionalReceiverSession: false,
    synthesizedUnscopedRedirect: false,
    synthesizedEmptyContext: false,
    reconciled: false,
  };
}

const UTC_TIMESTAMP_PATTERN =
  /^(\d{4})-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])T([01]\d|2[0-3]):([0-5]\d):([0-5]\d)(\.\d+)?Z$/;

function isLeapYear(year) {
  return year % 400 === 0 || (year % 4 === 0 && year % 100 !== 0);
}

function monthLength(year, month) {
  if (month === 2) {
    return isLeapYear(year) ? 29 : 28;
  }
  if (month === 4 || month === 6 || month === 9 || month === 11) {
    return 30;
  }
  return 31;
}

function parseUtc(ts) {
  if (typeof ts !== "string") {
    return null;
  }
  const match = UTC_TIMESTAMP_PATTERN.exec(ts);
  if (!match) {
    return null;
  }
  const year = match[1];
  const month = match[2];
  const day = match[3];
  const hour = match[4];
  const minute = match[5];
  const second = match[6];
  const fraction = match[7] === undefined ? "" : match[7].slice(1);
  const yearNum = Number(year);
  const monthNum = Number(month);
  const dayNum = Number(day);
  if (dayNum > monthLength(yearNum, monthNum)) {
    return null;
  }
  return { year, month, day, hour, minute, second, fraction };
}

function instantParts(ts) {
  const parsed = parseUtc(ts);
  if (parsed === null) {
    return null;
  }
  const ms = Date.UTC(
    Number(parsed.year),
    Number(parsed.month) - 1,
    Number(parsed.day),
    Number(parsed.hour),
    Number(parsed.minute),
    Number(parsed.second),
  );
  if (!Number.isFinite(ms)) {
    return null;
  }
  return {
    seconds: BigInt(ms) / 1000n,
    fraction: parsed.fraction,
  };
}

function compareInstants(leftTs, rightTs) {
  const left = instantParts(leftTs);
  const right = instantParts(rightTs);
  if (left === null || right === null) {
    return null;
  }
  if (left.seconds < right.seconds) {
    return -1;
  }
  if (left.seconds > right.seconds) {
    return 1;
  }
  const width = Math.max(left.fraction.length, right.fraction.length);
  const leftFrac = left.fraction.padEnd(width, "0");
  const rightFrac = right.fraction.padEnd(width, "0");
  if (leftFrac < rightFrac) {
    return -1;
  }
  if (leftFrac > rightFrac) {
    return 1;
  }
  return 0;
}

function durationWithin(start, end, maxSeconds) {
  const left = instantParts(start);
  const right = instantParts(end);
  if (left === null || right === null) {
    return false;
  }
  let whole = right.seconds - left.seconds;
  const width = Math.max(left.fraction.length, right.fraction.length);
  let frac = 0n;
  if (width > 0) {
    const scale = 10n ** BigInt(width);
    const leftFrac = BigInt(left.fraction.padEnd(width, "0"));
    const rightFrac = BigInt(right.fraction.padEnd(width, "0"));
    frac = rightFrac - leftFrac;
    if (frac < 0n) {
      whole -= 1n;
      frac += scale;
    }
  }
  if (whole < 0n || (whole === 0n && frac === 0n)) {
    return false;
  }
  if (whole > maxSeconds) {
    return false;
  }
  if (whole === maxSeconds && frac > 0n) {
    return false;
  }
  return true;
}

function constantsUnsupported(obj) {
  if (obj === null || typeof obj !== "object" || Array.isArray(obj)) {
    return true;
  }
  return obj.contract_family !== FAMILY || obj.contract_version !== VERSION || obj.profile !== PROFILE;
}

function sortedAscending(arr) {
  const sorted = [...arr].sort();
  return arr.every((item, index) => item === sorted[index]);
}

function ambiguousPrefix(arr) {
  const sorted = [...arr].sort();
  for (let i = 0; i < sorted.length; i += 1) {
    for (let j = i + 1; j < sorted.length; j += 1) {
      if (sorted[j].startsWith(sorted[i])) {
        return true;
      }
    }
  }
  return false;
}

function scopeArrayInvalid(arr) {
  if (!Array.isArray(arr)) {
    return false;
  }
  if (arr.length === 0) {
    return true;
  }
  if (new Set(arr).size !== arr.length) {
    return true;
  }
  if (arr.some((item) => typeof item !== "string" || item.length === 0 || item.includes("*") || /\s/.test(item))) {
    return true;
  }
  if (!sortedAscending(arr)) {
    return true;
  }
  return ambiguousPrefix(arr);
}

function isSubset(inner, outer) {
  const allowed = new Set(outer);
  return inner.every((item) => allowed.has(item));
}

function scopeProblem(initiation, context) {
  const requested = initiation?.requested_record_scope_refs;
  const actual = context?.record_scope_refs;
  const permissions = context?.source_permission_refs;
  if (scopeArrayInvalid(requested) || scopeArrayInvalid(actual) || scopeArrayInvalid(permissions)) {
    return true;
  }
  if (Array.isArray(requested) && Array.isArray(actual) && !isSubset(actual, requested)) {
    return true;
  }
  return false;
}

function sameArray(left, right) {
  return Array.isArray(left)
    && Array.isArray(right)
    && left.length === right.length
    && left.every((item, index) => item === right[index]);
}

function bindingMismatch(initiation, context) {
  return context.issuer !== initiation.issuer
    || context.audience !== initiation.receiver_ref
    || context.receiver_ref !== initiation.receiver_ref
    || context.client_ref !== initiation.client_ref
    || context.destination_uri !== initiation.destination_uri
    || context.handoff_ref !== initiation.handoff_ref
    || context.transaction_ref !== initiation.transaction_ref
    || context.correlation_ref !== initiation.correlation_ref;
}

function issuedInsideCodeWindow(initiation, context) {
  const afterStart = compareInstants(initiation.initiated_at, context.issued_at);
  const beforeEnd = compareInstants(context.issued_at, initiation.expires_at);
  return afterStart !== null && beforeEnd !== null && afterStart <= 0 && beforeEnd <= 0;
}

function lifetimeFailure(initiation, context, at) {
  if (!durationWithin(initiation.initiated_at, initiation.expires_at, CODE_WINDOW_SECONDS)) {
    return "expired";
  }
  if (!durationWithin(context.issued_at, context.expires_at, CONTEXT_WINDOW_SECONDS)) {
    return "expired";
  }
  if (!issuedInsideCodeWindow(initiation, context)) {
    return "expired";
  }
  const afterIssued = compareInstants(context.issued_at, at);
  const beforeExpiry = compareInstants(at, context.expires_at);
  if (afterIssued === null || beforeExpiry === null) {
    return "unverified";
  }
  if (afterIssued > 0) {
    return "unverified";
  }
  if (beforeExpiry >= 0) {
    return "expired";
  }
  return null;
}

function identityMatches(context, attested) {
  if (attested === null || typeof attested !== "object") {
    return false;
  }
  if (context.source_session_ref === context.source_context_ref) {
    return false;
  }
  return context.subject_ref === attested.subject_ref
    && context.organisation_ref === attested.organisation_ref
    && context.account_ref === attested.account_ref
    && context.source_role_ref === attested.source_role_ref
    && context.source_session_ref === attested.source_session_ref
    && context.source_context_ref === attested.source_context_ref
    && sameArray(context.source_permission_refs, attested.source_permission_refs)
    && sameArray(context.record_scope_refs, attested.record_scope_refs);
}

function sameCompleteAuthenticatedContext(context, redeemed) {
  if (
    context === null
    || redeemed === null
    || typeof context !== "object"
    || typeof redeemed !== "object"
    || Array.isArray(context)
    || Array.isArray(redeemed)
  ) {
    return false;
  }
  const fields = loadJson(CONTEXT_SCHEMA).required;
  if (Object.keys(context).length !== fields.length || Object.keys(redeemed).length !== fields.length) {
    return false;
  }
  for (const key of fields) {
    if (!Object.hasOwn(context, key) || !Object.hasOwn(redeemed, key)) {
      return false;
    }
    const left = context[key];
    const right = redeemed[key];
    if (Array.isArray(left) || Array.isArray(right)) {
      if (!sameArray(left, right)) {
        return false;
      }
    } else if (typeof left !== "string" || typeof right !== "string" || left !== right) {
      return false;
    }
  }
  return true;
}

function assessSourceSessionHandoff(input) {
  if (input.dependencyAvailable === false) {
    return closedResult("dependency_unavailable");
  }
  if (constantsUnsupported(input.initiation) || constantsUnsupported(input.context)) {
    return closedResult("unsupported_version");
  }
  if (scopeProblem(input.initiation, input.context)) {
    return closedResult("scope_invalid");
  }
  if (input.schemaValidInitiation === false || input.schemaValidContext === false) {
    return closedResult("malformed");
  }
  const reconciliationCandidate = input.uncertain === true
    && sameCompleteAuthenticatedContext(input.context, input.redeemedContext);
  if (input.codeConsumed === true && input.uncertain !== true) {
    return closedResult("replayed");
  }
  if (input.uncertain === true && !reconciliationCandidate) {
    return closedResult("replayed");
  }
  const lifetime = lifetimeFailure(input.initiation, input.context, input.at);
  if (lifetime !== null) {
    return closedResult(lifetime);
  }
  if (input.revoked === true || bindingMismatch(input.initiation, input.context)) {
    return closedResult("unverified");
  }
  if (input.presentation !== "server_redemption" || !identityMatches(input.context, input.attested)) {
    return closedResult("identity_not_bound");
  }
  if (input.requestReceiverAccess === true) {
    return closedResult("permission_denied");
  }
  const accepted = acceptedResult();
  if (reconciliationCandidate) {
    accepted.reconciled = true;
  }
  return accepted;
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
    [CONTEXT_SCHEMA, CONTEXT_EXAMPLE],
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
    [CONTEXT_SCHEMA, CONTEXT_EXAMPLE],
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
  for (const entry of matrix.outcomes) {
    assert.equal(entry.retryable, retryableFor(entry.outcome));
    assert.equal(semantics.includes(`\`${entry.outcome}\``), true, entry.outcome);
    const wire = {
      contract_family: FAMILY,
      contract_version: VERSION,
      profile: PROFILE,
      outcome: entry.outcome,
      retryable: entry.retryable,
      correlation_ref: "correlation-placeholder-001",
      occurred_at: "2026-08-15T00:00:10Z",
    };
    assert.equal(validate(wire), true, formatErrors(validate));
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
    const result = assessSourceSessionHandoff(presentationOf({ context }));
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
  for (const rel of [INITIATION_SCHEMA, CONTEXT_SCHEMA, FAILURE_SCHEMA]) {
    const schema = loadJson(rel);
    assert.equal(schema.additionalProperties, false, rel);
    assert.equal(schema.unevaluatedProperties, false, rel);
    assert.equal(schema.properties.contract_family.const, FAMILY);
    assert.equal(schema.properties.contract_version.const, VERSION);
    assert.equal(schema.properties.profile.const, PROFILE);
  }
});
