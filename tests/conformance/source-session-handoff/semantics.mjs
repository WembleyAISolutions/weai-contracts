import { createHash, createPublicKey, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "../../..");
const CONTEXT_SCHEMA = "contracts/source-session-handoff/v1.0/authenticated-context.schema.json";

const FAMILY = "source-session-handoff";
const VERSION = "v1.0";
const PROFILE = "oauth2-authorization-code-pkce-s256-v1";
const CODE_WINDOW_SECONDS = 60n;
const CONTEXT_WINDOW_SECONDS = 300n;

const UTC_TIMESTAMP_PATTERN =
  /^(\d{4})-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])T([01]\d|2[0-3]):([0-5]\d):([0-5]\d)(\.\d+)?Z$/;
const PKCE_VERIFIER_PATTERN = /^[A-Za-z0-9\-._~]{43,128}$/;
const PERMITTED_ALGS = ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "EdDSA"];
const SAFE_OAUTH_ERRORS = new Set([
  "invalid_request",
  "unauthorized_client",
  "access_denied",
  "unsupported_response_type",
  "server_error",
  "temporarily_unavailable",
]);
const BROWSER_PROHIBITED_FIELDS = [
  "subject_ref",
  "organisation_ref",
  "account_ref",
  "source_session_ref",
  "source_context_ref",
  "source_role_ref",
  "source_permission_refs",
  "record_scope_refs",
  "requested_record_scope_refs",
  "receiver_role",
  "membership",
  "grant",
  "permission",
  "code_verifier",
  "assertion",
  "access_token",
  "refresh_token",
  "id_token",
  "token",
];

function loadJson(relPath) {
  return JSON.parse(readFileSync(join(repoRoot, relPath), "utf8"));
}

const FAILURE_MATRIX = loadJson("vocab/source-session-handoff-failure-v1.0.json");

export function retryableFor(outcome) {
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

export function codeSpec(code) {
  const entry = FAILURE_MATRIX.codes.find((item) => item.code === code);
  return entry ?? null;
}

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

/**
 * Days since 1970-01-01 in the proleptic Gregorian calendar.
 * Year 0 is valid. This does not apply the 0–99 year offset.
 */
function daysFromCivil(year, month, day) {
  let y = year;
  if (month <= 2) {
    y -= 1;
  }
  const era = Math.floor(y / 400);
  const yoe = y - era * 400;
  const doy = Math.floor((153 * (month + (month > 2 ? -3 : 9)) + 2) / 5) + day - 1;
  const doe = yoe * 365 + Math.floor(yoe / 4) - Math.floor(yoe / 100) + doy;
  return era * 146097 + doe - 719468;
}

export function parseUtc(ts) {
  if (typeof ts !== "string") {
    return null;
  }
  const match = UTC_TIMESTAMP_PATTERN.exec(ts);
  if (!match) {
    return null;
  }
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  if (!Number.isInteger(year) || year < 0 || year > 9999) {
    return null;
  }
  if (day > monthLength(year, month)) {
    return null;
  }
  return {
    year,
    month,
    day,
    hour: Number(match[4]),
    minute: Number(match[5]),
    second: Number(match[6]),
    fraction: match[7] === undefined ? "" : match[7].slice(1),
  };
}

export function instantParts(ts) {
  const parsed = parseUtc(ts);
  if (parsed === null) {
    return null;
  }
  const days = daysFromCivil(parsed.year, parsed.month, parsed.day);
  const seconds = BigInt(days) * 86400n
    + BigInt(parsed.hour) * 3600n
    + BigInt(parsed.minute) * 60n
    + BigInt(parsed.second);
  return {
    seconds,
    fraction: parsed.fraction,
  };
}

function compareFractionDigits(left, right) {
  const shared = Math.min(left.length, right.length);
  for (let i = 0; i < shared; i += 1) {
    const leftDigit = left.charCodeAt(i);
    const rightDigit = right.charCodeAt(i);
    if (leftDigit < rightDigit) {
      return -1;
    }
    if (leftDigit > rightDigit) {
      return 1;
    }
  }
  const longer = left.length > right.length ? left : right;
  const sign = left.length === right.length ? 0 : (left.length > right.length ? 1 : -1);
  for (let i = shared; i < longer.length; i += 1) {
    if (longer.charCodeAt(i) !== 48) {
      return sign;
    }
  }
  return 0;
}

export function compareInstants(leftTs, rightTs) {
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
  return compareFractionDigits(left.fraction, right.fraction);
}

export function durationWithin(start, end, maxSeconds) {
  const left = instantParts(start);
  const right = instantParts(end);
  if (left === null || right === null) {
    return false;
  }
  let whole = right.seconds - left.seconds;
  const fractionOrder = compareFractionDigits(left.fraction, right.fraction);
  if (fractionOrder > 0) {
    whole -= 1n;
  }
  if (whole < 0n || (whole === 0n && fractionOrder === 0)) {
    return false;
  }
  if (whole > maxSeconds) {
    return false;
  }
  if (whole === maxSeconds && fractionOrder !== 0) {
    return false;
  }
  return true;
}

function canonicalPort(port) {
  if (!/^(0|[1-9][0-9]{0,4})$/.test(port)) {
    return false;
  }
  return BigInt(port) <= 65535n;
}

function canonicalIpv4(host) {
  const parts = host.split(".");
  if (parts.length !== 4) {
    return false;
  }
  return parts.every((part) => /^(0|[1-9][0-9]{0,2})$/.test(part) && Number(part) <= 255);
}

function splitAuthority(authority) {
  if (authority.startsWith("[")) {
    const end = authority.indexOf("]");
    if (end < 2) {
      return null;
    }
    const host = authority.slice(1, end);
    const after = authority.slice(end + 1);
    if (after.length === 0) {
      return { host, port: null };
    }
    if (!after.startsWith(":")) {
      return null;
    }
    return { host, port: after.slice(1) };
  }
  if (authority.includes("@")) {
    return null;
  }
  const colon = authority.lastIndexOf(":");
  if (colon === -1) {
    return { host: authority, port: null };
  }
  return {
    host: authority.slice(0, colon),
    port: authority.slice(colon + 1),
  };
}

function authorityPrecheck(authority) {
  if (authority.length === 0) {
    return false;
  }
  const split = splitAuthority(authority);
  if (split === null || split.host.length === 0) {
    return false;
  }
  if (split.port !== null && !canonicalPort(split.port)) {
    return false;
  }
  if (/^[0-9.]+$/.test(split.host) && !canonicalIpv4(split.host)) {
    return false;
  }
  if (profileHostnameExcluded(split.host)) {
    return false;
  }
  return true;
}

function profileHostnameExcluded(host) {
  if (host.startsWith("[")) {
    return false;
  }
  if (host.endsWith(".")) {
    return true;
  }
  if (host.includes("%")) {
    return true;
  }
  return host.split(".").some((label) => /^0[xX][0-9A-Fa-f]+$/.test(label));
}

export function destinationUriValid(value) {
  if (typeof value !== "string" || !value.startsWith("https://")) {
    return false;
  }
  if (/[\u0000-\u001F\u007F\s*?#\\]/.test(value)) {
    return false;
  }
  const rest = value.slice("https://".length);
  if (rest.length === 0) {
    return false;
  }
  const slash = rest.indexOf("/");
  const authority = slash === -1 ? rest : rest.slice(0, slash);
  const path = slash === -1 ? "" : rest.slice(slash);
  if (!authorityPrecheck(authority)) {
    return false;
  }
  let url;
  try {
    url = new URL(value);
  } catch {
    return false;
  }
  if (url.protocol !== "https:" || url.username !== "" || url.password !== "") {
    return false;
  }
  if (typeof url.hostname !== "string" || url.hostname.length === 0) {
    return false;
  }
  const originalAuthority = splitAuthority(authority);
  if (originalAuthority === null) {
    return false;
  }
  if (canonicalIpv4(url.hostname) && originalAuthority.host !== url.hostname) {
    return false;
  }
  if (url.search !== "" || url.hash !== "") {
    return false;
  }
  if (path === "") {
    return url.pathname === "/";
  }
  return path === url.pathname;
}

export function destinationsExactMatch(left, right) {
  return typeof left === "string" && left === right && destinationUriValid(left);
}

export function initiationSemanticsHold(initiation) {
  if (initiation === null || typeof initiation !== "object" || Array.isArray(initiation)) {
    return false;
  }
  return parseUtc(initiation.initiated_at) !== null
    && parseUtc(initiation.expires_at) !== null
    && destinationUriValid(initiation.destination_uri);
}

export function contextSemanticsHold(context) {
  if (context === null || typeof context !== "object" || Array.isArray(context)) {
    return false;
  }
  return parseUtc(context.issued_at) !== null
    && parseUtc(context.expires_at) !== null
    && destinationUriValid(context.destination_uri);
}

let authenticatedContextSchemaValid = null;

function authenticatedContextSchemaHolds(payload) {
  if (authenticatedContextSchemaValid === null) {
    const ajv = new Ajv2020({
      allErrors: true,
      strict: true,
      strictRequired: false,
    });
    ajv.addSchema(loadJson("contracts/common/v0.2/defs.schema.json"));
    ajv.addSchema(loadJson("contracts/common/v1.0/defs.schema.json"));
    ajv.addSchema(loadJson("contracts/source-session-handoff/v1.0/defs.schema.json"));
    authenticatedContextSchemaValid = ajv.compile(loadJson(CONTEXT_SCHEMA));
  }
  return authenticatedContextSchemaValid(payload) === true;
}

function authenticatedContextSemanticsHold(payload) {
  if (!contextSemanticsHold(payload) || constantsUnsupported(payload)) {
    return false;
  }
  if (
    typeof payload.source_session_ref !== "string"
    || typeof payload.source_context_ref !== "string"
    || payload.source_session_ref.length === 0
    || payload.source_context_ref.length === 0
    || payload.source_session_ref === payload.source_context_ref
  ) {
    return false;
  }
  if (
    scopeElementsStructurallyIllegal(payload.record_scope_refs)
    || scopeElementsStructurallyIllegal(payload.source_permission_refs)
    || scopeArrayInvalid(payload.record_scope_refs)
    || scopeArrayInvalid(payload.source_permission_refs)
  ) {
    return false;
  }
  return durationWithin(payload.issued_at, payload.expires_at, CONTEXT_WINDOW_SECONDS);
}

export function failureObjectConforms(failure, schemaValid) {
  if (schemaValid !== true) {
    return false;
  }
  if (failure === null || typeof failure !== "object" || Array.isArray(failure)) {
    return false;
  }
  if (parseUtc(failure.occurred_at) === null) {
    return false;
  }
  if (failure.retryable !== retryableFor(failure.outcome)) {
    return false;
  }
  const spec = codeSpec(failure.code);
  return spec !== null && spec.outcome === failure.outcome && spec.retryable === failure.retryable;
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

export function prefixScanEvidence(values) {
  const sorted = [...values].sort();
  let comparisons = 0;
  for (let i = 1; i < sorted.length; i += 1) {
    comparisons += 1;
    if (sorted[i].startsWith(sorted[i - 1])) {
      return { ambiguous: true, comparisons };
    }
  }
  return { ambiguous: false, comparisons };
}

function ambiguousPrefix(arr) {
  return prefixScanEvidence(arr).ambiguous;
}

export function scopeElementsStructurallyIllegal(arr) {
  if (!Array.isArray(arr)) {
    return false;
  }
  return arr.some((item) => typeof item !== "string" || item.length === 0 || /\s/.test(item));
}

export function scopeArrayInvalid(arr) {
  if (!Array.isArray(arr) || scopeElementsStructurallyIllegal(arr)) {
    return false;
  }
  if (arr.length === 0) {
    return true;
  }
  if (new Set(arr).size !== arr.length) {
    return true;
  }
  if (arr.some((item) => item.includes("*"))) {
    return true;
  }
  if (!sortedAscending(arr)) {
    return true;
  }
  return ambiguousPrefix(arr);
}

function structuralScopeProblem(initiation, context) {
  return scopeElementsStructurallyIllegal(initiation?.requested_record_scope_refs)
    || scopeElementsStructurallyIllegal(context?.record_scope_refs)
    || scopeElementsStructurallyIllegal(context?.source_permission_refs);
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

export function bindingMismatch(initiation, context) {
  return context.contract_family !== initiation.contract_family
    || context.contract_version !== initiation.contract_version
    || context.profile !== initiation.profile
    || context.issuer !== initiation.issuer
    || context.audience !== initiation.receiver_ref
    || context.receiver_ref !== initiation.receiver_ref
    || context.client_ref !== initiation.client_ref
    || context.destination_uri !== initiation.destination_uri
    || context.handoff_ref !== initiation.handoff_ref
    || context.transaction_ref !== initiation.transaction_ref
    || context.correlation_ref !== initiation.correlation_ref
    || context.purpose !== initiation.purpose;
}

function issuedInsideCodeWindow(initiation, context) {
  const afterStart = compareInstants(initiation.initiated_at, context.issued_at);
  const beforeEnd = compareInstants(context.issued_at, initiation.expires_at);
  return afterStart !== null && beforeEnd !== null && afterStart <= 0 && beforeEnd < 0;
}

function lifetimeFailure(initiation, context, at, sourceSessionExpiresAt) {
  if (!durationWithin(initiation.initiated_at, initiation.expires_at, CODE_WINDOW_SECONDS)) {
    return "expired";
  }
  if (!durationWithin(context.issued_at, context.expires_at, CONTEXT_WINDOW_SECONDS)) {
    return "expired";
  }
  if (!issuedInsideCodeWindow(initiation, context)) {
    return "expired";
  }
  if (sourceSessionExpiresAt === undefined || sourceSessionExpiresAt === null) {
    return "unverified";
  }
  if (parseUtc(sourceSessionExpiresAt) === null) {
    return "malformed";
  }
  const sessionEndsFirst = compareInstants(sourceSessionExpiresAt, context.expires_at);
  if (sessionEndsFirst === null) {
    return "malformed";
  }
  if (sessionEndsFirst < 0) {
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

export function identityMatches(context, attested) {
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

export function sameCompleteAuthenticatedContext(context, redeemed) {
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

export function assessSourceSessionHandoff(input) {
  if (input.dependencyAvailable === false) {
    return closedResult("dependency_unavailable");
  }
  if (constantsUnsupported(input.initiation) || constantsUnsupported(input.context)) {
    return closedResult("unsupported_version");
  }
  if (structuralScopeProblem(input.initiation, input.context)) {
    return closedResult("malformed");
  }
  if (scopeProblem(input.initiation, input.context)) {
    return closedResult("scope_invalid");
  }
  if (input.schemaValidInitiation !== true || input.schemaValidContext !== true) {
    return closedResult("malformed");
  }
  if (
    !initiationSemanticsHold(input.initiation)
    || !contextSemanticsHold(input.context)
    || parseUtc(input.at) === null
  ) {
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
  const lifetime = lifetimeFailure(
    input.initiation,
    input.context,
    input.at,
    input.sourceSessionExpiresAt,
  );
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

export function pkceVerifierValid(verifier) {
  return typeof verifier === "string" && PKCE_VERIFIER_PATTERN.test(verifier);
}

export function pkceChallengeFor(verifier) {
  if (!pkceVerifierValid(verifier)) {
    return null;
  }
  return createHash("sha256").update(verifier, "ascii").digest("base64url");
}

export function integralSecondLifetime(start, end) {
  const left = instantParts(start);
  const right = instantParts(end);
  if (left === null || right === null) {
    return null;
  }
  if (compareFractionDigits(left.fraction, right.fraction) !== 0) {
    return null;
  }
  const whole = right.seconds - left.seconds;
  if (whole <= 0n) {
    return null;
  }
  return whole;
}

export function browserProhibitedFields() {
  return [...BROWSER_PROHIBITED_FIELDS];
}

export function authorizationRequestDestinationAccepted(request) {
  if (request === null || typeof request !== "object" || Array.isArray(request)) {
    return false;
  }
  return destinationUriValid(request.destination_uri);
}

export function registrationEndpointsAccepted(registration) {
  if (registration === null || typeof registration !== "object" || Array.isArray(registration)) {
    return false;
  }
  return destinationUriValid(registration.authorization_endpoint)
    && destinationUriValid(registration.token_endpoint);
}

export function browserCallbackQueryAllowed(params, expectedState) {
  if (typeof expectedState !== "string" || expectedState.length === 0) {
    return false;
  }
  if (params === null || typeof params !== "object" || Array.isArray(params)) {
    return false;
  }
  const keys = Object.keys(params);
  if (keys.length !== 2 || params.state !== expectedState) {
    return false;
  }
  if (Object.hasOwn(params, "code") && !Object.hasOwn(params, "error")) {
    return authorizationCodeWellFormed(params.code);
  }
  return Object.hasOwn(params, "error")
    && !Object.hasOwn(params, "code")
    && SAFE_OAUTH_ERRORS.has(params.error);
}

export function registrationPermitsRedirect(registration, clientRef, destination) {
  if (registration === null || typeof registration !== "object") {
    return false;
  }
  if (registration.status !== "enabled" || registration.client_ref !== clientRef) {
    return false;
  }
  if (!registrationEndpointsAccepted(registration)) {
    return false;
  }
  if (!destinationUriValid(destination) || !Array.isArray(registration.destination_uris)) {
    return false;
  }
  return registration.destination_uris.some((item) => item === destination);
}

function canonicalBase64UrlBytes(segment) {
  if (typeof segment !== "string" || !/^[A-Za-z0-9_-]+$/.test(segment)) {
    return null;
  }
  const decoded = Buffer.from(segment, "base64url");
  if (decoded.toString("base64url") !== segment) {
    return null;
  }
  return decoded;
}

function jsonFromCanonicalBytes(bytes) {
  const text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  if (text.length > 0 && text.charCodeAt(0) === 0xfeff) {
    throw new Error("leading UTF-8 BOM");
  }
  return JSON.parse(text);
}

function authorizationCodeWellFormed(value) {
  return typeof value === "string" && /^[A-Za-z0-9\-._~]{22,512}$/.test(value);
}

export function inspectCompactJws(assertion) {
  if (typeof assertion !== "string") {
    return null;
  }
  const parts = assertion.split(".");
  if (parts.length !== 3) {
    return null;
  }
  const headerBytes = canonicalBase64UrlBytes(parts[0]);
  const payloadBytes = canonicalBase64UrlBytes(parts[1]);
  const signature = canonicalBase64UrlBytes(parts[2]);
  if (headerBytes === null || payloadBytes === null || signature === null) {
    return null;
  }
  try {
    const header = jsonFromCanonicalBytes(headerBytes);
    const payload = jsonFromCanonicalBytes(payloadBytes);
    if (header === null || typeof header !== "object" || Array.isArray(header)) {
      return null;
    }
    if (payload === null || typeof payload !== "object" || Array.isArray(payload)) {
      return null;
    }
    return {
      header,
      payload,
      signingInput: Buffer.from(`${parts[0]}.${parts[1]}`),
      signature,
    };
  } catch {
    return null;
  }
}

export function jwsHeaderAccepted(header, permittedAlgorithms) {
  if (header === null || typeof header !== "object" || Array.isArray(header)) {
    return false;
  }
  const keys = Object.keys(header);
  if (keys.length !== 2 || !Object.hasOwn(header, "alg") || !Object.hasOwn(header, "kid")) {
    return false;
  }
  if (typeof header.kid !== "string" || header.kid.length === 0 || /\s/.test(header.kid)) {
    return false;
  }
  if (header.alg === "none" || !PERMITTED_ALGS.includes(header.alg)) {
    return false;
  }
  if (!Array.isArray(permittedAlgorithms) || !permittedAlgorithms.includes(header.alg)) {
    return false;
  }
  return !Object.hasOwn(header, "jku")
    && !Object.hasOwn(header, "jwk")
    && !Object.hasOwn(header, "x5u")
    && !Object.hasOwn(header, "x5c")
    && !Object.hasOwn(header, "crit");
}

function publicKeyMatchesAlgorithm(alg, jwk) {
  if (jwk.use !== "sig" || jwk.alg !== alg) {
    return false;
  }
  if (alg === "EdDSA") {
    return jwk.kty === "OKP" && jwk.crv === "Ed25519";
  }
  if (alg === "RS256" || alg === "RS384" || alg === "RS512") {
    return jwk.kty === "RSA";
  }
  if (alg === "ES256") {
    return jwk.kty === "EC" && jwk.crv === "P-256";
  }
  if (alg === "ES384") {
    return jwk.kty === "EC" && jwk.crv === "P-384";
  }
  if (alg === "ES512") {
    return jwk.kty === "EC" && jwk.crv === "P-521";
  }
  return false;
}

function verificationKeyFor(registration, kid, alg) {
  if (registration === null || typeof registration !== "object" || Array.isArray(registration)) {
    return null;
  }
  if (!Array.isArray(registration.algorithms) || !registration.algorithms.includes(alg)) {
    return null;
  }
  const keys = registration.jwks && registration.jwks.keys;
  if (!Array.isArray(keys)) {
    return null;
  }
  const matches = keys.filter((key) => (
    key !== null
    && typeof key === "object"
    && !Array.isArray(key)
    && key.kid === kid
  ));
  if (matches.length !== 1) {
    return null;
  }
  const jwk = matches[0];
  const privateMembers = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];
  if (privateMembers.some((member) => Object.hasOwn(jwk, member))) {
    return null;
  }
  if (!publicKeyMatchesAlgorithm(alg, jwk)) {
    return null;
  }
  try {
    return createPublicKey({ key: jwk, format: "jwk" });
  } catch {
    return null;
  }
}

function jwsSignatureValid(alg, key, signingInput, signature) {
  if (!Buffer.isBuffer(signingInput) || !Buffer.isBuffer(signature) || signature.length === 0) {
    return false;
  }
  try {
    if (alg === "EdDSA") {
      return verify(null, signingInput, key, signature);
    }
    if (alg === "ES256" || alg === "ES384" || alg === "ES512") {
      const hash = alg === "ES256" ? "sha256" : alg === "ES384" ? "sha384" : "sha512";
      return verify(hash, signingInput, { key, dsaEncoding: "ieee-p1363" }, signature);
    }
    if (alg === "RS256" || alg === "RS384" || alg === "RS512") {
      const nodeAlg = alg === "RS256" ? "RSA-SHA256" : alg === "RS384" ? "RSA-SHA384" : "RSA-SHA512";
      return verify(nodeAlg, signingInput, key, signature);
    }
    return false;
  } catch {
    return false;
  }
}

function sameJsonValue(left, right) {
  if (Array.isArray(left) || Array.isArray(right)) {
    return sameArray(left, right);
  }
  if (left !== null && right !== null && typeof left === "object" && typeof right === "object") {
    const keys = Object.keys(left);
    if (keys.length !== Object.keys(right).length) {
      return false;
    }
    return keys.every((key) => Object.hasOwn(right, key) && sameJsonValue(left[key], right[key]));
  }
  return left === right;
}

const REDEMPTION_RESPONSE_FIELDS = [
  "contract_family",
  "contract_version",
  "profile",
  "status",
  "token_type",
  "assertion_format",
  "assertion",
  "expires_in",
];

function closedRedemptionResponse(response) {
  if (response === null || typeof response !== "object" || Array.isArray(response)) {
    return false;
  }
  const keys = Object.keys(response);
  if (keys.length !== REDEMPTION_RESPONSE_FIELDS.length) {
    return false;
  }
  if (!REDEMPTION_RESPONSE_FIELDS.every((field) => Object.hasOwn(response, field))) {
    return false;
  }
  return response.contract_family === FAMILY
    && response.contract_version === VERSION
    && response.profile === PROFILE
    && response.status === "issued"
    && response.token_type === "Bearer"
    && response.assertion_format === "compact-jws-authenticated-context-v1"
    && typeof response.assertion === "string"
    && Number.isInteger(response.expires_in)
    && response.expires_in >= 1
    && response.expires_in <= 300;
}

function registrationBindsContext(registration, context) {
  if (
    registration === null
    || typeof registration !== "object"
    || Array.isArray(registration)
    || context === null
    || typeof context !== "object"
    || Array.isArray(context)
  ) {
    return false;
  }
  return registration.status === "enabled"
    && registrationEndpointsAccepted(registration)
    && context.contract_family === FAMILY
    && context.contract_version === VERSION
    && context.profile === PROFILE
    && registration.issuer === context.issuer
    && registration.client_ref === context.client_ref
    && registration.receiver_ref === context.receiver_ref
    && registration.receiver_ref === context.audience
    && registration.purpose === context.purpose
    && Array.isArray(registration.allowed_contract_versions)
    && registration.allowed_contract_versions.includes(context.contract_version)
    && Array.isArray(registration.allowed_profiles)
    && registration.allowed_profiles.includes(context.profile)
    && Array.isArray(registration.destination_uris)
    && registration.destination_uris.includes(context.destination_uri);
}

export function redemptionResponseMatchesContext(response, context, registration) {
  if (!closedRedemptionResponse(response)) {
    return false;
  }
  const inspected = inspectCompactJws(response.assertion);
  if (inspected === null || !jwsHeaderAccepted(inspected.header, registration?.algorithms)) {
    return false;
  }
  const key = verificationKeyFor(registration, inspected.header.kid, inspected.header.alg);
  if (key === null || !jwsSignatureValid(inspected.header.alg, key, inspected.signingInput, inspected.signature)) {
    return false;
  }
  const payload = inspected.payload;
  if (!authenticatedContextSchemaHolds(payload) || !authenticatedContextSemanticsHold(payload)) {
    return false;
  }
  if (!registrationBindsContext(registration, payload)) {
    return false;
  }
  if (!sameJsonValue(payload, context)) {
    return false;
  }
  const lifetime = integralSecondLifetime(payload.issued_at, payload.expires_at);
  return lifetime !== null && lifetime === BigInt(response.expires_in) && lifetime <= 300n;
}

function machineResult(code, extras = {}) {
  const spec = codeSpec(code);
  if (spec === null) {
    throw new Error(`unsupported failure code ${code}`);
  }
  return {
    failure: spec.outcome,
    code,
    retryable: spec.retryable,
    contextAccepted: false,
    grantsReceiverAccess: false,
    mintsReceiverSession: false,
    mintsAdditionalReceiverSession: false,
    synthesizedUnscopedRedirect: false,
    synthesizedEmptyContext: false,
    reconciled: false,
    redirectPermitted: false,
    codeConsumed: false,
    ...extras,
  };
}

export function assessRedemption(input) {
  if (input.issuerUnavailable === true) {
    return machineResult("ISSUER_UNAVAILABLE");
  }
  if (input.dependencyAvailable === false) {
    return machineResult("DEPENDENCY_UNAVAILABLE");
  }
  const request = input.request;
  if (request === null || typeof request !== "object") {
    return machineResult("MALFORMED_REQUEST");
  }
  if (request.contract_family !== FAMILY) {
    return machineResult("UNSUPPORTED_CONTRACT_VERSION");
  }
  if (request.contract_version !== VERSION) {
    return machineResult("UNSUPPORTED_CONTRACT_VERSION");
  }
  if (request.profile !== PROFILE) {
    return machineResult("UNSUPPORTED_PROFILE");
  }
  if (constantsUnsupported(request) || input.schemaValidRequest !== true) {
    return machineResult("MALFORMED_REQUEST");
  }
  if (
    !destinationUriValid(request.destination_uri)
    || !pkceVerifierValid(request.code_verifier)
    || !authorizationCodeWellFormed(request.authorization_code)
  ) {
    return machineResult("MALFORMED_REQUEST");
  }
  if (input.codeChallengeMethod !== "S256") {
    return machineResult("INVALID_PKCE_METHOD");
  }
  const registration = input.registration;
  if (registration === null || typeof registration !== "object" || registration.client_ref !== request.client_ref) {
    return machineResult("UNKNOWN_CLIENT");
  }
  if (registration.status === "disabled") {
    return machineResult("CLIENT_DISABLED");
  }
  if (registration.status === "revoked") {
    return machineResult("CLIENT_REVOKED");
  }
  if (registration.status !== "enabled") {
    return machineResult("UNKNOWN_CLIENT");
  }
  if (!registrationEndpointsAccepted(registration)) {
    return machineResult("UNKNOWN_CLIENT");
  }
  if (!Array.isArray(registration.destination_uris) || !registration.destination_uris.includes(request.destination_uri)) {
    return machineResult("DESTINATION_MISMATCH");
  }
  const record = input.codeRecord;
  if (
    record === null
    || typeof record !== "object"
    || Array.isArray(record)
    || !Object.hasOwn(record, "authorization_code")
    || !authorizationCodeWellFormed(record.authorization_code)
    || record.authorization_code !== request.authorization_code
  ) {
    return machineResult("CODE_UNKNOWN");
  }
  if (record.code_challenge_method !== "S256") {
    return machineResult("INVALID_PKCE_METHOD");
  }
  if (record.client_ref !== request.client_ref) {
    return machineResult("UNKNOWN_CLIENT");
  }
  if (record.destination_uri !== request.destination_uri) {
    return machineResult("DESTINATION_MISMATCH");
  }
  if (
    parseUtc(input.now) === null
    || parseUtc(record.issued_at) === null
    || parseUtc(record.expires_at) === null
  ) {
    return machineResult("MALFORMED_REQUEST");
  }
  if (!durationWithin(record.issued_at, record.expires_at, CODE_WINDOW_SECONDS)) {
    return machineResult("CODE_EXPIRED");
  }
  const afterIssued = compareInstants(record.issued_at, input.now);
  const beforeExpiry = compareInstants(input.now, record.expires_at);
  if (afterIssued === null || beforeExpiry === null || afterIssued > 0 || beforeExpiry >= 0) {
    return machineResult("CODE_EXPIRED");
  }
  if (typeof record.consumed !== "boolean") {
    return machineResult("MALFORMED_REQUEST");
  }
  if (record.consumed === true) {
    return machineResult("CODE_REPLAYED");
  }
  const challenge = pkceChallengeFor(request.code_verifier);
  if (challenge === null || challenge !== record.code_challenge) {
    return machineResult("PKCE_MISMATCH");
  }
  if (request.purpose !== record.purpose || request.purpose !== registration.purpose) {
    return machineResult("PURPOSE_MISMATCH");
  }
  if (request.handoff_ref !== record.handoff_ref) {
    return machineResult("HANDOFF_MISMATCH");
  }
  if (request.transaction_ref !== record.transaction_ref) {
    return machineResult("TRANSACTION_MISMATCH");
  }
  if (request.correlation_ref !== record.correlation_ref) {
    return machineResult("CORRELATION_MISMATCH");
  }
  if (
    typeof record.source_session_ref !== "string"
    || typeof record.source_context_ref !== "string"
    || record.source_session_ref.length === 0
    || record.source_context_ref.length === 0
    || record.source_session_ref === record.source_context_ref
  ) {
    return machineResult("SOURCE_ROLE_CONTEXT_INVALID");
  }
  return {
    failure: null,
    code: null,
    retryable: false,
    contextAccepted: false,
    grantsReceiverAccess: false,
    mintsReceiverSession: false,
    mintsAdditionalReceiverSession: false,
    synthesizedUnscopedRedirect: false,
    synthesizedEmptyContext: false,
    reconciled: false,
    redirectPermitted: false,
    codeConsumed: true,
  };
}
