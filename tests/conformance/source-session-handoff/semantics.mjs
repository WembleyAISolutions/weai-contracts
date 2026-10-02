import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "../../..");
const CONTEXT_SCHEMA = "contracts/source-session-handoff/v1.0/authenticated-context.schema.json";

const FAMILY = "source-session-handoff";
const VERSION = "v1.0";
const PROFILE = "oauth2-authorization-code-pkce-s256-v1";
const CODE_WINDOW_SECONDS = 60n;
const CONTEXT_WINDOW_SECONDS = 300n;

const UTC_TIMESTAMP_PATTERN =
  /^(\d{4})-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])T([01]\d|2[0-3]):([0-5]\d):([0-5]\d)(\.\d+)?Z$/;

const DNS_LABEL = /^(?:[A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9-]{0,61}[A-Za-z0-9])$/;
const PATH_SEGMENT = /^(?:[A-Za-z0-9\-._~!$&'()+,;=:@]|%[0-9A-Fa-f]{2})+$/;
const HEXTET = /^[0-9A-Fa-f]{1,4}$/;

function loadJson(relPath) {
  return JSON.parse(readFileSync(join(repoRoot, relPath), "utf8"));
}

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

export function durationWithin(start, end, maxSeconds) {
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

function validPort(port) {
  if (!/^[0-9]{1,5}$/.test(port)) {
    return false;
  }
  return BigInt(port) <= 65535n;
}

function validIpv4(host) {
  const parts = host.split(".");
  if (parts.length !== 4) {
    return false;
  }
  return parts.every((part) => {
    if (!/^(?:0|[1-9][0-9]{0,2})$/.test(part)) {
      return false;
    }
    return Number(part) <= 255;
  });
}

function validDns(host) {
  const bare = host.endsWith(".") ? host.slice(0, -1) : host;
  if (bare.length === 0 || bare.length > 253 || bare.endsWith(".")) {
    return false;
  }
  return bare.split(".").every((label) => DNS_LABEL.test(label));
}

function ipv6GroupCount(groups) {
  if (groups.length === 0) {
    return 0;
  }
  const last = groups[groups.length - 1];
  if (last.includes(".")) {
    if (!validIpv4(last)) {
      return null;
    }
    const head = groups.slice(0, -1);
    if (!head.every((group) => HEXTET.test(group))) {
      return null;
    }
    return head.length + 2;
  }
  if (!groups.every((group) => HEXTET.test(group))) {
    return null;
  }
  return groups.length;
}

function validIpv6(body) {
  if (body.length === 0 || body.includes("%")) {
    return false;
  }
  const halves = body.split("::");
  if (halves.length > 2) {
    return false;
  }
  const left = halves[0] === "" ? [] : halves[0].split(":");
  const right = halves.length === 2
    ? (halves[1] === "" ? [] : halves[1].split(":"))
    : null;
  const leftCount = ipv6GroupCount(left);
  if (leftCount === null) {
    return false;
  }
  if (right === null) {
    return leftCount === 8;
  }
  const rightCount = ipv6GroupCount(right);
  if (rightCount === null) {
    return false;
  }
  return leftCount + rightCount < 8;
}

function validPath(path) {
  if (!path.startsWith("/")) {
    return false;
  }
  const segments = path.split("/");
  for (let index = 1; index < segments.length; index += 1) {
    const segment = segments[index];
    if (segment === "") {
      if (index !== segments.length - 1) {
        return false;
      }
      continue;
    }
    if (!PATH_SEGMENT.test(segment)) {
      return false;
    }
  }
  return true;
}

function validAuthority(authority) {
  if (authority.length === 0 || authority.includes("@")) {
    return false;
  }
  let host;
  let port = null;
  if (authority.startsWith("[")) {
    const end = authority.indexOf("]");
    if (end < 2) {
      return false;
    }
    host = authority.slice(1, end);
    const after = authority.slice(end + 1);
    if (after.length === 0) {
      port = null;
    } else if (after.startsWith(":")) {
      port = after.slice(1);
    } else {
      return false;
    }
    if (!validIpv6(host)) {
      return false;
    }
  } else {
    const colon = authority.lastIndexOf(":");
    if (colon === -1) {
      host = authority;
    } else {
      host = authority.slice(0, colon);
      port = authority.slice(colon + 1);
    }
    if (host.length === 0) {
      return false;
    }
    if (/^(?:[0-9]+\.){3}[0-9]+$/.test(host)) {
      if (!validIpv4(host)) {
        return false;
      }
    } else if (!validDns(host)) {
      return false;
    }
  }
  if (port !== null && !validPort(port)) {
    return false;
  }
  return true;
}

export function destinationUriValid(value) {
  if (typeof value !== "string" || !value.startsWith("https://")) {
    return false;
  }
  if (/[\u0000-\u001F\u007F\s*?#\\]/.test(value)) {
    return false;
  }
  const rest = value.slice("https://".length);
  if (rest.length === 0 || rest.startsWith("/") || rest.startsWith(":")) {
    return false;
  }
  const slash = rest.indexOf("/");
  const authority = slash === -1 ? rest : rest.slice(0, slash);
  const path = slash === -1 ? "" : rest.slice(slash);
  if (!validAuthority(authority)) {
    return false;
  }
  if (path !== "" && !validPath(path)) {
    return false;
  }
  return true;
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
  return failure.retryable === retryableFor(failure.outcome);
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

export function scopeArrayInvalid(arr) {
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
  if (scopeProblem(input.initiation, input.context)) {
    return closedResult("scope_invalid");
  }
  if (input.schemaValidInitiation === false || input.schemaValidContext === false) {
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
