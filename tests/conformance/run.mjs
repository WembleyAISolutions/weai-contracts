import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import Ajv2020 from "ajv/dist/2020.js";
import {
  CANONICALIZATION,
  DIGEST_SCHEME,
  digestInput,
  rfc8785,
  sameVerification,
  selfDigest,
} from "./digest.mjs";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "../..");
const manifest = JSON.parse(
  readFileSync(join(repoRoot, "tests/conformance/manifest.json"), "utf8"),
);

const ALLOWED_REASON_CODES = [
  "not_permitted",
  "invalid_request",
  "ambiguous_request",
  "replay_rejected",
  "idempotency_conflict",
];

const FORBIDDEN_TERM_DIGESTS = new Set([
  "dae89d3019f0767543ad0a75fcde9019c8a125b46850ce34843dd76d8c2ca77c",
  "b23b1c40cc2e491ecd1f36da7e39b9bb8807b83f8ce654ff14842593118715e7",
  "cb29803c0f61f6ad0e818f699f030add20997285cfc7e02d40efa87a2cbbf97c",
  "e2a169126b5f3dd4e0eed89c06ae9e095fc45a81c06d9c19b7a7a7e618b5d43d",
  "52ae25f63ff58a0fc009b7ff6afa20299343303ed1629dbdd838a6276d04c598",
  "891461fc2f556b3f0c1bd7534245bd0b35fe0884b2147ecdf68d3dda038f0d22",
  "4a0a05dbc0b4ed6bd76914345ccd87cf71820a63a7f5d95b12aa9cdb0081fe96",
  "fd89b0e82545ed13128d1e24aedd637dc2667943ee38603df400715195e66419",
  "9aed324a72baecd4544292a159a9674b939c7371f77fc95fbd65beb37fcda82a",
  "e79baf839f27788c8e72eca2bb4491a57ffce66ffc6bf981b446e96e45090cb9",
  "49f756463ad9dcfb9b6ade54d7d6f15476e7214f46a65b4b0c55d46845b12f70",
  "6923dd1bc0460082c5d55a831908c24a282860b7f1cd6c2b79cf1bc8857c639c",
  "8399e57405627368722830c9ff3db81fba0afa6120a439c7a2568a5be31b8295",
  "7a5356659c5b128bf2a1cfa958aca12b66573ecc89e0089dd5a74018541868aa",
  "8dcdd4d275abddc84b0f5ad7b5dc23b8425387130140b6a7b51b9f6641788d18",
  "68d3119bc0fc6e24f44c91674ed22f48516e69c847183de87ba128f996af0acf",
]);

function digest(value) {
  return createHash("sha256").update(value.toLowerCase()).digest("hex");
}

function forbiddenHits(text) {
  const words = text.match(/[A-Za-z0-9-]+/g) ?? [];
  const hits = [];
  for (let i = 0; i < words.length; i += 1) {
    const unigram = words[i];
    if (FORBIDDEN_TERM_DIGESTS.has(digest(unigram))) {
      hits.push(unigram);
    }
    if (i + 1 < words.length) {
      const bigram = `${words[i]} ${words[i + 1]}`;
      if (FORBIDDEN_TERM_DIGESTS.has(digest(bigram))) {
        hits.push(bigram);
      }
    }
  }
  return hits;
}

function loadJson(relPath) {
  return JSON.parse(readFileSync(join(repoRoot, relPath), "utf8"));
}

function createAjv() {
  const ajv = new Ajv2020({
    allErrors: true,
    strict: true,
    strictRequired: false,
  });
  ajv.addSchema(loadJson("contracts/common/v0.2/defs.schema.json"));
  ajv.addSchema(loadJson("contracts/common/v1.0/defs.schema.json"));
  return ajv;
}

const ajv = createAjv();
const validators = new Map();

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

function listFiles(relDir, acc = []) {
  const abs = join(repoRoot, relDir);
  if (!existsSync(abs)) {
    return acc;
  }
  for (const entry of readdirSync(abs)) {
    const rel = join(relDir, entry);
    const st = statSync(join(repoRoot, rel));
    if (st.isDirectory()) {
      if (entry === "node_modules" || entry === ".git") {
        continue;
      }
      listFiles(rel, acc);
    } else {
      acc.push(rel);
    }
  }
  return acc;
}

test("v0.1 fixtures still validate against v0.1", async (t) => {
  for (const item of manifest.v0_1) {
    await t.test(item.name, () => {
      const validate = validatorFor(item.schema);
      const fixture = loadJson(item.fixture);
      assert.equal(validate(fixture), true, formatErrors(validate));
    });
  }
});

test("v0.2 positive wire fixtures validate", async (t) => {
  for (const item of manifest.v0_2_positive) {
    await t.test(item.name, () => {
      const validate = validatorFor(item.schema);
      const fixture = loadJson(item.fixture);
      assert.equal(
        Object.hasOwn(fixture, "example_id"),
        false,
        "v0.2 wire fixtures must not be documentation wrappers",
      );
      assert.equal(
        Object.hasOwn(fixture, "notes"),
        false,
        "v0.2 wire fixtures must not be documentation wrappers",
      );
      assert.equal(validate(fixture), true, formatErrors(validate));
    });
  }
});

test("v0.2 negative wire fixtures are rejected", async (t) => {
  for (const item of manifest.v0_2_negative) {
    await t.test(item.name, () => {
      const validate = validatorFor(item.schema);
      const fixture = loadJson(item.fixture);
      assert.equal(
        validate(fixture),
        false,
        `${item.fixture} unexpectedly validated`,
      );
    });
  }
});

function ieee754FromHex(hex) {
  const bytes = Buffer.from(hex, "hex");
  assert.equal(bytes.length, 8);
  return bytes.readDoubleBE(0);
}

test("RFC 8785 JCS object property ordering", () => {
  assert.equal(rfc8785({ b: 1, a: 2 }), '{"a":2,"b":1}');
  const input = {
    "\u20ac": "Euro Sign",
    "\r": "Carriage Return",
    "\ufb33": "Hebrew Letter Dalet With Dagesh",
    "1": "One",
    "\ud83d\ude00": "Emoji: Grinning Face",
    "\u0080": "Control",
    "\u00f6": "Latin Small Letter O With Diaeresis",
  };
  assert.equal(
    rfc8785(input),
    '{"\\r":"Carriage Return","1":"One","\u0080":"Control","ö":"Latin Small Letter O With Diaeresis","€":"Euro Sign","😀":"Emoji: Grinning Face","דּ":"Hebrew Letter Dalet With Dagesh"}',
  );
});

test("RFC 8785 JCS numeric serialization", () => {
  const samples = [
    ["0000000000000000", "0"],
    ["8000000000000000", "0"],
    ["0000000000000001", "5e-324"],
    ["8000000000000001", "-5e-324"],
    ["7fefffffffffffff", "1.7976931348623157e+308"],
    ["ffefffffffffffff", "-1.7976931348623157e+308"],
    ["4340000000000000", "9007199254740992"],
    ["c340000000000000", "-9007199254740992"],
    ["4430000000000000", "295147905179352830000"],
    ["44b52d02c7e14af5", "9.999999999999997e+22"],
    ["44b52d02c7e14af6", "1e+23"],
    ["44b52d02c7e14af7", "1.0000000000000001e+23"],
    ["444b1ae4d6e2ef50", "1e+21"],
    ["3eb0c6f7a0b5ed8d", "0.000001"],
    ["41b3de4355555555", "333333333.3333333"],
    ["becbf647612f3696", "-0.0000033333333333333333"],
    ["43143ff3c1cb0959", "1424953923781206.2"],
  ];
  for (const [hex, expected] of samples) {
    assert.equal(rfc8785(ieee754FromHex(hex)), expected, hex);
  }
  assert.throws(() => rfc8785(Number.NaN));
  assert.throws(() => rfc8785(Number.POSITIVE_INFINITY));
});

test("RFC 8785 JCS Unicode and string serialization", () => {
  const input = {
    numbers: [333333333.33333329, 1e30, 4.5, 2e-3, 1e-27],
    string: "\u20ac$\u000F\nA'B\"\\\\\"/",
    literals: [null, true, false],
  };
  const canonical = rfc8785(input);
  assert.equal(
    canonical,
    '{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}',
  );
  assert.equal(
    Buffer.from(canonical, "utf8").toString("hex"),
    "7b226c69746572616c73223a5b6e756c6c2c747275652c66616c73655d2c226e756d62657273223a5b3333333333333333332e333333333333332c31652b33302c342e352c302e3030322c31652d32375d2c22737472696e67223a22e282ac245c75303030665c6e4127425c225c5c5c5c5c222f227d",
  );
});

test("RFC 8785 JCS nested arrays and objects", () => {
  const input = {
    1: { f: { f: "hi", F: 5 }, "\n": 56.0 },
    10: {},
    "": "empty",
    a: {},
    111: [{ e: "yes", E: "no" }],
    A: {},
  };
  assert.equal(
    rfc8785(input),
    '{"":"empty","1":{"\\n":56,"f":{"F":5,"f":"hi"}},"10":{},"111":[{"E":"no","e":"yes"}],"A":{},"a":{}}',
  );
  assert.equal(
    rfc8785([{ b: 2, a: 1 }, { d: [ { z: 1, y: 2 } ], c: 3 }]),
    '[{"a":1,"b":2},{"c":3,"d":[{"y":2,"z":1}]}]',
  );
});

test("idempotent duplicate is the same request wire digest", () => {
  const original = loadJson("contracts/execution-request/v0.2/request.example.json");
  const duplicate = loadJson(
    "tests/conformance/v0.2/positive/execution-request.request.idempotent-duplicate.json",
  );
  assert.equal(original.idempotency_key, duplicate.idempotency_key);
  assert.equal(original.nonce, duplicate.nonce);
  assert.equal(original.submitted_at, duplicate.submitted_at);
  assert.equal(original.request_ref, duplicate.request_ref);
  assert.equal(selfDigest(original), original.verification.value);
  assert.equal(selfDigest(duplicate), duplicate.verification.value);
  assert.equal(original.verification.value, duplicate.verification.value);
});

test("accepted response has distinct self-integrity and request binding", () => {
  const request = loadJson("contracts/execution-request/v0.2/request.example.json");
  const response = loadJson(
    "contracts/execution-request/v0.2/response.accepted.example.json",
  );
  assert.equal(request.request_ref, response.request_ref);
  assert.equal(sameVerification(response.request_verification, request.verification), true);
  assert.equal(selfDigest(response), response.verification.value);
  assert.notEqual(response.verification.value, request.verification.value);
});

test("pending and completed status results bind to the request and have self-integrity", () => {
  const request = loadJson("contracts/execution-request/v0.2/request.example.json");
  const query = loadJson("contracts/status-result/v0.2/query.example.json");
  const pending = loadJson("contracts/status-result/v0.2/result.pending.example.json");
  const completed = loadJson(
    "contracts/status-result/v0.2/result.completed.example.json",
  );
  for (const obj of [query, pending, completed]) {
    assert.equal(obj.result_ref, "result-placeholder-001");
    assert.equal(obj.request_ref, request.request_ref);
  }
  assert.equal(sameVerification(pending.request_verification, request.verification), true);
  assert.equal(sameVerification(completed.request_verification, request.verification), true);
  assert.equal(selfDigest(pending), pending.verification.value);
  assert.equal(selfDigest(completed), completed.verification.value);
  assert.notEqual(pending.verification.value, request.verification.value);
  assert.notEqual(completed.verification.value, pending.verification.value);
});

test("request/response reference mismatch is not a bound pair", () => {
  const request = loadJson("contracts/execution-request/v0.2/request.example.json");
  const mismatched = loadJson(
    "tests/conformance/v0.2/semantic/execution-request.response.request-ref-mismatch.json",
  );
  const validate = validatorFor("contracts/execution-request/v0.2/response.schema.json");
  assert.equal(validate(mismatched), true, formatErrors(validate));
  assert.notEqual(request.request_ref, mismatched.request_ref);
  assert.equal(sameVerification(mismatched.request_verification, request.verification), false);
});

test("denied response and error-denial share request binding and have distinct self-integrity", () => {
  const denied = loadJson(
    "contracts/execution-request/v0.2/response.denied.example.json",
  );
  const error = loadJson("contracts/error-denial/v0.2/example.json");
  assert.equal(denied.request_ref, error.request_ref);
  assert.equal(sameVerification(denied.request_verification, error.request_verification), true);
  assert.equal(selfDigest(denied), denied.verification.value);
  assert.equal(selfDigest(error), error.verification.value);
  assert.notEqual(denied.verification.value, error.verification.value);
  assert.equal(error.reason_code, "not_permitted");
});

test("public reason-code vocabulary is generic only", () => {
  const catalog = loadJson("vocab/reason-codes-v0.2.json");
  const codes = catalog.codes.map((entry) => entry.code);
  assert.deepEqual(codes, ALLOWED_REASON_CODES);
  assert.deepEqual(forbiddenHits(JSON.stringify(catalog)), []);
});

test("error-denial examples use catalog reason codes", () => {
  const exampleFiles = listFiles("contracts/error-denial/v0.2").filter((rel) =>
    rel.endsWith(".json") && !rel.endsWith("schema.json"),
  );
  for (const rel of exampleFiles) {
    const obj = loadJson(rel);
    assert.equal(
      ALLOWED_REASON_CODES.includes(obj.reason_code),
      true,
      `${rel} uses non-catalog reason_code ${obj.reason_code}`,
    );
  }
});

test("v0.2 request wire cannot carry decision/result fields", () => {
  const request = loadJson("contracts/execution-request/v0.2/request.example.json");
  for (const field of ["outcome", "accepted", "denied", "result_ref", "decision", "response"]) {
    assert.equal(Object.hasOwn(request, field), false, `request example has ${field}`);
  }
});

test("published wire objects match rfc8785 sha-256 self-digests", () => {
  const requestFiles = [
    "contracts/execution-request/v0.2/request.example.json",
    "tests/conformance/v0.2/positive/execution-request.request.minimal.json",
    "tests/conformance/v0.2/positive/execution-request.request.multiple-actor-refs.json",
    "tests/conformance/v0.2/positive/execution-request.request.authority-evidence-revision-refs.json",
    "tests/conformance/v0.2/positive/execution-request.request.idempotent-duplicate.json",
  ];
  for (const rel of requestFiles) {
    const request = loadJson(rel);
    assert.equal(request.verification.scheme, DIGEST_SCHEME);
    assert.equal(request.verification.canonicalization, CANONICALIZATION);
    assert.match(request.verification.value, /^[0-9a-f]{64}$/);
    assert.equal(selfDigest(request), request.verification.value, rel);
  }
  const downstream = [
    "contracts/execution-request/v0.2/response.accepted.example.json",
    "contracts/execution-request/v0.2/response.denied.example.json",
    "contracts/status-result/v0.2/result.pending.example.json",
    "contracts/status-result/v0.2/result.completed.example.json",
    "tests/conformance/v0.2/positive/status-result.result.denied.json",
    "contracts/error-denial/v0.2/example.json",
  ];
  for (const rel of downstream) {
    const obj = loadJson(rel);
    assert.equal(selfDigest(obj), obj.verification.value, rel);
  }
});

test("request payload mutation fails self-verification", () => {
  const request = loadJson("contracts/execution-request/v0.2/request.example.json");
  const validate = validatorFor("contracts/execution-request/v0.2/request.schema.json");
  const tampered = structuredClone(request);
  tampered.payload = { note: "tampered operation input" };
  assert.equal(validate(tampered), true, formatErrors(validate));
  assert.notEqual(selfDigest(tampered), request.verification.value);
  assert.equal(Object.hasOwn(tampered.payload, "actor_refs"), false);
  assert.equal(Object.hasOwn(tampered.payload, "verification"), false);
});

test("request submitted_at mutation fails self-verification", () => {
  const request = loadJson("contracts/execution-request/v0.2/request.example.json");
  const tampered = structuredClone(request);
  tampered.submitted_at = "2026-08-14T12:00:00Z";
  assert.notEqual(selfDigest(tampered), request.verification.value);
});

test("response outcome and result_ref mutation fail self-verification", () => {
  const response = loadJson(
    "contracts/execution-request/v0.2/response.accepted.example.json",
  );
  const outcomeTampered = structuredClone(response);
  outcomeTampered.outcome = "denied";
  delete outcomeTampered.result_ref;
  assert.notEqual(selfDigest(outcomeTampered), response.verification.value);
  const resultTampered = structuredClone(response);
  resultTampered.result_ref = "result-placeholder-tampered";
  assert.notEqual(selfDigest(resultTampered), response.verification.value);
});

test("response wrong request_verification fails request binding", () => {
  const request = loadJson("contracts/execution-request/v0.2/request.example.json");
  const response = loadJson(
    "contracts/execution-request/v0.2/response.accepted.example.json",
  );
  assert.equal(sameVerification(response.request_verification, request.verification), true);
  const tampered = structuredClone(response);
  tampered.request_verification = {
    ...tampered.request_verification,
    value: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  };
  assert.equal(sameVerification(tampered.request_verification, request.verification), false);
});

test("status result state and result_ref mutation fail self-verification", () => {
  const result = loadJson("contracts/status-result/v0.2/result.completed.example.json");
  const stateTampered = structuredClone(result);
  stateTampered.state = "failed";
  assert.notEqual(selfDigest(stateTampered), result.verification.value);
  const refTampered = structuredClone(result);
  refTampered.result_ref = "result-placeholder-tampered";
  assert.notEqual(selfDigest(refTampered), result.verification.value);
});

test("status result wrong request_verification fails request binding", () => {
  const request = loadJson("contracts/execution-request/v0.2/request.example.json");
  const result = loadJson("contracts/status-result/v0.2/result.completed.example.json");
  assert.equal(sameVerification(result.request_verification, request.verification), true);
  const tampered = structuredClone(result);
  tampered.request_verification = {
    ...tampered.request_verification,
    value: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  };
  assert.equal(sameVerification(tampered.request_verification, request.verification), false);
});

test("error-denial reason_code mutation fails self-verification", () => {
  const error = loadJson("contracts/error-denial/v0.2/example.json");
  const tampered = structuredClone(error);
  tampered.reason_code = "invalid_request";
  assert.notEqual(selfDigest(tampered), error.verification.value);
});

test("error-denial wrong request_verification fails request binding", () => {
  const denied = loadJson(
    "contracts/execution-request/v0.2/response.denied.example.json",
  );
  const error = loadJson("contracts/error-denial/v0.2/example.json");
  assert.equal(sameVerification(error.request_verification, denied.request_verification), true);
  const tampered = structuredClone(error);
  tampered.request_verification = {
    ...tampered.request_verification,
    value: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  };
  assert.equal(
    sameVerification(tampered.request_verification, denied.request_verification),
    false,
  );
});

test("accepted and denied are intake outcomes only", () => {
  const accepted = loadJson("contracts/execution-request/v0.2/response.accepted.example.json");
  const denied = loadJson("contracts/execution-request/v0.2/response.denied.example.json");
  assert.equal(accepted.outcome, "accepted");
  assert.equal(denied.outcome, "denied");
  assert.equal(Object.hasOwn(accepted, "decision"), false);
  assert.equal(Object.hasOwn(denied, "decision"), false);
});

test("published contract families stay within the admitted public set", () => {
  const allowedFamilies = new Set([
    "capability-consumption",
    "common",
    "error-denial",
    "execution-request",
    "professional-authority-evidence",
    "status-result",
  ]);
  const families = readdirSync(join(repoRoot, "contracts")).filter((name) =>
    statSync(join(repoRoot, "contracts", name)).isDirectory(),
  );
  for (const name of families) {
    assert.equal(allowedFamilies.has(name), true, `unexpected family directory ${name}`);
  }
  assert.equal(existsSync(join(repoRoot, "contracts/capability-consumption/v0.2")), false);
});

test("public fixtures and v0.2 docs have no private or product names", () => {
  const scanRoots = [
    "contracts/common/v0.2",
    "contracts/execution-request/v0.2",
    "contracts/status-result/v0.2",
    "contracts/error-denial/v0.2",
    "contracts/professional-authority-evidence/v1.0",
    "contracts/common/v1.0",
    "tests/conformance/v1.0",
    "tests/conformance/v0.2",
    "vocab",
    "semantics",
    "README.md",
  ];
  const hits = [];
  for (const start of scanRoots) {
    const files = existsSync(join(repoRoot, start)) && statSync(join(repoRoot, start)).isDirectory()
      ? listFiles(start)
      : [start];
    for (const rel of files) {
      const text = readFileSync(join(repoRoot, rel), "utf8");
      for (const hit of forbiddenHits(text)) {
        hits.push(`${rel}: ${hit}`);
      }
    }
  }
  assert.deepEqual(hits, []);
});

test("v0.1 published files remain the frozen baseline", () => {
  const examples = [
    "contracts/execution-request/v0.1/example.json",
    "contracts/status-result/v0.1/example.json",
    "contracts/error-denial/v0.1/example.json",
    "contracts/capability-consumption/v0.1/example.json",
  ];
  for (const rel of examples) {
    const obj = loadJson(rel);
    assert.equal(obj.contract_version, "v0.1");
  }
  const schemas = [
    "contracts/execution-request/v0.1/schema.json",
    "contracts/status-result/v0.1/schema.json",
    "contracts/error-denial/v0.1/schema.json",
    "contracts/capability-consumption/v0.1/schema.json",
  ];
  for (const rel of schemas) {
    const schema = loadJson(rel);
    assert.equal(schema.properties.contract_version.const, "v0.1");
  }
});

const V1_EVIDENCE_SCHEMA =
  "contracts/professional-authority-evidence/v1.0/evidence.schema.json";
const V1_EXAMPLE =
  "contracts/professional-authority-evidence/v1.0/evidence.example.json";
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

function compareUtc(a, b) {
  const left = parseUtc(a);
  const right = parseUtc(b);
  if (left === null || right === null) {
    throw new Error("compareUtc requires calendar-valid UTC timestamps");
  }
  const leftParts = [left.year, left.month, left.day, left.hour, left.minute, left.second];
  const rightParts = [right.year, right.month, right.day, right.hour, right.minute, right.second];
  for (let i = 0; i < leftParts.length; i += 1) {
    if (leftParts[i] < rightParts[i]) {
      return -1;
    }
    if (leftParts[i] > rightParts[i]) {
      return 1;
    }
  }
  const width = Math.max(left.fraction.length, right.fraction.length);
  const leftFraction = left.fraction.padEnd(width, "0");
  const rightFraction = right.fraction.padEnd(width, "0");
  if (leftFraction < rightFraction) {
    return -1;
  }
  if (leftFraction > rightFraction) {
    return 1;
  }
  return 0;
}

function v1PositivePath(name) {
  return `tests/conformance/v1.0/positive/professional-authority-evidence.${name}.json`;
}

function v1SemanticPath(name) {
  return `tests/conformance/v1.0/semantic/professional-authority-evidence.${name}.json`;
}

function v1PositiveFiles() {
  return listFiles("tests/conformance/v1.0/positive")
    .filter((rel) => rel.endsWith(".json"))
    .sort();
}

function bindDigest(obj) {
  const bound = structuredClone(obj);
  bound.verification.value = selfDigest(bound);
  return bound;
}

function refArrays(obj, acc = []) {
  if (obj === null || typeof obj !== "object") {
    return acc;
  }
  if (Array.isArray(obj)) {
    for (const item of obj) {
      refArrays(item, acc);
    }
    return acc;
  }
  for (const [key, value] of Object.entries(obj)) {
    if (key.endsWith("_refs") && Array.isArray(value)) {
      acc.push(value);
    } else {
      refArrays(value, acc);
    }
  }
  return acc;
}

function timestampsOf(obj) {
  return [
    obj.credential?.status_as_of,
    obj.credential?.valid_from,
    obj.credential?.valid_until,
    obj.credential_verification?.verified_at,
    obj.issued_at,
  ].filter((value) => value !== undefined);
}

function assertV1SchemaAndDigest(obj, label) {
  const validate = validatorFor(V1_EVIDENCE_SCHEMA);
  assert.equal(validate(obj), true, `${label} schema: ${formatErrors(validate)}`);
  assert.equal(selfDigest(obj), obj.verification.value, `${label} digest`);
}

function calendarValid(obj) {
  return timestampsOf(obj).every((ts) => parseUtc(ts) !== null);
}

function refsSorted(obj) {
  return refArrays(obj).every((arr) => {
    const sorted = [...arr].sort();
    return arr.length === sorted.length && arr.every((item, i) => item === sorted[i]);
  });
}

function temporalInvariantsHold(obj) {
  if (compareUtc(obj.credential.status_as_of, obj.credential_verification.verified_at) > 0) {
    return false;
  }
  if (compareUtc(obj.credential_verification.verified_at, obj.issued_at) > 0) {
    return false;
  }
  if (obj.credential.valid_from !== undefined && obj.credential.valid_until !== undefined) {
    if (compareUtc(obj.credential.valid_from, obj.credential.valid_until) > 0) {
      return false;
    }
  }
  if (obj.credential.status === "active") {
    if (
      obj.credential.valid_from !== undefined &&
      compareUtc(obj.credential.valid_from, obj.credential.status_as_of) > 0
    ) {
      return false;
    }
    if (
      obj.credential.valid_until !== undefined &&
      compareUtc(obj.credential.status_as_of, obj.credential.valid_until) > 0
    ) {
      return false;
    }
  }
  if (obj.credential.status === "expired") {
    if (obj.credential.valid_until === undefined) {
      return false;
    }
    if (compareUtc(obj.credential.valid_until, obj.credential.status_as_of) > 0) {
      return false;
    }
  }
  return true;
}

function sameLineage(a, b) {
  return (
    a.producer_ref === b.producer_ref &&
    a.credential.credential_ref === b.credential.credential_ref
  );
}

function credentialControlledFacts(obj) {
  return {
    credential_type_ref: obj.credential.credential_type_ref,
    issuer_ref: obj.credential.issuer_ref,
    status: obj.credential.status,
    status_as_of: obj.credential.status_as_of,
    valid_from: obj.credential.valid_from,
    valid_until: obj.credential.valid_until,
    authority_scope_refs: obj.credential.authority_scope_refs,
  };
}

function verificationControlledFacts(obj) {
  return {
    verification_method_ref: obj.credential_verification.verification_method_ref,
    verifier_ref: obj.credential_verification.verifier_ref,
    verified_at: obj.credential_verification.verified_at,
    evidence_refs: obj.credential_verification.evidence_refs,
    resource_revision_refs: obj.credential_verification.resource_revision_refs,
  };
}

function credentialFactsEqual(a, b) {
  return JSON.stringify(credentialControlledFacts(a)) === JSON.stringify(credentialControlledFacts(b));
}

function verificationFactsEqual(a, b) {
  return (
    JSON.stringify(verificationControlledFacts(a)) === JSON.stringify(verificationControlledFacts(b))
  );
}

function credentialRevisionCoherent(predecessor, successor) {
  if (credentialFactsEqual(predecessor, successor)) {
    return true;
  }
  return (
    successor.credential.credential_revision_ref !== predecessor.credential.credential_revision_ref
  );
}

function verificationRevisionCoherent(predecessor, successor) {
  if (verificationFactsEqual(predecessor, successor)) {
    return true;
  }
  return (
    successor.credential_verification.verification_record_revision_ref !==
    predecessor.credential_verification.verification_record_revision_ref
  );
}

function revisionRequiresSupersession(predecessor, successor) {
  if (!sameLineage(predecessor, successor)) {
    return false;
  }
  if (successor.evidence_ref === predecessor.evidence_ref) {
    return false;
  }
  return (
    successor.credential.credential_revision_ref !== predecessor.credential.credential_revision_ref ||
    successor.credential_verification.verification_record_revision_ref !==
      predecessor.credential_verification.verification_record_revision_ref
  );
}

function supersessionCoherent(predecessor, successor) {
  if (Object.hasOwn(successor, "supersedes_evidence_ref")) {
    if (successor.supersedes_evidence_ref === successor.evidence_ref) {
      return false;
    }
    if (successor.supersedes_evidence_ref === predecessor.evidence_ref) {
      return sameLineage(predecessor, successor);
    }
  }
  if (revisionRequiresSupersession(predecessor, successor)) {
    return successor.supersedes_evidence_ref === predecessor.evidence_ref;
  }
  return true;
}

function deleteAtPath(obj, path) {
  const parts = path.split(".");
  let target = obj;
  for (let i = 0; i < parts.length - 1; i += 1) {
    target = target[parts[i]];
  }
  delete target[parts[parts.length - 1]];
}

function successorShell(predecessor) {
  const next = structuredClone(predecessor);
  next.evidence_ref = "evidence-placeholder-successor";
  next.supersedes_evidence_ref = predecessor.evidence_ref;
  return next;
}

test("v1.0 positive wire fixtures validate", async (t) => {
  for (const item of manifest.v1_0_positive) {
    await t.test(item.name, () => {
      const validate = validatorFor(item.schema);
      const fixture = loadJson(item.fixture);
      assert.equal(
        Object.hasOwn(fixture, "example_id"),
        false,
        "v1.0 wire fixtures must not be documentation wrappers",
      );
      assert.equal(
        Object.hasOwn(fixture, "notes"),
        false,
        "v1.0 wire fixtures must not be documentation wrappers",
      );
      assert.equal(validate(fixture), true, formatErrors(validate));
    });
  }
});

test("v1.0 negative wire fixtures are rejected", async (t) => {
  for (const item of manifest.v1_0_negative) {
    await t.test(item.name, () => {
      const validate = validatorFor(item.schema);
      const fixture = loadJson(item.fixture);
      assert.equal(
        validate(fixture),
        false,
        `${item.fixture} unexpectedly validated`,
      );
    });
  }
});

test("S1 v1.0 positive fixtures and example recompute self-digest", () => {
  const files = [V1_EXAMPLE, ...v1PositiveFiles()];
  assert.equal(v1PositiveFiles().length, 13);
  for (const rel of files) {
    const obj = loadJson(rel);
    assert.equal(obj.verification.scheme, DIGEST_SCHEME);
    assert.equal(obj.verification.canonicalization, CANONICALIZATION);
    assert.match(obj.verification.value, /^[0-9a-f]{64}$/);
    assert.equal(selfDigest(obj), obj.verification.value, rel);
  }
});

test("S2 v1.0 field tampering changes the digest", () => {
  const original = loadJson(V1_EXAMPLE);
  const tampered = structuredClone(original);
  tampered.subject_ref = "subject-placeholder-tampered";
  assert.notEqual(selfDigest(tampered), original.verification.value);
  assert.notEqual(selfDigest(tampered), selfDigest(original));
});

test("S3 v1.0 positive _refs arrays are strictly ascending UTF-16", () => {
  for (const rel of v1PositiveFiles()) {
    const obj = loadJson(rel);
    for (const arr of refArrays(obj)) {
      assert.deepEqual(arr, [...arr].sort(), rel);
    }
  }
});

test("S4 v1.0 temporal invariant negatives", async (t) => {
  const cases = [
    ["status-after-verified", (obj) => compareUtc(obj.credential.status_as_of, obj.credential_verification.verified_at) > 0],
    ["verified-after-issued", (obj) => compareUtc(obj.credential_verification.verified_at, obj.issued_at) > 0],
    ["inverted-interval", (obj) => compareUtc(obj.credential.valid_from, obj.credential.valid_until) > 0],
    ["active-before-valid-from", (obj) => obj.credential.status === "active" && compareUtc(obj.credential.valid_from, obj.credential.status_as_of) > 0],
    ["active-after-valid-until", (obj) => obj.credential.status === "active" && compareUtc(obj.credential.status_as_of, obj.credential.valid_until) > 0],
    ["expired-missing-valid-until", (obj) => obj.credential.status === "expired" && obj.credential.valid_until === undefined],
    ["expired-future-valid-until", (obj) => obj.credential.status === "expired" && compareUtc(obj.credential.valid_until, obj.credential.status_as_of) > 0],
  ];
  for (const [name, fails] of cases) {
    await t.test(name, () => {
      const obj = loadJson(v1SemanticPath(name));
      assertV1SchemaAndDigest(obj, name);
      assert.equal(fails(obj), true, `${name} did not fail the intended temporal rule`);
      assert.equal(temporalInvariantsHold(obj), false, `${name} unexpectedly satisfied temporal invariants`);
    });
  }
});

test("S5 v1.0 calendar validity negatives", async (t) => {
  const cases = [
    ["impossible-calendar-day", "2026-02-30T00:00:00Z"],
    ["feb29-non-leap-year", "2026-02-29T00:00:00Z"],
  ];
  for (const [name, bad] of cases) {
    await t.test(name, () => {
      const obj = loadJson(v1SemanticPath(name));
      const validate = validatorFor(V1_EVIDENCE_SCHEMA);
      assert.equal(validate(obj), true, `${name} schema: ${formatErrors(validate)}`);
      assert.equal(selfDigest(obj), obj.verification.value, `${name} digest`);
      assert.equal(parseUtc(bad), null);
      assert.equal(parseUtc(obj.credential.status_as_of), null);
    });
  }
});

test("S6 v1.0 supersession lineage, self-supersession, and cross-lineage", () => {
  const predecessor = loadJson(v1PositivePath("active-individual"));
  const successor = loadJson(v1PositivePath("superseding-new-revision"));
  assertV1SchemaAndDigest(predecessor, "lineage predecessor");
  assertV1SchemaAndDigest(successor, "lineage successor");
  assert.equal(sameLineage(predecessor, successor), true);
  assert.equal(successor.supersedes_evidence_ref, predecessor.evidence_ref);
  assert.notEqual(successor.evidence_ref, predecessor.evidence_ref);
  assert.notEqual(
    successor.credential.credential_revision_ref,
    predecessor.credential.credential_revision_ref,
  );
  assert.equal(supersessionCoherent(predecessor, successor), true);

  const selfSupersession = loadJson(v1SemanticPath("self-supersession"));
  assertV1SchemaAndDigest(selfSupersession, "self-supersession");
  assert.equal(selfSupersession.supersedes_evidence_ref, selfSupersession.evidence_ref);
  assert.equal(supersessionCoherent(selfSupersession, selfSupersession), false);

  const cross = loadJson(v1SemanticPath("cross-lineage-supersession"));
  assertV1SchemaAndDigest(cross, "cross-lineage");
  assert.equal(cross.supersedes_evidence_ref, predecessor.evidence_ref);
  assert.equal(sameLineage(predecessor, cross), false);
  assert.equal(supersessionCoherent(predecessor, cross), false);
});

test("S7 v1.0 byte-identical replay pair", () => {
  const originalPath = join(repoRoot, v1PositivePath("active-individual"));
  const replayPath = join(repoRoot, v1PositivePath("replay-duplicate"));
  assert.deepEqual(readFileSync(originalPath), readFileSync(replayPath));
  const original = loadJson(v1PositivePath("active-individual"));
  const replay = loadJson(v1PositivePath("replay-duplicate"));
  assertV1SchemaAndDigest(original, "replay original");
  assertV1SchemaAndDigest(replay, "replay duplicate");
  assert.equal(rfc8785(digestInput(original)), rfc8785(digestInput(replay)));
  assert.equal(selfDigest(original), selfDigest(replay));
  assert.equal(original.verification.value, replay.verification.value);
  assert.equal(original.evidence_ref, replay.evidence_ref);
});

test("S8 v1.0 same evidence_ref with different bytes is a conflict", () => {
  const original = loadJson(v1PositivePath("active-individual"));
  const conflict = loadJson(v1SemanticPath("conflict-same-ref-different-bytes"));
  assertV1SchemaAndDigest(original, "conflict original");
  assertV1SchemaAndDigest(conflict, "conflict other");
  assert.equal(original.evidence_ref, conflict.evidence_ref);
  const originalInput = digestInput(original);
  const conflictInput = digestInput(conflict);
  assert.equal(Object.hasOwn(originalInput.verification, "value"), false);
  assert.equal(Object.hasOwn(conflictInput.verification, "value"), false);
  assert.notEqual(rfc8785(originalInput), rfc8785(conflictInput));
  assert.notEqual(original.verification.value, conflict.verification.value);
});

test("S9 v1.0 new evidence_ref with unchanged revisions is an ambiguous duplicate", () => {
  const original = loadJson(v1PositivePath("active-individual"));
  const duplicate = loadJson(v1SemanticPath("ambiguous-duplicate-new-ref-same-revisions"));
  assertV1SchemaAndDigest(original, "ambiguous original");
  assertV1SchemaAndDigest(duplicate, "ambiguous duplicate");
  assert.notEqual(original.evidence_ref, duplicate.evidence_ref);
  assert.equal(original.credential.credential_ref, duplicate.credential.credential_ref);
  assert.equal(
    original.credential.credential_revision_ref,
    duplicate.credential.credential_revision_ref,
  );
  assert.equal(
    original.credential_verification.verification_record_ref,
    duplicate.credential_verification.verification_record_ref,
  );
  assert.equal(
    original.credential_verification.verification_record_revision_ref,
    duplicate.credential_verification.verification_record_revision_ref,
  );
});

test("S10 v1.0 missing-required matrix", async (t) => {
  const requiredPaths = [
    "contract_family",
    "contract_version",
    "evidence_type",
    "evidence_ref",
    "producer_ref",
    "subject_ref",
    "subject_kind",
    "professional_domain_ref",
    "jurisdiction_ref",
    "credential",
    "credential_verification",
    "issued_at",
    "verification",
    "credential.credential_ref",
    "credential.credential_revision_ref",
    "credential.credential_type_ref",
    "credential.issuer_ref",
    "credential.status",
    "credential.status_as_of",
    "credential.authority_scope_refs",
    "credential_verification.verification_state",
    "credential_verification.verification_record_ref",
    "credential_verification.verification_record_revision_ref",
    "credential_verification.verification_method_ref",
    "credential_verification.verifier_ref",
    "credential_verification.verified_at",
    "credential_verification.evidence_refs",
    "credential_verification.resource_revision_refs",
  ];
  assert.equal(requiredPaths.length, 28);
  const example = loadJson(V1_EXAMPLE);
  const validate = validatorFor(V1_EVIDENCE_SCHEMA);
  for (const path of requiredPaths) {
    await t.test(`missing ${path}`, () => {
      const clone = structuredClone(example);
      deleteAtPath(clone, path);
      assert.equal(validate(clone), false, `${path} unexpectedly remained valid`);
    });
  }
});

test("S11 v1.0 prohibited-field injection matrix", async (t) => {
  const fields = [
    "allow",
    "deny",
    "decision",
    "outcome",
    "customer_ref",
    "payment",
    "settlement",
    "commission",
    "attachment_content",
    "session_token",
  ];
  const sites = ["", "credential", "credential_verification"];
  const example = loadJson(V1_EXAMPLE);
  const validate = validatorFor(V1_EVIDENCE_SCHEMA);
  for (const field of fields) {
    for (const site of sites) {
      const label = site === "" ? `top-level ${field}` : `${site}.${field}`;
      await t.test(label, () => {
        const clone = structuredClone(example);
        if (site === "") {
          clone[field] = "not-admitted";
        } else {
          clone[site][field] = "not-admitted";
        }
        assert.equal(validate(clone), false, `${label} unexpectedly remained valid`);
      });
    }
  }
});

test("S12 v1.0 producer/consumer canonical vector", () => {
  const producerPath = join(repoRoot, v1PositivePath("producer-vector"));
  const consumerPath = join(repoRoot, v1PositivePath("consumer-vector"));
  assert.deepEqual(readFileSync(producerPath), readFileSync(consumerPath));
  const producer = loadJson(v1PositivePath("producer-vector"));
  const consumer = loadJson(v1PositivePath("consumer-vector"));
  assertV1SchemaAndDigest(producer, "producer-vector");
  assertV1SchemaAndDigest(consumer, "consumer-vector");
  assert.equal(rfc8785(digestInput(producer)), rfc8785(digestInput(consumer)));
  assert.equal(selfDigest(producer), selfDigest(consumer));
  assert.equal(producer.verification.value, consumer.verification.value);
});

test("S13 v1.0 identical semantic input canonicalizes deterministically", () => {
  const first = structuredClone(loadJson(V1_EXAMPLE));
  const second = structuredClone(loadJson(V1_EXAMPLE));
  assert.equal(rfc8785(digestInput(first)), rfc8785(digestInput(second)));
  assert.equal(selfDigest(first), selfDigest(second));
});

test("S14-A v1.0 credential revision coherence", async (t) => {
  const predecessor = loadJson(V1_EXAMPLE);
  assertV1SchemaAndDigest(predecessor, "S14-A predecessor");
  const mutations = [
    ["credential_type_ref", (obj) => {
      obj.credential.credential_type_ref = "credential-type-placeholder-002";
    }],
    ["issuer_ref", (obj) => {
      obj.credential.issuer_ref = "issuer-placeholder-002";
    }],
    ["status", (obj) => {
      obj.credential.status = "inactive";
    }],
    ["status_as_of", (obj) => {
      obj.credential.status_as_of = "2026-08-14T23:59:59Z";
    }],
    ["valid_from", (obj) => {
      obj.credential.valid_from = "2026-08-01T00:00:00Z";
    }],
    ["valid_until", (obj) => {
      obj.credential.valid_until = "2027-08-15T00:00:00Z";
    }],
    ["authority_scope_refs", (obj) => {
      obj.credential.authority_scope_refs = [
        "scope-placeholder-001",
        "scope-placeholder-002",
      ];
    }],
  ];
  for (const [fact, mutate] of mutations) {
    await t.test(`${fact} unchanged credential_revision_ref is rejected`, () => {
      const successor = successorShell(predecessor);
      mutate(successor);
      const bound = bindDigest(successor);
      assertV1SchemaAndDigest(bound, `S14-A reject ${fact}`);
      assert.equal(calendarValid(bound), true);
      assert.equal(refsSorted(bound), true);
      assert.equal(temporalInvariantsHold(bound), true);
      assert.equal(
        bound.credential.credential_revision_ref,
        predecessor.credential.credential_revision_ref,
      );
      assert.equal(credentialRevisionCoherent(predecessor, bound), false);
    });
    await t.test(`${fact} with new credential_revision_ref is accepted`, () => {
      const successor = successorShell(predecessor);
      mutate(successor);
      successor.credential.credential_revision_ref = "credential-revision-placeholder-002";
      const bound = bindDigest(successor);
      assertV1SchemaAndDigest(bound, `S14-A accept ${fact}`);
      assert.equal(calendarValid(bound), true);
      assert.equal(refsSorted(bound), true);
      assert.equal(temporalInvariantsHold(bound), true);
      assert.notEqual(bound.evidence_ref, predecessor.evidence_ref);
      assert.equal(bound.supersedes_evidence_ref, predecessor.evidence_ref);
      assert.notEqual(
        bound.credential.credential_revision_ref,
        predecessor.credential.credential_revision_ref,
      );
      assert.equal(credentialRevisionCoherent(predecessor, bound), true);
    });
  }
});

test("S14-B v1.0 verification revision coherence", async (t) => {
  const predecessor = loadJson(V1_EXAMPLE);
  assertV1SchemaAndDigest(predecessor, "S14-B predecessor");
  const mutations = [
    ["verification_method_ref", (obj) => {
      obj.credential_verification.verification_method_ref = "method-placeholder-002";
    }],
    ["verifier_ref", (obj) => {
      obj.credential_verification.verifier_ref = "verifier-placeholder-002";
    }],
    ["verified_at", (obj) => {
      obj.credential_verification.verified_at = "2026-08-15T00:01:30Z";
    }],
    ["evidence_refs", (obj) => {
      obj.credential_verification.evidence_refs = [
        "source-evidence-placeholder-001",
        "source-evidence-placeholder-002",
      ];
    }],
    ["resource_revision_refs", (obj) => {
      obj.credential_verification.resource_revision_refs = [
        "resource-revision-placeholder-001",
        "resource-revision-placeholder-002",
      ];
    }],
  ];
  for (const [fact, mutate] of mutations) {
    await t.test(`${fact} unchanged verification_record_revision_ref is rejected`, () => {
      const successor = successorShell(predecessor);
      mutate(successor);
      const bound = bindDigest(successor);
      assertV1SchemaAndDigest(bound, `S14-B reject ${fact}`);
      assert.equal(calendarValid(bound), true);
      assert.equal(refsSorted(bound), true);
      assert.equal(temporalInvariantsHold(bound), true);
      assert.equal(
        bound.credential_verification.verification_record_revision_ref,
        predecessor.credential_verification.verification_record_revision_ref,
      );
      assert.equal(verificationRevisionCoherent(predecessor, bound), false);
    });
    await t.test(`${fact} with new verification_record_revision_ref is accepted`, () => {
      const successor = successorShell(predecessor);
      mutate(successor);
      successor.credential_verification.verification_record_revision_ref =
        "verification-revision-placeholder-002";
      const bound = bindDigest(successor);
      assertV1SchemaAndDigest(bound, `S14-B accept ${fact}`);
      assert.equal(calendarValid(bound), true);
      assert.equal(refsSorted(bound), true);
      assert.equal(temporalInvariantsHold(bound), true);
      assert.notEqual(bound.evidence_ref, predecessor.evidence_ref);
      assert.equal(bound.supersedes_evidence_ref, predecessor.evidence_ref);
      assert.notEqual(
        bound.credential_verification.verification_record_revision_ref,
        predecessor.credential_verification.verification_record_revision_ref,
      );
      assert.equal(verificationRevisionCoherent(predecessor, bound), true);
    });
  }
});

test("S14-C v1.0 missing supersession is rejected", () => {
  const predecessor = loadJson(V1_EXAMPLE);
  const successor = structuredClone(predecessor);
  successor.evidence_ref = "evidence-placeholder-successor";
  successor.credential.credential_revision_ref = "credential-revision-placeholder-002";
  const bound = bindDigest(successor);
  assertV1SchemaAndDigest(bound, "S14-C");
  assert.equal(calendarValid(bound), true);
  assert.equal(refsSorted(bound), true);
  assert.equal(temporalInvariantsHold(bound), true);
  assert.equal(sameLineage(predecessor, bound), true);
  assert.notEqual(bound.evidence_ref, predecessor.evidence_ref);
  assert.notEqual(
    bound.credential.credential_revision_ref,
    predecessor.credential.credential_revision_ref,
  );
  assert.equal(Object.hasOwn(bound, "supersedes_evidence_ref"), false);
  assert.equal(revisionRequiresSupersession(predecessor, bound), true);
  assert.equal(supersessionCoherent(predecessor, bound), false);
});

test("v1.0 integrity-mismatch is schema-valid and digest-invalid", () => {
  const obj = loadJson(v1SemanticPath("integrity-mismatch"));
  const validate = validatorFor(V1_EVIDENCE_SCHEMA);
  assert.equal(validate(obj), true, formatErrors(validate));
  assert.notEqual(selfDigest(obj), obj.verification.value);
});

test("v1.0 unsorted-refs is schema-valid, digest-valid, and not sorted", () => {
  const obj = loadJson(v1SemanticPath("unsorted-refs"));
  assertV1SchemaAndDigest(obj, "unsorted-refs");
  assert.equal(refsSorted(obj), false);
});
