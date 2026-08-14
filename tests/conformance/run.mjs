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
