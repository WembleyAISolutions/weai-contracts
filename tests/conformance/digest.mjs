import { createHash } from "node:crypto";
import canonicalize from "canonicalize";

export const DIGEST_SCHEME = "sha-256";
export const CANONICALIZATION = "rfc8785";

export function rfc8785(value) {
  const canonical = canonicalize(value);
  if (typeof canonical !== "string") {
    throw new TypeError("RFC 8785 canonicalization did not produce a string");
  }
  return canonical;
}

export function digestInput(obj) {
  const copy = structuredClone(obj);
  if (copy.verification && typeof copy.verification === "object") {
    delete copy.verification.value;
  }
  return copy;
}

export function selfDigest(obj) {
  return createHash("sha256").update(rfc8785(digestInput(obj)), "utf8").digest("hex");
}

export function verificationIdentity(obj) {
  return {
    scheme: obj.verification.scheme,
    canonicalization: obj.verification.canonicalization,
    value: obj.verification.value,
  };
}

export function sameVerification(a, b) {
  return (
    a.scheme === b.scheme &&
    a.canonicalization === b.canonicalization &&
    a.value === b.value
  );
}
