import { test } from "node:test";
import assert from "node:assert/strict";

import { generatePKCEChallenge, generateState } from "./pkce.js";

function base64UrlByteLength(s: string): number {
  // base64url decode length: 4 chars → 3 bytes, minus padding removed.
  const padded = s + "=".repeat((4 - (s.length % 4)) % 4);
  return Buffer.from(padded.replace(/-/g, "+").replace(/_/g, "/"), "base64").length;
}

test("code verifier carries >= 256 bits of entropy", async () => {
  const { codeVerifier } = await generatePKCEChallenge();
  // 32 random bytes = 256 bits.
  assert.equal(base64UrlByteLength(codeVerifier), 32);
});

test("code verifier is RFC 7636 base64url, 43-128 chars", async () => {
  const { codeVerifier } = await generatePKCEChallenge();
  assert.match(codeVerifier, /^[A-Za-z0-9\-_]+$/);
  assert.ok(codeVerifier.length >= 43 && codeVerifier.length <= 128, `len=${codeVerifier.length}`);
});

test("challenge is the base64url SHA-256 of the verifier (S256)", async () => {
  const { codeVerifier, codeChallenge } = await generatePKCEChallenge();
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(codeVerifier));
  const expected = Buffer.from(new Uint8Array(digest))
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  assert.equal(codeChallenge, expected);
  assert.equal(base64UrlByteLength(codeChallenge), 32);
});

test("state carries >= 256 bits of entropy and is unique per call", () => {
  const a = generateState();
  const b = generateState();
  assert.equal(base64UrlByteLength(a), 32);
  assert.notEqual(a, b);
});

test("verifiers are unique per call", async () => {
  const a = await generatePKCEChallenge();
  const b = await generatePKCEChallenge();
  assert.notEqual(a.codeVerifier, b.codeVerifier);
  assert.notEqual(a.codeChallenge, b.codeChallenge);
});
