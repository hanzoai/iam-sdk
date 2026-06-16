import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";

import { exportJWK, generateKeyPair, SignJWT, type JWK } from "jose";

import { validateToken, clearJwksCache } from "./auth.js";

// ---------------------------------------------------------------------------
// A minimal IAM that serves OIDC discovery + JWKS and signs RS256 tokens.
// jwks_uri is pinned to the canonical /v1/iam/.well-known/jwks path so the
// happy-path test also proves the SDK follows discovery to that endpoint.
// ---------------------------------------------------------------------------

const CLIENT_ID = "my-app";
const ISSUER_PATH = ""; // server root is the issuer
const JWKS_PATH = "/v1/iam/.well-known/jwks";

let server: Server;
let origin: string;
let privateKey: CryptoKey;
let publicJwk: JWK;
let jwksHits = 0;

before(async () => {
  const kp = await generateKeyPair("RS256");
  privateKey = kp.privateKey;
  publicJwk = { ...(await exportJWK(kp.publicKey)), kid: "test-key", alg: "RS256", use: "sig" };

  server = createServer((req, res) => {
    const url = new URL(req.url ?? "/", origin);
    if (url.pathname === "/.well-known/openid-configuration") {
      res.setHeader("Content-Type", "application/json");
      res.end(
        JSON.stringify({
          issuer: origin + ISSUER_PATH,
          authorization_endpoint: `${origin}/v1/iam/oauth/authorize`,
          token_endpoint: `${origin}/v1/iam/oauth/token`,
          userinfo_endpoint: `${origin}/v1/iam/oauth/userinfo`,
          jwks_uri: `${origin}${JWKS_PATH}`,
        }),
      );
      return;
    }
    if (url.pathname === JWKS_PATH) {
      jwksHits++;
      res.setHeader("Content-Type", "application/json");
      res.end(JSON.stringify({ keys: [publicJwk] }));
      return;
    }
    res.statusCode = 404;
    res.end("not found");
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as AddressInfo).port;
  origin = `http://127.0.0.1:${port}`;
});

after(() => {
  server.close();
});

async function mint(opts: {
  sub?: string;
  aud?: string | string[];
  email?: string;
  owner?: string;
  expSecondsFromNow?: number;
}): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const jwt = new SignJWT({ email: opts.email, owner: opts.owner })
    .setProtectedHeader({ alg: "RS256", kid: "test-key" })
    .setIssuer(origin + ISSUER_PATH)
    .setSubject(opts.sub ?? "acme/alice")
    .setIssuedAt(now)
    .setExpirationTime(now + (opts.expSecondsFromNow ?? 3600));
  if (opts.aud !== undefined) jwt.setAudience(opts.aud);
  return jwt.sign(privateKey);
}

function cfg(extra?: Record<string, unknown>) {
  return { serverUrl: origin, clientId: CLIENT_ID, ...extra };
}

test("happy path: valid token verifies, follows discovery to /v1/iam jwks", async () => {
  clearJwksCache();
  const before = jwksHits;
  const token = await mint({ aud: CLIENT_ID, email: "alice@acme.com", sub: "acme/alice" });
  const result = await validateToken(token, cfg());
  assert.equal(result.ok, true);
  if (result.ok) {
    assert.equal(result.userId, "acme/alice");
    assert.equal(result.owner, "acme");
    assert.equal(result.email, "alice@acme.com");
  }
  assert.ok(jwksHits > before, "JWKS endpoint (/v1/iam/.well-known/jwks) was fetched");
});

test("missing token fails closed", async () => {
  const result = await validateToken("", cfg());
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.reason, "iam_token_missing");
});

test("expired token fails with iam_token_expired", async () => {
  clearJwksCache();
  const token = await mint({ aud: CLIENT_ID, expSecondsFromNow: -120 });
  const result = await validateToken(token, cfg());
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.reason, "iam_token_expired");
});

test("wrong audience FAILS by default (no silent retry)", async () => {
  clearJwksCache();
  const token = await mint({ aud: "some-other-client" });
  const result = await validateToken(token, cfg());
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.reason, "iam_audience_invalid");
});

test("missing-aud token FAILS by default", async () => {
  clearJwksCache();
  const token = await mint({}); // no aud claim
  const result = await validateToken(token, cfg());
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.reason, "iam_audience_invalid");
});

test("allowMissingAudience=true accepts a token without aud", async () => {
  clearJwksCache();
  const token = await mint({ sub: "acme/bob", owner: "acme" });
  const result = await validateToken(token, cfg({ allowMissingAudience: true }));
  assert.equal(result.ok, true);
  if (result.ok) assert.equal(result.owner, "acme");
});

test("allowMissingAudience=true still verifies signature (tampered token fails)", async () => {
  clearJwksCache();
  const token = await mint({ sub: "acme/bob" });
  const tampered = token.slice(0, -3) + "AAA";
  const result = await validateToken(tampered, cfg({ allowMissingAudience: true }));
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.reason, "iam_signature_invalid");
});
