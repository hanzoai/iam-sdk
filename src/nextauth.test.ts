import { test } from "node:test";
import assert from "node:assert/strict";

import { HanzoIamProvider, IamProvider } from "./nextauth.js";

test("HanzoIamProvider uses EXPLICIT endpoints from paths.ts — never discovery", () => {
  const p = HanzoIamProvider({ serverUrl: "https://iam.hanzo.ai", clientId: "my-app" });
  // No wellKnown/discovery reliance.
  assert.equal(p.wellKnown, undefined);
  const authorization = p.authorization as { url: string; params: { scope: string } };
  const token = p.token as { url: string };
  const userinfo = p.userinfo as { url: string };
  assert.equal(authorization.url, "https://iam.hanzo.ai/v1/iam/oauth/authorize");
  assert.equal(token.url, "https://iam.hanzo.ai/v1/iam/oauth/token");
  assert.equal(userinfo.url, "https://iam.hanzo.ai/v1/iam/oauth/userinfo");
  assert.equal(p.jwks_endpoint, "https://iam.hanzo.ai/v1/iam/.well-known/jwks");
  assert.equal(p.issuer, "https://iam.hanzo.ai");
});

test("HanzoIamProvider default id is the canonical 'hanzo-iam'", () => {
  const p = HanzoIamProvider({ serverUrl: "https://iam.hanzo.ai", clientId: "my-app" });
  assert.equal(p.id, "hanzo-iam");
});

test("HanzoIamProvider pins client_secret_basic token auth", () => {
  const p = HanzoIamProvider({ serverUrl: "https://iam.hanzo.ai", clientId: "my-app" });
  const client = p.client as { token_endpoint_auth_method: string };
  assert.equal(client.token_endpoint_auth_method, "client_secret_basic");
});

test("HanzoIamProvider defaults checks to include pkce (not just state)", () => {
  const p = HanzoIamProvider({ serverUrl: "https://iam.hanzo.ai", clientId: "my-app" });
  assert.deepEqual(p.checks, ["state", "pkce"]);
});

test("HanzoIamProvider honors explicit checks override", () => {
  const p = HanzoIamProvider({
    serverUrl: "https://iam.hanzo.ai",
    clientId: "my-app",
    checks: ["pkce"],
  });
  assert.deepEqual(p.checks, ["pkce"]);
});

test("HanzoIamProvider requests openid profile email scopes", () => {
  const p = HanzoIamProvider({ serverUrl: "https://iam.hanzo.ai", clientId: "my-app" });
  const authorization = p.authorization as { params: { scope: string } };
  assert.equal(authorization.params.scope, "openid profile email");
});

test("HanzoIamProvider trims a trailing slash on serverUrl", () => {
  const p = HanzoIamProvider({ serverUrl: "https://iam.hanzo.ai/", clientId: "my-app" });
  const token = p.token as { url: string };
  assert.equal(token.url, "https://iam.hanzo.ai/v1/iam/oauth/token");
});

test("IamProvider is the same function as HanzoIamProvider (canonical alias)", () => {
  assert.equal(IamProvider, HanzoIamProvider);
});

test("profile() maps OIDC claims to the NextAuth user shape", () => {
  const p = HanzoIamProvider({ serverUrl: "https://iam.hanzo.ai", clientId: "my-app" });
  const profile = p.profile as (x: Record<string, unknown>) => Record<string, unknown>;
  const u = profile({ sub: "hanzo/alice", name: "Alice", email: "a@hanzo.ai", picture: "p.png" });
  assert.equal(u.id, "hanzo/alice");
  assert.equal(u.name, "Alice");
  assert.equal(u.email, "a@hanzo.ai");
  assert.equal(u.image, "p.png");
});
