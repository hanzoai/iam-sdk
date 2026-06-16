import { test } from "node:test";
import assert from "node:assert/strict";

import { IamProvider } from "./nextauth.js";

test("IamProvider points wellKnown at OIDC discovery", () => {
  const p = IamProvider({ serverUrl: "https://iam.hanzo.ai", clientId: "my-app" });
  assert.equal(p.wellKnown, "https://iam.hanzo.ai/.well-known/openid-configuration");
});

test("IamProvider defaults checks to include pkce (not just state)", () => {
  const p = IamProvider({ serverUrl: "https://iam.hanzo.ai", clientId: "my-app" });
  assert.deepEqual(p.checks, ["state", "pkce"]);
});

test("IamProvider honors explicit checks override", () => {
  const p = IamProvider({
    serverUrl: "https://iam.hanzo.ai",
    clientId: "my-app",
    checks: ["pkce"],
  });
  assert.deepEqual(p.checks, ["pkce"]);
});

test("IamProvider requests openid profile email scopes", () => {
  const p = IamProvider({ serverUrl: "https://iam.hanzo.ai", clientId: "my-app" });
  const authorization = p.authorization as { params: { scope: string } };
  assert.equal(authorization.params.scope, "openid profile email");
});
