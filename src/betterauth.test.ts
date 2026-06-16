import { test } from "node:test";
import assert from "node:assert/strict";

import { iamProvider } from "./betterauth.js";

test("iamProvider returns the exact better-auth genericOAuth shape", () => {
  const cfg = iamProvider({
    serverUrl: "https://iam.hanzo.ai",
    clientId: "my-app",
    clientSecret: "shh",
  });

  assert.deepEqual(cfg, {
    providerId: "hanzo",
    authorizationUrl: "https://iam.hanzo.ai/v1/iam/oauth/authorize",
    tokenUrl: "https://iam.hanzo.ai/v1/iam/oauth/token",
    userInfoUrl: "https://iam.hanzo.ai/v1/iam/oauth/userinfo",
    clientId: "my-app",
    clientSecret: "shh",
    scopes: ["openid", "profile", "email"],
    pkce: true,
    authentication: "basic",
  });
});

test("iamProvider has no discoveryUrl (paths are pinned, no magic discovery)", () => {
  const cfg = iamProvider({ serverUrl: "https://lux.id", clientId: "x" }) as unknown as Record<string, unknown>;
  assert.ok(!("discoveryUrl" in cfg));
  assert.equal(cfg.authorizationUrl, "https://lux.id/v1/iam/oauth/authorize");
});

test("iamProvider works for any brand origin", () => {
  const cfg = iamProvider({ serverUrl: "https://id.bootno.de/", clientId: "bootnode-app" });
  assert.equal(cfg.tokenUrl, "https://id.bootno.de/v1/iam/oauth/token");
  assert.equal(cfg.userInfoUrl, "https://id.bootno.de/v1/iam/oauth/userinfo");
  assert.equal(cfg.providerId, "hanzo");
});
