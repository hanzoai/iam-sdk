import { test } from "node:test";
import assert from "node:assert/strict";

import { createIamPassportStrategy } from "./passport.js";

// passport-oauth2 stores the resolved endpoints on its internal _oauth2
// instance. Locking them guarantees the strategy hits the canonical
// /v1/iam paths, not the legacy bare /oauth/* paths.
test("passport strategy pins authorize + token to /v1/iam/oauth/*", () => {
  const s = createIamPassportStrategy({
    serverUrl: "https://iam.hanzo.ai",
    clientId: "kms-client",
    clientSecret: "secret",
    callbackUrl: "https://kms.hanzo.ai/v1/sso/oidc/callback",
  }) as { _oauth2: { _authorizeUrl: string; _accessTokenUrl: string } };

  assert.equal(s._oauth2._authorizeUrl, "https://iam.hanzo.ai/v1/iam/oauth/authorize");
  assert.equal(s._oauth2._accessTokenUrl, "https://iam.hanzo.ai/v1/iam/oauth/token");
});

test("passport strategy trims trailing slashes on serverUrl", () => {
  const s = createIamPassportStrategy({
    serverUrl: "https://lux.id/",
    clientId: "c",
    callbackUrl: "https://app/cb",
  }) as { _oauth2: { _authorizeUrl: string; _accessTokenUrl: string } };

  assert.equal(s._oauth2._authorizeUrl, "https://lux.id/v1/iam/oauth/authorize");
  assert.equal(s._oauth2._accessTokenUrl, "https://lux.id/v1/iam/oauth/token");
});
