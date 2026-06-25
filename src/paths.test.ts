import { test } from "node:test";
import assert from "node:assert/strict";

import {
  OIDC_PATHS,
  IAM_PATHS,
  BRAND_SERVER_URLS,
  iamUrl,
  trimServerUrl,
  serverUrlForBrand,
} from "./paths.js";

// The canonical paths are LOCKED. If any of these change, every Hanzo
// client breaks against the IAM HTML SPA catch-all — so the test pins
// the exact strings.
test("OIDC_PATHS are the canonical /v1/iam values", () => {
  assert.equal(OIDC_PATHS.discovery, "/.well-known/openid-configuration");
  assert.equal(OIDC_PATHS.authorize, "/v1/iam/oauth/authorize");
  assert.equal(OIDC_PATHS.token, "/v1/iam/oauth/token");
  assert.equal(OIDC_PATHS.userinfo, "/v1/iam/oauth/userinfo");
  assert.equal(OIDC_PATHS.jwks, "/v1/iam/.well-known/jwks");
  assert.equal(OIDC_PATHS.logout, "/v1/iam/oauth/logout");
});

test("no legacy /oauth/* or /api/login/* paths exist", () => {
  for (const value of Object.values(OIDC_PATHS)) {
    assert.ok(!/^\/oauth\//.test(value), `legacy bare /oauth path: ${value}`);
    assert.ok(!value.includes("/api/login"), `legacy /api/login path: ${value}`);
  }
});

test("IAM_PATHS for non-OIDC endpoints sit under /v1/iam", () => {
  assert.equal(IAM_PATHS.authMethods, "/v1/iam/auth/methods");
  assert.equal(IAM_PATHS.onboarding, "/v1/iam/onboarding");
});

test("iamUrl concatenates origin + canonical path, trimming slashes", () => {
  assert.equal(iamUrl("https://iam.hanzo.ai", "token"), "https://iam.hanzo.ai/v1/iam/oauth/token");
  assert.equal(iamUrl("https://lux.id/", "authorize"), "https://lux.id/v1/iam/oauth/authorize");
  assert.equal(iamUrl("https://zoo.id///", "userinfo"), "https://zoo.id/v1/iam/oauth/userinfo");
  assert.equal(iamUrl("https://id.bootno.de", "jwks"), "https://id.bootno.de/v1/iam/.well-known/jwks");
});

test("trimServerUrl strips trailing slashes only", () => {
  assert.equal(trimServerUrl("https://iam.hanzo.ai/"), "https://iam.hanzo.ai");
  assert.equal(trimServerUrl("https://iam.hanzo.ai"), "https://iam.hanzo.ai");
  assert.equal(trimServerUrl("https://iam.hanzo.ai///"), "https://iam.hanzo.ai");
});

test("BRAND_SERVER_URLS is the single brand→origin source of truth", () => {
  assert.deepEqual(BRAND_SERVER_URLS, {
    hanzo: "https://iam.hanzo.ai",
    lux: "https://lux.id",
    zoo: "https://zoo.id",
    bootnode: "https://id.bootno.de",
    pars: "https://pars.id",
  });
});

test("serverUrlForBrand resolves each brand", () => {
  assert.equal(serverUrlForBrand("hanzo"), "https://iam.hanzo.ai");
  assert.equal(serverUrlForBrand("lux"), "https://lux.id");
  assert.equal(serverUrlForBrand("zoo"), "https://zoo.id");
  assert.equal(serverUrlForBrand("bootnode"), "https://id.bootno.de");
  assert.equal(serverUrlForBrand("pars"), "https://pars.id");
});
