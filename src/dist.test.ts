import { test } from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

// Verifies the SHIPPED dual-format build: every subpath resolves in both
// ESM (import) and CJS (require), exports its public surface, and carries
// no `./billing` entry. Run after `pnpm build`.

const require = createRequire(import.meta.url);
const distUrl = (name: string) => new URL(`../dist/${name}`, import.meta.url);
const distPath = (name: string) => fileURLToPath(distUrl(name));

test("ESM index exports the canonical public surface", async () => {
  const mod = await import(distUrl("index.js").href);
  for (const name of ["IamClient", "IamApiError", "validateToken", "clearJwksCache", "IAM", "toIAMToken", "OIDC_PATHS", "IAM_PATHS", "iamUrl"]) {
    assert.ok(name in mod, `ESM index missing ${name}`);
  }
  assert.equal(mod.OIDC_PATHS.token, "/v1/iam/oauth/token");
});

test("CJS index exports the canonical public surface", () => {
  const mod = require(distPath("index.cjs"));
  for (const name of ["IamClient", "IamApiError", "validateToken", "clearJwksCache", "IAM", "toIAMToken", "OIDC_PATHS", "IAM_PATHS", "iamUrl"]) {
    assert.ok(name in mod, `CJS index missing ${name}`);
  }
  assert.equal(mod.OIDC_PATHS.token, "/v1/iam/oauth/token");
});

test("each subpath resolves in both ESM and CJS", async () => {
  const subpaths = [
    "paths",
    "auth",
    "browser",
    "server",
    "types",
    "react",
    "views",
    "nextauth",
    "sveltekit",
    "remix",
    "express",
    "hono",
    "passport",
    "betterauth",
    "validation",
  ];
  for (const name of subpaths) {
    const esm = await import(distUrl(`${name}.js`).href);
    assert.ok(esm && typeof esm === "object", `ESM ${name} did not load`);
    const cjs = require(distPath(`${name}.cjs`));
    assert.ok(cjs && typeof cjs === "object", `CJS ${name} did not load`);
  }
});

test("betterauth subpath yields the genericOAuth shape in both formats", async () => {
  const esm = await import(distUrl("betterauth.js").href);
  const cjs = require(distPath("betterauth.cjs"));
  const args = { serverUrl: "https://iam.hanzo.ai", clientId: "c", clientSecret: "s" };
  assert.equal(esm.iamProvider(args).tokenUrl, "https://iam.hanzo.ai/v1/iam/oauth/token");
  assert.equal(cjs.iamProvider(args).providerId, "hanzo");
});

test("nextauth subpath ships HanzoIamProvider with EXPLICIT endpoints (no wellKnown)", async () => {
  const esm = await import(distUrl("nextauth.js").href);
  const cjs = require(distPath("nextauth.cjs"));
  for (const mod of [esm, cjs]) {
    assert.equal(typeof mod.HanzoIamProvider, "function", "HanzoIamProvider export missing");
    assert.equal(typeof mod.IamProvider, "function", "IamProvider alias missing");
    const p = mod.HanzoIamProvider({ serverUrl: "https://iam.hanzo.ai", clientId: "c" });
    assert.equal(p.wellKnown, undefined, "must not rely on discovery");
    assert.equal(p.authorization.url, "https://iam.hanzo.ai/v1/iam/oauth/authorize");
    assert.equal(p.token.url, "https://iam.hanzo.ai/v1/iam/oauth/token");
    assert.equal(p.id, "hanzo-iam");
  }
});

test("framework adapters ship and point at canonical endpoints", async () => {
  const sveltekit = await import(distUrl("sveltekit.js").href);
  assert.equal(typeof sveltekit.HanzoIam, "function");
  const remix = await import(distUrl("remix.js").href);
  const opts = remix.hanzoIamStrategyOptions({
    serverUrl: "https://lux.id",
    clientId: "c",
    clientSecret: "s",
    redirectURI: "https://app/cb",
  });
  assert.equal(opts.authorizationEndpoint, "https://lux.id/v1/iam/oauth/authorize");
  const express = require(distPath("express.cjs"));
  assert.equal(typeof express.requireAuth, "function");
  assert.equal(typeof express.getIamSession, "function");
  const hono = require(distPath("hono.cjs"));
  assert.equal(typeof hono.requireAuth, "function");
  assert.equal(typeof hono.getIamSession, "function");
});

test("server subpath yields getServerSession in both formats", async () => {
  const esm = await import(distUrl("server.js").href);
  const cjs = require(distPath("server.cjs"));
  assert.equal(typeof esm.getServerSession, "function");
  assert.equal(typeof cjs.getServerSession, "function");
  assert.equal(esm.SESSION_COOKIE, "hanzo_iam_access_token");
});

test("no billing artifact is shipped", async () => {
  const { existsSync } = await import("node:fs");
  assert.equal(existsSync(distPath("billing.js")), false);
  assert.equal(existsSync(distPath("billing.cjs")), false);
});
