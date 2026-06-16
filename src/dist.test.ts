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
