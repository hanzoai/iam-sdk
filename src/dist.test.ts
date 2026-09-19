import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

// Verifies the SHIPPED dual-format build: every subpath resolves in both
// ESM (import) and CJS (require) and typechecks for both kinds of consumer,
// exports its public surface, and carries no `./billing` entry. Run after
// `pnpm build`.

const require = createRequire(import.meta.url);
const root = fileURLToPath(new URL("..", import.meta.url));
const distUrl = (name: string) => new URL(`../dist/${name}`, import.meta.url);
const distPath = (name: string) => fileURLToPath(distUrl(name));

const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));

// "@hanzo/iam", "@hanzo/iam/auth", …: one specifier per exports entry.
const specifiers = Object.keys(pkg.exports).map((key) => pkg.name + key.slice(1));

test("CommonJS and ES module consumers typecheck against every subpath", (t) => {
  // A consumer with this package installed imports every subpath from a .cts
  // (the `require` condition) and a .mts (`import`). node16 cannot require()
  // an ES module, so a CommonJS build typed as ESM fails here with TS1479;
  // skipLibCheck stays off so the declarations themselves are checked too.
  const dir = mkdtempSync(join(tmpdir(), "iam-consumer-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  mkdirSync(join(dir, "node_modules", "@hanzo"), { recursive: true });
  symlinkSync(root, join(dir, "node_modules", "@hanzo", "iam"), "dir");
  const source =
    specifiers.map((specifier, i) => `import * as m${i} from "${specifier}";`).join("\n") +
    `\nexport const all = [${specifiers.map((_, i) => `m${i}`).join(", ")}];\n`;
  writeFileSync(join(dir, "consumer.cts"), source);
  writeFileSync(join(dir, "consumer.mts"), source);
  writeFileSync(
    join(dir, "tsconfig.json"),
    JSON.stringify({
      compilerOptions: { module: "node16", target: "es2022", lib: ["es2022", "dom"], strict: true, noEmit: true, types: [] },
      files: ["consumer.cts", "consumer.mts"],
    }),
  );
  const tsc = spawnSync(process.execPath, [join(root, "node_modules/typescript/bin/tsc"), "-p", dir], {
    encoding: "utf8",
  });
  assert.ifError(tsc.error);
  assert.equal(tsc.status, 0, tsc.stdout + tsc.stderr);
});

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
