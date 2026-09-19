import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

// Verifies the SHIPPED dual-format build: every file package.json names is
// built and packed, every subpath loads in both ESM (import) and CJS
// (require) and typechecks for both kinds of consumer, the public surface is
// there, and no `./billing` entry ships. Run after `pnpm build`.

const require = createRequire(import.meta.url);
const root = fileURLToPath(new URL("..", import.meta.url));
const distUrl = (name: string) => new URL(`../dist/${name}`, import.meta.url);
const distPath = (name: string) => fileURLToPath(distUrl(name));

const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));

// Every file an exports condition names, plus main, module and types. There
// are no `types` conditions: TypeScript types a .js by the .d.ts beside it and
// a .cjs by the .d.cts, so those ship too.
const targets = (node: unknown): string[] =>
  typeof node === "string" ? [node] : Object.values(node as object).flatMap(targets);
const named = [pkg.main, pkg.module, pkg.types, ...targets(pkg.exports)].map((file: string) =>
  file.replace(/^\.\//, ""),
);
const declarationOf = (file: string) => file.replace(/\.js$/, ".d.ts").replace(/\.cjs$/, ".d.cts");
const shipped: string[] = [...new Set(named.flatMap((file: string) => [file, declarationOf(file)]))];

// "@hanzo/iam", "@hanzo/iam/auth", …: one specifier per exports entry.
const specifiers = Object.keys(pkg.exports).map((key) => pkg.name + key.slice(1));

// The tarball `pnpm pack` makes, which is what a user installs. Scripts off,
// so packing reads the build instead of redoing it under the tests that read
// it. (npm 10's pack runs `prepare` even with --ignore-scripts; pnpm honours
// the setting.)
const work = mkdtempSync(join(tmpdir(), "iam-dist-"));
let tarball: string;
let packed: Set<string>;

before(() => {
  const { filename, files } = JSON.parse(
    execFileSync("pnpm", ["pack", "--json", "--pack-destination", work, "--config.ignore-scripts=true"], {
      cwd: root,
      encoding: "utf8",
    }),
  );
  tarball = join(work, basename(filename));
  packed = new Set(files.map((file: { path: string }) => file.path));
});

after(() => rmSync(work, { recursive: true, force: true }));

test("every file package.json names is built, with its declarations", () => {
  assert.deepEqual(shipped.filter((file) => !existsSync(join(root, file))), []);
});

test("the packed tarball holds every file package.json names, and no tests", () => {
  assert.deepEqual(shipped.filter((file) => !packed.has(file)), []);
  assert.deepEqual([...packed].filter((file) => file.endsWith(".test.ts")), []);
});

test("CommonJS and ES module consumers typecheck against every subpath", () => {
  // The consumer has what an install gives it: the tarball, the packages in
  // `dependencies`, and React's types, which an app using the react or views
  // subpath installs beside react, the peer. Nothing from this repo's
  // devDependencies is there, so a declaration that needs one fails here as
  // it would for a user. It imports every subpath from a .cts (the `require`
  // condition) and a .mts (`import`). node16 cannot require() an ES module,
  // so a CommonJS build typed as ESM fails with TS1479; skipLibCheck stays
  // off so the declarations themselves are checked too.
  const dir = join(work, "consumer");
  const installed = join(dir, "node_modules", pkg.name);
  mkdirSync(installed, { recursive: true });
  execFileSync("tar", ["-xzf", tarball, "-C", installed, "--strip-components=1"]);
  for (const name of [...Object.keys(pkg.dependencies), "@types/react"]) {
    const link = join(dir, "node_modules", name);
    mkdirSync(dirname(link), { recursive: true });
    symlinkSync(realpathSync(join(root, "node_modules", name)), link, "dir");
  }
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

test("each subpath loads through the exports map in both ESM and CJS", async () => {
  for (const specifier of specifiers) {
    const esm = await import(specifier);
    assert.ok(esm && typeof esm === "object", `ESM ${specifier} did not load`);
    const cjs = require(specifier);
    assert.ok(cjs && typeof cjs === "object", `CJS ${specifier} did not load`);
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
