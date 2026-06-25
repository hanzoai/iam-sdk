/**
 * Tests for the framework adapters (sveltekit / remix / express / hono) and
 * the brand→serverUrl map. Each adapter must point at the canonical
 * /v1/iam/oauth/* endpoints and never invent a path.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { BRAND_SERVER_URLS, serverUrlForBrand } from "./paths.js";
import { HanzoIam, HanzoIamProvider } from "./sveltekit.js";
import { hanzoIamStrategyOptions, requireSession, getSession as remixGetSession } from "./remix.js";
import { requireAuth as expressRequireAuth, getIamSession as expressGetSession } from "./express.js";
import { requireAuth as honoRequireAuth, getIamSession as honoGetSession } from "./hono.js";

const IAM = { serverUrl: "https://iam.hanzo.ai", clientId: "hanzo-app", clientSecret: "s3cret" };

// --- paths: brand map ------------------------------------------------------

test("BRAND_SERVER_URLS maps every brand to its canonical origin", () => {
  assert.equal(BRAND_SERVER_URLS.hanzo, "https://iam.hanzo.ai");
  assert.equal(BRAND_SERVER_URLS.lux, "https://lux.id");
  assert.equal(BRAND_SERVER_URLS.zoo, "https://zoo.id");
  assert.equal(BRAND_SERVER_URLS.bootnode, "https://id.bootno.de");
  assert.equal(BRAND_SERVER_URLS.pars, "https://pars.id");
});

test("serverUrlForBrand resolves a brand to its origin", () => {
  assert.equal(serverUrlForBrand("lux"), "https://lux.id");
  assert.equal(serverUrlForBrand("zoo"), "https://zoo.id");
});

// --- sveltekit (Auth.js) ---------------------------------------------------

test("sveltekit HanzoIam is the canonical provider with explicit endpoints", () => {
  assert.equal(HanzoIam, HanzoIamProvider);
  const p = HanzoIam(IAM);
  const authorization = p.authorization as { url: string };
  assert.equal(authorization.url, "https://iam.hanzo.ai/v1/iam/oauth/authorize");
  assert.equal((p.token as { url: string }).url, "https://iam.hanzo.ai/v1/iam/oauth/token");
  assert.equal(p.id, "hanzo-iam");
});

// --- remix -----------------------------------------------------------------

test("remix hanzoIamStrategyOptions pins explicit endpoints + S256 PKCE", () => {
  const opts = hanzoIamStrategyOptions({
    ...IAM,
    redirectURI: "https://app.hanzo.ai/auth/hanzo-iam/callback",
  });
  assert.equal(opts.authorizationEndpoint, "https://iam.hanzo.ai/v1/iam/oauth/authorize");
  assert.equal(opts.tokenEndpoint, "https://iam.hanzo.ai/v1/iam/oauth/token");
  assert.equal(opts.codeChallengeMethod, "S256");
  assert.deepEqual(opts.scopes, ["openid", "profile", "email"]);
  assert.equal(opts.redirectURI, "https://app.hanzo.ai/auth/hanzo-iam/callback");
});

test("remix getSession returns null without a token", async () => {
  const req = new Request("https://app.hanzo.ai/", {});
  const session = await remixGetSession(req, IAM);
  assert.equal(session, null);
});

test("remix requireSession throws a 401 Response without a token", async () => {
  const req = new Request("https://app.hanzo.ai/", {});
  await assert.rejects(
    () => requireSession(req, IAM),
    (err: unknown) => {
      assert.ok(err instanceof Response);
      assert.equal((err as Response).status, 401);
      return true;
    },
  );
});

// --- express ---------------------------------------------------------------

test("express requireAuth 401s a request with no token (no next())", async () => {
  const mw = expressRequireAuth(IAM);
  let statusCode = 0;
  let nexted = false;
  const res = {
    status(code: number) {
      statusCode = code;
      return res;
    },
    json(_body: unknown) {
      return undefined;
    },
  };
  await new Promise<void>((resolve) => {
    mw({ headers: {} }, res, () => {
      nexted = true;
      resolve();
    });
    // requireAuth resolves async; poll a microtask turn
    setTimeout(resolve, 50);
  });
  assert.equal(statusCode, 401);
  assert.equal(nexted, false);
});

test("express getIamSession throws when route was not guarded", () => {
  assert.throws(() => expressGetSession({ headers: {} }), /no session on request/);
});

// --- hono ------------------------------------------------------------------

test("hono requireAuth returns a 401 Response with no token (no next())", async () => {
  const mw = honoRequireAuth(IAM);
  let nexted = false;
  const store = new Map<string, unknown>();
  let jsonStatus = 0;
  const c = {
    req: { raw: new Request("https://app.hanzo.ai/api/me") },
    json(_body: unknown, status?: number) {
      jsonStatus = status ?? 200;
      return new Response(null, { status: status ?? 200 });
    },
    set(k: string, v: unknown) {
      store.set(k, v);
    },
    get(k: string) {
      return store.get(k);
    },
  };
  const res = await mw(c, async () => {
    nexted = true;
  });
  assert.ok(res instanceof Response);
  assert.equal(jsonStatus, 401);
  assert.equal(nexted, false);
});

test("hono getIamSession throws when route was not guarded", () => {
  const store = new Map<string, unknown>();
  const c = {
    req: { raw: new Request("https://app.hanzo.ai/") },
    json: () => new Response(),
    set: (k: string, v: unknown) => void store.set(k, v),
    get: (k: string) => store.get(k),
  };
  assert.throws(() => honoGetSession(c), /no session in context/);
});
