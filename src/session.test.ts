/**
 * Tests for the promoted functional auth surface (session.ts).
 *
 * Proves:
 *   - startLogin builds an Authorization-Code + PKCE-S256 authorize URL on the
 *     canonical /v1/iam/oauth/authorize path, discovered (no literal in app code).
 *   - the `provider` knob rides as `&provider=<name>` — one flow, parameterized.
 *   - handleCallback verifies state (CSRF) AND the stored PKCE verifier, then
 *     exchanges the code at the discovered token endpoint with code_verifier.
 *   - getSession / logout operate on the configured singleton's storage.
 */

import { test, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";

import {
  configureIam,
  startLogin,
  getLoginUrl,
  handleCallback,
  getSession,
  logout,
} from "./session.js";

// --- Minimal in-memory Storage ------------------------------------------------

class MemoryStorage implements Storage {
  private m = new Map<string, string>();
  get length() {
    return this.m.size;
  }
  clear(): void {
    this.m.clear();
  }
  getItem(k: string): string | null {
    return this.m.has(k) ? (this.m.get(k) as string) : null;
  }
  key(i: number): string | null {
    return Array.from(this.m.keys())[i] ?? null;
  }
  removeItem(k: string): void {
    this.m.delete(k);
  }
  setItem(k: string, v: string): void {
    this.m.set(k, String(v));
  }
}

// --- Minimal IAM: serves OIDC discovery + token endpoint ----------------------

const CLIENT_ID = "hanzo-demo";
let server: Server;
let origin: string;
let lastTokenBody: URLSearchParams | null = null;

before(async () => {
  server = createServer((req, res) => {
    const url = new URL(req.url ?? "/", origin);
    if (url.pathname === "/.well-known/openid-configuration") {
      res.setHeader("Content-Type", "application/json");
      res.end(
        JSON.stringify({
          issuer: origin,
          authorization_endpoint: `${origin}/v1/iam/oauth/authorize`,
          token_endpoint: `${origin}/v1/iam/oauth/token`,
          userinfo_endpoint: `${origin}/v1/iam/oauth/userinfo`,
          jwks_uri: `${origin}/v1/iam/.well-known/jwks`,
        }),
      );
      return;
    }
    if (url.pathname === "/v1/iam/oauth/token") {
      let raw = "";
      req.on("data", (c) => (raw += c));
      req.on("end", () => {
        lastTokenBody = new URLSearchParams(raw);
        res.setHeader("Content-Type", "application/json");
        res.end(
          JSON.stringify({
            access_token: "at-123",
            token_type: "Bearer",
            expires_in: 3600,
            refresh_token: "rt-123",
          }),
        );
      });
      return;
    }
    res.statusCode = 404;
    res.end("not found");
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(() => server.close());

// Fresh storage + config per test. `window` is stubbed only for redirect.
let storage: MemoryStorage;
beforeEach(() => {
  storage = new MemoryStorage();
  (globalThis as Record<string, unknown>).window = {
    location: { href: "", origin: "https://demo.hanzo.ai" },
  };
  configureIam({
    issuer: origin,
    clientId: CLIENT_ID,
    redirect: "https://demo.hanzo.ai/auth/callback",
    storage,
  });
});

// --- Authorize URL: PKCE + provider knob -------------------------------------

test("getLoginUrl: canonical authorize path, PKCE-S256, no provider by default", async () => {
  const url = new URL(await getLoginUrl());
  assert.equal(url.pathname, "/v1/iam/oauth/authorize");
  assert.equal(url.searchParams.get("client_id"), CLIENT_ID);
  assert.equal(url.searchParams.get("response_type"), "code");
  assert.equal(url.searchParams.get("redirect_uri"), "https://demo.hanzo.ai/auth/callback");
  assert.equal(url.searchParams.get("code_challenge_method"), "S256");
  assert.ok((url.searchParams.get("code_challenge") ?? "").length >= 43, "has PKCE challenge");
  assert.ok(url.searchParams.get("state"), "has state");
  assert.equal(url.searchParams.get("provider"), null, "no provider hint by default");
  // verifier + state persisted for the callback
  assert.ok(storage.getItem("hanzo_iam_code_verifier"), "verifier stashed");
  assert.ok(storage.getItem("hanzo_iam_state"), "state stashed");
});

for (const provider of ["google", "github", "web3"]) {
  test(`getLoginUrl: provider="${provider}" rides as &provider hint (one flow)`, async () => {
    const url = new URL(await getLoginUrl({ provider }));
    assert.equal(url.pathname, "/v1/iam/oauth/authorize");
    assert.equal(url.searchParams.get("provider"), provider);
    assert.equal(url.searchParams.get("code_challenge_method"), "S256");
    assert.ok(url.searchParams.get("code_challenge"), "still PKCE under provider");
  });
}

test("startLogin redirects window.location.href to the authorize URL with provider", async () => {
  await startLogin({ provider: "google", redirect: "https://demo.hanzo.ai/dashboard" });
  const href = (globalThis as Record<string, any>).window.location.href as string;
  const url = new URL(href);
  assert.equal(url.pathname, "/v1/iam/oauth/authorize");
  assert.equal(url.searchParams.get("provider"), "google");
  // post-login redirect stashed for handleCallback (uses real sessionStorage shim)
});

// --- handleCallback: state + verifier verification + token exchange ----------

test("handleCallback rejects a state mismatch (CSRF)", async () => {
  await getLoginUrl(); // seeds verifier + state
  const realState = storage.getItem("hanzo_iam_state");
  assert.ok(realState);
  await assert.rejects(
    () => handleCallback("https://demo.hanzo.ai/auth/callback?code=abc&state=forged"),
    /state mismatch/i,
  );
});

test("handleCallback rejects when the PKCE verifier is missing", async () => {
  // No getLoginUrl() — nothing stashed. A code+state with no verifier must fail.
  storage.setItem("hanzo_iam_state", "s1");
  await assert.rejects(
    () => handleCallback("https://demo.hanzo.ai/auth/callback?code=abc&state=s1"),
    /code verifier/i,
  );
});

test("handleCallback verifies state + exchanges code with the PKCE verifier", async () => {
  await getLoginUrl(); // seeds verifier + state
  const state = storage.getItem("hanzo_iam_state") as string;
  const verifier = storage.getItem("hanzo_iam_code_verifier") as string;
  assert.ok(state && verifier);

  const { token } = await handleCallback(
    `https://demo.hanzo.ai/auth/callback?code=the-code&state=${encodeURIComponent(state)}`,
  );

  assert.equal(token.accessToken, "at-123");
  // the token request carried the verifier + code on the discovered endpoint
  assert.ok(lastTokenBody, "token endpoint was hit");
  assert.equal(lastTokenBody!.get("grant_type"), "authorization_code");
  assert.equal(lastTokenBody!.get("code"), "the-code");
  assert.equal(lastTokenBody!.get("code_verifier"), verifier);
  assert.equal(lastTokenBody!.get("client_id"), CLIENT_ID);

  // session now authenticated; logout clears it
  assert.equal(getSession().authenticated, true);
  assert.equal(getSession().accessToken, "at-123");
  await logout();
  assert.equal(getSession().authenticated, false);
});
