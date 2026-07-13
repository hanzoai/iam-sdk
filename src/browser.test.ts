/**
 * Tests for the IN-PLACE login surface added in v0.13.4:
 *
 *   - signinPopup: the postMessage handshake. Proves the three mandatory
 *     gates — ORIGIN allowlist (foreign origins are dropped, never settle),
 *     STATE/CSRF (a forged state rejects), and one-shot teardown (listener +
 *     popup are removed) — and that the happy path runs the SAME PKCE token
 *     exchange with the stored verifier.
 *   - completePopupSignin: the popup callback bridge posts `{code,state}` to
 *     the opener with `targetOrigin` PINNED to its own origin (never "*"),
 *     and no-ops (returns false) for a normal top-level navigation.
 *   - loginWithWallet: inline SIWx — nonce → personal_sign(server message) →
 *     verify → PKCE-bound code → handleCallback. No redirect. The signature +
 *     message are sent for server-side recovery; the address is only a hint.
 */

import { test, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";

import { IAM, POPUP_WINDOW_NAME } from "./browser.js";

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

// --- Fake browser window (message bus + popup) --------------------------------

class FakePopup {
  closed = false;
  close(): void {
    this.closed = true;
  }
}

type MessageHandler = (e: { origin: string; data: unknown; source?: unknown }) => void;

class FakeWindow {
  private listeners = new Map<string, MessageHandler[]>();
  screenX = 0;
  screenY = 0;
  outerWidth = 1024;
  outerHeight = 768;
  location = { href: "https://demo.hanzo.ai/", origin: "https://demo.hanzo.ai" };
  opener: unknown = null;
  lastPopup: FakePopup | null = null;
  openReturnsNull = false;

  addEventListener(type: string, fn: MessageHandler): void {
    const arr = this.listeners.get(type) ?? [];
    arr.push(fn);
    this.listeners.set(type, arr);
  }
  removeEventListener(type: string, fn: MessageHandler): void {
    const arr = this.listeners.get(type);
    if (!arr) return;
    const i = arr.indexOf(fn);
    if (i >= 0) arr.splice(i, 1);
  }
  open(): FakePopup | null {
    if (this.openReturnsNull) return null;
    this.lastPopup = new FakePopup();
    return this.lastPopup;
  }
  close(): void {
    /* used only by completePopupSignin tests via a plain object */
  }
  dispatchMessage(ev: { origin: string; data: unknown; source?: unknown }): void {
    for (const fn of [...(this.listeners.get("message") ?? [])]) fn(ev);
  }
  get messageListenerCount(): number {
    return (this.listeners.get("message") ?? []).length;
  }
}

async function waitFor(cond: () => boolean, timeoutMs = 2000): Promise<void> {
  const start = Date.now();
  while (!cond()) {
    if (Date.now() - start > timeoutMs) throw new Error("waitFor: condition never met");
    await new Promise((r) => setTimeout(r, 5));
  }
}

// --- IAM server: discovery + token + web3 nonce/verify ------------------------

const CLIENT_ID = "hanzo-demo";
const REDIRECT = "https://demo.hanzo.ai/auth/callback";
const SIWE_MESSAGE =
  "demo.hanzo.ai wants you to sign in with your Ethereum account:\n0xabc...\n\nNonce: n-siwe-1";

let server: Server;
let origin: string;
let lastTokenBody: URLSearchParams | null = null;
let lastNonceUrl: string | null = null;
let lastVerify: { url: string; body: Record<string, unknown> } | null = null;

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
    if (url.pathname === "/v1/iam/web3/nonce") {
      lastNonceUrl = req.url ?? "";
      res.setHeader("Content-Type", "application/json");
      res.end(JSON.stringify({ status: "ok", data: { nonce: "n-siwe-1", message: SIWE_MESSAGE } }));
      return;
    }
    if (url.pathname === "/v1/iam/web3/verify") {
      let raw = "";
      req.on("data", (c) => (raw += c));
      req.on("end", () => {
        lastVerify = { url: req.url ?? "", body: JSON.parse(raw || "{}") };
        res.setHeader("Content-Type", "application/json");
        res.end(JSON.stringify({ status: "ok", data: "wallet-code" }));
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

let storage: MemoryStorage;
beforeEach(() => {
  storage = new MemoryStorage();
  lastTokenBody = null;
  lastNonceUrl = null;
  lastVerify = null;
});

function newIam(): IAM {
  return new IAM({ serverUrl: origin, clientId: CLIENT_ID, redirectUri: REDIRECT, storage });
}

// ============================================================================
// signinPopup — origin gate, CSRF gate, teardown, token exchange
// ============================================================================

test("signinPopup: drops a foreign-origin message and completes on the callback origin", async () => {
  const win = new FakeWindow();
  (globalThis as Record<string, unknown>).window = win;
  const iam = newIam();

  const p = iam.signinPopup({ additionalParams: { provider: "google" }, timeoutMs: 4000 });
  await waitFor(() => win.messageListenerCount > 0);
  const state = storage.getItem("hanzo_iam_state");
  assert.ok(state, "opener stashed the state it generated");

  // Gate 1: a message from a foreign origin — even carrying the RIGHT state —
  // must be ignored (not settle the promise, not hijack the flow).
  win.dispatchMessage({
    origin: "https://evil.example.com",
    data: { source: "hanzo-iam", code: "attacker-code", state },
  });

  // The legitimate callback origin then delivers the real code.
  win.dispatchMessage({
    origin: "https://demo.hanzo.ai",
    data: { source: "hanzo-iam", code: "good-code", state },
  });

  const token = await p;
  assert.equal(token.accessToken, "at-123");
  // The token exchange used the GOOD code (attacker's was dropped) + the
  // stored PKCE verifier — the exact same exchange the redirect path uses.
  assert.equal(lastTokenBody?.get("code"), "good-code");
  assert.ok((lastTokenBody?.get("code_verifier") ?? "").length >= 43, "PKCE verifier sent");
  // One-shot teardown: listener removed, popup closed.
  assert.equal(win.messageListenerCount, 0, "message listener torn down");
  assert.equal(win.lastPopup?.closed, true, "popup closed");
});

test("signinPopup: rejects a forged state from the callback origin (CSRF)", async () => {
  const win = new FakeWindow();
  (globalThis as Record<string, unknown>).window = win;
  const iam = newIam();

  const p = iam.signinPopup({ additionalParams: { provider: "github" }, timeoutMs: 4000 });
  await waitFor(() => win.messageListenerCount > 0);

  win.dispatchMessage({
    origin: "https://demo.hanzo.ai",
    data: { source: "hanzo-iam", code: "good-code", state: "forged-state" },
  });

  await assert.rejects(() => p, /state mismatch/i);
  assert.equal(lastTokenBody, null, "no token exchange on a CSRF-mismatched state");
  assert.equal(win.messageListenerCount, 0, "listener torn down on reject");
});

test("signinPopup: ignores untagged same-origin postMessage chatter", async () => {
  const win = new FakeWindow();
  (globalThis as Record<string, unknown>).window = win;
  const iam = newIam();

  const p = iam.signinPopup({ timeoutMs: 4000 });
  await waitFor(() => win.messageListenerCount > 0);
  const state = storage.getItem("hanzo_iam_state");

  // Right origin, but no `source: "hanzo-iam"` tag — unrelated app chatter.
  win.dispatchMessage({ origin: "https://demo.hanzo.ai", data: { hello: "world", state } });
  // Still pending: the real message settles it.
  win.dispatchMessage({
    origin: "https://demo.hanzo.ai",
    data: { source: "hanzo-iam", code: "c2", state },
  });

  const token = await p;
  assert.equal(token.accessToken, "at-123");
  assert.equal(lastTokenBody?.get("code"), "c2");
});

test("signinPopup: rejects when the popup is blocked", async () => {
  const win = new FakeWindow();
  win.openReturnsNull = true;
  (globalThis as Record<string, unknown>).window = win;
  const iam = newIam();
  await assert.rejects(() => iam.signinPopup(), /blocked by browser/i);
});

test("signinPopup: fail-secure — rejects (no token) when no message ever arrives", async () => {
  const win = new FakeWindow();
  (globalThis as Record<string, unknown>).window = win;
  const iam = newIam();
  await assert.rejects(() => iam.signinPopup({ timeoutMs: 150 }), /timed out/i);
  assert.equal(win.messageListenerCount, 0, "listener torn down on timeout");
  assert.equal(lastTokenBody, null, "no token exchange on timeout");
});

// ============================================================================
// completePopupSignin — the popup callback-page bridge
// ============================================================================

test("completePopupSignin: posts code+state to the opener with a PINNED origin, then closes", async () => {
  const { completePopupSignin } = await import("./browser.js");
  let captured: { msg: unknown; targetOrigin: unknown } | null = null;
  let closed = false;

  (globalThis as Record<string, unknown>).window = {
    name: POPUP_WINDOW_NAME,
    opener: {
      postMessage: (msg: unknown, targetOrigin: unknown) => {
        captured = { msg, targetOrigin };
      },
    },
    location: {
      href: "https://demo.hanzo.ai/auth/callback?code=CB-CODE&state=CB-STATE",
      origin: "https://demo.hanzo.ai",
    },
    close: () => {
      closed = true;
    },
  };

  const handled = completePopupSignin();
  assert.equal(handled, true);
  assert.ok(captured, "posted a message");
  // targetOrigin is PINNED to the callback's own origin — never "*".
  assert.equal((captured as { targetOrigin: unknown }).targetOrigin, "https://demo.hanzo.ai");
  const msg = (captured as { msg: Record<string, unknown> }).msg;
  assert.equal(msg.source, "hanzo-iam");
  assert.equal(msg.code, "CB-CODE");
  assert.equal(msg.state, "CB-STATE");
  assert.equal(closed, true, "popup closed itself");
});

test("completePopupSignin: window.name gate — inert on a non-popup page even with opener + ?code", async () => {
  const { completePopupSignin } = await import("./browser.js");
  let posted = false;
  let closed = false;
  (globalThis as Record<string, unknown>).window = {
    name: "", // NOT the reserved popup name — this is an ordinary tab
    opener: { postMessage: () => (posted = true) },
    location: { href: "https://demo.hanzo.ai/auth/callback?code=X&state=Y", origin: "https://demo.hanzo.ai" },
    close: () => (closed = true),
  };
  assert.equal(completePopupSignin(), false);
  assert.equal(posted, false, "must not post from a non-popup page");
  assert.equal(closed, false, "must not close a non-popup page");
});

test("completePopupSignin: returns false when there is no opener (normal navigation)", async () => {
  const { completePopupSignin } = await import("./browser.js");
  (globalThis as Record<string, unknown>).window = {
    name: POPUP_WINDOW_NAME,
    opener: null,
    location: { href: "https://demo.hanzo.ai/auth/callback?code=X&state=Y", origin: "https://demo.hanzo.ai" },
    close: () => {},
  };
  assert.equal(completePopupSignin(), false);
});

test("completePopupSignin: returns false when the URL carries no code/error", async () => {
  const { completePopupSignin } = await import("./browser.js");
  let posted = false;
  (globalThis as Record<string, unknown>).window = {
    name: POPUP_WINDOW_NAME,
    opener: { postMessage: () => (posted = true) },
    location: { href: "https://demo.hanzo.ai/dashboard", origin: "https://demo.hanzo.ai" },
    close: () => {},
  };
  assert.equal(completePopupSignin(), false);
  assert.equal(posted, false, "no message posted for a non-callback page");
});

// ============================================================================
// loginWithWallet — inline SIWx (EIP-4361), no redirect
// ============================================================================

test("loginWithWallet: nonce → personal_sign → verify → PKCE handleCallback", async () => {
  const iam = newIam();
  const calls: Array<{ method: string; params?: unknown }> = [];
  const eth = {
    request: async ({ method, params }: { method: string; params?: unknown }) => {
      calls.push({ method, params });
      if (method === "eth_requestAccounts") return ["0xAbC0000000000000000000000000000000000001"];
      if (method === "personal_sign") return "0xsignaturedeadbeef";
      throw new Error(`unexpected wallet method ${method}`);
    },
  };

  const token = await iam.loginWithWallet({ provider: eth });
  assert.equal(token.accessToken, "at-123");

  // The wallet signed the SERVER's message verbatim (not a client-invented one).
  const signCall = calls.find((c) => c.method === "personal_sign");
  assert.ok(signCall, "personal_sign was called");
  assert.deepEqual(signCall?.params, [SIWE_MESSAGE, "0xAbC0000000000000000000000000000000000001"]);

  // The nonce GET carried the address + clientId (server issues the nonce).
  assert.ok(lastNonceUrl?.includes("address=0xAbC"), "nonce request carried the address");
  assert.ok(lastNonceUrl?.includes(`clientId=${CLIENT_ID}`), "nonce request carried the clientId");

  // Verify POST sent message + signature for SERVER-SIDE recovery (address is
  // only a hint), and bound a PKCE challenge (S256) to the minted code.
  assert.ok(lastVerify, "verify endpoint was hit");
  assert.equal(lastVerify?.body.message, SIWE_MESSAGE);
  assert.equal(lastVerify?.body.signature, "0xsignaturedeadbeef");
  assert.equal(lastVerify?.body.address, "0xAbC0000000000000000000000000000000000001");
  const verifyQuery = new URL(lastVerify?.url ?? "", origin).searchParams;
  assert.equal(verifyQuery.get("code_challenge_method"), "S256");
  assert.ok((verifyQuery.get("code_challenge") ?? "").length >= 43, "PKCE challenge bound");

  // Completed IN-PLACE via the same PKCE exchange (verifier at token endpoint).
  assert.equal(lastTokenBody?.get("code"), "wallet-code");
  assert.ok((lastTokenBody?.get("code_verifier") ?? "").length >= 43, "PKCE verifier sent to token endpoint");
  // handleCallback consumes the transaction — verifier + state cleared afterward.
  assert.equal(storage.getItem("hanzo_iam_code_verifier"), null);
  assert.equal(storage.getItem("hanzo_iam_state"), null);
});

test("loginWithWallet: rejects with a clear error when no EIP-1193 provider is present", async () => {
  (globalThis as Record<string, unknown>).ethereum = undefined;
  const iam = newIam();
  await assert.rejects(() => iam.loginWithWallet(), /EIP-1193 wallet provider/i);
});

// ============================================================================
// handleCallback — per-attempt verifier isolation (LOW-2) + no soft-skip (INFO-2)
// ============================================================================

test("handleCallback: concurrent logins are isolated — a second attempt cannot stomp the first (LOW-2)", async () => {
  const iam = newIam();

  // Two overlapping attempts. The second stomps the LEGACY single slots, but
  // each keeps its own per-state verifier slot.
  const urlA = new URL(await iam.getSigninUrl());
  const stateA = urlA.searchParams.get("state") as string;
  const urlB = new URL(await iam.getSigninUrl());
  const stateB = urlB.searchParams.get("state") as string;
  assert.notEqual(stateA, stateB);

  // The FIRST attempt's callback still completes (its verifier survived).
  const tokenA = await iam.handleCallback(`${REDIRECT}?code=code-A&state=${stateA}`);
  assert.equal(tokenA.accessToken, "at-123");
  assert.equal(lastTokenBody?.get("code"), "code-A");
  assert.ok((lastTokenBody?.get("code_verifier") ?? "").length >= 43);

  // The SECOND attempt's callback also completes.
  const tokenB = await iam.handleCallback(`${REDIRECT}?code=code-B&state=${stateB}`);
  assert.equal(tokenB.accessToken, "at-123");
  assert.equal(lastTokenBody?.get("code"), "code-B");

  // Both per-attempt slots consumed — no leaks.
  assert.equal(storage.getItem(`hanzo_iam_code_verifier:${stateA}`), null);
  assert.equal(storage.getItem(`hanzo_iam_code_verifier:${stateB}`), null);
});

test("handleCallback: rejects a callback with no stored transaction — no soft-skip of the state check (INFO-2)", async () => {
  const iam = newIam();
  // Nothing stashed: no per-state slot AND no legacy saved state. Previously
  // this soft-skipped the CSRF check; now a missing saved state is a rejection.
  await assert.rejects(
    () => iam.handleCallback(`${REDIRECT}?code=x&state=whatever`),
    /state mismatch/i,
  );
  assert.equal(lastTokenBody, null, "no token exchange without a stored transaction");
});

test("clearTokens: sweeps every per-attempt PKCE verifier slot", async () => {
  const iam = newIam();
  await iam.getSigninUrl();
  await iam.getSigninUrl();
  // Two attempts → at least two namespaced slots present.
  const before = Array.from({ length: storage.length }, (_, i) => storage.key(i)).filter(
    (k) => k?.startsWith("hanzo_iam_code_verifier:"),
  );
  assert.ok(before.length >= 2, "namespaced verifier slots exist before clear");
  iam.clearTokens();
  const after = Array.from({ length: storage.length }, (_, i) => storage.key(i)).filter(
    (k) => k?.startsWith("hanzo_iam_code_verifier:"),
  );
  assert.equal(after.length, 0, "all per-attempt slots swept on clearTokens");
});
