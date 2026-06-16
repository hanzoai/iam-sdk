import { test } from "node:test";
import assert from "node:assert/strict";

import { getBearerToken, getServerSession, SESSION_COOKIE } from "./server.js";

const CFG = { serverUrl: "https://iam.hanzo.ai", clientId: "my-app" };

// --- getBearerToken: the framework-agnostic header extraction ---

test("reads Bearer token from a Web Request (Headers.get)", () => {
  const req = new Request("https://app/x", { headers: { authorization: "Bearer abc.def.ghi" } });
  assert.equal(getBearerToken(req), "abc.def.ghi");
});

test("reads Bearer token from a Node-style headers record", () => {
  const req = { headers: { authorization: "Bearer node.token.xyz" } };
  assert.equal(getBearerToken(req), "node.token.xyz");
});

test("Bearer scheme is case-insensitive and trims", () => {
  const req = { headers: { authorization: "  bearer   spaced.tok  " } };
  assert.equal(getBearerToken(req), "spaced.tok");
});

test("falls back to the session cookie when no Authorization header", () => {
  const req = new Request("https://app/x", {
    headers: { cookie: `theme=dark; ${SESSION_COOKIE}=cookie.tok.val; other=1` },
  });
  assert.equal(getBearerToken(req), "cookie.tok.val");
});

test("Authorization header wins over the cookie", () => {
  const req = new Request("https://app/x", {
    headers: { authorization: "Bearer header.tok", cookie: `${SESSION_COOKIE}=cookie.tok` },
  });
  assert.equal(getBearerToken(req), "header.tok");
});

test("custom cookie name is honored", () => {
  const req = { headers: { cookie: "my_session=xyz.tok" } };
  assert.equal(getBearerToken(req, { cookieName: "my_session" }), "xyz.tok");
});

test("returns undefined when neither header nor cookie present", () => {
  assert.equal(getBearerToken(new Request("https://app/x")), undefined);
  assert.equal(getBearerToken({ headers: {} }), undefined);
});

// --- getServerSession: fail-closed when no/invalid token ---

test("getServerSession returns null when no token is present", async () => {
  const session = await getServerSession(new Request("https://app/x"), CFG);
  assert.equal(session, null);
});

test("getServerSession returns null for a malformed token (cannot verify)", async () => {
  // Points at a non-resolving origin → discovery fails → null, never throws.
  const req = new Request("https://app/x", { headers: { authorization: "Bearer not-a-jwt" } });
  const session = await getServerSession(req, {
    serverUrl: "https://127.0.0.1:0",
    clientId: "x",
  });
  assert.equal(session, null);
});
