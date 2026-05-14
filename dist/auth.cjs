'use strict';

var jose = require('jose');

// src/auth.ts
var jwksSets = /* @__PURE__ */ new Map();
function getJwksKeySet(jwksUri) {
  let keySet = jwksSets.get(jwksUri);
  if (!keySet) {
    keySet = jose.createRemoteJWKSet(new URL(jwksUri));
    jwksSets.set(jwksUri, keySet);
  }
  return keySet;
}
function clearJwksCache() {
  jwksSets.clear();
}
var discoveryCache = /* @__PURE__ */ new Map();
var DISCOVERY_TTL_MS = 5 * 60 * 1e3;
async function resolveJwksUri(serverUrl) {
  const baseUrl = serverUrl.replace(/\/+$/, "");
  const cached = discoveryCache.get(baseUrl);
  if (cached && Date.now() - cached.fetchedAt < DISCOVERY_TTL_MS) {
    return { jwksUri: cached.jwksUri, issuer: cached.issuer };
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 8e3);
  try {
    const res = await fetch(`${baseUrl}/.well-known/openid-configuration`, {
      signal: controller.signal,
      headers: { Accept: "application/json" }
    });
    if (!res.ok) {
      throw new Error(`OIDC discovery failed: ${res.status}`);
    }
    const body = await res.json();
    const jwksUri = body.jwks_uri;
    const issuer = body.issuer ?? baseUrl;
    if (!jwksUri) {
      throw new Error("OIDC discovery response missing jwks_uri");
    }
    discoveryCache.set(baseUrl, { jwksUri, issuer, fetchedAt: Date.now() });
    return { jwksUri, issuer };
  } finally {
    clearTimeout(timer);
  }
}
async function validateToken(token, config) {
  if (!token || typeof token !== "string") {
    return { ok: false, reason: "iam_token_missing" };
  }
  let jwksUri;
  let issuer;
  try {
    const discovery = await resolveJwksUri(config.serverUrl);
    jwksUri = discovery.jwksUri;
    issuer = discovery.issuer;
  } catch {
    return { ok: false, reason: "iam_discovery_failed" };
  }
  const keySet = getJwksKeySet(jwksUri);
  let payload;
  try {
    const result = await jose.jwtVerify(token, keySet, {
      issuer,
      audience: config.clientId,
      clockTolerance: 30
      // 30s clock skew
    });
    payload = result.payload;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (message.includes("expired")) {
      return { ok: false, reason: "iam_token_expired" };
    }
    if (message.includes("audience")) {
      try {
        const result = await jose.jwtVerify(token, keySet, {
          issuer,
          clockTolerance: 30
        });
        payload = result.payload;
      } catch {
        return { ok: false, reason: "iam_signature_invalid" };
      }
    } else {
      return { ok: false, reason: "iam_signature_invalid" };
    }
  }
  const claims = payload;
  const sub = claims.sub || (typeof claims.owner === "string" && typeof claims.name === "string" ? `${claims.owner}/${claims.name}` : void 0);
  if (!sub) {
    return { ok: false, reason: "iam_subject_missing" };
  }
  const parts = sub.split("/");
  const owner = parts.length > 1 ? parts[0] : config.orgName ?? "unknown";
  return {
    ok: true,
    userId: sub,
    email: typeof claims.email === "string" ? claims.email : void 0,
    name: typeof claims.name === "string" ? claims.name : typeof claims.preferred_username === "string" ? claims.preferred_username : void 0,
    avatar: typeof claims.picture === "string" ? claims.picture : void 0,
    owner,
    claims
  };
}

exports.clearJwksCache = clearJwksCache;
exports.validateToken = validateToken;
//# sourceMappingURL=auth.cjs.map
//# sourceMappingURL=auth.cjs.map