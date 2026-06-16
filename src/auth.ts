/**
 * JWT validation using jose library + OIDC JWKS discovery.
 *
 * Validates access/ID tokens issued by Hanzo IAM. The JWKS URI is taken
 * from the live OIDC discovery document (which points at the canonical
 * `/v1/iam/.well-known/jwks` endpoint); the issuer is verified.
 *
 * Audience is verified against `config.clientId` by default. A token
 * whose `aud` does not match is REJECTED — unless the caller explicitly
 * opts out with `allowMissingAudience: true` (for IAM deployments that
 * issue access tokens without an `aud` claim). There is no silent
 * fall-through.
 */

import { createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";
import type { Config, AuthResult, JwtClaims } from "./types.js";
import { OIDC_PATHS, trimServerUrl } from "./paths.js";

// ---------------------------------------------------------------------------
// JWKS key set cache (per issuer)
// ---------------------------------------------------------------------------

const jwksSets = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

function getJwksKeySet(jwksUri: string): ReturnType<typeof createRemoteJWKSet> {
  let keySet = jwksSets.get(jwksUri);
  if (!keySet) {
    keySet = createRemoteJWKSet(new URL(jwksUri));
    jwksSets.set(jwksUri, keySet);
  }
  return keySet;
}

/** Clear cached JWKS key sets (useful for testing or key rotation). */
export function clearJwksCache(): void {
  jwksSets.clear();
}

// ---------------------------------------------------------------------------
// OIDC discovery cache (lightweight, no full client needed)
// ---------------------------------------------------------------------------

type CachedDiscovery = { jwksUri: string; issuer: string; fetchedAt: number };
const discoveryCache = new Map<string, CachedDiscovery>();
const DISCOVERY_TTL_MS = 5 * 60 * 1000;

async function resolveJwksUri(serverUrl: string): Promise<{ jwksUri: string; issuer: string }> {
  const baseUrl = trimServerUrl(serverUrl);
  const cached = discoveryCache.get(baseUrl);
  if (cached && Date.now() - cached.fetchedAt < DISCOVERY_TTL_MS) {
    return { jwksUri: cached.jwksUri, issuer: cached.issuer };
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 8_000);
  try {
    const res = await fetch(`${baseUrl}${OIDC_PATHS.discovery}`, {
      signal: controller.signal,
      headers: { Accept: "application/json" },
    });
    if (!res.ok) {
      throw new Error(`OIDC discovery failed: ${res.status}`);
    }
    const body = (await res.json()) as { jwks_uri?: string; issuer?: string };
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

// ---------------------------------------------------------------------------
// Token validation
// ---------------------------------------------------------------------------

/**
 * Validate a JWT access token against IAM's JWKS.
 *
 * Uses OIDC discovery to find the JWKS URI, then verifies the token
 * signature, issuer, audience, and expiry using the `jose` library.
 *
 * The audience MUST equal `config.clientId`. A mismatch fails with
 * `iam_audience_invalid` unless `config.allowMissingAudience === true`,
 * in which case the audience check is skipped entirely (for IAM
 * deployments that issue access tokens without an `aud` claim). There is
 * no automatic, silent retry.
 */
export async function validateToken(
  token: string,
  config: Config,
): Promise<AuthResult> {
  if (!token || typeof token !== "string") {
    return { ok: false, reason: "iam_token_missing" };
  }

  let jwksUri: string;
  let issuer: string;
  try {
    const discovery = await resolveJwksUri(config.serverUrl);
    jwksUri = discovery.jwksUri;
    issuer = discovery.issuer;
  } catch {
    return { ok: false, reason: "iam_discovery_failed" };
  }

  const keySet = getJwksKeySet(jwksUri);

  let payload: JWTPayload;
  try {
    const result = await jwtVerify(token, keySet, {
      issuer,
      // Skip aud verification only when explicitly allowed; otherwise
      // pin to the client id. No silent fall-through on mismatch.
      ...(config.allowMissingAudience ? {} : { audience: config.clientId }),
      clockTolerance: 30, // 30s clock skew
    });
    payload = result.payload;
  } catch (err) {
    // Branch on jose's typed error codes, not message strings.
    // jose v6: ERR_JWT_EXPIRED for `exp`; ERR_JWT_CLAIM_VALIDATION_FAILED
    // with `claim === "aud"` for an audience mismatch.
    const code = (err as { code?: string }).code;
    const claim = (err as { claim?: string }).claim;
    if (code === "ERR_JWT_EXPIRED") {
      return { ok: false, reason: "iam_token_expired" };
    }
    if (code === "ERR_JWT_CLAIM_VALIDATION_FAILED" && claim === "aud") {
      return { ok: false, reason: "iam_audience_invalid" };
    }
    return { ok: false, reason: "iam_signature_invalid" };
  }

  const claims = payload as unknown as JwtClaims;

  // Hanzo IAM tokens may use owner/name instead of sub claim
  const sub =
    claims.sub ||
    (typeof claims.owner === "string" && typeof claims.name === "string"
      ? `${claims.owner}/${claims.name}`
      : undefined);

  if (!sub) {
    return { ok: false, reason: "iam_subject_missing" };
  }

  // IAM sub format is "org/username" - extract owner
  const parts = sub.split("/");
  const owner = parts.length > 1 ? parts[0] : config.orgName ?? "unknown";

  return {
    ok: true,
    userId: sub,
    email: typeof claims.email === "string" ? claims.email : undefined,
    name:
      typeof claims.name === "string"
        ? claims.name
        : typeof claims.preferred_username === "string"
          ? claims.preferred_username
          : undefined,
    avatar: typeof claims.picture === "string" ? claims.picture : undefined,
    owner,
    claims,
  };
}
