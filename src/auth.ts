/**
 * JWT validation using jose library + OIDC JWKS discovery.
 *
 * Validates access/ID tokens issued by Hanzo IAM. The JWKS URI is taken
 * from the live OIDC discovery document when reachable; if discovery
 * fails or returns no usable `jwks_uri`, it DEGRADES to the canonical
 * `/v1/iam/.well-known/jwks` endpoint ({@link OIDC_PATHS.jwks}) — never
 * leaving token verification dead because a discovery round-trip blipped.
 * This mirrors the SDK-wide contract in `paths.ts`: a failed discovery
 * resolves to the same canonical paths, not to a wrong path or a 200-HTML
 * SPA catch-all. The issuer is verified.
 *
 * Audience is verified against `config.clientId` by default. A token
 * whose `aud` does not match is REJECTED — unless the caller explicitly
 * opts out with `allowMissingAudience: true` (for IAM deployments that
 * issue access tokens without an `aud` claim). There is no silent
 * fall-through.
 */

import {
  createLocalJWKSet,
  createRemoteJWKSet,
  jwtVerify,
  type JSONWebKeySet,
  type JWTPayload,
} from "jose";
import type { Config, AuthResult, JwtClaims } from "./types.js";
import { OIDC_PATHS, iamUrl, trimServerUrl } from "./paths.js";

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

// Fallback local key sets, deduped by kid. A spec-compliant JWKS has one key
// per `kid` (RFC 7517 §4.5), but some issuers publish the SAME key twice under
// one kid (e.g. an identical cert collected from a global + an org-scoped
// owner). jose's remote set then can't pick one and throws
// `JWKSMultipleMatchingKeys`, which would hard-fail verification of EVERY token
// signed with that kid. We dedupe by kid and verify against a local set so a
// malformed-but-harmless JWKS never breaks login. Cached per jwksUri.
const localJwksSets = new Map<string, ReturnType<typeof createLocalJWKSet>>();

async function getDedupedLocalKeySet(
  jwksUri: string,
): Promise<ReturnType<typeof createLocalJWKSet>> {
  const cached = localJwksSets.get(jwksUri);
  if (cached) return cached;

  const res = await fetch(jwksUri, { headers: { Accept: "application/json" } });
  if (!res.ok) throw new Error(`JWKS fetch failed: ${res.status}`);
  const jwks = (await res.json()) as JSONWebKeySet;

  const seen = new Set<string>();
  const keys = (jwks.keys ?? []).filter((k) => {
    const id = `${k.kid ?? ""}:${k.alg ?? ""}`;
    if (seen.has(id)) return false;
    seen.add(id);
    return true;
  });

  const keySet = createLocalJWKSet({ keys });
  localJwksSets.set(jwksUri, keySet);
  return keySet;
}

/** Clear cached JWKS key sets (useful for testing or key rotation). */
export function clearJwksCache(): void {
  jwksSets.clear();
  localJwksSets.clear();
}

// ---------------------------------------------------------------------------
// OIDC discovery cache (lightweight, no full client needed)
// ---------------------------------------------------------------------------

type CachedDiscovery = { jwksUri: string; issuer: string; fetchedAt: number };
const discoveryCache = new Map<string, CachedDiscovery>();
const DISCOVERY_TTL_MS = 5 * 60 * 1000;

/**
 * Resolve the JWKS URI (and issuer) for an IAM origin.
 *
 * Tries OIDC discovery first; on ANY failure — non-2xx, network error,
 * timeout, or a body with no `jwks_uri` (e.g. the IAM SPA HTML catch-all
 * parsed as JSON) — it degrades to the canonical {@link OIDC_PATHS.jwks}
 * endpoint with a host-relative issuer. This never throws for a reachable
 * IAM host: the canonical JWKS path is always a valid fallback, so a
 * discovery blip can't take down token verification across every service
 * that sits on `@hanzo/iam/server`.
 */
async function resolveJwksUri(serverUrl: string): Promise<{ jwksUri: string; issuer: string }> {
  const baseUrl = trimServerUrl(serverUrl);
  const cached = discoveryCache.get(baseUrl);
  if (cached && Date.now() - cached.fetchedAt < DISCOVERY_TTL_MS) {
    return { jwksUri: cached.jwksUri, issuer: cached.issuer };
  }

  // Canonical fallback — used verbatim when discovery is unusable.
  const fallback = { jwksUri: iamUrl(baseUrl, "jwks"), issuer: baseUrl };

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 8_000);
  let resolved = fallback;
  try {
    const res = await fetch(`${baseUrl}${OIDC_PATHS.discovery}`, {
      signal: controller.signal,
      headers: { Accept: "application/json" },
    });
    if (res.ok) {
      const body = (await res.json().catch(() => null)) as
        | { jwks_uri?: string; issuer?: string }
        | null;
      if (body?.jwks_uri) {
        resolved = { jwksUri: body.jwks_uri, issuer: body.issuer ?? baseUrl };
      }
    }
  } catch {
    // Discovery unreachable/timed out — keep the canonical fallback.
  } finally {
    clearTimeout(timer);
  }

  discoveryCache.set(baseUrl, { ...resolved, fetchedAt: Date.now() });
  return resolved;
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

  // resolveJwksUri degrades to the canonical JWKS path on discovery
  // failure, so this only throws if the serverUrl itself is unusable.
  let jwksUri: string;
  let issuer: string;
  if (config.jwksUri && config.issuer) {
    // Explicit overrides — bypass OIDC discovery entirely. This is the
    // in-cluster / split-horizon path: the pod can't reach the public IAM
    // origin (LB hairpin / WAF 403) and discovery would advertise an
    // unreachable public jwks_uri + a mismatched issuer, so the caller pins
    // a reachable in-cluster JWKS endpoint and the real public issuer.
    jwksUri = config.jwksUri;
    issuer = config.issuer;
  } else {
    // resolveJwksUri degrades to the canonical JWKS path on discovery failure,
    // so this only throws if the serverUrl itself is unusable.
    try {
      const resolved = await resolveJwksUri(config.serverUrl);
      jwksUri = resolved.jwksUri;
      issuer = resolved.issuer;
    } catch {
      return { ok: false, reason: "iam_discovery_failed" };
    }
  }

  const keySet = getJwksKeySet(jwksUri);
  const verifyOptions = {
    issuer,
    // Skip aud verification only when explicitly allowed; otherwise
    // pin to the client id. No silent fall-through on mismatch.
    ...(config.allowMissingAudience ? {} : { audience: config.clientId }),
    clockTolerance: 30, // 30s clock skew
  };

  let payload: JWTPayload;
  try {
    let result;
    try {
      result = await jwtVerify(token, keySet, verifyOptions);
    } catch (err) {
      // A JWKS that lists the token's kid more than once makes jose's remote
      // set ambiguous (`JWKSMultipleMatchingKeys`). Retry ONCE against a local
      // set deduped by kid — the only key for that kid then verifies cleanly.
      // Any other error propagates to the mapping below unchanged.
      if ((err as { code?: string }).code === "ERR_JWKS_MULTIPLE_MATCHING_KEYS") {
        const localSet = await getDedupedLocalKeySet(jwksUri);
        result = await jwtVerify(token, localSet, verifyOptions);
      } else {
        throw err;
      }
    }
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
