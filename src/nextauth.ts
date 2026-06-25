/**
 * NextAuth.js / Auth.js provider for Hanzo IAM (OIDC).
 *
 * One canonical provider so every Next.js / Auth.js app shares a single
 * implementation. NextAuth keeps its NATIVE routes (it hard-mounts
 * `/api/auth/*`); this SDK never moves them. The provider's ONLY job is to
 * point NextAuth's authorize/token/userinfo at our canonical
 * `/v1/iam/oauth/*` endpoints — the one translation, in code, once.
 *
 * Endpoints are EXPLICIT (from {@link OIDC_PATHS}); we do NOT rely on the
 * `wellKnown`/discovery round-trip. IAM serves a 200 `text/html` SPA for
 * any unregistered path, so a discovery fetch that fails or resolves to a
 * wrong path is silent breakage. Pinning the exact endpoints removes that
 * failure mode. `issuer` + `jwks_endpoint` are supplied so openid-client
 * can still verify the id_token signature without discovery.
 *
 * @example
 * ```ts
 * import NextAuth from "next-auth";
 * import { HanzoIamProvider } from "@hanzo/iam/nextauth";
 *
 * export default NextAuth({
 *   providers: [
 *     HanzoIamProvider({
 *       serverUrl: process.env.IAM_SERVER_URL!,   // e.g. https://iam.hanzo.ai
 *       clientId: process.env.IAM_CLIENT_ID!,
 *       clientSecret: process.env.IAM_CLIENT_SECRET,
 *     }),
 *   ],
 * });
 * ```
 *
 * @packageDocumentation
 */

import { OIDC_PATHS, iamUrl, trimServerUrl } from "./paths.js";

/**
 * The OIDC userinfo / id_token profile shape Hanzo IAM returns. Carries
 * the raw OIDC claims so a consumer's own `profile()` mapper can read
 * `sub`, `email`, `name`, `picture`, etc.
 */
export interface HanzoIamProfile extends Record<string, unknown> {
  sub: string;
  name: string;
  email: string;
  preferred_username?: string;
  picture?: string;
  avatar?: string;
  displayName?: string;
  email_verified?: boolean;
}

/** @deprecated Use {@link HanzoIamProfile}. Kept as an in-SDK alias. */
export type IamProfile = HanzoIamProfile;

/** Options for {@link HanzoIamProvider}. */
export interface HanzoIamProviderOptions {
  /** IAM origin (`serverUrl`), e.g. "https://iam.hanzo.ai". */
  serverUrl: string;
  /** OAuth2 client id (`<org>-<app>`). */
  clientId: string;
  /** OAuth2 client secret (confidential client). */
  clientSecret?: string;
  /** Organization name (owner context); passed through on `options`. */
  orgName?: string;
  /** Application name; passed through on `options`. */
  appName?: string;
  /** OAuth state/PKCE checks. Default: ["state", "pkce"]. */
  checks?: ("state" | "pkce" | "nonce" | "none")[];
  [key: string]: unknown;
}

/**
 * NextAuth.js / Auth.js compatible OAuth provider config for Hanzo IAM.
 *
 * Returns a plain `OAuthConfig`-shaped object. The caller spreads it into
 * `providers: [...]` and may override `id`/`name`/`profile` (console does:
 * it pins `id: "hanzo-iam"` and supplies its own `profile()` that upserts
 * the user). The default `id` is already `"hanzo-iam"`, so apps that don't
 * override it get the canonical id.
 *
 * PKCE (S256) is on by default (`checks: ["state", "pkce"]`). All endpoints
 * are explicit — no discovery round-trip.
 */
export function HanzoIamProvider<P extends HanzoIamProfile>(
  options: HanzoIamProviderOptions,
): Record<string, unknown> {
  const issuer = trimServerUrl(options.serverUrl);
  const checks = options.checks ?? ["state", "pkce"];

  return {
    id: "hanzo-iam",
    name: "Hanzo IAM",
    type: "oauth",
    issuer,
    // Explicit endpoints from the single source of truth — never discovery.
    authorization: {
      url: iamUrl(issuer, "authorize"),
      params: { scope: "openid profile email" },
    },
    token: { url: iamUrl(issuer, "token") },
    userinfo: { url: iamUrl(issuer, "userinfo") },
    jwks_endpoint: iamUrl(issuer, "jwks"),
    idToken: true,
    checks,
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    client: { token_endpoint_auth_method: "client_secret_basic" },
    profile(profile: P) {
      return {
        id: profile.sub,
        name:
          profile.displayName ||
          profile.name ||
          profile.preferred_username ||
          profile.email ||
          "",
        email: profile.email,
        image: profile.avatar || profile.picture || null,
      };
    },
    style: {
      bg: "#050508",
      text: "#fff",
      logo: "",
    },
    options,
  };
}

/**
 * Canonical alias for {@link HanzoIamProvider}.
 *
 * `@hanzo/iam` is the namespace, so `IamProvider` reads cleanly in app code.
 * Both names are stable exports; they are the same function.
 */
export const IamProvider = HanzoIamProvider;
