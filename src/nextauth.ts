/**
 * NextAuth.js / Auth.js provider for IAM (OIDC-based).
 *
 * Provides a canonical NextAuth/Auth.js provider configuration
 * so all Next.js apps can share one implementation.
 *
 * @example
 * ```ts
 * // next-auth config
 * import { IamProvider } from "@hanzo/iam/nextauth";
 *
 * export default NextAuth({
 *   providers: [
 *     IamProvider({
 *       serverUrl: process.env.IAM_ENDPOINT!,
 *       clientId: process.env.IAM_CLIENT_ID!,
 *       clientSecret: process.env.IAM_CLIENT_SECRET!,
 *     }),
 *   ],
 * });
 * ```
 *
 * @packageDocumentation
 */

import { OIDC_PATHS, trimServerUrl } from "./paths.js";

export interface IamProfile extends Record<string, unknown> {
  sub: string;
  name: string;
  email: string;
  preferred_username?: string;
  picture?: string;
  avatar?: string;
  displayName?: string;
  email_verified?: boolean;
}

/**
 * NextAuth.js / Auth.js compatible OAuth provider for IAM.
 *
 * Uses the standard OIDC well-known endpoint (`OIDC_PATHS.discovery`) for
 * automatic configuration. JWT id_token validation (issuer, audience,
 * signature) is handled by openid-client using the JWKS published at the
 * canonical `{serverUrl}/v1/iam/.well-known/jwks` endpoint (resolved from
 * discovery — never hard-coded to a wrong path).
 *
 * PKCE (S256) is on by default: `checks` defaults to `["state", "pkce"]`.
 */
export function IamProvider<P extends IamProfile>(
  options: {
    serverUrl: string;
    clientId: string;
    clientSecret?: string;
    orgName?: string;
    appName?: string;
    /** OAuth state/PKCE checks. Default: ["state", "pkce"]. */
    checks?: ("state" | "pkce" | "nonce" | "none")[];
    [key: string]: unknown;
  },
): Record<string, unknown> {
  const issuer = trimServerUrl(options.serverUrl);
  const checks = options.checks ?? ["state", "pkce"];

  return {
    id: "iam",
    name: "IAM",
    type: "oauth",
    wellKnown: `${issuer}${OIDC_PATHS.discovery}`,
    idToken: true,
    checks,
    authorization: { params: { scope: "openid profile email" } },
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
