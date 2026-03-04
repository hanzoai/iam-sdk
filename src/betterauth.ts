/**
 * BetterAuth SSO provider configuration for IAM.
 *
 * Returns a provider config object compatible with BetterAuth's
 * `socialProviders` or generic OAuth plugin.
 *
 * @example
 * ```ts
 * import { betterAuth } from "better-auth";
 * import { iamProvider } from "@hanzo/iam/betterauth";
 *
 * export const auth = betterAuth({
 *   socialProviders: [
 *     iamProvider({
 *       serverUrl: process.env.IAM_SERVER_URL!,
 *       clientId: process.env.IAM_CLIENT_ID!,
 *       clientSecret: process.env.IAM_CLIENT_SECRET!,
 *     }),
 *   ],
 * });
 * ```
 *
 * @packageDocumentation
 */

import type { IamConfig } from "./types.js";

export interface IamSocialProvider {
  id: string;
  name: string;
  type: "oidc";
  issuer: string;
  clientId: string;
  clientSecret?: string;
  authorization: { url: string; params: { scope: string } };
  token: { url: string };
  userinfo: { url: string };
  profile: (profile: Record<string, unknown>) => {
    id: string;
    name: string;
    email: string;
    image: string | null;
  };
}

/**
 * Create a BetterAuth-compatible social provider for IAM.
 *
 * Works with BetterAuth's SSO plugin or generic OAuth integration.
 * Uses standard OIDC endpoints.
 */
export function iamProvider(
  config: IamConfig & { redirectUri?: string },
): IamSocialProvider {
  const baseUrl = config.serverUrl.replace(/\/+$/, "");

  return {
    id: "iam",
    name: "IAM",
    type: "oidc",
    issuer: baseUrl,
    clientId: config.clientId,
    clientSecret: config.clientSecret,
    authorization: {
      url: `${baseUrl}/login/oauth/authorize`,
      params: { scope: "openid profile email" },
    },
    token: { url: `${baseUrl}/api/login/oauth/access_token` },
    userinfo: { url: `${baseUrl}/api/userinfo` },
    profile(profile: Record<string, unknown>) {
      return {
        id: (profile.sub as string) ?? (profile.id as string) ?? "",
        name:
          (profile.displayName as string) ??
          (profile.name as string) ??
          (profile.preferred_username as string) ??
          "",
        email: (profile.email as string) ?? "",
        image: (profile.avatar as string) ?? (profile.picture as string) ?? null,
      };
    },
  };
}

// Backwards-compatible aliases
/** @deprecated Use iamProvider instead */
export { iamProvider as hanzoIamProvider };
/** @deprecated Use iamProvider instead */
export { iamProvider as hanzoIamSocialProvider };
/** @deprecated Use IamSocialProvider instead */
export type { IamSocialProvider as HanzoIamSocialProvider };
