/**
 * better-auth `genericOAuth` provider configuration for Hanzo IAM.
 *
 * Returns ONE config entry to drop into better-auth's `genericOAuth`
 * plugin. The endpoints are pinned to the canonical IAM OIDC paths
 * (`OIDC_PATHS`) — no `discoveryUrl`, because IAM serves a 200 HTML SPA
 * catch-all for unregistered paths and a discovery round-trip must never
 * be allowed to resolve to the wrong path.
 *
 * @example
 * ```ts
 * import { betterAuth } from "better-auth";
 * import { genericOAuth } from "better-auth/plugins";
 * import { iamProvider } from "@hanzo/iam/betterauth";
 *
 * export const auth = betterAuth({
 *   plugins: [
 *     genericOAuth({
 *       config: [
 *         iamProvider({
 *           serverUrl: process.env.IAM_ENDPOINT!,      // e.g. https://iam.hanzo.ai
 *           clientId: process.env.IAM_CLIENT_ID!,
 *           clientSecret: process.env.IAM_CLIENT_SECRET!,
 *         }),
 *       ],
 *     }),
 *   ],
 * });
 * ```
 *
 * @packageDocumentation
 */

import type { Config } from "./types.js";
import { iamUrl } from "./paths.js";

/**
 * A single `genericOAuth` provider config entry, as consumed by
 * better-auth's `genericOAuth({ config: [...] })` plugin.
 */
export interface IamGenericOAuthConfig {
  /** Provider id better-auth routes by. `"hanzo"` for all Hanzo IAM brands. */
  providerId: string;
  /** Authorization endpoint URL. */
  authorizationUrl: string;
  /** Token endpoint URL. */
  tokenUrl: string;
  /** UserInfo endpoint URL. */
  userInfoUrl: string;
  /** OAuth2 client id. */
  clientId: string;
  /** OAuth2 client secret (confidential client). */
  clientSecret?: string;
  /** Requested scopes. */
  scopes: string[];
  /** Enable PKCE (S256). Always true. */
  pkce: true;
  /** Client authentication method at the token endpoint. */
  authentication: "basic";
}

/**
 * Create a better-auth `genericOAuth` config entry for Hanzo IAM.
 *
 * Pass the result inside `genericOAuth({ config: [iamProvider(...)] })`.
 */
export function iamProvider(config: Config): IamGenericOAuthConfig {
  return {
    providerId: "hanzo",
    authorizationUrl: iamUrl(config.serverUrl, "authorize"),
    tokenUrl: iamUrl(config.serverUrl, "token"),
    userInfoUrl: iamUrl(config.serverUrl, "userinfo"),
    clientId: config.clientId,
    clientSecret: config.clientSecret,
    scopes: ["openid", "profile", "email"],
    pkce: true,
    authentication: "basic",
  };
}
