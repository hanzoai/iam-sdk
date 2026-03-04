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
/**
 * Create a BetterAuth-compatible social provider for IAM.
 *
 * Works with BetterAuth's SSO plugin or generic OAuth integration.
 * Uses standard OIDC endpoints.
 */
export function iamProvider(config) {
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
        profile(profile) {
            return {
                id: profile.sub ?? profile.id ?? "",
                name: profile.displayName ??
                    profile.name ??
                    profile.preferred_username ??
                    "",
                email: profile.email ?? "",
                image: profile.avatar ?? profile.picture ?? null,
            };
        },
    };
}
// Backwards-compatible aliases
/** @deprecated Use iamProvider instead */
export { iamProvider as hanzoIamProvider };
/** @deprecated Use iamProvider instead */
export { iamProvider as hanzoIamSocialProvider };
//# sourceMappingURL=betterauth.js.map