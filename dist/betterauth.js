/**
 * BetterAuth SSO provider configuration for Hanzo IAM.
 *
 * Returns a provider config object compatible with BetterAuth's
 * `socialProviders` or generic OAuth plugin.
 *
 * @example
 * ```ts
 * import { betterAuth } from "better-auth";
 * import { hanzoIamProvider } from "@hanzo/iam/betterauth";
 *
 * export const auth = betterAuth({
 *   socialProviders: [
 *     hanzoIamProvider({
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
 * Create a BetterAuth-compatible social provider for Hanzo IAM.
 *
 * Works with BetterAuth's SSO plugin or generic OAuth integration.
 * Uses the standard Hanzo IAM / Casdoor OIDC endpoints.
 */
export function hanzoIamProvider(config) {
    const baseUrl = config.serverUrl.replace(/\/+$/, "");
    return {
        id: "hanzo-iam",
        name: "Hanzo IAM",
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
// Backwards-compatible alias
export { hanzoIamProvider as hanzoIamSocialProvider };
//# sourceMappingURL=betterauth.js.map