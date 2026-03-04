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
 * NextAuth.js / Auth.js compatible OAuth provider for IAM.
 *
 * Uses standard OIDC well-known endpoint for automatic configuration.
 * JWT id_token validation (issuer, audience, signature) is handled by
 * openid-client using the JWKS published at `{serverUrl}/.well-known/jwks`.
 *
 * Pass `checks: ["state", "pkce"]` in options for PKCE alignment.
 */
export function IamProvider(options) {
    const issuer = options.serverUrl.replace(/\/$/, "");
    const checks = options.checks ?? ["state"];
    return {
        id: "iam",
        name: "IAM",
        type: "oauth",
        wellKnown: `${issuer}/.well-known/openid-configuration`,
        idToken: true,
        checks,
        authorization: { params: { scope: "openid profile email" } },
        profile(profile) {
            return {
                id: profile.sub,
                name: profile.displayName ||
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
// Backwards-compatible aliases
/** @deprecated Use IamProvider instead */
export { IamProvider as HanzoIamProvider };
//# sourceMappingURL=nextauth.js.map