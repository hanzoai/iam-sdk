/**
 * NextAuth.js provider for Hanzo IAM (OIDC-based).
 *
 * Consolidates the HanzoIamProvider and IamProvider implementations
 * so all Next.js apps can share one canonical implementation.
 *
 * @example
 * ```ts
 * // next-auth config
 * import { HanzoIamProvider } from "@hanzo/iam/nextauth";
 *
 * export default NextAuth({
 *   providers: [
 *     HanzoIamProvider({
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
 * NextAuth.js / Auth.js compatible OAuth provider for Hanzo IAM.
 *
 * Uses standard OIDC well-known endpoint for automatic configuration.
 * JWT id_token validation (issuer, audience, signature) is handled by
 * openid-client using the JWKS published at `{serverUrl}/.well-known/jwks`.
 *
 * Pass `checks: ["state", "pkce"]` in options for PKCE alignment.
 */
export function HanzoIamProvider(options) {
    const issuer = options.serverUrl.replace(/\/$/, "");
    const checks = options.checks ?? ["state"];
    return {
        id: "hanzo-iam",
        name: "Hanzo IAM",
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
// Re-export with alias for backwards compat
export { HanzoIamProvider as IamProvider };
//# sourceMappingURL=nextauth.js.map