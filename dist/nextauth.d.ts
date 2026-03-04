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
 * Uses standard OIDC well-known endpoint for automatic configuration.
 * JWT id_token validation (issuer, audience, signature) is handled by
 * openid-client using the JWKS published at `{serverUrl}/.well-known/jwks`.
 *
 * Pass `checks: ["state", "pkce"]` in options for PKCE alignment.
 */
export declare function IamProvider<P extends IamProfile>(options: {
    serverUrl: string;
    clientId: string;
    clientSecret?: string;
    orgName?: string;
    appName?: string;
    /** OAuth state/PKCE checks. Default: ["state"]. Add "pkce" for extra security. */
    checks?: ("state" | "pkce" | "nonce" | "none")[];
    [key: string]: unknown;
}): Record<string, unknown>;
/** @deprecated Use IamProvider instead */
export { IamProvider as HanzoIamProvider };
/** @deprecated Use IamProfile instead */
export type { IamProfile as HanzoIamProfile };
//# sourceMappingURL=nextauth.d.ts.map