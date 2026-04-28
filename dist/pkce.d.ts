/**
 * PKCE (Proof Key for Code Exchange) utilities for browser-side OAuth2 flows.
 *
 * PKCE utilities for OAuth2 flows, using native Web Crypto API.
 */
/** Generate a PKCE code verifier + challenge pair. */
export declare function generatePKCEChallenge(): Promise<{
    codeVerifier: string;
    codeChallenge: string;
}>;
/** Generate a random state parameter for CSRF protection. */
export declare function generateState(): string;
//# sourceMappingURL=pkce.d.ts.map