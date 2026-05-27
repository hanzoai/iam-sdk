import { IamConfig, OidcDiscovery, TokenResponse, IamUser } from './types.js';
export { ApiResponse, AuthResult, Config, IamApiResponse, IamAuthResult, IamJwtClaims, IamOrder, IamOrganization, IamPayment, IamPlan, IamPricing, IamProject, IamSubscription, IamUsageRecord, IamUsageSummary, JwtClaims, Order, Organization, Payment, Plan, Pricing, Project, Subscription, UsageRecord, UsageSummary, User } from './types.js';
export { clearJwksCache, validateToken } from './auth.js';
export { IAM, IAMConfig, IAMToken, IAMUser, toIAMToken } from './browser.js';

/**
 * Core HTTP client for Hanzo IAM.
 *
 * Speaks pure OIDC / OAuth2 only. No Casdoor `/api/get-*` admin REST.
 * Identity, users, organizations are read from the validated JWT or
 * the OIDC userinfo endpoint — never from `/api/get-organizations`
 * style admin queries. Surface the IamClient exposes:
 *
 *   - getDiscovery       — /.well-known/openid-configuration
 *   - getJwksUri         — convenience over discovery
 *   - getAuthorizationUrl— builds the authorize redirect (PKCE)
 *   - exchangeCode       — code → tokens (RFC 6749 §4.1)
 *   - passwordGrant      — ROPC for CLIs / e2e tests (RFC 6749 §4.3)
 *   - refreshToken       — refresh grant (RFC 6749 §6)
 *   - getUserInfo        — /oauth/userinfo (RFC OIDC core §5.3)
 *   - apiRequest         — escape hatch for app-specific endpoints
 */

declare class IamClient {
    private readonly baseUrl;
    private readonly clientId;
    private readonly clientSecret;
    private readonly orgName;
    private readonly appName;
    private discoveryCache;
    constructor(config: IamConfig);
    private request;
    getDiscovery(): Promise<OidcDiscovery>;
    /** Get JWKS URI from OIDC discovery (cached). */
    getJwksUri(): Promise<string>;
    /** Build the authorization URL for user login redirect. */
    getAuthorizationUrl(params: {
        redirectUri: string;
        state: string;
        scope?: string;
        codeChallenge?: string;
        codeChallengeMethod?: string;
    }): Promise<string>;
    /** Exchange authorization code for tokens (RFC 6749 §4.1). */
    exchangeCode(params: {
        code: string;
        redirectUri: string;
        codeVerifier?: string;
    }): Promise<TokenResponse>;
    /**
     * Resource Owner Password Credentials grant (RFC 6749 §4.3).
     * For service-to-service auth, CLI login, and e2e tests only.
     * Browsers should use the redirect flow.
     */
    passwordGrant(params: {
        username: string;
        password: string;
        scope?: string;
    }): Promise<TokenResponse>;
    /** Refresh an access token (RFC 6749 §6). */
    refreshToken(refreshToken: string): Promise<TokenResponse>;
    /** Fetch user claims from the OIDC userinfo endpoint (OIDC core §5.3). */
    getUserInfo(accessToken: string): Promise<IamUser>;
    /**
     * Make an arbitrary authenticated request to the IAM server.
     * Intentionally untyped — callers that need org/project listings
     * should query their own admin API, not the IAM SDK.
     */
    apiRequest<T = unknown>(path: string, opts?: {
        method?: string;
        body?: unknown;
        token?: string;
        params?: Record<string, string>;
    }): Promise<T>;
    /** Bound owner/app context if the consumer passed them on construction. */
    get context(): {
        orgName?: string;
        appName?: string;
    };
}
declare class IamApiError extends Error {
    readonly status: number;
    constructor(status: number, message: string);
}

/**
 * PKCE (Proof Key for Code Exchange) utilities for browser-side OAuth2 flows.
 *
 * PKCE utilities for OAuth2 flows, using native Web Crypto API.
 */
/** Generate a PKCE code verifier + challenge pair. */
declare function generatePKCEChallenge(): Promise<{
    codeVerifier: string;
    codeChallenge: string;
}>;
/** Generate a random state parameter for CSRF protection. */
declare function generateState(): string;

export { IamApiError, IamClient, IamConfig, IamUser, OidcDiscovery, TokenResponse, generatePKCEChallenge, generateState };
