import { IamConfig, OidcDiscovery, TokenResponse, IamUser, IamOrganization, IamProject } from './types.cjs';
export { IamApiResponse, IamAuthResult, IamJwtClaims, IamOrder, IamPayment, IamPlan, IamPricing, IamSubscription, IamUsageRecord, IamUsageSummary, Order, Payment, Plan, Pricing, Subscription, UsageRecord, UsageSummary } from './types.cjs';
export { clearJwksCache, validateToken } from './auth.cjs';
export { IAM, IAMConfig, IAMToken, IAMUser, toIAMToken } from './browser.cjs';

/**
 * Core HTTP client for Hanzo IAM API.
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
    /** Exchange authorization code for tokens. */
    exchangeCode(params: {
        code: string;
        redirectUri: string;
        codeVerifier?: string;
    }): Promise<TokenResponse>;
    /**
     * Resource Owner Password Credentials grant.
     * Used for service-to-service auth, CLI login, and e2e tests.
     */
    passwordGrant(params: {
        username: string;
        password: string;
        scope?: string;
    }): Promise<TokenResponse>;
    /** Refresh an access token. */
    refreshToken(refreshToken: string): Promise<TokenResponse>;
    /** Get user info from access token (OIDC userinfo endpoint). */
    getUserInfo(accessToken: string): Promise<IamUser>;
    /** Get a user by ID ("org/username" format). */
    getUser(userId: string, token?: string): Promise<IamUser | null>;
    /** List organizations (for the configured owner). */
    getOrganizations(token?: string): Promise<IamOrganization[]>;
    /** Get a specific organization. */
    getOrganization(id: string, token?: string): Promise<IamOrganization | null>;
    /** Get organizations a user belongs to. */
    getUserOrganizations(userId: string, token?: string): Promise<IamOrganization[]>;
    /** List projects (for the configured owner). */
    getProjects(token?: string): Promise<IamProject[]>;
    /** Get a specific project by ID ("owner/name" format). */
    getProject(id: string, token?: string): Promise<IamProject | null>;
    /** Get all projects for an organization. */
    getOrganizationProjects(organization: string, token?: string): Promise<IamProject[]>;
    /** Make an arbitrary authenticated request to the IAM API. */
    apiRequest<T = unknown>(path: string, opts?: {
        method?: string;
        body?: unknown;
        token?: string;
        params?: Record<string, string>;
    }): Promise<T>;
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

export { IamApiError, IamClient, IamConfig, IamOrganization, IamProject, IamUser, OidcDiscovery, TokenResponse, generatePKCEChallenge, generateState };
