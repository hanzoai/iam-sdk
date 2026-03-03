/**
 * Core HTTP client for Hanzo IAM API.
 */
import type { IamConfig, IamUser, IamOrganization, IamProject, OidcDiscovery, TokenResponse } from "./types.js";
export declare class IamClient {
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
export declare class IamApiError extends Error {
    readonly status: number;
    constructor(status: number, message: string);
}
//# sourceMappingURL=client.d.ts.map