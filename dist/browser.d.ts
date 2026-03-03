/**
 * Browser-side OAuth2 flows for Hanzo IAM.
 *
 * Provides PKCE-based login redirect, code exchange, token refresh,
 * popup signin, and silent signin for single-page applications.
 *
 * Adapted and modernized for Hanzo IAM.
 */
import type { IamConfig, TokenResponse } from "./types.js";
export type BrowserIamConfig = IamConfig & {
    /** OAuth2 redirect URI (e.g. "https://app.hanzo.bot/auth/callback"). */
    redirectUri: string;
    /** OAuth2 scopes (default: "openid profile email"). */
    scope?: string;
    /** Storage to use for tokens (default: sessionStorage). */
    storage?: Storage;
    /**
     * Proxy base URL for token exchange and userinfo requests.
     * When set, token exchange POSTs go to `${proxyBaseUrl}/auth/token`
     * and userinfo GETs go to `${proxyBaseUrl}/auth/userinfo` instead of
     * directly to the IAM server. This avoids CORS issues when the IAM
     * server doesn't send Access-Control-Allow-Origin headers.
     */
    proxyBaseUrl?: string;
};
export declare class BrowserIamSdk {
    private readonly config;
    private readonly storage;
    private discoveryCache;
    constructor(config: BrowserIamConfig);
    private getDiscovery;
    /**
     * Start the OAuth2 PKCE login flow by redirecting to the IAM authorize endpoint.
     *
     * Generates PKCE challenge and state, stores them in session storage,
     * then redirects the browser.
     */
    signinRedirect(params?: {
        additionalParams?: Record<string, string>;
    }): Promise<void>;
    /**
     * Handle the OAuth2 callback after redirect. Exchanges the authorization code
     * for tokens using PKCE.
     *
     * Call this on your callback page (e.g. /auth/callback).
     * Returns the token response, or throws if the state doesn't match.
     */
    handleCallback(callbackUrl?: string): Promise<TokenResponse>;
    /** Refresh the access token using the stored refresh token. */
    refreshAccessToken(): Promise<TokenResponse>;
    /**
     * Open the IAM login page in a popup window. Resolves when the popup
     * completes the OAuth flow and returns tokens.
     */
    signinPopup(params?: {
        width?: number;
        height?: number;
        additionalParams?: Record<string, string>;
    }): Promise<TokenResponse>;
    /**
     * Attempt silent authentication via a hidden iframe.
     * Useful for checking if the user has an active IAM session.
     * Returns null if silent auth fails (user needs to log in interactively).
     */
    signinSilent(timeoutMs?: number): Promise<TokenResponse | null>;
    private storeTokens;
    /** Get the stored access token (may be expired). */
    getAccessToken(): string | null;
    /** Get the stored refresh token. */
    getRefreshToken(): string | null;
    /** Get the stored ID token. */
    getIdToken(): string | null;
    /** Check if the stored access token is expired. */
    isTokenExpired(): boolean;
    /**
     * Get a valid access token — refreshes automatically if expired.
     * Returns null if no token and no refresh token available.
     */
    getValidAccessToken(): Promise<string | null>;
    /** Clear all stored tokens (logout). */
    clearTokens(): void;
    /** Fetch user info from the OIDC userinfo endpoint using the stored access token. */
    getUserInfo(): Promise<Record<string, unknown>>;
    /** Build the signup URL for the IAM server. */
    getSignupUrl(params?: {
        enablePassword?: boolean;
    }): string;
    /** Build the user profile URL on the IAM server. */
    getUserProfileUrl(username: string): string;
}
//# sourceMappingURL=browser.d.ts.map