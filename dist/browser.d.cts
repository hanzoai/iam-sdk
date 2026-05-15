import { IamConfig, TokenResponse } from './types.cjs';

/**
 * Browser-side OAuth2/OIDC PKCE flow for Hanzo IAM.
 *
 * Pure standards: RFC 6749 (OAuth2), RFC 7636 (PKCE), OIDC core. No
 * Casdoor REST shortcuts (`/login`, `/signup`, `/send-verification-code`,
 * `/get-phone-user`, etc.). Apps drive a single redirect-to-authorize
 * flow; the IAM server owns every credential interaction.
 *
 *   IAM#signinRedirect()    — start PKCE redirect to /oauth/authorize
 *   IAM#handleCallback()    — exchange code at /oauth/token
 *   IAM#refreshAccessToken()— refresh grant
 *   IAM#signinPopup()       — same flow in a popup window
 *   IAM#signinSilent()      — prompt=none iframe attempt
 *   IAM#getUserInfo()       — /oauth/userinfo
 *   IAM#logout()            — RP-initiated logout (/oauth/logout)
 */

type IAMConfig = IamConfig & {
    /** OAuth2 redirect URI (e.g. "https://app.hanzo.bot/auth/callback"). */
    redirectUri: string;
    /** OAuth2 scopes (default: "openid profile email"). */
    scope?: string;
    /** Storage to use for tokens (default: sessionStorage). */
    storage?: Storage;
    /**
     * Optional proxy base URL for the token + userinfo endpoints.
     * When set, token exchange POSTs hit `${proxyBaseUrl}/oauth/token`
     * and userinfo GETs hit `${proxyBaseUrl}/oauth/userinfo` instead of
     * the IAM origin directly. Use this to keep cross-origin requests
     * off the browser (gateway proxies same-origin to IAM).
     */
    proxyBaseUrl?: string;
};
declare class IAM {
    private readonly config;
    private readonly storage;
    private discoveryCache;
    constructor(config: IAMConfig);
    private getDiscovery;
    private tokenEndpoint;
    private userinfoEndpoint;
    private buildAuthorizeUrl;
    /**
     * Start the OAuth2 PKCE login flow by redirecting to /oauth/authorize.
     * Generates PKCE challenge + state, stores them in session storage,
     * then sets `window.location.href`.
     */
    signinRedirect(params?: {
        additionalParams?: Record<string, string>;
    }): Promise<void>;
    /**
     * Build the authorize URL without redirecting — useful for `<a href>`
     * (e.g. social login buttons with `provider` in additionalParams).
     */
    getSigninUrl(params?: {
        additionalParams?: Record<string, string>;
    }): Promise<string>;
    /**
     * Handle the OAuth2 callback after the IAM redirect. Validates state,
     * exchanges the authorization code for tokens with PKCE, and stores
     * the result.
     *
     * Call this on your callback route (e.g. /auth/callback).
     */
    handleCallback(callbackUrl?: string): Promise<IAMToken>;
    /** Refresh the access token using the stored refresh token. */
    refreshAccessToken(): Promise<IAMToken>;
    /**
     * Open the IAM login page in a popup window. Resolves when the popup
     * completes the OAuth flow and returns tokens.
     */
    signinPopup(params?: {
        width?: number;
        height?: number;
        additionalParams?: Record<string, string>;
    }): Promise<IAMToken>;
    /**
     * Attempt silent authentication via a hidden iframe (`prompt=none`).
     * Returns null if silent auth fails (user needs to log in interactively).
     */
    signinSilent(timeoutMs?: number): Promise<IAMToken | null>;
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
    /** Clear all stored tokens (local logout). */
    clearTokens(): void;
    /**
     * RP-initiated logout (OIDC). Best-effort POST to /oauth/logout to
     * terminate the server-side session, then clears local tokens.
     */
    logout(): Promise<void>;
    /** Fetch user info from /oauth/userinfo using the stored access token. */
    getUserInfo(): Promise<Record<string, unknown>>;
    /**
     * Fetch the current user, shaped into the canonical `IAMUser` form
     * (camelCase, no `_` keys). Returns null when no token is present.
     */
    getUser(): Promise<IAMUser | null>;
}
/**
 * Canonical user shape returned by `IAM#getUser()`. Maps the OIDC userinfo
 * response (snake_case) to camelCase.
 */
type IAMUser = {
    sub: string;
    email?: string;
    name?: string;
    givenName?: string;
    familyName?: string;
    phoneNumber?: string;
    emailVerified?: boolean;
    picture?: string;
    owner?: string;
};
/**
 * Canonical token shape (camelCase, no `_` keys) for app code.
 */
type IAMToken = {
    accessToken: string;
    refreshToken?: string;
    idToken?: string;
    expiresIn?: number;
    tokenType?: string;
    scope?: string;
};
/** Convert the raw OAuth2 token response into the canonical `IAMToken`. */
declare function toIAMToken(t: TokenResponse): IAMToken;

export { IAM, type IAMConfig, type IAMToken, type IAMUser, toIAMToken };
