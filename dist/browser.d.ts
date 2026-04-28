/**
 * Browser-side OAuth2 flows for Hanzo IAM.
 *
 * Provides PKCE-based login redirect, code exchange, token refresh,
 * popup signin, and silent signin for single-page applications.
 *
 * Adapted and modernized for Hanzo IAM.
 */
import type { IamConfig, TokenResponse } from "./types.js";
export type IAMConfig = IamConfig & {
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
export declare class IAM {
    private readonly config;
    private readonly storage;
    private discoveryCache;
    constructor(config: IAMConfig);
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
    /**
     * Send a verification code to a phone or email destination.
     *
     * @param contact `{ phone, countryCode }` for SMS, `{ email }` for email.
     * @param method  Casdoor method: `login`, `signup`, `forget`, `mfaSetup`, etc.
     */
    sendVerificationCode(contact: {
        phone: string;
        countryCode: string;
    } | {
        email: string;
    }, method?: "login" | "signup" | "forget" | "mfaSetup"): Promise<{
        ok: boolean;
        error?: string;
    }>;
    /**
     * Look up whether a phone number is registered. Returns `{ exists: false }`
     * on 404 or unknown numbers; `{ exists: true }` when Casdoor confirms a user.
     */
    lookupPhoneUser(phone: string, countryCode: string): Promise<{
        exists: boolean;
        error?: string;
    }>;
    /**
     * Casdoor REST signup. Returns the new user's id on success.
     *
     * Phone signup flow: send phoneCode via `sendVerificationCode`, then call
     * this with the OTP in `phoneCode`. Casdoor verifies the code internally.
     * Email signup flow: same with `email` + `emailCode`.
     */
    signup(params: {
        method: "email" | "phone";
        name: string;
        username?: string;
        email?: string;
        phone?: string;
        countryCode?: string;
        password?: string;
        emailCode?: string;
        phoneCode?: string;
    }): Promise<{
        id?: string;
        ok: boolean;
        error?: string;
    }>;
    /**
     * REST login that returns an authorization code (Casdoor `/login`).
     *
     * Use this when you want the caller to drive the PKCE flow without a
     * full redirect — collect credentials in your own UI, get a code back,
     * then call `exchangeCodeForToken` to land tokens.
     */
    loginWithCredentials(params: {
        username: string;
        password: string;
        type?: "code" | "token";
        redirectUri?: string;
    }): Promise<{
        code?: string;
        ok: boolean;
        error?: string;
    }>;
    /**
     * Exchange an authorization code for tokens using the stored PKCE verifier.
     * Pairs with `loginWithCredentials` for a code → tokens round-trip.
     */
    exchangeCodeForToken(code: string, redirectUri?: string): Promise<TokenResponse>;
    /**
     * Phone OTP login: tries the numbered username variants Casdoor accepts
     * (`{phone}`, `{countryCode}{phone}`), exchanges the resulting code for
     * tokens. Returns the token response, or throws on failure.
     */
    loginWithPhoneOTP(params: {
        phone: string;
        countryCode: string;
        code: string;
        redirectUri?: string;
    }): Promise<TokenResponse>;
    /**
     * Logout via Casdoor REST `/logout` (clears server-side session) and
     * the local storage.
     */
    logout(): Promise<void>;
}
//# sourceMappingURL=browser.d.ts.map