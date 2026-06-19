/**
 * Browser-side OAuth2/OIDC PKCE flow for Hanzo IAM.
 *
 * Pure standards: RFC 6749 (OAuth2), RFC 7636 (PKCE), OIDC core. No
 * Casdoor REST shortcuts (`/login`, `/signup`, `/send-verification-code`,
 * `/get-phone-user`, etc.). Apps drive a single redirect-to-authorize
 * flow; the IAM server owns every credential interaction.
 *
 *   IAM#signinRedirect()    — start PKCE redirect to the authorize endpoint
 *   IAM#handleCallback()    — exchange code at the token endpoint
 *   IAM#refreshAccessToken()— refresh grant
 *   IAM#signinPopup()       — same flow in a popup window
 *   IAM#signinSilent()      — prompt=none iframe attempt
 *   IAM#getUserInfo()       — userinfo endpoint
 *   IAM#logout()            — RP-initiated logout
 *
 * Every endpoint resolves through `OIDC_PATHS` (see ./paths). Live OIDC
 * discovery is preferred when reachable; the hard-coded fallback uses
 * the exact same canonical paths so a CORS/network failure degrades to
 * correct URLs, never to the IAM HTML SPA catch-all.
 */

import type { Config, TokenResponse, OidcDiscovery } from "./types.js";
import { generatePKCEChallenge, generateState } from "./pkce.js";
import { OIDC_PATHS, iamUrl, trimServerUrl } from "./paths.js";

// ---------------------------------------------------------------------------
// Storage keys
// ---------------------------------------------------------------------------

const STORAGE_PREFIX = "hanzo_iam_";
const KEY_STATE = `${STORAGE_PREFIX}state`;
const KEY_CODE_VERIFIER = `${STORAGE_PREFIX}code_verifier`;
const KEY_ACCESS_TOKEN = `${STORAGE_PREFIX}access_token`;
const KEY_REFRESH_TOKEN = `${STORAGE_PREFIX}refresh_token`;
const KEY_ID_TOKEN = `${STORAGE_PREFIX}id_token`;
const KEY_EXPIRES_AT = `${STORAGE_PREFIX}expires_at`;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

export type IAMConfig = Config & {
  /** OAuth2 redirect URI (e.g. "https://app.hanzo.bot/auth/callback"). */
  redirectUri: string;
  /** OAuth2 scopes (default: "openid profile email"). */
  scope?: string;
  /** Storage to use for tokens (default: sessionStorage). */
  storage?: Storage;
  /**
   * Optional proxy base URL for the token + userinfo endpoints.
   * When set, token exchange POSTs hit `${proxyBaseUrl}/v1/iam/oauth/token`
   * and userinfo GETs hit `${proxyBaseUrl}/v1/iam/oauth/userinfo` instead
   * of the IAM origin directly. Use this to keep cross-origin requests
   * off the browser (gateway proxies same-origin to IAM).
   */
  proxyBaseUrl?: string;
};

// ---------------------------------------------------------------------------
// Browser IAM SDK
// ---------------------------------------------------------------------------

export class IAM {
  private readonly config: IAMConfig;
  private readonly storage: Storage;
  private discoveryCache: OidcDiscovery | null = null;

  constructor(config: IAMConfig) {
    this.config = config;
    this.storage = config.storage ?? sessionStorage;
  }

  // -----------------------------------------------------------------------
  // OIDC Discovery
  // -----------------------------------------------------------------------

  private async getDiscovery(): Promise<OidcDiscovery> {
    if (this.discoveryCache) return this.discoveryCache;

    const baseUrl = trimServerUrl(this.config.serverUrl);

    // Prefer live OIDC discovery. If it fails (e.g. CORS when the IAM
    // server doesn't send Access-Control-Allow-Origin), construct a
    // fallback from the canonical OIDC_PATHS — the SAME paths discovery
    // would return, so a failed round-trip degrades to correct URLs,
    // never to the IAM HTML SPA catch-all.
    try {
      const res = await fetch(`${baseUrl}${OIDC_PATHS.discovery}`, {
        headers: { Accept: "application/json" },
      });
      if (res.ok) {
        this.discoveryCache = (await res.json()) as OidcDiscovery;
        return this.discoveryCache;
      }
    } catch {
      // CORS or network error — fall through to constructed discovery
    }

    this.discoveryCache = {
      issuer: baseUrl,
      authorization_endpoint: iamUrl(baseUrl, "authorize"),
      token_endpoint: iamUrl(baseUrl, "token"),
      userinfo_endpoint: iamUrl(baseUrl, "userinfo"),
      jwks_uri: iamUrl(baseUrl, "jwks"),
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      scopes_supported: ["openid", "email", "profile"],
    };
    return this.discoveryCache;
  }

  // -----------------------------------------------------------------------
  // Token endpoint URL (proxy-aware)
  // -----------------------------------------------------------------------

  private async tokenEndpoint(): Promise<string> {
    if (this.config.proxyBaseUrl) {
      return iamUrl(this.config.proxyBaseUrl, "token");
    }
    const discovery = await this.getDiscovery();
    return discovery.token_endpoint;
  }

  private async userinfoEndpoint(): Promise<string> {
    if (this.config.proxyBaseUrl) {
      return iamUrl(this.config.proxyBaseUrl, "userinfo");
    }
    const discovery = await this.getDiscovery();
    return discovery.userinfo_endpoint;
  }

  // -----------------------------------------------------------------------
  // Authorize URL builder
  // -----------------------------------------------------------------------

  private async buildAuthorizeUrl(extra?: {
    additionalParams?: Record<string, string>;
    prompt?: string;
  }): Promise<{ url: URL; codeVerifier: string; state: string }> {
    const discovery = await this.getDiscovery();
    const { codeVerifier, codeChallenge } = await generatePKCEChallenge();
    const state = generateState();

    this.storage.setItem(KEY_STATE, state);
    this.storage.setItem(KEY_CODE_VERIFIER, codeVerifier);

    const url = new URL(discovery.authorization_endpoint);
    url.searchParams.set("client_id", this.config.clientId);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("redirect_uri", this.config.redirectUri);
    url.searchParams.set("scope", this.config.scope ?? "openid profile email");
    url.searchParams.set("state", state);
    url.searchParams.set("code_challenge", codeChallenge);
    url.searchParams.set("code_challenge_method", "S256");

    if (extra?.prompt) url.searchParams.set("prompt", extra.prompt);
    if (extra?.additionalParams) {
      for (const [k, v] of Object.entries(extra.additionalParams)) {
        url.searchParams.set(k, v);
      }
    }
    return { url, codeVerifier, state };
  }

  // -----------------------------------------------------------------------
  // Login redirect (PKCE)
  // -----------------------------------------------------------------------

  /**
   * Start the OAuth2 PKCE login flow by redirecting to /oauth/authorize.
   * Generates PKCE challenge + state, stores them in session storage,
   * then sets `window.location.href`.
   */
  async signinRedirect(params?: { additionalParams?: Record<string, string> }): Promise<void> {
    const { url } = await this.buildAuthorizeUrl(params);
    window.location.href = url.toString();
  }

  /**
   * Build the authorize URL without redirecting — useful for `<a href>`
   * (e.g. social login buttons with `provider` in additionalParams).
   */
  async getSigninUrl(params?: { additionalParams?: Record<string, string> }): Promise<string> {
    const { url } = await this.buildAuthorizeUrl(params);
    return url.toString();
  }

  // -----------------------------------------------------------------------
  // Callback handling
  // -----------------------------------------------------------------------

  /**
   * Handle the OAuth2 callback after the IAM redirect. Validates state,
   * exchanges the authorization code for tokens with PKCE, and stores
   * the result.
   *
   * Call this on your callback route (e.g. /auth/callback).
   */
  async handleCallback(callbackUrl?: string): Promise<IAMToken> {
    const url = new URL(callbackUrl ?? window.location.href);
    const error = url.searchParams.get("error");

    if (error) {
      const desc = url.searchParams.get("error_description") ?? error;
      throw new Error(`OAuth error: ${desc}`);
    }

    const state = url.searchParams.get("state");
    const savedState = this.storage.getItem(KEY_STATE);
    if (savedState && state !== savedState) {
      throw new Error("OAuth state mismatch — possible CSRF attack");
    }

    const code = url.searchParams.get("code");
    if (!code) {
      throw new Error("Missing authorization code in callback URL");
    }

    // PKCE verifier is present for SDK-initiated (signinRedirect / social)
    // flows. The embedded credential flow (`/v1/iam/login`, used by
    // `@hanzo/iam/views`) mints the code WITHOUT PKCE, so a missing verifier
    // is valid — exchange without it (the IAM accepts a non-PKCE code
    // exchange for the same public client). State is still verified above.
    const codeVerifier = this.storage.getItem(KEY_CODE_VERIFIER);

    // One-shot — clean up state before the network call.
    this.storage.removeItem(KEY_STATE);
    this.storage.removeItem(KEY_CODE_VERIFIER);

    const body = new URLSearchParams({
      grant_type: "authorization_code",
      client_id: this.config.clientId,
      code,
      redirect_uri: this.config.redirectUri,
    });
    if (codeVerifier) body.set("code_verifier", codeVerifier);

    const tokenUrl = await this.tokenEndpoint();
    const res = await fetch(tokenUrl, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    });

    if (!res.ok) {
      const text = await res.text().catch(() => "");
      throw new Error(`Token exchange failed (${res.status}): ${text}`);
    }

    const tokens = (await res.json()) as TokenResponse;
    this.storeTokens(tokens);
    return toIAMToken(tokens);
  }

  // -----------------------------------------------------------------------
  // Token refresh
  // -----------------------------------------------------------------------

  /** Refresh the access token using the stored refresh token. */
  async refreshAccessToken(): Promise<IAMToken> {
    const refreshToken = this.storage.getItem(KEY_REFRESH_TOKEN);
    if (!refreshToken) {
      throw new Error("No refresh token available");
    }

    const body = new URLSearchParams({
      grant_type: "refresh_token",
      client_id: this.config.clientId,
      refresh_token: refreshToken,
    });

    const tokenUrl = await this.tokenEndpoint();
    const res = await fetch(tokenUrl, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    });

    if (!res.ok) {
      const text = await res.text().catch(() => "");
      throw new Error(`Token refresh failed (${res.status}): ${text}`);
    }

    const tokens = (await res.json()) as TokenResponse;
    this.storeTokens(tokens);
    return toIAMToken(tokens);
  }

  // -----------------------------------------------------------------------
  // Popup signin
  // -----------------------------------------------------------------------

  /**
   * Open the IAM login page in a popup window. Resolves when the popup
   * completes the OAuth flow and returns tokens.
   */
  async signinPopup(params?: {
    width?: number;
    height?: number;
    additionalParams?: Record<string, string>;
  }): Promise<IAMToken> {
    const { url } = await this.buildAuthorizeUrl({
      additionalParams: params?.additionalParams,
    });

    const width = params?.width ?? 600;
    const height = params?.height ?? 700;
    const left = window.screenX + (window.outerWidth - width) / 2;
    const top = window.screenY + (window.outerHeight - height) / 2;

    return new Promise<IAMToken>((resolve, reject) => {
      const popup = window.open(
        url.toString(),
        "hanzo_iam_login",
        `width=${width},height=${height},left=${left},top=${top},menubar=no,toolbar=no`,
      );

      if (!popup) {
        reject(new Error("Failed to open login popup — blocked by browser?"));
        return;
      }

      const interval = setInterval(() => {
        try {
          if (popup.closed) {
            clearInterval(interval);
            reject(new Error("Login popup was closed before completing"));
            return;
          }
          // Check if popup navigated to our redirect URI
          const popupUrl = popup.location.href;
          if (popupUrl.startsWith(this.config.redirectUri)) {
            clearInterval(interval);
            popup.close();
            this.handleCallback(popupUrl).then(resolve, reject);
          }
        } catch {
          // Cross-origin — popup is still on IAM domain, keep waiting
        }
      }, 200);
    });
  }

  // -----------------------------------------------------------------------
  // Silent signin (iframe)
  // -----------------------------------------------------------------------

  /**
   * Attempt silent authentication via a hidden iframe (`prompt=none`).
   * Returns null if silent auth fails (user needs to log in interactively).
   */
  async signinSilent(timeoutMs = 5000): Promise<IAMToken | null> {
    const { url } = await this.buildAuthorizeUrl({ prompt: "none" });

    return new Promise<IAMToken | null>((resolve) => {
      const iframe = document.createElement("iframe");
      iframe.style.display = "none";

      const timeout = setTimeout(() => {
        cleanup();
        resolve(null);
      }, timeoutMs);

      const cleanup = () => {
        clearTimeout(timeout);
        iframe.remove();
        this.storage.removeItem(KEY_STATE);
        this.storage.removeItem(KEY_CODE_VERIFIER);
      };

      iframe.addEventListener("load", () => {
        try {
          const iframeUrl = iframe.contentWindow?.location.href;
          if (iframeUrl && iframeUrl.startsWith(this.config.redirectUri)) {
            cleanup();
            this.handleCallback(iframeUrl).then(
              (tokens) => resolve(tokens),
              () => resolve(null),
            );
          }
        } catch {
          // Cross-origin or error — silent auth failed
          cleanup();
          resolve(null);
        }
      });

      iframe.src = url.toString();
      document.body.appendChild(iframe);
    });
  }

  // -----------------------------------------------------------------------
  // Token management
  // -----------------------------------------------------------------------

  private storeTokens(tokens: TokenResponse): void {
    this.storage.setItem(KEY_ACCESS_TOKEN, tokens.access_token);
    if (tokens.refresh_token) {
      this.storage.setItem(KEY_REFRESH_TOKEN, tokens.refresh_token);
    }
    if (tokens.id_token) {
      this.storage.setItem(KEY_ID_TOKEN, tokens.id_token);
    }
    if (tokens.expires_in) {
      const expiresAt = Date.now() + tokens.expires_in * 1000;
      this.storage.setItem(KEY_EXPIRES_AT, String(expiresAt));
    }
  }

  /** Get the stored access token (may be expired). */
  getAccessToken(): string | null {
    return this.storage.getItem(KEY_ACCESS_TOKEN);
  }

  /** Get the stored refresh token. */
  getRefreshToken(): string | null {
    return this.storage.getItem(KEY_REFRESH_TOKEN);
  }

  /** Get the stored ID token. */
  getIdToken(): string | null {
    return this.storage.getItem(KEY_ID_TOKEN);
  }

  /** Check if the stored access token is expired. */
  isTokenExpired(): boolean {
    const expiresAt = this.storage.getItem(KEY_EXPIRES_AT);
    if (!expiresAt) return true;
    return Date.now() >= Number(expiresAt);
  }

  /**
   * Get a valid access token — refreshes automatically if expired.
   * Returns null if no token and no refresh token available.
   */
  async getValidAccessToken(): Promise<string | null> {
    const token = this.getAccessToken();
    if (token && !this.isTokenExpired()) {
      return token;
    }
    if (this.getRefreshToken()) {
      try {
        const tokens = await this.refreshAccessToken();
        return tokens.accessToken;
      } catch {
        return null;
      }
    }
    return null;
  }

  /** Clear all stored tokens (local logout). */
  clearTokens(): void {
    this.storage.removeItem(KEY_ACCESS_TOKEN);
    this.storage.removeItem(KEY_REFRESH_TOKEN);
    this.storage.removeItem(KEY_ID_TOKEN);
    this.storage.removeItem(KEY_EXPIRES_AT);
    this.storage.removeItem(KEY_STATE);
    this.storage.removeItem(KEY_CODE_VERIFIER);
  }

  // -----------------------------------------------------------------------
  // RP-initiated logout
  // -----------------------------------------------------------------------

  /**
   * RP-initiated logout (OIDC). Best-effort POST to the logout endpoint
   * to terminate the server-side session, then clears local tokens.
   */
  async logout(): Promise<void> {
    const token = this.storage.getItem(KEY_ACCESS_TOKEN);
    try {
      await fetch(iamUrl(this.config.serverUrl, "logout"), {
        method: "POST",
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });
    } catch {
      // best-effort — local cleanup is what matters
    }
    this.clearTokens();
  }

  // -----------------------------------------------------------------------
  // User info
  // -----------------------------------------------------------------------

  /** Fetch user info from /oauth/userinfo using the stored access token. */
  async getUserInfo(): Promise<Record<string, unknown>> {
    const token = await this.getValidAccessToken();
    if (!token) {
      throw new Error("No valid access token — user must log in");
    }
    const url = await this.userinfoEndpoint();
    const res = await fetch(url, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!res.ok) {
      throw new Error(`Userinfo fetch failed (${res.status})`);
    }
    return (await res.json()) as Record<string, unknown>;
  }

  /**
   * Fetch the current user, shaped into the canonical `IAMUser` form
   * (camelCase, no `_` keys). Returns null when no token is present.
   */
  async getUser(): Promise<IAMUser | null> {
    const token = await this.getValidAccessToken();
    if (!token) return null;
    const u = (await this.getUserInfo()) as Record<string, unknown>;
    return {
      sub: (u.sub as string) ?? "",
      email: u.email as string | undefined,
      name: u.name as string | undefined,
      givenName: u.given_name as string | undefined,
      familyName: u.family_name as string | undefined,
      phoneNumber: u.phone_number as string | undefined,
      emailVerified: u.email_verified as boolean | undefined,
      picture: u.picture as string | undefined,
      owner: u.owner as string | undefined,
    };
  }
}

/**
 * Canonical user shape returned by `IAM#getUser()`. Maps the OIDC userinfo
 * response (snake_case) to camelCase.
 */
export type IAMUser = {
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
export type IAMToken = {
  accessToken: string;
  refreshToken?: string;
  idToken?: string;
  expiresIn?: number;
  tokenType?: string;
  scope?: string;
};

/** Convert the raw OAuth2 token response into the canonical `IAMToken`. */
export function toIAMToken(t: TokenResponse): IAMToken {
  return {
    accessToken: t.access_token,
    refreshToken: t.refresh_token,
    idToken: t.id_token,
    expiresIn: t.expires_in,
    tokenType: t.token_type,
    scope: t.scope,
  };
}
