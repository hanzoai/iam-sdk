/**
 * Browser-side OAuth2 flows for Hanzo IAM.
 *
 * Provides PKCE-based login redirect, code exchange, token refresh,
 * popup signin, and silent signin for single-page applications.
 *
 * Adapted and modernized from casdoor-js-sdk.
 */

import type { IamConfig, TokenResponse, OidcDiscovery } from "./types.js";
import { generatePkceChallenge, generateState } from "./pkce.js";

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
// Browser IAM SDK
// ---------------------------------------------------------------------------

export type BrowserIamConfig = IamConfig & {
  /** OAuth2 redirect URI (e.g. "https://app.hanzo.bot/auth/callback"). */
  redirectUri: string;
  /** OAuth2 scopes (default: "openid profile email"). */
  scope?: string;
  /** Storage to use for tokens (default: sessionStorage). */
  storage?: Storage;
};

export class BrowserIamSdk {
  private readonly config: BrowserIamConfig;
  private readonly storage: Storage;
  private discoveryCache: OidcDiscovery | null = null;

  constructor(config: BrowserIamConfig) {
    this.config = config;
    this.storage = config.storage ?? sessionStorage;
  }

  // -----------------------------------------------------------------------
  // OIDC Discovery
  // -----------------------------------------------------------------------

  private async getDiscovery(): Promise<OidcDiscovery> {
    if (this.discoveryCache) return this.discoveryCache;

    const baseUrl = this.config.serverUrl.replace(/\/+$/, "");
    const res = await fetch(`${baseUrl}/.well-known/openid-configuration`, {
      headers: { Accept: "application/json" },
    });
    if (!res.ok) {
      throw new Error(`OIDC discovery failed: ${res.status}`);
    }
    this.discoveryCache = (await res.json()) as OidcDiscovery;
    return this.discoveryCache;
  }

  // -----------------------------------------------------------------------
  // Login redirect (PKCE)
  // -----------------------------------------------------------------------

  /**
   * Start the OAuth2 PKCE login flow by redirecting to the IAM authorize endpoint.
   *
   * Generates PKCE challenge and state, stores them in session storage,
   * then redirects the browser.
   */
  async signinRedirect(params?: { additionalParams?: Record<string, string> }): Promise<void> {
    const discovery = await this.getDiscovery();
    const { codeVerifier, codeChallenge } = await generatePkceChallenge();
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

    if (params?.additionalParams) {
      for (const [k, v] of Object.entries(params.additionalParams)) {
        url.searchParams.set(k, v);
      }
    }

    window.location.href = url.toString();
  }

  // -----------------------------------------------------------------------
  // Callback handling
  // -----------------------------------------------------------------------

  /**
   * Handle the OAuth2 callback after redirect. Exchanges the authorization code
   * for tokens using PKCE.
   *
   * Call this on your callback page (e.g. /auth/callback).
   * Returns the token response, or throws if the state doesn't match.
   */
  async handleCallback(callbackUrl?: string): Promise<TokenResponse> {
    const url = new URL(callbackUrl ?? window.location.href);
    const code = url.searchParams.get("code");
    const state = url.searchParams.get("state");
    const error = url.searchParams.get("error");

    if (error) {
      const desc = url.searchParams.get("error_description") ?? error;
      throw new Error(`OAuth error: ${desc}`);
    }

    if (!code) {
      throw new Error("Missing authorization code in callback URL");
    }

    const savedState = this.storage.getItem(KEY_STATE);
    if (!savedState || savedState !== state) {
      throw new Error("OAuth state mismatch — possible CSRF attack");
    }

    const codeVerifier = this.storage.getItem(KEY_CODE_VERIFIER);
    if (!codeVerifier) {
      throw new Error("Missing PKCE code verifier — was signinRedirect() called?");
    }

    // Clean up one-time state
    this.storage.removeItem(KEY_STATE);
    this.storage.removeItem(KEY_CODE_VERIFIER);

    const discovery = await this.getDiscovery();
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      client_id: this.config.clientId,
      code,
      redirect_uri: this.config.redirectUri,
      code_verifier: codeVerifier,
    });

    const res = await fetch(discovery.token_endpoint, {
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
    return tokens;
  }

  // -----------------------------------------------------------------------
  // Token refresh
  // -----------------------------------------------------------------------

  /** Refresh the access token using the stored refresh token. */
  async refreshAccessToken(): Promise<TokenResponse> {
    const refreshToken = this.storage.getItem(KEY_REFRESH_TOKEN);
    if (!refreshToken) {
      throw new Error("No refresh token available");
    }

    const discovery = await this.getDiscovery();
    const body = new URLSearchParams({
      grant_type: "refresh_token",
      client_id: this.config.clientId,
      refresh_token: refreshToken,
    });

    const res = await fetch(discovery.token_endpoint, {
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
    return tokens;
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
  }): Promise<TokenResponse> {
    const discovery = await this.getDiscovery();
    const { codeVerifier, codeChallenge } = await generatePkceChallenge();
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

    if (params?.additionalParams) {
      for (const [k, v] of Object.entries(params.additionalParams)) {
        url.searchParams.set(k, v);
      }
    }

    const width = params?.width ?? 600;
    const height = params?.height ?? 700;
    const left = window.screenX + (window.outerWidth - width) / 2;
    const top = window.screenY + (window.outerHeight - height) / 2;

    return new Promise<TokenResponse>((resolve, reject) => {
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
   * Attempt silent authentication via a hidden iframe.
   * Useful for checking if the user has an active IAM session.
   * Returns null if silent auth fails (user needs to log in interactively).
   */
  async signinSilent(timeoutMs = 5000): Promise<TokenResponse | null> {
    const discovery = await this.getDiscovery();
    const { codeVerifier, codeChallenge } = await generatePkceChallenge();
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
    url.searchParams.set("prompt", "none"); // No interactive login

    return new Promise<TokenResponse | null>((resolve) => {
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
        return tokens.access_token;
      } catch {
        return null;
      }
    }
    return null;
  }

  /** Clear all stored tokens (logout). */
  clearTokens(): void {
    this.storage.removeItem(KEY_ACCESS_TOKEN);
    this.storage.removeItem(KEY_REFRESH_TOKEN);
    this.storage.removeItem(KEY_ID_TOKEN);
    this.storage.removeItem(KEY_EXPIRES_AT);
    this.storage.removeItem(KEY_STATE);
    this.storage.removeItem(KEY_CODE_VERIFIER);
  }

  // -----------------------------------------------------------------------
  // User info
  // -----------------------------------------------------------------------

  /** Fetch user info from the OIDC userinfo endpoint using the stored access token. */
  async getUserInfo(): Promise<Record<string, unknown>> {
    const token = await this.getValidAccessToken();
    if (!token) {
      throw new Error("No valid access token — user must log in");
    }
    const discovery = await this.getDiscovery();
    const res = await fetch(discovery.userinfo_endpoint, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!res.ok) {
      throw new Error(`Userinfo fetch failed (${res.status})`);
    }
    return (await res.json()) as Record<string, unknown>;
  }

  // -----------------------------------------------------------------------
  // URL helpers
  // -----------------------------------------------------------------------

  /** Build the signup URL for the IAM server. */
  getSignupUrl(params?: { enablePassword?: boolean }): string {
    const base = this.config.serverUrl.replace(/\/+$/, "");
    const app = this.config.appName ?? "app";
    const org = this.config.orgName ?? "built-in";
    let url = `${base}/signup/${app}`;
    if (params?.enablePassword) {
      url += "?enablePassword=true";
    }
    return url;
  }

  /** Build the user profile URL on the IAM server. */
  getUserProfileUrl(username: string): string {
    const base = this.config.serverUrl.replace(/\/+$/, "");
    const org = this.config.orgName ?? "built-in";
    return `${base}/users/${org}/${username}`;
  }
}
