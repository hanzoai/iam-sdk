/**
 * Core HTTP client for Hanzo IAM.
 *
 * Speaks pure OIDC / OAuth2 only. No legacy `/api/get-*` admin REST.
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

import type {
  Config,
  User,
  OidcDiscovery,
  TokenResponse,
} from "./types.js";
import { OIDC_PATHS } from "./paths.js";

const DEFAULT_TIMEOUT_MS = 10_000;

export class IamClient {
  private readonly baseUrl: string;
  private readonly clientId: string;
  private readonly clientSecret: string | undefined;
  private readonly orgName: string | undefined;
  private readonly appName: string | undefined;
  private discoveryCache: { data: OidcDiscovery; fetchedAt: number } | null = null;

  constructor(config: Config) {
    this.baseUrl = config.serverUrl.replace(/\/+$/, "");
    this.clientId = config.clientId;
    this.clientSecret = config.clientSecret;
    this.orgName = config.orgName;
    this.appName = config.appName;
  }

  // -----------------------------------------------------------------------
  // Internal HTTP helpers
  // -----------------------------------------------------------------------

  private async request<T>(
    path: string,
    opts?: {
      method?: string;
      body?: unknown;
      token?: string;
      params?: Record<string, string>;
      timeoutMs?: number;
    },
  ): Promise<T> {
    const url = new URL(path, this.baseUrl);
    if (opts?.params) {
      for (const [k, v] of Object.entries(opts.params)) {
        url.searchParams.set(k, v);
      }
    }

    const controller = new AbortController();
    const timer = setTimeout(
      () => controller.abort(),
      opts?.timeoutMs ?? DEFAULT_TIMEOUT_MS,
    );

    const headers: Record<string, string> = {
      Accept: "application/json",
    };
    if (opts?.token) {
      headers.Authorization = `Bearer ${opts.token}`;
    }
    if (opts?.body) {
      headers["Content-Type"] = "application/json";
    }

    // Server-side basic auth for confidential client operations
    if (this.clientSecret && !opts?.token) {
      const credentials = `${this.clientId}:${this.clientSecret}`;
      const basic =
        typeof Buffer !== "undefined"
          ? Buffer.from(credentials).toString("base64")
          : btoa(credentials);
      headers.Authorization = `Basic ${basic}`;
    }

    try {
      const res = await fetch(url.toString(), {
        method: opts?.method ?? "GET",
        headers,
        body: opts?.body ? JSON.stringify(opts.body) : undefined,
        signal: controller.signal,
      });

      if (!res.ok) {
        const text = await res.text().catch(() => "");
        throw new IamApiError(res.status, `${res.statusText}: ${text}`.trim());
      }

      return (await res.json()) as T;
    } finally {
      clearTimeout(timer);
    }
  }

  // -----------------------------------------------------------------------
  // OIDC Discovery
  // -----------------------------------------------------------------------

  async getDiscovery(): Promise<OidcDiscovery> {
    const CACHE_TTL_MS = 5 * 60 * 1000;
    if (this.discoveryCache && Date.now() - this.discoveryCache.fetchedAt < CACHE_TTL_MS) {
      return this.discoveryCache.data;
    }
    const data = await this.request<OidcDiscovery>(OIDC_PATHS.discovery);
    this.discoveryCache = { data, fetchedAt: Date.now() };
    return data;
  }

  /** Get JWKS URI from OIDC discovery (cached). */
  async getJwksUri(): Promise<string> {
    const discovery = await this.getDiscovery();
    return discovery.jwks_uri;
  }

  // -----------------------------------------------------------------------
  // OAuth2 / Token
  // -----------------------------------------------------------------------

  /** Build the authorization URL for user login redirect. */
  async getAuthorizationUrl(params: {
    redirectUri: string;
    state: string;
    scope?: string;
    codeChallenge?: string;
    codeChallengeMethod?: string;
  }): Promise<string> {
    const discovery = await this.getDiscovery();
    const url = new URL(discovery.authorization_endpoint);
    url.searchParams.set("client_id", this.clientId);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("redirect_uri", params.redirectUri);
    url.searchParams.set("state", params.state);
    url.searchParams.set("scope", params.scope ?? "openid profile email");
    if (params.codeChallenge) {
      url.searchParams.set("code_challenge", params.codeChallenge);
      url.searchParams.set("code_challenge_method", params.codeChallengeMethod ?? "S256");
    }
    return url.toString();
  }

  /** Exchange authorization code for tokens (RFC 6749 §4.1). */
  async exchangeCode(params: {
    code: string;
    redirectUri: string;
    codeVerifier?: string;
  }): Promise<TokenResponse> {
    const discovery = await this.getDiscovery();
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      client_id: this.clientId,
      code: params.code,
      redirect_uri: params.redirectUri,
    });
    if (this.clientSecret) {
      body.set("client_secret", this.clientSecret);
    }
    if (params.codeVerifier) {
      body.set("code_verifier", params.codeVerifier);
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), DEFAULT_TIMEOUT_MS);
    try {
      const res = await fetch(discovery.token_endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: body.toString(),
        signal: controller.signal,
      });
      if (!res.ok) {
        const text = await res.text().catch(() => "");
        throw new IamApiError(res.status, `Token exchange failed: ${text}`);
      }
      return (await res.json()) as TokenResponse;
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * Resource Owner Password Credentials grant (RFC 6749 §4.3).
   * For service-to-service auth, CLI login, and e2e tests only.
   * Browsers should use the redirect flow.
   */
  async passwordGrant(params: {
    username: string;
    password: string;
    scope?: string;
  }): Promise<TokenResponse> {
    const discovery = await this.getDiscovery();
    const body = new URLSearchParams({
      grant_type: "password",
      client_id: this.clientId,
      username: params.username,
      password: params.password,
      scope: params.scope ?? "openid profile email phone",
    });
    if (this.clientSecret) {
      body.set("client_secret", this.clientSecret);
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), DEFAULT_TIMEOUT_MS);
    try {
      const res = await fetch(discovery.token_endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: body.toString(),
        signal: controller.signal,
      });
      if (!res.ok) {
        const text = await res.text().catch(() => "");
        throw new IamApiError(res.status, `Password grant failed: ${text}`);
      }
      return (await res.json()) as TokenResponse;
    } finally {
      clearTimeout(timer);
    }
  }

  /** Refresh an access token (RFC 6749 §6). */
  async refreshToken(refreshToken: string): Promise<TokenResponse> {
    const discovery = await this.getDiscovery();
    const body = new URLSearchParams({
      grant_type: "refresh_token",
      client_id: this.clientId,
      refresh_token: refreshToken,
    });
    if (this.clientSecret) {
      body.set("client_secret", this.clientSecret);
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), DEFAULT_TIMEOUT_MS);
    try {
      const res = await fetch(discovery.token_endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: body.toString(),
        signal: controller.signal,
      });
      if (!res.ok) {
        const text = await res.text().catch(() => "");
        throw new IamApiError(res.status, `Token refresh failed: ${text}`);
      }
      return (await res.json()) as TokenResponse;
    } finally {
      clearTimeout(timer);
    }
  }

  // -----------------------------------------------------------------------
  // User (OIDC userinfo only — never a legacy get-user verb)
  // -----------------------------------------------------------------------

  /** Fetch user claims from the OIDC userinfo endpoint (OIDC core §5.3). */
  async getUserInfo(accessToken: string): Promise<User> {
    const discovery = await this.getDiscovery();
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), DEFAULT_TIMEOUT_MS);
    try {
      const res = await fetch(discovery.userinfo_endpoint, {
        headers: { Authorization: `Bearer ${accessToken}` },
        signal: controller.signal,
      });
      if (!res.ok) {
        throw new IamApiError(res.status, "Failed to fetch userinfo");
      }
      return (await res.json()) as User;
    } finally {
      clearTimeout(timer);
    }
  }

  // -----------------------------------------------------------------------
  // Escape hatch — for app-specific endpoints under the same IAM origin
  // -----------------------------------------------------------------------

  /**
   * Make an arbitrary authenticated request to the IAM server.
   * Intentionally untyped — callers that need org/project listings
   * should query their own admin API, not the IAM SDK.
   */
  async apiRequest<T = unknown>(
    path: string,
    opts?: { method?: string; body?: unknown; token?: string; params?: Record<string, string> },
  ): Promise<T> {
    return this.request<T>(path, opts);
  }

  /** Bound owner/app context if the consumer passed them on construction. */
  get context(): { orgName?: string; appName?: string } {
    return { orgName: this.orgName, appName: this.appName };
  }
}

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

export class IamApiError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = "IamApiError";
    this.status = status;
  }
}
