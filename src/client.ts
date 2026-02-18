/**
 * Core HTTP client for Hanzo IAM (Casdoor) API.
 */

import type {
  IamConfig,
  IamApiResponse,
  IamUser,
  IamOrganization,
  OidcDiscovery,
  TokenResponse,
} from "./types.js";

const DEFAULT_TIMEOUT_MS = 10_000;

export class IamClient {
  private readonly baseUrl: string;
  private readonly clientId: string;
  private readonly clientSecret: string | undefined;
  private readonly orgName: string | undefined;
  private readonly appName: string | undefined;
  private discoveryCache: { data: OidcDiscovery; fetchedAt: number } | null = null;

  constructor(config: IamConfig) {
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
      const basic = Buffer.from(`${this.clientId}:${this.clientSecret}`).toString("base64");
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
    const data = await this.request<OidcDiscovery>(
      "/.well-known/openid-configuration",
    );
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

  /** Exchange authorization code for tokens. */
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

  /** Refresh an access token. */
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
  // User
  // -----------------------------------------------------------------------

  /** Get user info from access token (OIDC userinfo endpoint). */
  async getUserInfo(accessToken: string): Promise<IamUser> {
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
      return (await res.json()) as IamUser;
    } finally {
      clearTimeout(timer);
    }
  }

  /** Get a user by ID ("org/username" format). */
  async getUser(userId: string, token?: string): Promise<IamUser | null> {
    const resp = await this.request<IamApiResponse<IamUser>>("/api/get-user", {
      params: { id: userId },
      token,
    });
    return resp.data ?? null;
  }

  // -----------------------------------------------------------------------
  // Organization
  // -----------------------------------------------------------------------

  /** List organizations (for the configured owner). */
  async getOrganizations(token?: string): Promise<IamOrganization[]> {
    const owner = this.orgName ?? "admin";
    const resp = await this.request<IamApiResponse<IamOrganization[]>>(
      "/api/get-organizations",
      { params: { owner }, token },
    );
    return resp.data ?? [];
  }

  /** Get a specific organization. */
  async getOrganization(
    id: string,
    token?: string,
  ): Promise<IamOrganization | null> {
    const resp = await this.request<IamApiResponse<IamOrganization>>(
      "/api/get-organization",
      { params: { id }, token },
    );
    return resp.data ?? null;
  }

  /** Get organizations a user belongs to. */
  async getUserOrganizations(
    userId: string,
    token?: string,
  ): Promise<IamOrganization[]> {
    // Casdoor returns orgs the user is a member of via the user's properties.
    // We can also query via get-user and read their signupApplication/org.
    const user = await this.getUser(userId, token);
    if (!user) return [];
    // The owner field on a user is their org
    const org = await this.getOrganization(
      `admin/${user.owner}`,
      token,
    );
    return org ? [org] : [];
  }

  // -----------------------------------------------------------------------
  // Raw request (for extending)
  // -----------------------------------------------------------------------

  /** Make an arbitrary authenticated request to the IAM API. */
  async apiRequest<T = unknown>(
    path: string,
    opts?: { method?: string; body?: unknown; token?: string; params?: Record<string, string> },
  ): Promise<T> {
    return this.request<T>(path, opts);
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
