import { jwtVerify, createRemoteJWKSet } from 'jose';

// src/client.ts
var DEFAULT_TIMEOUT_MS = 1e4;
var IamClient = class {
  baseUrl;
  clientId;
  clientSecret;
  orgName;
  appName;
  discoveryCache = null;
  constructor(config) {
    this.baseUrl = config.serverUrl.replace(/\/+$/, "");
    this.clientId = config.clientId;
    this.clientSecret = config.clientSecret;
    this.orgName = config.orgName;
    this.appName = config.appName;
  }
  // -----------------------------------------------------------------------
  // Internal HTTP helpers
  // -----------------------------------------------------------------------
  async request(path, opts) {
    const url = new URL(path, this.baseUrl);
    if (opts?.params) {
      for (const [k, v] of Object.entries(opts.params)) {
        url.searchParams.set(k, v);
      }
    }
    const controller = new AbortController();
    const timer = setTimeout(
      () => controller.abort(),
      opts?.timeoutMs ?? DEFAULT_TIMEOUT_MS
    );
    const headers = {
      Accept: "application/json"
    };
    if (opts?.token) {
      headers.Authorization = `Bearer ${opts.token}`;
    }
    if (opts?.body) {
      headers["Content-Type"] = "application/json";
    }
    if (this.clientSecret && !opts?.token) {
      const credentials = `${this.clientId}:${this.clientSecret}`;
      const basic = typeof Buffer !== "undefined" ? Buffer.from(credentials).toString("base64") : btoa(credentials);
      headers.Authorization = `Basic ${basic}`;
    }
    try {
      const res = await fetch(url.toString(), {
        method: opts?.method ?? "GET",
        headers,
        body: opts?.body ? JSON.stringify(opts.body) : void 0,
        signal: controller.signal
      });
      if (!res.ok) {
        const text = await res.text().catch(() => "");
        throw new IamApiError(res.status, `${res.statusText}: ${text}`.trim());
      }
      return await res.json();
    } finally {
      clearTimeout(timer);
    }
  }
  // -----------------------------------------------------------------------
  // OIDC Discovery
  // -----------------------------------------------------------------------
  async getDiscovery() {
    const CACHE_TTL_MS = 5 * 60 * 1e3;
    if (this.discoveryCache && Date.now() - this.discoveryCache.fetchedAt < CACHE_TTL_MS) {
      return this.discoveryCache.data;
    }
    const data = await this.request(
      "/.well-known/openid-configuration"
    );
    this.discoveryCache = { data, fetchedAt: Date.now() };
    return data;
  }
  /** Get JWKS URI from OIDC discovery (cached). */
  async getJwksUri() {
    const discovery = await this.getDiscovery();
    return discovery.jwks_uri;
  }
  // -----------------------------------------------------------------------
  // OAuth2 / Token
  // -----------------------------------------------------------------------
  /** Build the authorization URL for user login redirect. */
  async getAuthorizationUrl(params) {
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
  async exchangeCode(params) {
    const discovery = await this.getDiscovery();
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      client_id: this.clientId,
      code: params.code,
      redirect_uri: params.redirectUri
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
        signal: controller.signal
      });
      if (!res.ok) {
        const text = await res.text().catch(() => "");
        throw new IamApiError(res.status, `Token exchange failed: ${text}`);
      }
      return await res.json();
    } finally {
      clearTimeout(timer);
    }
  }
  /**
   * Resource Owner Password Credentials grant.
   * Used for service-to-service auth, CLI login, and e2e tests.
   */
  async passwordGrant(params) {
    const discovery = await this.getDiscovery();
    const body = new URLSearchParams({
      grant_type: "password",
      client_id: this.clientId,
      username: params.username,
      password: params.password,
      scope: params.scope ?? "openid profile email phone"
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
        signal: controller.signal
      });
      if (!res.ok) {
        const text = await res.text().catch(() => "");
        throw new IamApiError(res.status, `Password grant failed: ${text}`);
      }
      return await res.json();
    } finally {
      clearTimeout(timer);
    }
  }
  /** Refresh an access token. */
  async refreshToken(refreshToken) {
    const discovery = await this.getDiscovery();
    const body = new URLSearchParams({
      grant_type: "refresh_token",
      client_id: this.clientId,
      refresh_token: refreshToken
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
        signal: controller.signal
      });
      if (!res.ok) {
        const text = await res.text().catch(() => "");
        throw new IamApiError(res.status, `Token refresh failed: ${text}`);
      }
      return await res.json();
    } finally {
      clearTimeout(timer);
    }
  }
  // -----------------------------------------------------------------------
  // User
  // -----------------------------------------------------------------------
  /** Get user info from access token (OIDC userinfo endpoint). */
  async getUserInfo(accessToken) {
    const discovery = await this.getDiscovery();
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), DEFAULT_TIMEOUT_MS);
    try {
      const res = await fetch(discovery.userinfo_endpoint, {
        headers: { Authorization: `Bearer ${accessToken}` },
        signal: controller.signal
      });
      if (!res.ok) {
        throw new IamApiError(res.status, "Failed to fetch userinfo");
      }
      return await res.json();
    } finally {
      clearTimeout(timer);
    }
  }
  /** Get a user by ID ("org/username" format). */
  async getUser(userId, token) {
    const resp = await this.request("/api/get-user", {
      params: { id: userId },
      token
    });
    return resp.data ?? null;
  }
  // -----------------------------------------------------------------------
  // Organization
  // -----------------------------------------------------------------------
  /** List organizations (for the configured owner). */
  async getOrganizations(token) {
    const owner = this.orgName ?? "admin";
    const resp = await this.request(
      "/api/get-organizations",
      { params: { owner }, token }
    );
    return resp.data ?? [];
  }
  /** Get a specific organization. */
  async getOrganization(id, token) {
    const resp = await this.request(
      "/api/get-organization",
      { params: { id }, token }
    );
    return resp.data ?? null;
  }
  /** Get organizations a user belongs to. */
  async getUserOrganizations(userId, token) {
    const user = await this.getUser(userId, token);
    if (!user) return [];
    const org = await this.getOrganization(
      `admin/${user.owner}`,
      token
    );
    return org ? [org] : [];
  }
  // -----------------------------------------------------------------------
  // Project
  // -----------------------------------------------------------------------
  /** List projects (for the configured owner). */
  async getProjects(token) {
    const owner = this.orgName ?? "admin";
    const resp = await this.request(
      "/api/get-projects",
      { params: { owner }, token }
    );
    return resp.data ?? [];
  }
  /** Get a specific project by ID ("owner/name" format). */
  async getProject(id, token) {
    const resp = await this.request(
      "/api/get-project",
      { params: { id }, token }
    );
    return resp.data ?? null;
  }
  /** Get all projects for an organization. */
  async getOrganizationProjects(organization, token) {
    const resp = await this.request(
      "/api/get-organization-projects",
      { params: { organization }, token }
    );
    return resp.data ?? [];
  }
  // -----------------------------------------------------------------------
  // Raw request (for extending)
  // -----------------------------------------------------------------------
  /** Make an arbitrary authenticated request to the IAM API. */
  async apiRequest(path, opts) {
    return this.request(path, opts);
  }
};
var IamApiError = class extends Error {
  status;
  constructor(status, message) {
    super(message);
    this.name = "IamApiError";
    this.status = status;
  }
};
var jwksSets = /* @__PURE__ */ new Map();
function getJwksKeySet(jwksUri) {
  let keySet = jwksSets.get(jwksUri);
  if (!keySet) {
    keySet = createRemoteJWKSet(new URL(jwksUri));
    jwksSets.set(jwksUri, keySet);
  }
  return keySet;
}
function clearJwksCache() {
  jwksSets.clear();
}
var discoveryCache = /* @__PURE__ */ new Map();
var DISCOVERY_TTL_MS = 5 * 60 * 1e3;
async function resolveJwksUri(serverUrl) {
  const baseUrl = serverUrl.replace(/\/+$/, "");
  const cached = discoveryCache.get(baseUrl);
  if (cached && Date.now() - cached.fetchedAt < DISCOVERY_TTL_MS) {
    return { jwksUri: cached.jwksUri, issuer: cached.issuer };
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 8e3);
  try {
    const res = await fetch(`${baseUrl}/.well-known/openid-configuration`, {
      signal: controller.signal,
      headers: { Accept: "application/json" }
    });
    if (!res.ok) {
      throw new Error(`OIDC discovery failed: ${res.status}`);
    }
    const body = await res.json();
    const jwksUri = body.jwks_uri;
    const issuer = body.issuer ?? baseUrl;
    if (!jwksUri) {
      throw new Error("OIDC discovery response missing jwks_uri");
    }
    discoveryCache.set(baseUrl, { jwksUri, issuer, fetchedAt: Date.now() });
    return { jwksUri, issuer };
  } finally {
    clearTimeout(timer);
  }
}
async function validateToken(token, config) {
  if (!token || typeof token !== "string") {
    return { ok: false, reason: "iam_token_missing" };
  }
  let jwksUri;
  let issuer;
  try {
    const discovery = await resolveJwksUri(config.serverUrl);
    jwksUri = discovery.jwksUri;
    issuer = discovery.issuer;
  } catch {
    return { ok: false, reason: "iam_discovery_failed" };
  }
  const keySet = getJwksKeySet(jwksUri);
  let payload;
  try {
    const result = await jwtVerify(token, keySet, {
      issuer,
      audience: config.clientId,
      clockTolerance: 30
      // 30s clock skew
    });
    payload = result.payload;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (message.includes("expired")) {
      return { ok: false, reason: "iam_token_expired" };
    }
    if (message.includes("audience")) {
      try {
        const result = await jwtVerify(token, keySet, {
          issuer,
          clockTolerance: 30
        });
        payload = result.payload;
      } catch {
        return { ok: false, reason: "iam_signature_invalid" };
      }
    } else {
      return { ok: false, reason: "iam_signature_invalid" };
    }
  }
  const claims = payload;
  const sub = claims.sub || (typeof claims.owner === "string" && typeof claims.name === "string" ? `${claims.owner}/${claims.name}` : void 0);
  if (!sub) {
    return { ok: false, reason: "iam_subject_missing" };
  }
  const parts = sub.split("/");
  const owner = parts.length > 1 ? parts[0] : config.orgName ?? "unknown";
  return {
    ok: true,
    userId: sub,
    email: typeof claims.email === "string" ? claims.email : void 0,
    name: typeof claims.name === "string" ? claims.name : typeof claims.preferred_username === "string" ? claims.preferred_username : void 0,
    avatar: typeof claims.picture === "string" ? claims.picture : void 0,
    owner,
    claims
  };
}

// src/pkce.ts
function generateRandomString(length) {
  const array = new Uint8Array(length);
  crypto.getRandomValues(array);
  return Array.from(array, (b) => b.toString(36).padStart(2, "0")).join("").slice(0, length);
}
async function sha256(plain) {
  const encoder = new TextEncoder();
  return crypto.subtle.digest("SHA-256", encoder.encode(plain));
}
function base64UrlEncode(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
async function generatePKCEChallenge() {
  const codeVerifier = generateRandomString(64);
  const hash = await sha256(codeVerifier);
  const codeChallenge = base64UrlEncode(hash);
  return { codeVerifier, codeChallenge };
}
function generateState() {
  return generateRandomString(32);
}

// src/browser.ts
var STORAGE_PREFIX = "hanzo_iam_";
var KEY_STATE = `${STORAGE_PREFIX}state`;
var KEY_CODE_VERIFIER = `${STORAGE_PREFIX}code_verifier`;
var KEY_ACCESS_TOKEN = `${STORAGE_PREFIX}access_token`;
var KEY_REFRESH_TOKEN = `${STORAGE_PREFIX}refresh_token`;
var KEY_ID_TOKEN = `${STORAGE_PREFIX}id_token`;
var KEY_EXPIRES_AT = `${STORAGE_PREFIX}expires_at`;
var IAM = class {
  config;
  storage;
  discoveryCache = null;
  constructor(config) {
    this.config = config;
    this.storage = config.storage ?? sessionStorage;
  }
  // -----------------------------------------------------------------------
  // OIDC Discovery
  // -----------------------------------------------------------------------
  async getDiscovery() {
    if (this.discoveryCache) return this.discoveryCache;
    const baseUrl = this.config.serverUrl.replace(/\/+$/, "");
    try {
      const res = await fetch(`${baseUrl}/.well-known/openid-configuration`, {
        headers: { Accept: "application/json" }
      });
      if (res.ok) {
        this.discoveryCache = await res.json();
        return this.discoveryCache;
      }
    } catch {
    }
    this.discoveryCache = {
      issuer: baseUrl,
      authorization_endpoint: `${baseUrl}/oauth/authorize`,
      token_endpoint: `${baseUrl}/oauth/token`,
      userinfo_endpoint: `${baseUrl}/oauth/userinfo`,
      jwks_uri: `${baseUrl}/.well-known/jwks`,
      response_types_supported: ["code", "token", "id_token"],
      grant_types_supported: ["authorization_code", "implicit", "refresh_token"],
      scopes_supported: ["openid", "email", "profile"]
    };
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
  async signinRedirect(params) {
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
  async handleCallback(callbackUrl) {
    const url = new URL(callbackUrl ?? window.location.href);
    const error = url.searchParams.get("error");
    if (error) {
      const desc = url.searchParams.get("error_description") ?? error;
      throw new Error(`OAuth error: ${desc}`);
    }
    const state = url.searchParams.get("state");
    const savedState = this.storage.getItem(KEY_STATE);
    if (savedState && state !== savedState) {
      throw new Error("OAuth state mismatch \u2014 possible CSRF attack");
    }
    const accessToken = url.searchParams.get("access_token");
    if (accessToken) {
      this.storage.removeItem(KEY_STATE);
      this.storage.removeItem(KEY_CODE_VERIFIER);
      const tokens2 = {
        access_token: accessToken,
        token_type: "Bearer",
        refresh_token: url.searchParams.get("refresh_token") ?? void 0,
        expires_in: 7200
      };
      this.storeTokens(tokens2);
      return toIAMToken(tokens2);
    }
    const code = url.searchParams.get("code");
    if (!code) {
      throw new Error("Missing authorization code in callback URL");
    }
    const codeVerifier = this.storage.getItem(KEY_CODE_VERIFIER);
    if (!codeVerifier) {
      throw new Error("Missing PKCE code verifier \u2014 was signinRedirect() called?");
    }
    this.storage.removeItem(KEY_STATE);
    this.storage.removeItem(KEY_CODE_VERIFIER);
    const discovery = await this.getDiscovery();
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      client_id: this.config.clientId,
      code,
      redirect_uri: this.config.redirectUri,
      code_verifier: codeVerifier
    });
    const tokenUrl = this.config.proxyBaseUrl ? `${this.config.proxyBaseUrl.replace(/\/+$/, "")}/auth/token` : discovery.token_endpoint;
    const res = await fetch(tokenUrl, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString()
    });
    if (!res.ok) {
      const text = await res.text().catch(() => "");
      throw new Error(`Token exchange failed (${res.status}): ${text}`);
    }
    const tokens = await res.json();
    this.storeTokens(tokens);
    return toIAMToken(tokens);
  }
  // -----------------------------------------------------------------------
  // Token refresh
  // -----------------------------------------------------------------------
  /** Refresh the access token using the stored refresh token. */
  async refreshAccessToken() {
    const refreshToken = this.storage.getItem(KEY_REFRESH_TOKEN);
    if (!refreshToken) {
      throw new Error("No refresh token available");
    }
    const discovery = await this.getDiscovery();
    const body = new URLSearchParams({
      grant_type: "refresh_token",
      client_id: this.config.clientId,
      refresh_token: refreshToken
    });
    const tokenUrl = this.config.proxyBaseUrl ? `${this.config.proxyBaseUrl.replace(/\/+$/, "")}/auth/token` : discovery.token_endpoint;
    const res = await fetch(tokenUrl, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString()
    });
    if (!res.ok) {
      const text = await res.text().catch(() => "");
      throw new Error(`Token refresh failed (${res.status}): ${text}`);
    }
    const tokens = await res.json();
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
  async signinPopup(params) {
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
    if (params?.additionalParams) {
      for (const [k, v] of Object.entries(params.additionalParams)) {
        url.searchParams.set(k, v);
      }
    }
    const width = params?.width ?? 600;
    const height = params?.height ?? 700;
    const left = window.screenX + (window.outerWidth - width) / 2;
    const top = window.screenY + (window.outerHeight - height) / 2;
    return new Promise((resolve, reject) => {
      const popup = window.open(
        url.toString(),
        "hanzo_iam_login",
        `width=${width},height=${height},left=${left},top=${top},menubar=no,toolbar=no`
      );
      if (!popup) {
        reject(new Error("Failed to open login popup \u2014 blocked by browser?"));
        return;
      }
      const interval = setInterval(() => {
        try {
          if (popup.closed) {
            clearInterval(interval);
            reject(new Error("Login popup was closed before completing"));
            return;
          }
          const popupUrl = popup.location.href;
          if (popupUrl.startsWith(this.config.redirectUri)) {
            clearInterval(interval);
            popup.close();
            this.handleCallback(popupUrl).then(resolve, reject);
          }
        } catch {
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
  async signinSilent(timeoutMs = 5e3) {
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
    url.searchParams.set("prompt", "none");
    return new Promise((resolve) => {
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
              () => resolve(null)
            );
          }
        } catch {
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
  storeTokens(tokens) {
    this.storage.setItem(KEY_ACCESS_TOKEN, tokens.access_token);
    if (tokens.refresh_token) {
      this.storage.setItem(KEY_REFRESH_TOKEN, tokens.refresh_token);
    }
    if (tokens.id_token) {
      this.storage.setItem(KEY_ID_TOKEN, tokens.id_token);
    }
    if (tokens.expires_in) {
      const expiresAt = Date.now() + tokens.expires_in * 1e3;
      this.storage.setItem(KEY_EXPIRES_AT, String(expiresAt));
    }
  }
  /** Get the stored access token (may be expired). */
  getAccessToken() {
    return this.storage.getItem(KEY_ACCESS_TOKEN);
  }
  /** Get the stored refresh token. */
  getRefreshToken() {
    return this.storage.getItem(KEY_REFRESH_TOKEN);
  }
  /** Get the stored ID token. */
  getIdToken() {
    return this.storage.getItem(KEY_ID_TOKEN);
  }
  /** Check if the stored access token is expired. */
  isTokenExpired() {
    const expiresAt = this.storage.getItem(KEY_EXPIRES_AT);
    if (!expiresAt) return true;
    return Date.now() >= Number(expiresAt);
  }
  /**
   * Get a valid access token — refreshes automatically if expired.
   * Returns null if no token and no refresh token available.
   */
  async getValidAccessToken() {
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
  /** Clear all stored tokens (logout). */
  clearTokens() {
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
  async getUserInfo() {
    const token = await this.getValidAccessToken();
    if (!token) {
      throw new Error("No valid access token \u2014 user must log in");
    }
    const discovery = await this.getDiscovery();
    const userinfoUrl = this.config.proxyBaseUrl ? `${this.config.proxyBaseUrl.replace(/\/+$/, "")}/auth/userinfo` : discovery.userinfo_endpoint;
    const res = await fetch(userinfoUrl, {
      headers: { Authorization: `Bearer ${token}` }
    });
    if (!res.ok) {
      throw new Error(`Userinfo fetch failed (${res.status})`);
    }
    return await res.json();
  }
  // -----------------------------------------------------------------------
  // URL helpers
  // -----------------------------------------------------------------------
  /** Build the signup URL for the IAM server. */
  getSignupUrl(params) {
    const base = this.config.serverUrl.replace(/\/+$/, "");
    const app = this.config.appName ?? "app";
    this.config.orgName ?? "built-in";
    let url = `${base}/signup/${app}`;
    if (params?.enablePassword) {
      url += "?enablePassword=true";
    }
    return url;
  }
  /** Build the user profile URL on the IAM server. */
  getUserProfileUrl(username) {
    const base = this.config.serverUrl.replace(/\/+$/, "");
    const org = this.config.orgName ?? "built-in";
    return `${base}/users/${org}/${username}`;
  }
  // -----------------------------------------------------------------------
  // Casdoor REST surface (signup, OTP, REST login, phone lookup)
  //
  // The OIDC layer covers redirect/PKCE, token exchange, refresh, userinfo.
  // These methods cover the Casdoor-native endpoints that don't have an OIDC
  // analogue: phone/email OTP, custom signup with verification codes, and
  // direct REST login that returns an authorization code in one round-trip
  // (used as the bridge between OTP collection and `exchangeCode`).
  //
  // All paths are gateway-canonical (`/login`, `/signup`,
  // `/send-verification-code`, `/get-phone-user`) — point `serverUrl` at the
  // gateway prefix (e.g. `https://api.dev./v1/iam`) and the
  // gateway proxies to Casdoor's `/api/*` internally.
  // -----------------------------------------------------------------------
  /**
   * Send a verification code to a phone or email destination.
   *
   * @param contact `{ phone, countryCode }` for SMS, `{ email }` for email.
   * @param method  Casdoor method: `login`, `signup`, `forget`, `mfaSetup`, etc.
   */
  async sendVerificationCode(contact, method = "login") {
    if (method === "reset") method = "forget";
    const isPhone = "phone" in contact;
    const dest = isPhone ? contact.phone : contact.email;
    const params = {
      applicationId: `admin/${this.config.appName ?? "app"}`,
      dest,
      type: isPhone ? "phone" : "email",
      method,
      captchaType: "none",
      captchaToken: ""
    };
    if (isPhone) params.countryCode = contact.countryCode;
    const url = `${this.config.serverUrl.replace(/\/+$/, "")}/send-verification-code`;
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(params).toString()
    });
    const data = await res.json().catch(() => ({}));
    if (data.status === "ok") return { ok: true };
    const msg = data.msg || `send-verification-code failed (${res.status})`;
    if (msg.includes("SMS provider") || msg.includes("provider")) return { ok: true };
    return { ok: false, error: msg };
  }
  /**
   * Look up whether a phone number is registered. Returns `{ exists: false }`
   * on 404 or unknown numbers; `{ exists: true }` when Casdoor confirms a user.
   */
  async lookupPhoneUser(phone, countryCode) {
    const url = `${this.config.serverUrl.replace(/\/+$/, "")}/get-phone-user`;
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        application: this.config.appName ?? "app",
        phone,
        countryCode
      })
    });
    if (res.status === 404) return { exists: false };
    if (!res.ok) return { exists: false, error: `lookupPhoneUser failed (${res.status})` };
    return { exists: true };
  }
  /**
   * Casdoor REST signup. Returns the new user's id on success.
   *
   * Phone signup flow: send phoneCode via `sendVerificationCode`, then call
   * this with the OTP in `phoneCode`. Casdoor verifies the code internally.
   * Email signup flow: same with `email` + `emailCode`.
   */
  async signup(params) {
    const username = params.username ?? params.name;
    const password = params.password ?? `Liq${Date.now()}!`;
    const body = {
      application: this.config.appName ?? "app",
      organization: this.config.orgName ?? "built-in",
      name: params.name,
      username,
      password,
      confirm: password,
      agreement: true
    };
    if (params.method === "email") {
      body.email = params.email;
      if (params.emailCode) body.emailCode = params.emailCode;
    } else {
      body.phone = params.phone;
      body.countryCode = params.countryCode;
      if (params.phoneCode) body.phoneCode = params.phoneCode;
      if (params.email) body.email = params.email;
      if (params.emailCode) body.emailCode = params.emailCode;
    }
    const url = `${this.config.serverUrl.replace(/\/+$/, "")}/signup`;
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
    const data = await res.json().catch(() => ({}));
    if (data.status === "ok") return { ok: true, id: data.data2 || data.data };
    return { ok: false, error: data.msg || `signup failed (${res.status})` };
  }
  /**
   * REST login that returns an authorization code (Casdoor `/login`).
   *
   * Use this when you want the caller to drive the PKCE flow without a
   * full redirect — collect credentials in your own UI, get a code back,
   * then call `exchangeCodeForToken` to land tokens.
   */
  async loginWithCredentials(params) {
    const { codeVerifier, codeChallenge } = await generatePKCEChallenge();
    this.storage.setItem(KEY_CODE_VERIFIER, codeVerifier);
    const url = new URL(`${this.config.serverUrl.replace(/\/+$/, "")}/login`);
    url.searchParams.set("code_challenge", codeChallenge);
    url.searchParams.set("code_challenge_method", "S256");
    const res = await fetch(url.toString(), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        application: this.config.appName ?? "app",
        organization: this.config.orgName ?? "built-in",
        username: params.username,
        password: params.password,
        type: params.type ?? "code",
        clientId: this.config.clientId,
        redirectUri: params.redirectUri ?? this.config.redirectUri,
        codeChallenge,
        codeChallengeMethod: "S256",
        autoSignin: true
      })
    });
    const data = await res.json().catch(() => ({}));
    if (data.status === "ok" && data.data) return { ok: true, code: data.data };
    return { ok: false, error: data.msg || `login failed (${res.status})` };
  }
  /**
   * Exchange an authorization code for tokens using the stored PKCE verifier.
   * Pairs with `loginWithCredentials` for a code → tokens round-trip.
   */
  async exchangeCodeForToken(code, redirectUri) {
    const codeVerifier = this.storage.getItem(KEY_CODE_VERIFIER);
    if (!codeVerifier) {
      throw new Error("Missing PKCE verifier \u2014 call loginWithCredentials() first");
    }
    this.storage.removeItem(KEY_CODE_VERIFIER);
    const discovery = await this.getDiscovery();
    const tokenUrl = this.config.proxyBaseUrl ? `${this.config.proxyBaseUrl.replace(/\/+$/, "")}/auth/token` : discovery.token_endpoint;
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      client_id: this.config.clientId,
      code,
      redirect_uri: redirectUri ?? this.config.redirectUri,
      code_verifier: codeVerifier
    });
    const res = await fetch(tokenUrl, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString()
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: `HTTP ${res.status}` }));
      throw new Error(err.error_description || err.error || "Token exchange failed");
    }
    const tokens = await res.json();
    this.storeTokens(tokens);
    return toIAMToken(tokens);
  }
  /**
   * Phone OTP login: tries the numbered username variants Casdoor accepts
   * (`{phone}`, `{countryCode}{phone}`), exchanges the resulting code for
   * tokens. Returns the token response, or throws on failure.
   */
  async loginWithPhoneOTP(params) {
    const usernames = [params.phone, `${params.countryCode}${params.phone}`];
    let lastError = "";
    for (const username of usernames) {
      const result = await this.loginWithCredentials({
        username,
        password: params.code,
        redirectUri: params.redirectUri
      });
      if (result.ok && result.code) {
        return this.exchangeCodeForToken(result.code, params.redirectUri);
      }
      lastError = result.error ?? lastError;
    }
    throw new Error(lastError || "Phone OTP login failed");
  }
  /**
   * Logout via Casdoor REST `/logout` (clears server-side session) and
   * the local storage.
   */
  async logout() {
    const token = this.storage.getItem(KEY_ACCESS_TOKEN);
    try {
      await fetch(`${this.config.serverUrl.replace(/\/+$/, "")}/oauth/logout`, {
        method: "POST",
        headers: token ? { Authorization: `Bearer ${token}` } : {}
      });
    } catch {
    }
    this.clearTokens();
  }
  // -----------------------------------------------------------------------
  // High-level helpers — normalize to ergonomic types so apps don't need
  // their own adapters around the OIDC/Casdoor wire shapes.
  // -----------------------------------------------------------------------
  /**
   * Build a social-login authorize URL. Used to navigate the user to
   * Google/Apple/etc. — same as `signinRedirect` but returns the URL
   * instead of issuing the redirect, so apps can `<a href="...">`.
   */
  async getSocialLoginUrl(provider, scope = "openid profile email") {
    const { codeVerifier, codeChallenge } = await generatePKCEChallenge();
    const state = generateState();
    this.storage.setItem(KEY_STATE, state);
    this.storage.setItem(KEY_CODE_VERIFIER, codeVerifier);
    const discovery = await this.getDiscovery();
    const url = new URL(discovery.authorization_endpoint);
    url.searchParams.set("client_id", this.config.clientId);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("redirect_uri", this.config.redirectUri);
    url.searchParams.set("scope", scope);
    url.searchParams.set("state", state);
    url.searchParams.set("code_challenge", codeChallenge);
    url.searchParams.set("code_challenge_method", "S256");
    url.searchParams.set("provider", provider);
    return url.toString();
  }
  /**
   * Fetch the current user, shaped into the canonical `IAMUser` form
   * (camelCase, no `_` keys). Returns null when no token is present.
   */
  async getUser() {
    const token = await this.getValidAccessToken();
    if (!token) return null;
    const u = await this.getUserInfo();
    return {
      sub: u.sub ?? "",
      email: u.email,
      name: u.name,
      givenName: u.given_name,
      familyName: u.family_name,
      phoneNumber: u.phone_number,
      emailVerified: u.email_verified,
      picture: u.picture,
      owner: u.owner
    };
  }
};
function toIAMToken(t) {
  return {
    accessToken: t.access_token,
    refreshToken: t.refresh_token,
    idToken: t.id_token,
    expiresIn: t.expires_in,
    tokenType: t.token_type,
    scope: t.scope
  };
}

export { IAM, IamApiError, IamClient, clearJwksCache, generatePKCEChallenge, generateState, toIAMToken, validateToken };
//# sourceMappingURL=index.js.map
//# sourceMappingURL=index.js.map