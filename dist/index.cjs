'use strict';

var jose = require('jose');

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
  /** Exchange authorization code for tokens (RFC 6749 §4.1). */
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
   * Resource Owner Password Credentials grant (RFC 6749 §4.3).
   * For service-to-service auth, CLI login, and e2e tests only.
   * Browsers should use the redirect flow.
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
  /** Refresh an access token (RFC 6749 §6). */
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
  // User (OIDC userinfo only — no Casdoor /api/get-user)
  // -----------------------------------------------------------------------
  /** Fetch user claims from the OIDC userinfo endpoint (OIDC core §5.3). */
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
  // -----------------------------------------------------------------------
  // Escape hatch — for app-specific endpoints under the same IAM origin
  // -----------------------------------------------------------------------
  /**
   * Make an arbitrary authenticated request to the IAM server.
   * Intentionally untyped — callers that need org/project listings
   * should query their own admin API, not the IAM SDK.
   */
  async apiRequest(path, opts) {
    return this.request(path, opts);
  }
  /** Bound owner/app context if the consumer passed them on construction. */
  get context() {
    return { orgName: this.orgName, appName: this.appName };
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
    keySet = jose.createRemoteJWKSet(new URL(jwksUri));
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
    const result = await jose.jwtVerify(token, keySet, {
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
        const result = await jose.jwtVerify(token, keySet, {
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
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      scopes_supported: ["openid", "email", "profile"]
    };
    return this.discoveryCache;
  }
  // -----------------------------------------------------------------------
  // Token endpoint URL (proxy-aware)
  // -----------------------------------------------------------------------
  async tokenEndpoint() {
    if (this.config.proxyBaseUrl) {
      return `${this.config.proxyBaseUrl.replace(/\/+$/, "")}/oauth/token`;
    }
    const discovery = await this.getDiscovery();
    return discovery.token_endpoint;
  }
  async userinfoEndpoint() {
    if (this.config.proxyBaseUrl) {
      return `${this.config.proxyBaseUrl.replace(/\/+$/, "")}/oauth/userinfo`;
    }
    const discovery = await this.getDiscovery();
    return discovery.userinfo_endpoint;
  }
  // -----------------------------------------------------------------------
  // Authorize URL builder
  // -----------------------------------------------------------------------
  async buildAuthorizeUrl(extra) {
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
  async signinRedirect(params) {
    const { url } = await this.buildAuthorizeUrl(params);
    window.location.href = url.toString();
  }
  /**
   * Build the authorize URL without redirecting — useful for `<a href>`
   * (e.g. social login buttons with `provider` in additionalParams).
   */
  async getSigninUrl(params) {
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
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      client_id: this.config.clientId,
      code,
      redirect_uri: this.config.redirectUri,
      code_verifier: codeVerifier
    });
    const tokenUrl = await this.tokenEndpoint();
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
    const body = new URLSearchParams({
      grant_type: "refresh_token",
      client_id: this.config.clientId,
      refresh_token: refreshToken
    });
    const tokenUrl = await this.tokenEndpoint();
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
    const { url } = await this.buildAuthorizeUrl({
      additionalParams: params?.additionalParams
    });
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
   * Attempt silent authentication via a hidden iframe (`prompt=none`).
   * Returns null if silent auth fails (user needs to log in interactively).
   */
  async signinSilent(timeoutMs = 5e3) {
    const { url } = await this.buildAuthorizeUrl({ prompt: "none" });
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
  /** Clear all stored tokens (local logout). */
  clearTokens() {
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
   * RP-initiated logout (OIDC). Best-effort POST to /oauth/logout to
   * terminate the server-side session, then clears local tokens.
   */
  async logout() {
    const token = this.storage.getItem(KEY_ACCESS_TOKEN);
    const baseUrl = this.config.serverUrl.replace(/\/+$/, "");
    try {
      await fetch(`${baseUrl}/oauth/logout`, {
        method: "POST",
        headers: token ? { Authorization: `Bearer ${token}` } : {}
      });
    } catch {
    }
    this.clearTokens();
  }
  // -----------------------------------------------------------------------
  // User info
  // -----------------------------------------------------------------------
  /** Fetch user info from /oauth/userinfo using the stored access token. */
  async getUserInfo() {
    const token = await this.getValidAccessToken();
    if (!token) {
      throw new Error("No valid access token \u2014 user must log in");
    }
    const url = await this.userinfoEndpoint();
    const res = await fetch(url, {
      headers: { Authorization: `Bearer ${token}` }
    });
    if (!res.ok) {
      throw new Error(`Userinfo fetch failed (${res.status})`);
    }
    return await res.json();
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

exports.IAM = IAM;
exports.IamApiError = IamApiError;
exports.IamClient = IamClient;
exports.clearJwksCache = clearJwksCache;
exports.generatePKCEChallenge = generatePKCEChallenge;
exports.generateState = generateState;
exports.toIAMToken = toIAMToken;
exports.validateToken = validateToken;
//# sourceMappingURL=index.cjs.map
//# sourceMappingURL=index.cjs.map