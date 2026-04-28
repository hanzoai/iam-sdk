/**
 * Browser-side OAuth2 flows for Hanzo IAM.
 *
 * Provides PKCE-based login redirect, code exchange, token refresh,
 * popup signin, and silent signin for single-page applications.
 *
 * Adapted and modernized for Hanzo IAM.
 */
import { generatePKCEChallenge, generateState } from "./pkce.js";
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
export class IAM {
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
        if (this.discoveryCache)
            return this.discoveryCache;
        const baseUrl = this.config.serverUrl.replace(/\/+$/, "");
        // Try fetching the OIDC discovery document. If it fails (e.g. due to
        // CORS when the IAM server doesn't send Access-Control-Allow-Origin),
        // construct a fallback from well-known Hanzo IAM endpoint paths.
        try {
            const res = await fetch(`${baseUrl}/.well-known/openid-configuration`, {
                headers: { Accept: "application/json" },
            });
            if (res.ok) {
                this.discoveryCache = (await res.json());
                return this.discoveryCache;
            }
        }
        catch {
            // CORS or network error — fall through to constructed discovery
        }
        this.discoveryCache = {
            issuer: baseUrl,
            authorization_endpoint: `${baseUrl}/oauth/authorize`,
            token_endpoint: `${baseUrl}/oauth/token`,
            userinfo_endpoint: `${baseUrl}/oauth/userinfo`,
            jwks_uri: `${baseUrl}/.well-known/jwks`,
            response_types_supported: ["code", "token", "id_token"],
            grant_types_supported: ["authorization_code", "implicit", "refresh_token"],
            scopes_supported: ["openid", "email", "profile"],
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
            throw new Error("OAuth state mismatch — possible CSRF attack");
        }
        // Implicit flow: access_token returned directly in URL
        const accessToken = url.searchParams.get("access_token");
        if (accessToken) {
            this.storage.removeItem(KEY_STATE);
            this.storage.removeItem(KEY_CODE_VERIFIER);
            const tokens = {
                access_token: accessToken,
                token_type: "Bearer",
                refresh_token: url.searchParams.get("refresh_token") ?? undefined,
                expires_in: 7200,
            };
            this.storeTokens(tokens);
            return tokens;
        }
        // Authorization code flow: exchange code for tokens via PKCE
        const code = url.searchParams.get("code");
        if (!code) {
            throw new Error("Missing authorization code in callback URL");
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
        // Use proxy URL when configured to avoid CORS on the token endpoint.
        const tokenUrl = this.config.proxyBaseUrl
            ? `${this.config.proxyBaseUrl.replace(/\/+$/, "")}/auth/token`
            : discovery.token_endpoint;
        const res = await fetch(tokenUrl, {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: body.toString(),
        });
        if (!res.ok) {
            const text = await res.text().catch(() => "");
            throw new Error(`Token exchange failed (${res.status}): ${text}`);
        }
        const tokens = (await res.json());
        this.storeTokens(tokens);
        return tokens;
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
            refresh_token: refreshToken,
        });
        const tokenUrl = this.config.proxyBaseUrl
            ? `${this.config.proxyBaseUrl.replace(/\/+$/, "")}/auth/token`
            : discovery.token_endpoint;
        const res = await fetch(tokenUrl, {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: body.toString(),
        });
        if (!res.ok) {
            const text = await res.text().catch(() => "");
            throw new Error(`Token refresh failed (${res.status}): ${text}`);
        }
        const tokens = (await res.json());
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
            const popup = window.open(url.toString(), "hanzo_iam_login", `width=${width},height=${height},left=${left},top=${top},menubar=no,toolbar=no`);
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
                }
                catch {
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
    async signinSilent(timeoutMs = 5000) {
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
        url.searchParams.set("prompt", "none"); // No interactive login
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
                        this.handleCallback(iframeUrl).then((tokens) => resolve(tokens), () => resolve(null));
                    }
                }
                catch {
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
    storeTokens(tokens) {
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
        if (!expiresAt)
            return true;
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
                return tokens.access_token;
            }
            catch {
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
            throw new Error("No valid access token — user must log in");
        }
        const discovery = await this.getDiscovery();
        const userinfoUrl = this.config.proxyBaseUrl
            ? `${this.config.proxyBaseUrl.replace(/\/+$/, "")}/auth/userinfo`
            : discovery.userinfo_endpoint;
        const res = await fetch(userinfoUrl, {
            headers: { Authorization: `Bearer ${token}` },
        });
        if (!res.ok) {
            throw new Error(`Userinfo fetch failed (${res.status})`);
        }
        return (await res.json());
    }
    // -----------------------------------------------------------------------
    // URL helpers
    // -----------------------------------------------------------------------
    /** Build the signup URL for the IAM server. */
    getSignupUrl(params) {
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
        // 'reset' is an idiomatic alias for Casdoor's 'forget'.
        if (method === "reset")
            method = "forget";
        const isPhone = "phone" in contact;
        const dest = isPhone ? contact.phone : contact.email;
        const params = {
            applicationId: `admin/${this.config.appName ?? "app"}`,
            dest,
            type: isPhone ? "phone" : "email",
            method,
            captchaType: "none",
            captchaToken: "",
        };
        if (isPhone)
            params.countryCode = contact.countryCode;
        const url = `${this.config.serverUrl.replace(/\/+$/, "")}/send-verification-code`;
        const res = await fetch(url, {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams(params).toString(),
        });
        const data = await res.json().catch(() => ({}));
        if (data.status === "ok")
            return { ok: true };
        const msg = data.msg || `send-verification-code failed (${res.status})`;
        // Provider misconfig is treated as soft success in dev — Casdoor still
        // generates the code and stores it for verification.
        if (msg.includes("SMS provider") || msg.includes("provider"))
            return { ok: true };
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
                countryCode,
            }),
        });
        if (res.status === 404)
            return { exists: false };
        if (!res.ok)
            return { exists: false, error: `lookupPhoneUser failed (${res.status})` };
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
            agreement: true,
        };
        if (params.method === "email") {
            body.email = params.email;
            if (params.emailCode)
                body.emailCode = params.emailCode;
        }
        else {
            body.phone = params.phone;
            body.countryCode = params.countryCode;
            if (params.phoneCode)
                body.phoneCode = params.phoneCode;
            if (params.email)
                body.email = params.email;
            if (params.emailCode)
                body.emailCode = params.emailCode;
        }
        const url = `${this.config.serverUrl.replace(/\/+$/, "")}/signup`;
        const res = await fetch(url, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body),
        });
        const data = await res.json().catch(() => ({}));
        if (data.status === "ok")
            return { ok: true, id: data.data2 || data.data };
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
                autoSignin: true,
            }),
        });
        const data = await res.json().catch(() => ({}));
        if (data.status === "ok" && data.data)
            return { ok: true, code: data.data };
        return { ok: false, error: data.msg || `login failed (${res.status})` };
    }
    /**
     * Exchange an authorization code for tokens using the stored PKCE verifier.
     * Pairs with `loginWithCredentials` for a code → tokens round-trip.
     */
    async exchangeCodeForToken(code, redirectUri) {
        const codeVerifier = this.storage.getItem(KEY_CODE_VERIFIER);
        if (!codeVerifier) {
            throw new Error("Missing PKCE verifier — call loginWithCredentials() first");
        }
        this.storage.removeItem(KEY_CODE_VERIFIER);
        const discovery = await this.getDiscovery();
        const tokenUrl = this.config.proxyBaseUrl
            ? `${this.config.proxyBaseUrl.replace(/\/+$/, "")}/auth/token`
            : discovery.token_endpoint;
        const body = new URLSearchParams({
            grant_type: "authorization_code",
            client_id: this.config.clientId,
            code,
            redirect_uri: redirectUri ?? this.config.redirectUri,
            code_verifier: codeVerifier,
        });
        const res = await fetch(tokenUrl, {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: body.toString(),
        });
        if (!res.ok) {
            const err = await res.json().catch(() => ({ error: `HTTP ${res.status}` }));
            throw new Error(err.error_description || err.error || "Token exchange failed");
        }
        const tokens = (await res.json());
        this.storeTokens(tokens);
        return tokens;
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
                redirectUri: params.redirectUri,
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
                headers: token ? { Authorization: `Bearer ${token}` } : {},
            });
        }
        catch {
            // best-effort — local cleanup is what matters
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
        if (!token)
            return null;
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
            owner: u.owner,
        };
    }
}
/** Convert the raw OAuth2 token response into the canonical `IAMToken`. */
export function toIAMToken(t) {
    return {
        accessToken: t.access_token,
        refreshToken: t.refresh_token,
        idToken: t.id_token,
        expiresIn: t.expires_in,
        tokenType: t.token_type,
        scope: t.scope,
    };
}
//# sourceMappingURL=browser.js.map