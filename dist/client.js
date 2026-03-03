/**
 * Core HTTP client for Hanzo IAM API.
 */
const DEFAULT_TIMEOUT_MS = 10_000;
export class IamClient {
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
        const timer = setTimeout(() => controller.abort(), opts?.timeoutMs ?? DEFAULT_TIMEOUT_MS);
        const headers = {
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
            const basic = typeof Buffer !== "undefined"
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
            return (await res.json());
        }
        finally {
            clearTimeout(timer);
        }
    }
    // -----------------------------------------------------------------------
    // OIDC Discovery
    // -----------------------------------------------------------------------
    async getDiscovery() {
        const CACHE_TTL_MS = 5 * 60 * 1000;
        if (this.discoveryCache && Date.now() - this.discoveryCache.fetchedAt < CACHE_TTL_MS) {
            return this.discoveryCache.data;
        }
        const data = await this.request("/.well-known/openid-configuration");
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
            return (await res.json());
        }
        finally {
            clearTimeout(timer);
        }
    }
    /** Refresh an access token. */
    async refreshToken(refreshToken) {
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
            return (await res.json());
        }
        finally {
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
                signal: controller.signal,
            });
            if (!res.ok) {
                throw new IamApiError(res.status, "Failed to fetch userinfo");
            }
            return (await res.json());
        }
        finally {
            clearTimeout(timer);
        }
    }
    /** Get a user by ID ("org/username" format). */
    async getUser(userId, token) {
        const resp = await this.request("/api/get-user", {
            params: { id: userId },
            token,
        });
        return resp.data ?? null;
    }
    // -----------------------------------------------------------------------
    // Organization
    // -----------------------------------------------------------------------
    /** List organizations (for the configured owner). */
    async getOrganizations(token) {
        const owner = this.orgName ?? "admin";
        const resp = await this.request("/api/get-organizations", { params: { owner }, token });
        return resp.data ?? [];
    }
    /** Get a specific organization. */
    async getOrganization(id, token) {
        const resp = await this.request("/api/get-organization", { params: { id }, token });
        return resp.data ?? null;
    }
    /** Get organizations a user belongs to. */
    async getUserOrganizations(userId, token) {
        // IAM returns orgs the user is a member of via the user's properties.
        // We can also query via get-user and read their signupApplication/org.
        const user = await this.getUser(userId, token);
        if (!user)
            return [];
        // The owner field on a user is their org
        const org = await this.getOrganization(`admin/${user.owner}`, token);
        return org ? [org] : [];
    }
    // -----------------------------------------------------------------------
    // Project
    // -----------------------------------------------------------------------
    /** List projects (for the configured owner). */
    async getProjects(token) {
        const owner = this.orgName ?? "admin";
        const resp = await this.request("/api/get-projects", { params: { owner }, token });
        return resp.data ?? [];
    }
    /** Get a specific project by ID ("owner/name" format). */
    async getProject(id, token) {
        const resp = await this.request("/api/get-project", { params: { id }, token });
        return resp.data ?? null;
    }
    /** Get all projects for an organization. */
    async getOrganizationProjects(organization, token) {
        const resp = await this.request("/api/get-organization-projects", { params: { organization }, token });
        return resp.data ?? [];
    }
    // -----------------------------------------------------------------------
    // Raw request (for extending)
    // -----------------------------------------------------------------------
    /** Make an arbitrary authenticated request to the IAM API. */
    async apiRequest(path, opts) {
        return this.request(path, opts);
    }
}
// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------
export class IamApiError extends Error {
    status;
    constructor(status, message) {
        super(message);
        this.name = "IamApiError";
        this.status = status;
    }
}
//# sourceMappingURL=client.js.map