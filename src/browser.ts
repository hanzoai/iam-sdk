/**
 * Browser-side OAuth2/OIDC PKCE flow for Hanzo IAM.
 *
 * Standards core: RFC 6749 (OAuth2), RFC 7636 (PKCE), OIDC. The default
 * flow is a single redirect-to-authorize where the IAM server owns the
 * credential interaction. For first-party apps that render their OWN
 * branded login on their own domain, the embedded credential methods
 * (`loginWithPassword` / `loginWithCode`) collect the credential in-app and
 * mint a PKCE-bound authorization code via the IAM login endpoint — the
 * SAME RFC 7636 code+PKCE exchange completes it through `handleCallback`.
 * (Not ROPC: no password ever hits the token endpoint.)
 *
 *   IAM#signinRedirect()    — start PKCE redirect to the authorize endpoint
 *   IAM#handleCallback()    — exchange code at the token endpoint (PKCE)
 *   IAM#loginWithPassword() — first-party embedded login → PKCE-bound code
 *   IAM#loginWithCode()     — embedded passwordless code login → PKCE code
 *   IAM#loginWithWallet()   — inline SIWx (EIP-4361) → PKCE-bound code, no redirect
 *   IAM#sendLoginCode()     — send an email/SMS verification code
 *   IAM#refreshAccessToken()— refresh grant
 *   IAM#signinPopup()       — in-place social login via popup + postMessage
 *   completePopupSignin()   — the popup's callback-page half of signinPopup
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
import { OIDC_PATHS, IAM_PATHS, iamUrl, trimServerUrl } from "./paths.js";

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

// Per-attempt PKCE verifier slot, keyed by the attempt's `state`. Isolates
// concurrent logins (double-click, a racing signinSilent, a re-run React
// effect) so a second attempt can never stomp the first's verifier. Note the
// trailing `:` keeps it disjoint from the legacy single slot KEY_CODE_VERIFIER.
const KEY_VERIFIER_PREFIX = `${KEY_CODE_VERIFIER}:`;
function verifierKey(state: string): string {
  return `${KEY_VERIFIER_PREFIX}${state}`;
}

// ---------------------------------------------------------------------------
// Popup handshake contract
// ---------------------------------------------------------------------------

/**
 * The `window.name` the popup opens with, and the `source` tag every popup
 * message carries. Both are part of the opener↔popup contract: the opener
 * only accepts a message whose `source` is exactly this, from exactly the
 * callback origin, carrying exactly the `state` it generated.
 */
export const POPUP_WINDOW_NAME = "hanzo_iam_login";
const POPUP_MESSAGE_SOURCE = "hanzo-iam" as const;

/**
 * The one-shot message the callback page posts back to the opener. Never
 * carries a token — only the freshly minted authorization `code` + `state`
 * (or an OAuth `error`). The opener completes the PKCE token exchange with
 * the verifier it holds; the code alone is useless without that verifier.
 */
interface PopupMessage {
  source: typeof POPUP_MESSAGE_SOURCE;
  code?: string;
  state?: string;
  error?: string;
}

// ---------------------------------------------------------------------------
// EIP-1193 wallet provider (minimal structural type — no web3 dependency)
// ---------------------------------------------------------------------------

/**
 * The minimal EIP-1193 surface the inline SIWx wallet login needs. Kept
 * structural so the SDK never depends on ethers/viem/web3.js — any injected
 * provider (`window.ethereum`, WalletConnect, Coinbase, …) satisfies it.
 */
export interface Eip1193Provider {
  request(args: { method: string; params?: readonly unknown[] | object }): Promise<unknown>;
}

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
  /**
   * IAM organization (e.g. "hanzo"). Required only for the first-party
   * embedded credential login (`loginWithPassword` / `loginWithCode`).
   */
  organization?: string;
  /** IAM application name. Defaults to `clientId` (they match for Hanzo apps). */
  application?: string;
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
  // PKCE transaction storage
  // -----------------------------------------------------------------------

  /**
   * Persist a login attempt's PKCE verifier. The authoritative slot is keyed
   * by `state` (concurrent attempts stay isolated); the legacy single slots
   * are kept as the latest-attempt pointer + a compatibility fallback for
   * flows that predate per-state storage.
   */
  private stashPkce(state: string, codeVerifier: string): void {
    this.storage.setItem(verifierKey(state), codeVerifier);
    this.storage.setItem(KEY_STATE, state);
    this.storage.setItem(KEY_CODE_VERIFIER, codeVerifier);
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

    this.stashPkce(state, codeVerifier);

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
  // First-party embedded credential login (PKCE-bound, no IAM-hosted UI)
  // -----------------------------------------------------------------------

  /**
   * Generate + persist a PKCE verifier and state for an embedded credential
   * login, returning the challenge to bind into the minted code. Uses the
   * SAME storage keys as `signinRedirect`, so `handleCallback` completes the
   * exact same RFC 7636 exchange regardless of how sign-in started.
   */
  private async beginCredential(): Promise<{ codeChallenge: string; state: string }> {
    const { codeVerifier, codeChallenge } = await generatePKCEChallenge();
    const state = generateState();
    this.stashPkce(state, codeVerifier);
    return { codeChallenge, state };
  }

  /**
   * POST the IAM login endpoint with a PKCE `code_challenge` so the returned
   * authorization code is challenge-bound. Returns the app-callback URL
   * carrying `code` + `state`; the caller navigates there and
   * `handleCallback()` performs the standard PKCE token exchange. Throws on
   * an IAM error. No password ever reaches the token endpoint.
   */
  private async credentialLogin(fields: Record<string, unknown>): Promise<string> {
    const { codeChallenge, state } = await this.beginCredential();
    const base = this.config.proxyBaseUrl ?? this.config.serverUrl;
    const url = new URL(`${trimServerUrl(base)}${IAM_PATHS.login}`);
    url.searchParams.set("clientId", this.config.clientId);
    url.searchParams.set("responseType", "code");
    url.searchParams.set("redirectUri", this.config.redirectUri);
    url.searchParams.set("scope", this.config.scope ?? "openid profile email");
    url.searchParams.set("state", state);
    url.searchParams.set("type", "code");
    url.searchParams.set("code_challenge", codeChallenge);
    url.searchParams.set("code_challenge_method", "S256");

    const res = await fetch(url.toString(), {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      credentials: "include",
      body: JSON.stringify({
        type: "code",
        application: this.config.application ?? this.config.clientId,
        organization: this.config.organization,
        autoSignin: true,
        ...fields,
      }),
    });
    const parsed = (await res.json().catch(() => ({}))) as Record<string, unknown>;
    if (!res.ok || parsed.status === "error") {
      throw new Error(typeof parsed.msg === "string" ? parsed.msg : `sign-in failed (${res.status})`);
    }
    const code = parsed.data;
    if (typeof code !== "string" || code.length === 0) {
      throw new Error("IAM did not return an authorization code");
    }
    const sep = this.config.redirectUri.includes("?") ? "&" : "?";
    return `${this.config.redirectUri}${sep}code=${encodeURIComponent(code)}&state=${encodeURIComponent(state)}`;
  }

  /** Embedded password login → returns the app-callback URL to navigate to. */
  loginWithPassword(username: string, password: string): Promise<string> {
    return this.credentialLogin({ username, password, signinMethod: "Password" });
  }

  /** Embedded passwordless code login → returns the app-callback URL. */
  loginWithCode(destination: string, code: string): Promise<string> {
    const isEmail = destination.includes("@");
    return this.credentialLogin({
      username: destination,
      code,
      signinMethod: "Verification code",
      ...(isEmail ? { email: destination } : { phone: destination }),
    });
  }

  /** Send a passwordless email/SMS verification code for `loginWithCode`. */
  async sendLoginCode(destination: string): Promise<void> {
    const isEmail = destination.includes("@");
    const base = this.config.proxyBaseUrl ?? this.config.serverUrl;
    const url = new URL(`${trimServerUrl(base)}${IAM_PATHS.sendCode}`);
    url.searchParams.set("clientId", this.config.clientId);
    if (this.config.organization) url.searchParams.set("organization", this.config.organization);
    const res = await fetch(url.toString(), {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({
        applicationId: `admin/${this.config.application ?? this.config.clientId}`,
        organization: this.config.organization,
        dest: destination,
        type: isEmail ? "email" : "phone",
        method: "login",
        checkUser: destination,
      }),
    });
    const parsed = (await res.json().catch(() => ({}))) as Record<string, unknown>;
    if (!res.ok || parsed.status === "error") {
      throw new Error(typeof parsed.msg === "string" ? parsed.msg : `could not send code (${res.status})`);
    }
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

    const code = url.searchParams.get("code");
    if (!code) {
      throw new Error("Missing authorization code in callback URL");
    }

    const state = url.searchParams.get("state");

    // Resolve the PKCE verifier for THIS attempt. Prefer the per-attempt slot
    // keyed by the returned `state`: its presence proves WE issued this state,
    // so concurrent logins stay isolated (no stomping) AND state/CSRF is
    // enforced structurally — an attacker cannot fabricate a state that maps
    // to a stored verifier slot. One-shot: consume the slot before the call.
    let codeVerifier: string | null = state ? this.storage.getItem(verifierKey(state)) : null;

    if (codeVerifier) {
      this.storage.removeItem(verifierKey(state as string));
      // Clear the latest-attempt pointer only if it names THIS attempt, so a
      // racing second login's pointer is left intact.
      if (this.storage.getItem(KEY_STATE) === state) {
        this.storage.removeItem(KEY_STATE);
        this.storage.removeItem(KEY_CODE_VERIFIER);
      }
    } else {
      // Legacy single-slot fallback. Enforce state here — a MISSING saved
      // state is itself a rejection (never soft-skip the CSRF check). This is
      // fail-closed: a stomped/concurrent flow that lost its slot also lands
      // here and is rejected with an accurate message (not a false CSRF cry).
      const savedState = this.storage.getItem(KEY_STATE);
      if (!savedState || state !== savedState) {
        throw new Error(
          "OAuth state mismatch — stale, concurrent, or forged login. Restart sign-in.",
        );
      }
      codeVerifier = this.storage.getItem(KEY_CODE_VERIFIER);
      if (!codeVerifier) {
        throw new Error(
          "Missing PKCE code verifier — start sign-in via signinRedirect() or the embedded credential login.",
        );
      }
      this.storage.removeItem(KEY_STATE);
      this.storage.removeItem(KEY_CODE_VERIFIER);
    }

    const body = new URLSearchParams({
      grant_type: "authorization_code",
      client_id: this.config.clientId,
      code,
      redirect_uri: this.config.redirectUri,
      code_verifier: codeVerifier,
    });

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
   * Open IAM login in a popup and complete IN-PLACE via a `postMessage`
   * handshake — the app window never navigates. This is the ONLY in-place
   * path for social (Google/GitHub set `X-Frame-Options`, so they cannot be
   * iframed; a popup is a full top-level context that can host them).
   *
   * Flow: this opener generates PKCE (S256) + `state` and opens the authorize
   * URL in the popup. The popup runs the provider hop and lands on the app's
   * `redirect_uri`, where {@link completePopupSignin} posts `{code,state}`
   * back to this opener and closes itself. This opener then runs the SAME
   * PKCE {@link handleCallback} exchange with the verifier it holds.
   *
   * Security (three gates, all mandatory, one-shot):
   *   1. ORIGIN — the message is accepted ONLY from the exact origin of
   *      `redirect_uri` (the callback origin). Any other `event.origin` is
   *      ignored. IAM never messages the opener directly.
   *   2. SOURCE — the payload must be tagged `source: "hanzo-iam"`.
   *   3. STATE — `state` must equal the value THIS call generated (CSRF).
   * The listener + popup are torn down after the first accepted message; the
   * `code` is never logged. A closed popup or timeout rejects (fail secure).
   */
  async signinPopup(params?: {
    width?: number;
    height?: number;
    additionalParams?: Record<string, string>;
    /** Reject if no message arrives within this window. Default 300s. */
    timeoutMs?: number;
  }): Promise<IAMToken> {
    const { url, state } = await this.buildAuthorizeUrl({
      additionalParams: params?.additionalParams,
    });

    const width = params?.width ?? 600;
    const height = params?.height ?? 700;
    const left = window.screenX + (window.outerWidth - width) / 2;
    const top = window.screenY + (window.outerHeight - height) / 2;

    // The ONLY origin allowed to deliver the code: the origin that hosts our
    // redirect_uri callback (same-origin as this app in the canonical
    // deployment). Resolved once, up front — never derived from the message.
    const expectedOrigin = new URL(this.config.redirectUri, window.location.href).origin;

    return new Promise<IAMToken>((resolve, reject) => {
      const popup = window.open(
        url.toString(),
        POPUP_WINDOW_NAME,
        `width=${width},height=${height},left=${left},top=${top},menubar=no,toolbar=no`,
      );

      if (!popup) {
        reject(new Error("Failed to open login popup — blocked by browser?"));
        return;
      }

      let settled = false;
      let closeGrace: ReturnType<typeof setTimeout> | null = null;
      const cleanup = () => {
        if (settled) return;
        settled = true;
        window.removeEventListener("message", onMessage);
        clearInterval(closedTimer);
        clearTimeout(timeoutTimer);
        if (closeGrace) clearTimeout(closeGrace);
        try {
          if (!popup.closed) popup.close();
        } catch {
          /* ok */
        }
      };

      const onMessage = (event: MessageEvent) => {
        if (settled) return;
        // Gate 1: ORIGIN allowlist. Reject anything not from our callback
        // origin — a message from IAM, an ad iframe, or any other window is
        // silently dropped (return, do NOT settle — the real one may follow).
        if (event.origin !== expectedOrigin) return;
        const data = event.data as Partial<PopupMessage> | null;
        // Gate 2: SOURCE tag. Ignore unrelated same-origin postMessage chatter.
        if (!data || typeof data !== "object" || data.source !== POPUP_MESSAGE_SOURCE) return;
        // Gate 3: STATE / CSRF. Must equal the state THIS call generated.
        if (typeof data.state !== "string" || data.state !== state) {
          cleanup();
          reject(new Error("OAuth state mismatch — possible CSRF (popup)"));
          return;
        }
        if (data.error) {
          cleanup();
          reject(new Error(`OAuth error: ${data.error}`));
          return;
        }
        if (typeof data.code !== "string" || data.code.length === 0) {
          cleanup();
          reject(new Error("Login popup returned no authorization code"));
          return;
        }
        // One-shot: tear everything down BEFORE the exchange so no second
        // message can race in. Then run the identical PKCE exchange the
        // redirect/credential paths use — the verifier is in our storage.
        const code = data.code;
        const returnedState = data.state;
        cleanup();
        const sep = this.config.redirectUri.includes("?") ? "&" : "?";
        const callbackUrl = `${this.config.redirectUri}${sep}code=${encodeURIComponent(code)}&state=${encodeURIComponent(returnedState)}`;
        this.handleCallback(callbackUrl).then(resolve, reject);
      };

      window.addEventListener("message", onMessage);

      // Fail secure: user closed the popup, or it never reported back. The
      // popup posts the code THEN closes itself, so a detected close starts a
      // short grace window — if the in-flight message lands, it settles first
      // (cleanup clears the grace timer); otherwise we reject.
      const closedTimer = setInterval(() => {
        if (settled || !popup.closed || closeGrace) return;
        closeGrace = setTimeout(() => {
          if (!settled) {
            cleanup();
            reject(new Error("Login popup was closed before completing"));
          }
        }, 1000);
      }, 300);
      const timeoutTimer = setTimeout(() => {
        if (!settled) {
          cleanup();
          reject(new Error("Login popup timed out"));
        }
      }, params?.timeoutMs ?? 300_000);
    });
  }

  // -----------------------------------------------------------------------
  // Inline Web3 wallet login (SIWx / EIP-4361, PKCE-bound)
  // -----------------------------------------------------------------------

  /**
   * Sign in with a browser wallet WITHOUT any redirect — the loop-prone
   * `signinRedirect({provider:"wallet"})` is gone. Flow:
   *
   *   1. `eth_requestAccounts` → the connected address.
   *   2. GET {@link IAM_PATHS.web3Nonce} → a server-owned single-use nonce and
   *      the exact EIP-4361 message to sign (server is the message authority).
   *   3. `personal_sign` the server's message verbatim.
   *   4. POST {@link IAM_PATHS.web3Verify} with `{message, signature, address}`
   *      + a PKCE `code_challenge`. The server RECOVERS the signer from the
   *      signature (a client-supplied `address` is a hint, never trusted),
   *      validates the nonce, and returns a PKCE-bound authorization `code`.
   *   5. {@link handleCallback} completes the SAME RFC 7636 exchange in-place.
   *
   * @param opts.provider Explicit EIP-1193 provider; defaults to the injected
   *   `window.ethereum`.
   */
  async loginWithWallet(opts?: { provider?: Eip1193Provider }): Promise<IAMToken> {
    const eth =
      opts?.provider ?? (globalThis as { ethereum?: Eip1193Provider }).ethereum;
    if (!eth || typeof eth.request !== "function") {
      throw new Error("No EIP-1193 wallet provider found (window.ethereum).");
    }

    const accounts = (await eth.request({ method: "eth_requestAccounts" })) as unknown;
    const address = Array.isArray(accounts) ? (accounts[0] as string | undefined) : undefined;
    if (!address) {
      throw new Error("Wallet did not return an address");
    }

    const base = this.config.proxyBaseUrl ?? this.config.serverUrl;
    const trimmed = trimServerUrl(base);

    // 2. Server-owned nonce + message. The message is signed VERBATIM; the
    //    client never invents challenge content (domain/nonce/issued-at).
    const nonceUrl = new URL(`${trimmed}${IAM_PATHS.web3Nonce}`);
    nonceUrl.searchParams.set("address", address);
    nonceUrl.searchParams.set("clientId", this.config.clientId);
    if (this.config.organization) nonceUrl.searchParams.set("organization", this.config.organization);
    const nonceRes = await fetch(nonceUrl.toString(), {
      headers: { Accept: "application/json" },
      credentials: "include",
    });
    const noncePayload = (await nonceRes.json().catch(() => ({}))) as Record<string, unknown>;
    if (!nonceRes.ok || noncePayload.status === "error") {
      throw new Error(
        typeof noncePayload.msg === "string" ? noncePayload.msg : `wallet nonce failed (${nonceRes.status})`,
      );
    }
    const nonceData = (noncePayload.data ?? noncePayload) as Record<string, unknown>;
    const message = nonceData.message as string | undefined;
    const nonce = nonceData.nonce as string | undefined;
    if (!message) {
      throw new Error("IAM did not return a SIWx message to sign");
    }

    // 3. Wallet signs the server's message verbatim.
    const signature = (await eth.request({
      method: "personal_sign",
      params: [message, address],
    })) as string;

    // 4. Verify → PKCE-bound authorization code. Bind PKCE + state up front.
    const { codeChallenge, state } = await this.beginCredential();
    const verifyUrl = new URL(`${trimmed}${IAM_PATHS.web3Verify}`);
    verifyUrl.searchParams.set("clientId", this.config.clientId);
    verifyUrl.searchParams.set("responseType", "code");
    verifyUrl.searchParams.set("redirectUri", this.config.redirectUri);
    verifyUrl.searchParams.set("scope", this.config.scope ?? "openid profile email");
    verifyUrl.searchParams.set("state", state);
    verifyUrl.searchParams.set("code_challenge", codeChallenge);
    verifyUrl.searchParams.set("code_challenge_method", "S256");
    const verifyRes = await fetch(verifyUrl.toString(), {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      credentials: "include",
      body: JSON.stringify({
        application: this.config.application ?? this.config.clientId,
        organization: this.config.organization,
        // Server recovers the signer from (message, signature); `address` is a
        // hint the server MUST re-derive and match — never a trusted identity.
        address,
        message,
        signature,
        nonce,
      }),
    });
    const verifyPayload = (await verifyRes.json().catch(() => ({}))) as Record<string, unknown>;
    if (!verifyRes.ok || verifyPayload.status === "error") {
      throw new Error(
        typeof verifyPayload.msg === "string" ? verifyPayload.msg : `wallet verify failed (${verifyRes.status})`,
      );
    }
    const code = verifyPayload.data;
    if (typeof code !== "string" || code.length === 0) {
      throw new Error("IAM did not return an authorization code");
    }

    // 5. Same RFC 7636 exchange, in-place — no navigation, no redirect.
    const sep = this.config.redirectUri.includes("?") ? "&" : "?";
    const callbackUrl = `${this.config.redirectUri}${sep}code=${encodeURIComponent(code)}&state=${encodeURIComponent(state)}`;
    return this.handleCallback(callbackUrl);
  }

  // -----------------------------------------------------------------------
  // Silent signin (iframe)
  // -----------------------------------------------------------------------

  /**
   * Attempt silent authentication via a hidden iframe (`prompt=none`).
   * Returns null if silent auth fails (user needs to log in interactively).
   */
  async signinSilent(timeoutMs = 5000): Promise<IAMToken | null> {
    const { url, state } = await this.buildAuthorizeUrl({ prompt: "none" });

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
        this.storage.removeItem(verifierKey(state));
        this.storage.removeItem(KEY_STATE);
        this.storage.removeItem(KEY_CODE_VERIFIER);
      };

      iframe.addEventListener("load", () => {
        try {
          const iframeUrl = iframe.contentWindow?.location.href;
          if (iframeUrl && iframeUrl.startsWith(this.config.redirectUri)) {
            // handleCallback consumes the per-attempt verifier slot itself —
            // do NOT pre-clear it here; only sweep leftovers if it fails.
            clearTimeout(timeout);
            iframe.remove();
            this.handleCallback(iframeUrl).then(
              (tokens) => resolve(tokens),
              () => {
                cleanup();
                resolve(null);
              },
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
    // Sweep any per-attempt PKCE verifier slots left by abandoned flows.
    for (let i = this.storage.length - 1; i >= 0; i--) {
      const k = this.storage.key(i);
      if (k && k.startsWith(KEY_VERIFIER_PREFIX)) this.storage.removeItem(k);
    }
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

/**
 * Popup-callback bridge — the OTHER half of {@link IAM#signinPopup}. Mount
 * this on your `redirect_uri` route (one line):
 *
 * ```ts
 * import { completePopupSignin } from "@hanzo/iam/browser";
 * if (!completePopupSignin()) {
 *   // normal top-level navigation → run the usual handleCallback()
 * }
 * ```
 *
 * When the page is our auth popup (it carries the reserved `window.name` set
 * by `signinPopup` AND has a `window.opener`), it hands the freshly minted
 * `code` + `state` back to the opener via a SINGLE `postMessage` and closes
 * itself — returning `true`. For a normal top-level navigation (wrong/no
 * window.name, or no opener) it does nothing and returns `false`, so the app
 * falls through to its standard `handleCallback()`.
 *
 * SECURITY: the message is posted with `targetOrigin` pinned to this page's
 * OWN origin — NEVER `"*"`. The `code` is therefore delivered only to an
 * opener on the same origin as this callback (the canonical deployment), and
 * can never leak cross-origin. The opener independently re-verifies
 * `event.origin` and `state`. A bare `code` is useless without the opener's
 * PKCE verifier, which never leaves the opener. The code is never logged.
 *
 * @returns `true` if this was a popup callback (handled + window closed),
 *   `false` for a normal navigation the app should complete itself.
 */
export function completePopupSignin(): boolean {
  if (typeof window === "undefined") return false;
  // Gate on the popup's window.name — signinPopup opens it with exactly this
  // name, which persists across the cross-origin provider hop. This makes the
  // bridge inert on any ordinary same-origin page that merely happens to carry
  // ?code + a window.opener (e.g. a tab opened with target=_blank), so it can
  // never post a message or close a window it was not meant to.
  if (window.name !== POPUP_WINDOW_NAME) return false;
  const opener = window.opener as Window | null;
  if (!opener || opener === window) return false;

  const url = new URL(window.location.href);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const error = url.searchParams.get("error") ?? url.searchParams.get("error_description");
  // Not an OAuth callback at all — leave it for the app.
  if (!code && !error) return false;

  const message: PopupMessage = {
    source: POPUP_MESSAGE_SOURCE,
    ...(code ? { code } : {}),
    ...(state ? { state } : {}),
    ...(error ? { error } : {}),
  };
  // Pin targetOrigin to our own origin: the opener MUST be same-origin as
  // this callback page. Never "*" — that would broadcast the code to any
  // cross-origin opener.
  opener.postMessage(message, window.location.origin);
  window.close();
  return true;
}

// ---------------------------------------------------------------------------
// Promoted functional surface — the ONE thing apps import.
//
// `configureIam` + `startLogin({provider?})` + `handleCallback` + session
// verbs over the configured singleton. See ./session.ts. Re-exported here so
// `import { startLogin } from "@hanzo/iam/browser"` just works.
// ---------------------------------------------------------------------------

export {
  configureIam,
  startLogin,
  getLoginUrl,
  handleCallback,
  getSession,
  getUser,
  logout,
  getIam,
  getIamConfig,
  type IamSessionConfig,
  type StartLoginOptions,
  type IamSession,
} from "./session.js";
