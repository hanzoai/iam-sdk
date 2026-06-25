/**
 * The promoted, app-facing functional auth surface for Hanzo IAM.
 *
 * This is the ONE thing an app imports. It is a thin, configured singleton
 * over the {@link IAM} browser engine — mechanism stays in `browser.ts`,
 * this module just gives it a module-level config so apps write
 *
 *   import { configureIam, startLogin, handleCallback, getSession } from '@hanzo/iam/browser'
 *
 * instead of hand-rolling a local `iam-auth.ts` copy. It is the SDK promotion
 * of `commerce/app/site/app/lib/iam-auth.ts`.
 *
 * Three orthogonal verbs, parameterized — never a branch per provider:
 *
 *   startLogin({ provider?, redirect? })   ONE Authorization-Code + PKCE flow.
 *                                          `provider` is the ONLY knob: omit it
 *                                          for the IAM login page, or name a
 *                                          social/web3 provider to delegate the
 *                                          social hop to IAM's shared org-level
 *                                          OAuth client. The app NEVER registers
 *                                          a per-app Google/GitHub client.
 *   handleCallback()                       ONE token exchange (PKCE verifier +
 *                                          state/CSRF check). No path literals —
 *                                          endpoints come from OIDC discovery
 *                                          (falling back to OIDC_PATHS).
 *   getSession() / getUser() / logout()    ONE session model.
 *
 * `provider` rides the authorize request as `&provider=<name>` on
 * `/v1/iam/oauth/authorize`. IAM performs the social hop with its shared
 * client (the provider hop's redirect_uri is IAM's own callback) and returns
 * the code to the APP's own `redirect_uri`. PKCE-S256 always. No `/api/`.
 */

import { IAM, type IAMConfig, type IAMUser, type IAMToken } from "./browser.js";

// ---------------------------------------------------------------------------
// Module-level configured singleton
// ---------------------------------------------------------------------------

let instance: IAM | null = null;
let activeConfig: IamSessionConfig | null = null;

/**
 * App-facing config. `issuer` is the brand IAM origin (e.g. "https://hanzo.id");
 * `clientId` is `<org>-<app>`. `redirect` defaults to the current origin +
 * `/auth/callback` — the framework's exact callback. Everything else (token,
 * userinfo, jwks, logout endpoints) is resolved from OIDC discovery.
 */
export interface IamSessionConfig {
  /** Brand IAM origin, e.g. "https://hanzo.id". Maps to IAM `serverUrl`. */
  issuer: string;
  /** OAuth client id (`<org>-<app>`). */
  clientId: string;
  /** App OAuth callback URI. Default: `${origin}/auth/callback`. */
  redirect?: string;
  /** OAuth scopes. Default: "openid profile email". */
  scope?: string;
  /** Token storage. Default: sessionStorage. */
  storage?: Storage;
  /** Same-origin proxy base for token/userinfo (keeps cross-origin off the browser). */
  proxyBaseUrl?: string;
}

/** Default app callback path appended to the current origin. */
const DEFAULT_CALLBACK_PATH = "/auth/callback";

function defaultRedirect(): string {
  const origin = typeof window !== "undefined" ? window.location.origin : "";
  return `${origin}${DEFAULT_CALLBACK_PATH}`;
}

function toIAMConfig(c: IamSessionConfig): IAMConfig {
  return {
    serverUrl: c.issuer,
    clientId: c.clientId,
    redirectUri: c.redirect ?? defaultRedirect(),
    scope: c.scope,
    storage: c.storage,
    proxyBaseUrl: c.proxyBaseUrl,
  };
}

/**
 * Configure the module-level IAM singleton. Call once at app startup. Returns
 * the underlying {@link IAM} engine for advanced use. Idempotent per config.
 */
export function configureIam(config: IamSessionConfig): IAM {
  activeConfig = config;
  instance = new IAM(toIAMConfig(config));
  return instance;
}

function engine(): IAM {
  if (!instance) {
    throw new Error(
      "@hanzo/iam: call configureIam({ issuer, clientId }) before startLogin/handleCallback.",
    );
  }
  return instance;
}

// ---------------------------------------------------------------------------
// startLogin — ONE flow, provider is the only knob
// ---------------------------------------------------------------------------

export interface StartLoginOptions {
  /**
   * Social/web3 provider hint (e.g. "google", "github", "web3"). Omit for the
   * IAM login page. The ONLY knob that selects the method — delegated to IAM's
   * shared org-level OAuth client, never a per-app registration.
   */
  provider?: string;
  /** Where to land after a successful login. Stashed across the round-trip. */
  redirect?: string;
}

const KEY_POST_LOGIN_REDIRECT = "hanzo_iam_post_login_redirect";

/**
 * Start the OIDC Authorization-Code + PKCE-S256 login by redirecting to
 * `/v1/iam/oauth/authorize`. `provider` (if given) rides as `&provider=<name>`.
 * Stashes the post-login `redirect` so {@link handleCallback} can return it.
 */
export async function startLogin(opts: StartLoginOptions = {}): Promise<void> {
  if (opts.redirect && typeof sessionStorage !== "undefined") {
    sessionStorage.setItem(KEY_POST_LOGIN_REDIRECT, opts.redirect);
  }
  const additionalParams = opts.provider ? { provider: opts.provider } : undefined;
  await engine().signinRedirect({ additionalParams });
}

/**
 * Build the authorize URL WITHOUT redirecting (for `<a href>` or tests).
 * Same PKCE + provider semantics as {@link startLogin}.
 */
export async function getLoginUrl(opts: StartLoginOptions = {}): Promise<string> {
  const additionalParams = opts.provider ? { provider: opts.provider } : undefined;
  return engine().getSigninUrl({ additionalParams });
}

// ---------------------------------------------------------------------------
// handleCallback — ONE token exchange
// ---------------------------------------------------------------------------

/**
 * Complete the login on the app's callback route: verify state + PKCE verifier,
 * exchange the code at the discovered token endpoint, store tokens. Returns the
 * stashed post-login redirect (or "/" if none).
 */
export async function handleCallback(callbackUrl?: string): Promise<{ token: IAMToken; redirect: string }> {
  const token = await engine().handleCallback(callbackUrl);
  let redirect = "/";
  if (typeof sessionStorage !== "undefined") {
    redirect = sessionStorage.getItem(KEY_POST_LOGIN_REDIRECT) ?? "/";
    sessionStorage.removeItem(KEY_POST_LOGIN_REDIRECT);
  }
  return { token, redirect };
}

// ---------------------------------------------------------------------------
// Session model — getSession / getUser / logout
// ---------------------------------------------------------------------------

export interface IamSession {
  /** Whether a valid (unexpired) access token is present. */
  authenticated: boolean;
  /** Current access token (null when unauthenticated). */
  accessToken: string | null;
}

/** Synchronous session snapshot from local token storage. */
export function getSession(): IamSession {
  const sdk = engine();
  const accessToken = sdk.getAccessToken();
  const authenticated = !!accessToken && !sdk.isTokenExpired();
  return { authenticated, accessToken: authenticated ? accessToken : null };
}

/** Fetch the current user from the userinfo endpoint (null when unauthenticated). */
export function getUser(): Promise<IAMUser | null> {
  return engine().getUser();
}

/** RP-initiated logout + local token clear. */
export function logout(): Promise<void> {
  if (typeof sessionStorage !== "undefined") {
    sessionStorage.removeItem(KEY_POST_LOGIN_REDIRECT);
  }
  return engine().logout();
}

/** Escape hatch: the underlying configured {@link IAM} engine. */
export function getIam(): IAM {
  return engine();
}

/** The currently active session config (null before `configureIam`). */
export function getIamConfig(): IamSessionConfig | null {
  return activeConfig;
}
