/**
 * The single source of truth for Hanzo IAM OIDC endpoint paths.
 *
 * Hanzo IAM is a standards-first OIDC provider served per-brand from a
 * configurable origin (`serverUrl`): hanzo → https://iam.hanzo.ai,
 * lux → https://lux.id, zoo → https://zoo.id, bootnode → https://id.bootno.de.
 *
 * These are the ONLY paths. There is no legacy `/oauth/*` and no
 * `/api/login/*`. Every module in this SDK references `OIDC_PATHS` —
 * no path string is written anywhere else.
 *
 * CRITICAL GOTCHA: IAM serves a 200 `text/html` SPA catch-all for ANY
 * unregistered path. A client that hits a wrong path therefore gets a
 * 200 HTML body, not a 404 — silent breakage. So clients MUST hit these
 * exact paths, and a discovery round-trip must never be allowed to
 * resolve to a different path. The hard-coded fallbacks here are these
 * same values, so a failed discovery degrades to correct paths.
 */

/** OIDC endpoint paths, relative to the brand `serverUrl`. */
export const OIDC_PATHS = {
  /** OIDC discovery document. */
  discovery: "/.well-known/openid-configuration",
  /** Authorization endpoint (RFC 6749 §3.1). */
  authorize: "/v1/iam/oauth/authorize",
  /** Token endpoint (RFC 6749 §3.2). */
  token: "/v1/iam/oauth/token",
  /** UserInfo endpoint (OIDC Core §5.3). */
  userinfo: "/v1/iam/oauth/userinfo",
  /** JWKS endpoint (RFC 7517). */
  jwks: "/v1/iam/.well-known/jwks",
  /** RP-initiated logout endpoint (OIDC RP-Initiated Logout). */
  logout: "/v1/iam/oauth/logout",
} as const;

export type OidcPathKey = keyof typeof OIDC_PATHS;

/**
 * Hanzo-IAM application paths that are NOT part of the OIDC spec — the
 * auth-method discovery endpoint and the onboarding state machine the
 * embedded views drive. Mounted under the same `/v1/iam` prefix.
 */
export const IAM_PATHS = {
  /** Live list of enabled auth methods for the embedded login views. */
  authMethods: "/v1/iam/auth/methods",
  /** Onboarding state-machine base (steps append `/identity`, etc.). */
  onboarding: "/v1/iam/onboarding",
  /**
   * Credential-login endpoint the embedded `<Login>` views POST to.
   * `type=code` (a client `redirectUri` is present) mints an authorization
   * code returned in `data`; `type=login` establishes the session cookie.
   * This is what the deployed IAM actually authenticates against — the OIDC
   * token endpoint's password/OTP grants are NOT enabled per-client.
   */
  login: "/v1/iam/login",
  /** Send an email/SMS verification code (passwordless login). */
  sendCode: "/v1/iam/send-verification-code",
  /** Account registration. */
  signup: "/v1/iam/signup",
  /**
   * Sign-In-with-X (SIWx / EIP-4361) nonce endpoint. Issues a server-owned,
   * single-use nonce (and the exact message to sign) so the wallet signature
   * cannot be replayed. The client NEVER invents the challenge — the server
   * is the authority over the message content and the nonce lifetime.
   */
  web3Nonce: "/v1/iam/web3/nonce",
  /**
   * SIWx verify endpoint. The client POSTs the exact signed message +
   * signature (and a PKCE `code_challenge`); the server recovers the signer
   * from the signature (never trusting a client-supplied address), validates
   * the nonce, and returns a PKCE-bound authorization `code`. The SAME
   * RFC 7636 exchange then completes it through `handleCallback`.
   */
  web3Verify: "/v1/iam/web3/verify",
} as const;

export type IamPathKey = keyof typeof IAM_PATHS;

/**
 * The canonical `serverUrl` origin for each Hanzo IAM brand. White-label
 * is host-based: one IAM deployment serves every brand and selects the
 * tenant by the origin it is reached on. This is the SINGLE place the
 * brand→origin mapping lives — adapters take a `brand` and resolve here
 * rather than each app hard-coding a hostname.
 */
export const BRAND_SERVER_URLS = {
  hanzo: "https://iam.hanzo.ai",
  lux: "https://lux.id",
  zoo: "https://zoo.id",
  bootnode: "https://id.bootno.de",
  pars: "https://pars.id",
} as const;

/** A known Hanzo IAM brand key. */
export type IamBrand = keyof typeof BRAND_SERVER_URLS;

/**
 * Resolve a brand to its canonical IAM `serverUrl`.
 *
 * @example
 * serverUrlForBrand("lux") // → "https://lux.id"
 */
export function serverUrlForBrand(brand: IamBrand): string {
  return BRAND_SERVER_URLS[brand];
}

/** Strip trailing slashes from a server origin so paths concat cleanly. */
export function trimServerUrl(serverUrl: string): string {
  return serverUrl.replace(/\/+$/, "");
}

/**
 * Build an absolute IAM endpoint URL from a server origin and a path key.
 *
 * @example
 * iamUrl("https://iam.hanzo.ai", "token") // → "https://iam.hanzo.ai/v1/iam/oauth/token"
 */
export function iamUrl(serverUrl: string, key: OidcPathKey): string {
  return `${trimServerUrl(serverUrl)}${OIDC_PATHS[key]}`;
}
