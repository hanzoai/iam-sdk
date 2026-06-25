/**
 * @hanzo/iam — TypeScript SDK for Hanzo IAM (identity & access management).
 *
 * Handles: auth (OIDC, JWT, PKCE), users, organizations, projects. One
 * canonical OIDC path set (`OIDC_PATHS`), one name per thing.
 *
 * @example
 * ```ts
 * import { IamClient, validateToken } from "@hanzo/iam";
 *
 * const client = new IamClient({
 *   serverUrl: "https://iam.hanzo.ai",
 *   clientId: "my-app",
 * });
 *
 * const result = await validateToken(accessToken, {
 *   serverUrl: "https://iam.hanzo.ai",
 *   clientId: "my-app",
 * });
 * ```
 */

// Core client (auth, users, orgs, projects → IAM)
export { IamClient, IamApiError } from "./client.js";

// JWT validation
export { validateToken, clearJwksCache } from "./auth.js";

// Browser PKCE auth (re-exported from separate entry point too)
export { IAM, toIAMToken, type IAMConfig, type IAMUser, type IAMToken } from "./browser.js";
export { generatePKCEChallenge, generateState } from "./pkce.js";

// Promoted functional auth surface — the ONE thing apps import.
// `provider` is the only knob; mechanism lives in browser.ts/session.ts.
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

// React bindings — import from "@hanzo/iam/react" for tree-shaking:
//   import { IamProvider, useIam, useOrganizations } from "@hanzo/iam/react"

// Types — one canonical name per thing. The package name "@hanzo/iam"
// is the namespace, so consumers write
// `import { User, Organization } from '@hanzo/iam'`.
export type {
  Config,
  OidcDiscovery,
  TokenResponse,
  JwtClaims,
  User,
  Organization,
  Project,
  AuthResult,
  ApiResponse,
  Subscription,
  Plan,
  Pricing,
  Payment,
  Order,
  UsageRecord,
  UsageSummary,
} from "./types.js";

// Canonical OIDC paths — the single source of truth.
export { OIDC_PATHS, IAM_PATHS, iamUrl, trimServerUrl } from "./paths.js";
