/**
 * @hanzo/iam — TypeScript SDK for Hanzo IAM (Casdoor-based identity & access management).
 *
 * @example
 * ```ts
 * import { IamClient, IamBillingClient, validateToken } from "@hanzo/iam";
 *
 * const client = new IamClient({
 *   serverUrl: "https://iam.hanzo.ai",
 *   clientId: "my-app",
 * });
 *
 * // Validate a JWT
 * const result = await validateToken(accessToken, {
 *   serverUrl: "https://iam.hanzo.ai",
 *   clientId: "my-app",
 * });
 * ```
 */

// Core client
export { IamClient, IamApiError } from "./client.js";

// JWT validation
export { validateToken, clearJwksCache } from "./auth.js";

// Billing client
export { IamBillingClient } from "./billing.js";

// Browser PKCE auth (re-exported from separate entry point too)
export { BrowserIamSdk, type BrowserIamConfig } from "./browser.js";
export { generatePkceChallenge, generateState } from "./pkce.js";

// React bindings — import from "@hanzo/iam/react" for tree-shaking:
//   import { IamProvider, useIam, useOrganizations } from "@hanzo/iam/react"

// Types (re-export everything)
export type {
  IamConfig,
  OidcDiscovery,
  TokenResponse,
  IamJwtClaims,
  IamUser,
  IamOrganization,
  IamSubscription,
  IamPlan,
  IamPricing,
  IamPayment,
  IamOrder,
  IamAuthResult,
  IamApiResponse,
} from "./types.js";
