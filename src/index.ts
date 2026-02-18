/**
 * @hanzo/iam — TypeScript SDK for Hanzo IAM (identity & access management).
 *
 * Handles: auth (OIDC, JWT, PKCE), users, organizations, projects.
 * Billing is backed by Commerce — the BillingClient talks to Commerce API.
 *
 * @example
 * ```ts
 * import { IamClient, BillingClient, validateToken } from "@hanzo/iam";
 *
 * const client = new IamClient({
 *   serverUrl: "https://iam.hanzo.ai",
 *   clientId: "my-app",
 * });
 *
 * const billing = new BillingClient({
 *   commerceUrl: "https://commerce.hanzo.ai",
 * });
 * ```
 */

// Core client (auth, users, orgs, projects → IAM)
export { IamClient, IamApiError } from "./client.js";

// Billing client (subscriptions, plans, payments, usage → Commerce API)
// Canonical source: commerce.js/billing. Re-exported here for convenience.
export { BillingClient, IamBillingClient, CommerceApiError } from "./billing.js";

// JWT validation
export { validateToken, clearJwksCache } from "./auth.js";

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
  IamProject,
  Subscription,
  Plan,
  Pricing,
  Payment,
  Order,
  UsageRecord,
  UsageSummary,
  IamSubscription,
  IamPlan,
  IamPricing,
  IamPayment,
  IamOrder,
  IamUsageRecord,
  IamUsageSummary,
  IamAuthResult,
  IamApiResponse,
} from "./types.js";
