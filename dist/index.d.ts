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
export { IamClient, IamApiError } from "./client.js";
export { validateToken, clearJwksCache } from "./auth.js";
export { IAM, toIAMToken, type IAMConfig, type IAMUser, type IAMToken } from "./browser.js";
export { generatePKCEChallenge, generateState } from "./pkce.js";
export type { IamConfig, OidcDiscovery, TokenResponse, IamJwtClaims, IamUser, IamOrganization, IamProject, Subscription, Plan, Pricing, Payment, Order, UsageRecord, UsageSummary, IamSubscription, IamPlan, IamPricing, IamPayment, IamOrder, IamUsageRecord, IamUsageSummary, IamAuthResult, IamApiResponse, } from "./types.js";
//# sourceMappingURL=index.d.ts.map