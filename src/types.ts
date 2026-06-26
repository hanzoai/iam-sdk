/**
 * Core types for the Hanzo IAM SDK.
 * Hanzo IAM data models.
 */

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

export type Config = {
  /** IAM server base URL (e.g. "https://iam.hanzo.ai"). */
  serverUrl: string;
  /** OAuth2 client ID. */
  clientId: string;
  /** OAuth2 client secret (for confidential clients / server-side). */
  clientSecret?: string;
  /** Organization name (owner context). */
  orgName?: string;
  /** Application name. */
  appName?: string;
  /**
   * When true, JWT validation skips the audience check entirely. Use
   * only for IAM deployments that issue access tokens without an `aud`
   * claim. Default false — `aud` must equal `clientId` or validation
   * fails with `iam_audience_invalid`.
   */
  allowMissingAudience?: boolean;
  /**
   * Explicit JWKS endpoint for server-side token validation, bypassing OIDC
   * discovery. REQUIRED for in-cluster / split-horizon deployments: a pod
   * often cannot reach the public IAM origin (`serverUrl`) — the external LB
   * hairpins or a WAF 403s pod→public traffic — and IAM's discovery doc
   * advertises that unreachable public `jwks_uri`. Point this at the
   * in-cluster IAM service instead, e.g.
   * `http://iam.hanzo.svc/v1/iam/.well-known/jwks`. When set, `validateToken`
   * fetches keys here and never calls discovery. The keys are the same (one
   * IAM), so signatures still verify.
   */
  jwksUri?: string;
  /**
   * Explicit expected token issuer, bypassing the issuer OIDC discovery would
   * report. REQUIRED alongside `jwksUri` for split-horizon: the token's `iss`
   * is the public per-brand login origin (e.g. `https://hanzo.id`), but
   * in-cluster discovery reports a different/canonical issuer
   * (e.g. `https://hanzo.ai`). Set this to the public origin tokens are
   * actually minted with so the issuer check matches.
   */
  issuer?: string;
};

// ---------------------------------------------------------------------------
// OIDC
// ---------------------------------------------------------------------------

export type OidcDiscovery = {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint: string;
  jwks_uri: string;
  scopes_supported?: string[];
  response_types_supported?: string[];
  grant_types_supported?: string[];
};

export type TokenResponse = {
  access_token: string;
  token_type: string;
  expires_in?: number;
  refresh_token?: string;
  id_token?: string;
  scope?: string;
};

// ---------------------------------------------------------------------------
// JWT Claims
// ---------------------------------------------------------------------------

export type JwtClaims = {
  /** Subject (user ID in format "org/username"). */
  sub: string;
  /** Issuer URL. */
  iss?: string;
  /** Audience. */
  aud?: string | string[];
  /** Expiry (unix seconds). */
  exp?: number;
  /** Issued at (unix seconds). */
  iat?: number;
  /** User email. */
  email?: string;
  /** Display name. */
  name?: string;
  /** Preferred username. */
  preferred_username?: string;
  /** Avatar URL. */
  picture?: string;
  /** Phone number. */
  phone?: string;
  /** Groups/roles. */
  groups?: string[];
  /** Arbitrary extra claims. */
  [key: string]: unknown;
};

// ---------------------------------------------------------------------------
// User
// ---------------------------------------------------------------------------

export type User = {
  owner: string;
  name: string;
  id?: string;
  displayName?: string;
  email?: string;
  phone?: string;
  avatar?: string;
  type?: string;
  isAdmin?: boolean;
  isGlobalAdmin?: boolean;
  createdTime?: string;
  signupApplication?: string;
};

// ---------------------------------------------------------------------------
// Organization
// ---------------------------------------------------------------------------

export type Organization = {
  owner: string;
  name: string;
  displayName?: string;
  createdTime?: string;
  websiteUrl?: string;
  logo?: string;
  logoDark?: string;
  favicon?: string;
  isPersonal?: boolean;
  orgBalance?: number;
  userBalance?: number;
  balanceCredit?: number;
  balanceCurrency?: string;
};

// ---------------------------------------------------------------------------
// Billing (canonical types — backed by Commerce service)
// ---------------------------------------------------------------------------

export type Subscription = {
  owner: string;
  name: string;
  displayName?: string;
  createdTime?: string;
  user?: string;
  plan?: string;
  pricing?: string;
  startTime?: string;
  endTime?: string;
  duration?: number;
  state?: "Active" | "Inactive" | "Expired" | "Cancelled" | string;
  description?: string;
};

export type Plan = {
  owner: string;
  name: string;
  displayName?: string;
  createdTime?: string;
  description?: string;
  pricePerMonth?: number;
  pricePerYear?: number;
  currency?: string;
  options?: string[];
  isEnabled?: boolean;
  role?: string;
};

export type Pricing = {
  owner: string;
  name: string;
  displayName?: string;
  createdTime?: string;
  description?: string;
  plans?: string[];
  isEnabled?: boolean;
  application?: string;
  trialDuration?: number;
};

export type Payment = {
  owner: string;
  name: string;
  displayName?: string;
  createdTime?: string;
  provider?: string;
  type?: string;
  currency?: string;
  price?: number;
  user?: string;
  state?: string;
  message?: string;
};

export type Order = {
  owner: string;
  name: string;
  displayName?: string;
  createdTime?: string;
  user?: string;
  products?: string[];
  price?: number;
  currency?: string;
  state?: string;
  message?: string;
};

export type UsageRecord = {
  owner: string;
  name: string;
  user?: string;
  application?: string;
  organization?: string;
  project?: string;
  model?: string;
  provider?: string;
  promptTokens?: number;
  completionTokens?: number;
  totalTokens?: number;
  cost?: number;
  currency?: string;
  premium?: boolean;
  stream?: boolean;
  status?: string;
  errorMsg?: string;
  clientIp?: string;
  requestId?: string;
  createdTime?: string;
};

export type UsageSummary = {
  totalRequests: number;
  totalTokens: number;
  totalCost: number;
  promptTokens: number;
  completionTokens: number;
};

// ---------------------------------------------------------------------------
// Project
// ---------------------------------------------------------------------------

export type Project = {
  owner: string;
  name: string;
  displayName?: string;
  description?: string;
  organization: string;
  tags?: string[];
  metadata?: Record<string, unknown>;
  isDefault?: boolean;
  createdTime?: string;
};

// ---------------------------------------------------------------------------
// Auth result
// ---------------------------------------------------------------------------

export type AuthResult =
  | {
      ok: true;
      userId: string;
      email?: string;
      name?: string;
      avatar?: string;
      owner: string;
      claims: JwtClaims;
    }
  | {
      ok: false;
      reason: string;
    };

// ---------------------------------------------------------------------------
// API response wrapper
// ---------------------------------------------------------------------------

export type ApiResponse<T> = {
  status: "ok" | "error";
  msg?: string;
  data?: T;
  data2?: unknown;
};
