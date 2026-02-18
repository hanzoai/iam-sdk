/**
 * Core types for the Hanzo IAM SDK.
 * Based on Casdoor data models.
 */

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

export type IamConfig = {
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

export type IamJwtClaims = {
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

export type IamUser = {
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

export type IamOrganization = {
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
// Subscription / Plan / Pricing
// ---------------------------------------------------------------------------

export type IamSubscription = {
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

export type IamPlan = {
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

export type IamPricing = {
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

// ---------------------------------------------------------------------------
// Payment / Order
// ---------------------------------------------------------------------------

export type IamPayment = {
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

export type IamOrder = {
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

// ---------------------------------------------------------------------------
// Auth result
// ---------------------------------------------------------------------------

export type IamAuthResult =
  | {
      ok: true;
      userId: string;
      email?: string;
      name?: string;
      avatar?: string;
      owner: string;
      claims: IamJwtClaims;
    }
  | {
      ok: false;
      reason: string;
    };

// ---------------------------------------------------------------------------
// API response wrapper
// ---------------------------------------------------------------------------

export type IamApiResponse<T> = {
  status: "ok" | "error";
  msg?: string;
  data?: T;
  data2?: unknown;
};
