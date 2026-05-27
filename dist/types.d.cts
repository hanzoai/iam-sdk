/**
 * Core types for the Hanzo IAM SDK.
 * Hanzo IAM data models.
 */
type Config = {
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
/** @deprecated Use {@link Config} instead. */
type IamConfig = Config;
type OidcDiscovery = {
    issuer: string;
    authorization_endpoint: string;
    token_endpoint: string;
    userinfo_endpoint: string;
    jwks_uri: string;
    scopes_supported?: string[];
    response_types_supported?: string[];
    grant_types_supported?: string[];
};
type TokenResponse = {
    access_token: string;
    token_type: string;
    expires_in?: number;
    refresh_token?: string;
    id_token?: string;
    scope?: string;
};
type JwtClaims = {
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
/** @deprecated Use {@link JwtClaims} instead. */
type IamJwtClaims = JwtClaims;
type User = {
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
/** @deprecated Use {@link User} instead. */
type IamUser = User;
type Organization = {
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
/** @deprecated Use {@link Organization} instead. */
type IamOrganization = Organization;
type Subscription = {
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
type Plan = {
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
type Pricing = {
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
type Payment = {
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
type Order = {
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
type UsageRecord = {
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
type UsageSummary = {
    totalRequests: number;
    totalTokens: number;
    totalCost: number;
    promptTokens: number;
    completionTokens: number;
};
type IamSubscription = Subscription;
type IamPlan = Plan;
type IamPricing = Pricing;
type IamPayment = Payment;
type IamOrder = Order;
type IamUsageRecord = UsageRecord;
type IamUsageSummary = UsageSummary;
type Project = {
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
/** @deprecated Use {@link Project} instead. */
type IamProject = Project;
type AuthResult = {
    ok: true;
    userId: string;
    email?: string;
    name?: string;
    avatar?: string;
    owner: string;
    claims: JwtClaims;
} | {
    ok: false;
    reason: string;
};
/** @deprecated Use {@link AuthResult} instead. */
type IamAuthResult = AuthResult;
type ApiResponse<T> = {
    status: "ok" | "error";
    msg?: string;
    data?: T;
    data2?: unknown;
};
/** @deprecated Use {@link ApiResponse} instead. */
type IamApiResponse<T> = ApiResponse<T>;

export type { ApiResponse, AuthResult, Config, IamApiResponse, IamAuthResult, IamConfig, IamJwtClaims, IamOrder, IamOrganization, IamPayment, IamPlan, IamPricing, IamProject, IamSubscription, IamUsageRecord, IamUsageSummary, IamUser, JwtClaims, OidcDiscovery, Order, Organization, Payment, Plan, Pricing, Project, Subscription, TokenResponse, UsageRecord, UsageSummary, User };
