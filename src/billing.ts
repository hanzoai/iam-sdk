/**
 * @hanzo/iam/billing — Billing client for Hanzo Commerce API.
 *
 * Canonical billing lives in commerce.js/billing. This provides the same
 * client for convenience when @hanzo/iam is already installed.
 * Both talk to Commerce API — one way to do billing.
 *
 * @example
 * ```ts
 * // Preferred:
 * import { BillingClient } from 'commerce.js/billing'
 *
 * // Also works:
 * import { BillingClient } from '@hanzo/iam/billing'
 * ```
 */

const DEFAULT_TIMEOUT_MS = 10_000;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

export type CommerceConfig = {
  /** Commerce API base URL (e.g. "https://commerce.hanzo.ai"). */
  commerceUrl: string;
  /** Optional IAM access token for authenticated requests. */
  token?: string;
};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type Balance = {
  balance: number;
  holds: number;
  available: number;
};

export type Transaction = {
  id?: string;
  type: "hold" | "hold-removed" | "transfer" | "deposit" | "withdraw";
  currency: string;
  amount: number;
  tags?: string[];
  expiresAt?: string;
  metadata?: Record<string, unknown>;
  createdAt?: string;
};

export type Subscription = {
  id?: string;
  planId?: string;
  userId?: string;
  status?: string;
  billingType?: string;
  periodStart?: string;
  periodEnd?: string;
  createdAt?: string;
};

export type Plan = {
  slug?: string;
  name?: string;
  description?: string;
  price?: number;
  currency?: string;
  interval?: string;
  metadata?: Record<string, unknown>;
};

export type Payment = {
  id?: string;
  orderId?: string;
  amount?: number;
  currency?: string;
  status?: string;
  captured?: boolean;
  createdAt?: string;
};

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

export class BillingClient {
  private readonly baseUrl: string;
  private token: string | undefined;

  constructor(config: CommerceConfig) {
    this.baseUrl = config.commerceUrl.replace(/\/+$/, "");
    this.token = config.token;
  }

  setToken(token: string) {
    this.token = token;
  }

  private async request<T>(
    path: string,
    opts?: { method?: string; body?: unknown; token?: string; params?: Record<string, string> },
  ): Promise<T> {
    const url = new URL(path, this.baseUrl);
    if (opts?.params) {
      for (const [k, v] of Object.entries(opts.params)) url.searchParams.set(k, v);
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), DEFAULT_TIMEOUT_MS);

    const headers: Record<string, string> = { Accept: "application/json" };
    const authToken = opts?.token ?? this.token;
    if (authToken) headers.Authorization = `Bearer ${authToken}`;
    if (opts?.body) headers["Content-Type"] = "application/json";

    try {
      const res = await fetch(url.toString(), {
        method: opts?.method ?? "GET",
        headers,
        body: opts?.body ? JSON.stringify(opts.body) : undefined,
        signal: controller.signal,
      });
      if (!res.ok) {
        const text = await res.text().catch(() => "");
        throw new CommerceApiError(res.status, `${res.statusText}: ${text}`.trim());
      }
      return (await res.json()) as T;
    } finally {
      clearTimeout(timer);
    }
  }

  async getBalance(user: string, currency = "usd", token?: string): Promise<Balance> {
    return this.request("/api/v1/billing/balance", { params: { user, currency }, token });
  }

  async getAllBalances(user: string, token?: string): Promise<Record<string, Balance>> {
    return this.request("/api/v1/billing/balance/all", { params: { user }, token });
  }

  async addUsageRecord(record: { user: string; currency?: string; amount: number; model?: string; provider?: string; tokens?: number }, token?: string): Promise<Transaction> {
    return this.request("/api/v1/billing/usage", { method: "POST", body: record, token });
  }

  async getUsageRecords(user: string, currency = "usd", token?: string): Promise<Transaction[]> {
    return this.request("/api/v1/billing/usage", { params: { user, currency }, token });
  }

  async addDeposit(params: { user: string; currency?: string; amount: number; notes?: string; tags?: string[]; expiresIn?: string }, token?: string): Promise<Transaction> {
    return this.request("/api/v1/billing/deposit", { method: "POST", body: params, token });
  }

  async grantStarterCredit(user: string, token?: string): Promise<Transaction> {
    return this.request("/api/v1/billing/credit", { method: "POST", body: { user }, token });
  }

  async subscribe(params: { planId: string; userId: string }, token?: string): Promise<Subscription> {
    return this.request("/api/v1/subscribe", { method: "POST", body: params, token });
  }

  async getSubscription(id: string, token?: string): Promise<Subscription | null> {
    try { return await this.request(`/api/v1/subscribe/${id}`, { token }); } catch { return null; }
  }

  async cancelSubscription(id: string, token?: string): Promise<void> {
    await this.request(`/api/v1/subscribe/${id}`, { method: "DELETE", token });
  }

  async getPlans(token?: string): Promise<Plan[]> {
    return this.request("/api/v1/plan", { token });
  }

  async getPlan(id: string, token?: string): Promise<Plan | null> {
    try { return await this.request(`/api/v1/plan/${id}`, { token }); } catch { return null; }
  }

  async authorize(orderId: string, token?: string): Promise<Payment> {
    return this.request(`/api/v1/authorize/${orderId}`, { method: "POST", token });
  }

  async capture(orderId: string, token?: string): Promise<Payment> {
    return this.request(`/api/v1/capture/${orderId}`, { method: "POST", token });
  }

  async charge(orderId: string, token?: string): Promise<Payment> {
    return this.request(`/api/v1/charge/${orderId}`, { method: "POST", token });
  }

  async refund(paymentId: string, token?: string): Promise<Payment> {
    return this.request(`/api/v1/refund/${paymentId}`, { method: "POST", token });
  }
}

export class CommerceApiError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = "CommerceApiError";
    this.status = status;
  }
}

// Backwards-compatible alias
export { BillingClient as IamBillingClient };
