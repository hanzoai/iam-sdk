/**
 * Billing client for Hanzo IAM (Casdoor) — subscriptions, plans, pricing, usage.
 */

import type {
  IamConfig,
  IamSubscription,
  IamPlan,
  IamPricing,
  IamPayment,
  IamOrder,
  IamApiResponse,
} from "./types.js";

const DEFAULT_TIMEOUT_MS = 10_000;

export class IamBillingClient {
  private readonly baseUrl: string;
  private readonly clientId: string;
  private readonly clientSecret: string | undefined;
  private readonly orgName: string | undefined;

  constructor(config: IamConfig) {
    this.baseUrl = config.serverUrl.replace(/\/+$/, "");
    this.clientId = config.clientId;
    this.clientSecret = config.clientSecret;
    this.orgName = config.orgName;
  }

  // -----------------------------------------------------------------------
  // Internal HTTP helper
  // -----------------------------------------------------------------------

  private async request<T>(
    path: string,
    opts?: {
      method?: string;
      body?: unknown;
      token?: string;
      params?: Record<string, string>;
    },
  ): Promise<T> {
    const url = new URL(path, this.baseUrl);
    if (opts?.params) {
      for (const [k, v] of Object.entries(opts.params)) {
        url.searchParams.set(k, v);
      }
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), DEFAULT_TIMEOUT_MS);

    const headers: Record<string, string> = {
      Accept: "application/json",
    };
    if (opts?.token) {
      headers.Authorization = `Bearer ${opts.token}`;
    }
    if (opts?.body) {
      headers["Content-Type"] = "application/json";
    }
    if (this.clientSecret && !opts?.token) {
      const basic = Buffer.from(`${this.clientId}:${this.clientSecret}`).toString("base64");
      headers.Authorization = `Basic ${basic}`;
    }

    try {
      const res = await fetch(url.toString(), {
        method: opts?.method ?? "GET",
        headers,
        body: opts?.body ? JSON.stringify(opts.body) : undefined,
        signal: controller.signal,
      });

      if (!res.ok) {
        const text = await res.text().catch(() => "");
        throw new Error(`IAM billing request failed (${res.status}): ${text}`.trim());
      }

      return (await res.json()) as T;
    } finally {
      clearTimeout(timer);
    }
  }

  // -----------------------------------------------------------------------
  // Subscriptions
  // -----------------------------------------------------------------------

  /** Get all subscriptions for an owner. */
  async getSubscriptions(token?: string): Promise<IamSubscription[]> {
    const owner = this.orgName ?? "admin";
    const resp = await this.request<IamApiResponse<IamSubscription[]>>(
      "/api/get-subscriptions",
      { params: { owner }, token },
    );
    return resp.data ?? [];
  }

  /** Get a specific subscription by ID ("owner/name" format). */
  async getSubscription(id: string, token?: string): Promise<IamSubscription | null> {
    const resp = await this.request<IamApiResponse<IamSubscription>>(
      "/api/get-subscription",
      { params: { id }, token },
    );
    return resp.data ?? null;
  }

  /** Get the subscription for a specific user. */
  async getUserSubscription(userId: string, token?: string): Promise<IamSubscription | null> {
    const subs = await this.getSubscriptions(token);
    return subs.find((s) => s.user === userId) ?? null;
  }

  // -----------------------------------------------------------------------
  // Plans
  // -----------------------------------------------------------------------

  /** Get all plans for an owner. */
  async getPlans(token?: string): Promise<IamPlan[]> {
    const owner = this.orgName ?? "admin";
    const resp = await this.request<IamApiResponse<IamPlan[]>>(
      "/api/get-plans",
      { params: { owner }, token },
    );
    return resp.data ?? [];
  }

  /** Get a specific plan by ID. */
  async getPlan(id: string, token?: string): Promise<IamPlan | null> {
    const resp = await this.request<IamApiResponse<IamPlan>>(
      "/api/get-plan",
      { params: { id }, token },
    );
    return resp.data ?? null;
  }

  // -----------------------------------------------------------------------
  // Pricing
  // -----------------------------------------------------------------------

  /** Get all pricing configurations for an owner. */
  async getPricings(token?: string): Promise<IamPricing[]> {
    const owner = this.orgName ?? "admin";
    const resp = await this.request<IamApiResponse<IamPricing[]>>(
      "/api/get-pricings",
      { params: { owner }, token },
    );
    return resp.data ?? [];
  }

  /** Get a specific pricing by ID. */
  async getPricing(id: string, token?: string): Promise<IamPricing | null> {
    const resp = await this.request<IamApiResponse<IamPricing>>(
      "/api/get-pricing",
      { params: { id }, token },
    );
    return resp.data ?? null;
  }

  // -----------------------------------------------------------------------
  // Payments
  // -----------------------------------------------------------------------

  /** Get all payments for an owner. */
  async getPayments(token?: string): Promise<IamPayment[]> {
    const owner = this.orgName ?? "admin";
    const resp = await this.request<IamApiResponse<IamPayment[]>>(
      "/api/get-payments",
      { params: { owner }, token },
    );
    return resp.data ?? [];
  }

  /** Get a specific payment by ID. */
  async getPayment(id: string, token?: string): Promise<IamPayment | null> {
    const resp = await this.request<IamApiResponse<IamPayment>>(
      "/api/get-payment",
      { params: { id }, token },
    );
    return resp.data ?? null;
  }

  // -----------------------------------------------------------------------
  // Orders (if supported by IAM)
  // -----------------------------------------------------------------------

  /** Get all orders for an owner. */
  async getOrders(token?: string): Promise<IamOrder[]> {
    const owner = this.orgName ?? "admin";
    const resp = await this.request<IamApiResponse<IamOrder[]>>(
      "/api/get-orders",
      { params: { owner }, token },
    );
    return resp.data ?? [];
  }

  /** Get a specific order by ID. */
  async getOrder(id: string, token?: string): Promise<IamOrder | null> {
    const resp = await this.request<IamApiResponse<IamOrder>>(
      "/api/get-order",
      { params: { id }, token },
    );
    return resp.data ?? null;
  }

  // -----------------------------------------------------------------------
  // Convenience: check subscription status for an org
  // -----------------------------------------------------------------------

  /** Check if an org has an active subscription. */
  async isSubscriptionActive(orgName: string, token?: string): Promise<{
    active: boolean;
    subscription: IamSubscription | null;
    plan: IamPlan | null;
  }> {
    const subs = await this.getSubscriptions(token);
    // Find subscription matching the org
    const sub = subs.find(
      (s) => s.owner === orgName && (s.state === "Active" || s.state === "active"),
    ) ?? null;

    if (!sub) {
      return { active: false, subscription: null, plan: null };
    }

    let plan: IamPlan | null = null;
    if (sub.plan) {
      plan = await this.getPlan(sub.plan, token);
    }

    return { active: true, subscription: sub, plan };
  }
}
