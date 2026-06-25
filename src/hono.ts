/**
 * Hono middleware for Hanzo IAM.
 *
 *  - {@link requireAuth} — middleware that 401s requests without a valid IAM
 *    token and otherwise stores the session in the Hono context (`c.set`).
 *  - {@link getSession} — resolve the session for a request without blocking
 *    (returns `null` when absent), for optional-auth routes.
 *
 * Hono keeps its NATIVE routing; this is just a guard. The Hono context
 * exposes the Web `Request` at `c.req.raw`, which the framework-agnostic
 * `@hanzo/iam/server` verifier consumes directly.
 *
 * @example
 * ```ts
 * import { Hono } from "hono";
 * import { requireAuth, getIamSession } from "@hanzo/iam/hono";
 *
 * const iam = { serverUrl: process.env.IAM_SERVER_URL!, clientId: process.env.IAM_CLIENT_ID! };
 * const app = new Hono();
 *
 * app.use("/api/*", requireAuth(iam));
 * app.get("/api/me", (c) => {
 *   const session = getIamSession(c);
 *   return c.json({ user: session.userId, org: session.owner });
 * });
 * ```
 *
 * @packageDocumentation
 */

import type { Config } from "./types.js";
import {
  getServerSession,
  type ServerSession,
  type ServerSessionOptions,
} from "./server.js";

/** Hono context variable key the session is stored under. */
export const IAM_SESSION_KEY = "iamSession" as const;

/**
 * Minimal Hono context shape (only what the guard touches): the raw Web
 * `Request`, a JSON responder, and the typed `get`/`set` var store.
 */
export interface IamHonoContext {
  req: { raw: Request };
  json(body: unknown, status?: number): Response;
  set(key: string, value: unknown): void;
  get(key: string): unknown;
}

/** Hono `next` callback. */
export type HonoNext = () => Promise<void>;

/**
 * Hono middleware that requires a valid IAM session.
 *
 * Verifies the bearer token / session cookie against IAM's JWKS, stores the
 * result under `c.set("iamSession", …)`, and calls `next()`. On no/invalid
 * token it returns `401` and does NOT call `next()`.
 */
export function requireAuth(
  config: Config,
  options?: ServerSessionOptions,
): (c: IamHonoContext, next: HonoNext) => Promise<Response | void> {
  return async (c, next) => {
    const session = await getServerSession(c.req.raw, config, options);
    if (!session) {
      return c.json({ error: "unauthorized" }, 401);
    }
    c.set(IAM_SESSION_KEY, session);
    await next();
  };
}

/**
 * Resolve the IAM session for a Hono request without blocking the route
 * (returns `null` when there is no valid token).
 */
export function getSession(
  c: IamHonoContext,
  config: Config,
  options?: ServerSessionOptions,
): Promise<ServerSession | null> {
  return getServerSession(c.req.raw, config, options);
}

/**
 * Read the session stored by {@link requireAuth} off the Hono context.
 * Throws if the route was not guarded by `requireAuth` (programming error).
 */
export function getIamSession(c: IamHonoContext): ServerSession {
  const session = c.get(IAM_SESSION_KEY) as ServerSession | undefined;
  if (!session) {
    throw new Error(
      "@hanzo/iam/hono: no session in context — guard the route with requireAuth() first, or use getSession() for optional auth.",
    );
  }
  return session;
}
