/**
 * Express / Connect middleware for Hanzo IAM.
 *
 * Two functions, both pointed at the canonical IAM endpoints via the
 * framework-agnostic `@hanzo/iam/server` verifier:
 *
 *  - {@link requireAuth} — middleware that 401s requests without a valid
 *    IAM token and otherwise attaches the session to `req.iamSession`.
 *  - {@link getSession} — resolve the session for a request without
 *    blocking (returns `null` when absent), for optional-auth routes.
 *
 * Express keeps its NATIVE routing; this is just a guard. Works with any
 * Connect-style framework whose `req.headers` is a Node headers record
 * (Express, Connect, raw `http`). For Hono use `@hanzo/iam/hono`.
 *
 * @example
 * ```ts
 * import express from "express";
 * import { requireAuth, getIamSession } from "@hanzo/iam/express";
 *
 * const iam = { serverUrl: process.env.IAM_SERVER_URL!, clientId: process.env.IAM_CLIENT_ID! };
 * const app = express();
 *
 * app.get("/me", requireAuth(iam), (req, res) => {
 *   const session = getIamSession(req);          // typed, always present here
 *   res.json({ user: session.userId, org: session.owner });
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
  type HeaderCarrier,
} from "./server.js";

/** The property `requireAuth` attaches the resolved session to on `req`. */
export const IAM_SESSION_PROP = "iamSession" as const;

/** Minimal Express-style request: a Node headers record + our attached session. */
export interface IamRequest extends HeaderCarrier {
  [IAM_SESSION_PROP]?: ServerSession;
}

/** Minimal Express-style response (only what the guard touches). */
export interface IamResponse {
  status(code: number): IamResponse;
  json(body: unknown): unknown;
}

/** Express `next` callback. */
export type NextFn = (err?: unknown) => void;

/** Express-style middleware signature. */
export type IamMiddleware = (
  req: IamRequest,
  res: IamResponse,
  next: NextFn,
) => void;

/**
 * Express/Connect middleware that requires a valid IAM session.
 *
 * Reads `Authorization: Bearer …` (then the session cookie), verifies it
 * against IAM's JWKS, attaches the result to `req.iamSession`, and calls
 * `next()`. On no/invalid token it responds `401` and does NOT call
 * `next()`.
 */
export function requireAuth(
  config: Config,
  options?: ServerSessionOptions,
): IamMiddleware {
  return (req, res, next) => {
    getServerSession(req, config, options)
      .then((session) => {
        if (!session) {
          res.status(401).json({ error: "unauthorized" });
          return;
        }
        req[IAM_SESSION_PROP] = session;
        next();
      })
      .catch(next);
  };
}

/**
 * Resolve the IAM session for an Express request without blocking the
 * route (returns `null` when there is no valid token). Use for routes that
 * are public but personalize when signed in.
 */
export function getSession(
  req: IamRequest,
  config: Config,
  options?: ServerSessionOptions,
): Promise<ServerSession | null> {
  return getServerSession(req, config, options);
}

/**
 * Read the session attached by {@link requireAuth} off a request. Throws if
 * called on a request that did not pass through `requireAuth` (programming
 * error). For optional auth, call {@link getSession} instead.
 */
export function getIamSession(req: IamRequest): ServerSession {
  const session = req[IAM_SESSION_PROP];
  if (!session) {
    throw new Error(
      "@hanzo/iam/express: no session on request — guard the route with requireAuth() first, or use getSession() for optional auth.",
    );
  }
  return session;
}
