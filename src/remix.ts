/**
 * Remix adapter for Hanzo IAM.
 *
 * Two pieces, both pointed at the canonical `/v1/iam/oauth/*` endpoints:
 *
 *  - {@link hanzoIamStrategyOptions} — the explicit-endpoint options object
 *    for `remix-auth-oauth2`'s `OAuth2Strategy` (login via Remix's own
 *    `remix-auth` Authenticator). `remix-auth-oauth2` stays a peer dep:
 *    the consumer constructs the strategy so we don't pin its version.
 *  - {@link requireSession} / {@link getSession} — loader/action guards.
 *    A Remix loader/action receives a Web `Request`, so these just wrap the
 *    framework-agnostic `@hanzo/iam/server` verifier.
 *
 * Remix keeps its NATIVE auth routes (the `remix-auth` Authenticator action
 * route, typically `routes/auth.$provider.tsx`); this SDK never moves them.
 *
 * @example Login strategy (`app/auth.server.ts`)
 * ```ts
 * import { Authenticator } from "remix-auth";
 * import { OAuth2Strategy } from "remix-auth-oauth2";
 * import { hanzoIamStrategyOptions } from "@hanzo/iam/remix";
 *
 * export const authenticator = new Authenticator(sessionStorage);
 * authenticator.use(
 *   new OAuth2Strategy(
 *     hanzoIamStrategyOptions({
 *       serverUrl: process.env.IAM_SERVER_URL!,
 *       clientId: process.env.IAM_CLIENT_ID!,
 *       clientSecret: process.env.IAM_CLIENT_SECRET!,
 *       redirectURI: "https://app.hanzo.ai/auth/hanzo-iam/callback",
 *     }),
 *     async ({ tokens }) => tokens,
 *   ),
 *   "hanzo-iam",
 * );
 * ```
 *
 * @example Guarded loader
 * ```ts
 * import { requireSession } from "@hanzo/iam/remix";
 *
 * const iam = { serverUrl: process.env.IAM_SERVER_URL!, clientId: process.env.IAM_CLIENT_ID! };
 *
 * export async function loader({ request }: { request: Request }) {
 *   const session = await requireSession(request, iam);   // throws 401 Response if absent
 *   return Response.json({ org: session.owner });
 * }
 * ```
 *
 * @packageDocumentation
 */

import type { Config } from "./types.js";
import { iamUrl } from "./paths.js";
import {
  getServerSession,
  type ServerSession,
  type ServerSessionOptions,
} from "./server.js";

/** Options accepted by {@link hanzoIamStrategyOptions}. */
export interface HanzoIamRemixOptions extends Config {
  /** OAuth2 redirect URI registered for this app's callback route. */
  redirectURI: string;
  /** OAuth scopes. Default: ["openid", "profile", "email"]. */
  scopes?: string[];
}

/**
 * Options object for `remix-auth-oauth2`'s `OAuth2Strategy`, with the
 * authorization + token endpoints pinned to the canonical IAM paths.
 * PKCE-S256 is requested via `codeChallengeMethod`.
 */
export interface HanzoIamStrategyOptions {
  clientId: string;
  clientSecret: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  redirectURI: string;
  scopes: string[];
  codeChallengeMethod: "S256";
}

/**
 * Build the explicit-endpoint options for a Remix `OAuth2Strategy`.
 * Pass the result straight to `new OAuth2Strategy(opts, verify)`.
 */
export function hanzoIamStrategyOptions(
  options: HanzoIamRemixOptions,
): HanzoIamStrategyOptions {
  return {
    clientId: options.clientId,
    clientSecret: options.clientSecret ?? "",
    authorizationEndpoint: iamUrl(options.serverUrl, "authorize"),
    tokenEndpoint: iamUrl(options.serverUrl, "token"),
    redirectURI: options.redirectURI,
    scopes: options.scopes ?? ["openid", "profile", "email"],
    codeChallengeMethod: "S256",
  };
}

/**
 * Resolve the IAM session for a Remix loader/action `Request`, or `null`.
 * Verifies the bearer token / session cookie against IAM's JWKS.
 */
export function getSession(
  request: Request,
  config: Config,
  options?: ServerSessionOptions,
): Promise<ServerSession | null> {
  return getServerSession(request, config, options);
}

/**
 * Like {@link getSession} but throws a `401` `Response` (Remix catches and
 * renders it) when there is no valid session. Returns the session otherwise.
 */
export async function requireSession(
  request: Request,
  config: Config,
  options?: ServerSessionOptions,
): Promise<ServerSession> {
  const session = await getServerSession(request, config, options);
  if (!session) {
    throw new Response("unauthorized", { status: 401 });
  }
  return session;
}
