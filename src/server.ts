/**
 * Framework-agnostic server-side session helper for Hanzo IAM.
 *
 * One way to answer "who is calling?" on the server: read the bearer
 * token (`Authorization: Bearer …`) or the session cookie, verify it
 * against IAM's JWKS via {@link validateToken}, and return the identity.
 *
 * Works with any request that exposes headers — the Web Fetch `Request`
 * (Next.js App Router route handlers / middleware, Hono, Remix) and the
 * Node `IncomingMessage` (Next.js Pages API routes, Express, raw http).
 *
 * @example Next.js App Router route handler
 * ```ts
 * import { getServerSession } from "@hanzo/iam/server";
 *
 * const iam = { serverUrl: process.env.IAM_ENDPOINT!, clientId: process.env.IAM_CLIENT_ID! };
 *
 * export async function GET(req: Request) {
 *   const session = await getServerSession(req, iam);
 *   if (!session) return new Response("unauthorized", { status: 401 });
 *   // session.userId, session.owner, session.email, session.claims
 *   return Response.json({ user: session.userId, org: session.owner });
 * }
 * ```
 *
 * @example Guarded route handler
 * ```ts
 * import { withSession } from "@hanzo/iam/server";
 *
 * export const GET = withSession(iam, (req, session) =>
 *   Response.json({ org: session.owner }),
 * );
 * ```
 *
 * @packageDocumentation
 */

import type { Config, JwtClaims } from "./types.js";
import { validateToken } from "./auth.js";

/** Canonical cookie name carrying the IAM access token for SSR. */
export const SESSION_COOKIE = "hanzo_iam_access_token";

/** The authenticated identity resolved from a verified IAM token. */
export interface ServerSession {
  /** Subject — IAM user id, format "org/username". */
  userId: string;
  /** Owning organization (the `owner` claim or the `sub` org prefix). */
  owner: string;
  /** User email, when present in the token. */
  email?: string;
  /** All verified JWT claims. */
  claims: JwtClaims;
}

/** Options for session resolution. */
export interface ServerSessionOptions {
  /** Cookie name to read the token from. Default {@link SESSION_COOKIE}. */
  cookieName?: string;
}

/**
 * Minimal request shape: either a Web `Request` (with `headers.get`) or a
 * Node `IncomingMessage` (with a `headers` record). Both are accepted.
 */
export interface HeaderCarrier {
  headers:
    | { get(name: string): string | null }
    | Record<string, string | string[] | undefined>;
}

function readHeader(req: HeaderCarrier, name: string): string | undefined {
  const headers = req.headers;
  if (typeof (headers as { get?: unknown }).get === "function") {
    return (headers as { get(n: string): string | null }).get(name) ?? undefined;
  }
  const value = (headers as Record<string, string | string[] | undefined>)[
    name.toLowerCase()
  ];
  if (Array.isArray(value)) return value[0];
  return value;
}

function parseCookie(header: string | undefined, name: string): string | undefined {
  if (!header) return undefined;
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq === -1) continue;
    if (part.slice(0, eq).trim() === name) {
      return decodeURIComponent(part.slice(eq + 1).trim());
    }
  }
  return undefined;
}

/**
 * Extract the IAM access token from a request: the `Authorization:
 * Bearer …` header takes precedence, falling back to the session cookie.
 * Returns undefined when neither is present.
 */
export function getBearerToken(
  req: HeaderCarrier,
  options?: ServerSessionOptions,
): string | undefined {
  const auth = readHeader(req, "authorization");
  if (auth) {
    const match = /^Bearer\s+(.+)$/i.exec(auth.trim());
    if (match) return match[1];
  }
  return parseCookie(readHeader(req, "cookie"), options?.cookieName ?? SESSION_COOKIE);
}

/**
 * Resolve the server session for a request. Reads the bearer token or
 * session cookie, verifies it against IAM, and returns the identity —
 * or `null` when no valid token is present.
 */
export async function getServerSession(
  req: HeaderCarrier,
  config: Config,
  options?: ServerSessionOptions,
): Promise<ServerSession | null> {
  const token = getBearerToken(req, options);
  if (!token) return null;

  const result = await validateToken(token, config);
  if (!result.ok) return null;

  return {
    userId: result.userId,
    owner: result.owner,
    email: result.email,
    claims: result.claims,
  };
}

/**
 * Wrap a route handler so it only runs with a valid session. Unauthorized
 * requests get a `401` (Web `Response`) before the handler is called.
 * The handler receives the original request plus the resolved session.
 *
 * Framework-agnostic over the Web Fetch `Request`/`Response` model used
 * by Next.js App Router, Hono, and Remix.
 */
export function withSession<Req extends HeaderCarrier, Res>(
  config: Config,
  handler: (req: Req, session: ServerSession) => Res | Promise<Res>,
  options?: ServerSessionOptions,
): (req: Req) => Promise<Res | Response> {
  return async (req: Req): Promise<Res | Response> => {
    const session = await getServerSession(req, config, options);
    if (!session) {
      return new Response("unauthorized", { status: 401 });
    }
    return handler(req, session);
  };
}
