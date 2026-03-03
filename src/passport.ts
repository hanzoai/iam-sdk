/**
 * Passport.js OAuth2 strategy factory for Hanzo IAM.
 *
 * Creates a pre-configured passport-oauth2 strategy that authenticates
 * against hanzo.id with PKCE and fetches user info on callback.
 *
 * @example
 * ```ts
 * import passport from "passport";
 * import { createIamPassportStrategy } from "@hanzo/iam/passport";
 *
 * passport.use("iam", createIamPassportStrategy({
 *   serverUrl: "https://hanzo.id",
 *   clientId: "hanzo-kms-client-id",
 *   clientSecret: process.env.IAM_CLIENT_SECRET!,
 *   callbackUrl: "https://kms.hanzo.ai/api/v1/sso/oidc/callback",
 * }));
 * ```
 *
 * @packageDocumentation
 */

import type { IamConfig } from "./types.js";

export interface IamPassportConfig extends IamConfig {
  /** Full callback URL for OAuth2 redirect. */
  callbackUrl: string;
  /** OAuth2 scopes. Default: "openid profile email". */
  scope?: string;
}

export interface IamPassportUser {
  accessToken: string;
  refreshToken?: string;
  userinfo: Record<string, unknown>;
}

/**
 * Create a Passport OAuth2 strategy for Hanzo IAM.
 *
 * Requires `passport-oauth2` as a peer dependency.
 * Returns an OAuth2Strategy instance ready to pass to `passport.use()`.
 *
 * The verify callback fetches userinfo from the IAM server and passes
 * `{ accessToken, refreshToken, userinfo }` as the user object.
 */
export function createIamPassportStrategy(
  config: IamPassportConfig,
): unknown {
  // Dynamic import to keep passport-oauth2 as optional peer dep.
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { Strategy: OAuth2Strategy } = require("passport-oauth2") as {
    Strategy: new (
      options: Record<string, unknown>,
      verify: (...args: unknown[]) => void,
    ) => unknown;
  };

  const baseUrl = config.serverUrl.replace(/\/+$/, "");

  const verify = async (
    ...args: unknown[]
  ): Promise<void> => {
    // passReqToCallback=true: (req, accessToken, refreshToken, profile, done)
    const accessToken = args[1] as string;
    const refreshToken = args[2] as string | undefined;
    const done = args[4] as (err: Error | null, user?: IamPassportUser) => void;

    try {
      const res = await fetch(`${baseUrl}/oauth/userinfo`, {
        headers: { Authorization: `Bearer ${accessToken}` },
      });
      if (!res.ok) {
        return done(new Error(`IAM userinfo failed: ${res.status}`));
      }
      const userinfo = (await res.json()) as Record<string, unknown>;
      done(null, { accessToken, refreshToken, userinfo });
    } catch (err) {
      done(err instanceof Error ? err : new Error(String(err)));
    }
  };

  return new OAuth2Strategy(
    {
      authorizationURL: `${baseUrl}/oauth/authorize`,
      tokenURL: `${baseUrl}/oauth/token`,
      clientID: config.clientId,
      clientSecret: config.clientSecret ?? "",
      callbackURL: config.callbackUrl,
      scope: config.scope ?? "openid profile email",
      state: true,
      pkce: true,
      passReqToCallback: true,
    },
    verify,
  );
}
