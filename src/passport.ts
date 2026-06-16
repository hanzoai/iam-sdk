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

import OAuth2Strategy from "passport-oauth2";

import type { Config } from "./types.js";
import { iamUrl } from "./paths.js";

export interface IamPassportConfig extends Config {
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
 * Returns an OAuth2Strategy instance ready to pass to `passport.use()`.
 * The verify callback fetches userinfo from the IAM server and passes
 * `{ accessToken, refreshToken, userinfo }` as the user object.
 *
 * `passport-oauth2` is a runtime dependency of this entry — using a
 * static import lets downstream bundlers (esbuild, webpack, etc.)
 * statically resolve and bundle it. Consumers who don't need passport
 * can import from `@hanzo/iam` directly to avoid pulling it in.
 */
export function createIamPassportStrategy(
  config: IamPassportConfig,
): unknown {

  const userinfoUrl = iamUrl(config.serverUrl, "userinfo");

  const verify = async (
    ...args: unknown[]
  ): Promise<void> => {
    // passReqToCallback=true: (req, accessToken, refreshToken, profile, done)
    const accessToken = args[1] as string;
    const refreshToken = args[2] as string | undefined;
    const done = args[4] as (err: Error | null, user?: IamPassportUser) => void;

    try {
      const res = await fetch(userinfoUrl, {
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
      authorizationURL: iamUrl(config.serverUrl, "authorize"),
      tokenURL: iamUrl(config.serverUrl, "token"),
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
