import { IamConfig } from './types.cjs';

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

interface IamPassportConfig extends IamConfig {
    /** Full callback URL for OAuth2 redirect. */
    callbackUrl: string;
    /** OAuth2 scopes. Default: "openid profile email". */
    scope?: string;
}
interface IamPassportUser {
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
declare function createIamPassportStrategy(config: IamPassportConfig): unknown;

export { type IamPassportConfig, type IamPassportUser, createIamPassportStrategy };
