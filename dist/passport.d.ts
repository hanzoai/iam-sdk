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
export declare function createIamPassportStrategy(config: IamPassportConfig): unknown;
//# sourceMappingURL=passport.d.ts.map