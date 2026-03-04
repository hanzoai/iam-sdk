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
/**
 * Create a Passport OAuth2 strategy for Hanzo IAM.
 *
 * Requires `passport-oauth2` as a peer dependency.
 * Returns an OAuth2Strategy instance ready to pass to `passport.use()`.
 *
 * The verify callback fetches userinfo from the IAM server and passes
 * `{ accessToken, refreshToken, userinfo }` as the user object.
 */
export function createIamPassportStrategy(config) {
    // Dynamic import to keep passport-oauth2 as optional peer dep.
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const { Strategy: OAuth2Strategy } = require("passport-oauth2");
    const baseUrl = config.serverUrl.replace(/\/+$/, "");
    const verify = async (...args) => {
        // passReqToCallback=true: (req, accessToken, refreshToken, profile, done)
        const accessToken = args[1];
        const refreshToken = args[2];
        const done = args[4];
        try {
            const res = await fetch(`${baseUrl}/api/userinfo`, {
                headers: { Authorization: `Bearer ${accessToken}` },
            });
            if (!res.ok) {
                return done(new Error(`IAM userinfo failed: ${res.status}`));
            }
            const userinfo = (await res.json());
            done(null, { accessToken, refreshToken, userinfo });
        }
        catch (err) {
            done(err instanceof Error ? err : new Error(String(err)));
        }
    };
    return new OAuth2Strategy({
        authorizationURL: `${baseUrl}/login/oauth/authorize`,
        tokenURL: `${baseUrl}/api/login/oauth/access_token`,
        clientID: config.clientId,
        clientSecret: config.clientSecret ?? "",
        callbackURL: config.callbackUrl,
        scope: config.scope ?? "openid profile email",
        state: true,
        pkce: true,
        passReqToCallback: true,
    }, verify);
}
//# sourceMappingURL=passport.js.map