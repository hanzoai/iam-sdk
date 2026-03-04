/**
 * BetterAuth SSO provider configuration for Hanzo IAM.
 *
 * Returns a provider config object compatible with BetterAuth's
 * `socialProviders` or generic OAuth plugin.
 *
 * @example
 * ```ts
 * import { betterAuth } from "better-auth";
 * import { hanzoIamProvider } from "@hanzo/iam/betterauth";
 *
 * export const auth = betterAuth({
 *   socialProviders: [
 *     hanzoIamProvider({
 *       serverUrl: process.env.IAM_SERVER_URL!,
 *       clientId: process.env.IAM_CLIENT_ID!,
 *       clientSecret: process.env.IAM_CLIENT_SECRET!,
 *     }),
 *   ],
 * });
 * ```
 *
 * @packageDocumentation
 */
import type { IamConfig } from "./types.js";
export interface HanzoIamSocialProvider {
    id: string;
    name: string;
    type: "oidc";
    issuer: string;
    clientId: string;
    clientSecret?: string;
    authorization: {
        url: string;
        params: {
            scope: string;
        };
    };
    token: {
        url: string;
    };
    userinfo: {
        url: string;
    };
    profile: (profile: Record<string, unknown>) => {
        id: string;
        name: string;
        email: string;
        image: string | null;
    };
}
/**
 * Create a BetterAuth-compatible social provider for Hanzo IAM.
 *
 * Works with BetterAuth's SSO plugin or generic OAuth integration.
 * Uses the standard Hanzo IAM / Casdoor OIDC endpoints.
 */
export declare function hanzoIamProvider(config: IamConfig & {
    redirectUri?: string;
}): HanzoIamSocialProvider;
export { hanzoIamProvider as hanzoIamSocialProvider };
//# sourceMappingURL=betterauth.d.ts.map