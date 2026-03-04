/**
 * BetterAuth SSO provider configuration for IAM.
 *
 * Returns a provider config object compatible with BetterAuth's
 * `socialProviders` or generic OAuth plugin.
 *
 * @example
 * ```ts
 * import { betterAuth } from "better-auth";
 * import { iamProvider } from "@hanzo/iam/betterauth";
 *
 * export const auth = betterAuth({
 *   socialProviders: [
 *     iamProvider({
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
export interface IamSocialProvider {
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
 * Create a BetterAuth-compatible social provider for IAM.
 *
 * Works with BetterAuth's SSO plugin or generic OAuth integration.
 * Uses standard OIDC endpoints.
 */
export declare function iamProvider(config: IamConfig & {
    redirectUri?: string;
}): IamSocialProvider;
/** @deprecated Use iamProvider instead */
export { iamProvider as hanzoIamProvider };
/** @deprecated Use iamProvider instead */
export { iamProvider as hanzoIamSocialProvider };
/** @deprecated Use IamSocialProvider instead */
export type { IamSocialProvider as HanzoIamSocialProvider };
//# sourceMappingURL=betterauth.d.ts.map