import { IamConfig } from './types.js';

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

interface IamSocialProvider {
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
declare function iamProvider(config: IamConfig & {
    redirectUri?: string;
}): IamSocialProvider;

export { type IamSocialProvider as HanzoIamSocialProvider, type IamSocialProvider, iamProvider as hanzoIamProvider, iamProvider as hanzoIamSocialProvider, iamProvider };
