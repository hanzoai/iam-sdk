/**
 * Auth.js provider for Hanzo IAM — SvelteKit (`@auth/sveltekit`) and any
 * other `@auth/core` host (SolidStart, Express via `@auth/express`, etc.).
 *
 * `@auth/core` consumes the SAME `OAuthConfig` shape as NextAuth, so this
 * is the NextAuth provider under an Auth.js-idiomatic name — one builder,
 * one set of explicit `/v1/iam/oauth/*` endpoints, no second copy. Auth.js
 * keeps its NATIVE routes (`/auth/*` handle); this SDK never moves them.
 *
 * @example SvelteKit `src/auth.ts`
 * ```ts
 * import { SvelteKitAuth } from "@auth/sveltekit";
 * import { HanzoIam } from "@hanzo/iam/sveltekit";
 * import { env } from "$env/dynamic/private";
 *
 * export const { handle, signIn, signOut } = SvelteKitAuth({
 *   providers: [
 *     HanzoIam({
 *       serverUrl: env.IAM_SERVER_URL,        // e.g. https://iam.hanzo.ai
 *       clientId: env.IAM_CLIENT_ID,
 *       clientSecret: env.IAM_CLIENT_SECRET,
 *     }),
 *   ],
 * });
 * ```
 *
 * @packageDocumentation
 */

export {
  HanzoIamProvider,
  HanzoIamProvider as HanzoIam,
  IamProvider,
  type HanzoIamProfile,
  type HanzoIamProviderOptions,
} from "./nextauth.js";
