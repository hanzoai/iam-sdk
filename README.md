> **MIRROR — do not publish from here.** The canonical `@hanzo/iam` source is **[hanzo-js/iam](https://github.com/hanzo-js/iam)** (the JS-SDK org home). Publishing happens there. This repo is retained for history only.

# @hanzo/iam

The one-way TypeScript SDK for authenticating against **Hanzo IAM**
(`hanzoai/iam`) — a clean-room OIDC provider served per-brand from a
configurable origin:

| Brand | `serverUrl` |
|-------|-------------|
| Hanzo | `https://iam.hanzo.ai` |
| Lux | `https://lux.id` |
| Zoo | `https://zoo.id` |
| Bootnode | `https://id.bootno.de` |
| Pars | `https://pars.id` |

The brand→origin map is exported as `BRAND_SERVER_URLS` /
`serverUrlForBrand(brand)` from `@hanzo/iam` (and `@hanzo/iam/paths`) — one
place, in code.

One OIDC path set. One name per thing. No backwards-compatibility shims.

## The one-way model

IAM is adapted **to** each framework; frameworks keep their **native** auth
routes. NextAuth/Auth.js hard-mount `/api/auth` (or `/auth`); Passport, Remix,
Express, and Hono each have their own route conventions — this SDK never moves
them onto `/v1`. The SDK's only job is to hand each framework a
provider/adapter **in its native shape** whose authorize/token/userinfo point
at our canonical `/v1/iam/oauth/*`. That translation lives here, in code, once
(`src/paths.ts`); every adapter resolves endpoints through it and nowhere
hard-codes a path. PKCE-S256 is always on; confidential clients use
`client_secret_basic`.

## The canonical paths

Every endpoint resolves through a single source of truth — `OIDC_PATHS`
(`@hanzo/iam/paths`). These are the **only** paths; there is no legacy
`/oauth/*` and no `/api/login/*`.

| Endpoint | Path |
|----------|------|
| discovery | `/.well-known/openid-configuration` |
| authorize | `/v1/iam/oauth/authorize` |
| token | `/v1/iam/oauth/token` |
| userinfo | `/v1/iam/oauth/userinfo` |
| jwks | `/v1/iam/.well-known/jwks` |
| logout | `/v1/iam/oauth/logout` |

> **Gotcha** IAM serves a `200 text/html` SPA for any unregistered path.
> A wrong path returns HTML, not a 404 — silent breakage. This SDK pins
> the exact paths and never lets discovery resolve to a wrong one: the
> OAuth adapters skip discovery entirely (explicit endpoints), and JWT
> verification **degrades to the canonical `jwks` path** when discovery
> fails or returns the HTML catch-all — so a discovery blip can never take
> down token validation.

PKCE (S256) is always on. Confidential clients use `client_secret_basic`.
Scopes are `["openid", "profile", "email"]`.

## Install

```bash
pnpm add @hanzo/iam
```

## One canonical usage per integration

### Server (Next.js App Router / Node / Hono / Remix) — `@hanzo/iam/server`

The piece PaaS-class apps need: resolve the caller's identity from the
bearer token or session cookie, verified against IAM's JWKS.

```ts
import { getServerSession, withSession } from "@hanzo/iam/server";

const iam = { serverUrl: process.env.IAM_ENDPOINT!, clientId: process.env.IAM_CLIENT_ID! };

// Option A — read the session yourself
export async function GET(req: Request) {
  const session = await getServerSession(req, iam);
  if (!session) return new Response("unauthorized", { status: 401 });
  return Response.json({ user: session.userId, org: session.owner, email: session.email });
}

// Option B — guard the handler (401 before your code runs)
export const POST = withSession(iam, (req, session) =>
  Response.json({ org: session.owner }),
);
```

`getServerSession(req, config, options?)` returns
`{ userId, owner, email?, claims } | null`. It reads `Authorization:
Bearer …` first, then the `hanzo_iam_access_token` cookie (override with
`options.cookieName`).

### JWT validation — `@hanzo/iam` (or `@hanzo/iam/auth`)

```ts
import { validateToken } from "@hanzo/iam";

const result = await validateToken(accessToken, {
  serverUrl: "https://iam.hanzo.ai",
  clientId: "my-app",
});

if (result.ok) {
  // result.userId, result.owner, result.email, result.claims
}
```

Audience **must** equal `clientId`; a mismatch fails with
`iam_audience_invalid`. For IAM deployments that issue tokens without an
`aud` claim, pass `allowMissingAudience: true` (the signature is still
verified).

The JWKS URI comes from OIDC discovery when reachable and **degrades to the
canonical `/v1/iam/.well-known/jwks` path** otherwise (discovery 5xx,
timeout, or the `200 text/html` SPA catch-all). The token signature is
always verified against the fetched JWKS — the fallback is not a bypass.

### better-auth — `@hanzo/iam/betterauth`

```ts
import { betterAuth } from "better-auth";
import { genericOAuth } from "better-auth/plugins";
import { iamProvider } from "@hanzo/iam/betterauth";

export const auth = betterAuth({
  plugins: [
    genericOAuth({
      config: [
        iamProvider({
          serverUrl: process.env.IAM_ENDPOINT!,
          clientId: process.env.IAM_CLIENT_ID!,
          clientSecret: process.env.IAM_CLIENT_SECRET!,
        }),
      ],
    }),
  ],
});
```

`iamProvider` returns a real `genericOAuth` config entry
(`providerId: "hanzo"`, pinned authorize/token/userinfo URLs, `pkce:
true`, `authentication: "basic"`). No `discoveryUrl`.

### NextAuth.js / Auth.js — `@hanzo/iam/nextauth`

```ts
import NextAuth from "next-auth";
import { HanzoIamProvider } from "@hanzo/iam/nextauth";

export default NextAuth({
  providers: [
    HanzoIamProvider({
      serverUrl: process.env.IAM_SERVER_URL!,
      clientId: process.env.IAM_CLIENT_ID!,
      clientSecret: process.env.IAM_CLIENT_SECRET,
    }),
  ],
});
```

The provider id defaults to `"hanzo-iam"`. Endpoints are **explicit** —
`authorization`/`token`/`userinfo`/`jwks_endpoint` come straight from
`OIDC_PATHS`; there is **no `wellKnown`/discovery round-trip** (a discovery
fetch that fails or resolves wrong would hit the IAM HTML SPA catch-all —
silent breakage). `issuer` + `jwks_endpoint` are supplied so openid-client
still verifies the id_token without discovery. `checks` default to
`["state", "pkce"]`; token auth is `client_secret_basic`. `IamProvider` is a
stable alias for the same function; the exported profile type is
`HanzoIamProfile`.

### SvelteKit / Auth.js core — `@hanzo/iam/sveltekit`

`@auth/core` (SvelteKit, SolidStart, `@auth/express`, …) consumes the same
provider shape as NextAuth, so the SvelteKit adapter is that provider under an
Auth.js-idiomatic name — one builder, the same explicit endpoints.

```ts
import { SvelteKitAuth } from "@auth/sveltekit";
import { HanzoIam } from "@hanzo/iam/sveltekit";
import { env } from "$env/dynamic/private";

export const { handle, signIn, signOut } = SvelteKitAuth({
  providers: [
    HanzoIam({
      serverUrl: env.IAM_SERVER_URL,
      clientId: env.IAM_CLIENT_ID,
      clientSecret: env.IAM_CLIENT_SECRET,
    }),
  ],
});
```

### Remix — `@hanzo/iam/remix`

Login via `remix-auth` + `remix-auth-oauth2` (you construct the strategy, so
its version stays yours); guards via the framework-agnostic verifier.

```ts
// app/auth.server.ts — login strategy
import { Authenticator } from "remix-auth";
import { OAuth2Strategy } from "remix-auth-oauth2";
import { hanzoIamStrategyOptions } from "@hanzo/iam/remix";

export const authenticator = new Authenticator(sessionStorage);
authenticator.use(
  new OAuth2Strategy(
    hanzoIamStrategyOptions({
      serverUrl: process.env.IAM_SERVER_URL!,
      clientId: process.env.IAM_CLIENT_ID!,
      clientSecret: process.env.IAM_CLIENT_SECRET!,
      redirectURI: "https://app.hanzo.ai/auth/hanzo-iam/callback",
    }),
    async ({ tokens }) => tokens,
  ),
  "hanzo-iam",
);
```

```ts
// guarded loader/action
import { requireSession } from "@hanzo/iam/remix";

const iam = { serverUrl: process.env.IAM_SERVER_URL!, clientId: process.env.IAM_CLIENT_ID! };

export async function loader({ request }: { request: Request }) {
  const session = await requireSession(request, iam); // throws 401 Response if absent
  return Response.json({ org: session.owner });
}
```

### Express / Connect — `@hanzo/iam/express`

```ts
import express from "express";
import { requireAuth, getIamSession } from "@hanzo/iam/express";

const iam = { serverUrl: process.env.IAM_SERVER_URL!, clientId: process.env.IAM_CLIENT_ID! };
const app = express();

app.get("/me", requireAuth(iam), (req, res) => {
  const session = getIamSession(req); // typed, present after requireAuth
  res.json({ user: session.userId, org: session.owner });
});
```

`requireAuth(config)` 401s tokenless requests and attaches the verified
session to `req.iamSession`. For optional-auth routes use
`getSession(req, config)` (returns `null` when absent).

### Hono — `@hanzo/iam/hono`

```ts
import { Hono } from "hono";
import { requireAuth, getIamSession } from "@hanzo/iam/hono";

const iam = { serverUrl: process.env.IAM_SERVER_URL!, clientId: process.env.IAM_CLIENT_ID! };
const app = new Hono();

app.use("/api/*", requireAuth(iam));
app.get("/api/me", (c) => {
  const session = getIamSession(c);
  return c.json({ user: session.userId, org: session.owner });
});
```

### React (SPA) — `@hanzo/iam/react`

`<Login>` is the DEFAULT login UI — one component, mounted embedded in your
app. Every method stays IN-PLACE (the app window never navigates to the
hosted login page): social via popup + `postMessage`, wallet via inline SIWx,
email/password/OTP via a PKCE-bound code.

```tsx
import { IamProvider, useIam, Login, completePopupSignin } from "@hanzo/iam/react";

function App() {
  return (
    <IamProvider config={{
      serverUrl: "https://iam.hanzo.ai",
      clientId: "my-app",
      redirectUri: `${window.location.origin}/auth/callback`,
    }}>
      <Main />
    </IamProvider>
  );
}

function Main() {
  const { user, isAuthenticated } = useIam();
  if (!isAuthenticated)
    return (
      <Login
        serverUrl="https://iam.hanzo.ai"
        clientId="my-app"
        redirectUri={`${location.origin}/auth/callback`}
        state=""
        providers={["google", "github", "wallet"]}
        onSuccess={(token) => { /* signed in, in-place */ }}
      />
    );
  return <div>Welcome, {user?.displayName}</div>;
}
```

Mount the popup callback bridge on your `redirect_uri` route — one line. It
hands the code back to the opener for popup sign-ins, and no-ops (returns
`false`) for a normal navigation so your usual `handleCallback()` runs:

```tsx
// pages/auth/callback
import { completePopupSignin, handleCallback } from "@hanzo/iam/browser";

if (!completePopupSignin()) {
  await handleCallback(); // normal top-level redirect callback
}
```

`useIam().login()` (full-page `signinRedirect`) remains only as an explicit
standalone fallback — prefer `<Login>` or `loginPopup` so login stays
in-place.

### Browser (framework-free PKCE) — `@hanzo/iam` (or `@hanzo/iam/browser`)

```ts
import { IAM, completePopupSignin } from "@hanzo/iam";

const iam = new IAM({
  serverUrl: "https://iam.hanzo.ai",
  clientId: "my-spa",
  redirectUri: "https://myapp.com/auth/callback",
});

// In-place social (Google/GitHub can't be iframed → popup + postMessage):
const token = await iam.signinPopup({ additionalParams: { provider: "google" } });
// In-place wallet (SIWx / EIP-4361, no redirect, no loop):
const walletToken = await iam.loginWithWallet();
// Standalone fallback only — full-page redirect to the hosted page:
await iam.signinRedirect();
const t = await iam.handleCallback();      // on the callback route
await iam.logout();
```

`signinPopup` verifies the callback message's `origin`, `source` tag, and
`state` before it will touch the code; `completePopupSignin` (mounted on the
`redirect_uri` route) posts back with `targetOrigin` pinned to its own origin,
never `"*"`. A bare code is useless without the opener's PKCE verifier, which
never leaves the opener.

Drop-in login + onboarding views also live at `@hanzo/iam/views` (`Login`,
`SocialButton`, `WalletButton`, `EmailPasswordForm`, `OTPStep`,
`OnboardingFlow`, and the five onboarding step primitives).

### Passport.js — `@hanzo/iam/passport`

```ts
import passport from "passport";
import { createIamPassportStrategy } from "@hanzo/iam/passport";

passport.use("iam", createIamPassportStrategy({
  serverUrl: "https://iam.hanzo.ai",
  clientId: "my-app",
  clientSecret: process.env.IAM_CLIENT_SECRET!,
  callbackUrl: "https://app.hanzo.ai/v1/sso/oidc/callback",
}));
```

### Validation — `@hanzo/iam/validation`

```ts
import { isValidPhone, isValidEmail } from "@hanzo/iam/validation";

isValidPhone("6178888888", "+1"); // true — E.164 +16178888888
isValidEmail("user@example.com"); // true
```

## Subpath map

| Import | Surface |
|--------|---------|
| `@hanzo/iam` | `IamClient`, `IamApiError`, `validateToken`, `clearJwksCache`, `IAM`, `toIAMToken`, `completePopupSignin`, `POPUP_WINDOW_NAME`, `generatePKCEChallenge`, `generateState`, `configureIam`, `startLogin`, `getLoginUrl`, `handleCallback`, `getSession`, `getUser`, `logout`, `OIDC_PATHS`, `IAM_PATHS`, `BRAND_SERVER_URLS`, `iamUrl`, `serverUrlForBrand`, all types |
| `@hanzo/iam/paths` | `OIDC_PATHS`, `IAM_PATHS`, `BRAND_SERVER_URLS`, `iamUrl`, `trimServerUrl`, `serverUrlForBrand` |
| `@hanzo/iam/session` | `configureIam`, `startLogin`, `getLoginUrl`, `handleCallback`, `getSession`, `getUser`, `logout`, `getIam` |
| `@hanzo/iam/server` | `getServerSession`, `withSession`, `getBearerToken`, `SESSION_COOKIE`, `ServerSession` |
| `@hanzo/iam/auth` | `validateToken`, `clearJwksCache` |
| `@hanzo/iam/browser` | `IAM` (`signinPopup`, `loginWithWallet`, `signinRedirect`, `handleCallback`), `completePopupSignin`, `POPUP_WINDOW_NAME`, `toIAMToken`, `IAMConfig`, `IAMUser`, `IAMToken`, `Eip1193Provider` |
| `@hanzo/iam/react` | `IamProvider`, `useIam`, `useOrganizations`, `useIamToken`, `OrgProjectSwitcher`, `Login`, `SocialButton`, `WalletButton`, `EmailPasswordForm`, `OTPStep`, `OnboardingFlow`, `useAuthMethods`, `completePopupSignin` |
| `@hanzo/iam/views` | `Login`, `SocialButton`, `WalletButton`, `EmailPasswordForm`, `OTPStep`, `OnboardingFlow`, `IdentityStep`, `DocumentsStep`, `BiometricStep`, `ScreenStep`, `SubmitStep`, `useAuthMethods` |
| `@hanzo/iam/betterauth` | `iamProvider` |
| `@hanzo/iam/nextauth` | `HanzoIamProvider`, `IamProvider` (alias), `HanzoIamProfile` |
| `@hanzo/iam/sveltekit` | `HanzoIam`, `HanzoIamProvider`, `IamProvider` |
| `@hanzo/iam/remix` | `hanzoIamStrategyOptions`, `requireSession`, `getSession` |
| `@hanzo/iam/express` | `requireAuth`, `getSession`, `getIamSession` |
| `@hanzo/iam/hono` | `requireAuth`, `getSession`, `getIamSession` |
| `@hanzo/iam/passport` | `createIamPassportStrategy` |
| `@hanzo/iam/types` | all types |
| `@hanzo/iam/validation` | `isValidPhone`, `isValidEmail` |

Bare `@hanzo/iam` resolves to the browser build under a browser bundler
and the Node build under Node, via package `exports` conditions.

## Configuration

| Option | Required | Description |
|--------|----------|-------------|
| `serverUrl` | Yes | IAM origin (e.g. `https://iam.hanzo.ai`) |
| `clientId` | Yes | OAuth2 client ID |
| `clientSecret` | No | Secret for confidential clients |
| `orgName` | No | Organization (owner) context |
| `appName` | No | Application name |
| `allowMissingAudience` | No | Skip the `aud` check during `validateToken` (default `false`) |

## License

MIT — [Hanzo AI](https://hanzo.ai)
