# @hanzo/iam

The one-way TypeScript SDK for authenticating against **Hanzo IAM** — a
Casdoor-derived OIDC provider served per-brand from a configurable origin:

| Brand | `serverUrl` |
|-------|-------------|
| Hanzo | `https://iam.hanzo.ai` |
| Lux | `https://lux.id` |
| Zoo | `https://zoo.id` |
| Bootnode | `https://id.bootno.de` |

One OIDC path set. One name per thing. No backwards-compatibility shims.

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
> the exact paths and never lets a failed discovery fall back to a wrong
> one.

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
import { IamProvider } from "@hanzo/iam/nextauth";

export default NextAuth({
  providers: [
    IamProvider({
      serverUrl: process.env.IAM_ENDPOINT!,
      clientId: process.env.IAM_CLIENT_ID!,
      clientSecret: process.env.IAM_CLIENT_SECRET!,
    }),
  ],
});
```

`checks` default to `["state", "pkce"]`. `wellKnown` points at OIDC
discovery; openid-client follows it to the canonical JWKS endpoint.

### React (SPA) — `@hanzo/iam/react`

```tsx
import { IamProvider, useIam, useOrganizations } from "@hanzo/iam/react";

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
  const { user, isAuthenticated, login, logout } = useIam();
  const { currentOrg, switchOrg } = useOrganizations();
  if (!isAuthenticated) return <button onClick={() => login()}>Log in</button>;
  return <div>Welcome, {user?.displayName}</div>;
}
```

Drop-in login + onboarding views live at `@hanzo/iam/views` (`Login`,
`SocialButton`, `WalletButton`, `EmailPasswordForm`, `OTPStep`,
`OnboardingFlow`, and the five onboarding step primitives).

### Browser (framework-free PKCE) — `@hanzo/iam` (or `@hanzo/iam/browser`)

```ts
import { IAM } from "@hanzo/iam";

const iam = new IAM({
  serverUrl: "https://iam.hanzo.ai",
  clientId: "my-spa",
  redirectUri: "https://myapp.com/auth/callback",
});

await iam.signinRedirect();           // start PKCE redirect
const token = await iam.handleCallback();  // on the callback route
const access = await iam.getValidAccessToken(); // auto-refreshes
await iam.logout();
```

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
| `@hanzo/iam` | `IamClient`, `IamApiError`, `validateToken`, `clearJwksCache`, `IAM`, `toIAMToken`, `generatePKCEChallenge`, `generateState`, `OIDC_PATHS`, `IAM_PATHS`, `iamUrl`, all types |
| `@hanzo/iam/paths` | `OIDC_PATHS`, `IAM_PATHS`, `iamUrl`, `trimServerUrl` |
| `@hanzo/iam/server` | `getServerSession`, `withSession`, `getBearerToken`, `SESSION_COOKIE`, `ServerSession` |
| `@hanzo/iam/auth` | `validateToken`, `clearJwksCache` |
| `@hanzo/iam/browser` | `IAM`, `toIAMToken`, `IAMConfig`, `IAMUser`, `IAMToken` |
| `@hanzo/iam/react` | `IamProvider`, `useIam`, `useOrganizations`, `useIamToken`, `OrgProjectSwitcher` |
| `@hanzo/iam/views` | `Login`, `SocialButton`, `WalletButton`, `EmailPasswordForm`, `OTPStep`, `OnboardingFlow`, `IdentityStep`, `DocumentsStep`, `BiometricStep`, `ScreenStep`, `SubmitStep`, `useAuthMethods` |
| `@hanzo/iam/betterauth` | `iamProvider` |
| `@hanzo/iam/nextauth` | `IamProvider` |
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
