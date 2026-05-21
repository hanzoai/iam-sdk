# @hanzo/iam

TypeScript SDK for [Hanzo IAM](https://iam.hanzo.ai) — identity & access management built on [Casdoor](https://casdoor.org).

## Features

- **JWT Validation** — OIDC discovery + JWKS-based signature verification via [jose](https://github.com/panva/jose)
- **OAuth2 PKCE** — Browser-side login flows (redirect, popup, silent signin)
- **API Client** — Users, organizations, OIDC discovery, token exchange
- **Billing** — Subscriptions, plans, pricing, payments, orders
- **TypeScript** — Full type safety with exported interfaces
- **Zero Config** — Auto-discovers endpoints via `.well-known/openid-configuration`

## Install

```bash
npm install @hanzo/iam
# or
pnpm add @hanzo/iam
```

## Server-Side Usage

### Validate a JWT

```typescript
import { validateToken } from "@hanzo/iam";

const result = await validateToken(accessToken, {
  serverUrl: "https://iam.hanzo.ai",
  clientId: "my-app",
});

if (result.ok) {
  console.log(result.userId, result.email, result.owner);
} else {
  console.error(result.reason);
}
```

### API Client

```typescript
import { IamClient } from "@hanzo/iam";

const client = new IamClient({
  serverUrl: "https://iam.hanzo.ai",
  clientId: "my-app",
  clientSecret: process.env.IAM_CLIENT_SECRET,
});

// OAuth2 authorization URL
const authUrl = await client.getAuthorizationUrl({
  redirectUri: "https://myapp.com/callback",
  state: "random-state",
});

// Exchange code for tokens
const tokens = await client.exchangeCode({
  code: "auth-code",
  redirectUri: "https://myapp.com/callback",
});

// Get user info
const user = await client.getUserInfo(tokens.access_token);
```

### Billing

```typescript
import { IamBillingClient } from "@hanzo/iam";

const billing = new IamBillingClient({
  serverUrl: "https://iam.hanzo.ai",
  clientId: "my-app",
  clientSecret: process.env.IAM_CLIENT_SECRET,
  orgName: "my-org",
});

const { active, subscription, plan } = await billing.isSubscriptionActive("my-org");
```

## Browser Usage (SPA)

```typescript
import { IAM } from "@hanzo/iam";

const iam = new IAM({
  serverUrl: "https://iam.hanzo.ai",
  clientId: "my-spa",
  redirectUri: "https://myapp.com/auth/callback",
});

// Start login
await iam.signinRedirect();

// On callback page
const token = await iam.handleCallback();

// Get a valid token (auto-refreshes if expired)
const access = await iam.getValidAccessToken();

// Fetch user info
const user = await iam.getUserInfo();

// Logout
iam.clearTokens();
```

### Conditional resolution

A single import line resolves to the right build per environment via the
package.json `exports` `browser` / `node` conditions:

| Consumer | Resolves to | Surface |
|----------|-------------|---------|
| Vite, webpack, Next.js, esbuild (browser target) | `dist/browser.js` | `IAM`, `toIAMToken`, `IAMConfig`, `IAMUser`, `IAMToken` |
| Node 18+ (`node` condition) | `dist/index.js` | `IamClient`, `validateToken`, `IAM`, types — full surface |
| Fallback (`default`) | `dist/index.js` | Full Node surface |

So both code paths are valid:

```typescript
// SPA / Next.js client / any bundled browser app
import { IAM } from "@hanzo/iam";

// Node service / SSR / scripts
import { IamClient, validateToken } from "@hanzo/iam";
```

## Sub-path Imports

```typescript
// Server-side JWT validation only (lighter import)
import { validateToken } from "@hanzo/iam/auth";

// Billing only
import { IamBillingClient } from "@hanzo/iam/billing";

// Types only
import type { IamConfig, IamUser } from "@hanzo/iam/types";
```

> **Deprecated**: `import { IAM } from "@hanzo/iam/browser"` still works
> but is no longer needed — use the bare specifier `@hanzo/iam` and let
> the `browser` export condition pick the right build. The `/browser`
> subpath will be removed in a future major.

## Configuration

| Option | Required | Description |
|--------|----------|-------------|
| `serverUrl` | Yes | IAM server URL (e.g. `https://iam.hanzo.ai`) |
| `clientId` | Yes | OAuth2 client ID |
| `clientSecret` | No | Client secret (server-side confidential clients) |
| `orgName` | No | Organization name for scoped queries |
| `appName` | No | Application name |

## Documentation

Full docs: [docs.hanzo.ai/services/iam/sdk](https://docs.hanzo.ai/services/iam/sdk)

## License

MIT — [Hanzo AI](https://hanzo.ai)
