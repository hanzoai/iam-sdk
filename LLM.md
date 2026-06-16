# iam-sdk — AI Assistant Context

# @hanzo/iam

The one-way TypeScript SDK for authenticating JS apps (Hanzo / Lux / Zoo /
Bootnode) against **Hanzo IAM**, a Casdoor-derived OIDC provider served
per-brand from a configurable `serverUrl`.

## The law: one source of truth for paths

`src/paths.ts` exports `OIDC_PATHS` — the ONLY OIDC paths. Every module
references it; **no path string is written anywhere else**. There is no
legacy `/oauth/*` and no `/api/login/*`.

| key | path |
|-----|------|
| discovery | `/.well-known/openid-configuration` |
| authorize | `/v1/iam/oauth/authorize` |
| token | `/v1/iam/oauth/token` |
| userinfo | `/v1/iam/oauth/userinfo` |
| jwks | `/v1/iam/.well-known/jwks` |
| logout | `/v1/iam/oauth/logout` |

`IAM_PATHS` holds the non-OIDC IAM-app endpoints used by the embedded
views: `authMethods` = `/v1/iam/auth/methods`, `onboarding` =
`/v1/iam/onboarding`.

**Gotcha that drives all of this:** IAM returns a `200 text/html` SPA for
any unregistered path. A wrong path yields HTML, not a 404 — silent
breakage. So: hit the exact paths, and never let a failed discovery fall
back to a wrong one. The hard-coded fallbacks in `browser.ts` use the
same canonical paths.

## Rules baked into the SDK

- **PKCE S256 always on.** `src/pkce.ts` verifier = base64url of 32
  `crypto.getRandomValues` bytes (256-bit entropy), challenge = base64url
  SHA-256 (S256). `generateState` is the same 256-bit primitive.
- **`validateToken` fails closed on audience.** `aud` must equal
  `clientId` → else `iam_audience_invalid`. Opt out only with
  `config.allowMissingAudience === true`. No silent retry. Branches on
  jose error *codes* (`ERR_JWT_EXPIRED`, `ERR_JWT_CLAIM_VALIDATION_FAILED`
  + `claim === "aud"`), not message strings.
- **One name per thing.** Canonical = `Iam*` classes (`IamClient`,
  `IamApiError`, `IamProvider`, `IamContext`) + `hanzo_iam_` storage
  prefix + clean type names (`Config`, `User`, `Organization`, …). The
  old `Hanzo*` aliases and the duplicate `Iam*` *type* aliases are
  **deleted** — do not reintroduce them.

## Subpath entries (tsup `entry[]` ↔ package.json `exports`)

`index`, `paths`, `auth`, `browser`, `server`, `types`, `react`, `views`,
`nextauth`, `passport`, `betterauth`, `validation`. Dual ESM (`.js`) + CJS
(`.cjs`) + `.d.ts`/`.d.cts` for each. **No `billing`** — it was a throwing
tombstone; deleted from src, tsup, and exports. Billing lives in
`@hanzo/commerce`.

- `src/server.ts` — framework-agnostic SSR helper. `getServerSession(req,
  config, opts?)` → `{ userId, owner, email?, claims } | null`. Reads
  `Authorization: Bearer …` then the `hanzo_iam_access_token` cookie.
  `withSession(config, handler, opts?)` guards a Web-`Response` route.
  Header reader duck-types both Web `Request` (`headers.get`) and Node
  `IncomingMessage` (headers record).
- `src/views.tsx` — REAL React components (built with `createElement`, no
  JSX syntax, so no `jsx` runtime needed at build). `Login` reads
  `IAM_PATHS.authMethods` and renders only enabled methods. The prior file
  was `export declare const`-only → an empty runtime module; that
  regression is locked out by `views.test.ts`.
- `src/betterauth.ts` — `iamProvider(config)` returns a real `genericOAuth`
  config entry: `{ providerId:"hanzo", authorizationUrl, tokenUrl,
  userInfoUrl, clientId, clientSecret, scopes, pkce:true,
  authentication:"basic" }`. Usage:
  `genericOAuth({ config: [iamProvider({...})] })`. No `discoveryUrl`.

## Build / test

- Node 26 + pnpm 9. `pnpm install && pnpm build` (tsup).
- Tests: `pnpm test` → `node --test --import tsx 'src/**/*.test.ts'`.
  `tsx` is a devDependency (native Node TS strips types but does NOT
  rewrite `./x.js` → `./x.ts`, so the test runner needs tsx).
- `node_modules/.bin/tsc --noEmit` must stay green (`tsconfig.json` sets
  `jsx: react-jsx` so the `.tsx` typechecks when imported from a test).
- 44 tests cover: locked paths, `validateToken` matrix (happy / expired /
  bad-aud-fails / missing-aud-fails / allowMissingAudience / tampered),
  PKCE ≥256-bit entropy, exact `iamProvider` shape, nextauth pkce default,
  passport `/v1/iam` URLs, server header extraction, views-are-real, and
  dual ESM+CJS resolution of every subpath.

## Repo

- npm package `@hanzo/iam`. Remote: `hanzoai/iam-sdk` (the git `origin`
  inside this checkout historically pointed at `hanzoai/iam` — push to
  `hanzoai/iam-sdk`).
- `go/` is a separate Go module (tenant helper); unrelated to the JS SDK.
