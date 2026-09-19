# iam-sdk — AI Assistant Context

# @hanzo/iam

The one-way TypeScript SDK for authenticating JS apps (Hanzo / Lux / Zoo /
Bootnode) against **Hanzo IAM**, a standards-first OIDC provider served
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
`/v1/iam/onboarding`, `login` = `/v1/iam/login`, `sendCode` =
`/v1/iam/send-verification-code`, `signup` = `/v1/iam/signup`, and the SIWx
wallet pair `web3Nonce` = `/v1/iam/web3/nonce`, `web3Verify` =
`/v1/iam/web3/verify`.

`BRAND_SERVER_URLS` / `serverUrlForBrand(brand)` is the ONE brand→origin
map (white-label is host-based; one IAM serves all brands): `hanzo` →
`iam.hanzo.ai`, `lux` → `lux.id`, `zoo` → `zoo.id`, `bootnode` →
`id.bootno.de`, `pars` → `pars.id`. Adapters take a `serverUrl`; apps that
prefer a brand key resolve it here rather than hard-coding a hostname.

## The one-way model (HIP-0111)

IAM is adapted TO each framework; frameworks keep their NATIVE auth routes
(NextAuth/Auth.js hard-mount `/api/auth` or `/auth` — never moved to
`/v1`; moving them caused a prod outage). Each adapter is the framework's
native provider/middleware shape whose authorize/token/userinfo resolve
through `paths.ts` to `/v1/iam/oauth/*`. **Every endpoint in every adapter
is built with `iamUrl(...)` / `OIDC_PATHS` — grep-proven, no path string
elsewhere, no `discoveryUrl`-only config.**

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
  `IamApiError`, `IamContext`) + `hanzo_iam_` storage prefix + clean type
  names (`Config`, `User`, `Organization`, …). Exception: the NextAuth
  provider's canonical export is `HanzoIamProvider` (+ `HanzoIamProfile`
  type) because that is what `console` imports; `IamProvider` is a stable
  alias to the same function. The React provider component is `IamProvider`
  (different module, different thing). Do not reintroduce other `Hanzo*`
  aliases.

## Subpath entries (tsup `entry[]` ↔ package.json `exports`)

`index`, `paths`, `auth`, `browser`, `session`, `server`, `types`, `react`,
`views`, `nextauth`, `sveltekit`, `remix`, `express`, `hono`, `passport`,
`betterauth`, `validation`. Dual ESM (`.js`) + CJS (`.cjs`) from tsup. The
declarations come from `tsc -p tsconfig.build.json`, a `.d.ts` per source
file, and `scripts/cts.mjs` copies each to a `.d.cts` whose relative imports
name `.cjs`, so a `require` consumer gets CommonJS types. The exports map has
no `types` conditions: TypeScript types a `.js` by the `.d.ts` beside it and a
`.cjs` by the `.d.cts`. tsup's own dts plugin cannot load on TypeScript 7,
which has no JS API. **No `billing`** — it was a throwing tombstone;
deleted from src, tsup, and exports. Billing lives in `@hanzo/commerce`.

Framework adapters (all thin, all → `paths.ts`, zero runtime framework
imports — they use structural types so no framework is a dependency):
- `src/nextauth.ts` — `HanzoIamProvider(opts)` (alias `IamProvider`) →
  NextAuth/Auth.js `OAuthConfig` with **explicit** `authorization`/`token`/
  `userinfo`/`jwks_endpoint` (NOT `wellKnown`/discovery — that would risk
  the SPA catch-all), default `id:"hanzo-iam"`, `client_secret_basic`,
  `checks:["state","pkce"]`. Exports type `HanzoIamProfile`. `console`
  spreads it and overrides `id`/`name`/`profile`.
- `src/sveltekit.ts` — re-exports the nextauth provider as `HanzoIam` for
  `@auth/core` hosts (SvelteKit/SolidStart/@auth/express). Same builder.
- `src/remix.ts` — `hanzoIamStrategyOptions(opts)` (explicit endpoints +
  `codeChallengeMethod:"S256"`) for `remix-auth-oauth2`'s `OAuth2Strategy`
  (peer, constructed by the app) + `requireSession`/`getSession` loader
  guards over `server.ts`.
- `src/express.ts` — `requireAuth(config)` middleware (401 + attach
  `req.iamSession`), `getSession` (optional), `getIamSession(req)` (typed
  read). Connect/Express/raw-http req.headers record.
- `src/hono.ts` — `requireAuth(config)` middleware (401 + `c.set`),
  `getSession`, `getIamSession(c)`. Uses `c.req.raw` Web Request.

- `src/server.ts` — framework-agnostic SSR helper. `getServerSession(req,
  config, opts?)` → `{ userId, owner, email?, claims } | null`. Reads
  `Authorization: Bearer …` then the `hanzo_iam_access_token` cookie.
  `withSession(config, handler, opts?)` guards a Web-`Response` route.
  Header reader duck-types both Web `Request` (`headers.get`) and Node
  `IncomingMessage` (headers record).
- `src/views.tsx` — REAL React components (built with `createElement`, no
  JSX syntax, so no `jsx` runtime needed at build). `Login` renders only the
  providers it is passed and is THE default login UI (also re-exported from
  the `/react` entry). Every method stays IN-PLACE — no full-page redirect to
  the hosted page: `SocialButton` → `IAM#signinPopup` (popup + `postMessage`;
  Google/GitHub can't be iframed), `WalletButton` → `IAM#loginWithWallet`
  (inline SIWx/EIP-4361, no loop), email/password/OTP → PKCE-bound
  `/v1/iam/login` code. All four converge on the SAME PKCE `handleCallback`.
  `signinRedirect` is only an explicit standalone fallback. The prior file
  was `export declare const`-only → an empty runtime module; that
  regression is locked out by `views.test.ts`.
- `src/browser.ts` popup+wallet (v0.13.5) — `IAM#signinPopup` completes over
  a one-shot `postMessage` handshake with THREE mandatory gates: `event.origin`
  === the `redirect_uri` origin (allowlist), `data.source === "hanzo-iam"`,
  and `data.state` === the state THIS call generated (CSRF). It tears the
  listener + popup down after the first accepted message and never logs the
  code. `completePopupSignin()` is the popup callback-page half — mount it on
  the `redirect_uri` route; it gates on the reserved `window.name`
  (`hanzo_iam_login`, set by `signinPopup`, survives the provider hop) so it is
  inert on any ordinary same-origin page that merely carries `?code` + an
  `opener`, then `postMessage`s `{code,state}` to the opener with `targetOrigin`
  pinned to its OWN origin (never `"*"`), else returns `false`.
  `IAM#loginWithWallet` runs GET `web3/nonce` → server message signed verbatim
  via `personal_sign` → POST `web3/verify` (server RECOVERS the signer; the
  client `address` is a hint, never trusted) → PKCE-bound code → `handleCallback`.
- PKCE transaction storage (v0.13.6 reconciliation) is BOTH durable AND
  per-attempt. It lives in `txStorage` = `localStorage` (via `resolveTxStorage`,
  probed at construct; falls back to the configured `storage` when localStorage
  is unavailable — SSR/privacy) so it survives the full-page OAuth redirect and
  Safari/WebKit ITP; and it is keyed per attempt as
  `hanzo_iam_code_verifier:<state>` (via `stashPkce`) so a double-click / racing
  `signinSilent` / re-run React effect can't stomp another attempt's verifier.
  Because localStorage persists across tabs/abandoned redirects, each slot value
  is stamped `${issuedAtMs}.${verifier}` and `stashPkce` opportunistically
  sweeps slots older than `VERIFIER_TTL_MS` (15m) — a live concurrent sibling
  (seconds old) is NEVER swept; `clearTokens` sweeps ALL slots (both stores).
  `handleCallback` resolves the verifier by the returned state from `txStorage`
  (then `storage` as a transition fallback), decoding the stamp — its presence
  structurally proves we issued that state (CSRF), and a MISSING saved state on
  the legacy path is itself a rejection (never a soft-skip). Redirect-survival +
  concurrent isolation + orphan-sweep all locked by `browser.test.ts`.
- `validateToken` (from main) honors explicit `config.jwksUri` + `config.issuer`
  overrides (in-cluster / split-horizon: pod can't reach the public IAM origin),
  bypassing discovery; otherwise `resolveJwksUri` degrades to the canonical
  `/v1/iam/.well-known/jwks` on any discovery failure. Both preserved.
- `src/betterauth.ts` — `iamProvider(config)` returns a real `genericOAuth`
  config entry: `{ providerId:"hanzo", authorizationUrl, tokenUrl,
  userInfoUrl, clientId, clientSecret, scopes, pkce:true,
  authentication:"basic" }`. Usage:
  `genericOAuth({ config: [iamProvider({...})] })`. No `discoveryUrl`.

## Build / test

- Node 26 + pnpm 9; the package needs Node ≥ 22.12, the first release that
  `require()`s an ES module unflagged (jose 6 is ESM only, and the CJS build
  requires it). `pnpm install` runs `prepare`, which is `pnpm build`.
- `pnpm build` = `rm -rf dist && tsup && pnpm declarations`, each step
  chained with `&&`, so a failed or killed `tsc` fails the build.
  `pnpm dev` runs `tsup --watch`, which cleans nothing, and reruns
  `pnpm declarations` after every rebuild, so types never drop out.
- CI: `.hanzo/workflows/ci.yml` (install with a frozen lockfile, build,
  typecheck, test on Node 22/24/26; `go vet` + `go test` in `go/`).
- Tests: `pnpm test` → `node --test --import tsx 'src/**/*.test.ts'`.
  `tsx` is a devDependency (native Node TS strips types but does NOT
  rewrite `./x.js` → `./x.ts`, so the test runner needs tsx).
- `pnpm typecheck` (`tsc --noEmit` on typescript 7, the native compiler)
  must stay green (`tsconfig.json` sets `jsx: react-jsx` so the `.tsx`
  typechecks when imported from a test).
- The tests cover: locked paths + brand map, `validateToken` matrix (happy /
  expired / bad-aud-fails / missing-aud-fails / allowMissingAudience /
  tampered), PKCE ≥256-bit entropy, exact `iamProvider` shape, nextauth
  explicit-endpoints + `hanzo-iam` id + `client_secret_basic`, the four new
  adapters (sveltekit/remix/express/hono) endpoint pinning + guard 401s,
  passport `/v1/iam` URLs, server header extraction, views-are-real, and
  the shipped build (`src/dist.test.ts`, after `pnpm build`): every file
  package.json names is built and in the `pnpm pack` list with its
  declarations, no test file is packed, every exports entry loads as ESM
  and as CJS, a `.cts` and a `.mts` consumer typecheck against every
  subpath on `module: node16`, and the shipped nextauth provider has no
  `wellKnown`.

## Repo

- **Retired mirror.** `@hanzo/iam` is built and published from
  `hanzo-js/iam`, which holds the npm line (0.21.x). package.json here is
  `"private": true`, so npm and pnpm refuse to publish it; never tag a
  release here either (`v0.13.8` exists as a tag and on npm already).
- Remote: `hanzoai/iam-sdk`. main is kept building and tested; a change
  that should reach npm goes to `hanzo-js/iam`.
- `go/` is a separate Go module (tenant helper); unrelated to the JS SDK.
