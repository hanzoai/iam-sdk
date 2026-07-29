# iam-sdk — AI Assistant Context

This repo is **one Go module** and nothing else:
`github.com/hanzoai/iam-sdk/go`, whose only package is `go/tenant`.

## What lives here

`tenant` resolves the caller's tenant identity from an HTTP request inside the
mesh. The IAM gateway validates the JWT and injects `X-Org-Id` / `X-User-Id` /
`X-User-Email`, stripping any client-supplied copies before forwarding — that
strip is why the headers can be trusted here. Surface:

| symbol | role |
|---|---|
| `Identity` | `{Org, UserID, Email}` — the authenticated caller |
| `Verifier` | `Verify(*http.Request) (Identity, error)`; the test seam |
| `HeaderVerifier` | production wiring; reads the three `X-*` headers |
| `ErrUnauthenticated` | returned when no identity is present |
| `Require(v, next)` | middleware: verify → stash on ctx → next; 401 on failure |
| `WithIdentity` / `FromContext` | the ctx pair |

`HeaderVerifier.Verify` requires **both** `Org` and `UserID` to be non-empty.
Email is optional. Do not relax that: it is the only check standing between a
header-less request and a handler that assumes a tenant.

## What does NOT live here — read this before "restoring" anything

`@hanzo/iam`, the TypeScript SDK, is published from
**hanzo-js/iam** and only from there. This repo published that npm name through
0.13.8, in parallel with hanzo-js/iam, which is the duplication that was
collapsed: two repos, one npm name, interleaved releases, and because 0.21.x >
0.13.x any `^0.13` consumer that widened its range silently changed source repo.

The TypeScript source, `package.json`, `tsup.config.ts`, `tsconfig.json`,
`pnpm-lock.yaml` and the publish workflow were **deleted**, not disabled. If you
are looking for them, they are at hanzo-js/iam — where `src/identity.ts`
(`resolveIdentity` / `membershipsFromToken` / `claimsOf` / `looksLikeId`) also
lives; that module never existed here. Do not re-add a package manifest to this
repo.

The Go module keeps the `iam-sdk` name because for Go the repo name *is* the
import path — renaming the repo renames the module. Consumers: `hanzo/agents/
control-plane` (via a local `replace`).

## Gate

`cd go && go build ./... && go vet ./... && go test ./...` — same as CI.
