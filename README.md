# iam-sdk

Go module **`github.com/hanzoai/iam-sdk/go`** — server-side tenant resolution
for services sitting behind Hanzo IAM.

```go
import "github.com/hanzoai/iam-sdk/go/tenant"

mux.Handle("/v1/things", tenant.Require(tenant.HeaderVerifier{}, things))

func things(w http.ResponseWriter, r *http.Request) {
    id, ok := tenant.FromContext(r.Context())  // id.Org, id.UserID, id.Email
    ...
}
```

One verb (`Require`), one noun (`Identity`), one interface (`Verifier`). The
gateway validates the JWT and injects `X-Org-Id` / `X-User-Id` / `X-User-Email`,
stripping any client-supplied copies first, so inside the mesh those headers are
authoritative. `HeaderVerifier` is the production wiring; the `Verifier`
interface lets a test swap a fake without standing up a real IAM.

## The JS SDK is not here

`@hanzo/iam` — the TypeScript/browser SDK — is published from
**[hanzo-js/iam](https://github.com/hanzo-js/iam)**, the JS-SDK org home, and
only from there. This repo published that name through 0.13.8; 0.14.0 onward
comes from hanzo-js/iam. The TypeScript source, its package manifest and its
publish workflow have been removed rather than left disabled, so there is one
source for the name and nothing here to drift or be re-enabled by accident.

The Go module keeps this repo's name because that name *is* its import path.
