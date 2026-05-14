// Copyright 2026 Hanzo AI.
// Licensed under the Apache License, Version 2.0.

// Package tenant resolves the caller's tenant identity from the request
// context. The IAM gateway (api.hanzo.ai) validates the JWT and injects
// identity headers; downstream services trust those headers because the
// gateway strips any client-supplied copies before forwarding.
//
// Hickey lens: one verb (Require), one noun (Identity), one interface
// (Verifier). The interface lets tests swap a fake without standing up
// a real IAM. Production wiring (HeaderVerifier) reads X-* headers per
// the 2026-03-27 convention.
package tenant

import (
	"context"
	"errors"
	"net/http"
)

// Identity is the authenticated caller resolved from the request.
type Identity struct {
	// Org is the org slug from JWT "owner" claim (X-Org-Id header).
	Org string
	// UserID is the user ID from JWT "sub" claim (X-User-Id header).
	UserID string
	// Email is the user email from JWT "email" claim (X-User-Email header).
	Email string
}

// Verifier resolves an Identity from an HTTP request. Implementations
// must return ErrUnauthenticated when no identity is present.
type Verifier interface {
	Verify(r *http.Request) (Identity, error)
}

// ErrUnauthenticated is returned when the request carries no identity.
var ErrUnauthenticated = errors.New("tenant: unauthenticated")

// HeaderVerifier reads identity from X-* headers set by the gateway.
// The gateway is the trust boundary; it strips client-supplied copies
// before forwarding, so the headers are authoritative inside the mesh.
type HeaderVerifier struct{}

// Verify reads X-Org-Id, X-User-Id, X-User-Email and returns Identity.
func (HeaderVerifier) Verify(r *http.Request) (Identity, error) {
	id := Identity{
		Org:    r.Header.Get("X-Org-Id"),
		UserID: r.Header.Get("X-User-Id"),
		Email:  r.Header.Get("X-User-Email"),
	}
	if id.Org == "" || id.UserID == "" {
		return Identity{}, ErrUnauthenticated
	}
	return id, nil
}

type ctxKey struct{}

// WithIdentity stores id on ctx for handlers to retrieve via FromContext.
func WithIdentity(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, ctxKey{}, id)
}

// FromContext returns the Identity placed on ctx by Require.
// The bool is false when no identity is present.
func FromContext(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(ctxKey{}).(Identity)
	return id, ok
}

// Require is a net/http middleware that verifies the request using v,
// stashes the Identity on the request context, and calls next. It
// responds 401 when v returns ErrUnauthenticated.
func Require(v Verifier, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := v.Verify(r)
		if err != nil {
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(WithIdentity(r.Context(), id)))
	})
}
