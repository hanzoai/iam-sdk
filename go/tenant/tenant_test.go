// Copyright 2026 Hanzo AI.
// Licensed under the Apache License, Version 2.0.

package tenant

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHeaderVerifierOK(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Org-Id", "acme")
	r.Header.Set("X-User-Id", "u-1")
	r.Header.Set("X-User-Email", "user@acme.test")

	id, err := HeaderVerifier{}.Verify(r)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if id.Org != "acme" || id.UserID != "u-1" || id.Email != "user@acme.test" {
		t.Fatalf("bad identity: %+v", id)
	}
}

func TestHeaderVerifierMissing(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if _, err := (HeaderVerifier{}).Verify(r); err != ErrUnauthenticated {
		t.Fatalf("want ErrUnauthenticated, got %v", err)
	}
}

func TestRequireMiddleware(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		id, ok := FromContext(r.Context())
		if !ok || id.Org != "acme" {
			t.Fatalf("missing identity in ctx: %+v", id)
		}
		w.WriteHeader(http.StatusOK)
	})
	h := Require(HeaderVerifier{}, next)

	// Authed
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Org-Id", "acme")
	r.Header.Set("X-User-Id", "u-1")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK || !called {
		t.Fatalf("authed call failed: code=%d called=%v", w.Code, called)
	}

	// Unauthed
	called = false
	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, r2)
	if w2.Code != http.StatusUnauthorized || called {
		t.Fatalf("unauthed should 401: code=%d called=%v", w2.Code, called)
	}
}
