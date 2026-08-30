package api

import "testing"

// TestNewRouter_DoesNotPanicOnRouteRegistration guards against
// http.ServeMux's route-registration panic (two overlapping patterns for
// the same method) — the failure mode a hand-added route is most likely to
// introduce, and one go build/go vet can't catch since it only surfaces at
// mux.Handle call time. A zero-value Dependencies is enough: NewRouter only
// wires handlers during construction, it never calls into a dependency.
func TestNewRouter_DoesNotPanicOnRouteRegistration(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("NewRouter panicked, likely a route pattern conflict: %v", r)
		}
	}()
	NewRouter(Dependencies{})
}
