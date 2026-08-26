package ca

import (
	"context"
	"crypto"
	"sync"
	"testing"
)

type nopAuthority struct{ name string }

func (a *nopAuthority) Name() string                         { return a.name }
func (a *nopAuthority) SupportedValidationMethods() []string { return nil }
func (a *nopAuthority) RequestValidation(context.Context, []string, string, string) (ProviderOrder, error) {
	return ProviderOrder{}, nil
}
func (a *nopAuthority) CheckChallenge(context.Context, ProviderOrder) (ProviderOrder, error) {
	return ProviderOrder{}, nil
}
func (a *nopAuthority) Issue(context.Context, ProviderOrder, string, []string, crypto.Signer) (IssuedCertificate, error) {
	return IssuedCertificate{}, nil
}
func (a *nopAuthority) Revoke(context.Context, string, string) error { return nil }

func TestRegistry_GetSetDelete(t *testing.T) {
	r := NewRegistry(&nopAuthority{name: "letsencrypt"})

	if _, ok := r.Get("letsencrypt"); !ok {
		t.Fatalf("expected letsencrypt to be present from NewRegistry")
	}
	if _, ok := r.Get("adcs"); ok {
		t.Fatalf("expected adcs to be absent before Set")
	}

	r.Set("adcs", &nopAuthority{name: "adcs"})
	if a, ok := r.Get("adcs"); !ok || a.Name() != "adcs" {
		t.Fatalf("expected adcs to be present after Set, got %v, %v", a, ok)
	}

	r.Delete("adcs")
	if _, ok := r.Get("adcs"); ok {
		t.Fatalf("expected adcs to be absent after Delete")
	}
}

// TestRegistry_ConcurrentAccess proves Get and Set can run concurrently
// without the "concurrent map read and map write" panic a plain
// map[string]Authority would hit under -race — this matters now that an
// admin editing integration settings (see internal/api's integration
// handlers) calls Set() at the same time in-flight requests call Get().
// Run with -race to actually catch a regression here.
func TestRegistry_ConcurrentAccess(t *testing.T) {
	r := NewRegistry(&nopAuthority{name: "letsencrypt"})

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			r.Set("letsencrypt", &nopAuthority{name: "letsencrypt"})
		}()
		go func() {
			defer wg.Done()
			r.Get("letsencrypt")
			r.Names()
		}()
	}
	wg.Wait()
}
