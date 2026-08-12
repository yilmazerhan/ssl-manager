package ca

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
)

// DNSAutomation publishes and removes the DNS-01 TXT record itself,
// through a real DNS provider, instead of asking a human to do it — this
// is what makes DNS-01 renewal genuinely unattended (docs/plan.html
// section 04/06). Without it, DNS-01 falls back to the same "here are the
// instructions" flow as manual HTTP-01.
type DNSAutomation struct {
	provider challenge.Provider
	// resolver is nil in production (net.DefaultResolver, i.e. the real
	// system resolver) and overridden only by tests, which need
	// propagation checks to query a mock DNS server instead of the real
	// internet.
	resolver *net.Resolver
}

// NewDNSAutomation builds automation for the named provider. An empty name
// returns (nil, nil) — the caller's job is to check for a nil
// *DNSAutomation and fall back to manual instructions, not to treat that
// as an error.
func NewDNSAutomation(providerName string) (*DNSAutomation, error) {
	switch providerName {
	case "":
		return nil, nil
	case "cloudflare":
		p, err := cloudflare.NewDNSProvider()
		if err != nil {
			return nil, fmt.Errorf("dns01: cloudflare: %w", err)
		}
		return &DNSAutomation{provider: p}, nil
	default:
		return nil, fmt.Errorf("dns01: unsupported provider %q", providerName)
	}
}

// Present publishes the TXT record via the provider's API, then blocks
// until this process's own DNS lookups can see it (or the provider's
// propagation timeout elapses). Skipping that wait would mean telling the
// CA "please check" before the record has actually propagated — the CA
// would just see a stale answer and fail the authorization.
func (d *DNSAutomation) Present(domain, token, keyAuth string) error {
	fqdn, value := dns01.GetRecord(domain, keyAuth)
	if err := d.provider.Present(domain, token, keyAuth); err != nil {
		return fmt.Errorf("dns01: publish TXT record for %s: %w", domain, err)
	}
	if err := d.waitForPropagation(fqdn, value); err != nil {
		return fmt.Errorf("dns01: %w", err)
	}
	return nil
}

func (d *DNSAutomation) CleanUp(domain, token, keyAuth string) error {
	if err := d.provider.CleanUp(domain, token, keyAuth); err != nil {
		return fmt.Errorf("dns01: remove TXT record for %s: %w", domain, err)
	}
	return nil
}

func (d *DNSAutomation) waitForPropagation(fqdn, expected string) error {
	timeout, interval := dns01.DefaultPropagationTimeout, dns01.DefaultPollingInterval
	if pt, ok := d.provider.(challenge.ProviderTimeout); ok {
		timeout, interval = pt.Timeout()
	}

	deadline := time.Now().Add(timeout)
	for {
		if d.hasTXTRecord(fqdn, expected) {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("propagation check for %s timed out after %s", fqdn, timeout)
		}
		time.Sleep(interval)
	}
}

func (d *DNSAutomation) hasTXTRecord(fqdn, expected string) bool {
	resolver := d.resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	records, err := resolver.LookupTXT(context.Background(), strings.TrimSuffix(fqdn, "."))
	if err != nil {
		return false
	}
	for _, r := range records {
		if r == expected {
			return true
		}
	}
	return false
}
