package winrm

import (
	"context"
	"testing"
	"time"
)

// TestClient_RunPowerShell_UnreachableHostReturnsError proves the client
// fails cleanly (an error, not a panic or an indefinite hang) against a
// host that refuses the connection outright — the common case for a
// mistyped address or a firewalled port, and the same failure mode
// TestSyncCertificate_RecordsErrorForUnreachableHost exercises through
// the whole Service.
func TestClient_RunPowerShell_UnreachableHostReturnsError(t *testing.T) {
	client := &Client{Host: "127.0.0.1", Port: 1, Username: "admin", Password: "pw", UseHTTPS: true, InsecureSkipVerify: true}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := client.RunPowerShell(ctx, "Write-Output hi"); err == nil {
		t.Fatalf("expected an error connecting to a port nothing listens on")
	}
}
