// Package winrm connects directly to a Windows host over WinRM (using
// stored admin credentials) and runs a PowerShell script that imports a
// certificate into the machine's certificate store and, for services that
// need it, rebinds them to it — see script.go for exactly what each
// ServiceType's script does.
//
// This deliberately doesn't go through an agent: it's the platform itself
// reaching out with credentials it already holds, the same trust model as
// every CA integration in internal/ca. The tradeoff is real and explicit —
// this requires network line-of-sight to the target's WinRM port and a
// stored credential per host, in exchange for not having to build and
// deploy a separate agent (the alternative considered for this and for
// internal/k8s's Kubernetes sync).
package winrm

import (
	"context"
	"fmt"
	"time"

	winrmlib "github.com/masterzen/winrm"
)

// dialTimeout bounds how long connecting to a target's WinRM endpoint can
// take — a host that's unreachable (firewalled, powered off, wrong
// address) should fail a sync quickly, not hang the background sync loop.
const dialTimeout = 30 * time.Second

// Client runs PowerShell scripts on a single remote Windows host over
// WinRM, authenticating with a plain username/password (NTLM/Negotiate,
// whatever the underlying library negotiates — no Kerberos ticket
// management, which would need this process to be domain-joined itself).
type Client struct {
	Host               string
	Port               int
	Username           string
	Password           string
	UseHTTPS           bool
	InsecureSkipVerify bool
}

// RunPowerShell runs script on the target host and returns its stdout.
// A non-zero exit code is treated as an error — every script this package
// generates (see script.go) is expected to succeed completely or not at
// all, there's no partial-success case worth distinguishing.
func (c *Client) RunPowerShell(ctx context.Context, script string) (string, error) {
	endpoint := winrmlib.NewEndpoint(c.Host, c.Port, c.UseHTTPS, c.InsecureSkipVerify, nil, nil, nil, dialTimeout)
	client, err := winrmlib.NewClient(endpoint, c.Username, c.Password)
	if err != nil {
		return "", fmt.Errorf("winrm: connect to %s:%d: %w", c.Host, c.Port, err)
	}

	stdout, stderr, exitCode, err := client.RunPSWithContext(ctx, script)
	if err != nil {
		return stdout, fmt.Errorf("winrm: run script on %s:%d: %w", c.Host, c.Port, err)
	}
	if exitCode != 0 {
		return stdout, fmt.Errorf("winrm: script on %s:%d exited %d: %s", c.Host, c.Port, exitCode, stderr)
	}
	return stdout, nil
}
