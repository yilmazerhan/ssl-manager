package winrm

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestBuildScript_WinRMHTTPS_RebindsListener(t *testing.T) {
	script, err := buildScript(ServiceWinRMHTTPS, []byte("fake-pfx-bytes"))
	if err != nil {
		t.Fatalf("buildScript: %v", err)
	}
	for _, want := range []string{
		"Import-PfxCertificate",
		"Cert:\\LocalMachine\\My",
		"WSMan:\\localhost\\Listener",
		"Transport=HTTPS",
		"New-Item",
		"CertificateThumbPrint",
		"SSL-SENTRY-BOUND:",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("expected script to contain %q, got:\n%s", want, script)
		}
	}
	wantB64 := base64.StdEncoding.EncodeToString([]byte("fake-pfx-bytes"))
	if !strings.Contains(script, wantB64) {
		t.Errorf("expected the base64-encoded PFX to appear in the script")
	}
}

func TestBuildScript_LDAPS_OnlyImportsNoBindStep(t *testing.T) {
	script, err := buildScript(ServiceLDAPS, []byte("fake-pfx-bytes"))
	if err != nil {
		t.Fatalf("buildScript: %v", err)
	}
	if !strings.Contains(script, "Import-PfxCertificate") {
		t.Errorf("expected the script to still import the certificate")
	}
	if strings.Contains(script, "WSMan:") {
		t.Errorf("expected no WinRM listener rebind for an LDAPS target, got:\n%s", script)
	}
}

func TestBuildScript_RejectsUnknownServiceType(t *testing.T) {
	if _, err := buildScript(ServiceType("smtp-tls"), []byte("x")); err == nil {
		t.Fatalf("expected an error for an unknown service_type")
	}
}
