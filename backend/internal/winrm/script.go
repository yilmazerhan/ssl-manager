package winrm

import (
	"encoding/base64"
	"fmt"
)

// pfxPassword protects the PFX only for the few seconds it's in transit
// inside the PowerShell script and on the target's temp disk before this
// same script deletes it — it never needs to be memorable or reused, so a
// fixed value is fine here, unlike every credential this platform stores
// long-term in Vault.
const pfxPassword = "ssl-sentry-transient"

// buildScript returns the PowerShell script RunPowerShell hands to the
// target host: import the PFX into the local machine's certificate store,
// then run whatever additional binding serviceType needs.
func buildScript(serviceType ServiceType, pfx []byte) (string, error) {
	bind, err := bindCommands(serviceType)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf(`
$ErrorActionPreference = 'Stop'
$pfxBytes = [Convert]::FromBase64String('%s')
$pfxPath = [System.IO.Path]::GetTempFileName()
[IO.File]::WriteAllBytes($pfxPath, $pfxBytes)
try {
    $securePassword = ConvertTo-SecureString -String '%s' -Force -AsPlainText
    $cert = Import-PfxCertificate -FilePath $pfxPath -CertStoreLocation Cert:\LocalMachine\My -Password $securePassword
    $thumbprint = $cert.Thumbprint
} finally {
    Remove-Item -Path $pfxPath -Force -ErrorAction SilentlyContinue
}
%s
Write-Output "SSL-SENTRY-BOUND:$thumbprint"
`, base64.StdEncoding.EncodeToString(pfx), pfxPassword, bind), nil
}

// bindCommands is the service-specific half of the script, run after the
// certificate is already sitting in Cert:\LocalMachine\My with $thumbprint
// set to its thumbprint.
func bindCommands(serviceType ServiceType) (string, error) {
	switch serviceType {
	case ServiceWinRMHTTPS:
		// A WinRM HTTPS listener's certificate can't be changed in place —
		// the documented approach is to remove the existing HTTPS
		// listener(s) and create a new one pointed at the new thumbprint.
		return `
Get-ChildItem WSMan:\localhost\Listener | Where-Object { $_.Keys -like 'Transport=HTTPS' } | Remove-Item -Recurse -Force
New-Item -Path WSMan:\localhost\Listener -Transport HTTPS -Address * -CertificateThumbPrint $thumbprint -Force | Out-Null
`, nil
	case ServiceLDAPS:
		// Active Directory Domain Services selects a Server-Authentication
		// certificate from the local machine store for LDAPS on its own —
		// importing it above is the whole job; there's no separate bind
		// step the way WinRM's listener needs one.
		return "", nil
	default:
		return "", fmt.Errorf("winrm: unknown service_type %q", serviceType)
	}
}
