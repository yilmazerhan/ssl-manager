// Package caconfig persists the editable, non-secret half of every CA/DNS
// integration's configuration — the half that used to be environment
// variables read once at process startup. The secret half (ZeroSSL's API
// key, AD CS's password, a DNS provider's API token) stays in Vault via
// internal/secrets, the same place every other operational secret in this
// app lives; see internal/api's integration handlers for how the two are
// combined into a live ca.Authority.
package caconfig

// LetsEncryptSettings mirrors ca.LetsEncryptConfig's non-secret fields.
// InsecureSkipVerify deliberately has no editable-settings counterpart —
// it stays an environment-only escape hatch for talking to a local test
// ACME server, not something exposed in a web UI.
type LetsEncryptSettings struct {
	Environment  string `json:"environment"`
	DirectoryURL string `json:"directory_url"`
	ContactEmail string `json:"contact_email"`
}

// ZeroSSLSettings mirrors ca.ZeroSSLConfig minus APIKey, which lives in
// Vault at secretPathZeroSSL.
type ZeroSSLSettings struct {
	BaseURL string `json:"base_url"`
}

// ADCSSettings mirrors ca.ADCSConfig minus Password (Vault, see
// secretPathADCS) and InsecureSkipVerify (environment-only, same
// reasoning as Let's Encrypt's).
type ADCSSettings struct {
	BaseURL        string `json:"base_url"`
	Template       string `json:"template"`
	Username       string `json:"username"`
	AllowBasicAuth bool   `json:"allow_basic_auth"`
}

// DNS01Settings names which DNS provider automates DNS-01 challenges (see
// ca.NewDNSAutomationWithToken). Provider "" means no automation — DNS-01
// falls back to manual instructions, same as HTTP-01. The provider's API
// token lives in Vault at secretPathDNS01.
type DNS01Settings struct {
	Provider string `json:"provider"`
}

// SelfSignedSettings has no secrets at all — self-signed certificates
// sign with the same Vault-backed key their own CSR carries the public
// half of, so there's no external account or credential to configure.
type SelfSignedSettings struct {
	ValidityDays int `json:"validity_days"`
}

// Vault KV paths for the secret half of each provider's settings — kept
// here, next to the non-secret settings they pair with, so the two halves
// of one provider's configuration aren't scattered across packages.
const (
	SecretPathZeroSSL = "ca/zerossl"
	SecretPathADCS    = "ca/adcs"
	SecretPathDNS01   = "ca/dns01"
)
