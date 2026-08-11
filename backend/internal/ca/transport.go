package ca

import (
	"crypto/tls"
	"net/http"
)

// insecureTransport is used only when LetsEncryptConfig.InsecureSkipVerify
// is explicitly set, to talk to a local Pebble test server whose
// certificate chain isn't otherwise trusted. Never enabled against a real
// certificate authority.
func insecureTransport() http.RoundTripper {
	return &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
}
