// Package k8s syncs a certificate's current PEM cert/chain and private key
// to a Kubernetes cluster as a `kubernetes.io/tls` Secret, so a deployment
// can mount it directly instead of a human copying files around by hand.
//
// It talks to the Kubernetes API server over plain REST with a bearer
// token — no client-go dependency, no generated clientset. A TLS Secret is
// one GET (does it exist?) and one POST or PUT away; pulling in client-go
// for that would be a lot of machinery for three HTTP calls.
package k8s

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// Client talks to a single Kubernetes API server.
type Client struct {
	BaseURL            string
	Token              string
	InsecureSkipVerify bool
	HTTPClient         *http.Client
}

// New builds a Client. insecureSkipVerify exists for the same reason it
// does on ca/adcs.go's ADCS client — a private/self-hosted API server
// fronted by a certificate this platform (or its operator) hasn't been
// told to trust yet — and carries the same caveat: only ever set it for a
// cluster the caller actually controls.
func New(baseURL, token string, insecureSkipVerify bool) *Client {
	return &Client{
		BaseURL:            baseURL,
		Token:              token,
		InsecureSkipVerify: insecureSkipVerify,
		HTTPClient: &http.Client{
			Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: insecureSkipVerify}},
		},
	}
}

type secretObject struct {
	APIVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Metadata   secretMetadata    `json:"metadata"`
	Type       string            `json:"type"`
	Data       map[string]string `json:"data"`
}

type secretMetadata struct {
	Name            string `json:"name"`
	Namespace       string `json:"namespace"`
	ResourceVersion string `json:"resourceVersion,omitempty"`
}

// UpsertTLSSecret creates or updates a `kubernetes.io/tls` Secret named
// name in namespace, containing certPEM (chain included, if any) and
// keyPEM. It GETs first to find out whether to POST (create) or PUT
// (update — which requires the existing resourceVersion Kubernetes uses
// for optimistic concurrency).
func (c *Client) UpsertTLSSecret(ctx context.Context, namespace, name string, certPEM, keyPEM []byte) error {
	data := map[string]string{
		"tls.crt": base64.StdEncoding.EncodeToString(certPEM),
		"tls.key": base64.StdEncoding.EncodeToString(keyPEM),
	}
	secret := secretObject{
		APIVersion: "v1",
		Kind:       "Secret",
		Metadata:   secretMetadata{Name: name, Namespace: namespace},
		Type:       "kubernetes.io/tls",
		Data:       data,
	}

	resourceVersion, err := c.currentResourceVersion(ctx, namespace, name)
	if err != nil {
		return err
	}
	if resourceVersion == "" {
		return c.do(ctx, http.MethodPost, fmt.Sprintf("/api/v1/namespaces/%s/secrets", namespace), secret)
	}
	secret.Metadata.ResourceVersion = resourceVersion
	return c.do(ctx, http.MethodPut, fmt.Sprintf("/api/v1/namespaces/%s/secrets/%s", namespace, name), secret)
}

// currentResourceVersion returns "" (not an error) when the Secret doesn't
// exist yet — the normal case for a certificate's very first sync.
func (c *Client) currentResourceVersion(ctx context.Context, namespace, name string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.BaseURL+fmt.Sprintf("/api/v1/namespaces/%s/secrets/%s", namespace, name), nil)
	if err != nil {
		return "", fmt.Errorf("k8s: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("k8s: get secret: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return "", nil
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("k8s: get secret: unexpected status %d: %s", resp.StatusCode, readBody(resp.Body))
	}
	var existing secretObject
	if err := json.NewDecoder(resp.Body).Decode(&existing); err != nil {
		return "", fmt.Errorf("k8s: decode existing secret: %w", err)
	}
	return existing.Metadata.ResourceVersion, nil
}

func (c *Client) do(ctx context.Context, method, path string, body interface{}) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("k8s: marshal request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("k8s: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("k8s: %s secret: %w", method, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("k8s: %s secret: unexpected status %d: %s", method, resp.StatusCode, readBody(resp.Body))
	}
	return nil
}

func readBody(r io.Reader) string {
	b, _ := io.ReadAll(io.LimitReader(r, 4096))
	return string(b)
}
