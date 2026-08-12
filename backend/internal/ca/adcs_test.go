package ca

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// mockCertsrvServer reproduces certsrv's documented certfnsh.asp/certnew.cer
// request/response shapes closely enough to prove our client builds correct
// requests and parses responses correctly. It requires no authentication,
// so it does not exercise go-ntlmssp's NTLM handshake (that's its own,
// separately-tested responsibility) — see adcs.go's doc comment.
func mockCertsrvServer(t *testing.T, template string, disposition func(reqID string) (issued bool, denied bool)) *httptest.Server {
	t.Helper()
	const requestID = "77"

	mux := http.NewServeMux()
	mux.HandleFunc("/certfnsh.asp", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}
		if r.FormValue("Mode") != "newreq" {
			t.Errorf("expected Mode=newreq, got %q", r.FormValue("Mode"))
		}
		if r.FormValue("CertRequest") == "" {
			t.Errorf("expected a CertRequest value")
		}
		wantAttrib := adcsCertAttrib(template)
		if got := r.FormValue("CertAttrib"); got != wantAttrib {
			t.Errorf("expected CertAttrib=%q, got %q", wantAttrib, got)
		}

		issued, denied := disposition(requestID)
		body := fmt.Sprintf("Certificate Pending<br>Your Request Id is %s.", requestID)
		if denied {
			body = fmt.Sprintf("Your Request Id is %s.<br>Denied by Policy Module", requestID)
		} else if issued {
			body = fmt.Sprintf(`Your Request Id is %s.<br><a href="certnew.cer?ReqID=%s&Enc=b64">issued certificate</a>`, requestID, requestID)
		}
		fmt.Fprint(w, body)
	})

	mux.HandleFunc("/certnew.cer", func(w http.ResponseWriter, r *http.Request) {
		reqID := r.URL.Query().Get("ReqID")
		issued, denied := disposition(reqID)
		switch {
		case denied:
			fmt.Fprint(w, "Denied by Policy Module")
		case issued:
			fmt.Fprint(w, testLeafCertPEM)
		default:
			fmt.Fprint(w, "Certificate Pending<br>Taken Under Submission")
		}
	})

	return httptest.NewServer(mux)
}

func TestADCS_FullFlow_ImmediateIssue(t *testing.T) {
	server := mockCertsrvServer(t, "WebServer", func(string) (bool, bool) { return true, false })
	defer server.Close()

	a := NewADCS(ADCSConfig{BaseURL: server.URL, Template: "WebServer"})
	ctx := context.Background()

	po, err := a.RequestValidation(ctx, []string{"app.corp.test"}, "adcs-enroll", "-----BEGIN CERTIFICATE REQUEST-----\nfake\n-----END CERTIFICATE REQUEST-----\n")
	if err != nil {
		t.Fatalf("RequestValidation: %v", err)
	}
	if len(po.Challenges) != 1 || po.Challenges[0].Error != "" {
		t.Fatalf("unexpected challenges: %+v", po.Challenges)
	}
	if !strings.Contains(po.Challenges[0].ResourceName, "77") {
		t.Errorf("expected the resource name to mention the request id, got %q", po.Challenges[0].ResourceName)
	}
	if !po.Challenges[0].Automated {
		t.Errorf("expected an AD CS challenge to be marked automated — there is nothing for a human to publish")
	}

	po, err = a.CheckChallenge(ctx, po)
	if err != nil {
		t.Fatalf("CheckChallenge: %v", err)
	}
	if !po.AllVerified() {
		t.Fatalf("expected an immediately-issued request to verify on the first check")
	}

	issued, err := a.Issue(ctx, po, "", nil, nil)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if issued.SerialNumber == "" {
		t.Errorf("expected a serial number")
	}
	if issued.CAReference != "77" {
		t.Errorf("expected CAReference to be the AD CS request id, got %q", issued.CAReference)
	}
}

func TestADCS_FullFlow_PendingThenApproved(t *testing.T) {
	approved := false
	server := mockCertsrvServer(t, "", func(string) (bool, bool) { return approved, false })
	defer server.Close()

	a := NewADCS(ADCSConfig{BaseURL: server.URL})
	ctx := context.Background()

	po, err := a.RequestValidation(ctx, []string{"pending.corp.test"}, "adcs-enroll", "-----BEGIN CERTIFICATE REQUEST-----\nfake\n-----END CERTIFICATE REQUEST-----\n")
	if err != nil {
		t.Fatalf("RequestValidation: %v", err)
	}

	po, err = a.CheckChallenge(ctx, po)
	if err != nil {
		t.Fatalf("CheckChallenge (pending): %v", err)
	}
	if po.AllVerified() {
		t.Fatalf("expected a pending request not to verify yet")
	}
	if po.Challenges[0].Error != "" {
		t.Fatalf("a pending request is not a failure, got error %q", po.Challenges[0].Error)
	}

	approved = true // simulate a CA administrator approving it out of band
	po, err = a.CheckChallenge(ctx, po)
	if err != nil {
		t.Fatalf("CheckChallenge (approved): %v", err)
	}
	if !po.AllVerified() {
		t.Fatalf("expected the request to verify once approved")
	}
}

func TestADCS_RequestDenied(t *testing.T) {
	server := mockCertsrvServer(t, "", func(string) (bool, bool) { return false, true })
	defer server.Close()

	a := NewADCS(ADCSConfig{BaseURL: server.URL})
	ctx := context.Background()

	po, err := a.RequestValidation(ctx, []string{"denied.corp.test"}, "adcs-enroll", "-----BEGIN CERTIFICATE REQUEST-----\nfake\n-----END CERTIFICATE REQUEST-----\n")
	if err != nil {
		t.Fatalf("RequestValidation: %v", err)
	}
	if po.Challenges[0].Error == "" {
		t.Fatalf("expected a denied request to carry an error on its challenge")
	}

	_, err = a.Issue(ctx, po, "", nil, nil)
	if err == nil {
		t.Fatal("expected Issue to fail for a denied request")
	}
}

func TestADCS_Revoke_AlwaysFails(t *testing.T) {
	a := NewADCS(ADCSConfig{BaseURL: "http://unused.invalid"})
	if err := a.Revoke(context.Background(), "irrelevant", "77"); err == nil {
		t.Fatal("expected Revoke to fail — certsrv's web enrollment interface has no revoke endpoint")
	}
}
