package scanner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestDASTRejectsCrossOriginRedirect(t *testing.T) {
	var hit atomic.Bool
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit.Store(true) }))
	defer other.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusFound)
	}))
	defer origin.Close()
	_, err := (BaselineDAST{Timeout: time.Second}).Scan(context.Background(), origin.URL)
	if err == nil || !strings.Contains(err.Error(), "redirect was rejected") {
		t.Fatalf("expected out-of-scope redirect error, got %v", err)
	}
	if hit.Load() {
		t.Fatal("DAST followed a redirect to an unrelated origin")
	}
}

func TestDASTDoesNotLeakCookieOrQuery(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "session=highly-sensitive-value; Path=/")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	// Use the local test certificate as a trust anchor, never skip verification.
	base := srv.Client().Transport.(*http.Transport)
	out, err := (BaselineDAST{Timeout: time.Second}).scanWithTransport(context.Background(), srv.URL+"/?token=supersecret", base)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"highly-sensitive-value", "supersecret"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("secret leaked into report")
		}
	}
	for _, want := range []string{"Cookie lacks security attributes", "Cookie has no SameSite attribute", "Missing Strict-Transport-Security"} {
		if !strings.Contains(string(encoded), want) {
			t.Errorf("missing finding %q", want)
		}
	}
	if strings.Contains(string(encoded), "HTTPS not enforced") {
		t.Fatal("false HTTPS finding")
	}
	if _, err := (BaselineDAST{Timeout: time.Second}).Scan(context.Background(), srv.URL); err == nil {
		t.Fatal("untrusted certificate accepted")
	}
	origin, _ := url.Parse("https://example.com/?token=supersecret")
	next, _ := url.Parse("https://example.com/redirect")
	if !sameDASTScope(origin, next) {
		t.Fatal("same-origin redirect should be allowed")
	}
	if sameDASTScope(origin, &url.URL{Scheme: "http", Host: "example.com"}) {
		t.Fatal("HTTPS downgrade must be forbidden")
	}
	if sameDASTScope(origin, &url.URL{Scheme: "https", Host: "example.com:8443"}) {
		t.Fatal("port changes must be forbidden")
	}
}

func TestDASTRejectsCredentials(t *testing.T) {
	_, err := (BaselineDAST{}).Scan(context.Background(), "https://user:password@example.com/")
	if err == nil {
		t.Fatal("embedded URL credentials must be rejected")
	}
}

func TestDASTFindingsDoNotContainQuery(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer srv.Close()
	result, err := (BaselineDAST{Timeout: time.Second}).Scan(context.Background(), srv.URL+"/?token=topsecret")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) == 0 {
		t.Fatal("expected baseline findings")
	}
	for _, finding := range result.Findings {
		if strings.Contains(finding.FilePath, "topsecret") || strings.Contains(finding.Description, "topsecret") {
			t.Fatalf("query secret leaked: %+v", finding)
		}
	}
}
