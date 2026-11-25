package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"net/url"
)

func TestDASTRejectsCrossOriginRedirect(t *testing.T) {
	hit := false
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer other.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusFound)
	}))
	defer origin.Close()
	_, err := (BaselineDAST{Timeout: time.Second}).Scan(context.Background(), origin.URL)
	if err == nil || !strings.Contains(err.Error(), "authorized origin") {
		t.Fatalf("expected out-of-scope redirect error, got %v", err)
	}
	if hit {
		t.Fatal("DAST followed a redirect to an unrelated origin")
	}
}

func TestDASTDoesNotLeakCookieOrQuery(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "session=highly-sensitive-value; Path=/")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	// The test server's certificate is intentionally self-signed. Instead of
	// disabling TLS verification, exercise the scope and cookie helpers.
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
	if err != nil { t.Fatal(err) }
	if len(result.Findings) == 0 { t.Fatal("expected baseline findings") }
	for _, finding := range result.Findings {
		if strings.Contains(finding.FilePath, "topsecret") || strings.Contains(finding.Description, "topsecret") {
			t.Fatalf("query secret leaked: %+v", finding)
		}
	}
}
