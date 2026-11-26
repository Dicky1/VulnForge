package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/example/sast-dast-analyzer/internal/models"
	"github.com/example/sast-dast-analyzer/internal/oob"
)

func activeTestOptions() DASTRunOptions {
	return DASTRunOptions{Interval: 0, MaxRequests: 500}
}

func findingWithTitle(findings []models.Finding, want string) (models.Finding, bool) {
	for _, f := range findings {
		if strings.Contains(f.Title, want) {
			return f, true
		}
	}
	return models.Finding{}, false
}

// TestActiveDASTRequiresQueryParams checks that a URL with no query string
// is rejected rather than silently scanning nothing or inventing params.
func TestActiveDASTRequiresQueryParams(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	base := srv.Client().Transport.(*http.Transport)
	_, _, err := (ActiveDAST{Timeout: time.Second}).scanURLWithTransport(context.Background(), srv.URL, activeTestOptions(), base)
	if err == nil || err != errActiveDASTNoParams {
		t.Fatalf("expected errActiveDASTNoParams, got %v", err)
	}
}

// TestActiveDASTDetectsReflectedXSS confirms a handler that echoes a query
// parameter unescaped is flagged, and one that doesn't reflect it is not.
func TestActiveDASTDetectsReflectedXSS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html>Hello " + r.URL.Query().Get("name") + "</html>"))
	}))
	defer srv.Close()
	base := srv.Client().Transport.(*http.Transport)
	findings, outputs, err := (ActiveDAST{Timeout: 5 * time.Second}).scanURLWithTransport(
		context.Background(), srv.URL+"/?name=world", activeTestOptions(), base)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(outputs) == 0 {
		t.Fatal("expected at least one tool output")
	}
	f, ok := findingWithTitle(findings, "Reflected Cross-Site Scripting")
	if !ok {
		t.Fatalf("expected reflected XSS finding, got findings: %+v", findings)
	}
	if f.DASTEvidence == nil || f.DASTEvidence.Request == nil || f.DASTEvidence.Response == nil {
		t.Fatal("expected request/response evidence to be attached")
	}
	if f.DASTEvidence.PayloadClass == "" || f.DASTEvidence.InjectionPoint != "query:name" {
		t.Fatalf("expected payload class and injection point set, got %+v", f.DASTEvidence)
	}
	if f.DASTEvidence.CurlCommand == "" || !strings.HasPrefix(f.DASTEvidence.CurlCommand, "curl ") {
		t.Fatalf("expected a reproducible curl command, got %q", f.DASTEvidence.CurlCommand)
	}
}

func TestActiveDASTNoFalsePositiveWhenNotReflected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html>static page, no reflection</html>"))
	}))
	defer srv.Close()
	base := srv.Client().Transport.(*http.Transport)
	findings, _, err := (ActiveDAST{Timeout: 5 * time.Second}).scanURLWithTransport(
		context.Background(), srv.URL+"/?q=anything", activeTestOptions(), base)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := findingWithTitle(findings, "Cross-Site Scripting"); ok {
		t.Fatal("false positive XSS finding on a page that never reflects input")
	}
}

// TestActiveDASTDetectsSQLiErrorBased checks a handler that leaks a DB error
// signature only when it receives a raw single quote.
func TestActiveDASTDetectsSQLiErrorBased(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("id"), "'") {
			w.Write([]byte("Error: You have an error in your SQL syntax near '''"))
			return
		}
		w.Write([]byte("ok"))
	}))
	defer srv.Close()
	base := srv.Client().Transport.(*http.Transport)
	findings, _, err := (ActiveDAST{Timeout: 5 * time.Second}).scanURLWithTransport(
		context.Background(), srv.URL+"/?id=1", activeTestOptions(), base)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := findingWithTitle(findings, "SQL Injection (error-based)"); !ok {
		t.Fatalf("expected SQLi error-based finding, got %+v", findings)
	}
}

// TestActiveDASTDetectsOpenRedirect checks that a Location header pointing
// off-host, triggered by the open-redirect probe, is flagged — and that
// ScanURL never actually follows the cross-host redirect.
func TestActiveDASTDetectsOpenRedirect(t *testing.T) {
	var followed bool
	external := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { followed = true }))
	defer external.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next := r.URL.Query().Get("next")
		if strings.Contains(next, "://") || strings.HasPrefix(next, "//") {
			http.Redirect(w, r, next, http.StatusFound)
			return
		}
		w.Write([]byte("ok"))
	}))
	defer srv.Close()
	base := srv.Client().Transport.(*http.Transport)
	findings, _, err := (ActiveDAST{Timeout: 5 * time.Second}).scanURLWithTransport(
		context.Background(), srv.URL+"/?next=/home", activeTestOptions(), base)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := findingWithTitle(findings, "Open Redirect"); !ok {
		t.Fatalf("expected open redirect finding, got %+v", findings)
	}
	if followed {
		t.Fatal("active DAST must never follow a cross-host redirect")
	}
}

// TestActiveDASTDetectsPathTraversal checks that a handler which leaks
// /etc/passwd-style content only for a traversal payload is flagged.
func TestActiveDASTDetectsPathTraversal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("file"), "..") {
			w.Write([]byte("root:x:0:0:root:/root:/bin/bash\n"))
			return
		}
		w.Write([]byte("report.txt"))
	}))
	defer srv.Close()
	base := srv.Client().Transport.(*http.Transport)
	findings, _, err := (ActiveDAST{Timeout: 5 * time.Second}).scanURLWithTransport(
		context.Background(), srv.URL+"/?file=report.txt", activeTestOptions(), base)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := findingWithTitle(findings, "Path Traversal"); !ok {
		t.Fatalf("expected path traversal finding, got %+v", findings)
	}
}

// TestActiveDASTDetectsBooleanSQLi checks the always-true/always-false pair
// comparison: a handler that returns the full listing for a true condition
// and an empty result for a false one.
func TestActiveDASTDetectsBooleanSQLi(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("id")
		switch {
		case strings.Contains(v, "OR '1'='1"):
			w.Write([]byte(strings.Repeat("row ", 200)))
		case strings.Contains(v, "AND '1'='2"):
			w.Write([]byte(""))
		default:
			w.Write([]byte(strings.Repeat("row ", 200)))
		}
	}))
	defer srv.Close()
	base := srv.Client().Transport.(*http.Transport)
	findings, _, err := (ActiveDAST{Timeout: 5 * time.Second}).scanURLWithTransport(
		context.Background(), srv.URL+"/?id=1", activeTestOptions(), base)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := findingWithTitle(findings, "boolean-based"); !ok {
		t.Fatalf("expected boolean-based SQLi finding, got %+v", findings)
	}
}

// TestActiveDASTOOBConfirmation wires a real oob.Store and oob.HTTPListener
// into ActiveDAST. The fake "vulnerable" target server simulates performing
// a server-side fetch of the attacker-controlled SSRF-OOB URL: in a real
// deployment, wildcard DNS for the configured OOB host would resolve
// "<token>.<oobHost>" to the listener's IP, so here the test server instead
// connects to the listener's real test address directly but sets the Host
// header to the token-bearing name exactly as a real resolved request
// would arrive — oob.HTTPListener correlates purely on that Host label.
func TestActiveDASTOOBConfirmation(t *testing.T) {
	store := oob.NewStore()
	listener := httptest.NewServer(oob.HTTPListener{Store: store})
	defer listener.Close()
	const oobCallbackHost = "oob.test.invalid"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("url")
		if idx := strings.Index(target, "://"); idx >= 0 && strings.Contains(target, oobCallbackHost) {
			rest := strings.TrimSuffix(target[idx+3:], "/")
			if dot := strings.Index(rest, "."); dot >= 0 {
				token := rest[:dot]
				cbReq, _ := http.NewRequest(http.MethodGet, listener.URL, nil)
				cbReq.Host = token + "." + oobCallbackHost
				http.DefaultClient.Do(cbReq) //nolint:errcheck // best-effort simulated OOB callback
			}
		}
		w.Write([]byte("ok"))
	}))
	defer srv.Close()
	base := srv.Client().Transport.(*http.Transport)
	findings, _, err := (ActiveDAST{
		Timeout:         5 * time.Second,
		OOBStore:        store,
		OOBCallbackHost: oobCallbackHost,
		OOBWait:         2 * time.Second,
	}).scanURLWithTransport(context.Background(), srv.URL+"/?url=https://example.com", activeTestOptions(), base)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := findingWithTitle(findings, "Server-Side Request Forgery"); !ok {
		t.Fatalf("expected OOB-confirmed SSRF finding, got %+v", findings)
	}
}

// TestActiveDASTRespectsRequestBudget checks that exhausting MaxRequests
// stops the scan early rather than erroring out or ignoring the budget.
func TestActiveDASTRespectsRequestBudget(t *testing.T) {
	var requests int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Write([]byte("ok"))
	}))
	defer srv.Close()
	base := srv.Client().Transport.(*http.Transport)
	_, outputs, err := (ActiveDAST{Timeout: 5 * time.Second}).scanURLWithTransport(
		context.Background(), srv.URL+"/?a=1&b=2", DASTRunOptions{MaxRequests: 3}, base)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if requests > 3 {
		t.Fatalf("expected at most 3 requests sent, server saw %d", requests)
	}
	if len(outputs) == 0 {
		t.Fatal("expected partial outputs to be returned, not none")
	}
}

// TestActiveDASTRejectsCrossOriginRedirectWithoutFollowing confirms the
// active client never auto-follows even a same-looking redirect: it must
// inspect the raw 3xx response itself for the open-redirect check.
func TestActiveDASTRejectsCrossOriginRedirectWithoutFollowing(t *testing.T) {
	var otherHit bool
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { otherHit = true }))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusFound)
	}))
	defer srv.Close()
	base := srv.Client().Transport.(*http.Transport)
	_, _, err := (ActiveDAST{Timeout: 5 * time.Second}).scanURLWithTransport(
		context.Background(), srv.URL+"/?x=1", activeTestOptions(), base)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if otherHit {
		t.Fatal("active DAST must never follow a redirect to another host")
	}
}

func TestActiveDASTTooManyParamsRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	base := srv.Client().Transport.(*http.Transport)
	var qs strings.Builder
	for i := 0; i < MaxActiveDASTParams+1; i++ {
		if i > 0 {
			qs.WriteByte('&')
		}
		fmt.Fprintf(&qs, "p%d=1", i)
	}
	_, _, err := (ActiveDAST{Timeout: time.Second}).scanURLWithTransport(
		context.Background(), srv.URL+"/?"+qs.String(), activeTestOptions(), base)
	if err == nil {
		t.Fatal("expected an error for too many query parameters")
	}
}
