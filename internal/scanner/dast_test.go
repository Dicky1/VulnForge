package scanner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
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

func TestDASTSessionScopeAndCookieEvidence(t *testing.T) {
	for _, mode := range []string{"bearer", "cookie"} {
		t.Run(mode, func(t *testing.T) {
			var outside atomic.Bool
			foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				outside.Store(true)
			}))
			defer foreign.Close()
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if mode == "bearer" && r.Header.Get("Authorization") != "Bearer existing-session-secret" ||
					mode == "cookie" && r.Header.Get("Cookie") != "session=existing-session-secret" {
					t.Error("session was not sent to authorized origin")
				}
				switch r.URL.Path {
				case "/start":
					http.Redirect(w, r, "/existing-session-secret?token=redirect-secret", http.StatusFound)
				case "/off-origin":
					http.Redirect(w, r, foreign.URL, http.StatusFound)
				default:
					if r.Referer() != "" {
						t.Error("redirect leaked Referer")
					}
					w.Header().Add("Set-Cookie", "first=server-cookie-secret; Secure; SameSite=Lax")
					w.Header().Add("Set-Cookie", "second=server-cookie-secret; HttpOnly; SameSite=Lax")
					w.Header().Add("Set-Cookie", "existing-session-secret=other; HttpOnly; SameSite=Lax")
				}
			}))
			defer srv.Close()
			scope, err := parseDASTURL(srv.URL)
			if err != nil {
				t.Fatal(err)
			}
			session := "existing-session-secret"
			if mode == "cookie" {
				session = "session=" + session
			}
			client, closeTransport, err := (BaselineDAST{Timeout: time.Second}).newClient(srv.Client().Transport.(*http.Transport), scope, DASTRunOptions{
				MaxRequests: 5, SessionKind: mode, Session: session,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer closeTransport()
			start := scope.JoinPath("start")
			out, err := scanDASTEndpoint(context.Background(), client, start, true)
			if err != nil || out.Endpoint.StatusCode != http.StatusOK {
				t.Fatalf("authenticated endpoint failed: %v, %+v", err, out.Endpoint)
			}
			missing := map[string][]string{}
			ids := map[string]bool{}
			for _, finding := range out.Findings {
				evidence := finding.DASTEvidence
				if evidence.CookieName != "" {
					missing[evidence.CookieName] = evidence.MissingAttributes
					ids[finding.ID] = true
				}
			}
			if len(ids) != 3 || !slices.Equal(missing["first"], []string{"HttpOnly"}) ||
				!slices.Equal(missing["second"], []string{"Secure"}) || !slices.Equal(missing["[redacted]"], []string{"Secure"}) {
				t.Fatalf("cookie evidence was merged, leaked or incorrect: %v", missing)
			}
			data, err := json.Marshal(out)
			if err != nil {
				t.Fatal(err)
			}
			for _, secret := range []string{"existing-session-secret", "server-cookie-secret", "redirect-secret"} {
				if strings.Contains(string(data), secret) {
					t.Error("session material leaked into evidence")
				}
			}
			out, err = scanDASTEndpoint(context.Background(), client, scope.JoinPath("off-origin"), true)
			if err == nil || out.Endpoint.Error != "redirect_out_of_scope" || outside.Load() {
				t.Fatalf("authenticated redirect was not blocked: %v, %+v", err, out.Endpoint)
			}
		})
	}
}

func TestDASTRequestBudgetIncludesRedirects(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/landing", http.StatusFound)
		}
	}))
	defer srv.Close()
	scanner := BaselineDAST{Timeout: time.Second}
	interval := 40 * time.Millisecond
	started := time.Now()
	results, err := scanner.ScanTargets(context.Background(), srv.URL, []string{"/start", "/other"}, DASTRunOptions{MaxRequests: 2, Interval: interval})
	if err != nil || len(results) != 2 {
		t.Fatalf("unexpected result count or error: %d, %v", len(results), err)
	}
	if hits.Load() != 2 || results[0].Endpoint.FinalURL != srv.URL+"/landing" || results[1].Endpoint.Error != "request_limit" {
		t.Fatalf("unexpected budget results: hits=%d, first=%+v, second=%+v", hits.Load(), results[0].Endpoint, results[1].Endpoint)
	}
	if time.Since(started) < interval {
		t.Fatal("redirect bypassed DAST interval")
	}
	if _, err := scanner.ScanTargets(context.Background(), srv.URL, []string{"/valid", "//elsewhere.test/"}, DASTRunOptions{MaxRequests: 2}); err == nil || hits.Load() != 2 {
		t.Fatal("invalid scope must fail validation before any request")
	}
	if _, err := scanner.ScanTargets(context.Background(), srv.URL, []string{"/valid"}, DASTRunOptions{
		MaxRequests: 2, SessionKind: "bearer", Session: "existing-session-secret",
	}); err == nil || hits.Load() != 2 {
		t.Fatal("plaintext session must be rejected before any request")
	}
}

func TestDASTProxyAndDirectMode(t *testing.T) {
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Host != "app.test" || r.URL.Path != "/check" {
			t.Error("proxy received an unexpected target")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer proxy.Close()
	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := parseDASTURL("http://app.test/check")
	if err != nil {
		t.Fatal(err)
	}
	base := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	scanner := BaselineDAST{Timeout: time.Second}
	client, closeTransport, err := scanner.newClient(base, scope, DASTRunOptions{MaxRequests: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer closeTransport()
	out, err := scanDASTEndpoint(context.Background(), client, scope, false)
	if err != nil || out.Endpoint.StatusCode != http.StatusOK {
		t.Fatalf("proxy request failed: %v, %+v", err, out.Endpoint)
	}
	direct, closeDirect, err := scanner.newClient(base, scope, DASTRunOptions{MaxRequests: 1, Direct: true})
	if err != nil {
		t.Fatal(err)
	}
	defer closeDirect()
	if direct.Transport.(*dastTransport).base.Proxy != nil {
		t.Fatal("direct client retained the configured proxy")
	}
}
