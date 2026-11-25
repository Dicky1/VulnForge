package scanner

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/example/sast-dast-analyzer/internal/models"
)

// BaselineDAST performs passive checks only: it does not inject payloads or mutate state.
type BaselineDAST struct {
	Timeout      time.Duration
	MaxBodyBytes int64
}

const MaxDASTEndpoints = 100

type DASTRunOptions struct {
	Interval    time.Duration
	MaxRequests int
	Direct      bool
	SessionKind string
	Session     string
}

var (
	errDASTScope         = errors.New("DAST redirect was rejected because it left the authorized origin")
	errDASTRedirectLimit = errors.New("DAST redirect limit exceeded")
	errDASTRequestLimit  = errors.New("DAST request limit reached")
)

// sameDASTScope only permits redirects within the explicitly selected origin,
// plus the standard HTTP-to-HTTPS upgrade on the same hostname. This prevents
// an in-scope application from redirecting the scanner to an unrelated host,
// port, or a downgraded HTTP endpoint.
func sameDASTScope(original, next *url.URL) bool {
	if !strings.EqualFold(original.Hostname(), next.Hostname()) || next.User != nil {
		return false
	}
	if original.Scheme == next.Scheme {
		return effectiveDASTPort(original) == effectiveDASTPort(next)
	}
	return original.Scheme == "http" && next.Scheme == "https" &&
		effectiveDASTPort(original) == "80" && effectiveDASTPort(next) == "443"
}

func effectiveDASTPort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	if u.Scheme == "https" {
		return "443"
	}
	return "80"
}

func (d BaselineDAST) Scan(ctx context.Context, rawURL string) (models.ToolOutput, error) {
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return models.ToolOutput{Tool: "baseline-dast", ExitCode: -1}, fmt.Errorf("unsupported default HTTP transport")
	}
	return d.scanWithTransport(ctx, rawURL, base)
}

// The caller supplies a base transport; production uses the default system
// trust store. Tests can use a transport trusting only a local TLS fixture.
func (d BaselineDAST) scanWithTransport(ctx context.Context, rawURL string, base *http.Transport) (models.ToolOutput, error) {
	scope, err := parseDASTURL(rawURL)
	if err != nil {
		return models.ToolOutput{Tool: "baseline-dast", ExitCode: -1}, err
	}
	client, closeTransport, err := d.newClient(base, scope, DASTRunOptions{MaxRequests: 5})
	if err != nil {
		return models.ToolOutput{Tool: "baseline-dast", ExitCode: -1}, err
	}
	defer closeTransport()
	return scanDASTEndpoint(ctx, client, scope, false)
}

// ScanTargets accepts either one explicit URL, or paths under a single configured origin.
// It validates the entire run before issuing requests and retains individual failures.
func (d BaselineDAST) ScanTargets(ctx context.Context, origin string, targets []string, options DASTRunOptions) ([]models.ToolOutput, error) {
	if len(targets) == 0 || len(targets) > MaxDASTEndpoints || origin == "" && len(targets) != 1 {
		return nil, fmt.Errorf("provide one DAST URL or up to %d paths under a single origin", MaxDASTEndpoints)
	}
	if options.MaxRequests < 1 || options.MaxRequests > 500 || options.Interval < 0 || options.Interval > time.Minute {
		return nil, fmt.Errorf("DAST request limit must be 1–500 and interval must be between zero and one minute")
	}
	var scope *url.URL
	var err error
	if origin == "" {
		scope, err = parseDASTURL(targets[0])
	} else {
		scope, err = parseDASTOrigin(origin)
	}
	if err != nil {
		return nil, err
	}
	urls := make([]*url.URL, 0, len(targets))
	seen := make(map[string]bool, len(targets))
	for i, target := range targets {
		u := scope
		if origin != "" {
			path, err := url.Parse(target)
			if err != nil || !strings.HasPrefix(target, "/") || strings.HasPrefix(target, "//") ||
				path.Host != "" || path.IsAbs() || path.User != nil || strings.Contains(target, "#") {
				return nil, fmt.Errorf("DAST target %d must be an absolute path under the configured origin", i+1)
			}
			u = scope.ResolveReference(path)
		}
		key := reportDASTURL(u)
		if seen[key] {
			return nil, fmt.Errorf("DAST target %d repeats a path already in scope", i+1)
		}
		seen[key] = true
		urls = append(urls, u)
	}
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("unsupported default HTTP transport")
	}
	client, closeTransport, err := d.newClient(base, scope, options)
	if err != nil {
		return nil, err
	}
	defer closeTransport()
	results := make([]models.ToolOutput, 0, len(urls))
	rateLimited := false
	for _, u := range urls {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if rateLimited {
			out := newDASTOutput(u)
			out.Endpoint.Error = "skipped_after_rate_limit"
			results = append(results, out)
			continue
		}
		out, _ := scanDASTEndpoint(ctx, client, u, options.SessionKind != "")
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		rateLimited = out.Endpoint.StatusCode == http.StatusTooManyRequests
		results = append(results, out)
	}
	return results, nil
}

func parseDASTURL(rawURL string) (*url.URL, error) {
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.Opaque != "" {
		return nil, fmt.Errorf("invalid DAST URL: use an explicit http(s) URL without embedded credentials")
	}
	u.Fragment, u.RawFragment = "", ""
	return u, nil
}

func parseDASTOrigin(rawURL string) (*url.URL, error) {
	u, err := parseDASTURL(rawURL)
	if err != nil {
		return nil, err
	}
	if u.Path != "" && u.Path != "/" || u.ForceQuery || u.RawQuery != "" || strings.Contains(rawURL, "#") {
		return nil, fmt.Errorf("DAST origin must contain only a scheme, host, and optional port")
	}
	return u, nil
}

func (d BaselineDAST) newClient(base *http.Transport, scope *url.URL, options DASTRunOptions) (*http.Client, func(), error) {
	var header, value string
	switch options.SessionKind {
	case "":
	case "bearer", "cookie":
		if scope.Scheme != "https" {
			return nil, nil, fmt.Errorf("DAST sessions require an HTTPS origin")
		}
		if strings.TrimSpace(options.Session) == "" || strings.IndexFunc(options.Session, func(r rune) bool { return r < ' ' || r > '~' }) >= 0 {
			return nil, nil, fmt.Errorf("DAST session value must be non-empty printable ASCII")
		}
		header, value = "Cookie", options.Session
		if options.SessionKind == "bearer" {
			header, value = "Authorization", "Bearer "+options.Session
		}
	default:
		return nil, nil, fmt.Errorf("DAST session must be bearer or cookie")
	}
	timeout := d.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	transport := base.Clone()
	if options.Direct {
		transport.Proxy = nil
	}
	transport.MaxResponseHeaderBytes = 1 << 20
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{}
	} else {
		transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	}
	if transport.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		transport.TLSClientConfig.MinVersion = tls.VersionTLS12
	}
	transport.TLSClientConfig.InsecureSkipVerify = false
	run := &dastTransport{base: transport, scope: scope, interval: options.Interval, remaining: options.MaxRequests, sessionHeader: header, sessionValue: value}
	client := &http.Client{Timeout: timeout, Transport: run, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errDASTRedirectLimit
		}
		if !sameDASTScope(scope, req.URL) || (via[len(via)-1].URL.Scheme == "https" && req.URL.Scheme != "https") {
			return errDASTScope
		}
		req.Header.Del("Referer")
		return nil
	}}
	return client, transport.CloseIdleConnections, nil
}

// A run sends requests sequentially, including redirects. Budgeting here
// also applies to redirects issued internally by http.Client.
type dastTransport struct {
	base                        *http.Transport
	scope                       *url.URL
	interval                    time.Duration
	next                        time.Time
	remaining                   int
	sessionHeader, sessionValue string
}

func (t *dastTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method != http.MethodGet || !sameDASTScope(t.scope, req.URL) {
		return nil, errDASTScope
	}
	if t.remaining == 0 {
		return nil, errDASTRequestLimit
	}
	if delay := time.Until(t.next); delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-req.Context().Done():
			return nil, req.Context().Err()
		case <-timer.C:
		}
	}
	if err := req.Context().Err(); err != nil {
		return nil, err
	}
	t.next = time.Now().Add(t.interval)
	t.remaining--
	if t.sessionHeader != "" {
		if req.URL.Scheme != "https" {
			return nil, errDASTScope
		}
		req = req.Clone(req.Context())
		req.Header.Set(t.sessionHeader, t.sessionValue)
	}
	return t.base.RoundTrip(req)
}

func newDASTOutput(u *url.URL) models.ToolOutput {
	endpoint := &models.DASTEndpoint{RequestedURL: reportDASTURL(u)}
	return models.ToolOutput{Tool: "baseline-dast", TargetURL: endpoint.RequestedURL, Endpoint: endpoint, ExitCode: -1}
}

func scanDASTEndpoint(ctx context.Context, client *http.Client, u *url.URL, authenticated bool) (models.ToolOutput, error) {
	out := newDASTOutput(u)
	endpoint := out.Endpoint
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		endpoint.Error = "invalid_request"
		return out, fmt.Errorf("could not construct DAST request")
	}
	req.Header.Set("User-Agent", "VulnForge/1.0 passive-security-check")
	resp, err := client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		if resp != nil {
			// On redirect rejection the client returns the last response
			// with its body closed, before contacting the destination.
			endpoint.StatusCode = resp.StatusCode
		}
		switch {
		case errors.Is(err, errDASTScope):
			endpoint.Error = "redirect_out_of_scope"
			return out, errDASTScope
		case errors.Is(err, errDASTRedirectLimit):
			endpoint.Error = "redirect_limit"
			return out, errDASTRedirectLimit
		case errors.Is(err, errDASTRequestLimit):
			endpoint.Error = "request_limit"
			return out, errDASTRequestLimit
		case errors.Is(err, context.DeadlineExceeded):
			endpoint.Error = "timeout"
		default:
			endpoint.Error = "request_failed"
		}
		// Transport errors may contain unredacted URLs or proxy data.
		return out, fmt.Errorf("DAST HTTP request failed or redirect was rejected")
	}
	defer resp.Body.Close()
	endpoint.FinalURL = reportDASTURL(resp.Request.URL)
	if authenticated && resp.Request.URL.EscapedPath() != u.EscapedPath() {
		// A login redirect can put session material in a path segment.
		redacted := *resp.Request.URL
		redacted.Path, redacted.RawPath = "/[redacted]", ""
		endpoint.FinalURL = reportDASTURL(&redacted)
	}
	endpoint.StatusCode = resp.StatusCode
	switch {
	case resp.StatusCode >= 500:
		endpoint.Error = "http_server_error"
	case resp.StatusCode == http.StatusTooManyRequests:
		endpoint.Error = "http_rate_limited"
	case resp.StatusCode == http.StatusNotFound:
		endpoint.Error = "http_not_found"
	case authenticated && (resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden):
		endpoint.Error = "http_access_denied"
	}
	if endpoint.Error != "" {
		return out, nil
	}
	out.ExitCode = 0
	out.Findings = assessDASTResponse(resp, *endpoint, authenticated)
	return out, nil
}

func reportDASTURL(u *url.URL) string {
	reportURL := *u
	reportURL.RawQuery = ""
	reportURL.ForceQuery = false
	reportURL.Fragment, reportURL.RawFragment = "", ""
	reportURL.Host = strings.ToLower(reportURL.Host)
	if reportURL.Path == "" {
		reportURL.Path = "/"
	}
	return reportURL.String()
}

func assessDASTResponse(resp *http.Response, endpoint models.DASTEndpoint, authenticated bool) []models.Finding {
	var findings []models.Finding
	add := func(id, title, desc string, sev models.Severity, evidence models.DASTEvidence) {
		f := makeFinding("baseline-dast", id, endpoint.RequestedURL, 0, desc, string(sev), "")
		f.Title = title
		f.Language = "web"
		evidence.Endpoint, evidence.Method = endpoint, http.MethodGet
		f.DASTEvidence = &evidence
		f.Remediation = "Set the header at the reverse proxy or application layer and verify it on every response."
		if evidence.CookieName != "" {
			f.Remediation = "Review the cookie's purpose and configure the appropriate security attributes."
		}
		findings = append(findings, f)
	}
	if resp.Request.URL.Scheme != "https" {
		add("DAST-HTTPS", "HTTPS not enforced", "The endpoint is reachable over plaintext HTTP.", models.SeverityHigh, models.DASTEvidence{})
	}
	checks := []struct {
		header, id, title string
		sev               models.Severity
	}{
		{"Content-Security-Policy", "DAST-CSP", "Missing Content-Security-Policy", models.SeverityMedium},
		{"X-Content-Type-Options", "DAST-NOSNIFF", "Missing X-Content-Type-Options", models.SeverityLow},
		{"Referrer-Policy", "DAST-REFERRER", "Missing Referrer-Policy", models.SeverityLow},
	}
	for _, c := range checks {
		if resp.Header.Get(c.header) == "" {
			add(c.id, c.title, "Response is missing the "+c.header+" header.", c.sev, models.DASTEvidence{HeaderName: c.header})
		}
	}
	if resp.Request.URL.Scheme == "https" && resp.Header.Get("Strict-Transport-Security") == "" {
		add("DAST-HSTS", "Missing Strict-Transport-Security", "HTTPS response is missing the HSTS header.", models.SeverityLow, models.DASTEvidence{HeaderName: "Strict-Transport-Security"})
	}
	if resp.Request.URL.Scheme == "https" {
		for _, cookie := range resp.Cookies() {
			name := cookie.Name
			// An authenticated service can reflect submitted credentials in
			// response header names. Omit names containing a sent credential.
			if authenticated && reflectsDASTCredential(name, resp.Request) {
				name = "[redacted]"
			}
			key := name + ":" + cookie.Domain + ":" + cookie.Path
			var missing []string
			if !cookie.Secure {
				missing = append(missing, "Secure")
			}
			if !cookie.HttpOnly {
				missing = append(missing, "HttpOnly")
			}
			if len(missing) > 0 {
				add("DAST-COOKIE:"+key, "Cookie lacks security attributes", "Cookie "+name+" is missing "+strings.Join(missing, " and ")+".", models.SeverityMedium, models.DASTEvidence{CookieName: name, MissingAttributes: missing})
			}
			if cookie.SameSite == 0 || cookie.SameSite == http.SameSiteDefaultMode {
				add("DAST-SAMESITE:"+key, "Cookie has no SameSite attribute", "Cookie "+name+" has no explicit SameSite policy.", models.SeverityLow, models.DASTEvidence{CookieName: name, MissingAttributes: []string{"SameSite"}})
			}
		}
	}
	return findings
}

func reflectsDASTCredential(name string, req *http.Request) bool {
	if token := strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer "); token != "" && strings.Contains(name, token) {
		return true
	}
	for _, cookie := range req.Cookies() {
		if cookie.Value != "" && strings.Contains(name, cookie.Value) {
			return true
		}
	}
	return false
}
