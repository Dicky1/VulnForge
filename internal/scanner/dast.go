package scanner

import (
	"context"
	"crypto/tls"
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
	out := models.ToolOutput{Tool: "baseline-dast", ExitCode: -1}
	u, err := url.ParseRequestURI(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil {
		return out, fmt.Errorf("invalid DAST URL: use an explicit http(s) URL without embedded credentials")
	}
	timeout := d.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxResponseHeaderBytes = 1 << 20
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	defer transport.CloseIdleConnections()
	client := &http.Client{Timeout: timeout, Transport: transport, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return fmt.Errorf("DAST redirect limit exceeded")
		}
		if !sameDASTScope(u, req.URL) || (via[len(via)-1].URL.Scheme == "https" && req.URL.Scheme != "https") {
			return fmt.Errorf("DAST redirect left the authorized origin")
		}
		return nil
	}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return out, fmt.Errorf("could not construct DAST request")
	}
	req.Header.Set("User-Agent", "VulnForge/1.0 passive-security-check")
	resp, err := client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		// URL errors can contain sensitive query values or redirect locations.
		return out, fmt.Errorf("DAST HTTP request failed or redirect was rejected")
	}
	defer resp.Body.Close()
	out.ExitCode = 0

	// The query string may contain session keys or tokens. Never include it in
	// findings, logs, or exported reports.
	reportURL := *u
	reportURL.RawQuery = ""
	reportURL.ForceQuery = false
	reportURL.Fragment = ""
	add := func(id, title, desc string, sev models.Severity) {
		f := makeFinding("baseline-dast", id, reportURL.String(), 0, desc, string(sev), "")
		f.Title = title
		f.Language = "web"
		f.Remediation = "Set the header at the reverse proxy or application layer and verify it on every response."
		out.Findings = append(out.Findings, f)
	}
	if resp.Request.URL.Scheme != "https" {
		add("DAST-HTTPS", "HTTPS not enforced", "The endpoint is reachable over plaintext HTTP.", models.SeverityHigh)
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
			add(c.id, c.title, "Response is missing the "+c.header+" header.", c.sev)
		}
	}
	if resp.Request.URL.Scheme == "https" && resp.Header.Get("Strict-Transport-Security") == "" {
		add("DAST-HSTS", "Missing Strict-Transport-Security", "HTTPS response is missing the HSTS header.", models.SeverityLow)
	}
	if resp.Request.URL.Scheme == "https" {
		for _, cookie := range resp.Cookies() {
			if !cookie.Secure || !cookie.HttpOnly {
				// Never embed the raw Set-Cookie header or cookie value in findings.
				add("DAST-COOKIE", "Cookie lacks security attributes", "A response cookie lacks Secure or HttpOnly.", models.SeverityMedium)
			}
			if cookie.SameSite == http.SameSiteDefaultMode {
				add("DAST-SAMESITE", "Cookie has no SameSite attribute", "A response cookie has no explicit SameSite policy.", models.SeverityLow)
			}
		}
	}
	return out, nil
}
