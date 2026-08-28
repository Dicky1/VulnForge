package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
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

func (d BaselineDAST) Scan(ctx context.Context, rawURL string) (models.ToolOutput, error) {
	u, err := url.ParseRequestURI(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return models.ToolOutput{Tool: "baseline-dast", ExitCode: -1}, fmt.Errorf("invalid DAST URL")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	client := &http.Client{Timeout: d.Timeout, Transport: transport, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return fmt.Errorf("too many redirects")
		}
		return nil
	}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return models.ToolOutput{Tool: "baseline-dast", ExitCode: -1}, err
	}
	req.Header.Set("User-Agent", "sast-dast-analyzer/1.0 passive-security-check")
	resp, err := client.Do(req)
	if err != nil {
		return models.ToolOutput{Tool: "baseline-dast", ExitCode: -1}, err
	}
	defer resp.Body.Close()
	limit := d.MaxBodyBytes
	if limit <= 0 {
		limit = 1 << 20
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, limit))
	out := models.ToolOutput{Tool: "baseline-dast", ExitCode: 0}
	add := func(id, title, desc string, sev models.Severity) {
		f := makeFinding("baseline-dast", id, u.String(), 0, desc, string(sev), "")
		f.Title = title
		f.Language = "web"
		f.Remediation = "Set the header at the reverse proxy or application layer and verify it on every response."
		out.Findings = append(out.Findings, f)
	}
	if u.Scheme != "https" {
		add("DAST-HTTPS", "HTTPS not enforced", "The endpoint is reachable over plaintext HTTP.", models.SeverityHigh)
	}
	checks := []struct {
		header, id, title string
		sev               models.Severity
	}{{"Content-Security-Policy", "DAST-CSP", "Missing Content-Security-Policy", models.SeverityMedium}, {"X-Content-Type-Options", "DAST-NOSNIFF", "Missing X-Content-Type-Options", models.SeverityLow}, {"Referrer-Policy", "DAST-REFERRER", "Missing Referrer-Policy", models.SeverityLow}}
	for _, c := range checks {
		if resp.Header.Get(c.header) == "" {
			add(c.id, c.title, "Response is missing the "+c.header+" header.", c.sev)
		}
	}
	if cookie := resp.Header.Values("Set-Cookie"); u.Scheme == "https" {
		for _, v := range cookie {
			low := strings.ToLower(v)
			if !strings.Contains(low, "secure") || !strings.Contains(low, "httponly") {
				add("DAST-COOKIE", "Cookie lacks security attributes", "Set-Cookie lacks Secure or HttpOnly: "+v, csev(cookie))
				break
			}
		}
	}
	if strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/html") && strings.Contains(strings.ToLower(string(body)), "<script") && resp.Header.Get("Content-Security-Policy") == "" { /* already represented by CSP finding */
	}
	return out, nil
}
func csev(_ []string) models.Severity { return models.SeverityMedium }
