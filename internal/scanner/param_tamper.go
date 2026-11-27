package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/example/sast-dast-analyzer/internal/models"
)

// ParamTamperFuzzer generates tampered parameter values from an OpenAPI-style
// spec and flags responses that violate expected status codes.
type ParamTamperFuzzer struct {
	Timeout      time.Duration
	MaxBodyBytes int64
}

type ParamSpec struct {
	Name     string `json:"name" yaml:"name"`
	In       string `json:"in" yaml:"in"` // query|path|body
	Type     string `json:"type" yaml:"type"`
	Required bool   `json:"required" yaml:"required"`
}

type EndpointSpec struct {
	Path        string      `json:"path" yaml:"path"`
	Method      string      `json:"method" yaml:"method"`
	Params      []ParamSpec `json:"params" yaml:"params"`
	ExpectCode  int         `json:"expect_code" yaml:"expect_code"` // expected on valid input
}

type TamperManifest struct {
	Origin    string         `json:"origin" yaml:"origin"`
	Endpoints []EndpointSpec `json:"endpoints" yaml:"endpoints"`
}

func (p ParamTamperFuzzer) Run(ctx context.Context, m TamperManifest) ([]models.Finding, error) {
	if m.Origin == "" || len(m.Endpoints) == 0 {
		return nil, fmt.Errorf("tamper manifest requires origin and endpoints")
	}
	origin, err := url.Parse(m.Origin)
	if err != nil || origin.Hostname() == "" {
		return nil, fmt.Errorf("invalid origin")
	}
	if p.Timeout <= 0 {
		p.Timeout = 15 * time.Second
	}
	if p.MaxBodyBytes <= 0 {
		p.MaxBodyBytes = 1 << 20
	}
	client := &http.Client{Timeout: p.Timeout}
	var findings []models.Finding

	tamperValues := []struct {
		label string
		fn    func(ParamSpec) string
	}{
		{"negative", func(ParamSpec) string { return "-1" }},
		{"zero", func(ParamSpec) string { return "0" }},
		{"huge", func(ParamSpec) string { return "999999999999" }},
		{"string", func(ParamSpec) string { return "AAAA" }},
		{"empty", func(ParamSpec) string { return "" }},
		{"null", func(ParamSpec) string { return "null" }},
	}

	for _, ep := range m.Endpoints {
		method := ep.Method
		if method == "" {
			method = http.MethodGet
		}
		for _, tv := range tamperValues {
			u := *origin
			q := u.Query()
			for _, pm := range ep.Params {
				if pm.In == "query" {
					q.Set(pm.Name, tv.fn(pm))
				}
			}
			u.RawQuery = q.Encode()
			path := ep.Path
			if !strings.HasPrefix(path, "/") {
				path = "/" + path
			}
			u.Path = path
			req, err := http.NewRequestWithContext(ctx, method, u.String(), nil)
			if err != nil {
				continue
			}
			req.Header.Set("User-Agent", "VulnForge/1.0 param-tamper")
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			resp.Body.Close()
			// Flag unexpected success (2xx) when tampering, or 5xx (server error).
			if (resp.StatusCode >= 200 && resp.StatusCode < 300) || resp.StatusCode >= 500 {
				sev := models.SeverityMedium
				if resp.StatusCode >= 500 {
					sev = models.SeverityHigh
				}
				f := models.Finding{
					ID:          fmt.Sprintf("PARAM-TAMPER:%s:%s:%d", ep.Path, tv.label, resp.StatusCode),
					Title:       "Parameter tampering accepted",
					Description: fmt.Sprintf("Endpoint %s accepted tampered value (%s) with status %d.", ep.Path, tv.label, resp.StatusCode),
					Severity:    sev,
					SourceTool:  "param-tamper",
					Language:    "web",
					FilePath:    ep.Path,
					CreatedAt:   time.Now().UTC(),
				}
				f.DASTEvidence = &models.DASTEvidence{
					Endpoint: models.DASTEndpoint{RequestedURL: u.String(), StatusCode: resp.StatusCode},
					Method:   method,
				}
				findings = append(findings, f)
			}
		}
	}
	return findings, nil
}
