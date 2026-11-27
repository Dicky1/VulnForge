package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/example/sast-dast-analyzer/internal/models"
)

// AuthzDiffEngine probes each endpoint with every configured session and flags
// cases where a lower-privileged session receives the same response as a
// higher-privileged one (potential BOLA/IDOR).
type AuthzDiffEngine struct {
	Timeout      time.Duration
	MaxBodyBytes int64
}

// Probe runs all sessions against all endpoints and returns findings.
func (a AuthzDiffEngine) Probe(ctx context.Context, m models.AuthzMatrix) ([]models.Finding, []models.AuthzProbe, error) {
	if m.Origin == "" || len(m.Sessions) < 2 || len(m.Endpoints) == 0 {
		return nil, nil, fmt.Errorf("authz matrix requires origin, >=2 sessions, and >=1 endpoint")
	}
	origin, err := url.Parse(m.Origin)
	if err != nil || (origin.Scheme != "http" && origin.Scheme != "https") || origin.Hostname() == "" {
		return nil, nil, fmt.Errorf("invalid origin")
	}
	if a.Timeout <= 0 {
		a.Timeout = 15 * time.Second
	}
	if a.MaxBodyBytes <= 0 {
		a.MaxBodyBytes = 1 << 20
	}

	client := &http.Client{Timeout: a.Timeout}
	var findings []models.Finding
	var probes []models.AuthzProbe

	for _, ep := range m.Endpoints {
		if !strings.HasPrefix(ep, "/") {
			ep = "/" + ep
		}
		u := origin.ResolveReference(&url.URL{Path: ep})

		// First pass: probe with each session.
		results := make(map[string]models.AuthzProbe, len(m.Sessions))
		for _, s := range m.Sessions {
			probe := a.doProbe(ctx, client, u, s, a.MaxBodyBytes)
			results[s.Name] = probe
			probes = append(probes, probe)
		}

		// Compare each lower-privileged session against every higher-privileged one.
		for i := range m.Sessions {
			for j := range m.Sessions {
				if i == j {
					continue
				}
				low := m.Sessions[i]
				high := m.Sessions[j]
				if low.Priority >= high.Priority {
					continue
				}
				lowProbe := results[low.Name]
				highProbe := results[high.Name]
				if lowProbe.Error != "" || highProbe.Error != "" {
					continue
				}
				// Flag: low session reaches endpoint that high session also reaches
				// with identical body (likely unauthorized data exposure).
				bodyMatch := lowProbe.BodyHash != "" && lowProbe.BodyHash == highProbe.BodyHash
				statusLeak := lowProbe.Status >= 200 && lowProbe.Status < 300 &&
					highProbe.Status >= 200 && highProbe.Status < 300
				if statusLeak && (bodyMatch || lowProbe.BodyLen == highProbe.BodyLen) {
					f := models.Finding{
						ID:          fmt.Sprintf("AUTHZ-DIFF:%s:%s:%s", ep, high.Name, low.Name),
						Title:       "Potential unauthorized data access (BOLA/IDOR)",
						Description: fmt.Sprintf("Lower-privileged session %q received an equivalent response to %q on %s.", low.Name, high.Name, ep),
						Severity:    models.SeverityHigh,
						SourceTool:  "authz-diff",
						Language:    "web",
						FilePath:    ep,
						CreatedAt:   time.Now().UTC(),
					}
					f.DASTEvidence = &models.DASTEvidence{
						Endpoint: models.DASTEndpoint{RequestedURL: u.String(), StatusCode: lowProbe.Status},
						Method:   http.MethodGet,
					}
					findings = append(findings, f)
				}
			}
		}
	}
	return findings, probes, nil
}

func (a AuthzDiffEngine) doProbe(ctx context.Context, client *http.Client, u *url.URL, s models.AuthzSession, maxBytes int64) models.AuthzProbe {
	probe := models.AuthzProbe{Session: s.Name, Role: s.Role, Endpoint: u.String()}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		probe.Error = "invalid_request"
		return probe
	}
	req.Header.Set("User-Agent", "VulnForge/1.0 authz-diff")
	switch s.Kind {
	case "bearer":
		req.Header.Set("Authorization", "Bearer "+s.Value)
	case "cookie":
		req.Header.Set("Cookie", s.Value)
	}
	resp, err := client.Do(req)
	if err != nil {
		probe.Error = "request_failed"
		return probe
	}
	defer resp.Body.Close()
	probe.Status = resp.StatusCode
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
	h := sha256.Sum256(body)
	probe.BodyHash = hex.EncodeToString(h[:])
	probe.BodyLen = len(body)
	return probe
}
