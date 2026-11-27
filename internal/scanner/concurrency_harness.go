package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/example/sast-dast-analyzer/internal/models"
)

// ConcurrencyHarness fires N parallel requests to detect duplicate/oversell.
type ConcurrencyHarness struct {
	Timeout time.Duration
	N       int
}

func (c ConcurrencyHarness) Run(ctx context.Context, targetURL string) ([]models.Finding, error) {
	if c.N < 2 {
		c.N = 10
	}
	if c.Timeout <= 0 {
		c.Timeout = 15 * time.Second
	}
	u, err := url.Parse(targetURL)
	if err != nil || u.Hostname() == "" {
		return nil, fmt.Errorf("invalid target URL")
	}
	client := &http.Client{Timeout: c.Timeout}
	type res struct {
		status int
		err    error
	}
	results := make([]res, c.N)
	var wg sync.WaitGroup
	for i := 0; i < c.N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), nil)
			if err != nil {
				results[i].err = err
				return
			}
			req.Header.Set("User-Agent", "VulnForge/1.0 concurrency")
			resp, err := client.Do(req)
			if err != nil {
				results[i].err = err
				return
			}
			resp.Body.Close()
			results[i].status = resp.StatusCode
		}(i)
	}
	wg.Wait()

	// Count successes; if more than 1 success on a mutating endpoint -> potential race.
	success := 0
	for _, r := range results {
		if r.err == nil && r.status >= 200 && r.status < 300 {
			success++
		}
	}
	var findings []models.Finding
	if success > 1 {
		f := models.Finding{
			ID:          "CONCURRENCY:race",
			Title:       "Potential race condition (duplicate success)",
			Description: fmt.Sprintf("%d of %d concurrent requests succeeded; possible duplicate/oversell.", success, c.N),
			Severity:    models.SeverityHigh,
			SourceTool:  "concurrency-harness",
			Language:    "web",
			FilePath:    u.Path,
			CreatedAt:   time.Now().UTC(),
		}
		f.DASTEvidence = &models.DASTEvidence{
			Endpoint: models.DASTEndpoint{RequestedURL: u.String(), StatusCode: 200},
			Method:   http.MethodPost,
		}
		findings = append(findings, f)
	}
	return findings, nil
}
