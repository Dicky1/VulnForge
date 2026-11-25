package agent

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/example/sast-dast-analyzer/internal/detector"
	"github.com/example/sast-dast-analyzer/internal/models"
	"github.com/example/sast-dast-analyzer/internal/scanner"
)

type SASTAgent struct {
	Timeout     time.Duration
	Logger      *log.Logger
	MaxWorkers  int
	AutoInstall bool
}

func (a *SASTAgent) RunMultiLanguageSASTScan(ctx context.Context, target string, languages map[string]detector.LanguageInfo) ([]models.Finding, error) {
	findings, _, err := a.ScanWithCoverage(ctx, target, languages)
	return findings, err
}

func (a *SASTAgent) ScanWithCoverage(ctx context.Context, target string, languages map[string]detector.LanguageInfo) ([]models.Finding, []string, error) {
	registry := scanner.NewToolRegistry(a.Timeout)
	recommended := detector.NewLanguageDetector(target).GetRecommendedToolsForLanguages(languages)
	type task struct {
		lang, name string
		scanner    models.Scanner
	}
	var tasks []task
	var incomplete []string
	seen := map[string]bool{}
	for lang, names := range recommended {
		for _, name := range names {
			if seen[name] {
				continue
			}
			s, ok := registry[name]
			seen[name] = true
			if !ok {
				if a.Logger != nil {
					a.Logger.Printf("scanner %s recommended for %s but no wrapper is registered", name, lang)
				}
				incomplete = append(incomplete, name)
				continue
			}
			tasks = append(tasks, task{lang, name, s})
		}
	}
	// Dependency-Check is universal, but its platform installation is not safe
	// to automate. Include it silently only when the user already installed it.
	if s, ok := registry["dependency-check"]; ok && !seen["dependency-check"] && s.IsInstalled() {
		tasks = append(tasks, task{"all", "dependency-check", s})
	}
	planned := make([]string, 0, len(tasks))
	for _, t := range tasks {
		planned = append(planned, t.name+"["+t.lang+"]")
	}
	sort.Strings(planned)
	if a.Logger != nil {
		a.Logger.Printf("scanner plan: %s", strings.Join(planned, ","))
	}
	workers := a.MaxWorkers
	if workers <= 0 {
		workers = 4
	}
	sem := make(chan struct{}, workers)
	type result struct {
		findings []models.Finding
		err      error
		name     string
	}
	ch := make(chan result, len(tasks))
	var wg sync.WaitGroup
	for _, t := range tasks {
		wg.Add(1)
		go func(t task) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()
			if ctx.Err() != nil {
				return
			}
			if !t.scanner.IsInstalled() {
				if !a.AutoInstall {
					ch <- result{err: errors.New("scanner unavailable"), name: t.name}
					return
				}
				if a.Logger != nil {
					a.Logger.Printf("installing scanner %s", t.name)
				}
				if err := t.scanner.Install(ctx); err != nil {
					ch <- result{err: fmt.Errorf("install: %w", err), name: t.name}
					return
				}
			}
			cfg := &models.ScanConfig{TargetPath: target, Language: t.lang, MaxWorkers: workers}
			o, err := t.scanner.Scan(ctx, target, cfg)
			if err == nil && o == nil {
				err = fmt.Errorf("scanner returned no output")
			}
			if err != nil {
				// o may be nil on error (e.g. slither temp-dir failure); never
				// dereference it here.
				ch <- result{err: err, name: t.name}
				return
			}
			for i := range o.Findings {
				if o.Findings[i].Language == "" {
					o.Findings[i].Language = t.lang
				}
			}
			ch <- result{o.Findings, nil, t.name}
		}(t)
	}
	go func() { wg.Wait(); close(ch) }()
	var out []models.Finding
	var failures int
	for r := range ch {
		if r.err != nil {
			failures++
			incomplete = append(incomplete, r.name)
			if a.Logger != nil {
				a.Logger.Printf("scanner %s skipped: %v", r.name, r.err)
			}
			continue
		}
		out = append(out, r.findings...)
	}
	sort.Strings(incomplete)
	if err := ctx.Err(); err != nil {
		return nil, incomplete, err
	}
	if len(out) == 0 && failures == len(tasks) && len(tasks) > 0 {
		return nil, incomplete, fmt.Errorf("all %d multi-language scanners were unavailable or failed", failures)
	}
	if len(tasks) == 0 && len(languages) > 0 {
		if len(incomplete) == 0 {
			incomplete = append(incomplete, "sast")
		}
		return nil, incomplete, errors.New("no scanners were available for the detected languages")
	}
	return out, incomplete, nil
}
