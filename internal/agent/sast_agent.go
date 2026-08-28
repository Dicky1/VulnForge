package agent

import (
	"context"
	"fmt"
	"github.com/example/sast-dast-analyzer/internal/models"
	"github.com/example/sast-dast-analyzer/internal/scanner"
	"log"
	"os/exec"
	"sync"
	"time"

	"github.com/example/sast-dast-analyzer/internal/detector"
)

type scannerInterface interface {
	Scan(context.Context, string) (models.ToolOutput, error)
}
type SASTAgent struct {
	Timeout     time.Duration
	Logger      *log.Logger
	MaxWorkers  int
	AutoInstall bool
}

func ValidateToolAvailability(toolName string) bool {
	_, err := exec.LookPath(toolName)
	return err == nil
}

func (a *SASTAgent) RunMultiLanguageSASTScan(ctx context.Context, target string, languages map[string]detector.LanguageInfo) ([]models.Finding, error) {
	registry := scanner.NewToolRegistry(a.Timeout)
	recommended := detector.NewLanguageDetector(target).GetRecommendedToolsForLanguages(languages)
	type task struct {
		lang, name string
		scanner    models.Scanner
	}
	var tasks []task
	seen := map[string]bool{}
	for lang, names := range recommended {
		for _, name := range names {
			if seen[name] {
				continue
			}
			s, ok := registry[name]
			if !ok {
				if a.Logger != nil {
					a.Logger.Printf("scanner %s recommended for %s but no wrapper is registered", name, lang)
				}
				continue
			}
			seen[name] = true
			tasks = append(tasks, task{lang, name, s})
		}
	}
	// Dependency-Check is universal and runs once when installed or auto-install was requested.
	if s, ok := registry["dependency-check"]; ok && !seen["dependency-check"] {
		tasks = append(tasks, task{"all", "dependency-check", s})
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
			sem <- struct{}{}
			defer func() { <-sem }()
			if !t.scanner.IsInstalled() {
				if !a.AutoInstall {
					ch <- result{err: fmt.Errorf("not installed"), name: t.name}
					return
				}
				if err := t.scanner.Install(ctx); err != nil {
					ch <- result{err: fmt.Errorf("install: %w", err), name: t.name}
					return
				}
			}
			cfg := &models.ScanConfig{TargetPath: target, Language: t.lang, MaxWorkers: workers}
			o, err := t.scanner.Scan(ctx, target, cfg)
			if err == nil {
				for i := range o.Findings {
					if o.Findings[i].Language == "" {
						o.Findings[i].Language = t.lang
					}
				}
			}
			ch <- result{o.Findings, err, t.name}
		}(t)
	}
	go func() { wg.Wait(); close(ch) }()
	var out []models.Finding
	var failures int
	for r := range ch {
		if r.err != nil {
			failures++
			if a.Logger != nil {
				a.Logger.Printf("scanner %s skipped: %v", r.name, r.err)
			}
			continue
		}
		out = append(out, r.findings...)
	}
	if len(out) == 0 && failures == len(tasks) && len(tasks) > 0 {
		return nil, fmt.Errorf("all %d multi-language scanners were unavailable or failed", failures)
	}
	return out, nil
}

func (a *SASTAgent) RunSASTScan(ctx context.Context, target string, tools []string) ([]models.Finding, error) {
	type result struct {
		o models.ToolOutput
		e error
	}
	ch := make(chan result, len(tools))
	var wg sync.WaitGroup
	for _, name := range tools {
		var s scannerInterface
		switch name {
		case "semgrep":
			s = scanner.NewSemgrepScanner(a.Timeout)
		case "bandit":
			s = scanner.NewBanditScanner(a.Timeout)
		case "gosec":
			s = scanner.NewGoSecScanner(a.Timeout)
		default:
			if a.Logger != nil {
				a.Logger.Printf("scanner unsupported: %s", name)
			}
			continue
		}
		wg.Add(1)
		go func() { defer wg.Done(); o, e := s.Scan(ctx, target); ch <- result{o, e} }()
	}
	go func() { wg.Wait(); close(ch) }()
	var out []models.Finding
	var errs []error
	for r := range ch {
		if r.e != nil {
			errs = append(errs, r.e)
			if a.Logger != nil {
				a.Logger.Printf("scanner skipped: %v", r.e)
			}
			continue
		}
		out = append(out, r.o.Findings...)
	}
	if len(out) == 0 && len(errs) > 0 {
		return nil, fmt.Errorf("all scanners failed: %v", errs)
	}
	return out, nil
}
