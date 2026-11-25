package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/example/sast-dast-analyzer/internal/models"
	"os"
	"path/filepath"
	"strings"
)

type DependencyCheckScanner struct{}

func NewDependencyCheckScanner() *DependencyCheckScanner { return &DependencyCheckScanner{} }
func (*DependencyCheckScanner) Name() string             { return "dependency-check" }
func (*DependencyCheckScanner) Language() string         { return "all" }
func (*DependencyCheckScanner) IsInstalled() bool {
	return installed("dependency-check") || installed("dependency-check.sh")
}
func (*DependencyCheckScanner) Install(context.Context) error {
	return errors.New("install OWASP Dependency-Check from its official distribution")
}
func (s *DependencyCheckScanner) Scan(ctx context.Context, target string, _ *models.ScanConfig) (*models.ToolOutput, error) {
	name := "dependency-check"
	if !installed(name) {
		name = "dependency-check.sh"
	}
	// Write the report to a private temp directory instead of into the
	// scanned (untrusted, possibly read-only) repository: the old path both
	// modified the target and would happily parse a pre-planted or symlinked
	// dependency-check-report.json shipped by the repository itself.
	outDir, err := os.MkdirTemp("", "analyzer-depcheck-*")
	if err != nil {
		return output(s.Name(), commandResult{exitCode: -1}, nil), fmt.Errorf("create dependency-check output dir: %w", err)
	}
	defer os.RemoveAll(outDir)
	reportPath := filepath.Join(outDir, "dependency-check-report.json")
	r, err := run(ctx, multiScannerTimeout, target, name, "--project=.", "--scan=.", "--format=JSON", "--out="+reportPath)
	if err != nil {
		return output(s.Name(), r, nil), err
	}
	raw := r.data
	if b, e := os.ReadFile(reportPath); e == nil {
		raw = b
	}
	f, e := s.ParseOutput(raw)
	return output(s.Name(), commandResult{data: raw, exitCode: r.exitCode}, f), e
}
func (*DependencyCheckScanner) ParseOutput(raw []byte) ([]models.Finding, error) {
	var d struct {
		Dependencies []struct {
			FileName, FilePath string
			Packages           []struct{ ID string } `json:"packages"`
			Vulnerabilities    []struct {
				Name, Description, Severity string
				CVSSV3                      struct {
					BaseScore             float64 `json:"baseScore"`
					AttackVector          string  `json:"attackVector"`
					AttackComplexity      string  `json:"attackComplexity"`
					PrivilegesRequired    string  `json:"privilegesRequired"`
					UserInteraction       string  `json:"userInteraction"`
					Scope                 string  `json:"scope"`
					ConfidentialityImpact string  `json:"confidentialityImpact"`
					IntegrityImpact       string  `json:"integrityImpact"`
					AvailabilityImpact    string  `json:"availabilityImpact"`
				}
				CWEs       []string `json:"cwes"`
				References []struct {
					URL string `json:"url"`
				}
			} `json:"vulnerabilities"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, err
	}
	var out []models.Finding
	for _, dep := range d.Dependencies {
		lang := packageLanguage(dep.FilePath)
		for _, v := range dep.Vulnerabilities {
			cwe := ""
			if len(v.CWEs) > 0 {
				cwe = v.CWEs[0]
			}
			desc := fmt.Sprintf("Dependency %s: %s", dep.FileName, v.Description)
			f := languageFinding("dependency-check", lang, v.Name, dep.FilePath, 0, v.Name, desc, v.Severity, "", cwe)
			if v.CVSSV3.BaseScore > 0 {
				f.CVSSBase = v.CVSSV3.BaseScore
				c := v.CVSSV3
				f.CVSSVector = cvssVectorFromParts(c.AttackVector, c.AttackComplexity, c.PrivilegesRequired, c.UserInteraction, c.Scope, c.ConfidentialityImpact, c.IntegrityImpact, c.AvailabilityImpact)
			}
			for _, p := range dep.Packages {
				f.ExploitChain = append(f.ExploitChain, p.ID)
			}
			out = append(out, f)
		}
	}
	return out, nil
}
func packageLanguage(path string) string {
	p := strings.ToLower(path)
	switch {
	case strings.Contains(p, "node_modules") || strings.HasSuffix(p, "package-lock.json"):
		return "javascript"
	case strings.Contains(p, "site-packages") || strings.HasSuffix(p, "requirements.txt"):
		return "python"
	case strings.Contains(p, ".m2") || strings.HasSuffix(p, ".jar"):
		return "java"
	case strings.HasSuffix(p, "gemfile.lock"):
		return "ruby"
	case strings.HasSuffix(p, "cargo.lock"):
		return "rust"
	case strings.HasSuffix(p, "composer.lock"):
		return "php"
	}
	return "unknown"
}
