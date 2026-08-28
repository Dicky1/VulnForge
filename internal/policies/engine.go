package policies

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/example/sast-dast-analyzer/internal/models"
	"gopkg.in/yaml.v2"
)

type PolicyEngine struct{}
type PolicyDocument struct {
	Policy     Policy    `yaml:"policy"`
	Filtering  Filtering `yaml:"filtering"`
	Compliance struct {
		Frameworks []string `yaml:"frameworks"`
	} `yaml:"compliance"`
}
type Policy struct {
	Name, Version string
	Rules         []Rule    `yaml:"rules"`
	Filtering     Filtering `yaml:"-"`
	Frameworks    []string  `yaml:"-"`
}
type Rule struct {
	Name, Type          string
	Enabled             bool
	Patterns            []string
	Severity            models.Severity
	Remediation         string
	CWE                 any `yaml:"cwe"`
	Languages           []string
	ConfidenceThreshold float64 `yaml:"confidence_threshold"`
}
type Filtering struct {
	ExcludePaths      []string        `yaml:"exclude_paths"`
	ExcludeCWE        []int           `yaml:"exclude_cwe"`
	MinimumConfidence float64         `yaml:"minimum_confidence"`
	MinimumSeverity   models.Severity `yaml:"minimum_severity"`
}
type PolicyError struct{ Field, Message string }

func NewPolicyEngine() *PolicyEngine { return &PolicyEngine{} }
func (pe *PolicyEngine) LoadPolicy(path string) (*Policy, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var d PolicyDocument
	if err = yaml.UnmarshalStrict(b, &d); err != nil {
		return nil, err
	}
	d.Policy.Filtering = d.Filtering
	d.Policy.Frameworks = d.Compliance.Frameworks
	if es := pe.ValidatePolicy(&d.Policy); len(es) > 0 {
		return nil, fmt.Errorf("invalid policy: %s: %s", es[0].Field, es[0].Message)
	}
	return &d.Policy, nil
}
func (pe *PolicyEngine) ValidatePolicy(p *Policy) []PolicyError {
	var out []PolicyError
	if strings.TrimSpace(p.Name) == "" {
		out = append(out, PolicyError{"policy.name", "required"})
	}
	for i, r := range p.Rules {
		prefix := "rules[" + strconv.Itoa(i) + "]"
		if r.Name == "" {
			out = append(out, PolicyError{prefix + ".name", "required"})
		}
		if r.Type != "pattern" && r.Type != "cwe" && r.Type != "custom" && r.Type != "ai" {
			out = append(out, PolicyError{prefix + ".type", "must be pattern, cwe, custom, or ai"})
		}
		for _, pattern := range r.Patterns {
			if _, err := regexp.Compile(pattern); err != nil {
				out = append(out, PolicyError{prefix + ".patterns", err.Error()})
			}
		}
	}
	return out
}
func (pe *PolicyEngine) ApplyPolicy(findings []models.Finding, p *Policy) []models.Finding {
	if p == nil {
		return findings
	}
	excluded := map[string]bool{}
	for _, n := range p.Filtering.ExcludeCWE {
		excluded[fmt.Sprintf("CWE-%d", n)] = true
	}
	out := make([]models.Finding, 0, len(findings))
	for _, f := range findings {
		if excluded[strings.ToUpper(f.CWE)] || excludedPath(f.FilePath, p.Filtering.ExcludePaths) || f.AIConfidence > 0 && f.AIConfidence < p.Filtering.MinimumConfidence || severityRank(f.Severity) < severityRank(p.Filtering.MinimumSeverity) {
			continue
		}
		for _, r := range p.Rules {
			if !r.Enabled || !languageAllowed(f.Language, r.Languages) {
				continue
			}
			matched := false
			switch r.Type {
			case "cwe":
				matched = strings.EqualFold(f.CWE, "CWE-"+fmt.Sprint(r.CWE))
			case "pattern", "custom":
				text := f.Title + " " + f.Description + " " + f.CodeSnippet
				for _, pattern := range r.Patterns {
					if regexp.MustCompile(pattern).MatchString(text) {
						matched = true
						break
					}
				}
			case "ai":
				matched = f.AIConfidence >= r.ConfidenceThreshold
			}
			if matched {
				if r.Severity != "" {
					f.Severity = r.Severity
				}
				if r.Remediation != "" {
					f.Remediation = r.Remediation
				}
			}
		}
		out = append(out, f)
	}
	return out
}
func excludedPath(path string, patterns []string) bool {
	p := filepath.ToSlash(path)
	for _, x := range patterns {
		if strings.Contains(p, strings.Trim(filepath.ToSlash(x), "/")) {
			return true
		}
	}
	return false
}
func severityRank(s models.Severity) int {
	switch s {
	case models.SeverityCritical:
		return 4
	case models.SeverityHigh:
		return 3
	case models.SeverityMedium:
		return 2
	case models.SeverityLow:
		return 1
	}
	return 0
}
func languageAllowed(lang string, list []string) bool {
	if len(list) == 0 {
		return true
	}
	for _, v := range list {
		if strings.EqualFold(lang, v) {
			return true
		}
	}
	return false
}
