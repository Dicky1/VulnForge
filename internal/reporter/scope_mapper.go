package reporter

import (
	"github.com/example/sast-dast-analyzer/internal/models"
	"net/url"
	"path/filepath"
	"strings"
)

type ScopeMapper struct{}

func (ScopeMapper) DetermineScopeStatus(f models.Finding, program *models.BountyProgram) models.ScopeAssessment {
	if program == nil {
		return models.ScopeAssessment{Status: "unknown", Reason: "No bounty program was selected; scope must be verified against the current program policy."}
	}
	host := findingHost(f)
	if host == "" {
		return models.ScopeAssessment{Status: "unknown", Program: program.Name, Reason: "Static code location is not an affected production URL. Confirm the deployed endpoint before submission."}
	}
	for _, pattern := range program.OutOfScope {
		if hostMatch(host, pattern) {
			return models.ScopeAssessment{Status: "out_of_scope", Program: program.Name, Reason: "Host matches explicit exclusion: " + pattern}
		}
	}
	for _, pattern := range program.Domains {
		if hostMatch(host, pattern) {
			return models.ScopeAssessment{Status: "in_scope", Program: program.Name, Reason: "Host matches configured scope: " + pattern}
		}
	}
	return models.ScopeAssessment{Status: "out_of_scope", Program: program.Name, Reason: "Host does not match any configured in-scope domain."}
}
func findingHost(f models.Finding) string {
	for _, v := range []string{f.FilePath, f.Description} {
		for _, token := range strings.Fields(v) {
			token = strings.Trim(token, "()[]{}<>,.;\"")
			if u, e := url.Parse(token); e == nil && (u.Scheme == "http" || u.Scheme == "https") {
				return strings.ToLower(u.Hostname())
			}
		}
	}
	return ""
}
func hostMatch(host, pattern string) bool {
	host = strings.ToLower(host)
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	if strings.HasPrefix(pattern, "*.") {
		suffix := strings.TrimPrefix(pattern, "*")
		return strings.HasSuffix(host, suffix) && host != strings.TrimPrefix(suffix, ".")
	}
	ok, _ := filepath.Match(pattern, host)
	return ok
}
