package reporter

import (
	"github.com/example/sast-dast-analyzer/internal/models"
	"strings"
)

func BuildBountyReferences(f models.Finding) models.BountyReferences {
	r := models.BountyReferences{}
	if f.CWE != "" {
		r.CWEIDs = []string{strings.ToUpper(f.CWE)}
		r.ExternalLinks = append(r.ExternalLinks, "https://cwe.mitre.org/data/definitions/"+strings.TrimPrefix(strings.ToUpper(f.CWE), "CWE-")+".html")
	}
	switch classify(f) {
	case "sql injection":
		r.OWASPIDs = []string{"A03:2021 Injection"}
		r.ExternalLinks = append(r.ExternalLinks, "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html")
	case "authentication bypass", "authorization bypass":
		r.OWASPIDs = []string{"A01:2021 Broken Access Control"}
	case "crypto weakness":
		r.OWASPIDs = []string{"A02:2021 Cryptographic Failures"}
	case "ssrf":
		r.OWASPIDs = []string{"A10:2021 Server-Side Request Forgery"}
	}
	return r
}

// FindRelevantCVEs intentionally returns no speculative CVE. A CVE should be
// attached only after product/version matching against authoritative records.
func FindRelevantCVEs(models.Finding) []string { return nil }
func MapToCWE(f models.Finding) []string {
	if f.CWE == "" {
		return nil
	}
	return []string{strings.ToUpper(f.CWE)}
}
func MapToOWASP(f models.Finding) []string { return BuildBountyReferences(f).OWASPIDs }
