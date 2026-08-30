package bounty_adapters

import (
	"encoding/json"
	"fmt"
	"github.com/example/sast-dast-analyzer/internal/models"
	"strings"
)

type BountyAdapter interface {
	FormatReport(models.BugBountyReport) (string, error)
	ValidateReport(models.BugBountyReport) error
	ExportJSON(models.BugBountyReport) ([]byte, error)
	Platform() string
}
type adapter struct{ platform string }

func (a adapter) Platform() string { return a.platform }
func (a adapter) ValidateReport(r models.BugBountyReport) error {
	if strings.TrimSpace(r.Title) == "" {
		return fmt.Errorf("title is required")
	}
	if len(r.StepsToReproduce) < 3 {
		return fmt.Errorf("at least three reproduction steps are required")
	}
	if r.Scope.Status != "in_scope" {
		return fmt.Errorf("scope is not confirmed in-scope")
	}
	if r.AffectedEndpoint == "" || strings.Contains(r.AffectedEndpoint, "<") {
		return fmt.Errorf("affected endpoint is not verified")
	}
	return nil
}
func (a adapter) ExportJSON(r models.BugBountyReport) ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}
func (a adapter) FormatReport(r models.BugBountyReport) (string, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n\n**Platform:** %s  \n**Severity:** %s (CVSS %.1f)  \n**Vulnerability type:** %s  \n**Affected endpoint:** %s  \n**Scope:** %s — %s\n\n## Vulnerability details\n%s\n\n## Steps to reproduce\n", r.Title, a.platform, r.Severity, r.SeverityJustification.CVSSScore, r.VulnerabilityType, r.AffectedEndpoint, r.Scope.Status, r.Scope.Reason, r.Description)
	for _, s := range r.StepsToReproduce {
		fmt.Fprintf(&b, "%d. %s\n", s.StepNumber, s.Description)
		if s.Command != "" {
			fmt.Fprintf(&b, "   ```bash\n   %s\n   ```\n", s.Command)
		}
		fmt.Fprintf(&b, "   Expected: %s\n", s.ExpectedResult)
	}
	fmt.Fprintf(&b, "\n## Proof of concept\n```bash\n%s\n```\n\n## Impact\n**Security:** %s\n\n**Business:** %s\n\n**Users:** %s\n\n## Remediation\n", r.ProofOfConcept.Curl, r.Impact.SecurityImpact, r.Impact.BusinessImpact, r.Impact.UserImpact)
	for _, v := range r.Remediation {
		fmt.Fprintf(&b, "- %s\n", v)
	}
	fmt.Fprintf(&b, "\n## References\n")
	for _, v := range r.References.ExternalLinks {
		fmt.Fprintf(&b, "- %s\n", v)
	}
	if !r.ReadyToSubmit {
		fmt.Fprintf(&b, "\n> **DRAFT — NOT READY TO SUBMIT:** %s\n", strings.Join(r.BlockingReasons, "; "))
	}
	return b.String(), nil
}
func New(platform string) BountyAdapter { return adapter{platform: platform} }
