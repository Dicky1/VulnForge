package reporter

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/example/sast-dast-analyzer/internal/models"
	adapters "github.com/example/sast-dast-analyzer/internal/reporter/bounty_adapters"
)

type BountyReporterOptions struct {
	Platform, ProgramName, Target string
	Programs                      []models.BountyProgram
	POCFormats                    []string
	MinSeverity                   models.Severity
}
type BugBountyReporter struct{ Options BountyReporterOptions }

func (b *BugBountyReporter) GenerateReadyToSubmitReport(f models.Finding, business *models.BusinessFinding) (models.BugBountyReport, error) {
	if severityRank(f.Severity) < severityRank(b.Options.MinSeverity) {
		return models.BugBountyReport{}, fmt.Errorf("finding severity %s is below bounty threshold %s", f.Severity, b.Options.MinSeverity)
	}
	program := b.program()
	scope := ScopeMapper{}.DetermineScopeStatus(f, program)
	endpoint := findingEndpoint(f)
	steps := BuildDetailedStepsToReproduce(f, endpoint)
	poc := POCFormatter{Formats: b.Options.POCFormats}.Format(f, endpoint)
	refs := BuildBountyReferences(f)
	severity := GenerateSeverityJustification(f)
	platform := b.Options.Platform
	if platform == "" && program != nil {
		platform = program.Platform
	}
	if platform == "" {
		platform = "hackerone"
	}
	r := models.BugBountyReport{ID: f.ID, Platform: platform, Title: GenerateCompellingTitle(f), Severity: strings.ToUpper(string(f.Severity)), SeverityJustification: severity, VulnerabilityType: titleKind(classify(f)), AffectedEndpoint: endpoint, Description: "The analyzer identified a potential " + classify(f) + " at " + f.FilePath + ". Runtime exploitability and the deployed endpoint must be independently verified before submission.", StepsToReproduce: steps, ProofOfConcept: poc, Impact: BuildImpactDescription(f, business), AttackScenarios: []string{"An attacker who can reach the verified affected surface may attempt to abuse the identified control weakness under the conditions documented by runtime validation."}, References: refs, Scope: scope, GeneratedAt: time.Now().UTC()}
	if program != nil {
		r.Program = program.Name
	}
	if business != nil {
		r.AffectedUsers = business.Impact.AffectedUsers
	}
	r.Remediation = bountyRemediation(f)
	r.Evidence = []models.BountyEvidence{{Type: "source", Path: fmt.Sprintf("%s:%d", f.FilePath, f.LineNumber), Note: "Static source location reported by " + f.SourceTool}, {Type: "scanner", Note: "Automated evidence only; attach a sanitized runtime request/response or transaction trace before submission."}}
	r.QualityChecks, r.BlockingReasons = qualityChecks(r)
	adapter := adapterFor(platform)
	if err := adapter.ValidateReport(r); err != nil {
		r.BlockingReasons = appendUnique(r.BlockingReasons, err.Error())
	}
	r.ReadyToSubmit = len(r.BlockingReasons) == 0
	formatted, err := adapter.FormatReport(r)
	if err != nil {
		return r, err
	}
	r.SubmissionTemplate = formatted
	return r, nil
}

func (b *BugBountyReporter) BuildBundle(findings []models.Finding, business *models.BusinessReport) models.BountyBundle {
	bundle := models.BountyBundle{GeneratedAt: time.Now().UTC(), Target: b.Options.Target, InputCount: len(findings), Reports: []models.BugBountyReport{}, Excluded: []models.BountyExclusion{}}
	seen := map[string]bool{}
	for _, f := range findings {
		if reason := bountyExclusionReason(f, b.Options.Target); reason != "" {
			bundle.Excluded = append(bundle.Excluded, models.BountyExclusion{FindingID: f.ID, Title: f.Title, SourceTool: f.SourceTool, FilePath: bountyRelativePath(f.FilePath, b.Options.Target), Reason: reason})
			continue
		}
		f.FilePath = bountyRelativePath(f.FilePath, b.Options.Target)
		key := strings.ToLower(classify(f) + ":" + f.FilePath + fmt.Sprint(f.LineNumber))
		if seen[key] {
			bundle.Excluded = append(bundle.Excluded, models.BountyExclusion{FindingID: f.ID, Title: f.Title, SourceTool: f.SourceTool, FilePath: f.FilePath, Reason: "Duplicate candidate with the same vulnerability type and source location."})
			continue
		}
		seen[key] = true
		var bf *models.BusinessFinding
		if v, ok := BusinessFindingFor(business, f.ID); ok {
			bf = &v
		}
		r, err := b.GenerateReadyToSubmitReport(f, bf)
		if err != nil {
			bundle.Excluded = append(bundle.Excluded, models.BountyExclusion{FindingID: f.ID, Title: f.Title, SourceTool: f.SourceTool, FilePath: f.FilePath, Reason: err.Error()})
			continue
		}
		bundle.Reports = append(bundle.Reports, r)
		if r.ReadyToSubmit {
			bundle.ReadyCount++
		} else {
			bundle.BlockedCount++
		}
	}
	return bundle
}

func bountyExclusionReason(f models.Finding, target string) string {
	if f.IsZeroDay || strings.EqualFold(f.SourceTool, "zeroday-detector") {
		return "Heuristic zero-day hypothesis is not submission-ready without independent runtime reproduction and evidence."
	}
	kind := classify(f)
	if kind == "security weakness" {
		return "Finding has no supported, specific bug-bounty vulnerability classification."
	}
	rel := strings.ToLower(filepath.ToSlash(bountyRelativePath(f.FilePath, target)))
	trim := strings.TrimPrefix(rel, "./")
	for _, prefix := range []string{"lib/", "vendor/", "node_modules/", "test/", "tests/", "testdata/", ".git/"} {
		if strings.HasPrefix(trim, prefix) {
			return "Finding is located in an excluded dependency, test, fixture, or repository metadata path."
		}
	}
	return ""
}
func bountyRelativePath(path, target string) string {
	if path == "" || target == "" {
		return path
	}
	if rel, err := filepath.Rel(target, path); err == nil && !strings.HasPrefix(rel, "..") {
		return filepath.ToSlash(rel)
	}
	return filepath.ToSlash(path)
}
func (b *BugBountyReporter) program() *models.BountyProgram {
	for i := range b.Options.Programs {
		p := &b.Options.Programs[i]
		if strings.EqualFold(p.Name, b.Options.ProgramName) || strings.EqualFold(p.Handle, b.Options.ProgramName) || (b.Options.ProgramName == "" && strings.EqualFold(p.Platform, b.Options.Platform)) {
			return p
		}
	}
	return nil
}
func findingEndpoint(f models.Finding) string {
	if host := findingHost(f); host != "" {
		for _, v := range strings.Fields(f.FilePath + " " + f.Description) {
			v = strings.Trim(v, "()[]{}<>,.;\"")
			if strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://") {
				return v
			}
		}
		return "https://" + host + "/<verified-path>"
	}
	return "<NOT_ESTABLISHED_FROM_STATIC_ANALYSIS>"
}
func bountyRemediation(f models.Finding) []string {
	var out []string
	if f.Remediation != "" {
		out = append(out, f.Remediation)
	}
	for _, s := range f.RemediationSuggestions {
		if s.Description != "" {
			out = appendUnique(out, s.Description)
		}
	}
	if len(out) == 0 {
		out = []string{"Confirm the root cause, enforce the missing security control, add a regression test, and rerun the relevant scanner."}
	}
	return out
}
func qualityChecks(r models.BugBountyReport) ([]models.QualityCheck, []string) {
	checks := []models.QualityCheck{}
	blocked := []string{}
	add := func(name string, pass bool, reason string) {
		checks = append(checks, models.QualityCheck{Name: name, Passed: pass, Reason: reason})
		if !pass {
			blocked = append(blocked, reason)
		}
	}
	generic := strings.HasPrefix(strings.ToLower(r.Title), "potential ") || strings.TrimSpace(r.Title) == ""
	add("specific_title", !generic, "Title must identify the weakness, location, and demonstrated impact.")
	add("detailed_steps", len(r.StepsToReproduce) >= 3, "At least three reproducible steps are required.")
	add("verified_endpoint", r.AffectedEndpoint != "" && !strings.Contains(r.AffectedEndpoint, "<"), "Exact affected production endpoint is not established.")
	add("runtime_evidence", false, "Attach sanitized runtime evidence demonstrating actual impact; static scanner output alone is insufficient.")
	add("scope", r.Scope.Status == "in_scope", "Program scope is not confirmed in-scope.")
	return checks, blocked
}
func adapterFor(platform string) adapters.BountyAdapter {
	switch strings.ToLower(platform) {
	case "bugcrowd":
		return adapters.NewBugcrowdAdapter()
	case "intigriti":
		return adapters.NewIntigritiAdapter()
	case "yeswehack":
		return adapters.NewYesWeHackAdapter()
	case "federacy":
		return adapters.NewFederacyAdapter()
	default:
		return adapters.NewHackerOneAdapter()
	}
}
func appendUnique(values []string, value string) []string {
	for _, v := range values {
		if v == value {
			return values
		}
	}
	return append(values, value)
}
func severityRank(s models.Severity) int {
	switch s {
	case models.SeverityCritical:
		return 4
	case models.SeverityHigh:
		return 3
	case models.SeverityMedium:
		return 2
	default:
		return 1
	}
}
