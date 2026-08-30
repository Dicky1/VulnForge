package reporter

import (
	"github.com/example/sast-dast-analyzer/internal/models"
	"strings"
	"testing"
)

func TestScopeMapper(t *testing.T) {
	program := &models.BountyProgram{Name: "Target", Domains: []string{"*.target.com", "target.com"}, OutOfScope: []string{"staging.target.com"}}
	mapper := ScopeMapper{}
	in := mapper.DetermineScopeStatus(models.Finding{Description: "https://api.target.com/users"}, program)
	if in.Status != "in_scope" {
		t.Fatalf("unexpected: %#v", in)
	}
	out := mapper.DetermineScopeStatus(models.Finding{Description: "https://staging.target.com/users"}, program)
	if out.Status != "out_of_scope" {
		t.Fatalf("unexpected: %#v", out)
	}
}

func TestStaticBountyReportIsBlockedWithoutInventedEvidence(t *testing.T) {
	f := models.Finding{ID: "f1", Title: "reentrancy-no-eth", Description: "external call before state update", Severity: models.SeverityHigh, CVSSBase: 8, CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", CWE: "CWE-841", SourceTool: "slither", Language: "solidity", FilePath: "src/Pool.sol", LineNumber: 42}
	r, err := (&BugBountyReporter{Options: BountyReporterOptions{Platform: "hackerone", POCFormats: []string{"curl", "python"}, MinSeverity: models.SeverityMedium}}).GenerateReadyToSubmitReport(f, nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.ReadyToSubmit || r.Scope.Status != "unknown" || !strings.Contains(r.AffectedEndpoint, "NOT_ESTABLISHED") {
		t.Fatalf("unsafe readiness: %#v", r)
	}
	if strings.Contains(strings.ToLower(r.ProofOfConcept.Curl), "169.254.169.254") || strings.Contains(strings.ToLower(r.ProofOfConcept.Curl), "union select") {
		t.Fatal("destructive or data-extraction payload generated")
	}
}

func TestBountyBundleDeduplicates(t *testing.T) {
	f := models.Finding{ID: "f1", Title: "SQL injection", Severity: models.SeverityHigh, FilePath: "api.go", LineNumber: 1}
	reporter := BugBountyReporter{Options: BountyReporterOptions{POCFormats: []string{"curl"}, MinSeverity: models.SeverityMedium}}
	bundle := reporter.BuildBundle([]models.Finding{f, f}, nil)
	if len(bundle.Reports) != 1 || bundle.BlockedCount != 1 {
		t.Fatalf("unexpected bundle: %#v", bundle)
	}
}

func TestBountyBundleExcludesHeuristicsAndDependencies(t *testing.T) {
	reporter := BugBountyReporter{Options: BountyReporterOptions{Target: `C:\project`, POCFormats: []string{"curl"}, MinSeverity: models.SeverityMedium}}
	findings := []models.Finding{
		{ID: "z", Title: "crypto issue", Severity: models.SeverityHigh, SourceTool: "zeroday-detector", IsZeroDay: true, FilePath: `C:\project\src\A.sol`},
		{ID: "dep", Title: "reentrancy", Severity: models.SeverityHigh, SourceTool: "slither", FilePath: `C:\project\lib\Dep.sol`},
		{ID: "owned", Title: "reentrancy", Severity: models.SeverityHigh, SourceTool: "slither", FilePath: `C:\project\src\Pool.sol`},
	}
	bundle := reporter.BuildBundle(findings, nil)
	if len(bundle.Reports) != 1 || len(bundle.Excluded) != 2 || bundle.InputCount != 3 || bundle.Reports[0].ID != "owned" || bundle.Reports[0].AffectedEndpoint != "<NOT_ESTABLISHED_FROM_STATIC_ANALYSIS>" {
		t.Fatalf("unexpected bundle: %#v", bundle)
	}
}
