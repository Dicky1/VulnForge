package reporter

import (
	"github.com/example/sast-dast-analyzer/internal/models"
	"path/filepath"
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

// TestConfirmedActiveFindingIsNotExcludedAsPassiveObservation verifies that
// evidence produced by an active probe (PayloadClass set) is treated as
// reproduced impact, not merely "passive response observation" — while a
// finding whose DASTEvidence is a purely passive header/cookie observation
// (PayloadClass empty) is still excluded, exactly as before.
func TestConfirmedActiveFindingIsNotExcludedAsPassiveObservation(t *testing.T) {
	passive := models.Finding{ID: "p1", Title: "Missing Strict-Transport-Security", Severity: models.SeverityLow, DASTEvidence: &models.DASTEvidence{HeaderName: "Strict-Transport-Security"}}
	if reason := bountyExclusionReason(passive, "https://target.example"); reason == "" {
		t.Fatal("expected a passive header observation to still be excluded")
	}

	active := models.Finding{ID: "a1", Title: "Reflected XSS", Severity: models.SeverityHigh, DASTEvidence: &models.DASTEvidence{PayloadClass: "xss.reflected", InjectionPoint: "query:name"}}
	if reason := bountyExclusionReason(active, "https://target.example"); reason != "" {
		t.Fatalf("expected a confirmed active probe result not to be excluded, got reason: %q", reason)
	}
}

// TestRuntimeEvidenceQualityCheckReflectsRealEvidence verifies the
// runtime_evidence quality gate: it must fail when no runtime/curl evidence
// is attached, and pass once a confirmed active probe attaches one.
func TestRuntimeEvidenceQualityCheckReflectsRealEvidence(t *testing.T) {
	base := models.BugBountyReport{
		Title:            "Confirmed SQL Injection at /search",
		StepsToReproduce: []models.BountyStep{{}, {}, {}},
		AffectedEndpoint: "https://target.example/search",
		Scope:            models.ScopeAssessment{Status: "in_scope"},
	}
	withoutEvidence := base
	withoutEvidence.Evidence = []models.BountyEvidence{{Type: "scanner", Note: "Automated evidence only."}}
	_, blocked := qualityChecks(withoutEvidence)
	found := false
	for _, b := range blocked {
		if strings.Contains(b, "runtime evidence") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected runtime_evidence to block without real evidence, blocked=%v", blocked)
	}

	withEvidence := base
	withEvidence.Evidence = []models.BountyEvidence{{Type: "runtime", Note: "Confirmed via active black-box probe"}, {Type: "curl", Note: "curl ..."}}
	checks, blocked := qualityChecks(withEvidence)
	for _, c := range checks {
		if c.Name == "runtime_evidence" && !c.Passed {
			t.Fatal("expected runtime_evidence to pass once real evidence is attached")
		}
	}
	for _, b := range blocked {
		if strings.Contains(b, "runtime evidence") {
			t.Fatalf("runtime_evidence should not still be in blocked reasons: %v", blocked)
		}
	}
}

// TestBountyRuntimeEvidenceIncludesCurlForActiveFindings verifies the
// evidence attached to a bounty report actually carries the reproducible
// curl command for a confirmed active finding, and a clear placeholder
// (never a fabricated curl command) for one with no real evidence.
func TestBountyRuntimeEvidenceIncludesCurlForActiveFindings(t *testing.T) {
	active := models.Finding{DASTEvidence: &models.DASTEvidence{PayloadClass: "sqli.error", InjectionPoint: "query:id", CurlCommand: "curl -sS 'https://target.example/?id=1%27'"}}
	ev := bountyRuntimeEvidence(active)
	var sawCurl bool
	for _, e := range ev {
		if e.Type == "curl" {
			sawCurl = true
			if e.Note != active.DASTEvidence.CurlCommand {
				t.Fatalf("expected the exact captured curl command, got %q", e.Note)
			}
		}
	}
	if !sawCurl {
		t.Fatal("expected a curl evidence entry for a confirmed active finding")
	}

	noEvidence := models.Finding{}
	for _, e := range bountyRuntimeEvidence(noEvidence) {
		if e.Type == "curl" || e.Type == "runtime" {
			t.Fatal("must never fabricate runtime/curl evidence for a finding with no DASTEvidence")
		}
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
	// Build OS-native paths: the test previously hard-coded Windows paths
	// (C:\project\...), which filepath.Rel cannot relate on Linux/macOS.
	root := filepath.Join(string(filepath.Separator)+"tmp", "project")
	reporter := BugBountyReporter{Options: BountyReporterOptions{Target: root, POCFormats: []string{"curl"}, MinSeverity: models.SeverityMedium}}
	findings := []models.Finding{
		{ID: "z", Title: "crypto issue", Severity: models.SeverityHigh, SourceTool: "zeroday-detector", IsZeroDay: true, FilePath: filepath.Join(root, "src", "A.sol")},
		{ID: "dep", Title: "reentrancy", Severity: models.SeverityHigh, SourceTool: "slither", FilePath: filepath.Join(root, "lib", "Dep.sol")},
		{ID: "owned", Title: "reentrancy", Severity: models.SeverityHigh, SourceTool: "slither", FilePath: filepath.Join(root, "src", "Pool.sol")},
	}
	bundle := reporter.BuildBundle(findings, nil)
	if len(bundle.Reports) != 1 || len(bundle.Excluded) != 2 || bundle.InputCount != 3 || bundle.Reports[0].ID != "owned" || bundle.Reports[0].AffectedEndpoint != "<NOT_ESTABLISHED_FROM_STATIC_ANALYSIS>" {
		t.Fatalf("unexpected bundle: %#v", bundle)
	}
}

func TestPOCQuotesUntrustedEndpoint(t *testing.T) {
	poc := POCFormatter{Formats: []string{"curl", "python"}}.Format(models.Finding{}, `https://x.test/"$(id)"`)
	if !strings.Contains(poc.Curl, `'https://x.test/"$(id)"'`) {
		t.Fatalf("endpoint not single-quoted for the shell: %s", poc.Curl)
	}
	if !strings.Contains(poc.Python, `url = "https://x.test/\"$(id)\""`) {
		t.Fatalf("endpoint not escaped for Python: %s", poc.Python)
	}
}
