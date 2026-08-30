package reporter

import (
	"strings"
	"testing"

	"github.com/example/sast-dast-analyzer/internal/models"
)

func testBusinessContext() models.BusinessContext {
	return models.BusinessContext{BusinessType: "fintech", AnnualRevenue: 10_000_000_000, NumUsers: 1_000_000, PrimaryCompliance: []string{"gdpr"}, Multipliers: map[string]float64{"fintech": 10}, Penalties: map[string]float64{"gdpr": .04}}
}

func TestBusinessImpactAndPriority(t *testing.T) {
	f := models.Finding{ID: "one", Title: "SQL injection", Description: "unsafe query", Severity: models.SeverityCritical, CVSSBase: 9.8, CWE: "CWE-89"}
	impact := (BusinessImpactCalculator{Context: testBusinessContext()}).CalculateBusinessImpact(f)
	if impact.AffectedUsers != 1_000_000 || impact.RevenueRiskMin != 1_000_000_000 || impact.ComplianceImpact["gdpr"] != 400_000_000 {
		t.Fatalf("unexpected impact: %#v", impact)
	}
	if score := (RiskMatrix{}).CalculatePriorityScore(models.SeverityCritical, "critical"); score != 1 {
		t.Fatalf("priority = %d", score)
	}
}

func TestBuildBusinessReportAndSafePOC(t *testing.T) {
	f := models.Finding{ID: "one", Title: "SQL injection", Description: "unsafe query", Severity: models.SeverityHigh, CVSSBase: 8, FilePath: "api.go", LineNumber: 10}
	r := BuildBusinessReport([]models.Finding{f}, testBusinessContext(), BusinessReportOptions{EnablePOC: true, EnableRoadmap: true, POCSkillLevel: "basic"})
	if len(r.Findings) != 1 || r.Findings[0].POC == nil || len(r.Roadmap.Phases) != 6 {
		t.Fatalf("unexpected report: %#v", r)
	}
	if strings.Contains(strings.ToLower(r.Findings[0].POC.CurlExample), "169.254.169.254") {
		t.Fatal("POC must not target cloud metadata")
	}
}
