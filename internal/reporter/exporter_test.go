package reporter

import (
	"encoding/json"
	"github.com/example/sast-dast-analyzer/internal/models"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestExportFormats(t *testing.T) {
	r := models.Report{Timestamp: time.Now(), TargetPath: "project", Language: "go", TotalFindings: 1, HighCount: 1, Findings: []models.Finding{{ID: "f1", Title: "Issue", Severity: models.SeverityHigh, CWE: "CWE-89", FilePath: "main.go", LineNumber: 2, Description: "SQL injection"}}}
	e := NewReportExporter()
	for _, format := range []string{"json", "html", "pdf", "sarif", "xml", "csv"} {
		path := filepath.Join(t.TempDir(), "report."+format)
		if err := e.Export(r, format, path); err != nil {
			t.Fatalf("%s: %v", format, err)
		}
		info, err := os.Stat(path)
		if err != nil || info.Size() == 0 {
			t.Fatalf("%s empty", format)
		}
	}
	path := filepath.Join(t.TempDir(), "x.sarif")
	if err := e.ExportSARIF(r, path); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	b, _ := os.ReadFile(path)
	if err := json.Unmarshal(b, &doc); err != nil || doc["version"] != "2.1.0" {
		t.Fatalf("invalid SARIF")
	}
}

func TestExportBountyBundle(t *testing.T) {
	dir := t.TempDir()
	r := models.Report{BountyBundle: &models.BountyBundle{Target: "project", BlockedCount: 1, Reports: []models.BugBountyReport{{ID: "f1", Platform: "hackerone", Title: "Specific issue in endpoint affects access", Severity: "HIGH", AffectedEndpoint: "<NOT_ESTABLISHED_FROM_STATIC_ANALYSIS>", Scope: models.ScopeAssessment{Status: "unknown"}, BlockingReasons: []string{"runtime evidence required"}}}}}
	path := filepath.Join(dir, "report.bounty.json")
	if err := NewReportExporter().ExportBountyBundle(r, path); err != nil {
		t.Fatal(err)
	}
	for _, ext := range []string{".json", ".md", ".txt", ".html", ".pdf"} {
		file := filepath.Join(dir, "report.bounty"+ext)
		if info, err := os.Stat(file); err != nil || info.Size() == 0 {
			t.Fatalf("missing %s", file)
		}
	}
}
