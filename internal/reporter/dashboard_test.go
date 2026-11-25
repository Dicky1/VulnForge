package reporter

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/example/sast-dast-analyzer/internal/models"
)

func TestDashboardRendersPieAndEscapesFindings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "r.html")
	r := models.Report{TargetPath: "/x", Findings: []models.Finding{
		{ID: "a", Title: `<script>alert(1)</script>`, Severity: models.SeverityCritical},
		{ID: "b", Title: "b", Severity: models.SeverityLow},
	}, TotalFindings: 2}
	if err := renderDashboard(r, path); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	html := string(b)
	if strings.Contains(html, "ZgotmplZ") {
		t.Fatal("pie chart CSS was rejected by html/template (ZgotmplZ)")
	}
	if strings.Contains(html, "<script>alert(1)</script>") {
		t.Fatal("finding title was not HTML-escaped")
	}
	if info, err := os.Stat(path); err == nil && info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("report is readable by other users: %v", info.Mode().Perm())
	}
}
