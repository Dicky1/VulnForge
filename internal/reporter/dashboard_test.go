package reporter

import (
	"os"
	"path/filepath"
	"runtime"
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
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("report is readable by other users: %v", info.Mode().Perm())
	}
}

// TestDashboardRendersAndEscapesDASTEvidence verifies that active-DAST
// evidence — which routinely contains the exact attack payload (e.g. a
// reflected-XSS canary) in the captured request/response body and in the
// generated curl command — is both displayed and safely HTML-escaped, so
// opening the report itself can never execute the payload it is reporting.
func TestDashboardRendersAndEscapesDASTEvidence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "r.html")
	r := models.Report{TargetPath: "https://target.example", Findings: []models.Finding{
		{
			ID: "dast-1", Title: "Reflected Cross-Site Scripting (XSS)", Severity: models.SeverityHigh,
			DASTEvidence: &models.DASTEvidence{
				PayloadClass:   "xss.reflected",
				InjectionPoint: "query:name",
				Request:        &models.RequestEvidence{Method: "GET", URL: `https://target.example/?name=<script>alert(document.cookie)</script>`},
				Response:       &models.ResponseEvidence{StatusCode: 200, Body: `<html>hi <script>alert(document.cookie)</script></html>`},
				CurlCommand:    `curl -sS -X 'GET' 'https://target.example/?name=<script>alert(1)</script>'`,
				OOBInteraction: &models.OOBInteraction{SourceIP: "203.0.113.5", Protocol: "http"},
			},
		},
	}, TotalFindings: 1}
	if err := renderDashboard(r, path); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	html := string(b)
	if strings.Contains(html, "<script>alert") {
		t.Fatal("raw <script> payload from DAST evidence was not HTML-escaped: report would execute attacker payload when opened")
	}
	for _, want := range []string{"query:name", "xss.reflected", "Status 200", "OOB confirmed", "203.0.113.5", "Reproduce"} {
		if !strings.Contains(html, want) {
			t.Errorf("expected rendered evidence to contain %q", want)
		}
	}
}
