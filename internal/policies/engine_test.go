package policies

import (
	"github.com/example/sast-dast-analyzer/internal/models"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadAndApplyPolicy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "p.yaml")
	body := `policy:
  name: test
  version: "1"
  rules:
    - {name: sql, type: cwe, cwe: 89, enabled: true, severity: critical}
filtering: {minimum_severity: medium}
compliance: {frameworks: [owasp-top-10]}
`
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	engine := NewPolicyEngine()
	p, err := engine.LoadPolicy(path)
	if err != nil {
		t.Fatal(err)
	}
	got := engine.ApplyPolicy([]models.Finding{{CWE: "CWE-89", Severity: models.SeverityMedium}}, p)
	if len(got) != 1 || got[0].Severity != models.SeverityCritical {
		t.Fatalf("unexpected %#v", got)
	}
}
