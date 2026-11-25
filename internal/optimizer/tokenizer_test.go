package optimizer

import (
	"testing"
	"github.com/example/sast-dast-analyzer/internal/models"
)

func TestFilterFindingsPreservesLowSeverityAndDoesNotTruncate(t *testing.T) {
	in := []models.Finding{
		{ID: "low", Title: "Missing header", Severity: models.SeverityLow, FilePath: "https://example.com"},
		{ID: "high", Title: "Risk", Severity: models.SeverityHigh, FilePath: "main.go", LineNumber: 1},
	}
	got := (Tokenizer{Budget: 1}).FilterFindings(in)
	if len(got) != 2 {
		t.Fatalf("expected all evidence retained regardless of token budget, got %d", len(got))
	}
	if got[0].ID != "high" { t.Fatalf("expected sorted high severity first, got %+v", got) }
}
