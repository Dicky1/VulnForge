package validator

import (
	"github.com/example/sast-dast-analyzer/internal/models"
	"testing"
)

func TestDeduplicateKeepsHigherCVSS(t *testing.T) {
	in := []models.Finding{{ID: "a", CWE: "CWE-1", FilePath: "x", CVSSBase: 4}, {ID: "b", CWE: "CWE-1", FilePath: "x", CVSSBase: 9}}
	got := Deduplicate(in)
	if len(got) != 1 || got[0].ID != "b" {
		t.Fatalf("got %#v", got)
	}
}

func TestDeduplicateKeepsDistinctLinesWithSameCWE(t *testing.T) {
	in := []models.Finding{
		{ID: "a", CWE: "CWE-89", FilePath: "x.go", LineNumber: 10, CVSSBase: 7},
		{ID: "b", CWE: "CWE-89", FilePath: "x.go", LineNumber: 42, CVSSBase: 7},
	}
	got := Deduplicate(in)
	if len(got) != 2 {
		t.Fatalf("expected two distinct findings on different lines to survive, got %#v", got)
	}
}
