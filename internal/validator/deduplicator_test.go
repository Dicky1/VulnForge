package validator

import (
	"github.com/example/sast-dast-analyzer/internal/models"
	"testing"
)

func TestDeduplicateKeepsHigherCVSS(t *testing.T) {
	in := []models.Finding{{ID: "a", CWE: "CWE-1", FilePath: "x", CVSSBase: 4}, {ID: "a", CWE: "CWE-1", FilePath: "x", CVSSBase: 9}}
	got := Deduplicate(in)
	if len(got) != 1 || got[0].CVSSBase != 9 {
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

func TestDeduplicateKeepsDistinctAdvisoriesWithoutLine(t *testing.T) {
	in := []models.Finding{
		{ID: "a", Title: "RUSTSEC-2024-0001", CWE: "CWE-1104", FilePath: "Cargo.lock", SourceTool: "cargo-audit"},
		{ID: "b", Title: "RUSTSEC-2024-0002", CWE: "CWE-1104", FilePath: "Cargo.lock", SourceTool: "cargo-audit"},
	}
	if got := Deduplicate(in); len(got) != 2 {
		t.Fatalf("distinct advisories on the same lockfile were merged: %#v", got)
	}
}

func TestDistinctChecksAndPackagesArePreserved(t *testing.T) {
	in := []models.Finding{
		{ID: "same", SourceTool: "trivy", Title: "same", FilePath: "image", Description: "package A"},
		{ID: "same", SourceTool: "trivy", Title: "same", FilePath: "image", Description: "package B"},
		{ID: "distinct", SourceTool: "trivy", Title: "same", FilePath: "image", Description: "package B"},
	}
	got := Deduplicate(in)
	if len(got) != 3 {
		t.Fatalf("lost finding: %v", got)
	}
	if got[0].ID == got[1].ID {
		t.Fatal("duplicate storage identity")
	}
}
