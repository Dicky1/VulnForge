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
