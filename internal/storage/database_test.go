package storage

import (
	"context"
	"github.com/example/sast-dast-analyzer/internal/models"
	"path/filepath"
	"testing"
	"time"
)

func TestSQLiteHistoryAndComparison(t *testing.T) {
	db, err := OpenSQLite(filepath.Join(t.TempDir(), "history.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	a := models.Report{ID: "a", Timestamp: time.Now().Add(-time.Hour), TargetPath: "x", Findings: []models.Finding{{ID: "old", Severity: models.SeverityHigh}}}
	b := models.Report{ID: "b", Timestamp: time.Now(), TargetPath: "x", Findings: []models.Finding{{ID: "new", Severity: models.SeverityCritical}}}
	if _, err = db.SaveReport(ctx, a); err != nil {
		t.Fatal(err)
	}
	if _, err = db.SaveReport(ctx, b); err != nil {
		t.Fatal(err)
	}
	comparison, err := db.CompareReports(ctx, "a", "b")
	if err != nil {
		t.Fatal(err)
	}
	if len(comparison.NewFindings) != 1 || len(comparison.FixedFindings) != 1 {
		t.Fatalf("unexpected %#v", comparison)
	}
	history, err := db.GetReportHistory(ctx, "x", 10)
	if err != nil || len(history) != 2 {
		t.Fatalf("history: %#v %v", history, err)
	}
}
