package storage

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/example/sast-dast-analyzer/internal/models"
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

func TestSQLiteIncompleteAndDifferentScopeComparisons(t *testing.T) {
	db, err := OpenSQLite(filepath.Join(t.TempDir(), "history.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	reports := []models.Report{
		{ID: "source", Timestamp: now, TargetPath: "app", Findings: []models.Finding{{ID: "old", Severity: models.SeverityHigh}}},
		{ID: "partial", Timestamp: now.Add(time.Second), TargetPath: "app", IncompleteChecks: []string{"gosec"}},
		{ID: "mixed", Timestamp: now.Add(2 * time.Second), TargetPath: "app", DASTTargetURL: "https://example.test/"},
		{ID: "different-paths", Timestamp: now.Add(3 * time.Second), TargetPath: "app", DASTTargetURL: "https://example.test/", DASTEndpoints: []models.DASTEndpoint{{RequestedURL: "https://example.test/login"}}},
		{ID: "session", Timestamp: now.Add(4 * time.Second), TargetPath: "app", DASTTargetURL: "https://example.test/", DASTSession: "cookie"},
	}
	for _, r := range reports {
		if _, err := db.SaveReport(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct{ id, want string }{
		{"partial", "completed scans"},
		{"mixed", "different source or DAST targets"},
	} {
		if _, err := db.CompareReports(ctx, "source", tc.id); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("comparison with %s: got %v, want %q", tc.id, err, tc.want)
		}
	}
	for _, id := range []string{"different-paths", "session"} {
		if _, err := db.CompareReports(ctx, "mixed", id); err == nil || !strings.Contains(err.Error(), "different DAST endpoint lists or session modes") {
			t.Errorf("comparison with %s should reject different coverage, got %v", id, err)
		}
	}
	var high, resolved int
	if err := db.db.QueryRowContext(ctx, "SELECT high_count,resolved_count FROM trend_analysis WHERE target_path='app'").Scan(&high, &resolved); err != nil {
		t.Fatal(err)
	}
	if high != 1 || resolved != 0 {
		t.Fatalf("partial or mixed scan changed source-only trend: high=%d resolved=%d", high, resolved)
	}
}
