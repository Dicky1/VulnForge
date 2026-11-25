package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/example/sast-dast-analyzer/internal/models"
	"github.com/example/sast-dast-analyzer/internal/storage"
)

func TestRunPassiveDASTWithoutSource(t *testing.T) {
	root := t.TempDir()
	t.Setenv("ANALYZER_ENV_FILE", filepath.Join(root, "absent.env"))
	t.Setenv("ANALYZER_CONFIG", "")
	t.Setenv("ANALYZER_AI_ENABLED", "true")
	t.Setenv("PATH", os.Getenv("PATH"))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start":
			if r.Method != http.MethodGet || r.URL.Query().Get("token") != "query-secret" {
				t.Error("unexpected initial request")
			}
			http.Redirect(w, r, "/landing", http.StatusFound)
		case "/landing":
			if r.Referer() != "" {
				t.Error("redirect leaked the initial URL in Referer")
			}
		default:
			t.Errorf("unexpected request path %q", r.URL.Path)
		}
	}))
	defer server.Close()

	output := filepath.Join(root, "report.json")
	cfg := filepath.Join("..", "..", "config", "config.yaml")
	ctx := context.Background()
	target := server.URL + "/start"
	dbPath := filepath.Join(root, "history.db")
	db, err := storage.OpenSQLite(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	old := models.Report{ID: "baseline", Timestamp: time.Now().UTC().AddDate(0, 0, -100), TargetPath: target, DASTTargetURL: target}
	if _, err := db.SaveReport(ctx, old); err != nil {
		t.Fatal(err)
	}
	args := []string{"--config", cfg, "--dast-url", target + "?token=query-secret#fragment-secret", "--output", output, "--compare-with", old.ID, "--database", dbPath}
	if err := run(ctx, log.New(io.Discard, "", 0), args); err != nil {
		t.Fatal(err)
	}
	if _, err := db.GetReportByID(ctx, old.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expired baseline should be pruned after comparing, got %v", err)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "query-secret") || strings.Contains(string(data), "fragment-secret") {
		t.Fatal("query or fragment leaked into report")
	}
	var report models.Report
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	if report.TargetPath != target || report.DASTTargetURL != target || report.Language != "web" {
		t.Fatalf("unexpected report target %q, DAST target %q, language %q", report.TargetPath, report.DASTTargetURL, report.Language)
	}
	stored, err := db.GetReportByID(ctx, report.ID)
	if err != nil {
		t.Fatalf("current report was not saved: %v", err)
	}
	if !slices.Equal(stored.DASTEndpoints, report.DASTEndpoints) || len(stored.DASTEndpoints) != 1 {
		t.Fatal("SQLite lost the HTTP endpoint outcome")
	}
	if len(report.Findings) == 0 || len(report.IncompleteChecks) != 0 || report.TokenUsed != 0 {
		t.Fatalf("unexpected finding count, scan coverage or token usage: %d, %v, %d", len(report.Findings), report.IncompleteChecks, report.TokenUsed)
	}
	for _, finding := range report.Findings {
		if finding.SourceTool != "baseline-dast" {
			t.Errorf("source scan unexpectedly ran: %s", finding.SourceTool)
		}
	}
}

func TestRunExportsIncompleteSourceScan(t *testing.T) {
	root := t.TempDir()
	t.Setenv("ANALYZER_ENV_FILE", filepath.Join(root, "absent.env"))
	t.Setenv("ANALYZER_AUTO_INSTALL", "false")
	t.Setenv("ANALYZER_AI_ENABLED", "false")
	t.Setenv("ANALYZER_SANDBOX_ENABLED", "true")
	t.Setenv("PATH", os.Getenv("PATH"))
	cfg := filepath.Join(root, "config.yaml")
	if err := os.WriteFile(cfg, []byte("sandbox:\n  images:\n    gosec: \"\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\nfunc main() {}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(root, "report.json")
	args := []string{"--target", root, "--config", cfg, "--output", output}
	if err := run(context.Background(), log.New(io.Discard, "", 0), args); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var report models.Report
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(report.IncompleteChecks, "gosec") {
		t.Errorf("unavailable Go scanner missing from coverage: %v", report.IncompleteChecks)
	}
}

func TestDASTManifestExportsEndpointOutcomes(t *testing.T) {
	root := t.TempDir()
	t.Setenv("ANALYZER_ENV_FILE", filepath.Join(root, "absent.env"))
	t.Setenv("PATH", os.Getenv("PATH"))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			w.WriteHeader(http.StatusOK)
		case "/missing":
			w.WriteHeader(http.StatusNotFound)
		case "/unavailable":
			w.WriteHeader(http.StatusServiceUnavailable)
		case "/busy":
			w.WriteHeader(http.StatusTooManyRequests)
		default:
			t.Error("unexpected request outside the manifest")
		}
	}))
	defer srv.Close()
	manifest := filepath.Join(root, "endpoints.yaml")
	if err := os.WriteFile(manifest, []byte("origin: "+srv.URL+"\npaths: [/ok, /missing, /unavailable, /busy, /after]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(root, "config.yaml")
	if err := os.WriteFile(cfg, []byte("analyzer:\n  target_path: does-not-exist\n"), 0600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(root, "report.json")
	args := []string{"dast", "--dast-targets", manifest, "--config", cfg, "--dast-interval", "0", "--output", output,
		"--export-format", "json,html,xml,sarif,pdf"}
	if err := run(context.Background(), log.New(io.Discard, "", 0), args); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var report models.Report
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	if report.TargetPath != srv.URL+"/" || !slices.Contains(report.IncompleteChecks, "baseline-dast") || len(report.DASTEndpoints) != 5 {
		t.Fatalf("unexpected DAST target or coverage: %q, %v, %v", report.TargetPath, report.IncompleteChecks, report.DASTEndpoints)
	}
	if report.DASTEndpoints[0].StatusCode != 200 || report.DASTEndpoints[0].Error != "" ||
		report.DASTEndpoints[1].StatusCode != 404 || report.DASTEndpoints[1].Error != "http_not_found" ||
		report.DASTEndpoints[2].StatusCode != 503 || report.DASTEndpoints[2].Error != "http_server_error" ||
		report.DASTEndpoints[3].StatusCode != 429 || report.DASTEndpoints[3].Error != "http_rate_limited" ||
		report.DASTEndpoints[4].StatusCode != 0 || report.DASTEndpoints[4].Error != "skipped_after_rate_limit" {
		t.Fatalf("unexpected endpoint outcomes: %+v", report.DASTEndpoints)
	}
	if len(report.Findings) == 0 {
		t.Fatal("successful endpoint should have baseline findings")
	}
	for _, finding := range report.Findings {
		if finding.DASTEvidence == nil || finding.DASTEvidence.Endpoint.FinalURL != srv.URL+"/ok" {
			t.Fatal("findings must reference the checked endpoint")
		}
	}
	for _, ext := range []string{"html", "xml", "sarif"} {
		data, err := os.ReadFile(filepath.Join(root, "report."+ext))
		if err != nil || !strings.Contains(string(data), "http_not_found") {
			t.Fatalf("%s export missing endpoint result: %v", ext, err)
		}
	}
}
