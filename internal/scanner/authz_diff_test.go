package scanner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/example/sast-dast-analyzer/internal/models"
)

func TestAuthzDiffFlagsCrossUserAccess(t *testing.T) {
	// Admin endpoint returns same body for both admin and guest -> flag.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"secret":"admin-data"}`))
	}))
	defer srv.Close()

	m := models.AuthzMatrix{
		Origin: srv.URL,
		Sessions: []models.AuthzSession{
			{Name: "admin", Role: "admin", Kind: "bearer", Value: "admin-token", Priority: 10},
			{Name: "guest", Role: "guest", Kind: "bearer", Value: "guest-token", Priority: 1},
		},
		Endpoints: []string{"/admin/secret"},
	}
	findings, probes, err := (AuthzDiffEngine{Timeout: 5 * 1000000000}).Probe(context.Background(), m)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	if len(probes) != 2 {
		t.Fatalf("expected 2 probes, got %d", len(probes))
	}
	b, _ := json.Marshal(findings[0])
	if !containsStr(string(b), "Potential unauthorized") {
		t.Fatalf("unexpected finding: %s", b)
	}
}

func TestAuthzDiffNoFlagWhenDenied(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer admin-token" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"secret":"admin-data"}`))
			return
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	m := models.AuthzMatrix{
		Origin: srv.URL,
		Sessions: []models.AuthzSession{
			{Name: "admin", Role: "admin", Kind: "bearer", Value: "admin-token", Priority: 10},
			{Name: "guest", Role: "guest", Kind: "bearer", Value: "guest-token", Priority: 1},
		},
		Endpoints: []string{"/admin/secret"},
	}
	findings, _, err := (AuthzDiffEngine{Timeout: 5 * 1000000000}).Probe(context.Background(), m)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}

func containsStr(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
