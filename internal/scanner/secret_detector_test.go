package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSecretDetectorRedacts(t *testing.T) {
	root := t.TempDir()
	secret := "AKIA1234567890ABCDEF"
	if err := os.WriteFile(filepath.Join(root, "app.go"), []byte(`package x; const key="`+secret+`"`), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := NewSecretDetector().Scan(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d", len(got))
	}
	if strings.Contains(got[0].CodeSnippet, secret) {
		t.Fatal("secret leaked into finding")
	}
}
