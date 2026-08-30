package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadEnvFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(path, []byte("# config\nANALYZER_TEST_VALUE=from-file\nANALYZER_TEST_QUOTED=\"hello world\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ANALYZER_TEST_VALUE", "from-shell")
	if err := LoadEnvFile(path); err != nil {
		t.Fatal(err)
	}
	if got := os.Getenv("ANALYZER_TEST_VALUE"); got != "from-shell" {
		t.Fatalf("shell value was overwritten: %q", got)
	}
	if got := os.Getenv("ANALYZER_TEST_QUOTED"); got != "hello world" {
		t.Fatalf("quoted value = %q", got)
	}
}
