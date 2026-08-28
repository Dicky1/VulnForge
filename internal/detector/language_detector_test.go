package detector

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectLanguages(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"go.mod", "main.go", "package.json", "app.ts"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(""), 0600); err != nil {
			t.Fatal(err)
		}
	}
	got, err := NewLanguageDetector(root).DetectLanguages()
	if err != nil {
		t.Fatal(err)
	}
	if got["go"].FileCount != 2 || got["javascript"].FileCount != 2 {
		t.Fatalf("unexpected: %#v", got)
	}
}

func TestFindProjectRoot(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0700); err != nil {
		t.Fatal(err)
	}
	nested := filepath.Join(root, "src", "pkg")
	if err := os.MkdirAll(nested, 0700); err != nil {
		t.Fatal(err)
	}
	if got := NewLanguageDetector(nested).FindProjectRoot(); got != root {
		t.Fatalf("got %s, want %s", got, root)
	}
}
