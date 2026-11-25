package integrations

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteGeneratedFileDoesNotClobber(t *testing.T) {
	p := filepath.Join(t.TempDir(), "ci", "Jenkinsfile")
	if err := WriteGeneratedFile(p, "new", false); err != nil {
		t.Fatal(err)
	}
	if err := WriteGeneratedFile(p, "other", false); !errors.Is(err, ErrExists) {
		t.Fatalf("expected ErrExists, got %v", err)
	}
	b, _ := os.ReadFile(p)
	if string(b) != "new" {
		t.Fatalf("existing file was overwritten: %q", b)
	}
}

func TestWriteGeneratedFileWithinRejectsSymlink(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "ci")); err != nil {
		t.Skip(err)
	}
	if err := WriteGeneratedFileWithin(root, filepath.Join(root, "ci", "x"), "x", false); err == nil {
		t.Fatal("symlink parent accepted")
	}
	if _, err := os.Stat(filepath.Join(outside, "x")); !os.IsNotExist(err) {
		t.Fatal("unexpected outside write")
	}
}
