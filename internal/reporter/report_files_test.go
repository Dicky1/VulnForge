package reporter

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestPrivateReportReplacement(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "report.json")
	if err := os.WriteFile(path, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := write(path, []byte("new")); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && st.Mode().Perm() != 0600 {
		t.Fatal(st.Mode())
	}
	b, err := os.ReadFile(path)
	if err != nil || string(b) != "new" {
		t.Fatal(string(b), err)
	}
	if err := atomicReport(path, func(io.Writer) error { return errors.New("render failed") }); err == nil {
		t.Fatal("expected render failure")
	}
	b, err = os.ReadFile(path)
	if err != nil || string(b) != "new" {
		t.Fatal("failed render replaced file")
	}
}
func TestReportReplacementDoesNotFollowDestinationLink(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "original")
	if err := os.WriteFile(outside, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "report")
	if err := os.Symlink(outside, link); err != nil {
		t.Skip(err)
	}
	if err := write(link, []byte("report")); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(outside)
	if err != nil || string(b) != "original" {
		t.Fatal("outside file modified", err)
	}
}
