package scanner

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestClangStandaloneIntegration(t *testing.T) {
	if _, err := exec.LookPath("clang"); err != nil {
		t.Skip("clang executable unavailable")
	}
	ConfigureSandbox(SandboxConfig{})
	t.Cleanup(func() { ConfigureSandbox(SandboxConfig{}) })
	root := t.TempDir()
	file := filepath.Join(root, "fixture.c")
	if err := os.WriteFile(file, []byte("int fixture(void) { int *p = 0; return *p; }\n"), 0600); err != nil {
		t.Fatal(err)
	}
	out, err := NewClangAnalyzerScanner().Scan(context.Background(), root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Findings) != 1 || out.Findings[0].CWE != "CWE-476" || out.Findings[0].FilePath != file {
		t.Fatalf("unexpected: %#v", out.Findings)
	}
	files, err := os.ReadDir(root)
	if err != nil || len(files) != 1 {
		t.Fatalf("scanner modified target: %v %v", files, err)
	}
	if err := os.WriteFile(file, []byte("this is not valid C\n"), 0600); err != nil {
		t.Fatal(err)
	}
	out, err = NewClangAnalyzerScanner().Scan(context.Background(), root, nil)
	if err == nil || out.ExitCode == 0 {
		t.Fatalf("expected incomplete scan, got %#v %v", out, err)
	}
}
