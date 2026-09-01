package parser

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseREADMEOnlyCodeBlocks(t *testing.T) {
	p := filepath.Join(t.TempDir(), "README.md")
	body := "pip install ignored\n```sh\npip install semgrep\nexport TOKEN=value\n```\n"
	if err := os.WriteFile(p, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	m, err := ParseREADME(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(m["semgrep"].InstallCmds) != 1 {
		t.Fatalf("unexpected setup: %#v", m)
	}
	if m["project"].EnvVars["TOKEN"] != "value" {
		t.Fatal("environment variable not parsed")
	}
}

// A malicious target README must not be able to smuggle an extra,
// attacker-chosen package name onto a recognized install line.
func TestParseREADMERejectsSmuggledPackageNames(t *testing.T) {
	p := filepath.Join(t.TempDir(), "README.md")
	body := "```sh\npip install evil-package semgrep\n```\n"
	if err := os.WriteFile(p, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	m, err := ParseREADME(p)
	if err != nil {
		t.Fatal(err)
	}
	if setup := m["semgrep"]; setup != nil && len(setup.InstallCmds) > 0 {
		t.Fatalf("expected the smuggled install line to be rejected, got %#v", setup.InstallCmds)
	}
}
