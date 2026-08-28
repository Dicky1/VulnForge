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
