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

// .sol files used to be skipped entirely by secretExtension, hiding hardcoded
// AWS-style credentials embedded in Solidity source (e.g. deployment scripts).
func TestSecretDetectorScansSolidityFiles(t *testing.T) {
	root := t.TempDir()
	secret := "AKIA1234567890ABCDEF"
	body := "// SPDX-License-Identifier: MIT\ncontract Deployer {\n    string constant KEY = \"" + secret + "\";\n}\n"
	if err := os.WriteFile(filepath.Join(root, "Deployer.sol"), []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := NewSecretDetector().Scan(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("expected the secret in the .sol file to be detected, got %d findings", len(got))
	}
}
