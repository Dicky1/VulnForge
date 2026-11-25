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

func TestSecretDetectorSkipsSymlinks(t *testing.T) {
	root := t.TempDir()
	external := filepath.Join(t.TempDir(), "private.go")
	if err := os.WriteFile(external, []byte(`package x; const key="AKIA1234567890ABCDEF"`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, filepath.Join(root, "linked.go")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	got, err := NewSecretDetector().Scan(context.Background(), root)
	if err != nil || len(got) != 0 {
		t.Fatalf("outside-target link must not be scanned: %v, %v", got, err)
	}
}

func TestSecretDetectorExclusionsMatchComponents(t *testing.T) {
	d := NewSecretDetector()
	if d.excluded("vendorized/app.go") || !d.excluded("src/vendor/app.go") {
		t.Fatal("exclusions must match complete path components")
	}
}

func TestLongLineDoesNotAbortScan(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.js"), []byte(strings.Repeat("x", (1<<20)+64)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "b.go"), []byte(`package x; const key="AKIA1234567890ABCDEF" // test configuration`), 0600); err != nil {
		t.Fatal(err)
	}
	findings, err := NewSecretDetector().Scan(context.Background(), root)
	if err != nil || len(findings) != 1 {
		t.Fatalf("expected later finding, got %d %v", len(findings), err)
	}
}
