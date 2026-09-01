package agent

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// Solidity, Kotlin, and Swift files used to be invisible to the zero-day
// heuristic scan because their extensions were missing from sourceExt.
func TestDetectZeroDayPatternsCoversSolidityKotlinSwift(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"Vault.sol":   "contract Vault {\n    function setAdmin() public {\n        isAdmin = true;\n    }\n}\n",
		"Admin.kt":    "fun grant() {\n    isAdmin = true\n}\n",
		"Admin.swift": "func grant() {\n    isAdmin = true\n}\n",
	}
	want := map[string]string{"Vault.sol": "solidity", "Admin.kt": "kotlin", "Admin.swift": "swift"}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	findings, err := DetectZeroDayPatterns(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]string{}
	for _, f := range findings {
		seen[filepath.Base(f.FilePath)] = f.Language
	}
	for name, lang := range want {
		if got, ok := seen[name]; !ok {
			t.Fatalf("expected a zero-day finding in %s, findings=%#v", name, findings)
		} else if got != lang {
			t.Fatalf("expected %s to be tagged language %q, got %q", name, lang, got)
		}
	}
}
