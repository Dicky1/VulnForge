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

func TestDetectSolidityProject(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"foundry.toml", "Vault.sol"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(""), 0600); err != nil {
			t.Fatal(err)
		}
	}
	dependency := filepath.Join(root, "lib", "dependency")
	if err := os.MkdirAll(dependency, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dependency, "build.py"), []byte(""), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := NewLanguageDetector(root).DetectLanguages()
	if err != nil {
		t.Fatal(err)
	}
	if got["solidity"].FileCount != 2 {
		t.Fatalf("unexpected Solidity detection: %#v", got)
	}
	if _, found := got["python"]; found {
		t.Fatalf("Foundry lib dependency must not affect language planning: %#v", got)
	}
	tools := NewLanguageDetector(root).GetRecommendedToolsForLanguages(got)
	if len(tools["solidity"]) != 1 || tools["solidity"][0] != "slither" {
		t.Fatalf("unexpected Solidity tools: %#v", tools)
	}
}

func TestGradleKotlinScriptDoesNotImplyKotlinSource(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "build.gradle.kts"), []byte("plugins {}"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := NewLanguageDetector(root).DetectLanguages()
	if err != nil {
		t.Fatal(err)
	}
	if _, found := got["kotlin"]; found {
		t.Fatalf("Gradle DSL misdetected as Kotlin source: %#v", got)
	}
	if err := os.WriteFile(filepath.Join(root, "Main.kt"), []byte("fun main() {}"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err = NewLanguageDetector(root).DetectLanguages()
	if err != nil || got["kotlin"].FileCount != 1 {
		t.Fatalf("Kotlin source not detected: %#v, %v", got, err)
	}
}

// A .NET-only or Swift-only project used to be detected but planned with zero
// scanners, since neither language had a catalog entry.
func TestDotnetAndSwiftGetAScannerRecommendation(t *testing.T) {
	root := t.TempDir()
	languages := map[string]LanguageInfo{"dotnet": {Name: "dotnet"}, "swift": {Name: "swift"}}
	tools := NewLanguageDetector(root).GetRecommendedToolsForLanguages(languages)
	if len(tools["dotnet"]) == 0 {
		t.Fatalf("expected at least one scanner recommended for dotnet, got %#v", tools["dotnet"])
	}
	if len(tools["swift"]) == 0 {
		t.Fatalf("expected at least one scanner recommended for swift, got %#v", tools["swift"])
	}
}
