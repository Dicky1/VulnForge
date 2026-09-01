package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFoundryNeedsHostForge(t *testing.T) {
	foundryProject := t.TempDir()
	if err := os.WriteFile(filepath.Join(foundryProject, "foundry.toml"), []byte(""), 0600); err != nil {
		t.Fatal(err)
	}
	plainProject := t.TempDir()

	cases := []struct {
		name      string
		target    string
		sandboxed bool
		want      bool
	}{
		{"Foundry project, unsandboxed, needs host forge", foundryProject, false, true},
		{"Foundry project, sandboxed image already bundles forge", foundryProject, true, false},
		{"non-Foundry project never needs forge", plainProject, false, false},
	}
	for _, c := range cases {
		if got := foundryNeedsHostForge(c.target, c.sandboxed); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}
