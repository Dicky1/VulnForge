package sbom

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateSBOM(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "requirements.txt"), []byte("requests==2.32.0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	bom, err := NewSBOMGenerator().GenerateSBOM(root, "cyclonedx")
	if err != nil {
		t.Fatal(err)
	}
	if len(bom.Components) != 1 || bom.Components[0].PURL != "pkg:pypi/requests@2.32.0" {
		t.Fatalf("unexpected %#v", bom)
	}
}

func TestGenerateSBOMSkipsLinkedManifest(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte("private-package==1.0.0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "requirements.txt")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	bom, err := NewSBOMGenerator().GenerateSBOM(root, "cyclonedx")
	if err != nil {
		t.Fatal(err)
	}
	if len(bom.Components) != 0 {
		t.Fatalf("read dependencies from outside target: %#v", bom.Components)
	}
}
