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
