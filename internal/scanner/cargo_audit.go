package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/example/sast-dast-analyzer/internal/models"
)

type CargoAuditScanner struct{}

func NewCargoAuditScanner() *CargoAuditScanner { return &CargoAuditScanner{} }
func (*CargoAuditScanner) Name() string        { return "cargo-audit" }
func (*CargoAuditScanner) Language() string    { return "rust" }
func (*CargoAuditScanner) IsInstalled() bool   { return installed("cargo-audit") }
func (*CargoAuditScanner) Install(ctx context.Context) error {
	return installCommand(ctx, "cargo", "install", "cargo-audit", "--locked")
}
func (s *CargoAuditScanner) Scan(ctx context.Context, target string, _ *models.ScanConfig) (*models.ToolOutput, error) {
	r, err := run(ctx, multiScannerTimeout, target, "cargo", "audit", "--json")
	if err != nil {
		return output(s.Name(), r, nil), err
	}
	f, e := s.ParseOutput(r.data)
	return output(s.Name(), r, f), e
}
func (*CargoAuditScanner) ParseOutput(raw []byte) ([]models.Finding, error) {
	var d struct {
		Vulnerabilities struct {
			List []struct {
				Advisory struct {
					ID, Title, Description, Severity string
					CVE                              string `json:"cve"`
					URL                              string
				}
				Package struct{ Name, Version string }
			} `json:"list"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, err
	}
	var out []models.Finding
	for _, x := range d.Vulnerabilities.List {
		id := x.Advisory.ID
		if id == "" {
			id = x.Advisory.CVE
		}
		desc := fmt.Sprintf("%s %s: %s (%s)", x.Package.Name, x.Package.Version, x.Advisory.Description, x.Advisory.URL)
		out = append(out, languageFinding("cargo-audit", "rust", id, "Cargo.lock", 0, x.Advisory.Title, desc, x.Advisory.Severity, "", "CWE-1104"))
	}
	return out, nil
}
