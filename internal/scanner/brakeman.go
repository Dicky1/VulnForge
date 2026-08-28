package scanner

import (
	"context"
	"encoding/json"
	"github.com/example/sast-dast-analyzer/internal/models"
)

type BrakemanScanner struct{}

func NewBrakemanScanner() *BrakemanScanner { return &BrakemanScanner{} }
func (*BrakemanScanner) Name() string      { return "brakeman" }
func (*BrakemanScanner) Language() string  { return "ruby" }
func (*BrakemanScanner) IsInstalled() bool { return installed("brakeman") }
func (*BrakemanScanner) Install(ctx context.Context) error {
	return installCommand(ctx, "gem", "install", "brakeman", "--no-document")
}
func (s *BrakemanScanner) Scan(ctx context.Context, target string, _ *models.ScanConfig) (*models.ToolOutput, error) {
	r, err := run(ctx, multiScannerTimeout, target, "brakeman", "-f", "json")
	if err != nil {
		return output(s.Name(), r, nil), err
	}
	f, e := s.ParseOutput(r.data)
	return output(s.Name(), r, f), e
}
func (*BrakemanScanner) ParseOutput(raw []byte) ([]models.Finding, error) {
	var d struct {
		Warnings []struct {
			WarningType               string `json:"warning_type"`
			Message, File, Confidence string
			Line                      int
			CWEID                     any `json:"cwe_id"`
		} `json:"warnings"`
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, err
	}
	var out []models.Finding
	for _, x := range d.Warnings {
		cwe := ""
		if x.CWEID != nil {
			b, _ := json.Marshal(x.CWEID)
			cwe = "CWE-" + string(b)
		}
		sev := map[string]string{"High": "CRITICAL", "Medium": "HIGH", "Weak": "MEDIUM"}[x.Confidence]
		out = append(out, languageFinding("brakeman", "ruby", x.WarningType, x.File, x.Line, x.WarningType, x.Message, sev, "", cwe))
	}
	return out, nil
}
