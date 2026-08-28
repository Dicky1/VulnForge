package scanner

import (
	"context"
	"encoding/json"
	"github.com/example/sast-dast-analyzer/internal/models"
)

type PsalmScanner struct{}

func NewPsalmScanner() *PsalmScanner    { return &PsalmScanner{} }
func (*PsalmScanner) Name() string      { return "psalm" }
func (*PsalmScanner) Language() string  { return "php" }
func (*PsalmScanner) IsInstalled() bool { return installed("psalm") }
func (*PsalmScanner) Install(ctx context.Context) error {
	return installCommand(ctx, "composer", "global", "require", "vimeo/psalm")
}
func (s *PsalmScanner) Scan(ctx context.Context, target string, _ *models.ScanConfig) (*models.ToolOutput, error) {
	r, err := run(ctx, multiScannerTimeout, target, "psalm", "--output-format=json")
	if err != nil {
		return output(s.Name(), r, nil), err
	}
	f, e := s.ParseOutput(r.data)
	return output(s.Name(), r, f), e
}
func (*PsalmScanner) ParseOutput(raw []byte) ([]models.Finding, error) {
	var d []struct {
		Type, Message, FileName, Severity string
		LineFrom                          int `json:"line_from"`
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, err
	}
	var out []models.Finding
	for _, x := range d {
		if !containsSecurity(x.Type + " " + x.Message) {
			continue
		}
		out = append(out, languageFinding("psalm", "php", x.Type, x.FileName, x.LineFrom, x.Type, x.Message, x.Severity, "", "CWE-20"))
	}
	return out, nil
}
