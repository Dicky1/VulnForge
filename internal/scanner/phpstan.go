package scanner

import (
	"context"
	"encoding/json"
	"github.com/example/sast-dast-analyzer/internal/models"
)

type PHPStanScanner struct{}

func NewPHPStanScanner() *PHPStanScanner  { return &PHPStanScanner{} }
func (*PHPStanScanner) Name() string      { return "phpstan" }
func (*PHPStanScanner) Language() string  { return "php" }
func (*PHPStanScanner) IsInstalled() bool { return installed("phpstan") }
func (*PHPStanScanner) Install(ctx context.Context) error {
	return installCommand(ctx, "composer", "global", "require", "phpstan/phpstan")
}
func (s *PHPStanScanner) Scan(ctx context.Context, target string, _ *models.ScanConfig) (*models.ToolOutput, error) {
	r, err := run(ctx, multiScannerTimeout, target, "phpstan", "analyse", "--error-format=json", ".")
	if err != nil {
		return output(s.Name(), r, nil), err
	}
	f, e := s.ParseOutput(r.data)
	return output(s.Name(), r, f), e
}
func (*PHPStanScanner) ParseOutput(raw []byte) ([]models.Finding, error) {
	var d struct {
		Files map[string]struct {
			Messages []struct {
				Message    string
				Line       int
				Level      int
				Identifier string
			} `json:"messages"`
		} `json:"files"`
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, err
	}
	var out []models.Finding
	for file, v := range d.Files {
		for _, m := range v.Messages {
			if !containsSecurity(m.Message + " " + m.Identifier) {
				continue
			}
			sev := "LOW"
			if m.Level >= 9 {
				sev = "CRITICAL"
			} else if m.Level >= 7 {
				sev = "HIGH"
			} else if m.Level >= 5 {
				sev = "MEDIUM"
			}
			out = append(out, languageFinding("phpstan", "php", m.Identifier, file, m.Line, m.Identifier, m.Message, sev, "", "CWE-20"))
		}
	}
	return out, nil
}
