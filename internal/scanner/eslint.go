package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/example/sast-dast-analyzer/internal/models"
)

type ESLintScanner struct{}

func NewESLintScanner() *ESLintScanner   { return &ESLintScanner{} }
func (*ESLintScanner) Name() string      { return "eslint" }
func (*ESLintScanner) Language() string  { return "javascript" }
func (*ESLintScanner) IsInstalled() bool { return installed("eslint") }
func (*ESLintScanner) Install(ctx context.Context) error {
	return installCommand(ctx, "npm", "install", "--global", "eslint", "@microsoft/eslint-plugin-sdl")
}
func (s *ESLintScanner) Scan(ctx context.Context, target string, _ *models.ScanConfig) (*models.ToolOutput, error) {
	r, err := run(ctx, multiScannerTimeout, target, "eslint", "--format=json", "--plugin=@microsoft/security", ".")
	if err != nil {
		return output(s.Name(), r, nil), err
	}
	f, e := s.ParseOutput(r.data)
	return output(s.Name(), r, f), e
}
func (*ESLintScanner) ParseOutput(raw []byte) ([]models.Finding, error) {
	var docs []struct {
		FilePath string `json:"filePath"`
		Messages []struct {
			RuleID         string `json:"ruleId"`
			Severity, Line int
			Message        string
		} `json:"messages"`
	}
	if err := json.Unmarshal(raw, &docs); err != nil {
		return nil, err
	}
	var out []models.Finding
	for _, d := range docs {
		for _, m := range d.Messages {
			sev := "note"
			if m.Severity == 2 {
				sev = "error"
			} else if m.Severity == 1 {
				sev = "warning"
			}
			cwe := ""
			if containsSecurity(m.RuleID + " " + m.Message) {
				cwe = "CWE-79"
			}
			out = append(out, languageFinding("eslint", "javascript", fmt.Sprint(m.RuleID), d.FilePath, m.Line, m.RuleID, m.Message, sev, "", cwe))
		}
	}
	return out, nil
}
