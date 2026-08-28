package scanner

import (
	"context"
	"encoding/json"
	"github.com/example/sast-dast-analyzer/internal/models"
	"time"
)

type BanditScanner struct{ Timeout time.Duration }

func NewBanditScanner(t time.Duration) *BanditScanner { return &BanditScanner{t} }
func (s *BanditScanner) Scan(ctx context.Context, target string) (models.ToolOutput, error) {
	r, err := run(ctx, s.Timeout, target, "bandit", "-r", "-f", "json", target)
	out := models.ToolOutput{Tool: "bandit", RawJSON: json.RawMessage(r.data), ExitCode: r.exitCode}
	if err != nil {
		return out, err
	}
	var d struct {
		Results []struct {
			TestID    string `json:"test_id"`
			IssueType string `json:"issue_type"`
			Filename  string `json:"filename"`
			Line      int    `json:"line_number"`
			Severity  string `json:"issue_severity"`
			Text      string `json:"issue_text"`
			Code      string `json:"code"`
		} `json:"results"`
	}
	if err = json.Unmarshal(r.data, &d); err != nil {
		return out, err
	}
	for _, x := range d.Results {
		f := makeFinding("bandit", x.TestID, x.Filename, x.Line, x.Text, x.Severity, x.Code)
		f.Title = x.IssueType
		out.Findings = append(out.Findings, f)
	}
	return out, nil
}
