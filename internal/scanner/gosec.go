package scanner

import (
	"context"
	"encoding/json"
	"github.com/example/sast-dast-analyzer/internal/models"
	"strconv"
	"time"
)

type GoSecScanner struct{ Timeout time.Duration }

func NewGoSecScanner(t time.Duration) *GoSecScanner { return &GoSecScanner{t} }
func (s *GoSecScanner) Scan(ctx context.Context, target string) (models.ToolOutput, error) {
	r, err := run(ctx, s.Timeout, target, "gosec", "-fmt=json", "./...")
	out := models.ToolOutput{Tool: "gosec", RawJSON: json.RawMessage(r.data), ExitCode: r.exitCode}
	if err != nil {
		return out, err
	}
	var d struct {
		Issues []struct {
			RuleID                  string `json:"rule_id"`
			File                    string `json:"file"`
			Line                    string `json:"line"`
			Severity, Details, Code string
		} `json:"Issues"`
	}
	if err = json.Unmarshal(r.data, &d); err != nil {
		return out, err
	}
	for _, x := range d.Issues {
		line, _ := strconv.Atoi(x.Line)
		out.Findings = append(out.Findings, makeFinding("gosec", x.RuleID, x.File, line, x.Details, x.Severity, x.Code))
	}
	return out, nil
}
