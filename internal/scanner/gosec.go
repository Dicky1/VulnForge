package scanner

import (
	"context"
	"encoding/json"
	"github.com/example/sast-dast-analyzer/internal/models"
	"strconv"
	"strings"
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
			RuleID string `json:"rule_id"`
			CWE    struct {
				ID string `json:"id"`
			} `json:"cwe"`
			File                    string `json:"file"`
			Line                    string `json:"line"`
			Severity, Details, Code string
		} `json:"Issues"`
	}
	if err = json.Unmarshal(r.data, &d); err != nil {
		return out, err
	}
	for _, x := range d.Issues {
		// gosec reports multi-line issues as a range ("12-14"); keep the start.
		start, _, _ := strings.Cut(x.Line, "-")
		line, _ := strconv.Atoi(strings.TrimSpace(start))
		f := makeFinding("gosec", x.RuleID, x.File, line, x.Details, x.Severity, x.Code)
		f.CWE = firstCWE(x.CWE.ID)
		out.Findings = append(out.Findings, f)
	}
	return out, nil
}
