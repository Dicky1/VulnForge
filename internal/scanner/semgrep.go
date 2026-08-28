package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/example/sast-dast-analyzer/internal/models"
)

type SemgrepScanner struct{ Timeout time.Duration }

func NewSemgrepScanner(timeout time.Duration) *SemgrepScanner { return &SemgrepScanner{timeout} }
func (s *SemgrepScanner) Scan(ctx context.Context, target string) (models.ToolOutput, error) {
	r, err := run(ctx, s.Timeout, target, "semgrep", "--config=p/security-audit", "--json", target)
	out := models.ToolOutput{Tool: "semgrep", RawJSON: json.RawMessage(r.data), ExitCode: r.exitCode}
	if err != nil {
		return out, err
	}
	var doc struct {
		Results []struct {
			CheckID, Path string
			Start         struct{ Line int }
			Extra         struct {
				Message, Severity string
				Lines             string `json:"lines"`
				Metadata          struct {
					CWE any `json:"cwe"`
				}
			}
		} `json:"results"`
	}
	if err := json.Unmarshal(r.data, &doc); err != nil {
		return out, err
	}
	for _, x := range doc.Results {
		out.Findings = append(out.Findings, makeFinding("semgrep", x.CheckID, x.Path, x.Start.Line, x.Extra.Message, x.Extra.Severity, x.Extra.Lines))
	}
	return out, nil
}

func makeFinding(tool, id, path string, line int, desc, severity, snippet string) models.Finding {
	h := sha256.Sum256([]byte(tool + ":" + id + ":" + path + ":" + strconv.Itoa(line)))
	return models.Finding{ID: hex.EncodeToString(h[:8]), Title: id, Description: desc, Severity: normalizeSeverity(severity), CVSSBase: cvss(normalizeSeverity(severity)), SourceTool: tool, FilePath: path, LineNumber: line, CodeSnippet: snippet, CreatedAt: time.Now().UTC()}
}
func normalizeSeverity(v string) models.Severity {
	switch strings.ToUpper(v) {
	case "CRITICAL", "ERROR":
		return models.SeverityCritical
	case "HIGH", "WARNING":
		return models.SeverityHigh
	case "MEDIUM", "INFO":
		return models.SeverityMedium
	default:
		return models.SeverityLow
	}
}
func cvss(s models.Severity) float64 {
	switch s {
	case models.SeverityCritical:
		return 9.5
	case models.SeverityHigh:
		return 8
	case models.SeverityMedium:
		return 5.5
	default:
		return 3
	}
}
