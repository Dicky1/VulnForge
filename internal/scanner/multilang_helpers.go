package scanner

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"time"

	"github.com/example/sast-dast-analyzer/internal/models"
)

const multiScannerTimeout = 10 * time.Minute

func installed(name string) bool { _, err := exec.LookPath(name); return err == nil }
func installCommand(ctx context.Context, name string, args ...string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	b, err := cmd.CombinedOutput()
	if err != nil {
		return errors.New(strings.TrimSpace(string(b)) + ": " + err.Error())
	}
	return nil
}
func output(tool string, r commandResult, findings []models.Finding) *models.ToolOutput {
	return &models.ToolOutput{Tool: tool, RawJSON: r.data, ExitCode: r.exitCode, Findings: findings}
}
func languageFinding(tool, language, id, path string, line int, title, description, severity, snippet, cwe string) models.Finding {
	f := makeFinding(tool, id, path, line, description, severity, snippet)
	f.Title = title
	f.Language = language
	f.CWE = cwe
	return f
}
func containsSecurity(v string) bool {
	v = strings.ToLower(v)
	for _, k := range []string{"security", "taint", "injection", "sql", "xss", "escape", "sanitize", "auth", "password", "secret", "traversal", "unsafe", "deserialize", "file inclusion", "command", "eval", "crypto", "buffer overflow", "use-after-free", "format string"} {
		if strings.Contains(v, k) {
			return true
		}
	}
	return false
}
