package scanner

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/example/sast-dast-analyzer/internal/models"
)

const multiScannerTimeout = 10 * time.Minute

func installed(name string) bool { _, err := exec.LookPath(name); return err == nil }
func installCommand(ctx context.Context, name string, args ...string) error {
	if sandbox.Enabled {
		return errors.New("host auto-install disabled while scanner isolation is required")
	}
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

var cweRef = regexp.MustCompile(`(?i)\bCWE-?(\d+)\b`)

// firstCWE normalizes the many shapes scanners use for CWE metadata
// ("CWE-89: ...", ["CWE-79: ..."], 89, [89], "89") into "CWE-<n>".
func firstCWE(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		if m := cweRef.FindStringSubmatch(x); m != nil {
			return "CWE-" + m[1]
		}
		x = strings.TrimSpace(x)
		if x != "" && strings.Trim(x, "0123456789") == "" {
			return "CWE-" + x
		}
		return ""
	case float64:
		if x > 0 {
			return fmt.Sprintf("CWE-%d", int(x))
		}
		return ""
	case int:
		if x > 0 {
			return fmt.Sprintf("CWE-%d", x)
		}
		return ""
	case []any:
		for _, e := range x {
			if c := firstCWE(e); c != "" {
				return c
			}
		}
	case []string:
		for _, e := range x {
			if c := firstCWE(e); c != "" {
				return c
			}
		}
	}
	return ""
}
