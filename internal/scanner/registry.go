package scanner

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"time"

	"github.com/example/sast-dast-analyzer/internal/models"
)

type legacyAdapter struct {
	name, language, binary string
	scan                   func(context.Context, string) (models.ToolOutput, error)
	install                func(context.Context) error
}

func (a *legacyAdapter) Name() string      { return a.name }
func (a *legacyAdapter) Language() string  { return a.language }
func (a *legacyAdapter) IsInstalled() bool { return installed(a.binary) }
func (a *legacyAdapter) Scan(ctx context.Context, target string, _ *models.ScanConfig) (*models.ToolOutput, error) {
	o, e := a.scan(ctx, target)
	for i := range o.Findings {
		if o.Findings[i].Language == "" {
			o.Findings[i].Language = languageFromPath(o.Findings[i].FilePath)
			if o.Findings[i].Language == "unknown" && a.language != "all" {
				o.Findings[i].Language = a.language
			}
		}
	}
	return &o, e
}

func languageFromPath(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".go":
		return "go"
	case ".py":
		return "python"
	case ".js", ".jsx", ".ts", ".tsx":
		return "javascript"
	case ".java":
		return "java"
	case ".php":
		return "php"
	case ".rs":
		return "rust"
	case ".rb":
		return "ruby"
	case ".c", ".cc", ".cpp", ".h", ".hpp":
		return "cpp"
	case ".cs", ".fs", ".vb":
		return "dotnet"
	case ".swift":
		return "swift"
	case ".kt", ".kts":
		return "kotlin"
	}
	return "unknown"
}
func (a *legacyAdapter) ParseOutput([]byte) ([]models.Finding, error) {
	return nil, errors.New("parsing is performed by the wrapped scanner")
}
func (a *legacyAdapter) Install(ctx context.Context) error {
	if a.install == nil {
		return errors.New("automatic installation unavailable")
	}
	return a.install(ctx)
}

func NewToolRegistry(timeout time.Duration) models.ToolRegistry {
	sem := NewSemgrepScanner(timeout)
	band := NewBanditScanner(timeout)
	gosec := NewGoSecScanner(timeout)
	return models.ToolRegistry{
		"semgrep": &legacyAdapter{"semgrep", "all", "semgrep", sem.Scan, func(ctx context.Context) error {
			return installCommand(ctx, "python", "-m", "pip", "install", "semgrep")
		}},
		"bandit": &legacyAdapter{"bandit", "python", "bandit", band.Scan, func(ctx context.Context) error {
			return installCommand(ctx, "python", "-m", "pip", "install", "bandit")
		}},
		"gosec": &legacyAdapter{"gosec", "go", "gosec", gosec.Scan, func(ctx context.Context) error {
			return installCommand(ctx, "go", "install", "github.com/securego/gosec/v2/cmd/gosec@latest")
		}},
		"eslint": NewESLintScanner(), "spotbugs": NewSpotBugsScanner(), "phpstan": NewPHPStanScanner(), "psalm": NewPsalmScanner(),
		"cargo-audit": NewCargoAuditScanner(), "brakeman": NewBrakemanScanner(), "dependency-check": NewDependencyCheckScanner(), "clang-analyzer": NewClangAnalyzerScanner(),
	}
}
