package models

import "context"

// Scanner is the common contract for language-specific security tools.
type Scanner interface {
	Name() string
	Language() string
	Scan(ctx context.Context, targetPath string, config *ScanConfig) (*ToolOutput, error)
	ParseOutput(rawOutput []byte) ([]Finding, error)
	IsInstalled() bool
	Install(ctx context.Context) error
}

type ToolRegistry map[string]Scanner
