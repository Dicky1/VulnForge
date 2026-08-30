package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/example/sast-dast-analyzer/internal/models"
)

// SlitherScanner runs the Slither static analyzer for Solidity projects.
type SlitherScanner struct{}

func NewSlitherScanner() *SlitherScanner  { return &SlitherScanner{} }
func (*SlitherScanner) Name() string      { return "slither" }
func (*SlitherScanner) Language() string  { return "solidity" }
func (*SlitherScanner) IsInstalled() bool { return installed("slither") }
func (*SlitherScanner) Install(ctx context.Context) error {
	return installCommand(ctx, "python", "-m", "pip", "install", "slither-analyzer")
}

func (s *SlitherScanner) Scan(ctx context.Context, target string, _ *models.ScanConfig) (*models.ToolOutput, error) {
	if _, err := os.Stat(filepath.Join(target, "foundry.toml")); err == nil && !installed("forge") {
		return &models.ToolOutput{Tool: s.Name(), ExitCode: -1}, errors.New("Foundry project requires forge on PATH; install Foundry and run forge --version")
	}
	f, err := os.CreateTemp("", "analyzer-slither-*.json")
	if err != nil {
		return nil, fmt.Errorf("create Slither output: %w", err)
	}
	jsonPath := f.Name()
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("close Slither output: %w", err)
	}
	// Slither refuses to overwrite an existing JSON file. CreateTemp gives us a
	// collision-resistant path, then the scanner itself creates the file.
	if err := os.Remove(jsonPath); err != nil {
		return nil, fmt.Errorf("prepare Slither output: %w", err)
	}
	defer os.Remove(jsonPath)

	r, err := run(ctx, multiScannerTimeout, target, "slither", ".", "--json", jsonPath)
	if err != nil {
		return output(s.Name(), r, nil), err
	}
	raw, readErr := os.ReadFile(jsonPath)
	if readErr != nil {
		detail := strings.TrimSpace(string(r.data))
		if detail != "" {
			return output(s.Name(), r, nil), fmt.Errorf("Slither did not produce JSON (exit %d): %s", r.exitCode, detail)
		}
		return output(s.Name(), r, nil), fmt.Errorf("read Slither JSON: %w", readErr)
	}
	findings, parseErr := s.ParseOutput(raw)
	o := output(s.Name(), r, findings)
	o.RawJSON = raw
	return o, parseErr
}

func (*SlitherScanner) ParseOutput(raw []byte) ([]models.Finding, error) {
	var doc struct {
		Success bool   `json:"success"`
		Error   string `json:"error"`
		Results struct {
			Detectors []struct {
				Check, Impact, Confidence, Description string
				Elements                               []struct {
					SourceMapping struct {
						FilenameRelative string `json:"filename_relative"`
						FilenameShort    string `json:"filename_short"`
						Lines            []int  `json:"lines"`
						Content          string `json:"content"`
					} `json:"source_mapping"`
				} `json:"elements"`
			} `json:"detectors"`
		} `json:"results"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse slither JSON: %w", err)
	}
	if !doc.Success && doc.Error != "" {
		return nil, fmt.Errorf("slither: %s", doc.Error)
	}
	findings := make([]models.Finding, 0, len(doc.Results.Detectors))
	for _, detector := range doc.Results.Detectors {
		path, snippet, line := "", "", 0
		if len(detector.Elements) > 0 {
			mapping := detector.Elements[0].SourceMapping
			path = mapping.FilenameRelative
			if path == "" {
				path = mapping.FilenameShort
			}
			snippet = mapping.Content
			if len(mapping.Lines) > 0 {
				line = mapping.Lines[0]
			}
		}
		description := strings.TrimSpace(detector.Description)
		if detector.Confidence != "" {
			description += fmt.Sprintf(" (Slither confidence: %s)", detector.Confidence)
		}
		findings = append(findings, languageFinding("slither", "solidity", detector.Check, path, line, detector.Check, description, detector.Impact, snippet, ""))
	}
	return findings, nil
}
