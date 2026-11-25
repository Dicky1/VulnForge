package scanner

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/example/sast-dast-analyzer/internal/models"
	"io/fs"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

type ClangAnalyzerScanner struct{}

func NewClangAnalyzerScanner() *ClangAnalyzerScanner { return &ClangAnalyzerScanner{} }
func (*ClangAnalyzerScanner) Name() string           { return "clang-analyzer" }
func (*ClangAnalyzerScanner) Language() string       { return "cpp" }
func (*ClangAnalyzerScanner) IsInstalled() bool {
	return installed("clang") || SandboxAvailableFor("clang")
}
func (*ClangAnalyzerScanner) Install(context.Context) error {
	return errors.New("install LLVM/Clang using the platform package manager")
}
func (s *ClangAnalyzerScanner) Scan(ctx context.Context, target string, _ *models.ScanConfig) (*models.ToolOutput, error) {
	// A standalone analyzer invocation needs a translation unit, not a directory.
	// Do not execute target build scripts or read target compiler command files.
	ctx, cancel := context.WithTimeout(ctx, multiScannerTimeout)
	defer cancel()
	root, err := filepath.Abs(target)
	if err != nil {
		return nil, err
	}
	out := &models.ToolOutput{Tool: s.Name(), ExitCode: 0}
	count := 0
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.IsDir() {
			if path != root && (entry.Name() == ".git" || entry.Name() == "vendor" || entry.Name() == "node_modules") {
				return filepath.SkipDir
			}
			return nil
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		switch strings.ToLower(filepath.Ext(path)) {
		case ".c", ".cc", ".cpp", ".cxx":
		default:
			return nil
		}
		count++
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		r, err := run(ctx, multiScannerTimeout, root, "clang", "--analyze", "--no-default-config", "-fno-color-diagnostics", "-Xanalyzer", "-analyzer-output=text", "--", "./"+filepath.ToSlash(rel))
		if err != nil {
			return err
		}
		findings, err := s.ParseOutput(r.combined())
		if err != nil {
			return err
		}
		for i := range findings {
			if !filepath.IsAbs(findings[i].FilePath) {
				findings[i].FilePath = filepath.Join(root, findings[i].FilePath)
			}
		}
		out.Findings = append(out.Findings, findings...)
		if r.exitCode != 0 {
			return fmt.Errorf("clang analysis incomplete: translation unit failed (exit %d)", r.exitCode)
		}
		return nil
	})
	if err == nil && count == 0 {
		err = errors.New("no C/C++ translation units found")
	}
	if err != nil {
		out.ExitCode = -1
	}
	return out, err
}

var clangLine = regexp.MustCompile(`^(.+?):(\d+)(?::\d+)?:\s*warning:\s*(.+?)(?:\s*\[([^]]+)\])?$`)

func (*ClangAnalyzerScanner) ParseOutput(raw []byte) ([]models.Finding, error) {
	var out []models.Finding
	s := bufio.NewScanner(bytes.NewReader(raw))
	for s.Scan() {
		m := clangLine.FindStringSubmatch(strings.TrimSpace(s.Text()))
		if m == nil {
			continue
		}
		line, _ := strconv.Atoi(m[2])
		cwe := ""
		lower := strings.ToLower(m[3] + " " + m[4])
		if strings.Contains(lower, "null pointer") || strings.Contains(lower, "nulldereference") {
			cwe = "CWE-476"
		} else if strings.Contains(lower, "use-after-free") {
			cwe = "CWE-416"
		} else if strings.Contains(lower, "format string") {
			cwe = "CWE-134"
		} else if strings.Contains(lower, "integer overflow") {
			cwe = "CWE-190"
		} else if strings.Contains(lower, "out of bounds") || strings.Contains(lower, "buffer overflow") {
			cwe = "CWE-119"
		} else if !containsSecurity(lower) {
			continue
		}
		out = append(out, languageFinding("clang-analyzer", "cpp", m[4], m[1], line, m[4], m[3], "HIGH", "", cwe))
	}
	return out, s.Err()
}
