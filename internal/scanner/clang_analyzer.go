package scanner

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"github.com/example/sast-dast-analyzer/internal/models"
	"regexp"
	"strconv"
	"strings"
)

type ClangAnalyzerScanner struct{}

func NewClangAnalyzerScanner() *ClangAnalyzerScanner { return &ClangAnalyzerScanner{} }
func (*ClangAnalyzerScanner) Name() string           { return "clang-analyzer" }
func (*ClangAnalyzerScanner) Language() string       { return "cpp" }
func (*ClangAnalyzerScanner) IsInstalled() bool      { return installed("scan-build") || installed("clang") }
func (*ClangAnalyzerScanner) Install(context.Context) error {
	return errors.New("install LLVM/Clang using the platform package manager")
}
func (s *ClangAnalyzerScanner) Scan(ctx context.Context, target string, _ *models.ScanConfig) (*models.ToolOutput, error) {
	name, args := "scan-build", []string{"--status-bugs", "clang", "-fsyntax-only", "."}
	if !installed(name) {
		name = "clang"
		args = []string{"--analyze", "."}
	}
	r, err := run(ctx, multiScannerTimeout, target, name, args...)
	if err != nil {
		return output(s.Name(), r, nil), err
	}
	f, e := s.ParseOutput(r.data)
	return output(s.Name(), r, f), e
}

var clangLine = regexp.MustCompile(`^(.+?):(\d+)(?::\d+)?:\s*(?:warning|error):\s*(.+?)(?:\s*\[([^]]+)\])?$`)

func (*ClangAnalyzerScanner) ParseOutput(raw []byte) ([]models.Finding, error) {
	var out []models.Finding
	s := bufio.NewScanner(bytes.NewReader(raw))
	for s.Scan() {
		m := clangLine.FindStringSubmatch(strings.TrimSpace(s.Text()))
		if m == nil || !containsSecurity(m[3]+" "+m[4]) {
			continue
		}
		line, _ := strconv.Atoi(m[2])
		cwe := "CWE-119"
		lower := strings.ToLower(m[3])
		if strings.Contains(lower, "use-after-free") {
			cwe = "CWE-416"
		} else if strings.Contains(lower, "format string") {
			cwe = "CWE-134"
		} else if strings.Contains(lower, "integer") {
			cwe = "CWE-190"
		}
		out = append(out, languageFinding("clang-analyzer", "cpp", m[4], m[1], line, m[4], m[3], "HIGH", "", cwe))
	}
	return out, s.Err()
}
