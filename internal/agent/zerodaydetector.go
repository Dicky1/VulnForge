package agent

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"github.com/example/sast-dast-analyzer/internal/models"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type zeroPattern struct {
	name, desc, cwe, mitre string
	re                     *regexp.Regexp
}

var zeroPatterns = []zeroPattern{
	{"Non-standard cryptography", "Custom cryptographic primitive or unsafe cipher construction", "CWE-327", "T1027", regexp.MustCompile(`(?i)(custom|homebrew).*(crypto|cipher)|(?:rot13|xor)\s*\(|cipher\.New(?:ECB|CBC)Encrypter`)},
	{"Validation bypass", "Input validation may be bypassed by loose matching or missing sanitization", "CWE-20", "T1190", regexp.MustCompile(`(?i)(skip|bypass).*(valid|sanit)|regexp\.(Match|Compile).*\.\*|innerHTML\s*=`)},
	{"Authorization bypass", "Authorization decision appears fail-open or controlled by request input", "CWE-862", "T1068", regexp.MustCompile(`(?i)(skipAuth|bypassAuth|isAdmin\s*:?=\s*(?:true|request)|role\s*:?=\s*(?:req|request))`)},
	{"Unsynchronized shared state", "Concurrent mutation may create an exploitable race condition", "CWE-362", "T1499", regexp.MustCompile(`(?i)concurrent map writes|shared(State|Map)\s*:?=|go\s+func.*\w+\[[^]]+\]\s*=`)},
	{"Business logic manipulation", "Price, discount, or state transition appears directly client-controlled", "CWE-840", "T1190", regexp.MustCompile(`(?i)(price|discount|balance|status)\s*:?=\s*(req|request|input|params)`)},
}

func DetectZeroDayPatterns(ctx context.Context, target string) ([]models.Finding, error) {
	var out []models.Finding
	err := filepath.WalkDir(target, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() {
			if d.Name() == ".git" || d.Name() == "vendor" || d.Name() == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if !sourceExt(filepath.Ext(path)) {
			return nil
		}
		info, e := d.Info()
		if e != nil || info.Size() > 2<<20 {
			return nil
		}
		f, e := os.Open(path)
		if e != nil {
			return nil
		}
		defer f.Close()
		s := bufio.NewScanner(f)
		line := 0
		for s.Scan() {
			line++
			text := s.Text()
			// Do not flag detector/rule declarations themselves when analyzing security tooling.
			if strings.Contains(text, "regexp.MustCompile") || strings.HasSuffix(filepath.ToSlash(path), "/zerodaydetector.go") {
				continue
			}
			for _, p := range zeroPatterns {
				if p.re.MatchString(text) {
					sum := sha256.Sum256([]byte(p.name + path + text))
					out = append(out, models.Finding{ID: hex.EncodeToString(sum[:8]), Title: "Potential zero-day: " + p.name, Description: p.desc, Severity: models.SeverityHigh, CVSSBase: 8.1, CWE: p.cwe, MITRETechniques: []string{p.mitre}, SourceTool: "zeroday-detector", Language: sourceLanguage(path), FilePath: path, LineNumber: line, CodeSnippet: strings.TrimSpace(text), AIConfidence: .75, IsZeroDay: true, Remediation: "Review the complete data and authorization flow; replace custom controls with well-tested, fail-closed primitives and add adversarial tests.", CreatedAt: time.Now().UTC()})
					break
				}
			}
		}
		return nil
	})
	return AnalyzeExploitChains(out), err
}
func sourceLanguage(path string) string {
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
	case ".cs":
		return "dotnet"
	case ".swift":
		return "swift"
	case ".kt", ".kts":
		return "kotlin"
	case ".sol":
		return "solidity"
	}
	return "unknown"
}
func sourceExt(e string) bool {
	switch strings.ToLower(e) {
	case ".go", ".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".rb", ".php", ".cs", ".c", ".cpp", ".rs", ".sol", ".kt", ".kts", ".swift":
		return true
	}
	return false
}
func AnalyzeExploitChains(in []models.Finding) []models.Finding {
	for i := range in {
		for j := range in {
			if i == j {
				continue
			}
			if in[i].FilePath == in[j].FilePath || filepath.Dir(in[i].FilePath) == filepath.Dir(in[j].FilePath) {
				in[i].ExploitChain = append(in[i].ExploitChain, in[j].ID+": "+in[j].Title)
				if len(in[i].ExploitChain) == 2 {
					break
				}
			}
		}
	}
	return in
}
