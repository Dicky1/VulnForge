package scanner

import (
	"bufio"
	"context"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/example/sast-dast-analyzer/internal/models"
)

type secretPattern struct {
	name, cwe string
	severity  models.Severity
	re        *regexp.Regexp
}
type SecretDetector struct {
	EntropyThreshold float64
	ExcludePaths     []string
}

func NewSecretDetector() *SecretDetector {
	return &SecretDetector{EntropyThreshold: 4.5, ExcludePaths: []string{".git", "vendor", "node_modules", ".gocache", "testdata"}}
}

var secretPatterns = []secretPattern{
	{"AWS access key", "CWE-798", models.SeverityCritical, regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)},
	{"AWS secret key", "CWE-798", models.SeverityCritical, regexp.MustCompile(`(?i)(aws_secret_access_key|aws_secret_key)\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})`)},
	{"GitHub token", "CWE-798", models.SeverityCritical, regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{20,255}\b`)},
	{"Slack token", "CWE-798", models.SeverityCritical, regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`)},
	{"Private key", "CWE-321", models.SeverityCritical, regexp.MustCompile(`-----BEGIN (?:RSA |EC )?PRIVATE KEY-----`)},
	{"JWT token", "CWE-798", models.SeverityCritical, regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`)},
	{"Stripe key", "CWE-798", models.SeverityCritical, regexp.MustCompile(`\b(?:sk|pk)_(?:test|live)_[A-Za-z0-9]{12,}\b`)},
	{"SendGrid key", "CWE-798", models.SeverityCritical, regexp.MustCompile(`\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b`)},
	{"Database URL", "CWE-798", models.SeverityCritical, regexp.MustCompile(`(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s:@/]+:[^\s@/]+@`)},
	{"Hardcoded credential", "CWE-798", models.SeverityCritical, regexp.MustCompile(`(?i)\b(?:api[_-]?key|password|passwd|pwd)\s*[:=]\s*["']([^"']{8,})["']`)},
}
var assignmentString = regexp.MustCompile(`(?i)(?:secret|token|key|credential|auth)[A-Za-z0-9_ -]*\s*[:=]\s*["']([A-Za-z0-9+/=_-]{24,})["']`)
var placeholders = regexp.MustCompile(`(?i)(example|sample|placeholder|replace.?me|dummy|fake|test|xxxx|your[_-]?(?:key|token|password)|changeme)`)

func (d *SecretDetector) Scan(ctx context.Context, target string) ([]models.Finding, error) {
	var out []models.Finding
	err := filepath.WalkDir(target, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		rel, _ := filepath.Rel(target, path)
		if entry.IsDir() {
			if path != target && d.excluded(rel) {
				return filepath.SkipDir
			}
			return nil
		}
		if d.excluded(rel) || !secretSource(path) {
			return nil
		}
		info, e := entry.Info()
		if e != nil || info.Size() > 2<<20 {
			return nil
		}
		f, e := os.Open(path)
		if e != nil {
			return nil
		}
		defer f.Close()
		s := bufio.NewScanner(f)
		s.Buffer(make([]byte, 64*1024), 1024*1024)
		line := 0
		for s.Scan() {
			line++
			text := s.Text()
			if placeholders.MatchString(text) {
				continue
			}
			matched := false
			for _, p := range secretPatterns {
				if p.re.MatchString(text) {
					finding := languageFinding("secret-detector", languageFromPath(path), p.name, path, line, p.name, "Potential hardcoded secret detected", string(p.severity), redact(text), p.cwe)
					finding.Remediation = "Revoke and rotate the credential immediately, remove it from Git history, and load its replacement from a managed secret store."
					out = append(out, finding)
					matched = true
					break
				}
			}
			if matched {
				continue
			}
			for _, m := range assignmentString.FindAllStringSubmatch(text, -1) {
				if shannonEntropy(m[1]) > d.EntropyThreshold {
					finding := languageFinding("secret-detector", languageFromPath(path), "high-entropy-secret", path, line, "High-entropy credential candidate", "A high-entropy string may be a hardcoded credential.", "HIGH", redact(text), "CWE-798")
					finding.Remediation = "Verify the value, rotate it if active, and store secrets outside source control."
					out = append(out, finding)
					break
				}
			}
		}
		return s.Err()
	})
	return out, err
}
func (d *SecretDetector) excluded(path string) bool {
	p := filepath.ToSlash(path)
	for _, x := range d.ExcludePaths {
		if strings.Contains(p, strings.Trim(filepath.ToSlash(x), "/")) {
			return true
		}
	}
	return false
}
func secretSource(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	if strings.Contains(base, "_test.") || strings.Contains(base, ".spec.") || strings.Contains(base, ".test.") {
		return false
	}
	if base == ".env" || strings.Contains(base, "config") || strings.Contains(base, "credential") {
		return true
	}
	return secretExtension(filepath.Ext(path)) || strings.HasSuffix(base, ".yaml") || strings.HasSuffix(base, ".yml") || strings.HasSuffix(base, ".json") || strings.HasSuffix(base, ".properties")
}
func secretExtension(ext string) bool {
	switch strings.ToLower(ext) {
	case ".go", ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".php", ".rb", ".rs", ".c", ".cc", ".cpp", ".h", ".hpp", ".cs", ".swift", ".kt", ".kts", ".sh", ".ps1":
		return true
	}
	return false
}
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	counts := map[rune]float64{}
	for _, r := range s {
		counts[r]++
	}
	n := float64(len([]rune(s)))
	var e float64
	for _, c := range counts {
		p := c / n
		e -= p * math.Log2(p)
	}
	return e
}
func redact(s string) string {
	if len(s) > 160 {
		s = s[:160]
	}
	return "[REDACTED secret-bearing line; length=" + strconv.Itoa(len(s)) + "]"
}
