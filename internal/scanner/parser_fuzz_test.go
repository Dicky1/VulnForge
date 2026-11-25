package scanner

import (
	"github.com/example/sast-dast-analyzer/internal/models"
	"testing"
)

func FuzzScannerParsers(f *testing.F) {
	for _, seed := range []string{"", "null", "{}", "[]", "{\"results\":[]}", "{\"success\":true,\"results\":{\"detectors\":[]}}", "fixture.c:1:4: warning: Dereference of null pointer [core.NullDereference]"} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 1<<20 {
			t.Skip()
		}
		for _, parser := range []interface {
			ParseOutput([]byte) ([]models.Finding, error)
		}{
			NewBrakemanScanner(), NewCargoAuditScanner(), NewClangAnalyzerScanner(), NewDependencyCheckScanner(), NewESLintScanner(), NewPHPStanScanner(), NewPsalmScanner(), NewSlitherScanner(), NewSpotBugsScanner(),
		} {
			_, _ = parser.ParseOutput(raw)
		}
		_, _ = parseSemgrepOutput(raw, models.ToolOutput{})
		_, _ = parseTrivy(raw, "fixture")
		_, _ = parseGrype(raw, "fixture")
	})
}

func BenchmarkSemgrepParse(b *testing.B) {
	raw := []byte(`{"results":[{"check_id":"fixture.rule","path":"fixture.go","start":{"line":3},"extra":{"message":"fixture finding","severity":"WARNING","metadata":{"cwe":["CWE-89"]}}}]}`)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := parseSemgrepOutput(raw, models.ToolOutput{}); err != nil {
			b.Fatal(err)
		}
	}
}
