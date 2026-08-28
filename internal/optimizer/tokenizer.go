package optimizer

import (
	"encoding/json"
	"github.com/example/sast-dast-analyzer/internal/models"
	"github.com/example/sast-dast-analyzer/internal/validator"
	"sort"
)

type Tokenizer struct {
	Budget       int
	SkipPatterns []string
}

func EstimateTokens(v any) int { b, _ := json.Marshal(v); return (len(b) + 3) / 4 }
func (t Tokenizer) FilterFindings(in []models.Finding) []models.Finding {
	in = validator.Deduplicate(in)
	in = validator.SkipKnownFalsePositives(in, t.SkipPatterns)
	out := make([]models.Finding, 0, len(in))
	for _, f := range in {
		if f.Severity == models.SeverityCritical || (f.Severity == models.SeverityHigh && (f.AIConfidence == 0 || f.AIConfidence >= .75)) || (f.Severity == models.SeverityMedium && (f.AIConfidence == 0 || f.AIConfidence >= .85)) {
			out = append(out, f)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return priority(out[i]) > priority(out[j]) })
	used := 0
	n := 0
	for _, f := range out {
		cost := EstimateTokens(f)
		if t.Budget > 0 && used+cost > t.Budget {
			break
		}
		used += cost
		out[n] = f
		n++
	}
	return out[:n]
}
func priority(f models.Finding) float64 {
	base := map[models.Severity]float64{models.SeverityCritical: 100, models.SeverityHigh: 75, models.SeverityMedium: 50, models.SeverityLow: 25}[f.Severity]
	if f.IsZeroDay {
		base += 30
	}
	return base + f.AIConfidence*20
}
