package optimizer

import (
	"encoding/json"
	"sort"

	"github.com/example/sast-dast-analyzer/internal/models"
	"github.com/example/sast-dast-analyzer/internal/validator"
)

// Tokenizer prepares findings for downstream processing. Budget controls AI
// prompt selection only; it must never silently discard audit evidence.
type Tokenizer struct {
	Budget       int
	SkipPatterns []string
}

func EstimateTokens(v any) int { b, _ := json.Marshal(v); return (len(b) + 3) / 4 }

// FilterFindings retains all severities. Low-confidence assessments are not
// evidence of a false positive and do not justify dropping scanner output.
func (t Tokenizer) FilterFindings(in []models.Finding) []models.Finding {
	out := validator.Deduplicate(append([]models.Finding(nil), in...))
	out = validator.SkipKnownFalsePositives(out, t.SkipPatterns)
	sort.SliceStable(out, func(i, j int) bool { return priority(out[i]) > priority(out[j]) })
	return out
}

// WithinBudget returns a non-destructive selection for optional AI requests.
func (t Tokenizer) WithinBudget(in []models.Finding) []models.Finding {
	if t.Budget <= 0 {
		return append([]models.Finding(nil), in...)
	}
	var out []models.Finding
	used := 0
	for _, f := range in {
		cost := EstimateTokens(f)
		if used+cost > t.Budget {
			continue
		}
		used += cost
		out = append(out, f)
	}
	return out
}

func priority(f models.Finding) float64 {
	base := map[models.Severity]float64{models.SeverityCritical: 100, models.SeverityHigh: 75, models.SeverityMedium: 50, models.SeverityLow: 25}[f.Severity]
	if f.IsZeroDay {
		base += 30
	}
	return base + f.AIConfidence*20
}

// SelectForAI partitions the report without dropping findings. Budget is an
// estimate, not a promise about upstream billed token counts.
func (t Tokenizer) SelectForAI(in []models.Finding) (selected, remaining []models.Finding) {
	used := 0
	for _, f := range in {
		cost := EstimateTokens(f)
		if t.Budget > 0 && used+cost > t.Budget {
			remaining = append(remaining, f)
			continue
		}
		selected = append(selected, f)
		used += cost
	}
	return
}
