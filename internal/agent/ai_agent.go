package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/example/sast-dast-analyzer/internal/models"
	"sort"
	"strconv"
	"strings"
	"sync"
)

type AIClient interface {
	ValidateFindings(context.Context, string) (string, error)
}
type AIValidationAgent struct {
	Client                AIClient
	BatchSize, MaxWorkers int
	ConfidenceThreshold   float64
}
type validation struct {
	FindingIndex            int           `json:"finding_index"`
	IsValid                 flexibleBool  `json:"is_valid"`
	Confidence              flexibleFloat `json:"confidence"`
	Reason                  string        `json:"reason"`
	ExploitationFeasibility string        `json:"exploitation_feasibility"`
	ZeroDayPotential        flexibleBool  `json:"zero_day_potential"`
}

type flexibleBool bool
type flexibleFloat float64

func (b *flexibleBool) UnmarshalJSON(raw []byte) error {
	value := strings.ToLower(strings.Trim(strings.TrimSpace(string(raw)), `"`))
	switch value {
	case "true", "1", "yes":
		*b = true
	case "false", "0", "no", "", "null":
		*b = false
	default:
		number, err := strconv.ParseFloat(value, 64)
		if err == nil && (number == 0 || number == 1) {
			*b = flexibleBool(number == 1)
			return nil
		}
		if strings.HasPrefix(value, "none") || strings.HasPrefix(value, "false") || strings.HasPrefix(value, "no ") || strings.HasPrefix(value, "unlikely") {
			*b = false
			return nil
		}
		if strings.HasPrefix(value, "true") || strings.HasPrefix(value, "yes ") || strings.HasPrefix(value, "likely") {
			*b = true
			return nil
		}
		if err != nil || (number != 0 && number != 1) {
			return fmt.Errorf("invalid boolean value %q", value)
		}
	}
	return nil
}

func (f *flexibleFloat) UnmarshalJSON(raw []byte) error {
	value := strings.Trim(strings.TrimSpace(string(raw)), `"`)
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return fmt.Errorf("invalid numeric value %q", value)
	}
	*f = flexibleFloat(parsed)
	return nil
}

func (a *AIValidationAgent) ValidateFindingsInBatch(ctx context.Context, in []models.Finding) ([]models.Finding, error) {
	if len(in) == 0 {
		return in, nil
	}
	if a.BatchSize <= 0 {
		a.BatchSize = 10
	}
	if a.BatchSize > 10 {
		a.BatchSize = 10
	}
	if a.MaxWorkers <= 0 {
		a.MaxWorkers = 4
	}
	type job struct {
		start int
		items []models.Finding
	}
	type result struct {
		start int
		count int
		items []models.Finding
		err   error
	}
	jobs := make(chan job)
	results := make(chan result)
	var wg sync.WaitGroup
	for i := 0; i < a.MaxWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				x, e := a.validateBatch(ctx, j.items)
				results <- result{j.start, len(j.items), x, e}
			}
		}()
	}
	go func() {
		for i := 0; i < len(in); i += a.BatchSize {
			end := i + a.BatchSize
			if end > len(in) {
				end = len(in)
			}
			jobs <- job{i, in[i:end]}
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()
	// Start from the original findings so a batch that errors out falls back
	// to its unvalidated findings instead of silently dropping them.
	validated := append([]models.Finding(nil), in...)
	keep := make([]bool, len(in))
	var first error
	for r := range results {
		if r.err != nil {
			if first == nil {
				first = r.err
			}
			for i := r.start; i < r.start+r.count && i < len(keep); i++ {
				keep[i] = true
			}
			continue
		}
		for i, f := range r.items {
			validated[r.start+i] = f
			keep[r.start+i] = f.AIConfidence >= a.ConfidenceThreshold
		}
	}
	out := make([]models.Finding, 0, len(in))
	for i, f := range validated {
		if keep[i] {
			out = append(out, f)
		}
	}
	return out, first
}
func (a *AIValidationAgent) validateBatch(ctx context.Context, in []models.Finding) ([]models.Finding, error) {
	prompt := buildLanguageAwarePrompt(in)
	raw, err := a.Client.ValidateFindings(ctx, prompt)
	if err != nil {
		return nil, err
	}
	raw = strings.TrimSpace(raw)
	raw = strings.TrimPrefix(raw, "```json")
	raw = strings.TrimPrefix(raw, "```")
	raw = strings.TrimSuffix(raw, "```")
	var vs []validation
	if err = json.Unmarshal([]byte(strings.TrimSpace(raw)), &vs); err != nil {
		return nil, fmt.Errorf("malformed Claude validation: %w", err)
	}
	out := append([]models.Finding(nil), in...)
	seen := map[int]bool{}
	for _, v := range vs {
		confidence := float64(v.Confidence)
		if v.FindingIndex < 0 || v.FindingIndex >= len(out) || seen[v.FindingIndex] || confidence < 0 || confidence > 1 {
			continue
		}
		seen[v.FindingIndex] = true
		if !bool(v.IsValid) {
			confidence = 0
		}
		f := &out[v.FindingIndex]
		f.AIConfidence = confidence
		f.AIAnalysis = v.Reason + " Exploitation feasibility: " + v.ExploitationFeasibility
		f.IsZeroDay = bool(v.ZeroDayPotential)
	}
	return out, nil
}

func buildLanguageAwarePrompt(in []models.Finding) string {
	contexts := map[string]string{
		"python":     "SQL injection, command injection, pickle deserialization, and path traversal",
		"javascript": "prototype pollution, XSS, ReDoS, template injection, and open redirect",
		"java":       "XXE, deserialization, SQL/LDAP injection, and expression-language injection",
		"go":         "unchecked errors, race conditions, integer overflow, and unsafe operations",
		"php":        "type juggling, filter bypass, LFI/RFI, and eval injection",
		"ruby":       "eval injection, YAML deserialization, command injection, and path traversal",
		"cpp":        "buffer overflow, use-after-free, integer overflow, and format strings",
		"dotnet":     "XXE, deserialization, SQL injection, and LINQ injection",
		"swift":      "unsafe memory operations and force-unwrap issues",
		"kotlin":     "Java interoperability, deserialization, injection, and authorization flaws",
		"rust":       "unsafe blocks, memory-safety boundary violations, and vulnerable dependencies",
	}
	groups := map[string][]int{}
	for i, f := range in {
		lang := f.Language
		if lang == "" {
			lang = "unknown"
		}
		groups[lang] = append(groups[lang], i)
	}
	var b strings.Builder
	b.WriteString("You are a security validation engine. Validate scanner findings in their language context. Determine whether each is real or a false positive, confidence 0-1, exploitation feasibility, possible chains, and zero-day potential.\nLanguage context:\n")
	languages := make([]string, 0, len(groups))
	for lang := range groups {
		languages = append(languages, lang)
	}
	sort.Strings(languages)
	for _, lang := range languages {
		indexes := groups[lang]
		fmt.Fprintf(&b, "- %s (finding indexes %v): focus on %s.\n", lang, indexes, contexts[lang])
	}
	b.WriteString("Return ONLY a JSON array with keys finding_index, is_valid, confidence, reason, exploitation_feasibility, zero_day_potential. is_valid and zero_day_potential MUST be JSON boolean literals true or false, never numbers or explanatory text. confidence MUST be a number from 0 to 1. Preserve the original finding indexes and do not use markdown. Findings:\n")
	payload, _ := json.Marshal(in)
	b.Write(payload)
	return b.String()
}
