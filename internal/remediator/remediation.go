package remediator

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/example/sast-dast-analyzer/internal/models"
)

type RemediationEngine struct{}
type AIClient interface {
	ValidateFindings(context.Context, string) (string, error)
}

func NewRemediationEngine() *RemediationEngine { return &RemediationEngine{} }
func (re *RemediationEngine) GenerateRemediations(f models.Finding) []models.RemediationSuggestion {
	kind := classify(f)
	s := suggestions[kind]
	if s.Title == "" {
		s = models.RemediationSuggestion{Title: "Review and remediate the vulnerable data flow", Description: "Trace untrusted input to the reported sink, apply a fail-closed control, and add a regression test.", Severity: f.Severity, Link: "https://cwe.mitre.org/", Feasibility: .7, Effort: "medium", RiskReduction: .7}
	}
	s.Severity = f.Severity
	return []models.RemediationSuggestion{s}
}
func (re *RemediationEngine) GenerateRemediationsWithAI(ctx context.Context, client AIClient, f models.Finding) ([]models.RemediationSuggestion, error) {
	if client == nil {
		return re.GenerateRemediations(f), nil
	}
	safe := f
	safe.CodeSnippet = "[omitted]"
	payload, _ := json.Marshal(safe)
	prompt := "Generate one secure, minimal, language-specific remediation for this finding. Return ONLY a JSON array matching fields title, description, code_before, code_after, severity, link, feasibility (0-1), effort, risk_reduction (0-1). Never include real credentials. Finding: " + string(payload)
	raw, err := client.ValidateFindings(ctx, prompt)
	if err != nil {
		return re.GenerateRemediations(f), err
	}
	raw = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(raw), "```json"), "```"), "```"))
	var out []models.RemediationSuggestion
	if err = json.Unmarshal([]byte(raw), &out); err != nil {
		return re.GenerateRemediations(f), fmt.Errorf("parse AI remediation: %w", err)
	}
	if len(out) == 0 {
		return re.GenerateRemediations(f), nil
	}
	return out, nil
}
func classify(f models.Finding) string {
	v := strings.ToLower(f.CWE + " " + f.Title + " " + f.Description)
	switch {
	case strings.Contains(v, "cwe-89") || strings.Contains(v, "sql injection"):
		return "sql"
	case strings.Contains(v, "cwe-798") || strings.Contains(v, "secret") || strings.Contains(v, "credential"):
		return "secret"
	case strings.Contains(v, "cwe-327") || strings.Contains(v, "weak crypto"):
		return "crypto"
	case strings.Contains(v, "cwe-862") || strings.Contains(v, "missing auth"):
		return "auth"
	case strings.Contains(v, "cwe-611") || strings.Contains(v, "xxe"):
		return "xxe"
	}
	return ""
}

var suggestions = map[string]models.RemediationSuggestion{
	"sql":    {Title: "Use parameterized database operations", Description: "Replace string-built SQL with placeholders or an ORM binding API.", CodeBefore: `query := "SELECT * FROM users WHERE id=" + input`, CodeAfter: `row := db.QueryRowContext(ctx, "SELECT * FROM users WHERE id = ?", input)`, Link: "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html", Feasibility: .9, Effort: "low", RiskReduction: .95},
	"secret": {Title: "Rotate and externalize the credential", Description: "Revoke the exposed value, purge it from history, and retrieve its replacement from a secret manager.", CodeBefore: `const apiKey = "[REDACTED]"`, CodeAfter: `apiKey := os.Getenv("API_KEY")`, Link: "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html", Feasibility: .85, Effort: "medium", RiskReduction: .98},
	"crypto": {Title: "Replace obsolete cryptography", Description: "Use a maintained AEAD construction and platform cryptographic random source.", CodeBefore: `md5.Sum(data)`, CodeAfter: `sha256.Sum256(data) // for hashing; use Argon2id for passwords`, Link: "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html", Feasibility: .75, Effort: "medium", RiskReduction: .9},
	"auth":   {Title: "Enforce authorization at the resource boundary", Description: "Require authenticated identity and a deny-by-default policy check before accessing the resource.", CodeAfter: `if !policy.Allowed(subject, action, resource) { return ErrForbidden }`, Link: "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html", Feasibility: .75, Effort: "medium", RiskReduction: .95},
	"xxe":    {Title: "Disable external XML entities", Description: "Configure the parser to reject DTDs and external entity resolution, then validate against an allowlisted schema.", Link: "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html", Feasibility: .9, Effort: "low", RiskReduction: .95},
}
