package models

import (
	"encoding/json"
	"time"
)

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

type Finding struct {
	ID                     string                  `json:"id"`
	Title                  string                  `json:"title"`
	Description            string                  `json:"description"`
	Severity               Severity                `json:"severity"`
	CVSSBase               float64                 `json:"cvss_base"`
	CWE                    string                  `json:"cwe,omitempty"`
	MITRETechniques        []string                `json:"mitre_techniques,omitempty"`
	SourceTool             string                  `json:"source_tool"`
	Language               string                  `json:"language,omitempty"`
	FilePath               string                  `json:"file_path"`
	LineNumber             int                     `json:"line_number"`
	CodeSnippet            string                  `json:"code_snippet,omitempty"`
	AIConfidence           float64                 `json:"ai_confidence"`
	AIAnalysis             string                  `json:"ai_analysis,omitempty"`
	ExploitChain           []string                `json:"exploit_chain,omitempty"`
	IsZeroDay              bool                    `json:"is_zero_day"`
	Remediation            string                  `json:"remediation,omitempty"`
	RemediationSuggestions []RemediationSuggestion `json:"remediation_suggestions,omitempty"`
	Compliance             map[string][]string     `json:"compliance,omitempty"`
	CVSSVector             string                  `json:"cvss_vector,omitempty"`
	CreatedAt              time.Time               `json:"created_at"`
}

type RemediationSuggestion struct {
	Title         string   `json:"title"`
	Description   string   `json:"description"`
	CodeBefore    string   `json:"code_before,omitempty"`
	CodeAfter     string   `json:"code_after,omitempty"`
	Severity      Severity `json:"severity"`
	Link          string   `json:"link,omitempty"`
	Feasibility   float64  `json:"feasibility"`
	Effort        string   `json:"effort"`
	RiskReduction float64  `json:"risk_reduction"`
}

type ComplianceGap struct {
	Control        string    `json:"control" yaml:"control"`
	Description    string    `json:"description" yaml:"description"`
	Recommendation string    `json:"recommendation" yaml:"recommendation"`
	Findings       []Finding `json:"findings,omitempty" yaml:"-"`
}

type ComplianceReport struct {
	Framework       string                   `json:"framework"`
	Gaps            map[string]ComplianceGap `json:"gaps"`
	CoveragePercent float64                  `json:"coverage_percentage"`
	Recommendations []string                 `json:"recommendations"`
}

type ToolOutput struct {
	Tool     string          `json:"tool"`
	Findings []Finding       `json:"findings"`
	RawJSON  json.RawMessage `json:"raw_json,omitempty"`
	ExitCode int             `json:"exit_code"`
}

type ScanConfig struct {
	TargetPath          string   `json:"target_path"`
	Language            string   `json:"language"`
	EnableSAST          bool     `json:"enable_sast"`
	EnableDAST          bool     `json:"enable_dast"`
	SASTTools           []string `json:"sast_tools"`
	DASTTools           []string `json:"dast_tools"`
	AIValidation        bool     `json:"ai_validation"`
	ConfidenceThreshold float64  `json:"confidence_threshold"`
	MaxWorkers          int      `json:"max_workers"`
	TokenBudget         int      `json:"token_budget"`
}

type Report struct {
	ID                string             `json:"id,omitempty" xml:"id,omitempty"`
	Timestamp         time.Time          `json:"timestamp"`
	TargetPath        string             `json:"target_path"`
	Language          string             `json:"language"`
	TotalFindings     int                `json:"total_findings"`
	CriticalCount     int                `json:"critical_count"`
	HighCount         int                `json:"high_count"`
	Findings          []Finding          `json:"findings"`
	ZeroDayFindings   []Finding          `json:"zero_day_findings"`
	TokenUsed         int                `json:"token_used"`
	Duration          string             `json:"duration"`
	ComplianceReports []ComplianceReport `json:"compliance_reports,omitempty"`
	GitBranch         string             `json:"git_branch,omitempty"`
	GitCommit         string             `json:"git_commit,omitempty"`
}
