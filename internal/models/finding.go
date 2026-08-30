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
	BusinessReport    *BusinessReport    `json:"business_report,omitempty"`
	BountyBundle      *BountyBundle      `json:"bounty_bundle,omitempty"`
}

type BusinessContext struct {
	BusinessType      string             `json:"business_type"`
	AnnualRevenue     float64            `json:"annual_revenue"`
	NumUsers          int                `json:"num_users"`
	AverageUserValue  float64            `json:"average_user_value"`
	GeographicScope   string             `json:"geographic_scope"`
	PrimaryCompliance []string           `json:"primary_compliance"`
	Multipliers       map[string]float64 `json:"multipliers,omitempty"`
	Penalties         map[string]float64 `json:"penalties,omitempty"`
}

type BusinessImpact struct {
	Level                string             `json:"level"`
	AffectedUsers        int                `json:"affected_users"`
	AffectedUsersPercent float64            `json:"affected_users_percent"`
	RevenueRiskMin       float64            `json:"revenue_risk_min_idr"`
	RevenueRiskMax       float64            `json:"revenue_risk_max_idr"`
	DataExposure         string             `json:"data_exposure"`
	OperationalDowntime  float64            `json:"operational_downtime_hours"`
	CompliancePenalty    float64            `json:"compliance_penalty_idr"`
	ComplianceImpact     map[string]float64 `json:"compliance_impact_idr,omitempty"`
	Disclaimer           string             `json:"disclaimer"`
}

type FinancialMetrics struct {
	BusinessType string  `json:"business_type"`
	Multiplier   float64 `json:"multiplier"`
	MinimumIDR   float64 `json:"minimum_idr"`
	MaximumIDR   float64 `json:"maximum_idr"`
	Method       string  `json:"method"`
}

type POC struct {
	Title            string   `json:"title"`
	Description      string   `json:"description"`
	Prerequisites    []string `json:"prerequisites"`
	StepByStep       []string `json:"step_by_step"`
	ExpectedResult   string   `json:"expected_result"`
	CurlExample      string   `json:"curl_example,omitempty"`
	Screenshot       string   `json:"screenshot,omitempty"`
	SkillLevel       string   `json:"skill_level"`
	EstimatedMinutes int      `json:"estimated_minutes"`
	SafetyNotice     string   `json:"safety_notice"`
}

type BusinessProcess struct {
	Name             string   `json:"name"`
	CriticalityScore int      `json:"criticality_score"`
	AffectedFeatures []string `json:"affected_features"`
	NumUsersImpacted int      `json:"num_users_impacted"`
	RevenueImpactPct float64  `json:"revenue_impact_pct"`
	OwningTeam       string   `json:"owning_team"`
	ImpactNarrative  string   `json:"impact_narrative"`
}

type FindingExplanation struct {
	SimpleTitle      string `json:"simple_title"`
	WhatHappened     string `json:"what_happened"`
	WhyDangerous     string `json:"why_dangerous"`
	RealWorldExample string `json:"real_world_example"`
	BusinessExample  string `json:"business_example"`
	FixSummary       string `json:"fix_summary"`
	CVSSBusinessText string `json:"cvss_business_text"`
}

type BusinessFinding struct {
	FindingID       string             `json:"finding_id"`
	PriorityScore   int                `json:"priority_score"`
	PriorityLabel   string             `json:"priority_label"`
	Impact          BusinessImpact     `json:"impact"`
	Financial       FinancialMetrics   `json:"financial"`
	Processes       []BusinessProcess  `json:"affected_processes"`
	Explanation     FindingExplanation `json:"explanation"`
	POC             *POC               `json:"poc,omitempty"`
	EstimatedEffort float64            `json:"estimated_effort_hours"`
}

type RoadmapItem struct {
	FindingID     string   `json:"finding_id"`
	Title         string   `json:"title"`
	Priority      int      `json:"priority"`
	EffortHours   float64  `json:"effort_hours"`
	RequiredTeams []string `json:"required_teams"`
	Dependencies  []string `json:"dependencies"`
	TestingPlan   string   `json:"testing_plan"`
	RollbackPlan  string   `json:"rollback_plan"`
}

type RemediationPhase struct {
	Name         string        `json:"name"`
	DeadlineDays int           `json:"deadline_days"`
	TotalHours   float64       `json:"total_hours"`
	Items        []RoadmapItem `json:"items"`
}

type RemediationRoadmap struct {
	Phases []RemediationPhase `json:"phases"`
}

type ExecutiveSummary struct {
	BriefDescription      string  `json:"brief_description"`
	BusinessImpactSummary string  `json:"business_impact_summary"`
	OverallRiskLevel      string  `json:"overall_risk_level"`
	OverallRiskScore      float64 `json:"overall_risk_score"`
	Urgency               string  `json:"urgency"`
	AverageFixHours       float64 `json:"average_fix_hours"`
	TotalRevenueRiskIDR   float64 `json:"total_revenue_risk_idr"`
	TotalAffectedUsers    int     `json:"total_affected_users"`
}

type BusinessReport struct {
	GeneratedAt      time.Time                 `json:"generated_at"`
	Context          BusinessContext           `json:"context"`
	ExecutiveSummary ExecutiveSummary          `json:"executive_summary"`
	Findings         []BusinessFinding         `json:"findings"`
	Roadmap          RemediationRoadmap        `json:"remediation_roadmap"`
	SeverityCounts   map[string]int            `json:"severity_counts"`
	RiskMatrix       map[string]map[string]int `json:"risk_matrix"`
}
