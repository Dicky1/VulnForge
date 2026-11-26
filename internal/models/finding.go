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
	DASTEvidence           *DASTEvidence           `json:"dast_evidence,omitempty"`
	CreatedAt              time.Time               `json:"created_at"`
}

type DASTEndpoint struct {
	RequestedURL string `json:"requested_url" xml:"requestedURL"`
	FinalURL     string `json:"final_url,omitempty" xml:"finalURL,omitempty"`
	StatusCode   int    `json:"status_code,omitempty" xml:"statusCode,omitempty"`
	Error        string `json:"error,omitempty" xml:"error,omitempty"`
}

type DASTEvidence struct {
	Endpoint          DASTEndpoint `json:"endpoint" xml:"endpoint"`
	Method            string       `json:"method" xml:"method"`
	HeaderName        string       `json:"header_name,omitempty" xml:"headerName,omitempty"`
	CookieName        string       `json:"cookie_name,omitempty" xml:"cookieName,omitempty"`
	MissingAttributes []string     `json:"missing_attributes,omitempty" xml:"missingAttribute,omitempty"`

	// Request/Response are a redacted, size-bounded capture of the exact
	// HTTP exchange that produced this finding, so it can be reproduced
	// and reviewed without re-running the scan.
	Request  *RequestEvidence  `json:"request,omitempty" xml:"request,omitempty"`
	Response *ResponseEvidence `json:"response,omitempty" xml:"response,omitempty"`
	// Timestamp is when the evidence-producing request was made.
	Timestamp time.Time `json:"timestamp,omitempty" xml:"timestamp,omitempty"`
	// CurlCommand is a safely-quoted, reproducible curl invocation for the
	// captured request. It never contains unredacted secrets.
	CurlCommand string `json:"curl_command,omitempty" xml:"curlCommand,omitempty"`

	// PayloadClass and InjectionPoint identify, for active findings, which
	// payload engine class produced the evidence and where it was injected
	// (e.g. "xss.reflected", "query:search").
	PayloadClass   string `json:"payload_class,omitempty" xml:"payloadClass,omitempty"`
	InjectionPoint string `json:"injection_point,omitempty" xml:"injectionPoint,omitempty"`

	// OOBToken is the unique correlation token embedded in the request when
	// this finding relies on out-of-band confirmation (blind SSRF/SSTI/XXE,
	// async command injection, etc). OOBInteraction is filled in once a
	// matching callback is observed by the listener.
	OOBToken       string          `json:"oob_token,omitempty" xml:"oobToken,omitempty"`
	OOBInteraction *OOBInteraction `json:"oob_interaction,omitempty" xml:"oobInteraction,omitempty"`
}

// HTTPHeader is a single captured header name/value pair. A slice is used
// instead of map[string][]string so JSON/XML output preserves order and
// XML can use a repeated element.
type HTTPHeader struct {
	Name  string `json:"name" xml:"name"`
	Value string `json:"value" xml:"value"`
}

// RequestEvidence is a redacted, size-bounded capture of an HTTP request.
type RequestEvidence struct {
	Method          string       `json:"method" xml:"method"`
	URL             string       `json:"url" xml:"url"`
	Headers         []HTTPHeader `json:"headers,omitempty" xml:"headers>header,omitempty"`
	Body            string       `json:"body,omitempty" xml:"body,omitempty"`
	BodyTruncated   bool         `json:"body_truncated,omitempty" xml:"bodyTruncated,omitempty"`
	RedactedHeaders []string     `json:"redacted_headers,omitempty" xml:"redactedHeaders>name,omitempty"`
}

// ResponseEvidence is a redacted, size-bounded capture of an HTTP response.
type ResponseEvidence struct {
	StatusCode    int          `json:"status_code" xml:"statusCode"`
	Headers       []HTTPHeader `json:"headers,omitempty" xml:"headers>header,omitempty"`
	Body          string       `json:"body,omitempty" xml:"body,omitempty"`
	BodyTruncated bool         `json:"body_truncated,omitempty" xml:"bodyTruncated,omitempty"`
}

// OOBInteraction records a single out-of-band callback that correlates to a
// finding's OOBToken, as observed by an internal/oob listener.
type OOBInteraction struct {
	Token      string    `json:"token" xml:"token"`
	Protocol   string    `json:"protocol,omitempty" xml:"protocol,omitempty"`
	SourceIP   string    `json:"source_ip,omitempty" xml:"sourceIP,omitempty"`
	ReceivedAt time.Time `json:"received_at,omitempty" xml:"receivedAt,omitempty"`
	RawRequest string    `json:"raw_request,omitempty" xml:"rawRequest,omitempty"`
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
	Tool      string          `json:"tool"`
	TargetURL string          `json:"target_url,omitempty"`
	Endpoint  *DASTEndpoint   `json:"endpoint,omitempty"`
	Findings  []Finding       `json:"findings"`
	RawJSON   json.RawMessage `json:"raw_json,omitempty"`
	ExitCode  int             `json:"exit_code"`
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
	DASTTargetURL     string             `json:"dast_target_url,omitempty"`
	DASTEndpoints     []DASTEndpoint     `json:"dast_endpoints,omitempty"`
	DASTSession       string             `json:"dast_session,omitempty"`
	IncompleteChecks  []string           `json:"incomplete_checks,omitempty"`
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
