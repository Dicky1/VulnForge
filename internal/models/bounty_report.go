package models

import "time"

type BountyStep struct {
	StepNumber     int    `json:"step_number"`
	Description    string `json:"description"`
	Command        string `json:"command,omitempty"`
	ExpectedResult string `json:"expected_result"`
	Screenshot     string `json:"screenshot,omitempty"`
}

type BountyPOC struct {
	Curl       string `json:"curl,omitempty"`
	Python     string `json:"python,omitempty"`
	RawHTTP    string `json:"raw_http,omitempty"`
	JavaScript string `json:"javascript,omitempty"`
	Setup      string `json:"setup"`
	Cleanup    string `json:"cleanup"`
	Expected   string `json:"expected_output"`
	Timing     string `json:"timing"`
	Safety     string `json:"safety_notice"`
}

type ImpactDescription struct {
	SecurityImpact string `json:"security_impact"`
	BusinessImpact string `json:"business_impact"`
	UserImpact     string `json:"user_impact"`
	ScopeOfImpact  string `json:"scope_of_impact"`
}

type SeverityJustification struct {
	CVSSScore        float64  `json:"cvss_score"`
	CVSSVector       string   `json:"cvss_vector"`
	Reasoning        []string `json:"reasoning"`
	IndustryStandard string   `json:"industry_standard"`
}

type BountyReferences struct {
	CVEIDs        []string `json:"cve_ids,omitempty"`
	CWEIDs        []string `json:"cwe_ids,omitempty"`
	OWASPIDs      []string `json:"owasp_ids,omitempty"`
	ExternalLinks []string `json:"external_links,omitempty"`
}

type ScopeAssessment struct {
	Status  string `json:"status"`
	Reason  string `json:"reason"`
	Program string `json:"program,omitempty"`
}

type BountyEvidence struct {
	Type string `json:"type"`
	Path string `json:"path,omitempty"`
	Note string `json:"note"`
}

type QualityCheck struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Reason string `json:"reason"`
}

type BugBountyReport struct {
	ID                    string                `json:"id"`
	Platform              string                `json:"platform"`
	Program               string                `json:"program,omitempty"`
	Title                 string                `json:"title"`
	Severity              string                `json:"severity"`
	SeverityJustification SeverityJustification `json:"severity_justification"`
	VulnerabilityType     string                `json:"vulnerability_type"`
	AffectedEndpoint      string                `json:"affected_endpoint"`
	Description           string                `json:"description"`
	StepsToReproduce      []BountyStep          `json:"steps_to_reproduce"`
	ProofOfConcept        BountyPOC             `json:"proof_of_concept"`
	Impact                ImpactDescription     `json:"impact"`
	AffectedUsers         int                   `json:"affected_users"`
	AttackScenarios       []string              `json:"attack_scenarios"`
	Remediation           []string              `json:"remediation"`
	References            BountyReferences      `json:"references"`
	Evidence              []BountyEvidence      `json:"evidence"`
	Scope                 ScopeAssessment       `json:"scope"`
	QualityChecks         []QualityCheck        `json:"quality_checks"`
	ReadyToSubmit         bool                  `json:"ready_to_submit"`
	BlockingReasons       []string              `json:"blocking_reasons,omitempty"`
	SubmissionTemplate    string                `json:"submission_template"`
	GeneratedAt           time.Time             `json:"generated_at"`
}

type BountyProgram struct {
	Name           string   `json:"name" yaml:"name"`
	Platform       string   `json:"platform" yaml:"platform"`
	Handle         string   `json:"handle" yaml:"handle"`
	Domains        []string `json:"domains" yaml:"domains"`
	OutOfScope     []string `json:"out_of_scope" yaml:"out_of_scope"`
	SeverityLevels []string `json:"severity_levels" yaml:"severity_levels"`
	Policy         string   `json:"policy,omitempty" yaml:"policy"`
}

type BountyBundle struct {
	GeneratedAt  time.Time         `json:"generated_at"`
	Target       string            `json:"target"`
	InputCount   int               `json:"input_count"`
	Reports      []BugBountyReport `json:"reports"`
	ReadyCount   int               `json:"ready_count"`
	BlockedCount int               `json:"blocked_count"`
	Excluded     []BountyExclusion `json:"excluded_findings,omitempty"`
}

type BountyExclusion struct {
	FindingID  string `json:"finding_id"`
	Title      string `json:"title"`
	SourceTool string `json:"source_tool"`
	FilePath   string `json:"file_path,omitempty"`
	Reason     string `json:"reason"`
}
