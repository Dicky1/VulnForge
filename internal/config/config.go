package config

import (
	"errors"
	"github.com/example/sast-dast-analyzer/internal/models"
	"os"

	"gopkg.in/yaml.v2"
)

type Config struct {
	BugBounty struct {
		Enabled                 bool                   `yaml:"enabled"`
		GenerateReadyToSubmit   bool                   `yaml:"generate_ready_to_submit"`
		SubmissionTemplates     map[string]bool        `yaml:"submission_templates"`
		IncludePOCFormats       []string               `yaml:"include_poc_formats"`
		SeverityMapping         map[string]string      `yaml:"severity_mapping"`
		BountyPrograms          []models.BountyProgram `yaml:"bounty_programs"`
		SubmissionQualityChecks struct {
			ValidateTitle    bool   `yaml:"validate_title"`
			ValidateSteps    bool   `yaml:"validate_steps"`
			ValidatePOC      bool   `yaml:"validate_poc"`
			CheckDuplicates  bool   `yaml:"check_duplicates"`
			CheckScope       bool   `yaml:"check_scope"`
			MinSeverityLevel string `yaml:"min_severity_level"`
		} `yaml:"submission_quality_checks"`
		ExportFormats []string `yaml:"export_formats"`
	} `yaml:"bug_bounty"`
	Reporter struct {
		EnableBusinessImpact     bool   `yaml:"enable_business_impact"`
		EnablePOCGeneration      bool   `yaml:"enable_poc_generation"`
		EnableRemediationRoadmap bool   `yaml:"enable_remediation_roadmap"`
		POCSkillLevel            string `yaml:"poc_skill_level"`
	} `yaml:"reporter"`
	BusinessContext struct {
		BusinessType      string   `yaml:"business_type"`
		AnnualRevenue     float64  `yaml:"annual_revenue"`
		NumUsers          int      `yaml:"num_users"`
		AverageUserValue  float64  `yaml:"average_user_value"`
		GeographicScope   string   `yaml:"geographic_scope"`
		PrimaryCompliance []string `yaml:"primary_compliance"`
	} `yaml:"business_context"`
	FinancialMultipliers map[string]float64 `yaml:"financial_multipliers"`
	CompliancePenalties  map[string]float64 `yaml:"compliance_penalties"`
	RemediationEffort    []struct {
		Type  string  `yaml:"type"`
		Hours float64 `yaml:"hours"`
	} `yaml:"remediation_effort"`
	TimelineDefinition struct {
		Immediate  int `yaml:"immediate"`
		Week1      int `yaml:"week1"`
		Week2      int `yaml:"week2"`
		Month1     int `yaml:"month1"`
		Month2     int `yaml:"month2"`
		Month3Plus int `yaml:"month3_plus"`
	} `yaml:"timeline_definition"`
	AI struct {
		Provider string `yaml:"provider"`
	} `yaml:"ai"`
	NineRouter struct {
		BaseURL        string `yaml:"base_url"`
		APIKey         string `yaml:"api_key"`
		Model          string `yaml:"model"`
		MaxRetries     int    `yaml:"max_retries"`
		TimeoutSeconds int    `yaml:"timeout_seconds"`
		HealthCheck    bool   `yaml:"health_check"`
	} `yaml:"ninerouter"`
	Analyzer struct {
		TargetPath    string   `yaml:"target_path"`
		OutputPath    string   `yaml:"output_path"`
		ExportFormats []string `yaml:"export_formats"`
		Policy        string   `yaml:"policy"`
	} `yaml:"analyzer"`
	Storage struct {
		Enabled       bool   `yaml:"enabled"`
		Type          string `yaml:"type"`
		DatabasePath  string `yaml:"database_path"`
		RetentionDays int    `yaml:"retention_days"`
	} `yaml:"storage"`
	SecretDetection struct {
		Enabled              bool     `yaml:"enabled"`
		HighEntropyThreshold float64  `yaml:"high_entropy_threshold"`
		ExcludePaths         []string `yaml:"exclude_paths"`
		Tools                []string `yaml:"tools"`
	} `yaml:"secret_detection"`
	Scoring struct {
		CVSSEnabled     bool   `yaml:"cvss_enabled"`
		CVSSVersion     string `yaml:"cvss_version"`
		SeverityMapping bool   `yaml:"severity_mapping"`
	} `yaml:"scoring"`
	Remediation struct {
		Enabled             bool `yaml:"enabled"`
		AIPowered           bool `yaml:"ai_powered"`
		IncludeCodeExamples bool `yaml:"include_code_examples"`
	} `yaml:"remediation"`
	Report struct {
		Formats            []string `yaml:"formats"`
		IncludeCompliance  bool     `yaml:"include_compliance"`
		IncludeRemediation bool     `yaml:"include_remediation"`
		IncludeTrend       bool     `yaml:"include_trend"`
	} `yaml:"report"`
	Container struct {
		ScanningEnabled bool     `yaml:"scanning_enabled"`
		Scanner         string   `yaml:"scanner"`
		Registries      []string `yaml:"registries"`
	} `yaml:"container"`
	SBOM struct {
		Generate               bool   `yaml:"generate"`
		Format                 string `yaml:"format"`
		IncludeVulnerabilities bool   `yaml:"include_vulnerabilities"`
	} `yaml:"sbom"`
	Integrations struct {
		GitHubActions bool `yaml:"github_actions"`
		GitLabCI      bool `yaml:"gitlab_ci"`
		Jenkins       bool `yaml:"jenkins"`
		PreCommit     bool `yaml:"pre_commit"`
	} `yaml:"integrations"`
	Claude struct {
		APIKey         string `yaml:"api_key"`
		Model          string `yaml:"model"`
		MaxRetries     int    `yaml:"max_retries"`
		TimeoutSeconds int    `yaml:"timeout_seconds"`
	} `yaml:"claude"`
	SAST struct {
		Enabled bool     `yaml:"enabled"`
		Tools   []string `yaml:"tools"`
		Timeout int      `yaml:"timeout"`
	} `yaml:"sast"`
	DAST struct {
		Enabled        bool  `yaml:"enabled"`
		TimeoutSeconds int   `yaml:"timeout_seconds"`
		MaxBodyBytes   int64 `yaml:"max_body_bytes"`
	} `yaml:"dast"`
	Validator struct {
		EnableAI            bool    `yaml:"enable_ai"`
		ConfidenceThreshold float64 `yaml:"confidence_threshold"`
		BatchSize           int     `yaml:"batch_size"`
		MaxWorkers          int     `yaml:"max_workers"`
	} `yaml:"validator"`
	Optimizer struct {
		MaxTokenBudget    int      `yaml:"max_token_budget"`
		DedupEnabled      bool     `yaml:"dedup_enabled"`
		SeverityWeighting bool     `yaml:"severity_weighting"`
		SkipPatterns      []string `yaml:"skip_patterns"`
	} `yaml:"optimizer"`
	ZeroDayDetection struct {
		Enable     bool     `yaml:"enable"`
		FocusAreas []string `yaml:"focus_areas"`
	} `yaml:"zerodaydetection"`
}

func Default() Config {
	var c Config
	c.AI.Provider = "anthropic"
	c.BugBounty.IncludePOCFormats = []string{"curl", "python", "raw_http", "javascript"}
	c.BugBounty.SubmissionQualityChecks.ValidateTitle = true
	c.BugBounty.SubmissionQualityChecks.ValidateSteps = true
	c.BugBounty.SubmissionQualityChecks.ValidatePOC = true
	c.BugBounty.SubmissionQualityChecks.CheckDuplicates = true
	c.BugBounty.SubmissionQualityChecks.CheckScope = true
	c.BugBounty.SubmissionQualityChecks.MinSeverityLevel = "medium"
	c.BugBounty.ExportFormats = []string{"json", "markdown", "html", "pdf", "plaintext"}
	c.Reporter.EnableBusinessImpact = true
	c.Reporter.EnablePOCGeneration = true
	c.Reporter.EnableRemediationRoadmap = true
	c.Reporter.POCSkillLevel = "intermediate"
	c.BusinessContext.BusinessType = "other"
	c.BusinessContext.GeographicScope = "indonesia"
	c.FinancialMultipliers = map[string]float64{"fintech": 10, "payment-gateway": 100, "payment": 100, "ecommerce": 2, "marketplace": 1.5, "saas": 1, "other": 1}
	c.CompliancePenalties = map[string]float64{"gdpr": .04, "pci-dss": 100000, "hipaa": 50000, "ccpa": 7500}
	c.TimelineDefinition.Immediate, c.TimelineDefinition.Week1, c.TimelineDefinition.Week2 = 24, 7, 14
	c.TimelineDefinition.Month1, c.TimelineDefinition.Month2, c.TimelineDefinition.Month3Plus = 30, 60, 999
	c.NineRouter.BaseURL = "http://localhost:20128"
	c.NineRouter.MaxRetries = 3
	c.NineRouter.TimeoutSeconds = 60
	c.NineRouter.HealthCheck = true
	c.Analyzer.OutputPath = "report.json"
	c.Analyzer.ExportFormats = []string{"json"}
	c.Analyzer.Policy = "policies/default.yaml"
	c.Storage.Type = "sqlite"
	c.Storage.DatabasePath = "analyzer.db"
	c.Storage.RetentionDays = 90
	c.SecretDetection.Enabled = true
	c.SecretDetection.HighEntropyThreshold = 4.5
	c.SecretDetection.ExcludePaths = []string{"test/", "vendor/", "node_modules/"}
	c.Scoring.CVSSEnabled = true
	c.Scoring.CVSSVersion = "3.1"
	c.Scoring.SeverityMapping = true
	c.Remediation.Enabled = true
	c.Remediation.IncludeCodeExamples = true
	c.Report.IncludeCompliance = true
	c.Report.IncludeRemediation = true
	c.Container.Scanner = "trivy"
	c.SBOM.Format = "cyclonedx"
	c.Claude.Model = "claude-opus-4-8"
	c.Claude.MaxRetries, c.Claude.TimeoutSeconds = 3, 30
	c.SAST.Enabled, c.SAST.Tools, c.SAST.Timeout = true, []string{"semgrep", "bandit", "gosec"}, 600
	c.DAST.TimeoutSeconds, c.DAST.MaxBodyBytes = 20, 1<<20
	c.Validator.EnableAI, c.Validator.ConfidenceThreshold = true, .75
	c.Validator.BatchSize, c.Validator.MaxWorkers = 10, 4
	c.Optimizer.MaxTokenBudget, c.Optimizer.DedupEnabled, c.Optimizer.SeverityWeighting = 5000, true, true
	c.Optimizer.SkipPatterns = []string{"TODO", "debug", `test.*password`, "fixture"}
	c.ZeroDayDetection.Enable = true
	c.ZeroDayDetection.FocusAreas = []string{"crypto", "validation", "authorization", "logic", "race_conditions"}
	return c
}

func Load(path string) (Config, error) {
	c := Default()
	defaultMultipliers := c.FinancialMultipliers
	defaultPenalties := c.CompliancePenalties
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	c.FinancialMultipliers = nil
	c.CompliancePenalties = nil
	if err := yaml.UnmarshalStrict(b, &c); err != nil {
		return c, err
	}
	if c.FinancialMultipliers == nil {
		c.FinancialMultipliers = map[string]float64{}
	}
	for key, value := range defaultMultipliers {
		if _, found := c.FinancialMultipliers[key]; !found {
			c.FinancialMultipliers[key] = value
		}
	}
	if c.CompliancePenalties == nil {
		c.CompliancePenalties = map[string]float64{}
	}
	for key, value := range defaultPenalties {
		if _, found := c.CompliancePenalties[key]; !found {
			c.CompliancePenalties[key] = value
		}
	}
	return c, nil
}
