package config

import (
	"errors"
	"os"

	"gopkg.in/yaml.v2"
)

type Config struct {
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
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	if err := yaml.UnmarshalStrict(b, &c); err != nil {
		return c, err
	}
	return c, nil
}
