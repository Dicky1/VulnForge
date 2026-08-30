package main

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/example/sast-dast-analyzer/internal/agent"
	"github.com/example/sast-dast-analyzer/internal/compliance"
	"github.com/example/sast-dast-analyzer/internal/config"
	"github.com/example/sast-dast-analyzer/internal/detector"
	"github.com/example/sast-dast-analyzer/internal/integrations"
	"github.com/example/sast-dast-analyzer/internal/models"
	"github.com/example/sast-dast-analyzer/internal/optimizer"
	"github.com/example/sast-dast-analyzer/internal/policies"
	"github.com/example/sast-dast-analyzer/internal/remediator"
	"github.com/example/sast-dast-analyzer/internal/reporter"
	"github.com/example/sast-dast-analyzer/internal/sbom"
	"github.com/example/sast-dast-analyzer/internal/scanner"
	"github.com/example/sast-dast-analyzer/internal/scorer"
	"github.com/example/sast-dast-analyzer/internal/storage"
	claudepkg "github.com/example/sast-dast-analyzer/pkg/claude"
	"github.com/example/sast-dast-analyzer/pkg/ninerouter"
)

type options struct {
	target, output, formats, policy, dastURL, containerImage, sbomFormat, compareID, dbPath, bountyProgram string
	track, githubActions, gitlabCI, jenkins, preCommit                                                     bool
}
type validationClient interface {
	ValidateFindings(context.Context, string) (string, error)
	TokenUsed() int
}

func main() {
	logger := log.New(os.Stderr, "analyzer ", log.LstdFlags|log.LUTC)
	defer func() {
		if r := recover(); r != nil {
			logger.Printf("fatal panic: %v", r)
			os.Exit(1)
		}
	}()
	if err := run(context.Background(), logger, os.Args[1:]); err != nil {
		logger.Printf("error: %v", err)
		os.Exit(1)
	}
}

func parseOptions(args []string) (options, error) {
	var o options
	fs := flag.NewFlagSet("analyzer", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.StringVar(&o.target, "target", "", "source directory to scan")
	fs.StringVar(&o.output, "output", "", "base report output path")
	fs.StringVar(&o.formats, "export-format", "", "comma-separated: json,html,dashboard,pdf,sarif,xml,csv,bounty-report")
	fs.StringVar(&o.policy, "policy", "", "policy YAML path")
	fs.StringVar(&o.dastURL, "dast-url", "", "authorized runtime URL for passive DAST")
	fs.BoolVar(&o.track, "track-history", false, "save report in SQLite history")
	fs.StringVar(&o.dbPath, "database", "", "SQLite database path")
	fs.StringVar(&o.containerImage, "scan-containers", "", "explicit Docker/OCI image reference")
	fs.StringVar(&o.sbomFormat, "generate-sbom", "", "generate cyclonedx or spdx SBOM")
	fs.StringVar(&o.compareID, "compare-with", "", "historical report ID to compare")
	fs.StringVar(&o.bountyProgram, "bounty-program", "", "bounty program name, handle, or platform adapter")
	fs.BoolVar(&o.githubActions, "github-actions", false, "generate GitHub Actions workflow")
	fs.BoolVar(&o.gitlabCI, "gitlab-ci", false, "generate GitLab CI configuration")
	fs.BoolVar(&o.jenkins, "jenkins", false, "generate Jenkinsfile")
	fs.BoolVar(&o.preCommit, "pre-commit", false, "generate .git/hooks/pre-commit")
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	if o.target == "" && fs.NArg() > 0 {
		o.target = fs.Arg(0)
	}
	if fs.NArg() > 1 {
		return o, fmt.Errorf("unexpected positional arguments: %v", fs.Args()[1:])
	}
	return o, nil
}

func run(ctx context.Context, logger *log.Logger, args []string) error {
	envPath := os.Getenv("ANALYZER_ENV_FILE")
	if envPath == "" {
		envPath = ".env"
	}
	if err := config.LoadEnvFile(envPath); err != nil {
		return fmt.Errorf("load environment: %w", err)
	}
	if err := config.PrepareToolPath(); err != nil {
		return fmt.Errorf("prepare tool path: %w", err)
	}
	o, err := parseOptions(args)
	if err != nil {
		return err
	}
	cfg, err := config.Load(filepath.Join("config", "config.yaml"))
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if o.target == "" {
		o.target = cfg.Analyzer.TargetPath
	}
	if o.target == "" {
		return errors.New("usage: analyzer <target-path> or analyzer --target <path>")
	}
	if o.output == "" {
		o.output = cfg.Analyzer.OutputPath
	}
	if o.output == "" {
		o.output = "report.json"
	}
	if o.formats == "" {
		o.formats = strings.Join(cfg.Analyzer.ExportFormats, ",")
	}
	if o.formats == "" {
		o.formats = "json"
	}
	if o.policy == "" {
		o.policy = cfg.Analyzer.Policy
	}
	if o.dbPath == "" {
		o.dbPath = cfg.Storage.DatabasePath
	}
	if o.sbomFormat == "" && cfg.SBOM.Generate {
		o.sbomFormat = cfg.SBOM.Format
	}
	o.track = o.track || cfg.Storage.Enabled
	target, err := filepath.Abs(o.target)
	if err != nil {
		return err
	}
	info, err := os.Stat(target)
	if err != nil {
		return fmt.Errorf("invalid target: %w", err)
	}
	if !info.IsDir() {
		return errors.New("target must be a directory")
	}
	started := time.Now()
	var policy *policies.Policy
	if o.policy != "" {
		policy, err = policies.NewPolicyEngine().LoadPolicy(o.policy)
		if err != nil {
			return fmt.Errorf("load policy: %w", err)
		}
	}
	if err = generateIntegrations(target, o, cfg); err != nil {
		return err
	}
	ld := detector.NewLanguageDetector(target)
	languages, err := ld.DetectLanguages()
	if err != nil {
		return fmt.Errorf("detect languages: %w", err)
	}
	logger.Printf("detected languages: %s", summarizeLanguages(languages))
	autoInstall := config.EnvBool("ANALYZER_AUTO_INSTALL", false)
	aiEnabled := config.EnvBool("ANALYZER_AI_ENABLED", cfg.Validator.EnableAI)
	logger.Printf("environment ready: auto-install=%t ai-enabled=%t ai-provider=%s", autoInstall, aiEnabled, effectiveAIProvider(cfg))
	setup := &agent.SetupAgent{Timeout: time.Duration(cfg.SAST.Timeout) * time.Second, AllowInstall: autoInstall, Logger: logger}
	if parsed, e := setup.ParseREADME(filepath.Join(target, "README.md")); e == nil {
		if e = setup.AutoInstallAndRun(ctx, parsed); e != nil {
			logger.Printf("README setup skipped: %v", e)
		}
	}
	var findings []models.Finding
	if cfg.SAST.Enabled {
		sast := &agent.SASTAgent{Timeout: time.Duration(cfg.SAST.Timeout) * time.Second, Logger: logger, MaxWorkers: cfg.Validator.MaxWorkers, AutoInstall: autoInstall}
		findings, err = sast.RunMultiLanguageSASTScan(ctx, target, languages)
		if err != nil {
			logger.Printf("SAST degraded: %v", err)
		}
	}
	if cfg.SecretDetection.Enabled {
		sd := scanner.NewSecretDetector()
		sd.EntropyThreshold = cfg.SecretDetection.HighEntropyThreshold
		sd.ExcludePaths = append(sd.ExcludePaths, cfg.SecretDetection.ExcludePaths...)
		secrets, e := sd.Scan(ctx, target)
		if e != nil {
			return fmt.Errorf("secret detection: %w", e)
		}
		findings = append(findings, secrets...)
	}
	if o.dastURL != "" {
		dast := scanner.BaselineDAST{Timeout: time.Duration(cfg.DAST.TimeoutSeconds) * time.Second, MaxBodyBytes: cfg.DAST.MaxBodyBytes}
		result, e := dast.Scan(ctx, o.dastURL)
		if e != nil {
			logger.Printf("DAST degraded: %v", e)
		} else {
			findings = append(findings, result.Findings...)
		}
	}
	if o.containerImage != "" {
		cs := scanner.NewContainerScanner()
		cs.Scanner = cfg.Container.Scanner
		containerFindings, e := cs.Scan(ctx, o.containerImage)
		if e != nil {
			logger.Printf("container scan degraded: %v", e)
		} else {
			findings = append(findings, containerFindings...)
		}
	}
	opt := optimizer.Tokenizer{Budget: cfg.Optimizer.MaxTokenBudget, SkipPatterns: cfg.Optimizer.SkipPatterns}
	findings = opt.FilterFindings(findings)
	if cfg.Scoring.CVSSEnabled {
		calc := &scorer.CVSSCalculator{}
		for i := range findings {
			m := calc.MetricsForFinding(findings[i])
			findings[i].CVSSBase = calc.CalculateScore(m)
			findings[i].CVSSVector = scorer.Vector(m)
			if cfg.Scoring.SeverityMapping {
				findings[i].Severity = calc.SeverityFromScore(findings[i].CVSSBase)
			}
		}
	}
	tokenUsed := 0
	var aiClient validationClient
	if aiEnabled && len(findings) > 0 {
		client, e := newAIClient(ctx, cfg)
		if e != nil {
			logger.Printf("AI validation disabled: %v", e)
		} else {
			aiClient = client
			ai := &agent.AIValidationAgent{Client: client, BatchSize: cfg.Validator.BatchSize, MaxWorkers: cfg.Validator.MaxWorkers, ConfidenceThreshold: cfg.Validator.ConfidenceThreshold}
			validated, e := ai.ValidateFindingsInBatch(ctx, findings)
			if e != nil {
				logger.Printf("AI validation partially failed: %v", e)
			}
			if len(validated) > 0 || e == nil {
				findings = validated
			}
			findings = opt.FilterFindings(findings)
			tokenUsed = client.TokenUsed()
		}
	}
	var zeros []models.Finding
	if cfg.ZeroDayDetection.Enable {
		zeros, err = agent.DetectZeroDayPatterns(ctx, target)
		if err != nil {
			return err
		}
		findings = append(findings, zeros...)
	}
	findings = policies.NewPolicyEngine().ApplyPolicy(findings, policy)
	cm := compliance.NewComplianceMapper()
	owaspGroups := cm.MapToOWASPTop10(findings)
	topGroups := cm.MapToCWETop25(findings)
	for i := range findings {
		findings[i].Compliance = map[string][]string{}
		for category, group := range owaspGroups {
			if containsFinding(group, findings[i].ID) {
				findings[i].Compliance["OWASP Top 10"] = append(findings[i].Compliance["OWASP Top 10"], category)
			}
		}
		for cwe, group := range topGroups {
			if containsFinding(group, findings[i].ID) {
				findings[i].Compliance["CWE Top 25"] = append(findings[i].Compliance["CWE Top 25"], cwe)
			}
		}
	}
	if cfg.Remediation.Enabled {
		engine := remediator.NewRemediationEngine()
		for i := range findings {
			suggestions := engine.GenerateRemediations(findings[i])
			if cfg.Remediation.AIPowered && aiClient != nil {
				if generated, e := engine.GenerateRemediationsWithAI(ctx, aiClient, findings[i]); e == nil {
					suggestions = generated
				} else {
					logger.Printf("AI remediation fallback for %s: %v", findings[i].ID, e)
				}
			}
			findings[i].RemediationSuggestions = suggestions
			if findings[i].Remediation == "" && len(findings[i].RemediationSuggestions) > 0 {
				findings[i].Remediation = findings[i].RemediationSuggestions[0].Description
			}
		}
		if aiClient != nil {
			tokenUsed = aiClient.TokenUsed()
		}
	}
	var complianceReports []models.ComplianceReport
	if cfg.Report.IncludeCompliance {
		for _, framework := range []string{"GDPR", "PCI-DSS", "HIPAA", "SOC2", "ISO27001"} {
			complianceReports = append(complianceReports, cm.GenerateReport(findings, framework))
		}
	}
	if o.sbomFormat != "" {
		bom, e := sbom.NewSBOMGenerator().GenerateSBOM(target, o.sbomFormat)
		if e != nil {
			return fmt.Errorf("generate SBOM: %w", e)
		}
		b, _ := json.MarshalIndent(bom, "", "  ")
		name := "sbom.cyclonedx.json"
		if strings.HasPrefix(strings.ToLower(o.sbomFormat), "spdx") {
			name = "sbom.spdx.json"
		} else if strings.Contains(strings.ToLower(o.sbomFormat), "xml") {
			b, _ = xml.MarshalIndent(bom, "", "  ")
			b = append([]byte(xml.Header), b...)
			name = "sbom.cyclonedx.xml"
		}
		if e = os.WriteFile(name, b, 0600); e != nil {
			return e
		}
	}
	var businessReport *models.BusinessReport
	if cfg.Reporter.EnableBusinessImpact {
		businessContext := models.BusinessContext{BusinessType: cfg.BusinessContext.BusinessType, AnnualRevenue: cfg.BusinessContext.AnnualRevenue, NumUsers: cfg.BusinessContext.NumUsers, AverageUserValue: cfg.BusinessContext.AverageUserValue, GeographicScope: cfg.BusinessContext.GeographicScope, PrimaryCompliance: cfg.BusinessContext.PrimaryCompliance, Multipliers: cfg.FinancialMultipliers, Penalties: cfg.CompliancePenalties}
		businessReport = reporter.BuildBusinessReport(findings, businessContext, reporter.BusinessReportOptions{EnablePOC: cfg.Reporter.EnablePOCGeneration, EnableRoadmap: cfg.Reporter.EnableRemediationRoadmap, POCSkillLevel: cfg.Reporter.POCSkillLevel})
		priority := map[string]int{}
		for _, finding := range businessReport.Findings {
			priority[finding.FindingID] = finding.PriorityScore
		}
		sort.SliceStable(findings, func(i, j int) bool { return priority[findings[i].ID] < priority[findings[j].ID] })
	} else {
		sort.SliceStable(findings, func(i, j int) bool { return rank(findings[i].Severity) > rank(findings[j].Severity) })
	}
	var bountyBundle *models.BountyBundle
	if cfg.BugBounty.Enabled {
		platform, programName := bountySelection(o.bountyProgram)
		bountyReporter := reporter.BugBountyReporter{Options: reporter.BountyReporterOptions{Platform: platform, ProgramName: programName, Target: target, Programs: cfg.BugBounty.BountyPrograms, POCFormats: cfg.BugBounty.IncludePOCFormats, MinSeverity: parseSeverity(cfg.BugBounty.SubmissionQualityChecks.MinSeverityLevel)}}
		bundle := bountyReporter.BuildBundle(findings, businessReport)
		bountyBundle = &bundle
	}
	report := models.Report{ID: fmt.Sprintf("scan-%d", time.Now().UnixNano()), Timestamp: time.Now().UTC(), TargetPath: target, Language: summarizeLanguages(languages), Findings: findings, ZeroDayFindings: zeros, TotalFindings: len(findings), TokenUsed: tokenUsed, Duration: time.Since(started).String(), ComplianceReports: complianceReports, BusinessReport: businessReport, BountyBundle: bountyBundle}
	for _, f := range findings {
		if f.Severity == models.SeverityCritical {
			report.CriticalCount++
		}
		if f.Severity == models.SeverityHigh {
			report.HighCount++
		}
	}
	if integrations.DetectGitRepo(target) {
		report.GitBranch = integrations.GetCurrentBranch(target)
		report.GitCommit = integrations.GetCommitHash(target)
	}
	if o.track || o.compareID != "" {
		db, e := storage.OpenSQLite(o.dbPath)
		if e != nil {
			return fmt.Errorf("open history database: %w", e)
		}
		defer db.Close()
		if _, e = db.SaveReport(ctx, report); e != nil {
			return fmt.Errorf("save report history: %w", e)
		}
		if e = db.PruneOlderThan(ctx, cfg.Storage.RetentionDays); e != nil {
			logger.Printf("history retention cleanup failed: %v", e)
		}
		if o.compareID != "" {
			comparison, e := db.CompareReports(ctx, o.compareID, report.ID)
			if e != nil {
				return fmt.Errorf("compare reports: %w", e)
			}
			logger.Printf("history comparison: new=%d fixed=%d regressions=%d", len(comparison.NewFindings), len(comparison.FixedFindings), len(comparison.Regressions))
		}
	}
	exporter := reporter.NewReportExporter()
	for _, format := range splitFormats(o.formats) {
		path := outputForFormat(o.output, format)
		if e := exporter.Export(report, format, path); e != nil {
			return fmt.Errorf("export %s: %w", format, e)
		}
		logger.Printf("wrote %s", path)
	}
	fmt.Printf("Scan complete: id=%s total=%d critical=%d high=%d zero_day=%d tokens=%d duration=%s\n", report.ID, report.TotalFindings, report.CriticalCount, report.HighCount, len(zeros), tokenUsed, report.Duration)
	return nil
}

func newAIClient(ctx context.Context, cfg config.Config) (validationClient, error) {
	provider := effectiveAIProvider(cfg)
	switch provider {
	case "9router", "nine-router", "ninerouter":
		key := os.Getenv("NINEROUTER_KEY")
		if key == "" {
			key = cfg.NineRouter.APIKey
		}
		baseURL := os.Getenv("NINEROUTER_URL")
		if baseURL == "" {
			baseURL = cfg.NineRouter.BaseURL
		}
		model := os.Getenv("NINEROUTER_MODEL")
		if model == "" {
			model = cfg.NineRouter.Model
		}
		client, err := ninerouter.NewClient(baseURL, key, model, time.Duration(cfg.NineRouter.TimeoutSeconds)*time.Second, cfg.NineRouter.MaxRetries)
		if err != nil {
			return nil, err
		}
		if cfg.NineRouter.HealthCheck {
			if err = client.Health(ctx); err != nil {
				return nil, fmt.Errorf("9Router unavailable: %w", err)
			}
		}
		return client, nil
	case "anthropic", "":
		key := os.Getenv("ANTHROPIC_API_KEY")
		if key == "" {
			key = cfg.Claude.APIKey
		}
		return claudepkg.NewClient(key, cfg.Claude.Model, time.Duration(cfg.Claude.TimeoutSeconds)*time.Second, cfg.Claude.MaxRetries)
	default:
		return nil, fmt.Errorf("unsupported AI provider %q", provider)
	}
}

func effectiveAIProvider(cfg config.Config) string {
	provider := strings.ToLower(strings.TrimSpace(os.Getenv("ANALYZER_AI_PROVIDER")))
	if provider == "" {
		provider = strings.ToLower(strings.TrimSpace(cfg.AI.Provider))
	}
	return provider
}

func generateIntegrations(target string, o options, cfg config.Config) error {
	files := map[string]string{}
	if o.githubActions || cfg.Integrations.GitHubActions {
		files[filepath.Join(target, ".github", "workflows", "security-scan.yml")] = integrations.GenerateGithubActionsYAML()
	}
	if o.gitlabCI || cfg.Integrations.GitLabCI {
		files[filepath.Join(target, ".gitlab-ci.yml")] = integrations.GenerateGitlabCIYAML()
	}
	if o.jenkins || cfg.Integrations.Jenkins {
		files[filepath.Join(target, "Jenkinsfile")] = integrations.GenerateJenkinsfile()
	}
	if o.preCommit || cfg.Integrations.PreCommit {
		if !integrations.DetectGitRepo(target) {
			return errors.New("pre-commit generation requires a Git repository")
		}
		files[filepath.Join(target, ".git", "hooks", "pre-commit")] = integrations.GeneratePreCommitHook()
	}
	for path, body := range files {
		if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
			return err
		}
		if err := os.WriteFile(path, []byte(body), 0750); err != nil {
			return err
		}
	}
	return nil
}
func splitFormats(v string) []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range strings.Split(v, ",") {
		f = strings.ToLower(strings.TrimSpace(f))
		if f != "" && !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	return out
}
func outputForFormat(path, format string) string {
	ext := "." + format
	if format == "sarif" {
		ext = ".sarif"
	} else if format == "dashboard" {
		ext = ".dashboard.html"
	} else if format == "bounty-report" {
		ext = ".bounty.json"
	}
	base := strings.TrimSuffix(path, filepath.Ext(path))
	return base + ext
}

func bountySelection(value string) (string, string) {
	lower := strings.ToLower(strings.TrimSpace(value))
	switch lower {
	case "hackerone", "bugcrowd", "intigriti", "yeswehack", "federacy":
		return lower, ""
	case "":
		return "hackerone", ""
	default:
		return "", value
	}
}
func parseSeverity(value string) models.Severity {
	switch strings.ToLower(value) {
	case "critical":
		return models.SeverityCritical
	case "high":
		return models.SeverityHigh
	case "low":
		return models.SeverityLow
	default:
		return models.SeverityMedium
	}
}
func containsFinding(v []models.Finding, id string) bool {
	for _, f := range v {
		if f.ID == id {
			return true
		}
	}
	return false
}
func rank(s models.Severity) int {
	switch s {
	case models.SeverityCritical:
		return 4
	case models.SeverityHigh:
		return 3
	case models.SeverityMedium:
		return 2
	default:
		return 1
	}
}
func summarizeLanguages(languages map[string]detector.LanguageInfo) string {
	names := make([]string, 0, len(languages))
	for name := range languages {
		names = append(names, name)
	}
	sort.Strings(names)
	if len(names) == 0 {
		return "unknown"
	}
	return strings.Join(names, ",")
}
