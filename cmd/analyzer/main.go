package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
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
	"github.com/example/sast-dast-analyzer/internal/oob"
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
	"gopkg.in/yaml.v2"
)

type options struct {
	target, output, formats, policy, dastURL, containerImage, sbomFormat, compareID, dbPath, bountyProgram, configPath string
	track, githubActions, gitlabCI, jenkins, preCommit                                                                 bool
	dastOnly, dastDirect                                                                                               bool
	dastTargets, dastSession                                                                                           string
	dastInterval                                                                                                       time.Duration
	dastMaxRequests                                                                                                    int
	dastActive                                                                                                         bool
	oobCallbackHost, oobListenAddr                                                                                     string
	oobWait                                                                                                            time.Duration
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
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, logger, os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return // -h/--help already printed usage; not an error
		}
		logger.Printf("error: %v", err)
		os.Exit(1)
	}
}

func parseOptions(args []string) (options, error) {
	var o options
	name := "analyzer"
	if len(args) > 0 && args[0] == "dast" {
		o.dastOnly = true
		name += " dast"
		args = args[1:]
	}
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.StringVar(&o.target, "target", "", "source directory to scan")
	fs.StringVar(&o.output, "output", "", "base report output path")
	fs.StringVar(&o.formats, "export-format", "", "comma-separated: json,html,dashboard,pdf,sarif,xml,csv,bounty-report")
	fs.StringVar(&o.policy, "policy", "", "policy YAML path")
	fs.StringVar(&o.configPath, "config", "", "config YAML path (default $ANALYZER_CONFIG or config/config.yaml)")
	fs.StringVar(&o.dastURL, "dast-url", "", "authorized runtime URL for passive DAST")
	fs.StringVar(&o.dastTargets, "dast-targets", "", "YAML manifest of an authorized origin and endpoint paths")
	fs.StringVar(&o.dastSession, "dast-session", "", "use an existing bearer or cookie session in dast mode")
	fs.DurationVar(&o.dastInterval, "dast-interval", 250*time.Millisecond, "minimum interval between DAST requests, including redirects")
	fs.IntVar(&o.dastMaxRequests, "dast-max-requests", 100, "DAST request budget, including redirects")
	fs.BoolVar(&o.dastDirect, "dast-no-proxy", false, "ignore proxy environment settings for DAST")
	fs.BoolVar(&o.dastActive, "active", false, "enable opt-in active payload injection against existing query parameters (dast subcommand, single --dast-url only)")
	fs.StringVar(&o.oobCallbackHost, "dast-oob-host", "", "externally reachable host used to build out-of-band (OOB) callback URLs for blind SSRF/XXE/command-injection probes")
	fs.StringVar(&o.oobListenAddr, "dast-oob-listen", "", "local address to bind a built-in OOB HTTP listener (e.g. :8080); requires --dast-oob-host to be reachable at that address")
	fs.DurationVar(&o.oobWait, "dast-oob-wait", 3*time.Second, "how long to wait for an out-of-band callback per probe")
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
	if fs.NArg() > 0 {
		if o.target != "" || fs.NArg() != 1 {
			return o, errors.New("provide a single source directory and put flags before positional arguments")
		}
		o.target = fs.Arg(0)
	}
	return o, nil
}

func run(ctx context.Context, logger *log.Logger, args []string) error {
	if len(args) >= 2 && args[0] == "dast" && args[1] == "inventory" {
		return writeDASTInventory(args[2:], os.Stdout)
	}
	o, err := parseOptions(args)
	if err != nil {
		return err
	}
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
	if o.configPath == "" {
		o.configPath = os.Getenv("ANALYZER_CONFIG")
	}
	if o.configPath == "" {
		o.configPath = filepath.Join("config", "config.yaml")
	} else if _, statErr := os.Stat(o.configPath); statErr != nil {
		// An explicitly requested config must exist; only the implicit
		// default may silently fall back to built-in defaults.
		return fmt.Errorf("load config: %w", statErr)
	}
	cfg, err := config.Load(o.configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	sandboxEnabled := config.EnvBool("ANALYZER_SANDBOX_ENABLED", cfg.Sandbox.Enabled)
	scanner.ConfigureSandbox(scanner.SandboxConfig{
		Enabled:        sandboxEnabled,
		NetworkDefault: cfg.Sandbox.NetworkDefault,
		Memory:         cfg.Sandbox.Memory,
		CPUs:           cfg.Sandbox.CPUs,
		PIDsLimit:      cfg.Sandbox.PIDsLimit,
		Images:         cfg.Sandbox.Images,
		NetworkAllow:   toSet(cfg.Sandbox.NetworkAllow),
	})
	if o.target == "" && !o.dastOnly {
		o.target = cfg.Analyzer.TargetPath
	}
	hasDAST := o.dastURL != "" || o.dastTargets != ""
	if o.dastOnly && (o.target != "" || o.containerImage != "") {
		return errors.New("dast mode only accepts web targets")
	}
	if o.target == "" && !hasDAST {
		return errors.New("provide a source directory with --target or web targets with --dast-url or --dast-targets")
	}
	if o.dastSession != "" && !o.dastOnly {
		return errors.New("use the dast subcommand for an authenticated scan")
	}
	if o.dastActive {
		if !o.dastOnly {
			return errors.New("--active requires the dast subcommand")
		}
		if o.dastURL == "" || o.dastTargets != "" {
			return errors.New("--active requires a single --dast-url (not --dast-targets)")
		}
	}
	if o.oobListenAddr != "" && !o.dastActive {
		return errors.New("--dast-oob-listen requires --active")
	}
	hasSource := o.target != ""
	if !hasSource && (o.sbomFormat != "" || o.githubActions || o.gitlabCI || o.jenkins || o.preCommit) {
		return errors.New("SBOM and integration generation require a source directory")
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
	if o.policy == "" && cfg.Analyzer.Policy != "" {
		// The configured default policy path is relative to the working
		// directory; running the binary from elsewhere must not abort the
		// whole scan just because that default file is absent.
		if _, statErr := os.Stat(cfg.Analyzer.Policy); statErr == nil {
			o.policy = cfg.Analyzer.Policy
		} else {
			logger.Printf("default policy %s not found; continuing without a policy", cfg.Analyzer.Policy)
		}
	}
	if o.dbPath == "" {
		o.dbPath = cfg.Storage.DatabasePath
	}
	if hasSource && o.sbomFormat == "" && cfg.SBOM.Generate {
		o.sbomFormat = cfg.SBOM.Format
	}
	o.track = o.track || cfg.Storage.Enabled
	var target string
	if hasSource {
		target, err = filepath.Abs(o.target)
		if err != nil {
			return err
		}
		info, err := os.Lstat(target)
		if err != nil {
			return fmt.Errorf("invalid target: %w", err)
		}
		if !info.IsDir() {
			return errors.New("target must be a directory")
		}
	}
	started := time.Now()
	var policy *policies.Policy
	if o.policy != "" {
		policy, err = policies.NewPolicyEngine().LoadPolicy(o.policy)
		if err != nil {
			return fmt.Errorf("load policy: %w", err)
		}
	}
	var findings []models.Finding
	var incompleteChecks []string
	var languages map[string]detector.LanguageInfo
	var dastTarget string
	var dastEndpoints []models.DASTEndpoint
	var dastErr error
	if hasDAST {
		results, e := runDAST(ctx, o, time.Duration(cfg.DAST.TimeoutSeconds)*time.Second)
		if e != nil {
			return fmt.Errorf("DAST failed: %w", e)
		}
		dastTarget = dastReportTarget(results)
		failed := 0
		for _, result := range results {
			dastEndpoints = append(dastEndpoints, *result.Endpoint)
			findings = append(findings, result.Findings...)
			if result.Endpoint.Error != "" {
				failed++
			}
		}
		if failed > 0 {
			incompleteChecks = append(incompleteChecks, "baseline-dast")
			logger.Printf("DAST completed %d of %d endpoint checks", len(results)-failed, len(results))
		}
		if failed == len(results) {
			dastErr = errors.New("DAST completed no endpoint checks")
		}
		if o.dastActive && dastErr == nil {
			activeFindings, activeOutputs, e := runActiveDAST(ctx, o, time.Duration(cfg.DAST.TimeoutSeconds)*time.Second, logger)
			if e != nil {
				return fmt.Errorf("active DAST failed: %w", e)
			}
			findings = append(findings, activeFindings...)
			for _, result := range activeOutputs {
				if result.Endpoint != nil && result.Endpoint.Error != "" {
					incompleteChecks = append(incompleteChecks, "active-dast:"+result.Endpoint.Error)
				}
			}
			logger.Printf("active DAST sent %d request(s), found %d finding(s)", len(activeOutputs), len(activeFindings))
		}
	}
	setupRequested := hasSource && cfg.SAST.Enabled && config.EnvBool("ANALYZER_AUTO_INSTALL", false)
	autoInstall := setupRequested && !sandboxEnabled
	aiEnabled := hasSource && config.EnvBool("ANALYZER_AI_ENABLED", cfg.Validator.EnableAI)
	logger.Printf("environment ready: auto-install=%t ai-enabled=%t ai-provider=%s", autoInstall, aiEnabled, effectiveAIProvider(cfg))
	if hasSource {
		if err = generateIntegrations(logger, target, o, cfg); err != nil {
			return err
		}
		languages, err = detector.NewLanguageDetector(target).DetectLanguages()
		if err != nil {
			return fmt.Errorf("detect languages: %w", err)
		}
		logger.Printf("detected languages: %s", summarizeLanguages(languages))
		if cfg.SAST.Enabled {
			if setupRequested {
				setup := &agent.SetupAgent{Timeout: time.Duration(cfg.SAST.Timeout) * time.Second, AllowInstall: true, Logger: logger}
				readmePath := filepath.Join(target, "README.md")
				if info, e := os.Lstat(readmePath); e == nil && info.Mode().IsRegular() {
					if parsed, e := setup.ParseREADME(readmePath); e == nil {
						if e = setup.AutoInstallAndRun(ctx, parsed); e != nil {
							logger.Printf("README setup skipped: %v", e)
						}
					}
				}
			}
			sast := &agent.SASTAgent{Timeout: time.Duration(cfg.SAST.Timeout) * time.Second, Logger: logger, MaxWorkers: cfg.Validator.MaxWorkers, AutoInstall: autoInstall}
			sourceFindings, skipped, e := sast.ScanWithCoverage(ctx, target, languages)
			if err := ctx.Err(); err != nil {
				return err
			}
			if e != nil {
				logger.Printf("SAST degraded: %v", e)
			}
			findings = append(findings, sourceFindings...)
			incompleteChecks = append(incompleteChecks, skipped...)
		}
	}
	if hasSource && cfg.SecretDetection.Enabled {
		sd := scanner.NewSecretDetector()
		sd.EntropyThreshold = cfg.SecretDetection.HighEntropyThreshold
		sd.ExcludePaths = append(sd.ExcludePaths, cfg.SecretDetection.ExcludePaths...)
		secrets, e := sd.Scan(ctx, target)
		if e != nil {
			return fmt.Errorf("secret detection: %w", e)
		}
		findings = append(findings, secrets...)
	}
	if o.containerImage != "" {
		cs := scanner.NewContainerScanner()
		cs.Scanner = cfg.Container.Scanner
		containerFindings, e := cs.Scan(ctx, o.containerImage)
		if e != nil {
			logger.Printf("container scan degraded: %v", e)
			incompleteChecks = append(incompleteChecks, "container")
		} else {
			findings = append(findings, containerFindings...)
		}
	}
	opt := optimizer.Tokenizer{Budget: cfg.Optimizer.MaxTokenBudget, SkipPatterns: cfg.Optimizer.SkipPatterns}
	// Dedup + known-false-positive skip only. The token budget limits what is
	// sent to the LLM below; it must never truncate the report itself (the
	// old FilterFindings call silently dropped every finding past ~5000
	// estimated tokens, plus all LOW findings).
	findings = opt.FilterFindings(findings)
	if cfg.Scoring.CVSSEnabled {
		calc := &scorer.CVSSCalculator{}
		for i := range findings {
			// Keep authoritative scores reported by the scanner itself
			// (Trivy/Grype/Dependency-Check advisories carry a real CVSS
			// vector); only heuristically score findings that have none.
			if findings[i].CVSSVector == "" {
				m := calc.MetricsForFinding(findings[i])
				findings[i].CVSSBase = calc.CalculateScore(m)
				findings[i].CVSSVector = scorer.Vector(m)
			}
			if cfg.Scoring.SeverityMapping && findings[i].Severity == "" {
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
			toValidate, overBudget := opt.SelectForAI(findings)
			if len(overBudget) > 0 {
				logger.Printf("AI token budget (%d) covers %d of %d findings; %d kept unvalidated", cfg.Optimizer.MaxTokenBudget, len(toValidate), len(findings), len(overBudget))
			}
			validated, e := ai.ValidateFindingsInBatch(ctx, toValidate)
			if e != nil {
				logger.Printf("AI validation partially failed: %v", e)
			}
			if len(validated) > 0 || e == nil {
				findings = append(validated, overBudget...)
			}
			tokenUsed = client.TokenUsed()
		}
	}
	var zeros []models.Finding
	if hasSource && cfg.ZeroDayDetection.Enable {
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
	exporter := reporter.NewReportExporter()
	if o.sbomFormat != "" {
		bom, e := sbom.NewSBOMGenerator().GenerateSBOM(target, o.sbomFormat)
		if e != nil {
			return fmt.Errorf("generate SBOM: %w", e)
		}
		name, e := exporter.ExportSBOM(bom, o.sbomFormat, filepath.Dir(o.output))
		if e != nil {
			return fmt.Errorf("export SBOM: %w", e)
		}
		logger.Printf("wrote %s", name)
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
	reportTarget, reportLanguage := target, summarizeLanguages(languages)
	if !hasSource {
		reportTarget, reportLanguage = dastTarget, "web"
	}
	var bountyBundle *models.BountyBundle
	if cfg.BugBounty.Enabled {
		platform, programName := bountySelection(o.bountyProgram)
		bountyReporter := reporter.BugBountyReporter{Options: reporter.BountyReporterOptions{Platform: platform, ProgramName: programName, Target: reportTarget, Programs: cfg.BugBounty.BountyPrograms, POCFormats: cfg.BugBounty.IncludePOCFormats, MinSeverity: parseSeverity(cfg.BugBounty.SubmissionQualityChecks.MinSeverityLevel)}}
		bundle := bountyReporter.BuildBundle(findings, businessReport)
		bountyBundle = &bundle
	}
	report := models.Report{ID: fmt.Sprintf("scan-%d", time.Now().UnixNano()), Timestamp: time.Now().UTC(), TargetPath: reportTarget, DASTTargetURL: dastTarget, DASTEndpoints: dastEndpoints, DASTSession: o.dastSession, IncompleteChecks: incompleteChecks, Language: reportLanguage, Findings: findings, TotalFindings: len(findings), TokenUsed: tokenUsed, Duration: time.Since(started).String(), ComplianceReports: complianceReports, BusinessReport: businessReport, BountyBundle: bountyBundle}
	for _, f := range findings {
		if f.SourceTool == "zeroday-detector" && f.IsZeroDay {
			report.ZeroDayFindings = append(report.ZeroDayFindings, f)
		}
		if f.Severity == models.SeverityCritical {
			report.CriticalCount++
		}
		if f.Severity == models.SeverityHigh {
			report.HighCount++
		}
	}
	if hasSource && integrations.DetectGitRepo(target) {
		report.GitBranch = integrations.GetCurrentBranch(target)
		report.GitCommit = integrations.GetCommitHash(target)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	var comparisonErr error
	if o.track || o.compareID != "" {
		db, e := storage.OpenSQLite(o.dbPath)
		if e != nil {
			return fmt.Errorf("open history database: %w", e)
		}
		defer db.Close()
		if _, e = db.SaveReport(ctx, report); e != nil {
			return fmt.Errorf("save report history: %w", e)
		}
		if o.compareID != "" {
			comparison, e := db.CompareReports(ctx, o.compareID, report.ID)
			if e != nil {
				comparisonErr = fmt.Errorf("compare reports: %w", e)
			} else {
				logger.Printf("history comparison: new=%d fixed=%d regressions=%d", len(comparison.NewFindings), len(comparison.FixedFindings), len(comparison.Regressions))
			}
		}
		if e = db.PruneOlderThan(ctx, cfg.Storage.RetentionDays); e != nil {
			logger.Printf("history retention cleanup failed: %v", e)
		}
	}
	for _, format := range splitFormats(o.formats) {
		path := outputForFormat(o.output, format)
		if e := exporter.Export(report, format, path); e != nil {
			return fmt.Errorf("export %s: %w", format, e)
		}
		logger.Printf("wrote %s", path)
	}
	if len(incompleteChecks) > 0 {
		logger.Printf("scan incomplete: %s", strings.Join(incompleteChecks, ", "))
	}
	fmt.Printf("Scan finished: id=%s total=%d critical=%d high=%d zero_day=%d tokens=%d duration=%s\n", report.ID, report.TotalFindings, report.CriticalCount, report.HighCount, len(report.ZeroDayFindings), tokenUsed, report.Duration)
	return errors.Join(comparisonErr, dastErr)
}

func runDAST(ctx context.Context, o options, timeout time.Duration) ([]models.ToolOutput, error) {
	if o.dastURL != "" && o.dastTargets != "" {
		return nil, errors.New("choose either --dast-url or --dast-targets")
	}
	origin, paths := "", []string{o.dastURL}
	if o.dastTargets != "" {
		manifest, err := scanner.ReadDASTManifest(o.dastTargets)
		if err != nil {
			return nil, err
		}
		origin, paths = manifest.Origin, manifest.Paths
	}
	var session string
	switch o.dastSession {
	case "":
	case "bearer":
		session = os.Getenv("VULNFORGE_DAST_BEARER_TOKEN")
	case "cookie":
		session = os.Getenv("VULNFORGE_DAST_COOKIE")
	default:
		return nil, errors.New("DAST session must be bearer or cookie")
	}
	return (scanner.BaselineDAST{Timeout: timeout}).ScanTargets(ctx, origin, paths, scanner.DASTRunOptions{
		Interval: o.dastInterval, MaxRequests: o.dastMaxRequests, Direct: o.dastDirect, SessionKind: o.dastSession, Session: session,
	})
}

// runActiveDAST runs the opt-in active probe set against o.dastURL. When
// o.oobListenAddr is set, it starts a local OOB HTTP listener for the
// duration of the scan so blind SSRF/XXE/command-injection probes can be
// confirmed; the listener is always shut down before returning, including
// on error or cancellation.
func runActiveDAST(ctx context.Context, o options, timeout time.Duration, logger *log.Logger) ([]models.Finding, []models.ToolOutput, error) {
	var session string
	switch o.dastSession {
	case "":
	case "bearer":
		session = os.Getenv("VULNFORGE_DAST_BEARER_TOKEN")
	case "cookie":
		session = os.Getenv("VULNFORGE_DAST_COOKIE")
	}
	store := oob.NewStore()
	active := scanner.ActiveDAST{Timeout: timeout, OOBCallbackHost: o.oobCallbackHost, OOBWait: o.oobWait, OOBStore: store}
	if o.oobListenAddr != "" {
		srv := oob.NewHTTPServerWithDomain(o.oobListenAddr, store, o.oobCallbackHost)
		errCh := make(chan error, 1)
		go func() { errCh <- srv.ListenAndServe() }()
		defer func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if e := srv.Shutdown(shutdownCtx); e != nil {
				logger.Printf("oob listener shutdown: %v", e)
			}
		}()
		select {
		case e := <-errCh:
			if e != nil && !errors.Is(e, http.ErrServerClosed) {
				return nil, nil, fmt.Errorf("starting OOB listener on %s: %w", o.oobListenAddr, e)
			}
		case <-time.After(200 * time.Millisecond):
			// Listener accepted the bind and is serving; proceed.
		}
	}
	return active.ScanURL(ctx, o.dastURL, scanner.DASTRunOptions{
		Interval: o.dastInterval, MaxRequests: o.dastMaxRequests, Direct: o.dastDirect, SessionKind: o.dastSession, Session: session,
	})
}

func dastReportTarget(results []models.ToolOutput) string {
	target := results[0].TargetURL
	if len(results) == 1 {
		return target
	}
	// ScanTargets has already validated and redacted all targets.
	u, _ := url.Parse(target)
	return (&url.URL{Scheme: u.Scheme, Host: u.Host, Path: "/"}).String()
}

func writeDASTInventory(args []string, output io.Writer) error {
	fs := flag.NewFlagSet("analyzer dast inventory", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	origin := fs.String("origin", "", "authorized origin for the manifest")
	openapi := fs.String("openapi", "", "local OpenAPI YAML or JSON file")
	har := fs.String("har", "", "local HTTP Archive file")
	burp := fs.String("burp", "", "local Burp XML item export")
	sitemap := fs.String("sitemap", "", "local XML sitemap URL set")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var format, path string
	for name, value := range map[string]string{"openapi": *openapi, "har": *har, "burp": *burp, "sitemap": *sitemap} {
		if value != "" {
			if format != "" {
				return errors.New("choose one inventory input")
			}
			format, path = name, value
		}
	}
	if fs.NArg() != 0 || *origin == "" || format == "" {
		return errors.New("provide --origin and one of --openapi, --har, --burp, or --sitemap")
	}
	manifest, err := scanner.InventoryDASTPaths(*origin, path, format)
	if err != nil {
		return err
	}
	data, err := yaml.Marshal(manifest)
	if err != nil {
		return err
	}
	_, err = output.Write(data)
	return err
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
		if key != "" && !ninerouter.SecureEndpoint(baseURL) {
			return nil, fmt.Errorf("refusing to send NINEROUTER_KEY over plaintext HTTP to non-loopback host %q; use https", baseURL)
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

func generateIntegrations(logger *log.Logger, target string, o options, cfg config.Config) error {
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
		executable := filepath.Base(filepath.Dir(path)) == "hooks"
		if err := integrations.WriteGeneratedFileWithin(target, path, body, executable); err != nil {
			if errors.Is(err, integrations.ErrExists) {
				// Never clobber the project's own pipeline or hook.
				logger.Printf("integration skipped: %v", err)
				continue
			}
			return err
		}
		logger.Printf("generated %s", path)
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
func toSet(v []string) map[string]bool {
	out := make(map[string]bool, len(v))
	for _, s := range v {
		out[s] = true
	}
	return out
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
