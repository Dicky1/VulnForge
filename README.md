# Multi-language SAST/DAST Analyzer with AI validation

Security-analysis CLI that detects project languages, plans compatible scanners, normalizes and deduplicates their output, optionally validates high-priority findings with AI, and generates technical, management, and bug-bounty reports.

> “Zero-day” findings are hypotheses, not proof of a previously unknown vulnerability. Always reproduce and manually review them before disclosure.

## Requirements

- Go 1.24+
- One or more scanners on `PATH`. Language-aware selection supports Semgrep, Bandit, GoSec, ESLint, SpotBugs, PHPStan, Psalm, Cargo Audit, Brakeman, Slither, OWASP Dependency-Check, and Clang Analyzer.
- Anthropic API key or a running 9Router instance for AI validation. AI remains optional; scanning degrades gracefully when unavailable.

Some scanners also require their language toolchain. For example, `cargo-audit` requires Cargo, Slither requires Python, Foundry-based Solidity projects may require `forge`, ESLint requires Node.js/npm, and Clang Analyzer requires LLVM/Clang. A report may still be exported when scanners are skipped, so always review the scanner-plan and degraded-mode messages in the console.

```sh
pip install semgrep
pip install bandit
go install github.com/securego/gosec/v2/cmd/gosec@latest
export ANTHROPIC_API_KEY=replace-me
```

## Quick start: melakukan scan baru

From the analyzer repository, install dependencies and verify the build:

```powershell
go mod download
go test ./...
go build -o analyzer.exe ./cmd/analyzer
```

Scan a source directory using the default policy:

```powershell
.\analyzer.exe --target "C:\path\to\project" --output report.json
```

Alternatively, run without building a binary:

```sh
go run ./cmd/analyzer/main.go --target /absolute/path/to/project --output report.json
```

The older positional form remains supported:

```powershell
.\analyzer.exe "C:\path\to\project"
```

Scan source code plus an authorized running application:

```powershell
.\analyzer.exe --target "C:\path\to\project" `
  --dast-url "https://staging.example.com" `
  --export-format json,html,sarif `
  --output report.json
```

The CLI writes `report.json` in the current directory. Configure scanner timeouts, model, confidence threshold, workers, and token budget in `config/config.yaml`.

The optional DAST URL enables a passive, non-mutating HTTP baseline scan for HTTPS, cookie flags, and response security headers. Only scan systems you own or are explicitly authorized to assess.

The detector recognizes Go, Python, JavaScript/TypeScript, Java, C/C++, PHP, Rust, Ruby, .NET, Swift, Kotlin, and Solidity projects. Foundry dependencies under `lib/` are excluded from language planning; Slither still resolves them while compiling the Solidity project. Polyglot repositories are supported and scanners are deduplicated through a bounded worker pool.

## Environment manager

Copy `.env.example` to `.env`; the analyzer loads it automatically before YAML configuration and scanner planning:

```powershell
Copy-Item .env.example .env
.\analyzer.exe --target "C:\path\to\project" --output report.json
```

With `ANALYZER_AUTO_INSTALL=true`, the environment manager attempts to install supported missing scanners. The relevant package manager or toolchain must already exist; for example, Cargo must be installed before `cargo-audit` can be installed. Set `ANALYZER_AI_ENABLED=false` for a scanner-only run. Existing shell variables override `.env`. Set `ANALYZER_ENV_FILE` to use another environment file. Platform toolchains such as Foundry/`forge` and LLVM still need to be installed through their official installers; common per-user locations such as `~/.foundry/bin` are discovered automatically.

Keep `ANALYZER_AUTO_INSTALL=false` when scanning repositories you do not fully trust. The analyzer may inspect installation hints in target documentation, so enable automatic installation only for trusted targets and preferably inside an isolated environment.

## AI provider: Anthropic or 9Router

The default provider is Anthropic. Configure its key in the environment:

```powershell
$env:ANTHROPIC_API_KEY = "your-key"
.\analyzer.exe --target "C:\path\to\project"
```

To route AI validation and remediation through [9Router](https://github.com/decolua/9router), install and start it:

```powershell
npm install -g 9router
9router
```

9Router normally listens on `http://localhost:20128`. Connect providers in its dashboard, then discover the available model IDs:

```powershell
Invoke-RestMethod http://localhost:20128/v1/models
```

Set the analyzer environment variables and run a scan:

```powershell
$env:ANALYZER_AI_PROVIDER = "9router"
$env:NINEROUTER_URL = "http://localhost:20128"
$env:NINEROUTER_MODEL = "cc/claude-opus-4-6"
$env:NINEROUTER_KEY = "your-9router-api-key" # Omit when local API-key auth is disabled.

.\analyzer.exe --target "C:\path\to\project" `
  --policy policies/default.yaml `
  --export-format json,html,sarif
```

It can also be configured persistently in `config/config.yaml`:

```yaml
ai:
  provider: "9router"
ninerouter:
  base_url: "http://localhost:20128"
  api_key: ""
  model: "cc/claude-opus-4-6"
  max_retries: 3
  timeout_seconds: 60
  health_check: true
```

`NINEROUTER_KEY` is preferred over storing a key in YAML. Never commit `.env` or real API keys. If a key has entered Git history, remove it and rotate it before publishing the repository. Model IDs depend on the providers and combos configured in your 9Router dashboard; use the exact ID returned by `/v1/models`.

## Extended security pipeline

The analyzer also provides native secret detection with redacted evidence, CVSS v3.1 scoring, local and optional Claude-powered remediation, OWASP/CWE/compliance mapping, custom YAML policies, SQLite history, container scanning through Trivy or Grype, and CycloneDX/SPDX SBOM generation.

Export all supported report formats (`html` is the offline interactive business report; `dashboard` emits a separate `.dashboard.html` copy):

```sh
go run ./cmd/analyzer/main.go --target ./project \
  --policy policies/default.yaml \
  --export-format json,html,dashboard,pdf,sarif,xml,csv \
  --output report.json
```

Generate a bug-bounty submission bundle (JSON, Markdown, HTML, PDF, and plaintext):

```powershell
.\analyzer.exe --target "C:\path\to\project" `
  --policy policies/default.yaml `
  --export-format json,html,sarif,bounty-report `
  --bounty-program yeswehack `
  --output report.json
```

Supported bounty adapters are `hackerone`, `bugcrowd`, `intigriti`, `yeswehack`, and `federacy`. With `--output report.json`, the bundle uses names such as `report.bounty.json`, `report.bounty.md`, `report.bounty.html`, `report.bounty.pdf`, and `report.bounty.txt`.

The bounty quality gate filters ineligible candidates and does not treat static scanner output as submission-ready evidence. An empty bundle is valid and means no finding passed the current eligibility checks. Generated items remain human-review drafts; verify the exact vulnerable asset, program scope, runtime reproduction, impact, and evidence before submission. POCs use non-destructive markers and must only be run with written authorization. The analyzer does not submit reports to a bounty platform.

History and SBOM:

```sh
go run ./cmd/analyzer/main.go --target ./project \
  --track-history --database analyzer.db \
  --generate-sbom cyclonedx
```

Compare the new scan with a stored report:

```sh
go run ./cmd/analyzer/main.go --target ./project \
  --track-history --compare-with scan-previous-id
```

Container images must be provided explicitly:

```sh
go run ./cmd/analyzer/main.go --target ./project \
  --scan-containers docker.io/library/nginx:latest
```

Generate CI/CD files inside the target repository:

```sh
go run ./cmd/analyzer/main.go --target ./project --github-actions
go run ./cmd/analyzer/main.go --target ./project --gitlab-ci
go run ./cmd/analyzer/main.go --target ./project --jenkins
go run ./cmd/analyzer/main.go --target ./project --pre-commit
```

Generation flags write files into the target repository. The pre-commit hook blocks commits only when the generated report contains critical findings.

On Linux/macOS, install package-manager-based scanners with:

```sh
bash tools/install_dependencies.sh
```

Target documentation may be inspected for scanner installation hints when automatic installation is enabled. Treat this as execution of third-party dependency installation instructions: use it only with trusted repositories, review the console output, and prefer a disposable VM or container.

## How the pipeline works

1. Scanners run concurrently with deadlines and normalize their JSON into a common finding model.
2. Known fixtures and duplicates are removed before any API call.
3. High-priority findings are trimmed to the configured estimated token budget and validated in batches of at most ten.
4. Local anomaly rules inspect source files for custom crypto, validation/auth bypass, unsafe shared state, and business-logic manipulation.
5. The JSON report includes CVSS estimates, CWE/MITRE mapping, remediation, AI rationale, confidence, and possible exploit-chain links.

The AI stage sends finding metadata and code snippets to the selected provider. When using 9Router, its configured upstream provider may receive that content. Do not enable AI validation for source prohibited by your data-handling policy. Model-generated assessments may be incorrect.
