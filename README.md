# Multi-language SAST/DAST Analyzer with AI validation

Security-analysis CLI for consolidating Semgrep, Bandit, and GoSec output, reducing duplicates, validating high-priority findings with Claude, and heuristically surfacing anomalous code paths for expert review.

> “Zero-day” findings are hypotheses, not proof of a previously unknown vulnerability. Always reproduce and manually review them before disclosure.

## Requirements

- Go 1.24+
- One or more scanners on `PATH`. Language-aware selection supports Semgrep, Bandit, GoSec, ESLint, SpotBugs, PHPStan, Psalm, Cargo Audit, Brakeman, OWASP Dependency-Check, and Clang Analyzer.
- Anthropic API key or a running 9Router instance for AI validation. AI remains optional; scanning degrades gracefully when unavailable.

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

The detector recognizes Go, Python, JavaScript/TypeScript, Java, C/C++, PHP, Rust, Ruby, .NET, Swift, and Kotlin projects. Polyglot repositories are supported: recommended scanners are deduplicated and run through a bounded worker pool. Tools without an implemented wrapper are logged and skipped.

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

`NINEROUTER_KEY` is preferred over storing a key in YAML. Model IDs depend on the providers and combos configured in your 9Router dashboard; use the exact ID returned by `/v1/models`.

## Extended security pipeline

The analyzer also provides native secret detection with redacted evidence, CVSS v3.1 scoring, local and optional Claude-powered remediation, OWASP/CWE/compliance mapping, custom YAML policies, SQLite history, container scanning through Trivy or Grype, and CycloneDX/SPDX SBOM generation.

Export all supported report formats:

```sh
go run ./cmd/analyzer/main.go --target ./project \
  --policy policies/default.yaml \
  --export-format json,html,pdf,sarif,xml,csv \
  --output report.json
```

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

README commands are parsed automatically. They are only installed when `ANALYZER_AUTO_INSTALL=1`, and even then the setup agent permits only recognized Semgrep/Bandit/GoSec install forms. Arbitrary shell expressions and Docker commands are never executed.

## How the pipeline works

1. Scanners run concurrently with deadlines and normalize their JSON into a common finding model.
2. Known fixtures and duplicates are removed before any API call.
3. High-priority findings are trimmed to the configured estimated token budget and validated in batches of at most ten.
4. Local anomaly rules inspect source files for custom crypto, validation/auth bypass, unsafe shared state, and business-logic manipulation.
5. The JSON report includes CVSS estimates, CWE/MITRE mapping, remediation, AI rationale, confidence, and possible exploit-chain links.

The AI stage sends finding metadata and code snippets to the selected provider. When using 9Router, its configured upstream provider may receive that content. Do not enable AI validation for source prohibited by your data-handling policy. Model-generated assessments may be incorrect.

## Verification

```sh
go test ./...
go vet ./...
go build ./cmd/analyzer
```
