# VulnForge — Multi-Language SAST/DAST Analyzer with AI Validation

[![Go Report Card](https://goreportcard.com/badge/github.com/Dicky1/VulnForge)](https://goreportcard.com/report/github.com/Dicky1/VulnForge)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

VulnForge is an enterprise-grade security analysis CLI and orchestrator that detects project languages, plans and runs compatible static/dynamic scanners concurrently, normalizes and deduplicates findings, calculates CVSS v3.1 scores, and optionally validates high-priority vulnerabilities using AI (Anthropic Claude or 9Router). 

It generates comprehensive technical audits, executive management dashboards, regulatory compliance matrices (OWASP Top 10, CWE Top 25, GDPR, PCI-DSS, HIPAA, SOC 2, ISO 27001), CycloneDX/SPDX SBOMs, and submission-ready Bug Bounty bundles tailored for platforms like HackerOne, Bugcrowd, Intigriti, YesWeHack, and Federacy.

> **Disclaimer**: "Zero-day" and AI-flagged findings are hypotheses and triage aids, not confirmed proof of an exploitable vulnerability. Always reproduce and manually verify findings in an authorized environment before disclosure.

---

## Key Features

- **Automated Polyglot Language Detection**: Scans and identifies Go, Python, JavaScript, TypeScript, Java, C/C++, PHP, Rust, Ruby, .NET, Swift, Kotlin, and Solidity repositories.
- **Unified Scanner Orchestration**: Runs 12+ scanners through a bounded concurrent worker pool:
  - **SAST**: Semgrep, Bandit, GoSec, ESLint, SpotBugs, PHPStan, Psalm, Cargo Audit, Brakeman, Slither, Clang Analyzer, and OWASP Dependency-Check.
  - **Secrets**: Built-in regex detection and Shannon entropy calculator with automatic credential redaction (`[REDACTED]`).
  - **Passive DAST**: Non-intrusive baseline HTTP scanner checking TLS enforcement, security headers (CSP, HSTS, X-Content-Type-Options, Referrer-Policy), and cookie attributes (`Secure`, `HttpOnly`, `SameSite`).
  - **Containers**: Trivy or Grype integration for Docker/OCI container image scanning.
- **Docker Container Sandboxing**: Runs untrusted target repositories and scanners inside isolated Docker containers with `--cap-drop ALL`, `--security-opt no-new-privileges:true`, `--read-only` root, resource quotas, and `--network none`.
- **Untrusted README Protection**: Restricts auto-installation commands parsed from target repositories to strict allowlists; completely refuses execution on the host if Docker sandboxing is unavailable.
- **AI-Powered Validation & Remediation**: Leverages Anthropic Claude or [9Router](https://github.com/decolua/9router) to filter out false positives and generate language-specific remediation code patches. Sensitive snippets are omitted (`safe.CodeSnippet = "[omitted]"`) to protect confidential code.
- **Enterprise Policy Engine**: YAML-based rule enforcement supporting custom regex patterns, CWE filters, severity overrides, and suppression rules with precompiled regex caching.
- **Historical Tracking & Regressions**: Embedded SQLite storage (`analyzer.db`) for tracking scan history, new findings, fixed issues, and severity regressions (`--compare-with`).
- **Multi-Format Reporting**:
  - `json`: Machine-readable raw report.
  - `html` / `dashboard`: Standalone, interactive offline management dashboard with risk matrices, downtime projections, and verification POCs.
  - `sarif`: GitHub Code Scanning / OASIS SARIF v2.1.0 compliant.
  - `pdf`: Executive-ready PDF report with severity badges and remediation roadmaps.
  - `csv`: Spreadsheet export with automatic CSV formula injection sanitization (CWE-1236).
  - `xml`: Standard XML interchange format.
  - `bounty-report`: Bug bounty submission bundles (`.bounty.json`, `.bounty.md`, `.bounty.html`, `.bounty.pdf`, `.bounty.txt`).
- **CI/CD Integration Generator**: One-click generation of workflows for GitHub Actions, GitLab CI, Jenkinsfile, and Git pre-commit hooks.

---

## Requirements

- **Go**: 1.24+
- **Toolchains & Scanners**: One or more scanners installed on `PATH` (or configured via Docker Sandbox).
- **AI Key (Optional)**: `ANTHROPIC_API_KEY` for Claude, or a running `9Router` instance (`http://localhost:20128`). Scanning degrades gracefully when AI is unavailable.

---

## Installation & Build

Clone the repository and build the binary:

```bash
git clone https://github.com/Dicky1/VulnForge.git
cd VulnForge
go mod download
go test ./...
go build -o analyzer.exe ./cmd/analyzer
```

---

## Quick Start: Menjalankan Scan

### 1. Basic Source Scan
Scan a project directory and export to JSON:

```powershell
.\analyzer.exe --target "C:\path\to\project" --output report.json
```

Or on Linux / macOS:

```bash
./analyzer --target /path/to/project --output report.json
```

### 2. Multi-Format & Passive DAST Scan
Scan source code alongside an authorized running staging web endpoint, exporting to multiple formats simultaneously:

```powershell
.\analyzer.exe --target "C:\path\to\project" `
  --dast-url "https://staging.example.com" `
  --export-format json,html,dashboard,sarif,pdf,csv `
  --output report.json
```

### 3. Bug Bounty Submission Bundle
Generate submission-ready drafts for a specific bug bounty platform:

```powershell
.\analyzer.exe --target "C:\path\to\project" `
  --policy policies/default.yaml `
  --export-format json,html,sarif,bounty-report `
  --bounty-program hackerone `
  --output report.json
```
*Supported platforms*: `hackerone`, `bugcrowd`, `intigriti`, `yeswehack`, `federacy`.

### 4. Historical Differential Scan
Track scan history in SQLite and compare against a previous scan ID to detect new bugs or regressions:

```powershell
# First scan with history tracking:
.\analyzer.exe --target "C:\path\to\project" --track-history --database analyzer.db

# Follow-up scan compared to previous run:
.\analyzer.exe --target "C:\path\to\project" --track-history --compare-with scan-1718000000000
```

### 5. SBOM & Container Image Scanning
Generate CycloneDX or SPDX Software Bill of Materials, and scan container images via Trivy/Grype:

```powershell
.\analyzer.exe --target "C:\path\to\project" `
  --generate-sbom cyclonedx `
  --scan-containers "docker.io/library/nginx:alpine"
```

---

## CLI Options Reference

| Flag | Type | Description |
| :--- | :--- | :--- |
| `--target` | `string` | Path to the source code directory to scan (or positional argument). |
| `--output` | `string` | Base path for exported reports (default: `report.json`). |
| `--export-format` | `string` | Comma-separated: `json,html,dashboard,pdf,sarif,xml,csv,bounty-report`. |
| `--policy` | `string` | Path to custom YAML security policy file. |
| `--dast-url` | `string` | Authorized runtime URL for passive baseline HTTP scanning. |
| `--track-history` | `bool` | Store scan results in the SQLite database for historical tracking. |
| `--database` | `string` | Custom path to SQLite database (default from `config.yaml`). |
| `--compare-with` | `string` | Historical report ID to run differential regression analysis against. |
| `--bounty-program` | `string` | Platform adapter (`hackerone`, `bugcrowd`, `intigriti`, `yeswehack`, `federacy`). |
| `--scan-containers`| `string` | Explicit Docker/OCI image reference to scan with Trivy/Grype. |
| `--generate-sbom` | `string` | Format for SBOM generation (`cyclonedx` or `spdx`). |
| `--github-actions` | `bool` | Generates `.github/workflows/security-scan.yml` in target repo. |
| `--gitlab-ci` | `bool` | Generates `.gitlab-ci.yml` in target repo. |
| `--jenkins` | `bool` | Generates `Jenkinsfile` in target repo. |
| `--pre-commit` | `bool` | Generates `.git/hooks/pre-commit` hook in target Git repo. |

---

## Environment & Configuration

Copy `.env.example` to `.env`:

```powershell
Copy-Item .env.example .env
```

Key environment variables:

| Variable | Default | Description |
| :--- | :--- | :--- |
| `ANALYZER_ENV_FILE` | `.env` | Custom path to `.env` file. |
| `ANALYZER_AI_ENABLED` | `true` | Set to `false` to run scanner-only offline mode without AI. |
| `ANALYZER_AI_PROVIDER` | `anthropic`| AI provider: `anthropic` or `9router`. |
| `ANTHROPIC_API_KEY` | `""` | Anthropic API key for Claude. |
| `NINEROUTER_URL` | `http://localhost:20128` | Base URL for local or remote 9Router instance. |
| `NINEROUTER_MODEL` | `cc/claude-opus-4-6` | Model ID configured in 9Router. |
| `NINEROUTER_KEY` | `""` | Optional API key for 9Router. |
| `ANALYZER_SANDBOX_ENABLED` | `false` | Enable Docker container isolation for scanners. |
| `ANALYZER_AUTO_INSTALL` | `false` | Allow auto-installing missing scanners (strictly validated). |
| `ANALYZER_TOOL_PATHS` | `""` | Extra paths appended to system `PATH` (separated by platform delimiter). |

Advanced settings such as timeouts, token budgets, scanner concurrency limits, and financial risk multipliers can be customized in [`config/config.yaml`](config/config.yaml).

---

## Language & Scanner Support Matrix

| Language | Supported Scanners | Sandbox Image Available |
| :--- | :--- | :---: |
| **Go** | GoSec | Yes (`vulnforge-gosec`) |
| **Python** | Bandit, Semgrep | Yes (`vulnforge-bandit`, `returntocorp/semgrep`) |
| **JavaScript / TypeScript** | ESLint (`@microsoft/eslint-plugin-sdl`), Semgrep | Yes (Semgrep) |
| **Java** | SpotBugs, OWASP Dependency-Check, Semgrep | Yes (Semgrep) |
| **PHP** | PHPStan, Psalm, Semgrep | Yes (Semgrep) |
| **Rust** | Cargo Audit, Semgrep | Yes (Semgrep) |
| **Ruby** | Brakeman | Host |
| **C / C++** | Clang Static Analyzer (`scan-build`) | Host |
| **Solidity** | Slither (Foundry & Hardhat support) | Yes (`vulnforge-slither`) |
| **Kotlin / .NET / Swift** | Semgrep | Yes (Semgrep) |
| **Containers** | Trivy, Grype | Host / Daemon |
| **Secrets** | Native High-Entropy & Pattern Detector | Built-in |
| **Web Endpoint** | Native Passive DAST | Built-in |

---

## Security Hardening Details

VulnForge implements defense-in-depth principles:
1. **Command Injection Prevention**: Subprocess calls avoid shell wrappers (`sh -c` or `cmd.exe /c`), passing parameters strictly as tokenized argument slices.
2. **Container Isolation**: Scanner subprocesses run with dropped Linux capabilities (`--cap-drop ALL`), disabled privilege escalation (`no-new-privileges`), and read-only target mounts (`/workspace:ro`).
3. **Secret Redaction**: Detected keys, tokens, and passwords are unconditionally replaced with redacted placeholders to prevent leakage into reports or AI prompts.
4. **Data Minimization for AI**: When requesting remediation diffs, source snippets are omitted from prompts to prevent source code exfiltration to external LLMs.
5. **CSV Formula Injection Mitigation**: All CSV exported fields are sanitized against formula injection (CWE-1236) by prepending `'` to fields starting with `=`, `+`, `-`, or `@`.
6. **SQL Injection Immune**: Scan history transactions utilize parameterized SQL queries exclusively.
7. **XSS Protection**: HTML executive dashboards leverage Go's contextual `html/template` auto-escaping.

---

## Testing & Quality

Run the comprehensive unit test suite:

```bash
go test -v ./...
```

Verify formatting and linting:

```bash
go vet ./...
```

---

## License

This project is licensed under the [MIT License](LICENSE).
