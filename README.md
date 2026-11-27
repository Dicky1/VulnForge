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
- **AI-Powered Validation & Remediation**: Uses Anthropic Claude or [9Router](https://github.com/decolua/9router) for advisory triage and remediation suggestions. AI does not delete findings or establish zero-day status; source snippets and paths are omitted from the default validation prompt. Scanner titles and metadata may still contain sensitive information; disable external AI for confidential scans.
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

### 2. Black-Box AuthZ / Logic Probing (new)

Authorized active (non-destructive) checks for BOLA/IDOR, parameter tampering, and race conditions:

```powershell
# AuthZ diff (BOLA/IDOR) with role matrix
.\analyzer.exe --dast-url "https://staging.example.com" --authz-matrix authz.yaml --output report.json

# Parameter tampering fuzzer (from OpenAPI-style manifest)
.\analyzer.exe --dast-url "https://staging.example.com" --tamper-manifest tamper.yaml --output report.json
```

- `--authz-matrix`: YAML with origin, sessions (bearer/cookie + priority), and endpoints. Flags endpoints where a lower-privileged session receives an equivalent response to a higher-privileged one.
- `--tamper-manifest`: YAML with origin and endpoints + params. Probes negative/zero/huge/string/empty/null values and flags unexpected 2xx or 5xx.
- Concurrency harness available programmatically (`scanner.ConcurrencyHarness`) to detect duplicate/oversell on mutating endpoints.

### 3. Passive DAST Scan
Check the HTTPS, headers, and cookie attributes observed at an authorized endpoint:

```powershell
.\analyzer.exe --dast-url "https://staging.example.com" --output report.json
```

A URL-only scan uses built-in HTTP checks without AI validation. Keep `analyzer.target_path` empty in the selected config for this mode. The report stores the endpoint without its query or fragment.

Use the `dast` subcommand to select web-only mode even when the config has a source target. To check multiple endpoints, save an explicit list in `endpoints.yaml`.

```yaml
origin: https://staging.example.com
paths:
  - /
  - /login
  - /api/health
```

```powershell
go run ./cmd/analyzer dast --dast-targets endpoints.yaml --export-format json,html --output report.json
```

The manifest accepts up to 100 paths under one origin. The HTTP client sends GET requests sequentially, honors the configured timeout, and limits redirects to the original origin or a standard HTTP-to-HTTPS upgrade. `--dast-interval` defaults to `250ms`, and `--dast-max-requests` defaults to 100. Both apply across the entire run and include redirects. An HTTP 429 response stops further requests in the run. The client honors `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY`. Use `--dast-no-proxy` for direct connections.

For authenticated staging checks, supply an existing session with `--dast-session cookie` and `VULNFORGE_DAST_COOKIE` (a Cookie header value), or `--dast-session bearer` and `VULNFORGE_DAST_BEARER_TOKEN` (the token alone). Use the `dast` subcommand and an HTTPS origin. Reports include endpoint outcomes and evidence such as status, header name, and missing attributes per cookie. Credentials, cookie values, raw headers, query strings, and response bodies are excluded. Keep sensitive data out of endpoint path segments. Authenticated redirects to a different path show a redacted final path.

Generate a candidate manifest offline from a local OpenAPI document, HAR file, Burp XML item export, or sitemap URL set.

```powershell
go run ./cmd/analyzer dast inventory --origin https://staging.example.com --openapi openapi.yaml
```

The inventory command prints YAML to review and save. Use `--har`, `--burp`, or `--sitemap` for those inputs. Imported paths drop query strings, and captured GET URLs must match the selected origin. Review path segments before saving or sharing the generated manifest.

Add a source directory to combine static and runtime findings in the same report:

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

Use the same source directory, DAST endpoint list, and session mode for both runs. The CLI logs incomplete checks and includes them in JSON (`incomplete_checks`), HTML, PDF, XML, and SARIF. Partial scans still produce reports. A history comparison involving an incomplete scan returns an error after exporting the current report. If no DAST endpoint could be checked, the CLI exports its outcomes and then exits with an error.

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
| `--config` | `string` | Config YAML path (or `ANALYZER_CONFIG`). |
| `--output` | `string` | Base path for exported reports (default: `report.json`). |
| `--export-format` | `string` | Comma-separated: `json,html,dashboard,pdf,sarif,xml,csv,bounty-report`. |
| `--policy` | `string` | Path to custom YAML security policy file. |
| `--dast-url` | `string` | Authorized runtime URL for passive baseline HTTP scanning. May be used by itself. |
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
| `ANALYZER_SANDBOX_ENABLED` | `false` | Enable required scanner isolation; configured scanner execution fails closed if Docker or an image is unavailable. Explicit container image scanning is separate. |
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
3. **Secret Redaction**: The native secret detector redacts matched source lines and passive DAST omits cookie values and query strings. Third-party scanner output is not a guarantee of complete redaction; protect report files and review them before sharing.
4. **Data Minimization for AI**: When requesting remediation diffs, source snippets are omitted from prompts to prevent source code exfiltration to external LLMs.
5. **CSV Formula Injection Mitigation**: All CSV exported fields are sanitized against formula injection (CWE-1236) by prepending `'` to fields starting with `=`, `+`, `-`, or `@`.
6. **Parameterized SQL**: Scan history transactions utilize parameterized SQL queries exclusively.
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


### Candidate validation notes

This working tree is a pre-push candidate, not a validated release. See `VALIDATION.md` for test coverage, unresolved gaps, and release checks. Do not run source scanners on untrusted code outside appropriate isolation. Use only authorized targets and a trusted output directory.
