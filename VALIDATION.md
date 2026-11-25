# VulnForge pre-push consolidation candidate

Base: GitHub snapshot `2cebe6da3d63f28d8f476548ec275dc8299b78c1`, branch `fix/blackbox-baseline-security-20261125`. No remote push or merge was made for this candidate. No new active black-box functionality was introduced.

## Scope of changes

- Selectively incorporate Claude's patch and the earlier local candidate, retaining stricter redirect and sandbox policies and AI evidence preservation from the existing branch.
- Separate scanner stdout/stderr; bound captured output; handle cancellation/default timeouts; deny host auto-install while isolation is required.
- Preserve distinct findings and package advisory identities; prevent duplicate storage IDs; partition the AI input budget without discarding unselected findings; remove broad default skip patterns. Default policy now retains low-severity findings and does not reject findings solely on AI confidence.
- Fix existing parser metadata and wrapper bugs (CWE normalization, Semgrep rule ID, GoSec ranges, ESLint plugin name); preserve scanner-supplied CVSS vectors and existing severity. Actual external tool integration has not been verified.
- Minimize AI prompt evidence, treat responses as advisory, prevent AI from classifying a finding as zero-day, bound AI worker count and 9Router retries/cache; reject insecure 9Router credential transport and redirects.
- Keep ordinary symlinks/special files out of the native secret and heuristic scan; tolerate long lines within the existing file-size limit. Heuristics are labeled unverified, with low severity and no fabricated AI confidence.
- Avoid overwriting generated CI files and reject existing symlink parents under the selected source root. This does not establish race-free containment against concurrent filesystem modification.
- Fix dashboard pie rendering, report privacy and failed-write handling through temporary files and replacement, CSV formula escaping, portable report paths, and CLI config/help/SBOM output handling.

## Tests performed in this environment

- Exact supplied snapshot was extracted into a local Git working tree. Claude patch conflicts were excluded and reconciled; original production `go.mod` and `go.sum` were not downgraded or replaced.
- Local Go is 1.23.2. A temporary separate minimal module file with the same module name was used ONLY to run standard-library-only packages without downloading dependencies. No dependency stubs were used.
- Final unit, race and vet checks: agent, compliance, detector, integrations, models, optimizer, parser, remediator, sbom, scanner, scorer, validator, ninerouter. Ten of these thirteen packages contain tests; three were compiled but have no tests.
- Selected reporter source files (excluding `exporter.go`, `exporter_test.go`, `bounty_export.go`, `pdf_style.go`): race tests and vet passed, including actual dashboard, business logic, bounty gate, and report file helpers. This is not a full reporter package test.
- Environment-file parser tests passed independently of YAML configuration.
- Windows amd64 cross-compilation passed for the same thirteen dependency-free packages; Windows execution was not tested.
- Earlier consolidation passes found a missing `io` import in the dashboard. It was fixed; final selected reporter tests passed. See accompanying test log for intermediate and final results.

## Release blockers / remaining technical debt

P0: full Go 1.24 build/test with real dependencies, real Docker isolation checks, scanner executable integration and incomplete-scan status/coverage handling, further filesystem confinement review (including races), dependency vulnerability review, review of report and AI data paths with real providers. Passive DAST scope remains a baseline origin redirect check, not full network policy or DNS rebinding protection. External tools and target-provided build/configuration may introduce additional trust boundaries.

P1: validate PDF/CSV/SARIF/XML/JSON exports end-to-end, SQLite history/migrations and YAML policies, Anthropic SDK and actual 9Router integration, fix/revalidate Clang and SpotBugs execution and offline Semgrep rules, resolve all unused or inconsistent configuration, canonical Go module name and CI generator installation workflow, refactor monolithic CLI, improve finding identity migration/stability, verify all scanner formats and cross-platform runtime. Existing container image scanning is not covered by the source scanner sandbox. Windows ACL behavior is not established by POSIX chmod tests.

P2: benchmark CPU/memory, expand parser fuzz testing and cross-platform integration fixtures, review documentation and packaging, finish release checks and tag only after all gates pass.

## Required next validation on a complete test host (do not push yet)

Use Go 1.24 or newer and the actual dependencies declared in go.mod. From the candidate root:

```sh
go version
go mod download
go mod verify
go build ./...
go test -count=1 ./...
go vet ./...
go test -race -count=1 ./...
govulncheck ./...
```

Run these on Linux and Windows (race testing requires a supported host/toolchain). `govulncheck` must already be installed and the vulnerability database reachable. Then run fixture-based, authorized local integration tests with each supported external scanner and Docker, both AI providers using non-sensitive test data, SQLite, and all report exports. Verify timeout, cancellation, failure reporting and absence of false success for skipped tools. No production targets are needed. Full dependency and integration checks remain unexecuted here because DNS/egress to proxy.golang.org fails and nearly all external scanner binaries and Docker are absent. Do not downgrade the production module to bypass the Go version requirement.

This candidate is NOT release-ready. Do not claim zero bugs or merge until the remaining gates are satisfied.

## Follow-up pre-push validation (25 November 2026)

The candidate remains local; no push or new pull request was performed. The following tests were completed on Go 1.23.2 with the isolated minimal module:

- Real Clang 17 integration: standalone C translation-unit analysis, null-dereference finding, no output file written to the target, and invalid source reported as an incomplete scan. The wrapper now passes translation units instead of a directory; it does not execute project build scripts. Projects requiring custom compiler flags or generated headers remain unsupported by this standalone mode.
- Local TLS DAST integration: validated cookie redaction, query redaction, HSTS and SameSite findings, and rejection of an untrusted certificate. Fixed missing SameSite detection (Go represents an absent attribute as zero).
- Parser fuzzing: two short runs, 53,385 and 12,282 executions (65,667 total), across 12 parsers without a crash. This is bounded fuzz testing, not proof of parser safety.
- Unit tests with coverage, race tests, and vet passed for the same 13 offline packages. Scanner statement coverage: 47.9%; compliance and remediation are still untested by that suite. Reporter subset and environment parser passed again. Windows amd64 cross-build passed, not runtime testing.
- Semgrep single-finding parser microbenchmark: 3,744 ns/op, 1,209 B/op, 26 allocs/op on this test host. Not an end-to-end throughput benchmark.
- Production `go test ./...` attempted again and failed before compilation because Go 1.24 cannot be downloaded (DNS connection refused). Docker and most external scanner binaries remain absent. The full dependency, real-provider, integration, vulnerability, and cross-platform runtime gates remain OPEN.

Release status: BLOCKED. Do not push or open a new PR until the required checks have passed. The existing earlier draft PR is not the consolidated candidate.
