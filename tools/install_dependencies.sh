#!/usr/bin/env bash
set -uo pipefail

# Installs scanners whose package managers are already available. Platform-level
# tools (SpotBugs, LLVM, OWASP Dependency-Check) are reported for manual setup.
failed=0
run() {
  printf 'Installing %s...\n' "$1"
  shift
  if ! "$@"; then
    printf 'Warning: installation failed; continuing.\n' >&2
    failed=1
  fi
}

command -v python >/dev/null && run "Semgrep and Bandit" python -m pip install --upgrade semgrep bandit
command -v go >/dev/null && run "GoSec" go install github.com/securego/gosec/v2/cmd/gosec@latest
command -v npm >/dev/null && run "ESLint security plugin" npm install --global eslint @microsoft/security
command -v composer >/dev/null && run "PHPStan and Psalm" composer global require phpstan/phpstan vimeo/psalm
command -v cargo >/dev/null && run "Cargo Audit" cargo install cargo-audit --locked
command -v gem >/dev/null && run "Brakeman" gem install brakeman --no-document

printf '%s\n' "Install SpotBugs, LLVM scan-build, and OWASP Dependency-Check with your OS package manager."
exit "$failed"
