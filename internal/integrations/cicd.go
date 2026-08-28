package integrations

const githubActions = `name: Security Scan
on: [push, pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: {go-version: '1.24'}
      - run: go run ./cmd/analyzer/main.go --target . --export-format json,sarif --output report.json
        env:
          ANTHROPIC_API_KEY: $` + `{{ secrets.ANTHROPIC_API_KEY }}` + `
      - uses: actions/upload-artifact@v4
        with: {name: security-report, path: 'report.*'}
`
const gitlabCI = `security_scan:
  image: golang:1.24
  script:
    - go run ./cmd/analyzer/main.go --target . --export-format json,sarif --output report.json
  artifacts:
    when: always
    paths: [report.json, report.sarif]
`
const jenkins = `pipeline {
  agent any
  stages {
    stage('Security Scan') {
      steps { sh 'go run ./cmd/analyzer/main.go --target . --export-format json,sarif --output report.json' }
    }
  }
  post { always { archiveArtifacts artifacts: 'report.*', fingerprint: true } }
}`
const preCommit = `#!/bin/sh
set -eu
go run ./cmd/analyzer/main.go --target . --export-format json --output report.json
if grep -q '"critical_count": [1-9]' report.json; then
  echo "Commit blocked: critical security findings detected." >&2
  exit 1
fi
`

func GenerateGithubActionsYAML() string { return githubActions }
func GenerateGitlabCIYAML() string      { return gitlabCI }
func GenerateJenkinsfile() string       { return jenkins }
func GeneratePreCommitHook() string     { return preCommit }
