package reporter

import (
	"fmt"
	"github.com/example/sast-dast-analyzer/internal/models"
	"strings"
)

func BuildDetailedStepsToReproduce(f models.Finding, endpoint string) []models.BountyStep {
	location := fmt.Sprintf("%s:%d", f.FilePath, f.LineNumber)
	if endpoint == "" {
		endpoint = "<AUTHORIZED_STAGING_URL>"
	}
	steps := []models.BountyStep{{StepNumber: 1, Description: "Obtain written authorization and deploy the affected revision to an isolated staging or local environment.", ExpectedResult: "Testing environment contains no production credentials or real user data."}, {StepNumber: 2, Description: "Review the suspected data flow at " + location + " and identify the corresponding deployed request or contract call.", ExpectedResult: "The exact affected input and code path are documented."}}
	switch classify(f) {
	case "sql injection":
		steps = append(steps, models.BountyStep{StepNumber: 3, Description: "Send a benign quote-character probe to the identified test parameter.", Command: `curl -G "` + endpoint + `" --data-urlencode "value='"`, ExpectedResult: "Record whether validation rejects the input or the response differs from a normal request; do not enumerate data."})
	case "authentication bypass":
		steps = append(steps, models.BountyStep{StepNumber: 3, Description: "Submit an expired or deliberately invalid test credential.", ExpectedResult: "The service must return 401/403 and create an audit event."})
	case "authorization bypass":
		steps = append(steps, models.BountyStep{StepNumber: 3, Description: "Using two test accounts, request a resource owned by the other account.", ExpectedResult: "The server must return 403 without disclosing resource content."})
	case "ssrf":
		steps = append(steps, models.BountyStep{StepNumber: 3, Description: "Submit the URL of a researcher-controlled local mock server; never use cloud metadata or third-party hosts.", ExpectedResult: "Unapproved/private destinations are blocked."})
	case "reentrancy":
		steps = append(steps, models.BountyStep{StepNumber: 3, Description: "On a local fork with test tokens, call the affected function through a receiver that attempts one nested callback.", ExpectedResult: "The nested call is rejected and balance invariants remain unchanged."})
	default:
		steps = append(steps, models.BountyStep{StepNumber: 3, Description: "Create a minimal non-destructive regression test that reaches the reported branch.", ExpectedResult: "The behavior is reproduced without modifying persistent or third-party data."})
	}
	steps = append(steps, models.BountyStep{StepNumber: len(steps) + 1, Description: "Capture sanitized request/response evidence, scanner output, revision hash, and timestamp.", ExpectedResult: "Evidence is sufficient for an independent triager to reproduce the observation."})
	return steps
}

type POCFormatter struct{ Formats []string }

func (p POCFormatter) Format(f models.Finding, endpoint string) models.BountyPOC {
	if endpoint == "" {
		endpoint = "<AUTHORIZED_STAGING_URL>"
	}
	out := models.BountyPOC{Setup: "Use an isolated test environment, written authorization, sanitized test data, and the exact affected revision.", Cleanup: "Remove test accounts/data, stop local mocks, and preserve sanitized evidence according to program policy.", Expected: "A vulnerable build shows the documented control failure; a fixed build rejects the probe without side effects.", Timing: "Expected validation time: 5–30 minutes after environment setup.", Safety: "Non-destructive validation only. Do not extract credentials, alter records, cause denial of service, or access third-party/internal metadata."}
	enabled := map[string]bool{}
	for _, v := range p.Formats {
		enabled[strings.ToLower(v)] = true
	}
	if enabled["curl"] {
		out.Curl = `curl -i -G "` + endpoint + `" --data-urlencode "probe=SECURITY_TEST_MARKER"`
	}
	if enabled["python"] {
		out.Python = "import requests\nurl = \"" + endpoint + "\"\nr = requests.get(url, params={\"probe\": \"SECURITY_TEST_MARKER\"}, timeout=10)\nprint(r.status_code, r.text[:500])"
	}
	if enabled["raw_http"] {
		out.RawHTTP = "GET /<verified-path>?probe=SECURITY_TEST_MARKER HTTP/1.1\r\nHost: <verified-in-scope-host>\r\nConnection: close\r\n\r\n"
	}
	if enabled["javascript"] {
		out.JavaScript = "fetch('/<verified-path>?probe=SECURITY_TEST_MARKER', {credentials: 'include'}).then(r => r.text()).then(console.log)"
	}
	return out
}
