package reporter

import (
	"errors"
	"fmt"
	"github.com/example/sast-dast-analyzer/internal/models"
)

type POCGenerator struct{ SkillLevel string }

func (pg *POCGenerator) GeneratePOC(f models.Finding) (models.POC, error) {
	level, minutes := pg.SkillLevel, 30
	if level == "" {
		level = "intermediate"
	}
	if level == "basic" {
		minutes = 5
	} else if level == "advanced" {
		minutes = 120
	}
	p := models.POC{Title: "Authorized validation: " + f.Title, Description: "Non-destructive reproduction guidance for an isolated test environment.", Prerequisites: []string{"Written authorization", "Staging or local environment", "Test account and sanitized test data"}, SkillLevel: level, EstimatedMinutes: minutes, SafetyNotice: "Run only on systems you own or are explicitly authorized to test. Do not target production or real user data."}
	location := fmt.Sprintf("%s:%d", f.FilePath, f.LineNumber)
	switch classify(f) {
	case "sql injection":
		p.StepByStep = []string{"Locate the input reaching " + location, "In a local test, submit a benign quote character and observe validation", "Confirm the query uses parameters by reviewing logs or a unit test"}
		p.ExpectedResult = "Unsafe code changes query structure; fixed code treats input as data."
		p.CurlExample = `curl -G "http://127.0.0.1:8080/test" --data-urlencode "value='"`
	case "authentication bypass":
		p.StepByStep = []string{"Identify the authentication mechanism near " + location, "Use an expired or deliberately invalid test token", "Verify access is denied and logged"}
		p.ExpectedResult = "Every invalid credential receives 401/403 without disclosing protected data."
	case "authorization bypass":
		p.StepByStep = []string{"Create two test users with different roles", "Request a resource owned by the other test user", "Verify server-side authorization denies access"}
		p.ExpectedResult = "Cross-user access is rejected with 403."
	case "ssrf":
		p.StepByStep = []string{"Use a local mock HTTP server", "Submit its loopback URL to the affected test parameter", "Verify allow-list and private-address controls block the request"}
		p.ExpectedResult = "Private and unapproved destinations are blocked."
		p.CurlExample = `curl "http://127.0.0.1:8080/test?url=http://127.0.0.1:9000"`
	case "xxe":
		p.StepByStep = []string{"Use a harmless XML fixture with an external entity pointing to a local mock server", "Submit it only to staging", "Verify DTD and external entity processing is disabled"}
		p.ExpectedResult = "Parser rejects DTD/external entities without reading files or network resources."
	case "rce":
		p.StepByStep = []string{"Trace the untrusted value at " + location, "Use a harmless marker string in an isolated test", "Verify no shell, eval, or template execution occurs"}
		p.ExpectedResult = "Input remains inert and no command is executed."
	case "reentrancy":
		p.StepByStep = []string{"Deploy contracts to a local fork with test funds only", "Use a test receiver that attempts one nested callback", "Assert balances and state cannot be updated twice"}
		p.ExpectedResult = "Reentrant callback is rejected and accounting invariants remain unchanged."
	default:
		return models.POC{}, errors.New("no safe POC template applies to this finding")
	}
	return p, nil
}
