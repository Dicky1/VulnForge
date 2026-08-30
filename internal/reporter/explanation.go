package reporter

import (
	"github.com/example/sast-dast-analyzer/internal/models"
	"strings"
)

type CVSSTranslator struct{}

func (CVSSTranslator) TranslateCVSSScore(score float64) string {
	switch {
	case score >= 9:
		return "Immediate threat to business operations; a successful attack could compromise the system."
	case score >= 7:
		return "Significant risk that may expose sensitive data or business functionality."
	case score >= 4:
		return "Moderate risk that generally requires specific conditions or user interaction."
	default:
		return "Lower risk that is less likely to cause major damage on its own."
	}
}

func (CVSSTranslator) ExplainCVSSMetrics(vector string) []string {
	var out []string
	for _, metric := range strings.Split(vector, "/") {
		switch metric {
		case "AV:N":
			out = append(out, "Can be attacked remotely over a network.")
		case "AC:L":
			out = append(out, "Relatively easy to exploit; no unusual condition is required.")
		case "PR:N":
			out = append(out, "No login or existing permission is required.")
		case "UI:R":
			out = append(out, "A user must perform an action before exploitation can succeed.")
		case "UI:N":
			out = append(out, "No user action is needed for exploitation.")
		}
	}
	return out
}

func ExplainFinding(f models.Finding) models.FindingExplanation {
	t := CVSSTranslator{}.TranslateCVSSScore(f.CVSSBase)
	e := models.FindingExplanation{SimpleTitle: "A security control may not work as intended", WhatHappened: "The analyzer identified code behavior that may weaken an expected security control.", WhyDangerous: "An attacker may use the weakness to affect data, accounts, or service availability.", RealWorldExample: "An authorized tester reproduces the behavior in staging and confirms whether the control can be bypassed.", BusinessExample: "If exploitable, customer trust, operations, and regulatory obligations may be affected.", FixSummary: "Review the affected code, apply the recommended control, and add a regression test.", CVSSBusinessText: t}
	switch classify(f) {
	case "sql injection":
		e.SimpleTitle = "Database queries may be manipulated"
		e.WhatHappened = "User-controlled data may be combined with a database query without safe parameters."
		e.WhyDangerous = "An attacker could read, change, or delete records outside their permission."
		e.BusinessExample = "Customer profiles, transactions, or management reports may be exposed."
		e.FixSummary = "Use parameterized queries and validate input."
	case "authentication bypass":
		e.SimpleTitle = "Accounts may be accessed without valid credentials"
		e.WhatHappened = "The login or token validation flow may accept an invalid identity."
		e.FixSummary = "Validate every credential and deny access by default."
	case "authorization bypass":
		e.SimpleTitle = "Users may access data outside their role"
		e.WhatHappened = "The server may not enforce ownership or role checks on every request."
		e.FixSummary = "Enforce server-side authorization for each resource and action."
	case "reentrancy":
		e.SimpleTitle = "A transaction may update balances more than once"
		e.WhatHappened = "An external contract call may re-enter the operation before accounting is finalized."
		e.WhyDangerous = "Funds or debt accounting could become inconsistent."
		e.BusinessExample = "A lending pool could lose assets or report incorrect balances."
		e.FixSummary = "Apply checks-effects-interactions and a reentrancy guard, then test accounting invariants."
	}
	return e
}
