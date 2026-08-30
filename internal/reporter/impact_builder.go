package reporter

import (
	"fmt"
	"github.com/example/sast-dast-analyzer/internal/models"
)

func BuildImpactDescription(f models.Finding, b *models.BusinessFinding) models.ImpactDescription {
	security := "The finding may weaken confidentiality, integrity, or availability; exact properties require runtime validation."
	scope := "Affected source component: " + f.FilePath
	switch classify(f) {
	case "sql injection":
		security = "Confidentiality and integrity may be affected if query structure can be controlled."
	case "authentication bypass":
		security = "Authentication may be bypassed, allowing an invalid identity to access protected functions."
	case "authorization bypass":
		security = "Authorization boundaries may fail across users or roles."
	case "reentrancy":
		security = "Integrity of asset and debt accounting may be affected by nested contract execution."
	case "rce":
		security = "Host confidentiality, integrity, and availability may be affected if code execution is confirmed."
	}
	business, user := "Potential incident response cost, customer trust impact, and regulatory review depend on demonstrated exploitability.", "Affected-user count is not established by technical evidence."
	if b != nil {
		business = fmt.Sprintf("Scenario exposure ranges from %s to %s; this is a prioritization estimate, not a predicted loss.", formatIDR(b.Impact.RevenueRiskMin), formatIDR(b.Impact.RevenueRiskMax))
		user = fmt.Sprintf("Up to approximately %d users (%.0f%%) may be in the affected scenario.", b.Impact.AffectedUsers, b.Impact.AffectedUsersPercent)
	}
	return models.ImpactDescription{SecurityImpact: security, BusinessImpact: business, UserImpact: user, ScopeOfImpact: scope}
}
