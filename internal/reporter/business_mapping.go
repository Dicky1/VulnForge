package reporter

import (
	"fmt"
	"github.com/example/sast-dast-analyzer/internal/models"
)

type ProcessImpactMapper struct{ Context models.BusinessContext }

func (m ProcessImpactMapper) MapFindingToBusinessProcess(f models.Finding) []models.BusinessProcess {
	typeText := classify(f)
	name, team, features, criticality := "Application operations", "Engineering", []string{"Affected application feature"}, 2
	switch typeText {
	case "authentication bypass":
		name, team, features, criticality = "Identity and login", "Identity & Security", []string{"Login", "User sessions", "API access"}, 5
	case "authorization bypass":
		name, team, features, criticality = "Permissions and data access", "Backend & Security", []string{"Roles", "Permissions", "Data access control"}, 5
	case "sql injection":
		name, team, features, criticality = "Customer data operations", "Backend & Data", []string{"Data retrieval", "Reports", "Search"}, 5
	case "ssrf":
		name, team, features, criticality = "External integrations", "Platform & DevOps", []string{"Payment integration", "Third-party APIs", "Cloud resources"}, 4
	case "crypto weakness":
		name, team, features, criticality = "Data protection", "Security & Platform", []string{"Encryption", "Token generation", "Signature verification"}, 5
	case "reentrancy":
		name, team, features, criticality = "Asset and lending transactions", "Smart Contract & Risk", []string{"Deposits", "Withdrawals", "Liquidation"}, 5
	}
	pct := map[models.Severity]float64{models.SeverityCritical: 100, models.SeverityHigh: 50, models.SeverityMedium: 10, models.SeverityLow: 5}[f.Severity]
	users := int(float64(m.Context.NumUsers) * pct / 100)
	narrative := fmt.Sprintf("This weakness affects %s, owned by %s, and may disrupt service for approximately %d users representing up to %.0f%% of exposed business activity.", name, team, users, pct)
	return []models.BusinessProcess{{Name: name, CriticalityScore: criticality, AffectedFeatures: features, NumUsersImpacted: users, RevenueImpactPct: pct, OwningTeam: team, ImpactNarrative: narrative}}
}
