package reporter

import (
	"math"
	"strings"

	"github.com/example/sast-dast-analyzer/internal/models"
)

type BusinessImpactCalculator struct{ Context models.BusinessContext }

func (c BusinessImpactCalculator) CalculateBusinessImpact(f models.Finding) models.BusinessImpact {
	pct, min, max, downtime, level := 5.0, 0.0, 1_000_000.0, 1.0, "low"
	switch f.Severity {
	case models.SeverityCritical:
		pct, min, max, downtime, level = 100, 100_000_000, 0, 24, "critical"
	case models.SeverityHigh:
		pct, min, max, downtime, level = 50, 10_000_000, 100_000_000, 8, "high"
	case models.SeverityMedium:
		pct, min, max, downtime, level = 10, 1_000_000, 10_000_000, 3, "medium"
	}
	typeText := classify(f)
	data := "Limited technical information may be exposed"
	if typeText == "authentication bypass" || typeText == "authorization bypass" {
		data = "Potential exposure of all data reachable by the affected identity"
	} else if typeText == "sql injection" {
		data = "Potential database disclosure or modification"
	} else if typeText == "rce" {
		data, downtime = "Potential access to application and host data", 24
	}
	multiplier := c.Context.Multipliers[strings.ToLower(c.Context.BusinessType)]
	if multiplier == 0 {
		multiplier = 1
	}
	min, max = min*multiplier, max*multiplier
	if max == 0 {
		max = math.Max(min, c.Context.AnnualRevenue*.1)
	}
	compliance := c.GetComplianceImpact(f)
	penalty := 0.0
	for _, value := range compliance {
		penalty += value
	}
	users := int(math.Ceil(float64(c.Context.NumUsers) * pct / 100))
	return models.BusinessImpact{Level: level, AffectedUsers: users, AffectedUsersPercent: pct, RevenueRiskMin: min, RevenueRiskMax: max, DataExposure: data, OperationalDowntime: downtime, CompliancePenalty: penalty, ComplianceImpact: compliance, Disclaimer: "Scenario estimate for prioritization; not a forecast or guaranteed loss."}
}

func (c BusinessImpactCalculator) GetComplianceImpact(f models.Finding) map[string]float64 {
	out := map[string]float64{}
	for _, framework := range c.Context.PrimaryCompliance {
		key := strings.ToLower(framework)
		value := c.Context.Penalties[key]
		if key == "gdpr" && value > 0 && value <= 1 {
			value *= c.Context.AnnualRevenue
		}
		if value > 0 {
			out[key] = value
		}
	}
	return out
}

func (c BusinessImpactCalculator) GetFinancialImpact(f models.Finding) models.FinancialMetrics {
	i := c.CalculateBusinessImpact(f)
	m := c.Context.Multipliers[strings.ToLower(c.Context.BusinessType)]
	if m == 0 {
		m = 1
	}
	return models.FinancialMetrics{BusinessType: c.Context.BusinessType, Multiplier: m, MinimumIDR: i.RevenueRiskMin, MaximumIDR: i.RevenueRiskMax, Method: "severity scenario × business-type multiplier"}
}

func classify(f models.Finding) string {
	v := strings.ToLower(f.Title + " " + f.Description + " " + f.CWE)
	switch {
	case strings.Contains(v, "sql") || strings.Contains(v, "cwe-89"):
		return "sql injection"
	case strings.Contains(v, "auth") && strings.Contains(v, "authoriz"):
		return "authorization bypass"
	case strings.Contains(v, "auth"):
		return "authentication bypass"
	case strings.Contains(v, "ssrf") || strings.Contains(v, "cwe-918"):
		return "ssrf"
	case strings.Contains(v, "xxe") || strings.Contains(v, "cwe-611"):
		return "xxe"
	case strings.Contains(v, "command") || strings.Contains(v, "code execution") || strings.Contains(v, "rce"):
		return "rce"
	case strings.Contains(v, "reentran"):
		return "reentrancy"
	case strings.Contains(v, "crypto") || strings.Contains(v, "signature"):
		return "crypto weakness"
	default:
		return "security weakness"
	}
}
