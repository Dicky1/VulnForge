package reporter

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/example/sast-dast-analyzer/internal/models"
)

type BusinessReportOptions struct {
	EnablePOC, EnableRoadmap bool
	POCSkillLevel            string
}

func BuildBusinessReport(findings []models.Finding, ctx models.BusinessContext, opts BusinessReportOptions) *models.BusinessReport {
	calc, mapper, matrix, effort := BusinessImpactCalculator{Context: ctx}, ProcessImpactMapper{Context: ctx}, RiskMatrix{}, RemediationPlan{}
	result := &models.BusinessReport{GeneratedAt: time.Now().UTC(), Context: ctx, SeverityCounts: map[string]int{}, RiskMatrix: map[string]map[string]int{}}
	byID := map[string]models.BusinessFinding{}
	for _, f := range findings {
		impact := calc.CalculateBusinessImpact(f)
		b := models.BusinessFinding{FindingID: f.ID, Impact: impact, Financial: calc.GetFinancialImpact(f), Processes: mapper.MapFindingToBusinessProcess(f), Explanation: ExplainFinding(f), EstimatedEffort: effort.EstimateFixingEffort(f)}
		b.PriorityScore = matrix.CalculatePriorityScore(f.Severity, impact.Level)
		b.PriorityLabel = priorityLabel(b.PriorityScore)
		if opts.EnablePOC {
			if p, err := (&POCGenerator{SkillLevel: opts.POCSkillLevel}).GeneratePOC(f); err == nil {
				b.POC = &p
			}
		}
		result.Findings = append(result.Findings, b)
		byID[f.ID] = b
		result.SeverityCounts[string(f.Severity)]++
		if result.RiskMatrix[string(f.Severity)] == nil {
			result.RiskMatrix[string(f.Severity)] = map[string]int{}
		}
		result.RiskMatrix[string(f.Severity)][impact.Level]++
	}
	sort.SliceStable(result.Findings, func(i, j int) bool { return result.Findings[i].PriorityScore < result.Findings[j].PriorityScore })
	if opts.EnableRoadmap {
		result.Roadmap = effort.GenerateTimelineByPriority(findings, byID)
	}
	result.ExecutiveSummary = executiveSummary(result)
	return result
}

func executiveSummary(r *models.BusinessReport) models.ExecutiveSummary {
	if len(r.Findings) == 0 {
		return models.ExecutiveSummary{BriefDescription: "No reportable security findings were identified by the scanners that completed successfully.", OverallRiskLevel: "Low", Urgency: "Continue routine monitoring."}
	}
	risk, totalMax, totalHours, maxUsers := 0.0, 0.0, 0.0, 0
	for _, f := range r.Findings {
		risk += float64(17 - f.PriorityScore)
		totalMax += f.Impact.RevenueRiskMax
		totalHours += f.EstimatedEffort
		if f.Impact.AffectedUsers > maxUsers {
			maxUsers = f.Impact.AffectedUsers
		}
	}
	score := risk / float64(len(r.Findings)) / 16 * 100
	level, urgency := "Low", "Address through normal maintenance within 60–90 days."
	if score >= 75 {
		level, urgency = "Critical", "Begin containment immediately and remediate within 24 hours."
	} else if score >= 50 {
		level, urgency = "High", "Assign owners now and remediate highest priorities within 7 days."
	} else if score >= 25 {
		level, urgency = "Medium", "Plan remediation within 30 days."
	}
	return models.ExecutiveSummary{BriefDescription: "The assessment found weaknesses that may affect customer data, financial transactions, or service availability. Findings are prioritized by technical severity and estimated business exposure.", BusinessImpactSummary: fmt.Sprintf("Scenario-based exposure is up to Rp %.0f across %d affected findings; this is an estimate, not a predicted loss.", totalMax, len(r.Findings)), OverallRiskLevel: level, OverallRiskScore: score, Urgency: urgency, AverageFixHours: totalHours / float64(len(r.Findings)), TotalRevenueRiskIDR: totalMax, TotalAffectedUsers: maxUsers}
}

func BusinessFindingFor(r *models.BusinessReport, id string) (models.BusinessFinding, bool) {
	if r == nil {
		return models.BusinessFinding{}, false
	}
	for _, f := range r.Findings {
		if f.FindingID == id {
			return f, true
		}
	}
	return models.BusinessFinding{}, false
}
func formatIDR(v float64) string {
	switch {
	case v >= 1e12:
		return fmt.Sprintf("Rp %.1fT", v/1e12)
	case v >= 1e9:
		return fmt.Sprintf("Rp %.1fM", v/1e9)
	case v >= 1e6:
		return fmt.Sprintf("Rp %.1fJt", v/1e6)
	default:
		return fmt.Sprintf("Rp %.0f", v)
	}
}
func safeClass(v any) string { return strings.ToLower(strings.ReplaceAll(fmt.Sprint(v), " ", "-")) }
