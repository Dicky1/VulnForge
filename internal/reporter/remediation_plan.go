package reporter

import (
	"github.com/example/sast-dast-analyzer/internal/models"
	"strings"
)

type RemediationPlan struct{}

func (RemediationPlan) EstimateFixingEffort(f models.Finding) float64 {
	v := strings.ToLower(f.Title + " " + f.Description)
	if strings.Contains(v, "config") || strings.Contains(v, "header") {
		return .5
	}
	if classify(f) == "reentrancy" || classify(f) == "crypto weakness" {
		return 12
	}
	if f.Severity == models.SeverityCritical {
		return 16
	}
	if f.Severity == models.SeverityHigh {
		return 4
	}
	return 2
}
func (rp RemediationPlan) GenerateTimelineByPriority(findings []models.Finding, enriched map[string]models.BusinessFinding) models.RemediationRoadmap {
	phases := []models.RemediationPhase{{Name: "Immediate", DeadlineDays: 1}, {Name: "Week 1", DeadlineDays: 7}, {Name: "Week 2", DeadlineDays: 14}, {Name: "Month 1", DeadlineDays: 30}, {Name: "Month 2", DeadlineDays: 60}, {Name: "Month 3+", DeadlineDays: 999}}
	for _, f := range findings {
		b := enriched[f.ID]
		idx := 5
		if f.Severity == models.SeverityCritical || b.PriorityScore <= 3 {
			idx = 0
		} else if b.PriorityScore <= 6 {
			idx = 1
		} else if f.Severity == models.SeverityHigh {
			idx = 2
		} else if b.Impact.Level == "high" || b.Impact.Level == "critical" {
			idx = 3
		} else if f.Severity == models.SeverityMedium {
			idx = 4
		}
		teams := []string{"Engineering", "Security"}
		if f.Language == "solidity" {
			teams = []string{"Smart Contract", "Security", "Risk"}
		}
		item := models.RoadmapItem{FindingID: f.ID, Title: f.Title, Priority: b.PriorityScore, EffortHours: b.EstimatedEffort, RequiredTeams: teams, Dependencies: []string{"Reproduce safely before changing code"}, TestingPlan: "Add regression test, rerun the relevant scanner, and perform peer review.", RollbackPlan: "Keep the previous release artifact and revert if business-critical regression tests fail."}
		phases[idx].Items = append(phases[idx].Items, item)
		phases[idx].TotalHours += item.EffortHours
	}
	return models.RemediationRoadmap{Phases: phases}
}
