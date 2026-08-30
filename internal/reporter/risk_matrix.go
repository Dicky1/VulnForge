package reporter

import "github.com/example/sast-dast-analyzer/internal/models"

type RiskMatrix struct{}

func (RiskMatrix) CalculatePriorityScore(technical models.Severity, impact string) int {
	rank := map[models.Severity]int{models.SeverityLow: 1, models.SeverityMedium: 2, models.SeverityHigh: 3, models.SeverityCritical: 4}[technical]
	impactRank := map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}[impact]
	if rank == 0 {
		rank = 1
	}
	if impactRank == 0 {
		impactRank = 1
	}
	matrix := [][]int{{16, 14, 11, 8}, {13, 10, 7, 5}, {9, 6, 3, 2}, {4, 3, 2, 1}}
	return matrix[rank-1][impactRank-1]
}
func priorityLabel(score int) string {
	if score <= 3 {
		return "Immediate"
	}
	if score <= 6 {
		return "ASAP"
	}
	if score <= 10 {
		return "Planned"
	}
	return "Monitor"
}
