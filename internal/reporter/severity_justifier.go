package reporter

import (
	"fmt"
	"github.com/example/sast-dast-analyzer/internal/models"
	"strings"
)

func GenerateSeverityJustification(f models.Finding) models.SeverityJustification {
	vector := f.CVSSVector
	if vector == "" {
		vector = "CVSS vector not established by available evidence"
	}
	reason := []string{fmt.Sprintf("Scanner-assigned base score: %.1f (%s).", f.CVSSBase, strings.ToUpper(string(f.Severity)))}
	if f.CVSSVector != "" {
		reason = append(reason, CVSSTranslator{}.ExplainCVSSMetrics(f.CVSSVector)...)
	} else {
		reason = append(reason, "Attack vector, privileges, interaction, and impact metrics require manual verification before submission.")
	}
	return models.SeverityJustification{CVSSScore: f.CVSSBase, CVSSVector: vector, Reasoning: reason, IndustryStandard: "CVSS v3.1; platform triage may adjust severity based on demonstrated impact."}
}
