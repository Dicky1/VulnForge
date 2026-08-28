package scorer

import (
	"math"
	"strings"

	"github.com/example/sast-dast-analyzer/internal/models"
)

type CVSSMetrics struct{ AV, AC, PR, UI, S, C, I, A string }
type CVSSCalculator struct{}

func (cc *CVSSCalculator) CalculateScore(m CVSSMetrics) float64 {
	av := metric(m.AV, map[string]float64{"N": .85, "A": .62, "L": .55, "P": .2})
	ac := metric(m.AC, map[string]float64{"L": .77, "H": .44})
	ui := metric(m.UI, map[string]float64{"N": .85, "R": .62})
	scope := short(m.S) == "C"
	prMap := map[string]float64{"N": .85, "L": .62, "H": .27}
	if scope {
		prMap = map[string]float64{"N": .85, "L": .68, "H": .5}
	}
	pr := metric(m.PR, prMap)
	c := metric(m.C, map[string]float64{"H": .56, "L": .22, "N": 0})
	i := metric(m.I, map[string]float64{"H": .56, "L": .22, "N": 0})
	a := metric(m.A, map[string]float64{"H": .56, "L": .22, "N": 0})
	iss := 1 - (1-c)*(1-i)*(1-a)
	impact := 6.42 * iss
	if scope {
		impact = 7.52*(iss-.029) - 3.25*math.Pow(iss-.02, 15)
	}
	if impact <= 0 {
		return 0
	}
	exploitability := 8.22 * av * ac * pr * ui
	base := impact + exploitability
	if scope {
		base = 1.08 * base
	}
	return roundUp(math.Min(base, 10))
}
func (*CVSSCalculator) SeverityFromScore(score float64) models.Severity {
	switch {
	case score >= 9:
		return models.SeverityCritical
	case score >= 7:
		return models.SeverityHigh
	case score >= 4:
		return models.SeverityMedium
	case score > 0:
		return models.SeverityLow
	default:
		return models.SeverityLow
	}
}
func (*CVSSCalculator) MetricsForFinding(f models.Finding) CVSSMetrics {
	m := CVSSMetrics{"L", "L", "L", "N", "U", "L", "L", "L"}
	text := strings.ToLower(f.Title + " " + f.Description + " " + f.CWE)
	if strings.Contains(text, "remote") || strings.Contains(text, "injection") || strings.Contains(text, "xss") || strings.Contains(text, "secret") {
		m.AV = "N"
	}
	if strings.Contains(text, "auth") || strings.Contains(text, "cwe-862") {
		m.PR = "N"
	}
	if strings.Contains(text, "secret") || strings.Contains(text, "credential") {
		m.C = "H"
	}
	if strings.Contains(text, "command") || strings.Contains(text, "code execution") {
		m.C, m.I, m.A = "H", "H", "H"
	}
	if strings.Contains(text, "xss") {
		m.UI = "R"
	}
	return m
}
func Vector(m CVSSMetrics) string {
	return "CVSS:3.1/AV:" + short(m.AV) + "/AC:" + short(m.AC) + "/PR:" + short(m.PR) + "/UI:" + short(m.UI) + "/S:" + short(m.S) + "/C:" + short(m.C) + "/I:" + short(m.I) + "/A:" + short(m.A)
}
func metric(v string, values map[string]float64) float64 { return values[short(v)] }
func short(v string) string {
	v = strings.ToUpper(v)
	if len(v) == 0 {
		return ""
	}
	switch v {
	case "NETWORK":
		return "N"
	case "ADJACENT":
		return "A"
	case "LOCAL":
		return "L"
	case "PHYSICAL":
		return "P"
	case "LOW":
		return "L"
	case "HIGH":
		return "H"
	case "NONE":
		return "N"
	case "REQUIRED":
		return "R"
	case "UNCHANGED":
		return "U"
	case "CHANGED":
		return "C"
	}
	return v[:1]
}
func roundUp(v float64) float64 { return math.Ceil(v*10-1e-9) / 10 }
