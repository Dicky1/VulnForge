package compliance

import (
	"strings"

	"github.com/example/sast-dast-analyzer/internal/models"
)

type ComplianceMapper struct{}

func NewComplianceMapper() *ComplianceMapper { return &ComplianceMapper{} }

var owasp = map[string]string{"CWE-862": "A01:2021 Broken Access Control", "CWE-863": "A01:2021 Broken Access Control", "CWE-22": "A01:2021 Broken Access Control", "CWE-327": "A02:2021 Cryptographic Failures", "CWE-798": "A02:2021 Cryptographic Failures", "CWE-89": "A03:2021 Injection", "CWE-79": "A03:2021 Injection", "CWE-78": "A03:2021 Injection", "CWE-20": "A03:2021 Injection", "CWE-611": "A05:2021 Security Misconfiguration", "CWE-1104": "A06:2021 Vulnerable and Outdated Components", "CWE-502": "A08:2021 Software and Data Integrity Failures"}
var top25 = map[string]bool{"CWE-787": true, "CWE-79": true, "CWE-89": true, "CWE-416": true, "CWE-78": true, "CWE-20": true, "CWE-125": true, "CWE-22": true, "CWE-352": true, "CWE-434": true, "CWE-862": true, "CWE-476": true, "CWE-287": true, "CWE-190": true, "CWE-502": true, "CWE-77": true, "CWE-119": true, "CWE-798": true, "CWE-918": true, "CWE-306": true, "CWE-362": true, "CWE-269": true, "CWE-94": true, "CWE-863": true, "CWE-276": true}

func (cm *ComplianceMapper) MapToOWASPTop10(findings []models.Finding) map[string][]models.Finding {
	out := map[string][]models.Finding{}
	for _, f := range findings {
		if c := owasp[strings.ToUpper(f.CWE)]; c != "" {
			out[c] = append(out[c], f)
		}
	}
	return out
}
func (cm *ComplianceMapper) MapToCWETop25(findings []models.Finding) map[string][]models.Finding {
	out := map[string][]models.Finding{}
	for _, f := range findings {
		c := strings.ToUpper(f.CWE)
		if top25[c] {
			out[c] = append(out[c], f)
		}
	}
	return out
}
func (cm *ComplianceMapper) MapToCompliance(findings []models.Finding, framework string) map[string]models.ComplianceGap {
	controls := frameworkControls[strings.ToUpper(framework)]
	out := map[string]models.ComplianceGap{}
	for _, f := range findings {
		for _, c := range controls {
			if matchesAny(f.CWE, c.CWEs) {
				g := out[c.ID]
				g.Control = c.ID
				g.Description = c.Description
				g.Recommendation = c.Recommendation
				g.Findings = append(g.Findings, f)
				out[c.ID] = g
			}
		}
	}
	return out
}
func (cm *ComplianceMapper) GenerateReport(findings []models.Finding, framework string) models.ComplianceReport {
	gaps := cm.MapToCompliance(findings, framework)
	total := len(frameworkControls[strings.ToUpper(framework)])
	coverage := 100.0
	if total > 0 {
		coverage = 100 - float64(len(gaps))/float64(total)*100
	}
	recs := []string{}
	for _, g := range gaps {
		recs = append(recs, g.Recommendation)
	}
	return models.ComplianceReport{Framework: framework, Gaps: gaps, CoveragePercent: coverage, Recommendations: recs}
}

type control struct {
	ID, Description, Recommendation string
	CWEs                            []string
}

var frameworkControls = map[string][]control{
	"GDPR":     {{"Article 32", "Security of processing", "Apply appropriate technical controls and protect credentials.", []string{"CWE-798", "CWE-327", "CWE-311"}}},
	"PCI-DSS":  {{"6.2.4", "Prevent common software attacks", "Remediate injection and access-control flaws before deployment.", []string{"CWE-79", "CWE-89", "CWE-78", "CWE-862"}}, {"8.3", "Strong authentication", "Remove embedded credentials and enforce identity controls.", []string{"CWE-798", "CWE-287"}}},
	"HIPAA":    {{"164.312(a)", "Access control", "Enforce unique identity and authorization controls.", []string{"CWE-862", "CWE-287"}}},
	"SOC2":     {{"CC6", "Logical access", "Protect credentials and enforce authorization.", []string{"CWE-798", "CWE-862", "CWE-287"}}},
	"ISO27001": {{"A.8.26", "Application security requirements", "Address application vulnerabilities through secure engineering.", []string{"CWE-79", "CWE-89", "CWE-78", "CWE-327"}}},
}

func matchesAny(cwe string, list []string) bool {
	for _, v := range list {
		if strings.EqualFold(cwe, v) {
			return true
		}
	}
	return false
}
