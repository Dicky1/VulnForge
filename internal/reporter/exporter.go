package reporter

import (
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/example/sast-dast-analyzer/internal/models"
	"github.com/example/sast-dast-analyzer/internal/sbom"
)

type ReportExporter struct{}

func NewReportExporter() *ReportExporter { return &ReportExporter{} }
func (re *ReportExporter) Export(r models.Report, format, path string) error {
	switch strings.ToLower(format) {
	case "json":
		return re.ExportJSON(r, path)
	case "html":
		return re.ExportHTML(r, path)
	case "dashboard":
		return re.ExportHTML(r, path)
	case "bounty-report":
		return re.ExportBountyBundle(r, path)
	case "pdf":
		return re.ExportPDF(r, path)
	case "sarif":
		return re.ExportSARIF(r, path)
	case "xml":
		return re.ExportXML(r, path)
	case "csv":
		return re.ExportCSV(r, path)
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}
func (*ReportExporter) ExportJSON(r models.Report, path string) error {
	b, e := json.MarshalIndent(r, "", "  ")
	if e != nil {
		return e
	}
	return write(path, b)
}

func (*ReportExporter) ExportSBOM(bom sbom.SBOM, format, dir string) (string, error) {
	format = strings.ToLower(format)
	name := "sbom.cyclonedx.json"
	if strings.HasPrefix(format, "spdx") {
		name = "sbom.spdx.json"
	} else if strings.Contains(format, "xml") {
		name = "sbom.cyclonedx.xml"
	}
	path := filepath.Join(dir, name)
	var data []byte
	var err error
	if strings.HasSuffix(name, ".xml") {
		data, err = xml.MarshalIndent(bom, "", "  ")
		data = append([]byte(xml.Header), data...)
	} else {
		data, err = json.MarshalIndent(bom, "", "  ")
	}
	if err != nil {
		return "", err
	}
	return path, write(path, data)
}

func (*ReportExporter) ExportHTML(r models.Report, path string) error {
	return renderDashboard(r, path)
}

func (*ReportExporter) ExportPDF(r models.Report, path string) error {
	pdf := newStyledPDF("Security Analysis Report")
	pdf.AddPage()
	pdf.SetFont("Arial", "B", 20)
	pdf.CellFormat(0, 12, "Security Analysis Report", "", 1, "L", false, 0, "")
	pdf.Ln(2)
	metaRow(pdf, "Target", r.TargetPath)
	if r.DASTTargetURL != "" && r.DASTTargetURL != r.TargetPath {
		metaRow(pdf, "DAST endpoint", r.DASTTargetURL)
	}
	if len(r.IncompleteChecks) > 0 {
		metaRow(pdf, "Incomplete checks", strings.Join(r.IncompleteChecks, ", "))
	}
	metaRow(pdf, "Languages", r.Language)
	metaRow(pdf, "Generated", r.Timestamp.Format("2006-01-02 15:04 UTC"))
	metaRow(pdf, "Duration", r.Duration)

	pdf.Ln(3)
	counts := severityCounts(r.Findings)
	for _, s := range []models.Severity{models.SeverityCritical, models.SeverityHigh, models.SeverityMedium, models.SeverityLow} {
		severityBadge(pdf, s)
		pdf.SetFont("Arial", "", 9)
		pdf.CellFormat(16, 5.5, fmt.Sprintf(" %d ", counts[s]), "", 0, "L", false, 0, "")
	}
	pdf.Ln(10)

	if len(r.DASTEndpoints) > 0 {
		sectionHeader(pdf, "HTTP Endpoints")
		pdf.SetFont("Arial", "", 9)
		for _, endpoint := range r.DASTEndpoints {
			pdf.MultiCell(0, 5, endpoint.RequestedURL, "", "L", false)
			if endpoint.FinalURL != "" && endpoint.FinalURL != endpoint.RequestedURL {
				pdf.MultiCell(0, 5, "Final URL: "+endpoint.FinalURL, "", "L", false)
			}
			if endpoint.StatusCode > 0 {
				pdf.MultiCell(0, 5, fmt.Sprintf("HTTP %d", endpoint.StatusCode), "", "L", false)
			}
			if endpoint.Error != "" {
				pdf.MultiCell(0, 5, endpoint.Error, "", "L", false)
			}
			pdf.Ln(2)
		}
	}

	if r.BusinessReport != nil {
		s := r.BusinessReport.ExecutiveSummary
		sectionHeader(pdf, "Executive Summary")
		metaRow(pdf, "Overall risk", fmt.Sprintf("%s (%.0f/100)", s.OverallRiskLevel, s.OverallRiskScore))
		metaRow(pdf, "Urgency", s.Urgency)
		pdf.Ln(1)
		pdf.SetFont("Arial", "", 9)
		pdf.MultiCell(0, 5, s.BriefDescription, "", "L", false)
		pdf.Ln(1)
		pdf.MultiCell(0, 5, s.BusinessImpactSummary, "", "L", false)

		sectionHeader(pdf, "Top Business Priorities")
		limit := 5
		if len(r.BusinessReport.Findings) < limit {
			limit = len(r.BusinessReport.Findings)
		}
		for _, business := range r.BusinessReport.Findings[:limit] {
			pdf.SetFont("Arial", "B", 10)
			pdf.MultiCell(0, 5.5, fmt.Sprintf("Priority %d - %s", business.PriorityScore, business.Explanation.SimpleTitle), "", "L", false)
			pdf.SetFont("Arial", "", 9)
			pdf.MultiCell(0, 5, business.Explanation.WhyDangerous, "", "L", false)
			setTextColor(pdf, colorMuted)
			pdf.MultiCell(0, 5, fmt.Sprintf("Estimated exposure: %s to %s", formatIDR(business.Impact.RevenueRiskMin), formatIDR(business.Impact.RevenueRiskMax)), "", "L", false)
			setTextColor(pdf, colorInk)
			pdf.MultiCell(0, 5, "Fix: "+business.Explanation.FixSummary, "", "L", false)
			pdf.Ln(1)
			divider(pdf)
		}

		pdf.AddPage()
		sectionHeader(pdf, "Remediation Roadmap")
		for _, phase := range r.BusinessReport.Roadmap.Phases {
			pdf.SetFont("Arial", "B", 11)
			pdf.CellFormat(0, 7, fmt.Sprintf("%s - due within %d day(s), %.1f effort hours", phase.Name, phase.DeadlineDays, phase.TotalHours), "", 1, "L", false, 0, "")
			pdf.SetFont("Arial", "", 9)
			for _, item := range phase.Items {
				pdf.MultiCell(0, 5, fmt.Sprintf("- Priority %d: %s (%s)", item.Priority, item.Title, strings.Join(item.RequiredTeams, ", ")), "", "L", false)
			}
			pdf.Ln(2)
		}
	}

	if len(r.Findings) > 0 {
		pdf.AddPage()
		sectionHeader(pdf, "Findings")
		for _, f := range r.Findings {
			findingCard(pdf, f)
		}
	}

	if e := ensureDir(path); e != nil {
		return e
	}
	return atomicReportPath(path, pdf.OutputFileAndClose)
}

func (*ReportExporter) ExportSARIF(r models.Report, path string) error {
	rules := map[string]any{}
	results := make([]any, 0, len(r.Findings))
	for _, f := range r.Findings {
		rule := f.CWE
		if rule == "" {
			rule = f.SourceTool + "/" + f.Title
		}
		rules[rule] = map[string]any{"id": rule, "name": f.Title, "shortDescription": map[string]string{"text": f.Description}, "helpUri": firstLink(f)}
		location := map[string]any{"physicalLocation": map[string]any{"artifactLocation": map[string]string{"uri": filepath.ToSlash(f.FilePath)}, "region": map[string]int{"startLine": max(f.LineNumber, 1)}}}
		result := map[string]any{"ruleId": rule, "level": sarifLevel(f.Severity), "message": map[string]string{"text": f.Description}, "locations": []any{location}}
		if f.DASTEvidence != nil {
			result["properties"] = map[string]any{"dastEvidence": f.DASTEvidence}
		}
		if f.Remediation != "" {
			result["fixes"] = []any{map[string]any{"description": map[string]string{"text": f.Remediation}}}
		}
		results = append(results, result)
	}
	ruleList := make([]any, 0, len(rules))
	for _, v := range rules {
		ruleList = append(ruleList, v)
	}
	driver := map[string]any{"name": "sast-dast-analyzer", "informationUri": "https://github.com/", "rules": ruleList}
	run := map[string]any{"tool": map[string]any{"driver": driver}, "results": results}
	if len(r.DASTEndpoints) > 0 {
		run["properties"] = map[string]any{"dastEndpoints": r.DASTEndpoints, "dastSession": r.DASTSession}
	}
	if len(r.IncompleteChecks) > 0 {
		run["invocations"] = []any{map[string]any{
			"executionSuccessful": false,
			"toolExecutionNotifications": []any{map[string]any{
				"level": "warning", "message": map[string]string{"text": "Incomplete checks: " + strings.Join(r.IncompleteChecks, ", ")},
			}},
		}}
	}
	doc := map[string]any{"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": []any{run}}
	b, e := json.MarshalIndent(doc, "", "  ")
	if e != nil {
		return e
	}
	return write(path, b)
}

type xmlReport struct {
	XMLName       xml.Name              `xml:"securityReport"`
	Timestamp     string                `xml:"timestamp"`
	Target        string                `xml:"target"`
	DASTTarget    string                `xml:"dastTarget,omitempty"`
	DASTEndpoints []models.DASTEndpoint `xml:"dastEndpoints>endpoint,omitempty"`
	DASTSession   string                `xml:"dastSession,omitempty"`
	Incomplete    []string              `xml:"incompleteChecks>check,omitempty"`
	Languages     string                `xml:"languages"`
	Total         int                   `xml:"total"`
	Critical      int                   `xml:"critical"`
	High          int                   `xml:"high"`
	Findings      []xmlFinding          `xml:"findings>finding"`
}
type xmlFinding struct {
	ID           string               `xml:"id,attr"`
	Title        string               `xml:"title"`
	Severity     string               `xml:"severity"`
	CWE          string               `xml:"cwe"`
	File         string               `xml:"file"`
	Description  string               `xml:"description"`
	Remediation  string               `xml:"remediation"`
	Line         int                  `xml:"line"`
	CVSS         float64              `xml:"cvss"`
	DASTEvidence *models.DASTEvidence `xml:"dastEvidence,omitempty"`
}

func (*ReportExporter) ExportXML(r models.Report, path string) error {
	x := xmlReport{Timestamp: r.Timestamp.Format(time.RFC3339), Target: r.TargetPath, DASTTarget: r.DASTTargetURL, Incomplete: r.IncompleteChecks, Languages: r.Language, Total: r.TotalFindings, Critical: r.CriticalCount, High: r.HighCount}
	x.DASTEndpoints, x.DASTSession = r.DASTEndpoints, r.DASTSession
	for _, f := range r.Findings {
		x.Findings = append(x.Findings, xmlFinding{ID: f.ID, Title: f.Title, Severity: string(f.Severity), CWE: f.CWE, File: f.FilePath, Description: f.Description, Remediation: f.Remediation, Line: f.LineNumber, CVSS: f.CVSSBase, DASTEvidence: f.DASTEvidence})
	}
	b, e := xml.MarshalIndent(x, "", "  ")
	if e != nil {
		return e
	}
	return write(path, append([]byte(xml.Header), b...))
}
func (*ReportExporter) ExportCSV(r models.Report, path string) error {
	return atomicReport(path, func(f io.Writer) error {
		var e error
		w := csv.NewWriter(f)
		if e = w.Write([]string{"ID", "Title", "Severity", "Language", "CWE", "CVSS", "File", "Line", "Remediation"}); e != nil {
			return e
		}
		for _, v := range r.Findings {
			if e = w.Write([]string{
				sanitizeCSVField(v.ID),
				sanitizeCSVField(v.Title),
				sanitizeCSVField(string(v.Severity)),
				sanitizeCSVField(v.Language),
				sanitizeCSVField(v.CWE),
				strconv.FormatFloat(v.CVSSBase, 'f', 1, 64),
				sanitizeCSVField(v.FilePath),
				strconv.Itoa(v.LineNumber),
				sanitizeCSVField(v.Remediation),
			}); e != nil {
				return e
			}
		}
		w.Flush()
		if e = w.Error(); e != nil {
			return e
		}
		return nil
	})
}
func sanitizeCSVField(s string) string {
	trim := strings.TrimLeft(s, " \t\r\n")
	if len(s) > 0 && (s[0] == '=' || s[0] == '+' || s[0] == '-' || s[0] == '@' || s[0] == '\t' || s[0] == '\r' || s[0] == '\n' || (len(trim) > 0 && strings.ContainsRune("=+-@", rune(trim[0])))) {
		return "'" + s
	}
	return s
}

func sarifLevel(s models.Severity) string {
	switch s {
	case models.SeverityCritical, models.SeverityHigh:
		return "error"
	case models.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}
func firstLink(f models.Finding) string {
	if len(f.RemediationSuggestions) > 0 {
		return f.RemediationSuggestions[0].Link
	}
	return "https://cwe.mitre.org/data/definitions/" + strings.TrimPrefix(strings.ToUpper(f.CWE), "CWE-") + ".html"
}
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
