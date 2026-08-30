package reporter

import (
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/example/sast-dast-analyzer/internal/models"
	"github.com/go-pdf/fpdf"
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

func (*ReportExporter) ExportHTML(r models.Report, path string) error {
	return renderDashboard(r, path)
}

func (*ReportExporter) ExportPDF(r models.Report, path string) error {
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetTitle("Security Analysis Report", false)
	pdf.AddPage()
	pdf.SetFont("Arial", "B", 20)
	pdf.Cell(0, 12, "Security Analysis Report")
	pdf.Ln(16)
	pdf.SetFont("Arial", "", 10)
	pdf.MultiCell(0, 6, fmt.Sprintf("Target: %s\nLanguages: %s\nGenerated: %s\nTotal: %d | Critical: %d | High: %d", r.TargetPath, r.Language, r.Timestamp.Format("2006-01-02 15:04 UTC"), r.TotalFindings, r.CriticalCount, r.HighCount), "", "L", false)
	if r.BusinessReport != nil {
		s := r.BusinessReport.ExecutiveSummary
		pdf.Ln(5)
		pdf.SetFont("Arial", "B", 14)
		pdf.Cell(0, 8, "Executive Summary")
		pdf.Ln(9)
		pdf.SetFont("Arial", "", 10)
		pdf.MultiCell(0, 6, fmt.Sprintf("Overall business risk: %s (%.0f/100)\n%s\n%s\nUrgency: %s", s.OverallRiskLevel, s.OverallRiskScore, s.BriefDescription, s.BusinessImpactSummary, s.Urgency), "1", "L", false)
		pdf.Ln(6)
		pdf.SetFont("Arial", "B", 14)
		pdf.Cell(0, 8, "Top Business Priorities")
		pdf.Ln(9)
		limit := 5
		if len(r.BusinessReport.Findings) < limit {
			limit = len(r.BusinessReport.Findings)
		}
		for _, business := range r.BusinessReport.Findings[:limit] {
			pdf.SetFont("Arial", "B", 10)
			pdf.MultiCell(0, 5, fmt.Sprintf("Priority %d - %s", business.PriorityScore, business.Explanation.SimpleTitle), "", "L", false)
			pdf.SetFont("Arial", "", 9)
			pdf.MultiCell(0, 5, fmt.Sprintf("%s\nEstimated exposure: %s to %s\nFix summary: %s", business.Explanation.WhyDangerous, formatIDR(business.Impact.RevenueRiskMin), formatIDR(business.Impact.RevenueRiskMax), business.Explanation.FixSummary), "1", "L", false)
		}
		pdf.AddPage()
		pdf.SetFont("Arial", "B", 16)
		pdf.Cell(0, 10, "Remediation Roadmap")
		pdf.Ln(12)
		for _, phase := range r.BusinessReport.Roadmap.Phases {
			pdf.SetFont("Arial", "B", 11)
			pdf.Cell(0, 7, fmt.Sprintf("%s - %.1f hours", phase.Name, phase.TotalHours))
			pdf.Ln(8)
			pdf.SetFont("Arial", "", 9)
			for _, item := range phase.Items {
				pdf.MultiCell(0, 5, fmt.Sprintf("Priority %d: %s (%s)", item.Priority, item.Title, strings.Join(item.RequiredTeams, ", ")), "", "L", false)
			}
		}
	}
	for _, f := range r.Findings {
		pdf.Ln(5)
		pdf.SetFont("Arial", "B", 11)
		pdf.MultiCell(0, 6, fmt.Sprintf("[%s] %s", strings.ToUpper(string(f.Severity)), f.Title), "", "L", false)
		pdf.SetFont("Arial", "", 9)
		pdf.MultiCell(0, 5, fmt.Sprintf("%s:%d | %s | CVSS %.1f\n%s\nRemediation: %s", f.FilePath, f.LineNumber, f.CWE, f.CVSSBase, f.Description, f.Remediation), "1", "L", false)
	}
	if e := ensureDir(path); e != nil {
		return e
	}
	return pdf.OutputFileAndClose(path)
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
	doc := map[string]any{"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": []any{run}}
	b, e := json.MarshalIndent(doc, "", "  ")
	if e != nil {
		return e
	}
	return write(path, b)
}

type xmlReport struct {
	XMLName   xml.Name     `xml:"securityReport"`
	Timestamp string       `xml:"timestamp"`
	Target    string       `xml:"target"`
	Languages string       `xml:"languages"`
	Total     int          `xml:"total"`
	Critical  int          `xml:"critical"`
	High      int          `xml:"high"`
	Findings  []xmlFinding `xml:"findings>finding"`
}
type xmlFinding struct {
	ID          string  `xml:"id,attr"`
	Title       string  `xml:"title"`
	Severity    string  `xml:"severity"`
	CWE         string  `xml:"cwe"`
	File        string  `xml:"file"`
	Description string  `xml:"description"`
	Remediation string  `xml:"remediation"`
	Line        int     `xml:"line"`
	CVSS        float64 `xml:"cvss"`
}

func (*ReportExporter) ExportXML(r models.Report, path string) error {
	x := xmlReport{Timestamp: r.Timestamp.Format(time.RFC3339), Target: r.TargetPath, Languages: r.Language, Total: r.TotalFindings, Critical: r.CriticalCount, High: r.HighCount}
	for _, f := range r.Findings {
		x.Findings = append(x.Findings, xmlFinding{ID: f.ID, Title: f.Title, Severity: string(f.Severity), CWE: f.CWE, File: f.FilePath, Description: f.Description, Remediation: f.Remediation, Line: f.LineNumber, CVSS: f.CVSSBase})
	}
	b, e := xml.MarshalIndent(x, "", "  ")
	if e != nil {
		return e
	}
	return write(path, append([]byte(xml.Header), b...))
}
func (*ReportExporter) ExportCSV(r models.Report, path string) error {
	if e := ensureDir(path); e != nil {
		return e
	}
	f, e := os.Create(path)
	if e != nil {
		return e
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	if e = w.Write([]string{"ID", "Title", "Severity", "Language", "CWE", "CVSS", "File", "Line", "Remediation"}); e != nil {
		return e
	}
	for _, v := range r.Findings {
		if e = w.Write([]string{v.ID, v.Title, string(v.Severity), v.Language, v.CWE, strconv.FormatFloat(v.CVSSBase, 'f', 1, 64), v.FilePath, strconv.Itoa(v.LineNumber), v.Remediation}); e != nil {
			return e
		}
	}
	return w.Error()
}
func write(path string, b []byte) error {
	if e := ensureDir(path); e != nil {
		return e
	}
	return os.WriteFile(path, b, 0600)
}
func ensureDir(path string) error {
	dir := filepath.Dir(path)
	if dir == "." || dir == "" {
		return nil
	}
	return os.MkdirAll(dir, 0750)
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
