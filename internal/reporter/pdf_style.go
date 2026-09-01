package reporter

import (
	"fmt"
	"strings"

	"github.com/example/sast-dast-analyzer/internal/models"
	"github.com/go-pdf/fpdf"
)

// Shared visual language for every PDF export (the main scan report and the
// bug-bounty bundle), so both look like the same product instead of two
// unrelated prototypes: a repeated page header/footer with page numbers, one
// severity color scale used consistently, section headers with a rule
// instead of ad-hoc boxed MultiCells, and a monospace block for code
// snippets. See internal/reporter/exporter.go and bounty_export.go for the
// call sites.

const (
	pdfMarginLeft  = 10.0
	pdfMarginRight = 200.0
)

type rgb struct{ r, g, b int }

var (
	colorInk    = rgb{23, 32, 51}    // body text
	colorMuted  = rgb{100, 116, 139} // meta text, captions
	colorRule   = rgb{226, 232, 240} // divider lines
	colorAccent = rgb{37, 99, 235}   // section headers
	colorCode   = rgb{245, 247, 250} // code snippet background

	severityColors = map[models.Severity]rgb{
		models.SeverityCritical: {185, 28, 28},
		models.SeverityHigh:     {194, 65, 12},
		models.SeverityMedium:   {161, 98, 7},
		models.SeverityLow:      {30, 64, 175},
	}
)

func severityColor(s models.Severity) rgb {
	if c, ok := severityColors[s]; ok {
		return c
	}
	return colorMuted
}

func setTextColor(pdf *fpdf.Fpdf, c rgb) { pdf.SetTextColor(c.r, c.g, c.b) }

// newStyledPDF returns a fresh document with a repeated header (the report
// title) and footer (page N of total, plus a standing disclaimer) already
// wired up.
func newStyledPDF(title string) *fpdf.Fpdf {
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetTitle(title, false)
	pdf.SetAutoPageBreak(true, 22)
	pdf.SetHeaderFunc(func() {
		pdf.SetFont("Arial", "", 8)
		setTextColor(pdf, colorMuted)
		pdf.SetY(8)
		pdf.CellFormat(0, 5, title, "", 1, "L", false, 0, "")
		pdf.SetDrawColor(colorRule.r, colorRule.g, colorRule.b)
		pdf.Line(pdfMarginLeft, 14, pdfMarginRight, 14)
		pdf.SetY(18)
		setTextColor(pdf, colorInk)
	})
	pdf.SetFooterFunc(func() {
		pdf.SetY(-15)
		pdf.SetFont("Arial", "I", 8)
		setTextColor(pdf, colorMuted)
		pdf.CellFormat(0, 10, fmt.Sprintf("Page %d of {nb} - generated output; verify findings before acting on them", pdf.PageNo()), "", 0, "C", false, 0, "")
	})
	pdf.AliasNbPages("{nb}")
	setTextColor(pdf, colorInk)
	return pdf
}

// sectionHeader draws a small colored heading with a rule underneath, and
// leaves the cursor ready for body text below it.
func sectionHeader(pdf *fpdf.Fpdf, text string) {
	pdf.Ln(4)
	pdf.SetFont("Arial", "B", 13)
	setTextColor(pdf, colorAccent)
	pdf.CellFormat(0, 8, text, "", 1, "L", false, 0, "")
	y := pdf.GetY()
	pdf.SetDrawColor(colorAccent.r, colorAccent.g, colorAccent.b)
	pdf.SetLineWidth(0.6)
	pdf.Line(pdfMarginLeft, y, pdfMarginRight, y)
	pdf.SetLineWidth(0.2)
	pdf.Ln(4)
	setTextColor(pdf, colorInk)
}

// metaRow renders a "Label   value" line — used instead of cramming several
// facts into one \n-joined MultiCell, which is hard to scan.
func metaRow(pdf *fpdf.Fpdf, label, value string) {
	if value == "" {
		return
	}
	pdf.SetFont("Arial", "B", 9)
	setTextColor(pdf, colorMuted)
	pdf.CellFormat(32, 6, label, "", 0, "L", false, 0, "")
	pdf.SetFont("Arial", "", 9)
	setTextColor(pdf, colorInk)
	pdf.MultiCell(0, 6, value, "", "L", false)
}

// severityBadge draws a small filled, colored pill with the severity label
// in it, matching the color scale used across the HTML/dashboard reports.
func severityBadge(pdf *fpdf.Fpdf, s models.Severity) {
	c := severityColor(s)
	pdf.SetFillColor(c.r, c.g, c.b)
	pdf.SetTextColor(255, 255, 255)
	pdf.SetFont("Arial", "B", 8)
	label := " " + strings.ToUpper(string(s)) + " "
	w := pdf.GetStringWidth(label) + 4
	pdf.CellFormat(w, 5.5, label, "", 0, "L", true, 0, "")
	setTextColor(pdf, colorInk)
}

// divider draws a thin, light horizontal rule to separate list items —
// replaces the full boxed borders the original renderer drew around every
// paragraph, which read as debug output rather than a design choice.
func divider(pdf *fpdf.Fpdf) {
	y := pdf.GetY() + 1
	pdf.SetDrawColor(colorRule.r, colorRule.g, colorRule.b)
	pdf.Line(pdfMarginLeft, y, pdfMarginRight, y)
	pdf.SetY(y + 3)
}

// codeBlock renders a monospace, lightly shaded block for a source snippet.
func codeBlock(pdf *fpdf.Fpdf, snippet string) {
	if strings.TrimSpace(snippet) == "" {
		return
	}
	pdf.SetFont("Courier", "", 8)
	pdf.SetFillColor(colorCode.r, colorCode.g, colorCode.b)
	pdf.MultiCell(0, 4.5, snippet, "", "L", true)
	pdf.SetFont("Arial", "", 9)
}

func severityCounts(findings []models.Finding) map[models.Severity]int {
	counts := map[models.Severity]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}
	return counts
}

// findingCard renders one finding as a self-contained block: severity badge
// + CVSS, title, file/CWE/tool meta line, description, code snippet (when
// present — the previous renderer silently dropped it), and remediation,
// closed off with a divider instead of a full box border.
func findingCard(pdf *fpdf.Fpdf, f models.Finding) {
	severityBadge(pdf, f.Severity)
	pdf.SetFont("Arial", "", 9)
	setTextColor(pdf, colorMuted)
	pdf.CellFormat(0, 5.5, fmt.Sprintf("  CVSS %.1f", f.CVSSBase), "", 1, "L", false, 0, "")

	setTextColor(pdf, colorInk)
	pdf.SetFont("Arial", "B", 11)
	pdf.MultiCell(0, 6, f.Title, "", "L", false)

	meta := fmt.Sprintf("%s:%d", f.FilePath, f.LineNumber)
	if f.CWE != "" {
		meta += "  |  " + f.CWE
	}
	if f.SourceTool != "" {
		meta += "  |  " + f.SourceTool
	}
	pdf.SetFont("Arial", "", 8)
	setTextColor(pdf, colorMuted)
	pdf.MultiCell(0, 5, meta, "", "L", false)
	setTextColor(pdf, colorInk)

	if f.Description != "" {
		pdf.SetFont("Arial", "", 9)
		pdf.Ln(1)
		pdf.MultiCell(0, 5, f.Description, "", "L", false)
	}
	if f.CodeSnippet != "" {
		pdf.Ln(1)
		codeBlock(pdf, f.CodeSnippet)
	}
	if f.Remediation != "" {
		pdf.Ln(1)
		pdf.SetFont("Arial", "B", 9)
		pdf.CellFormat(12, 5, "Fix:", "", 0, "L", false, 0, "")
		pdf.SetFont("Arial", "", 9)
		pdf.MultiCell(0, 5, f.Remediation, "", "L", false)
	}
	pdf.Ln(2)
	divider(pdf)
}
