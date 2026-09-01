package reporter

import (
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strings"

	"github.com/example/sast-dast-analyzer/internal/models"
)

func (*ReportExporter) ExportBountyBundle(r models.Report, jsonPath string) error {
	if r.BountyBundle == nil {
		return fmt.Errorf("bug bounty reporting is not enabled")
	}
	raw, err := json.MarshalIndent(r.BountyBundle, "", "  ")
	if err != nil {
		return err
	}
	if err = write(jsonPath, raw); err != nil {
		return err
	}
	base := strings.TrimSuffix(jsonPath, filepath.Ext(jsonPath))
	md := formatBountyBundle(*r.BountyBundle)
	if err = write(base+".md", []byte(md)); err != nil {
		return err
	}
	if err = write(base+".txt", []byte(strings.ReplaceAll(md, "#", ""))); err != nil {
		return err
	}
	if err = exportBountyHTML(*r.BountyBundle, base+".html"); err != nil {
		return err
	}
	return exportBountyPDF(*r.BountyBundle, base+".pdf")
}
func formatBountyBundle(b models.BountyBundle) string {
	var out strings.Builder
	fmt.Fprintf(&out, "# Bug Bounty Submission Bundle\n\nTarget: `%s`  \nScanner findings reviewed: %d  \nReady: %d  \nBlocked drafts: %d  \nExcluded: %d\n\n", b.Target, b.InputCount, b.ReadyCount, b.BlockedCount, len(b.Excluded))
	if len(b.Reports) == 0 {
		out.WriteString("## No eligible bounty candidates\n\nNo finding passed the evidence, classification, ownership, and severity gates. Review the exclusions below and collect runtime evidence before submission.\n\n")
	}
	if len(b.Excluded) > 0 {
		out.WriteString("## Excluded findings\n\n")
		for _, x := range b.Excluded {
			fmt.Fprintf(&out, "- **%s** (`%s`): %s\n", x.Title, x.SourceTool, x.Reason)
		}
		out.WriteString("\n")
	}
	for _, r := range b.Reports {
		out.WriteString("---\n\n" + r.SubmissionTemplate + "\n")
	}
	return out.String()
}

var bountyHTML = template.Must(template.New("bounty").Parse(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Bug Bounty Submission Bundle</title><style>body{font:14px system-ui;background:#f2f5f9;color:#172033;margin:0}main{max-width:1000px;margin:auto;padding:28px}.card{background:white;padding:22px;margin:16px 0;border-radius:12px;box-shadow:0 4px 18px #0001}.blocked{border-left:6px solid #b4233d}.ready{border-left:6px solid #17815f}.excluded{border-left:6px solid #d49a18}.empty{border-left:6px solid #3977b8}.pill{padding:4px 9px;border-radius:99px;background:#e5ebf3;font-weight:700}pre{white-space:pre-wrap;background:#101828;color:#d7e3f4;padding:15px;border-radius:8px;overflow:auto}.notice{background:#fff0d4;padding:14px;border-radius:8px}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:10px;border-bottom:1px solid #e4e8ee;vertical-align:top}li{margin:8px 0}</style></head><body><main><h1>Bug Bounty Submission Bundle</h1><p>{{.Target}} · {{.InputCount}} reviewed · {{.ReadyCount}} ready · {{.BlockedCount}} blocked · {{len .Excluded}} excluded</p><div class="notice">Generated reports require human verification. Never submit static scanner output as a confirmed vulnerability without reproducible evidence and confirmed program scope.</div>{{if not .Reports}}<section class="card empty"><h2>No eligible bounty candidates</h2><p>No finding passed the evidence, classification, ownership, and severity gates. The scan did not fail; review the reasons below and collect runtime evidence before submission.</p></section>{{end}}{{if .Excluded}}<section class="card excluded"><h2>Excluded findings</h2><table><tr><th>Finding</th><th>Source</th><th>Reason</th></tr>{{range .Excluded}}<tr><td><b>{{.Title}}</b><br><small>{{.FilePath}}</small></td><td>{{.SourceTool}}</td><td>{{.Reason}}</td></tr>{{end}}</table></section>{{end}}{{range .Reports}}<article class="card {{if .ReadyToSubmit}}ready{{else}}blocked{{end}}"><span class="pill">{{.Platform}}</span> <span class="pill">{{.Severity}}</span><h2>{{.Title}}</h2><p><b>Status:</b> {{if .ReadyToSubmit}}Ready after final human review{{else}}Draft — blocked{{end}}</p>{{if .BlockingReasons}}<ul>{{range .BlockingReasons}}<li>{{.}}</li>{{end}}</ul>{{end}}<p><b>Endpoint:</b> {{.AffectedEndpoint}}</p><h3>Description</h3><p>{{.Description}}</p><h3>Steps to reproduce</h3><ol>{{range .StepsToReproduce}}<li>{{.Description}}<br><small>Expected: {{.ExpectedResult}}</small>{{if .Command}}<pre>{{.Command}}</pre>{{end}}</li>{{end}}</ol><h3>Safe POC</h3><pre>{{.ProofOfConcept.Curl}}</pre><h3>Impact</h3><p>{{.Impact.SecurityImpact}}</p><p>{{.Impact.BusinessImpact}}</p><h3>Remediation</h3><ul>{{range .Remediation}}<li>{{.}}</li>{{end}}</ul></article>{{end}}</main></body></html>`))

func exportBountyHTML(b models.BountyBundle, path string) error {
	if err := ensureDir(path); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return bountyHTML.Execute(f, b)
}
func exportBountyPDF(b models.BountyBundle, path string) error {
	pdf := newStyledPDF("Bug Bounty Submission Bundle")
	pdf.AddPage()
	pdf.SetFont("Arial", "B", 18)
	pdf.CellFormat(0, 10, "Bug Bounty Submission Bundle", "", 1, "L", false, 0, "")
	pdf.Ln(2)
	metaRow(pdf, "Target", b.Target)
	metaRow(pdf, "Reviewed", fmt.Sprintf("%d", b.InputCount))
	metaRow(pdf, "Ready", fmt.Sprintf("%d", b.ReadyCount))
	metaRow(pdf, "Blocked drafts", fmt.Sprintf("%d", b.BlockedCount))
	metaRow(pdf, "Excluded", fmt.Sprintf("%d", len(b.Excluded)))

	if len(b.Reports) == 0 {
		sectionHeader(pdf, "No eligible bounty candidates")
		pdf.SetFont("Arial", "", 9)
		pdf.MultiCell(0, 5, "No finding passed the evidence, classification, ownership, and severity gates. Review the exclusions below and collect runtime evidence before submission.", "", "L", false)
	}

	if len(b.Excluded) > 0 {
		sectionHeader(pdf, "Excluded findings")
		for _, x := range b.Excluded {
			pdf.SetFont("Arial", "B", 9)
			pdf.MultiCell(0, 5, x.Title, "", "L", false)
			pdf.SetFont("Arial", "", 8)
			setTextColor(pdf, colorMuted)
			pdf.MultiCell(0, 4.5, x.SourceTool+" - "+x.Reason, "", "L", false)
			setTextColor(pdf, colorInk)
			pdf.Ln(1)
			divider(pdf)
		}
	}

	for _, r := range b.Reports {
		pdf.AddPage()
		severityBadge(pdf, models.Severity(strings.ToLower(r.Severity)))
		pdf.SetFont("Arial", "", 9)
		setTextColor(pdf, colorMuted)
		status := "Draft - blocked"
		if r.ReadyToSubmit {
			status = "Ready after final human review"
		}
		pdf.CellFormat(0, 5.5, "  "+r.Platform+"  |  "+status, "", 1, "L", false, 0, "")
		setTextColor(pdf, colorInk)
		pdf.SetFont("Arial", "B", 14)
		pdf.MultiCell(0, 7, r.Title, "", "L", false)

		metaRow(pdf, "Endpoint", r.AffectedEndpoint)
		metaRow(pdf, "Scope", r.Scope.Status+" - "+r.Scope.Reason)

		if len(r.BlockingReasons) > 0 {
			sectionHeader(pdf, "Blocking reasons")
			pdf.SetFont("Arial", "", 9)
			for _, reason := range r.BlockingReasons {
				pdf.MultiCell(0, 5, "- "+reason, "", "L", false)
			}
		}

		sectionHeader(pdf, "Description")
		pdf.SetFont("Arial", "", 9)
		pdf.MultiCell(0, 5, r.Description, "", "L", false)

		sectionHeader(pdf, "Impact")
		pdf.SetFont("Arial", "", 9)
		pdf.MultiCell(0, 5, r.Impact.SecurityImpact, "", "L", false)

		sectionHeader(pdf, "Remediation")
		pdf.SetFont("Arial", "", 9)
		for _, fix := range r.Remediation {
			pdf.MultiCell(0, 5, "- "+fix, "", "L", false)
		}
	}

	if err := ensureDir(path); err != nil {
		return err
	}
	return pdf.OutputFileAndClose(path)
}
