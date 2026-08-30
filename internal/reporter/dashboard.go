package reporter

import (
	"fmt"
	"html/template"
	"os"
	"sort"

	"github.com/example/sast-dast-analyzer/internal/models"
)

type dashboardFinding struct {
	Technical   models.Finding
	Business    models.BusinessFinding
	HasBusiness bool
}
type dashboardView struct {
	Report     models.Report
	Findings   []dashboardFinding
	Top        []dashboardFinding
	Pie        string
	MaxRevenue string
}

var dashboardTemplate = template.Must(template.New("dashboard").Funcs(template.FuncMap{
	"idr": formatIDR, "class": safeClass,
	"slice": func(values ...string) []string { return values },
	"matrixCount": func(m map[string]map[string]int, s, i string) int {
		if m[s] == nil {
			return 0
		}
		return m[s][i]
	},
	"heat": func(s, i string) string {
		if (s == "critical" && i == "critical") || (s == "high" && i == "high") {
			return "hot"
		}
		if s == "critical" || i == "critical" || s == "high" || i == "high" {
			return "warm"
		}
		return ""
	},
}).Parse(`<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Business Security Report</title>
<style>
:root{--ink:#172033;--muted:#60708a;--bg:#f3f6fb;--card:#fff;--brand:#183b68;--accent:#23a6a6;--critical:#a61b36;--high:#d45b22;--medium:#d39b16;--low:#31856b}*{box-sizing:border-box}body{margin:0;font:14px Inter,Segoe UI,system-ui,sans-serif;background:var(--bg);color:var(--ink)}header{background:linear-gradient(125deg,#102b4e,#1e587b 70%,#238d91);color:white;padding:42px max(5vw,24px)}header h1{font-size:32px;margin:0 0 8px}.wrap{max-width:1240px;margin:auto;padding:24px}.tabs{display:flex;gap:8px;flex-wrap:wrap;margin:-20px 0 20px}.tab{border:0;border-radius:99px;padding:10px 16px;background:#dfe7f1;color:#29415f;cursor:pointer;font-weight:700}.tab.active{background:var(--brand);color:#fff}.panel{display:none}.panel.active{display:block}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:15px}.card{background:var(--card);border-radius:14px;padding:20px;margin-bottom:16px;box-shadow:0 7px 24px #183b6812;border:1px solid #e8edf4}.metric b{font-size:27px;display:block;margin-top:7px}.eyebrow{text-transform:uppercase;letter-spacing:.08em;color:var(--muted);font-size:11px;font-weight:800}.risk{display:inline-block;border-radius:99px;padding:5px 10px;color:#fff;font-weight:800}.risk.critical{background:var(--critical)}.risk.high{background:var(--high)}.risk.medium{background:var(--medium)}.risk.low{background:var(--low)}.split{display:grid;grid-template-columns:minmax(220px,.7fr) 2fr;gap:18px}.pie{width:180px;height:180px;border-radius:50%;margin:auto;background:conic-gradient({{.Pie}});position:relative}.pie:after{content:"{{.Report.TotalFindings}} findings";position:absolute;inset:28px;border-radius:50%;background:white;display:grid;place-items:center;font-weight:800;text-align:center}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:11px 9px;border-bottom:1px solid #e7ebf1;vertical-align:top}th{color:var(--muted);font-size:12px}.priority{font-size:18px;font-weight:900}.timeline{border-left:4px solid #b9d3dd;margin-left:10px;padding-left:22px}.phase{position:relative}.phase:before{content:"";position:absolute;width:14px;height:14px;border-radius:50%;background:var(--accent);left:-31px;top:5px}.finding h3{margin-bottom:6px}.plain{background:#edf7f6;border-left:4px solid var(--accent);padding:13px}.poc{background:#fff9e8;border-left:4px solid #d5a226;padding:14px}.notice{background:#fdebed;color:#7d1930;padding:12px;border-radius:8px}.matrix{display:grid;grid-template-columns:90px repeat(4,1fr);gap:5px}.cell{padding:14px 7px;text-align:center;border-radius:7px;background:#e8eef5}.cell.hot{background:#f6c9ce}.cell.warm{background:#f9dfb5}.bar{height:12px;border-radius:9px;background:#dce5ef;overflow:hidden}.bar span{display:block;height:100%;background:linear-gradient(90deg,var(--accent),var(--high))}code{white-space:pre-wrap;word-break:break-word}small,.muted{color:var(--muted)}@media(max-width:720px){.split{grid-template-columns:1fr}table{display:block;overflow:auto}}@media print{.tabs{display:none}.panel{display:block!important;page-break-before:always}.panel:first-of-type{page-break-before:auto}.card{box-shadow:none}header{padding:25px}.wrap{max-width:none}}
</style></head><body><header><div class="eyebrow" style="color:#bce4e3">Management Security Assessment</div><h1>{{.Report.TargetPath}}</h1><div>{{.Report.Language}} · {{.Report.Timestamp.Format "02 Jan 2006 15:04 UTC"}}</div></header><main class="wrap">
<nav class="tabs"><button class="tab active" data-tab="executive">Executive</button><button class="tab" data-tab="business">Business Risk</button><button class="tab" data-tab="poc">Validation POC</button><button class="tab" data-tab="roadmap">Roadmap</button><button class="tab" data-tab="technical">Technical</button></nav>
<section id="executive" class="panel active">{{if .Report.BusinessReport}}{{$s:=.Report.BusinessReport.ExecutiveSummary}}<div class="grid"><div class="card metric"><span class="eyebrow">Overall risk</span><b><span class="risk {{class $s.OverallRiskLevel}}">{{$s.OverallRiskLevel}}</span></b><small>{{printf "%.0f" $s.OverallRiskScore}} / 100</small></div><div class="card metric"><span class="eyebrow">Scenario exposure</span><b>{{idr $s.TotalRevenueRiskIDR}}</b><small>Estimated upper-bound; not predicted loss</small></div><div class="card metric"><span class="eyebrow">People potentially affected</span><b>{{$s.TotalAffectedUsers}}</b></div><div class="card metric"><span class="eyebrow">Average fix effort</span><b>{{printf "%.1f" $s.AverageFixHours}}h</b></div></div><div class="card"><h2>Executive summary</h2><p>{{$s.BriefDescription}}</p><p>{{$s.BusinessImpactSummary}}</p><p><strong>Recommended urgency:</strong> {{$s.Urgency}}</p></div>{{end}}<div class="split"><div class="card"><h2>Finding distribution</h2><div class="pie"></div><p class="muted">Distribution reflects scanner results, not confirmed incidents.</p></div><div class="card"><h2>Top priorities</h2><table><tr><th>Priority</th><th>Business explanation</th><th>Exposure</th></tr>{{range .Top}}<tr><td class="priority">#{{.Business.PriorityScore}}</td><td><b>{{.Business.Explanation.SimpleTitle}}</b><br><small>{{.Business.Explanation.WhyDangerous}}</small></td><td>{{idr .Business.Impact.RevenueRiskMax}}</td></tr>{{end}}</table></div></div></section>
<section id="business" class="panel"><div class="card"><h2>Risk prioritization matrix</h2><p>Rows represent technical severity; columns represent business impact. Numbers are finding counts.</p><div class="matrix"><div></div><b>Low</b><b>Medium</b><b>High</b><b>Critical</b>{{range $sev:=slice "critical" "high" "medium" "low"}}<b>{{$sev}}</b>{{range $impact:=slice "low" "medium" "high" "critical"}}{{$n:=matrixCount $.Report.BusinessReport.RiskMatrix $sev $impact}}<div class="cell {{heat $sev $impact}}">{{$n}}</div>{{end}}{{end}}</div></div>{{range .Findings}}{{if .HasBusiness}}<article class="card finding"><span class="risk {{class .Business.Impact.Level}}">{{.Business.Impact.Level}}</span> <b>Priority {{.Business.PriorityScore}} · {{.Business.PriorityLabel}}</b><h3>{{.Business.Explanation.SimpleTitle}}</h3><div class="plain"><b>What happened</b><p>{{.Business.Explanation.WhatHappened}}</p><b>Business relevance</b><p>{{.Business.Explanation.BusinessExample}}</p><b>Plain-language fix</b><p>{{.Business.Explanation.FixSummary}}</p></div>{{range .Business.Processes}}<p><b>Affected process:</b> {{.Name}} — {{.ImpactNarrative}}</p>{{end}}<p><b>Estimated exposure:</b> {{idr .Business.Impact.RevenueRiskMin}} – {{idr .Business.Impact.RevenueRiskMax}} · <b>Downtime scenario:</b> {{.Business.Impact.OperationalDowntime}}h</p><small>{{.Business.Impact.Disclaimer}}</small></article>{{end}}{{end}}</section>
<section id="poc" class="panel"><div class="notice"><b>Authorized validation only.</b> These procedures are intentionally non-destructive. Use staging/local environments and sanitized test data.</div>{{range .Findings}}{{if .Business.POC}}<article class="card"><h2>{{.Business.POC.Title}}</h2><p>{{.Business.POC.Description}}</p><p><b>Skill/time:</b> {{.Business.POC.SkillLevel}} · {{.Business.POC.EstimatedMinutes}} minutes</p><div class="poc"><ol>{{range .Business.POC.StepByStep}}<li>{{.}}</li>{{end}}</ol><b>Expected safe result:</b> {{.Business.POC.ExpectedResult}}{{if .Business.POC.CurlExample}}<pre><code>{{.Business.POC.CurlExample}}</code></pre>{{end}}</div><small>{{.Business.POC.SafetyNotice}}</small></article>{{end}}{{end}}</section>
<section id="roadmap" class="panel"><div class="card"><h2>Remediation timeline</h2><div class="timeline">{{range .Report.BusinessReport.Roadmap.Phases}}<div class="phase"><h3>{{.Name}} <small>deadline: {{.DeadlineDays}} days · {{.TotalHours}} hours</small></h3>{{if .Items}}<table><tr><th>Priority</th><th>Finding</th><th>Owner / effort</th><th>Verification</th></tr>{{range .Items}}<tr><td>#{{.Priority}}</td><td>{{.Title}}</td><td>{{range .RequiredTeams}}{{.}} · {{end}}{{.EffortHours}}h</td><td>{{.TestingPlan}}</td></tr>{{end}}</table>{{else}}<p class="muted">No findings assigned.</p>{{end}}</div>{{end}}</div></div></section>
<section id="technical" class="panel"><div class="card"><h2>Detailed technical findings</h2><table><tr><th>Severity</th><th>Finding</th><th>Location</th><th>CWE / CVSS</th></tr>{{range .Findings}}<tr><td><span class="risk {{class .Technical.Severity}}">{{.Technical.Severity}}</span></td><td><b>{{.Technical.Title}}</b><br>{{.Technical.Description}}<br><small>{{.Technical.Remediation}}</small></td><td>{{.Technical.FilePath}}:{{.Technical.LineNumber}}</td><td>{{.Technical.CWE}} / {{.Technical.CVSSBase}}</td></tr>{{end}}</table></div><div class="card"><h2>Appendix: terminology</h2><p><b>CVSS</b> estimates technical exploitability and impact on a 0–10 scale. It does not measure financial loss.</p><p><b>CWE</b> identifies the general software weakness category. <b>Priority</b> combines technical severity with scenario-based business impact.</p><p><b>Proof of concept</b> here means a controlled, non-destructive validation procedure—not an instruction to attack production.</p><p><b>Financial exposure</b> is a planning scenario based on configured business context and must not be treated as an accounting forecast.</p></div></section>
</main><script>document.querySelectorAll('.tab').forEach(b=>b.onclick=()=>{document.querySelectorAll('.tab,.panel').forEach(x=>x.classList.remove('active'));b.classList.add('active');document.getElementById(b.dataset.tab).classList.add('active')})</script></body></html>`))

func renderDashboard(r models.Report, path string) error {
	if err := ensureDir(path); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if r.BusinessReport == nil {
		r.BusinessReport = &models.BusinessReport{SeverityCounts: map[string]int{}, RiskMatrix: map[string]map[string]int{}}
	}
	view := dashboardView{Report: r}
	for _, finding := range r.Findings {
		b, ok := BusinessFindingFor(r.BusinessReport, finding.ID)
		view.Findings = append(view.Findings, dashboardFinding{Technical: finding, Business: b, HasBusiness: ok})
	}
	sort.SliceStable(view.Findings, func(i, j int) bool {
		return view.Findings[i].Business.PriorityScore < view.Findings[j].Business.PriorityScore
	})
	limit := 5
	if len(view.Findings) < limit {
		limit = len(view.Findings)
	}
	view.Top = view.Findings[:limit]
	counts := map[string]int{}
	for _, f := range r.Findings {
		counts[string(f.Severity)]++
	}
	total := len(r.Findings)
	if total == 0 {
		total = 1
	}
	c := float64(counts["critical"]) / float64(total) * 100
	h := c + float64(counts["high"])/float64(total)*100
	m := h + float64(counts["medium"])/float64(total)*100
	view.Pie = "var(--critical) 0 " + num(c) + "%,var(--high) " + num(c) + "% " + num(h) + "%,var(--medium) " + num(h) + "% " + num(m) + "%,var(--low) " + num(m) + "% 100%"
	return dashboardTemplate.Execute(f, view)
}
func num(v float64) string { return template.HTMLEscapeString(fmt.Sprintf("%.2f", v)) }
