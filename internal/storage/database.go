package storage

import (
	"context"
	"crypto/rand"
	"database/sql"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/example/sast-dast-analyzer/internal/models"
	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schema string

type Database interface {
	SaveReport(context.Context, models.Report) (string, error)
	GetReportByID(context.Context, string) (models.Report, error)
	GetReportHistory(context.Context, string, int) ([]models.Report, error)
	CompareReports(context.Context, string, string) (ComparisonResult, error)
	GetTrendAnalysis(context.Context, string, int) (TrendData, error)
	Close() error
}
type SQLiteDatabase struct{ db *sql.DB }
type ComparisonResult struct {
	BaseReportID    string           `json:"base_report_id"`
	CurrentReportID string           `json:"current_report_id"`
	NewFindings     []models.Finding `json:"new_findings,omitempty"`
	FixedFindings   []models.Finding `json:"fixed_findings,omitempty"`
	Regressions     []models.Finding `json:"regressions,omitempty"`
	SeverityTrend   map[string]int   `json:"severity_trend"`
}
type TrendPoint struct {
	Date     string `json:"date"`
	Critical int    `json:"critical"`
	High     int    `json:"high"`
	Medium   int    `json:"medium"`
	Resolved int    `json:"resolved"`
}
type TrendData struct {
	TargetPath string       `json:"target_path"`
	Points     []TrendPoint `json:"points"`
}

func OpenSQLite(path string) (*SQLiteDatabase, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	if _, err = db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	return &SQLiteDatabase{db}, nil
}
func (s *SQLiteDatabase) Close() error { return s.db.Close() }
func (s *SQLiteDatabase) SaveReport(ctx context.Context, r models.Report) (string, error) {
	if r.ID == "" {
		r.ID = newID()
	}
	b, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	resolved := s.resolvedSincePrevious(ctx, r)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO reports(id,timestamp,target_path,language,total_findings,critical_count,high_count,token_used,duration,report_json) VALUES(?,?,?,?,?,?,?,?,?,?)`, r.ID, r.Timestamp.Format(time.RFC3339Nano), r.TargetPath, r.Language, r.TotalFindings, r.CriticalCount, r.HighCount, r.TokenUsed, r.Duration, b)
	if err != nil {
		return "", err
	}
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO findings(id,report_id,title,severity,cwe,file_path,line,ai_confidence,is_zero_day) VALUES(?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return "", err
	}
	defer stmt.Close()
	for _, f := range r.Findings {
		if _, err = stmt.ExecContext(ctx, f.ID, r.ID, f.Title, f.Severity, f.CWE, f.FilePath, f.LineNumber, f.AIConfidence, f.IsZeroDay); err != nil {
			return "", err
		}
	}
	counts := severityCounts(r.Findings)
	_, err = tx.ExecContext(ctx, `INSERT INTO trend_analysis(target_path,date,critical_count,high_count,medium_count,resolved_count) VALUES(?,?,?,?,?,?) ON CONFLICT(target_path,date) DO UPDATE SET critical_count=excluded.critical_count,high_count=excluded.high_count,medium_count=excluded.medium_count,resolved_count=excluded.resolved_count`, r.TargetPath, r.Timestamp.Format("2006-01-02"), counts["critical"], counts["high"], counts["medium"], resolved)
	if err != nil {
		return "", err
	}
	if err = tx.Commit(); err != nil {
		return "", err
	}
	return r.ID, nil
}
func (s *SQLiteDatabase) resolvedSincePrevious(ctx context.Context, current models.Report) int {
	var b []byte
	if err := s.db.QueryRowContext(ctx, `SELECT report_json FROM reports WHERE target_path=? ORDER BY timestamp DESC LIMIT 1`, current.TargetPath).Scan(&b); err != nil {
		return 0
	}
	var previous models.Report
	if json.Unmarshal(b, &previous) != nil {
		return 0
	}
	now := byID(current.Findings)
	resolved := 0
	for id := range byID(previous.Findings) {
		if _, ok := now[id]; !ok {
			resolved++
		}
	}
	return resolved
}
func (s *SQLiteDatabase) PruneOlderThan(ctx context.Context, days int) error {
	if days <= 0 {
		return nil
	}
	cutoff := time.Now().UTC().AddDate(0, 0, -days).Format(time.RFC3339Nano)
	_, err := s.db.ExecContext(ctx, `DELETE FROM reports WHERE timestamp < ?`, cutoff)
	return err
}
func (s *SQLiteDatabase) GetReportByID(ctx context.Context, id string) (models.Report, error) {
	var b []byte
	if err := s.db.QueryRowContext(ctx, `SELECT report_json FROM reports WHERE id=?`, id).Scan(&b); err != nil {
		return models.Report{}, err
	}
	var r models.Report
	return r, json.Unmarshal(b, &r)
}
func (s *SQLiteDatabase) GetReportHistory(ctx context.Context, target string, limit int) ([]models.Report, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := s.db.QueryContext(ctx, `SELECT report_json FROM reports WHERE target_path=? ORDER BY timestamp DESC LIMIT ?`, target, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.Report
	for rows.Next() {
		var b []byte
		if err = rows.Scan(&b); err != nil {
			return nil, err
		}
		var r models.Report
		if err = json.Unmarshal(b, &r); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
func (s *SQLiteDatabase) CompareReports(ctx context.Context, baseID, currentID string) (ComparisonResult, error) {
	a, e := s.GetReportByID(ctx, baseID)
	if e != nil {
		return ComparisonResult{}, e
	}
	b, e := s.GetReportByID(ctx, currentID)
	if e != nil {
		return ComparisonResult{}, e
	}
	out := ComparisonResult{BaseReportID: baseID, CurrentReportID: currentID, SeverityTrend: map[string]int{}}
	am, bm := byID(a.Findings), byID(b.Findings)
	for id, f := range bm {
		old, ok := am[id]
		if !ok {
			out.NewFindings = append(out.NewFindings, f)
		} else if severityValue(f.Severity) > severityValue(old.Severity) {
			out.Regressions = append(out.Regressions, f)
		}
	}
	for id, f := range am {
		if _, ok := bm[id]; !ok {
			out.FixedFindings = append(out.FixedFindings, f)
		}
	}
	ac, bc := severityCounts(a.Findings), severityCounts(b.Findings)
	for _, v := range []string{"critical", "high", "medium", "low"} {
		out.SeverityTrend[v] = bc[v] - ac[v]
	}
	return out, nil
}
func (s *SQLiteDatabase) GetTrendAnalysis(ctx context.Context, target string, days int) (TrendData, error) {
	if days <= 0 {
		days = 30
	}
	rows, err := s.db.QueryContext(ctx, `SELECT date,critical_count,high_count,medium_count,resolved_count FROM trend_analysis WHERE target_path=? AND date>=date('now',?) ORDER BY date`, target, fmt.Sprintf("-%d days", days))
	if err != nil {
		return TrendData{}, err
	}
	defer rows.Close()
	out := TrendData{TargetPath: target}
	for rows.Next() {
		var p TrendPoint
		if err = rows.Scan(&p.Date, &p.Critical, &p.High, &p.Medium, &p.Resolved); err != nil {
			return out, err
		}
		out.Points = append(out.Points, p)
	}
	return out, rows.Err()
}
func newID() string {
	b := make([]byte, 16)
	if _, e := rand.Read(b); e != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}
func byID(v []models.Finding) map[string]models.Finding {
	m := map[string]models.Finding{}
	for _, f := range v {
		m[f.ID] = f
	}
	return m
}
func severityCounts(v []models.Finding) map[string]int {
	m := map[string]int{}
	for _, f := range v {
		m[string(f.Severity)]++
	}
	return m
}
func severityValue(s models.Severity) int {
	switch s {
	case models.SeverityCritical:
		return 4
	case models.SeverityHigh:
		return 3
	case models.SeverityMedium:
		return 2
	default:
		return 1
	}
}
