package storage

import (
	"context"
	"crypto/rand"
	"database/sql"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
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
	// The legacy trend table has one row per target and day, without room
	// for distinct endpoint lists or authenticated scan profiles.
	if len(r.IncompleteChecks) == 0 && len(r.DASTEndpoints) <= 1 && r.DASTSession == "" &&
		(r.DASTTargetURL == "" || r.TargetPath == r.DASTTargetURL) {
		resolved, err := resolvedSincePrevious(ctx, tx, r)
		if err != nil {
			return "", err
		}
		counts := severityCounts(r.Findings)
		_, err = tx.ExecContext(ctx, `INSERT INTO trend_analysis(target_path,date,critical_count,high_count,medium_count,resolved_count) VALUES(?,?,?,?,?,?) ON CONFLICT(target_path,date) DO UPDATE SET critical_count=excluded.critical_count,high_count=excluded.high_count,medium_count=excluded.medium_count,resolved_count=excluded.resolved_count`, r.TargetPath, r.Timestamp.Format("2006-01-02"), counts["critical"], counts["high"], counts["medium"], resolved)
		if err != nil {
			return "", err
		}
	}
	if err = tx.Commit(); err != nil {
		return "", err
	}
	return r.ID, nil
}
func resolvedSincePrevious(ctx context.Context, tx *sql.Tx, current models.Report) (int, error) {
	var b []byte
	err := tx.QueryRowContext(ctx, `SELECT report_json FROM reports WHERE target_path=? AND id<>?
		AND COALESCE(json_extract(CAST(report_json AS TEXT), '$.dast_target_url'), '')=?
		AND COALESCE(json_array_length(CAST(report_json AS TEXT), '$.dast_endpoints'), 0)<=1
		AND COALESCE(json_extract(CAST(report_json AS TEXT), '$.dast_session'), '')=''
		ORDER BY timestamp DESC, rowid DESC LIMIT 1`, current.TargetPath, current.ID, current.DASTTargetURL).Scan(&b)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	var previous models.Report
	if err := json.Unmarshal(b, &previous); err != nil {
		return 0, err
	}
	if len(previous.IncompleteChecks) > 0 || legacyDASTCookies(previous) {
		return 0, nil
	}
	now := byID(current.Findings)
	resolved := 0
	for id := range byID(previous.Findings) {
		if _, ok := now[id]; !ok {
			resolved++
		}
	}
	return resolved, nil
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
	if a.TargetPath != b.TargetPath || a.DASTTargetURL != b.DASTTargetURL {
		return ComparisonResult{}, errors.New("reports have different source or DAST targets")
	}
	if a.DASTSession != b.DASTSession || !maps.Equal(dastEndpointSet(a), dastEndpointSet(b)) {
		return ComparisonResult{}, errors.New("reports have different DAST endpoint lists or session modes")
	}
	if len(a.IncompleteChecks) > 0 || len(b.IncompleteChecks) > 0 {
		return ComparisonResult{}, errors.New("both reports must have completed scans for comparison")
	}
	if legacyDASTCookies(a) != legacyDASTCookies(b) && (len(a.DASTEndpoints) > 0 || len(b.DASTEndpoints) > 0) &&
		(len(a.DASTEndpoints) == 0 || len(b.DASTEndpoints) == 0) {
		return ComparisonResult{}, errors.New("baseline cookie findings use legacy IDs; establish a new DAST baseline")
	}
	out := ComparisonResult{BaseReportID: baseID, CurrentReportID: currentID, SeverityTrend: map[string]int{}}
	am, bm := byID(a.Findings), byID(b.Findings)
	for _, f := range b.Findings {
		old, ok := am[f.ID]
		if !ok {
			out.NewFindings = append(out.NewFindings, f)
		} else if severityValue(f.Severity) > severityValue(old.Severity) {
			out.Regressions = append(out.Regressions, f)
		}
	}
	for _, f := range a.Findings {
		if _, ok := bm[f.ID]; !ok {
			out.FixedFindings = append(out.FixedFindings, f)
		}
	}
	ac, bc := severityCounts(a.Findings), severityCounts(b.Findings)
	for _, v := range []string{"critical", "high", "medium", "low"} {
		out.SeverityTrend[v] = bc[v] - ac[v]
	}
	return out, nil
}

func dastEndpointSet(r models.Report) map[string]bool {
	targets := make(map[string]bool, len(r.DASTEndpoints))
	for _, endpoint := range r.DASTEndpoints {
		targets[endpoint.RequestedURL] = true
	}
	if len(targets) == 0 && r.DASTTargetURL != "" {
		targets[r.DASTTargetURL] = true
	}
	return targets
}

func legacyDASTCookies(r models.Report) bool {
	for _, finding := range r.Findings {
		if finding.SourceTool == "baseline-dast" && finding.DASTEvidence == nil &&
			(finding.Title == "Cookie lacks security attributes" || finding.Title == "Cookie has no SameSite attribute") {
			return true
		}
	}
	return false
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
