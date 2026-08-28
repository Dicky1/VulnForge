CREATE TABLE IF NOT EXISTS reports (
  id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, target_path TEXT NOT NULL,
  language TEXT, total_findings INTEGER, critical_count INTEGER,
  high_count INTEGER, token_used INTEGER, duration TEXT, report_json BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
  id TEXT NOT NULL, report_id TEXT NOT NULL, title TEXT, severity TEXT, cwe TEXT,
  file_path TEXT, line INTEGER, ai_confidence REAL, is_zero_day INTEGER,
  PRIMARY KEY (id, report_id), FOREIGN KEY(report_id) REFERENCES reports(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS trend_analysis (
  target_path TEXT NOT NULL, date TEXT NOT NULL, critical_count INTEGER,
  high_count INTEGER, medium_count INTEGER, resolved_count INTEGER,
  PRIMARY KEY(target_path, date)
);
CREATE INDEX IF NOT EXISTS idx_reports_target_time ON reports(target_path, timestamp DESC);
