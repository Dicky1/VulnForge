package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/example/sast-dast-analyzer/internal/models"
	"os"
	"path/filepath"
)

type SpotBugsScanner struct{}

func NewSpotBugsScanner() *SpotBugsScanner { return &SpotBugsScanner{} }
func (*SpotBugsScanner) Name() string      { return "spotbugs" }
func (*SpotBugsScanner) Language() string  { return "java" }
func (*SpotBugsScanner) IsInstalled() bool { return installed("spotbugs") }
func (*SpotBugsScanner) Install(context.Context) error {
	return errors.New("install SpotBugs using the platform package manager")
}
func (s *SpotBugsScanner) Scan(ctx context.Context, target string, _ *models.ScanConfig) (*models.ToolOutput, error) {
	r, err := run(ctx, multiScannerTimeout, target, "spotbugs", "-textui", "-output=spotbugs.json", "-outputFormat=json", ".")
	if err != nil {
		return output(s.Name(), r, nil), err
	}
	raw := r.data
	if len(raw) == 0 {
		raw, _ = os.ReadFile(filepath.Join(target, "spotbugs.json"))
	}
	f, e := s.ParseOutput(raw)
	return output(s.Name(), r, f), e
}
func (*SpotBugsScanner) ParseOutput(raw []byte) ([]models.Finding, error) {
	var d struct {
		BugCollection struct {
			BugInstances []struct {
				Type, Priority, Abbrev, Category string
				LongMessage                      string `json:"LongMessage"`
				SourceLine                       struct {
					SourcePath string
					Start      int
				}
			} `json:"BugInstance"`
		} `json:"BugCollection"`
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, err
	}
	cwes := map[string]string{"NP_NULL_ON_SOME_PATH": "CWE-476", "SQL_NONCONSTANT_STRING_PASSED_TO_EXECUTE": "CWE-89", "COMMAND_INJECTION": "CWE-78"}
	var out []models.Finding
	for _, x := range d.BugCollection.BugInstances {
		sev := map[string]string{"HIGH": "CRITICAL", "MEDIUM": "HIGH", "LOW": "MEDIUM"}[x.Priority]
		out = append(out, languageFinding("spotbugs", "java", x.Type, x.SourceLine.SourcePath, x.SourceLine.Start, x.Abbrev, x.LongMessage, sev, "", cwes[x.Type]))
	}
	return out, nil
}
