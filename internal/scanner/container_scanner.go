package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/example/sast-dast-analyzer/internal/models"
)

type ContainerScanner struct {
	Scanner string
	Timeout time.Duration
}

func NewContainerScanner() *ContainerScanner {
	return &ContainerScanner{Scanner: "trivy", Timeout: 15 * time.Minute}
}
func (c *ContainerScanner) Scan(ctx context.Context, image string) ([]models.Finding, error) {
	image = strings.TrimSpace(image)
	if image == "" {
		return nil, fmt.Errorf("container image is required")
	}
	// Reject option-looking references so the value can never be parsed as a
	// trivy/grype flag (argument injection, e.g. "--config=/attacker/file").
	if strings.HasPrefix(image, "-") || strings.ContainsAny(image, " \t\r\n") {
		return nil, fmt.Errorf("invalid container image reference %q", image)
	}
	scanner := strings.ToLower(strings.TrimSpace(c.Scanner))
	if scanner == "" {
		scanner = "trivy"
	}
	if scanner != "trivy" && scanner != "grype" {
		return nil, fmt.Errorf("unsupported container scanner %q (use trivy or grype)", c.Scanner)
	}
	if c.Timeout <= 0 {
		c.Timeout = 15 * time.Minute
	}
	var args []string
	if scanner == "grype" {
		args = []string{image, "-o", "json"}
	} else {
		args = []string{"image", "--quiet", "--format", "json", "--scanners", "vuln,misconfig,secret", image}
	}
	ctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()
	// Parse stdout only: progress/log lines on stderr would corrupt the JSON.
	var stderr strings.Builder
	cmd := exec.CommandContext(ctx, scanner, args...)
	cmd.Stderr = &stderr
	b, err := cmd.Output()
	if err != nil {
		detail := strings.TrimSpace(stderr.String())
		if len(detail) > 2000 {
			detail = detail[:2000]
		}
		return nil, fmt.Errorf("%s scan: %w: %s", scanner, err, detail)
	}
	if scanner == "grype" {
		return parseGrype(b, image)
	}
	return parseTrivy(b, image)
}
func parseTrivy(raw []byte, image string) ([]models.Finding, error) {
	var d struct {
		Results []struct {
			Target, Type    string
			Vulnerabilities []struct {
				VulnerabilityID, PkgName, InstalledVersion, FixedVersion, Title, Description, Severity string
				CVSS                                                                                   map[string]struct {
					V3Score  float64 `json:"V3Score"`
					V3Vector string  `json:"V3Vector"`
				}
			}
			Misconfigurations []struct{ ID, Title, Description, Message, Severity, Resolution string }
		}
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, err
	}
	var out []models.Finding
	for _, r := range d.Results {
		for _, v := range r.Vulnerabilities {
			desc := fmt.Sprintf("Image %s package %s %s (fixed: %s): %s", image, v.PkgName, v.InstalledVersion, v.FixedVersion, v.Description)
			f := languageFinding("trivy", "container", v.VulnerabilityID+":"+v.PkgName+":"+v.InstalledVersion, r.Target, 0, v.Title, desc, v.Severity, "", "CWE-1104")
			for _, score := range v.CVSS {
				if score.V3Score > 0 && (f.CVSSVector == "" || score.V3Score > f.CVSSBase) {
					f.CVSSBase = score.V3Score
					f.CVSSVector = score.V3Vector
					if f.CVSSVector == "" {
						f.CVSSVector = scannerScoredVector
					}
				}
			}
			f.Remediation = "Upgrade " + v.PkgName + " to " + v.FixedVersion + " and rebuild the image from a trusted minimal base."
			out = append(out, f)
		}
		for _, m := range r.Misconfigurations {
			f := languageFinding("trivy", "container", m.ID, r.Target, 0, m.Title, m.Description+" "+m.Message, m.Severity, "", "CWE-16")
			f.Remediation = m.Resolution
			out = append(out, f)
		}
	}
	return out, nil
}
func parseGrype(raw []byte, image string) ([]models.Finding, error) {
	var d struct {
		Matches []struct {
			Vulnerability struct {
				ID, Severity, Description string
				CVSS                      []struct {
					Version string `json:"version"`
					Vector  string `json:"vector"`
					Metrics struct {
						BaseScore float64 `json:"baseScore"`
					}
				}
			}
			Artifact struct{ Name, Version string }
		}
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, err
	}
	var out []models.Finding
	for _, m := range d.Matches {
		f := languageFinding("grype", "container", m.Vulnerability.ID+":"+m.Artifact.Name+":"+m.Artifact.Version, image, 0, m.Vulnerability.ID, fmt.Sprintf("%s %s: %s", m.Artifact.Name, m.Artifact.Version, m.Vulnerability.Description), m.Vulnerability.Severity, "", "CWE-1104")
		for _, v := range m.Vulnerability.CVSS {
			if v.Metrics.BaseScore > 0 && (f.CVSSVector == "" || v.Metrics.BaseScore > f.CVSSBase) && !strings.HasPrefix(v.Version, "2") {
				f.CVSSBase = v.Metrics.BaseScore
				f.CVSSVector = v.Vector
				if f.CVSSVector == "" {
					f.CVSSVector = scannerScoredVector
				}
			}
		}
		out = append(out, f)
	}
	return out, nil
}

// scannerScoredVector marks a finding whose CVSSBase came from the scanner's
// own advisory data even though no vector string was supplied, so the
// keyword-based re-scoring in main does not overwrite the authoritative score.
const scannerScoredVector = "SCANNER-REPORTED"

// cvssVectorFromParts builds a CVSS v3.1 vector from spelled-out metric
// values ("NETWORK", "LOW", ...) as reported by OWASP Dependency-Check.
func cvssVectorFromParts(av, ac, pr, ui, s, c, i, a string) string {
	first := func(v string) string {
		v = strings.ToUpper(strings.TrimSpace(v))
		if v == "" {
			return "X"
		}
		return v[:1]
	}
	if av == "" && ac == "" && pr == "" {
		return scannerScoredVector
	}
	return "CVSS:3.1/AV:" + first(av) + "/AC:" + first(ac) + "/PR:" + first(pr) + "/UI:" + first(ui) + "/S:" + first(s) + "/C:" + first(c) + "/I:" + first(i) + "/A:" + first(a)
}
