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
	if strings.TrimSpace(image) == "" {
		return nil, fmt.Errorf("container image is required")
	}
	scanner := c.Scanner
	if scanner == "" {
		scanner = "trivy"
	}
	var args []string
	if scanner == "grype" {
		args = []string{image, "-o", "json"}
	} else {
		args = []string{"image", "--quiet", "--format", "json", "--scanners", "vuln,misconfig,secret", image}
	}
	ctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()
	b, err := exec.CommandContext(ctx, scanner, args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s scan: %w: %s", scanner, err, strings.TrimSpace(string(b)))
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
					V3Score float64 `json:"V3Score"`
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
			f := languageFinding("trivy", "container", v.VulnerabilityID, r.Target, 0, v.Title, desc, v.Severity, "", "CWE-1104")
			for _, score := range v.CVSS {
				if score.V3Score > f.CVSSBase {
					f.CVSSBase = score.V3Score
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
		f := languageFinding("grype", "container", m.Vulnerability.ID, image, 0, m.Vulnerability.ID, fmt.Sprintf("%s %s: %s", m.Artifact.Name, m.Artifact.Version, m.Vulnerability.Description), m.Vulnerability.Severity, "", "CWE-1104")
		for _, v := range m.Vulnerability.CVSS {
			if v.Metrics.BaseScore > f.CVSSBase {
				f.CVSSBase = v.Metrics.BaseScore
			}
		}
		out = append(out, f)
	}
	return out, nil
}
