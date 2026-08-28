package scanner

import (
	"archive/tar"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/example/sast-dast-analyzer/internal/models"
)

type ContainerScanner struct {
	Scanner string
	Timeout time.Duration
}
type RegistryCredentials struct{ Username, Password string }
type ImageVulnerability struct {
	Image   string
	Finding models.Finding
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
func (c *ContainerScanner) ExtractFilesystemFromImage(ctx context.Context, image string) (string, error) {
	dir, err := os.MkdirTemp("", "analyzer-image-")
	if err != nil {
		return "", err
	}
	cleanup := func() { os.RemoveAll(dir) }
	idBytes, err := exec.CommandContext(ctx, "docker", "create", image).Output()
	if err != nil {
		cleanup()
		return "", err
	}
	id := strings.TrimSpace(string(idBytes))
	defer exec.CommandContext(context.Background(), "docker", "rm", "-f", id).Run()
	cmd := exec.CommandContext(ctx, "docker", "export", id)
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		cleanup()
		return "", err
	}
	if err = cmd.Start(); err != nil {
		cleanup()
		return "", err
	}
	if err = extractTar(pipe, dir); err != nil {
		cleanup()
		return "", err
	}
	if err = cmd.Wait(); err != nil {
		cleanup()
		return "", err
	}
	return dir, nil
}
func extractTar(r io.Reader, dir string) error {
	tr := tar.NewReader(r)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		target := filepath.Join(dir, filepath.Clean(h.Name))
		rel, err := filepath.Rel(dir, target)
		if err != nil || strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
			return fmt.Errorf("unsafe image layer path %q", h.Name)
		}
		switch h.Typeflag {
		case tar.TypeDir:
			if err = os.MkdirAll(target, 0750); err != nil {
				return err
			}
		case tar.TypeReg:
			if err = os.MkdirAll(filepath.Dir(target), 0750); err != nil {
				return err
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
			if err != nil {
				return err
			}
			_, copyErr := io.CopyN(f, tr, h.Size)
			closeErr := f.Close()
			if copyErr != nil {
				return copyErr
			}
			if closeErr != nil {
				return closeErr
			}
		}
	}
}
func (c *ContainerScanner) ScanContainerRegistry(context.Context, string, RegistryCredentials) ([]ImageVulnerability, error) {
	return nil, fmt.Errorf("registry-wide enumeration requires registry-specific catalog authorization; scan explicit image references instead")
}
