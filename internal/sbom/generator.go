package sbom

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

type Component struct {
	Type     string            `json:"type" xml:"type,attr"`
	Name     string            `json:"name" xml:"name"`
	Version  string            `json:"version,omitempty" xml:"version,omitempty"`
	PURL     string            `json:"purl,omitempty" xml:"purl,omitempty"`
	Licenses []string          `json:"licenses,omitempty" xml:"licenses>license,omitempty"`
	Hashes   map[string]string `json:"hashes,omitempty" xml:"-"`
}
type SBOM struct {
	BOMFormat       string              `json:"bomFormat" xml:"bomFormat"`
	SpecVersion     string              `json:"specVersion" xml:"specVersion"`
	SerialNumber    string              `json:"serialNumber" xml:"serialNumber"`
	Version         int                 `json:"version" xml:"version"`
	GeneratedAt     time.Time           `json:"generatedAt" xml:"generatedAt"`
	Components      []Component         `json:"components" xml:"components>component"`
	Vulnerabilities map[string][]string `json:"vulnerabilities,omitempty" xml:"-"`
}
type SBOMGenerator struct{}

func NewSBOMGenerator() *SBOMGenerator { return &SBOMGenerator{} }
func (sg *SBOMGenerator) GenerateSBOM(target, format string) (SBOM, error) {
	b := SBOM{BOMFormat: "CycloneDX", SpecVersion: "1.5", SerialNumber: "urn:uuid:" + serial(target), Version: 1, GeneratedAt: time.Now().UTC(), Vulnerabilities: map[string][]string{}}
	if strings.HasPrefix(strings.ToLower(format), "spdx") {
		b.BOMFormat = "SPDX"
		b.SpecVersion = "SPDX-2.3"
		if strings.Contains(format, "2.2") {
			b.SpecVersion = "SPDX-2.2"
		}
	}
	parsers := map[string]func(string) ([]Component, error){"go.mod": parseGoMod, "requirements.txt": parseRequirements, "package.json": parsePackageJSON, "composer.lock": parseComposer, "Cargo.lock": parseCargo, "Gemfile.lock": parseGemfile, "packages.lock.json": parseNuget}
	parsers["package-lock.json"] = parsePackageLock
	parsers["Pipfile.lock"] = parsePipfile
	parsers["pom.xml"] = parsePOM
	parsers["gradle.lockfile"] = parseGradle
	parsers["project.assets.json"] = parseProjectAssets
	err := filepath.WalkDir(target, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if path != target && (d.Name() == ".git" || d.Name() == "vendor" || d.Name() == "node_modules" || d.Name() == ".gocache" || d.Name() == "target") {
				return filepath.SkipDir
			}
			return nil
		}
		if fn := parsers[d.Name()]; fn != nil {
			v, e := fn(path)
			if e != nil {
				return e
			}
			b.Components = append(b.Components, v...)
		}
		return nil
	})
	if err != nil {
		return b, err
	}
	dedup := map[string]Component{}
	for _, c := range b.Components {
		dedup[c.PURL] = c
	}
	b.Components = b.Components[:0]
	for _, c := range dedup {
		b.Components = append(b.Components, c)
	}
	sort.Slice(b.Components, func(i, j int) bool { return b.Components[i].PURL < b.Components[j].PURL })
	return b, nil
}
func parseGoMod(path string) ([]Component, error) {
	return parseLines(path, "golang", regexp.MustCompile(`^\s*([^\s]+)\s+v([^\s]+)`), false)
}
func parseRequirements(path string) ([]Component, error) {
	return parseLines(path, "pypi", regexp.MustCompile(`^([A-Za-z0-9_.-]+)==([^\s;]+)`), false)
}
func parseLines(path, kind string, re *regexp.Regexp, _ bool) ([]Component, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	var out []Component
	s := bufio.NewScanner(f)
	for s.Scan() {
		m := re.FindStringSubmatch(s.Text())
		if len(m) > 2 {
			out = append(out, component(kind, m[1], m[2], path))
		}
	}
	return out, s.Err()
}
func parsePackageJSON(path string) ([]Component, error) {
	var d struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if e := decode(path, &d); e != nil {
		return nil, e
	}
	var out []Component
	for n, v := range d.Dependencies {
		out = append(out, component("npm", n, cleanVersion(v), path))
	}
	for n, v := range d.DevDependencies {
		out = append(out, component("npm", n, cleanVersion(v), path))
	}
	return out, nil
}
func parseComposer(path string) ([]Component, error) {
	var d struct {
		Packages []struct {
			Name, Version string
			License       []string
		} `json:"packages"`
	}
	if e := decode(path, &d); e != nil {
		return nil, e
	}
	var out []Component
	for _, p := range d.Packages {
		c := component("composer", p.Name, cleanVersion(p.Version), path)
		c.Licenses = p.License
		out = append(out, c)
	}
	return out, nil
}
func parseCargo(path string) ([]Component, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	var out []Component
	name := ""
	s := bufio.NewScanner(f)
	nameRE := regexp.MustCompile(`^name\s*=\s*"([^"]+)"`)
	versionRE := regexp.MustCompile(`^version\s*=\s*"([^"]+)"`)
	for s.Scan() {
		if m := nameRE.FindStringSubmatch(s.Text()); len(m) > 1 {
			name = m[1]
			continue
		}
		if m := versionRE.FindStringSubmatch(s.Text()); len(m) > 1 && name != "" {
			out = append(out, component("cargo", name, m[1], path))
			name = ""
		}
	}
	return out, s.Err()
}
func parseGemfile(path string) ([]Component, error) {
	return parseLines(path, "gem", regexp.MustCompile(`^\s{4}([^\s(]+)\s+\(([^)]+)\)`), false)
}
func parseNuget(path string) ([]Component, error) {
	var d struct {
		Dependencies map[string]struct {
			Resolved string `json:"resolved"`
		} `json:"dependencies"`
	}
	if e := decode(path, &d); e != nil {
		return nil, e
	}
	var out []Component
	for n, v := range d.Dependencies {
		out = append(out, component("nuget", n, v.Resolved, path))
	}
	return out, nil
}
func parsePackageLock(path string) ([]Component, error) {
	var d struct {
		Packages map[string]struct{ Name, Version string }
	}
	if e := decode(path, &d); e != nil {
		return nil, e
	}
	var out []Component
	for key, v := range d.Packages {
		if key == "" || v.Version == "" {
			continue
		}
		name := v.Name
		if name == "" {
			name = filepath.Base(key)
		}
		out = append(out, component("npm", name, v.Version, path))
	}
	return out, nil
}
func parsePipfile(path string) ([]Component, error) {
	var d map[string]map[string]struct {
		Version string `json:"version"`
	}
	if e := decode(path, &d); e != nil {
		return nil, e
	}
	var out []Component
	for _, section := range []string{"default", "develop"} {
		for n, v := range d[section] {
			out = append(out, component("pypi", n, strings.TrimPrefix(v.Version, "=="), path))
		}
	}
	return out, nil
}

type pomProject struct {
	Dependencies []struct {
		Group, Artifact, Version string `xml:",any"`
	} `xml:"dependencies>dependency"`
}

func parsePOM(path string) ([]Component, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	var d struct {
		Dependencies []struct {
			Group    string `xml:"groupId"`
			Artifact string `xml:"artifactId"`
			Version  string `xml:"version"`
		} `xml:"dependencies>dependency"`
	}
	if e = xml.Unmarshal(b, &d); e != nil {
		return nil, e
	}
	var out []Component
	for _, v := range d.Dependencies {
		out = append(out, component("maven", v.Group+"/"+v.Artifact, v.Version, path))
	}
	return out, nil
}
func parseGradle(path string) ([]Component, error) {
	return parseLines(path, "maven", regexp.MustCompile(`^([^:]+:[^:]+):([^=\s]+)`), false)
}
func parseProjectAssets(path string) ([]Component, error) {
	var d struct {
		Libraries map[string]json.RawMessage `json:"libraries"`
	}
	if e := decode(path, &d); e != nil {
		return nil, e
	}
	var out []Component
	for key := range d.Libraries {
		parts := strings.SplitN(key, "/", 2)
		if len(parts) == 2 {
			out = append(out, component("nuget", parts[0], parts[1], path))
		}
	}
	return out, nil
}
func component(kind, name, version, path string) Component {
	b, _ := os.ReadFile(path)
	sum := sha256.Sum256(b)
	return Component{Type: "library", Name: name, Version: version, PURL: fmt.Sprintf("pkg:%s/%s@%s", kind, name, version), Hashes: map[string]string{"SHA-256": hex.EncodeToString(sum[:])}}
}
func decode(path string, v any) error {
	b, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	return json.Unmarshal(b, v)
}
func cleanVersion(v string) string { return strings.TrimLeft(v, "^~>=<v ") }
func serial(v string) string {
	s := sha256.Sum256([]byte(v + time.Now().String()))
	return fmt.Sprintf("%x-%x-%x-%x-%x", s[:4], s[4:6], s[6:8], s[8:10], s[10:16])
}
