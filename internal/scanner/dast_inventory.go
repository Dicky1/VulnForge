package scanner

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v2"
)

type DASTManifest struct {
	Origin string   `yaml:"origin"`
	Paths  []string `yaml:"paths"`
}

const maxDASTInputBytes = 8 << 20

func readDASTInput(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxDASTInputBytes {
		return nil, fmt.Errorf("DAST input must be a regular file up to 8 MiB")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxDASTInputBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxDASTInputBytes {
		return nil, fmt.Errorf("DAST input exceeds 8 MiB")
	}
	return data, nil
}

func ReadDASTManifest(path string) (DASTManifest, error) {
	data, err := readDASTInput(path)
	if err != nil {
		return DASTManifest{}, err
	}
	var manifest DASTManifest
	if err := yaml.UnmarshalStrict(data, &manifest); err != nil {
		return DASTManifest{}, fmt.Errorf("invalid DAST manifest: expected an origin and a list of paths")
	}
	if manifest.Origin == "" {
		return DASTManifest{}, fmt.Errorf("DAST manifest requires an origin")
	}
	return manifest, nil
}

// InventoryDASTPaths lists concrete GET paths from a local document. It never
// resolves references, reads response bodies, or contacts the listed hosts.
func InventoryDASTPaths(origin, path, format string) (DASTManifest, error) {
	scope, err := parseDASTOrigin(origin)
	if err != nil {
		return DASTManifest{}, err
	}
	data, err := readDASTInput(path)
	if err != nil {
		return DASTManifest{}, err
	}
	paths := map[string]bool{}
	add := func(path string) {
		u, err := url.Parse(path)
		if err == nil && strings.HasPrefix(path, "/") && !strings.HasPrefix(path, "//") &&
			u.Host == "" && !u.IsAbs() && !strings.ContainsAny(u.Path, "{}") {
			paths[u.EscapedPath()] = true
		}
	}
	addURL := func(rawURL string) {
		u, err := parseDASTURL(rawURL)
		if err != nil || scope.Scheme != u.Scheme || !sameDASTScope(scope, u) {
			return
		}
		path := u.EscapedPath()
		if path == "" {
			path = "/"
		}
		add(path)
	}
	switch format {
	case "openapi":
		var spec struct {
			Paths map[string]map[string]any `yaml:"paths"`
		}
		if err := yaml.Unmarshal(data, &spec); err != nil {
			return DASTManifest{}, fmt.Errorf("invalid OpenAPI document")
		}
		for path, operations := range spec.Paths {
			if operations["get"] != nil {
				add(path)
			}
		}
	case "har":
		var har struct {
			Log struct {
				Entries []struct {
					Request struct {
						Method string `json:"method"`
						URL    string `json:"url"`
					} `json:"request"`
				} `json:"entries"`
			} `json:"log"`
		}
		if err := json.Unmarshal(data, &har); err != nil {
			return DASTManifest{}, fmt.Errorf("invalid HAR document")
		}
		for _, entry := range har.Log.Entries {
			if entry.Request.Method == http.MethodGet {
				addURL(entry.Request.URL)
			}
		}
	case "burp":
		var export struct {
			XMLName xml.Name `xml:"items"`
			Items   []struct {
				Method string `xml:"method"`
				URL    string `xml:"url"`
			} `xml:"item"`
		}
		if err := xml.Unmarshal(data, &export); err != nil {
			return DASTManifest{}, fmt.Errorf("invalid Burp XML export")
		}
		for _, item := range export.Items {
			if item.Method == http.MethodGet {
				addURL(item.URL)
			}
		}
	case "sitemap":
		var sitemap struct {
			XMLName xml.Name `xml:"urlset"`
			URLs    []string `xml:"url>loc"`
		}
		if err := xml.Unmarshal(data, &sitemap); err != nil {
			return DASTManifest{}, fmt.Errorf("expected a local sitemap URL set")
		}
		for _, rawURL := range sitemap.URLs {
			addURL(strings.TrimSpace(rawURL))
		}
	default:
		return DASTManifest{}, fmt.Errorf("unsupported DAST inventory format")
	}
	if len(paths) == 0 {
		return DASTManifest{}, fmt.Errorf("no concrete GET paths found")
	}
	manifest := DASTManifest{Origin: reportDASTURL(scope), Paths: make([]string, 0, len(paths))}
	for path := range paths {
		manifest.Paths = append(manifest.Paths, path)
	}
	sort.Strings(manifest.Paths)
	return manifest, nil
}
