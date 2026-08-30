package detector

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type LanguageInfo struct {
	Name         string   `json:"name"`
	Confidence   float64  `json:"confidence"`
	FileCount    int      `json:"file_count"`
	ProjectFiles []string `json:"project_files"`
}

type LanguageDetector struct{ targetPath string }

func NewLanguageDetector(targetPath string) *LanguageDetector {
	return &LanguageDetector{targetPath: targetPath}
}

type languageRule struct {
	name       string
	markers    map[string]bool
	extensions map[string]bool
}

var rules = []languageRule{
	{"go", set("go.mod", "go.sum"), set(".go")},
	{"python", set("requirements.txt", "setup.py", "Pipfile", "pyproject.toml"), set(".py")},
	{"javascript", set("package.json", "tsconfig.json"), set(".js", ".ts", ".jsx", ".tsx")},
	{"java", set("pom.xml", "build.gradle", ".classpath"), set(".java")},
	{"cpp", set("CMakeLists.txt", "Makefile"), set(".c", ".cpp", ".cc", ".h", ".hpp")},
	{"php", set("composer.json", ".env"), set(".php")},
	{"rust", set("Cargo.toml", "Cargo.lock"), set(".rs")},
	{"ruby", set("Gemfile", "Gemfile.lock"), set(".rb")},
	{"dotnet", set("global.json", "Directory.Build.props"), set(".csproj", ".sln", ".cs", ".fsproj", ".vbproj")},
	{"swift", set("Package.swift"), set(".swift")},
	{"kotlin", set(), set(".kt")},
	{"solidity", set("foundry.toml", "hardhat.config.js", "hardhat.config.ts", "truffle-config.js"), set(".sol")},
}

func set(v ...string) map[string]bool {
	m := map[string]bool{}
	for _, x := range v {
		m[x] = true
	}
	return m
}

func (ld *LanguageDetector) DetectLanguages() (map[string]LanguageInfo, error) {
	out := map[string]LanguageInfo{}
	_, isFoundryProject := os.Stat(filepath.Join(ld.targetPath, "foundry.toml"))
	err := filepath.WalkDir(ld.targetPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if isFoundryProject == nil && d.Name() == "lib" && path != ld.targetPath {
				return filepath.SkipDir
			}
			switch d.Name() {
			case ".git", ".hg", ".svn", "vendor", "node_modules", ".gocache", "target", "bin", "obj":
				if path != ld.targetPath {
					return filepath.SkipDir
				}
			}
			return nil
		}
		name, ext := d.Name(), strings.ToLower(filepath.Ext(d.Name()))
		rel, _ := filepath.Rel(ld.targetPath, path)
		for _, r := range rules {
			if r.markers[name] || r.extensions[ext] {
				info := out[r.name]
				info.Name = r.name
				info.Confidence = .95
				info.FileCount++
				if r.markers[name] {
					info.ProjectFiles = append(info.ProjectFiles, filepath.ToSlash(rel))
				}
				out[r.name] = info
			}
		}
		return nil
	})
	for k, v := range out {
		sort.Strings(v.ProjectFiles)
		out[k] = v
	}
	return out, err
}

func (ld *LanguageDetector) GetRecommendedToolsForLanguages(languages map[string]LanguageInfo) map[string][]string {
	catalog := map[string][]string{"go": {"gosec"}, "python": {"bandit", "semgrep"}, "javascript": {"eslint", "semgrep"}, "java": {"spotbugs", "dependency-check", "semgrep"}, "php": {"phpstan", "psalm", "semgrep"}, "rust": {"cargo-audit", "semgrep"}, "ruby": {"brakeman"}, "cpp": {"clang-analyzer"}, "kotlin": {"semgrep"}, "solidity": {"slither"}}
	out := map[string][]string{}
	for lang := range languages {
		out[lang] = append([]string(nil), catalog[lang]...)
	}
	return out
}

func (ld *LanguageDetector) FindProjectRoot() string {
	p, _ := filepath.Abs(ld.targetPath)
	for {
		for _, marker := range []string{".git", ".hg", ".svn"} {
			if ok, _ := exists(filepath.Join(p, marker)); ok {
				return p
			}
		}
		parent := filepath.Dir(p)
		if parent == p {
			return ld.targetPath
		}
		p = parent
	}
}
func exists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}
